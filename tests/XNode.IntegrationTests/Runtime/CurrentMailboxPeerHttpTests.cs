using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using XNode.Core.Mailbox;
using XNode.Core;
using XNode.Core.Mailbox.Client;
using Peer = XNode.IntegrationTests.Runtime.CurrentMailboxReplicaReceiverTests.Fixture;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Real local TLS/H2 and two independent native stores under actual
/// signed test-owned network/grants/floors. Not Program/ONION or device evidence.</summary>
public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task WrongHolderCannotWriteServerIntentOrReserveNativeReplay()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(f.ClientStoreFrame());
        var signature = decoded.Presentation.HolderSignature.ToArray(); signature[0] ^= 1;
        var invalid = MailboxAuthenticatedClientRequestCodec.Encode(decoded with
        { Presentation = decoded.Presentation with { HolderSignature = signature } });
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(invalid, f.Ledger!).AsTask()));
        Assert.False(File.Exists(f.LedgerFile)); Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.PendingCount);
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles); Assert.Equal(0, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task ServerIntentCapacityBackpressureCannotCollectOrDispatchAnotherOperation()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(maximumEntries: 1);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!)).Status);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with
        {
            OperationId = Enumerable.Repeat((byte)0x68, 16).ToArray(),
            DeduplicationDigest = Enumerable.Repeat((byte)0x69, 32).ToArray(),
            Ciphertext = Enumerable.Repeat((byte)0x70, 64).ToArray()
        };
        f.Reopen();
        await Assert.ThrowsAsync<MailboxClientLedgerCapacityException>(() => f.Coordinator.StoreClientAsync(
            f.ClientStoreFrame(MailboxClientCodec.EncodeEncryptedEnvelope(body), 2), f.Ledger!).AsTask());
        Assert.Single(f.ExactIntents); Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal(1, f.RemoteHost.Requests);
        // Replay diagnostics count grant scopes, not individual outcomes: the
        // second counter is now Pending; the first durable outcome still exists.
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.CompletedCount); Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        Assert.Equal(1, f.Sender.Node.OutcomeCount);
    }

    [Fact]
    public async Task AuthorityLossAfterActualIntentWriteReleasesNoPeerMutationAndReopensExactly()
    {
        await using var f = await Fixture.CreateAsync();
        f.OpenLedger(new IntentWriteCallback(() => f.Signed.RejectProof = true)); var client = f.ClientStoreFrame();
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask()));
        var exact = Assert.Single(f.ExactIntents);
        Assert.Equal(0, f.RemoteHost.Requests); Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        f.Signed.RejectProof = false; f.Reopen(); f.Signed.Sample = 101;
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, f.Ledger!)).Status);
        Assert.Equal(exact, Assert.Single(f.ExactIntents)); Assert.Equal(1, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task CorruptedSavedPeerSignatureCannotReserveNewReplayOrDispatch()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); var client = f.ClientStoreFrame();
        f.RemoteHost.DropNext = true; _ = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        var original = MailboxPeerWireV2Codec.Decode(Assert.Single(f.ExactIntents));
        var signature = original.Signature.ToArray(); signature[0] ^= 1;
        var broken = original with { Signature = signature };
        var path = f.LedgerFile; f.Ledger!.Dispose(); f.Ledger = null;
        var document = JsonNode.Parse(File.ReadAllBytes(path))!;
        document["operations"]!.AsObject().Single().Value!["peerRequest"] = Convert.ToBase64String(MailboxPeerWireV2Codec.Encode(broken));
        File.WriteAllText(path, document.ToJsonString()); var prior = File.ReadAllBytes(path); f.OpenLedger();
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask()));
        Assert.Equal(prior, File.ReadAllBytes(path)); Assert.Equal(1, f.RemoteHost.Requests);
        Assert.Single(f.Sender.ReplayFiles); Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(f.Sender.ReplayFiles[0]));
    }
    [Fact]
    public async Task ServerAuthoredStoreOwnsExactRandomNonceAcrossLostResponseAdvanceAndReopen()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = f.ClientStoreFrame(); f.RemoteHost.DropNext = true;
        var partial = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, partial.Status);
        var exact = Assert.Single(f.ExactIntents);
        Assert.Equal(1UL, MailboxPeerWireV2Codec.Decode(exact).Cursor);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        f.Reopen(); f.Signed.Sample = 101;
        var recovered = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, recovered.Status);
        Assert.Equal(exact, Assert.Single(f.ExactIntents));
        Assert.Equal(2, f.RemoteHost.Requests); Assert.Equal(2, f.PeerClient.ExactRequests.Count);
        Assert.All(f.PeerClient.ExactRequests, request => Assert.Equal(exact, request));
        f.Reopen(); f.Signed.Sample = 102;
        Assert.Equal(recovered.CanonicalMqr3.ToArray(),
            (await f.Coordinator.StoreClientAsync(client, f.Ledger!)).CanonicalMqr3.ToArray());
        Assert.Equal(2, f.RemoteHost.Requests);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
    }

    [Fact]
    public async Task ServerAuthoredStoreReplayAfterTombstoneDoesNotRewriteOrRemint()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = f.ClientStoreFrame();
        var stored = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        var exact = Assert.Single(f.ExactIntents);
        // The fixed pre-producer fixture time is older than the actual Store.
        // Author ACK against that real Store's creation/cursor lower bound.
        var storedPeer = MailboxPeerWireV2Codec.Decode(exact);
        var removal = MailboxPeerWireV2Codec.Decode(f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone)) with
        { Cursor = storedPeer.Cursor, CreatedAtUnixSeconds = storedPeer.CreatedAtUnixSeconds };
        var tombstone = MailboxPeerWireV2Codec.Encode(f.Recipient.Crypto.SignRequest(removal, f.Recipient.SenderSeed));
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
            tombstone, MailboxPeerReplicationOperation.Tombstone)).Status);
        f.Reopen(); f.Signed.Sample = 101;
        var historical = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        Assert.Equal(stored.CanonicalMqr3.ToArray(), historical.CanonicalMqr3.ToArray());
        Assert.Equal(exact, Assert.Single(f.ExactIntents)); Assert.Equal(2, f.RemoteHost.Requests);
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
    }

    [Fact]
    public async Task ServerAuthoredConcurrentExactRetriesUseOneCursorNonceAndRemoteWrite()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = f.ClientStoreFrame();
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask()));
        Assert.All(results, result =>
        {
            Assert.Equal(MailboxPeerQuorumStatus.Durable, result.Status);
            Assert.Equal(results[0].CanonicalMqr3.ToArray(), result.CanonicalMqr3.ToArray());
        });
        Assert.Single(f.ExactIntents); Assert.Equal(1, f.RemoteHost.Requests);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
    }

    [Fact]
    public async Task ServerAuthoredDistinctOperationsAllocateDurableCursorsAndDistinctNonces()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!)).Status);
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with
        {
            OperationId = Enumerable.Repeat((byte)0x68, 16).ToArray(),
            DeduplicationDigest = Enumerable.Repeat((byte)0x69, 32).ToArray(),
            Ciphertext = Enumerable.Repeat((byte)0x70, 64).ToArray()
        };
        var client = f.ClientStoreFrame(MailboxClientCodec.EncodeEncryptedEnvelope(body), 2);
        f.Reopen(); f.Signed.Sample = 101;
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, f.Ledger!)).Status);
        var intents = f.ExactIntents.Select(bytes => MailboxPeerWireV2Codec.Decode(bytes)).OrderBy(frame => frame.Cursor).ToArray();
        Assert.Equal(new ulong[] { 1, 2 }, intents.Select(frame => frame.Cursor));
        Assert.False(intents[0].ReplayNonce.Span.SequenceEqual(intents[1].ReplayNonce.Span));
        Assert.Equal(2, f.Sender.MutationFiles.Length); Assert.Equal(2, f.Recipient.MutationFiles.Length);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ServerIntentWriteFailureNeverDispatchesAndCannotRemintKnownReplay(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync();
        f.OpenLedger(new IntentWriteFault(beforeReplace)); var client = f.ClientStoreFrame();
        Assert.IsType<IOException>(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask()));
        Assert.Equal(0, f.RemoteHost.Requests); Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        var prior = f.ExactIntents;
        f.Reopen(); f.Signed.Sample = 101;
        if (beforeReplace)
        {
            Assert.Empty(prior);
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask());
            Assert.Empty(f.ExactIntents); Assert.Equal(0, f.RemoteHost.Requests);
            Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        }
        else
        {
            Assert.Single(prior);
            Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, f.Ledger!)).Status);
            Assert.Equal(Assert.Single(prior), Assert.Single(f.ExactIntents)); Assert.Equal(1, f.RemoteHost.Requests);
        }
    }

    [Fact]
    public async Task LostProducerIntentAfterCompletedStoreFailsWithoutRecreation()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = f.ClientStoreFrame();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, f.Ledger!)).Status);
        var path = f.LedgerFile; f.Ledger!.Dispose(); f.Ledger = null; File.Delete(path);
        f.Reopen(); f.OpenLedger();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask());
        Assert.False(File.Exists(path)); Assert.Equal(1, f.RemoteHost.Requests);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
    }

    [Fact]
    public async Task HigherClientCounterCannotRecreateLostIntentForExistingMutationCustody()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!)).Status);
        var path = f.LedgerFile; f.Ledger!.Dispose(); f.Ledger = null; File.Delete(path);
        f.Reopen(); f.OpenLedger();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(f.ClientStoreFrame(counter: 2), f.Ledger!).AsTask());
        Assert.False(File.Exists(path)); Assert.Equal(1, f.RemoteHost.Requests);
        Assert.Single(f.Sender.ReplayFiles); Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(f.Sender.ReplayFiles[0]));
        Assert.Equal(1, f.Sender.Node.OutcomeCount);
    }

    [Fact]
    public async Task CurrentStoreRejectsIncompatibleIntentLedgerWithoutRepair()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = f.ClientStoreFrame(); f.RemoteHost.DropNext = true;
        _ = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        var path = f.LedgerFile; f.Ledger!.Dispose(); f.Ledger = null;
        var old = File.ReadAllText(path).Replace("\"schemaVersion\":4", "\"schemaVersion\":3", StringComparison.Ordinal);
        File.WriteAllText(path, old); f.OpenLedger();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask());
        Assert.Equal(old, File.ReadAllText(path)); Assert.Equal(1, f.RemoteHost.Requests);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
    }
    [Fact]
    public async Task PersistedClientQuorumRecoversAfterReplayCompletionWriteFailure()
    {
        await using var f = await Fixture.CreateAsync();
        var fault = new ReplayCompletionWriteFault();
        f.Sender.Node.ReopenRuntime(fault); f.Sender.Reopen(); f.Bind();
        var client = f.ClientStoreFrame(); var peer = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        f.RemoteHost.AfterReceive = reply => { fault.Armed = true; return reply; };
        Assert.IsType<IOException>(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(client, peer).AsTask()));
        // The native journal retries an atomic replace four times on Windows.
        // Fail every attempt so the durable outcome exists but completion does not.
        Assert.Equal(OperatingSystem.IsWindows() ? 4 : 1, fault.Failures);
        Assert.Equal(1, f.Sender.Node.OutcomeCount);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(Assert.Single(f.Sender.ReplayFiles)));
        f.RemoteHost.AfterReceive = null; f.Reopen(); f.Signed.Sample = 101;
        var recovered = await f.Coordinator.StoreClientAsync(client, peer);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, recovered.Status);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
        Assert.Equal(1, f.Sender.Node.OutcomeCount); Assert.Equal(1, f.RemoteHost.Requests);
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
    }

    [Fact]
    public async Task ScopedPeerCannotBorrowAnotherAdmissionOwnerEvenWithSameNodeAndFloors()
    {
        await using var f = await Fixture.CreateAsync();
        var node = f.Sender.Node;
        var other = new CurrentMailboxAdmission(f.Signed, f.Signed, node.Node, node.Deposit, node.Retrieve, node.Runtime);
        Assert.NotNull(await Record.ExceptionAsync(() => other.WithGrantAsync(node.ExactGrant, MailboxCapabilityDomain.Deposit,
            (scope, token) => f.Sender.Receiver.WithAdmittedPeerAsync(f.Recipient.Frame(MailboxPeerReplicationOperation.Store),
                MailboxPeerReplicationOperation.Store, MailboxPeerWireResponseReplicaV2.Sender, scope,
                (_, _) => ValueTask.FromResult(1), token)).AsTask()));
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles); Assert.Equal(0, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task ConcurrentClientStoreCompletesOneCanonicalOutcomeAndOneRemoteWrite()
    {
        await using var f = await Fixture.CreateAsync();
        var client = f.ClientStoreFrame(); var peer = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => f.Coordinator.StoreClientAsync(client, peer).AsTask()));
        Assert.All(results, result =>
        {
            Assert.Equal(MailboxPeerQuorumStatus.Durable, result.Status);
            Assert.Equal(results[0].CanonicalMqr3.ToArray(), result.CanonicalMqr3.ToArray());
        });
        Assert.Equal(1, f.RemoteHost.Requests); Assert.Equal(1, f.PeerClient.Calls);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
    }

    [Fact]
    public async Task ClientStoreOutcomeIsExactAfterAdvancingTimeReopenAndTombstone()
    {
        await using var f = await Fixture.CreateAsync();
        var client = f.ClientStoreFrame(); var peer = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var first = await f.Coordinator.StoreClientAsync(client, peer).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(MailboxPeerQuorumStatus.Durable, first.Status);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
        f.Signed.Sample = 101; f.Reopen();
        var retry = await f.Coordinator.StoreClientAsync(client, peer);
        Assert.Equal(first.CanonicalMqr3.ToArray(), retry.CanonicalMqr3.ToArray());
        Assert.Equal(1, f.RemoteHost.Requests);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
            f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone), MailboxPeerReplicationOperation.Tombstone)).Status);
        f.Reopen();
        var historical = await f.Coordinator.StoreClientAsync(client, peer);
        Assert.Equal(first.CanonicalMqr3.ToArray(), historical.CanonicalMqr3.ToArray());
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
        Assert.Equal(2, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task ClientStoreLostRemoteResponseKeepsBothReplaysPendingUntilExactReopenRetry()
    {
        await using var f = await Fixture.CreateAsync();
        var client = f.ClientStoreFrame(); var peer = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        f.RemoteHost.DropNext = true;
        var partial = await f.Coordinator.StoreClientAsync(client, peer);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, partial.Status); Assert.True(partial.CanonicalMqr3.IsEmpty);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Sender.ReplayFiles)));
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
        f.Reopen();
        var complete = await f.Coordinator.StoreClientAsync(client, peer);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, complete.Status);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.PendingCount);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal(2, f.RemoteHost.Requests);
    }

    [Theory]
    [InlineData("body")]
    [InlineData("grant")]
    [InlineData("holder")]
    public async Task ClientStoreRejectsCrossFedOrForgedInputBeforeEitherReplay(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var client = f.ClientStoreFrame(); var encoded = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        if (defect == "holder")
        {
            var parsed = MailboxAuthenticatedClientRequestCodec.Decode(client);
            var signature = parsed.Presentation.HolderSignature.ToArray(); signature[^1] ^= 1;
            client = MailboxAuthenticatedClientRequestCodec.Encode(parsed with { Presentation = parsed.Presentation with { HolderSignature = signature } });
        }
        else
        {
            var peer = MailboxPeerWireV2Codec.Decode(encoded);
            if (defect == "body")
            {
                var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(peer.Payload.Span);
                var payload = MailboxClientCodec.EncodeEncryptedEnvelope(body with { Ciphertext = Enumerable.Repeat((byte)0x61, 64).ToArray() });
                peer = peer with { Payload = payload, PayloadDigest = SHA256.HashData(payload) };
            }
            else
            {
                var grant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host, MailboxCapabilityDomain.Deposit, 0x61);
                byte[] proof = [.. peer.SenderMembershipProof.CanonicalInclusionProof.Span[..38], .. grant];
                peer = peer with
                {
                    SenderMembershipProof = peer.SenderMembershipProof with { CanonicalInclusionProof = proof },
                    RecipientMembershipProof = peer.RecipientMembershipProof with { CanonicalInclusionProof = proof }
                };
            }
            encoded = MailboxPeerWireV2Codec.Encode(f.Sender.Crypto.SignRequest(peer, f.Signed.Node(f.Sender.Node.Node).Seed));
        }
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(client, encoded).AsTask()));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount);
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Recipient.ReplayFiles);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(0, f.PeerClient.Calls);
    }

    [Theory]
    [InlineData("expiry")]
    [InlineData("source-loss")]
    public async Task ClientStoreCallbackAuthorityLossCannotCompleteClientReplay(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var client = f.ClientStoreFrame(); var peer = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        f.RemoteHost.AfterReceive = response =>
        { if (defect == "expiry") f.Signed.Sample = 105; else f.Signed.RejectProof = true; return response; };
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(client, peer).AsTask()));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.CompletedCount);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        f.Signed.Sample = 100; f.Signed.RejectProof = false; f.RemoteHost.AfterReceive = null; f.Reopen();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, peer)).Status);
    }

    [Fact]
    public async Task CurrentPeerClientDeliversToPinnedEndpoint()
    {
        await using var f = await Fixture.CreateAsync();
        ReadOnlyMemory<byte>? reply = null;
        var error = await Record.ExceptionAsync(async () => reply = await new CurrentMailboxReplicaPeerClient().SendAsync(
            f.Recipient.Node.Replicas[0].Transport, MailboxPeerReplicationOperation.Store,
            f.Recipient.Frame(MailboxPeerReplicationOperation.Store), CancellationToken.None));
        Assert.True(error is null, $"Failure={error?.GetType().Name}; HTTP error={(error as HttpRequestException)?.HttpRequestError}; inner={error?.InnerException?.GetType().Name}.");
        Assert.NotNull(reply);
        Assert.Equal(MailboxWireHttpContract.PeerStore.MaximumResponseBytes, reply.Value.Length);
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
        Assert.Equal(1, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task TwoStoresThroughPinnedHttp2PersistReadTombstoneAndReopen()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var first = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.True(first.Status == MailboxPeerQuorumStatus.Durable,
            $"Quorum={first.Status}; peer calls={f.PeerClient.Calls}; failure={f.PeerClient.Failure}; HTTP requests={f.RemoteHost.Requests}; status={f.RemoteHost.LastStatus}; bytes={f.RemoteHost.LastBytes}; remote replay={f.Recipient.ReplayFiles.Length}.");
        Assert.Equal(2, first.DurableReplicaCount);
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(first.CanonicalMqr3.Span);
        Assert.NotEqual(quorum.FirstReplica.ReplicaId.ToArray(), quorum.SecondReplica.ReplicaId.ToArray());
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
        Assert.Equal(1, f.RemoteHost.Requests);
        f.Reopen();
        var retry = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.Equal(first.CanonicalMqr3.ToArray(), retry.CanonicalMqr3.ToArray());
        Assert.Equal(1, f.RemoteHost.Requests); // Completed native response, no second HTTP write.
        var tombstone = f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone);
        var removed = await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, removed.Status);
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
        f.Reopen();
        var replay = await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(removed.CanonicalMqr3.ToArray(), replay.CanonicalMqr3.ToArray());
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
    }

    [Fact]
    public async Task ConcurrentExactRetryHasOneRemoteWriteAndOneMutationPerStore()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store).AsTask()));
        Assert.All(results, result =>
        {
            Assert.Equal(MailboxPeerQuorumStatus.Durable, result.Status);
            Assert.Equal(2, result.DurableReplicaCount);
            Assert.Equal(results[0].CanonicalMqr3.ToArray(), result.CanonicalMqr3.ToArray());
        });
        Assert.Equal(1, f.RemoteHost.Requests); Assert.Equal(1, f.PeerClient.Calls);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Single(f.Sender.ReplayFiles); Assert.Single(f.Recipient.ReplayFiles);
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
    }

    [Fact]
    public async Task LostRemoteResponseLeavesSenderPendingAndExactReopenReconcilesBothStores()
    {
        await using var f = await Fixture.CreateAsync();
        f.RemoteHost.DropNext = true;
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var unknown = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, unknown.Status); Assert.True(unknown.CanonicalMqr3.IsEmpty);
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Sender.ReplayFiles)));
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(Assert.Single(f.Recipient.ReplayFiles)));
        f.Reopen();
        var resumed = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, resumed.Status); Assert.Equal(2, resumed.DurableReplicaCount);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(Assert.Single(f.Sender.ReplayFiles)));
        Assert.Equal(2, f.RemoteHost.Requests);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("duplicate-local")]
    [InlineData("expiry")]
    [InlineData("source-loss")]
    public async Task HostileOrExpiredHttpCallbackCannotProduceQuorum(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        f.RemoteHost.AfterReceive = response =>
        {
            if (defect == "signature") { var changed = response.ToArray(); changed[^1] ^= 1; return changed; }
            if (defect == "duplicate-local")
            {
                var remote = MailboxReceiptV2Codec.DecodeReplica(response.Span);
                var local = remote with { ReplicaId = f.Sender.Node.Node, Signature = new byte[64] };
                return MailboxReceiptV2Codec.EncodeReplica(f.Sender.Crypto.SignReplicaResponse(local,
                    f.Signed.Node(f.Sender.Node.Node).Seed));
            }
            if (defect == "expiry") f.Signed.Sample = 105;
            if (defect == "source-loss") f.Signed.RejectProof = true;
            return response;
        };
        if (defect is "expiry" or "source-loss")
            Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store).AsTask()));
        else
        {
            var rejected = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
            Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, rejected.Status); Assert.True(rejected.CanonicalMqr3.IsEmpty);
        }
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Sender.ReplayFiles)));
        f.Signed.Sample = 100; f.Signed.RejectProof = false; f.RemoteHost.AfterReceive = null;
        f.Reopen();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store)).Status);
    }

    [Fact]
    public async Task WrongSignedTlsPinCannotContactRemoteOrClaimQuorum()
    {
        await using var f = await Fixture.CreateAsync(wrongPin: true);
        var failed = await f.Coordinator.ReplicateAsync(f.Recipient.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, failed.Status); Assert.True(failed.CanonicalMqr3.IsEmpty);
        Assert.Equal(0, f.RemoteHost.Requests); Assert.Empty(f.Recipient.ReplayFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Sender.ReplayFiles)));
    }

    [Fact]
    public async Task PeerEndpointRejectsWrongOperationAndMediaBeforeMutation()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        using var client = new HttpClient(HttpPrivacyPeerClient.CreatePinnedHandler(f.Recipient.Node.Replicas[0].Transport));
        foreach (var defect in new[] { "operation", "media" })
        {
            using var content = new ByteArrayContent(exact);
            content.Headers.ContentType = new MediaTypeHeaderValue(defect == "media" ? "application/json" : MailboxWireHttpContract.Prq2ContentType);
            var route = defect == "operation" ? MailboxWireHttpContract.PeerTombstoneRoute : MailboxWireHttpContract.PeerStoreRoute;
            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://127.0.0.1:{f.RemoteHost.Port}{route}")
            { Content = content, Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
            using var response = await client.SendAsync(request);
            Assert.Equal(defect == "media" ? HttpStatusCode.UnsupportedMediaType : HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync());
            Assert.Empty(f.Recipient.ReplayFiles); Assert.Empty(f.Recipient.MutationFiles);
        }
    }

    private static byte Status(string path)
    { using var json = JsonDocument.Parse(File.ReadAllBytes(path)); return json.RootElement.GetProperty("status").GetByte(); }

    private sealed class Fixture : IAsyncDisposable
    {
        internal DeepIdV2PublicationAuthorityFixture Signed = null!;
        private readonly List<Host> hosts = [];
        internal Host RemoteHost = null!;
        internal Peer Sender = null!, Recipient = null!;
        internal CurrentMailboxReplicationCoordinator Coordinator = null!;
        internal ObservedPeerClient PeerClient = new();
        internal MailboxClientOperationLedger? Ledger;
        private const string IntentDirectory = "mailbox-client-intent";
        private int intentEntries = 100_000;
        internal string LedgerFile => Path.Combine(Sender.Node.DataRoot, IntentDirectory, "operations.json");
        internal byte[][] ExactIntents
        {
            get
            {
                if (!File.Exists(LedgerFile)) return [];
                using var document = JsonDocument.Parse(File.ReadAllBytes(LedgerFile));
                return document.RootElement.GetProperty("operations").EnumerateObject()
                    .Select(item => Convert.FromBase64String(item.Value.GetProperty("peerRequest").GetString()!)).ToArray();
            }
        }
        internal void OpenLedger(IMailboxDurabilityBarrier? durability = null, int? maximumEntries = null)
        {
            Ledger?.Dispose();
            if (maximumEntries is not null) intentEntries = maximumEntries.Value;
            Ledger = new(Sender.Node.DataRoot, new MailboxClientAdapterOptions
            {
                DirectoryName = IntentDirectory,
                MaxOperationEntries = intentEntries,
                MaxCursorAuthorities = Math.Min(4096, intentEntries),
                MaxConcurrentSingleFlights = Math.Min(1024, intentEntries)
            },
                clock: new NoUtcIntentClock(), durability: durability);
        }
        internal static async Task<Fixture> CreateAsync(bool wrongPin = false)
        {
            var f = new Fixture();
            try
            {
                for (var i = 0; i < 3; i++) f.hosts.Add(await Host.CreateAsync());
                var origins = f.hosts.Select(host => new DeepIdV2PublicationAuthorityFixture.TransportOrigin(
                    IPAddress.Loopback, checked((ushort)host.Port), wrongPin ? SHA256.HashData(host.Pin) : host.Pin, SHA256.HashData(host.Pin))).ToArray();
                // The next pin must remain distinct even in the intentionally wrong-current-pin case.
                if (wrongPin) origins = origins.Select(origin => origin with { NextSpki = SHA256.HashData(origin.NextSpki.Span) }).ToArray();
                f.Signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(transportOrigins: origins);
                f.Recipient = await Peer.CreateAsync(f.Signed, 0); f.Sender = await Peer.CreateAsync(f.Signed, 1);
                f.RemoteHost = f.hosts.Single(host => host.Port == f.Recipient.Node.Replicas[0].Transport.Port);
                f.Bind(); return f;
            }
            catch { await f.DisposeAsync(); throw; }
        }
        internal void Bind()
        {
            RemoteHost.Endpoint = new(Recipient.Receiver, RemoteHost.Port);
            Coordinator = new(Sender.Receiver, PeerClient, new ReplicatedMailboxOptions { Enabled = true });
        }
        internal byte[] ClientStoreFrame(byte[]? envelope = null, ulong counter = 1)
        {
            var binding = MailboxAuthenticatedRequestTranscript.ForStore(MailboxAuthenticatedRequestTranscript.DecodeStoreBody(envelope ?? Recipient.Envelope));
            var crypto = new SodiumMailboxCapabilityCrypto();
            return MailboxAuthenticatedClientRequestCodec.Encode(new()
            {
                Binding = binding,
                Presentation = crypto.SignPresentation(MailboxAuthenticatedCapabilityCodec.DecodeGrant(Sender.Node.ExactGrant),
                    binding, counter, Enumerable.Repeat((byte)0x57, 32).ToArray())
            });
        }
        internal void Reopen()
        {
            var hadLedger = Ledger is not null; Ledger?.Dispose(); Ledger = null;
            Sender.Node.ReopenRuntime(); Recipient.Node.ReopenRuntime(); Sender.Reopen(); Recipient.Reopen();
            if (hadLedger) OpenLedger(); Bind();
        }
        public async ValueTask DisposeAsync()
        {
            foreach (var host in hosts) await host.DisposeAsync();
            Ledger?.Dispose();
            if (Sender is not null) await Sender.DisposeAsync(); if (Recipient is not null) await Recipient.DisposeAsync();
            Signed?.Dispose();
        }
    }

    private sealed class NoUtcIntentClock : IClock
    { public DateTimeOffset UtcNow => throw new InvalidOperationException("Current intent must not use host UTC."); }

    private sealed class IntentWriteCallback(Action callback) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new();
        public void FlushFileAndParentDirectory(string path) { native.FlushFileAndParentDirectory(path); callback(); }
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
        public void ReplaceFile(string temporaryPath, string finalPath) => native.ReplaceFile(temporaryPath, finalPath);
    }

    private sealed class IntentWriteFault(bool beforeReplace) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new();
        public void FlushFileAndParentDirectory(string path)
        { native.FlushFileAndParentDirectory(path); if (!beforeReplace) throw new IOException("Test-owned durable intent failure."); }
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (beforeReplace) throw new IOException("Test-owned intent replace failure.");
            native.ReplaceFile(temporaryPath, finalPath);
        }
    }

    private sealed class ReplayCompletionWriteFault : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new();
        internal bool Armed;
        internal int Failures;
        public void FlushFileAndParentDirectory(string path) => native.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (Armed) { Failures++; throw new IOException("Test-owned replay completion write failure."); }
            native.ReplaceFile(temporaryPath, finalPath);
        }
    }

    private sealed class ObservedPeerClient : ICurrentMailboxReplicaPeerClient
    {
        internal int Calls;
        internal readonly List<byte[]> ExactRequests = [];
        internal string? Failure;
        public async ValueTask<ReadOnlyMemory<byte>?> SendAsync(VerifiedOnionNextHopTransport recipient,
            MailboxPeerReplicationOperation operation, ReadOnlyMemory<byte> exactRequest, CancellationToken token)
        {
            Calls++;
            ExactRequests.Add(exactRequest.ToArray());
            try { return await new CurrentMailboxReplicaPeerClient().SendAsync(recipient, operation, exactRequest, token); }
            catch (Exception error)
            {
                Failure = $"{error.GetType().Name}/{(error as HttpRequestException)?.HttpRequestError}/{error.InnerException?.GetType().Name}";
                throw;
            }
        }
    }

    private sealed class Host : IAsyncDisposable
    {
        private WebApplication app = null!;
        private X509Certificate2 certificate = null!;
        internal int Port, Requests, LastStatus, LastBytes;
        internal byte[] Pin = [];
        internal CurrentMailboxPeerHttpEndpoint? Endpoint;
        internal bool DropNext;
        internal Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>? AfterReceive;
        internal static async Task<Host> CreateAsync()
        {
            var host = new Host(); using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            using var issued = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            // Windows Schannel needs an imported key handle, not the ephemeral
            // CertificateRequest key. DefaultKeySet deletes the imported test
            // key with the certificate; no operator store/import is used.
            var pfx = issued.Export(X509ContentType.Pfx);
            try { host.certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.DefaultKeySet); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
            host.Pin = SHA256.HashData(host.certificate.PublicKey.ExportSubjectPublicKeyInfo());
            var builder = WebApplication.CreateSlimBuilder(); builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
                listen => { listen.Protocols = HttpProtocols.Http2; listen.UseHttps(host.certificate); }));
            host.app = builder.Build();
            foreach (var operation in new[] { MailboxPeerReplicationOperation.Store, MailboxPeerReplicationOperation.Tombstone })
            {
                var contract = operation == MailboxPeerReplicationOperation.Store ? MailboxWireHttpContract.PeerStore : MailboxWireHttpContract.PeerTombstone;
                host.app.MapPost(contract.Route, async (HttpContext context, CancellationToken token) =>
                {
                    Interlocked.Increment(ref host.Requests);
                    if (host.Endpoint is null) return Results.StatusCode(503);
                    // Capture the actual product endpoint's bytes so only test-owned
                    // network fault injection changes/drops the outgoing response.
                    var original = context.Response.Body; using var captured = new MemoryStream(); context.Response.Body = captured;
                    var result = await host.Endpoint.HandleAsync(context, contract, operation, token);
                    await result.ExecuteAsync(context); context.Response.Body = original;
                    host.LastStatus = context.Response.StatusCode; host.LastBytes = checked((int)captured.Length);
                    if (host.DropNext && context.Response.StatusCode == 200) { host.DropNext = false; context.Abort(); return Results.Empty; }
                    var bytes = captured.ToArray();
                    if (context.Response.StatusCode != 200) return Results.StatusCode(context.Response.StatusCode);
                    var response = host.AfterReceive?.Invoke(bytes) ?? bytes;
                    return Results.Bytes(response.ToArray(), contract.ResponseContentType);
                });
            }
            await host.app.StartAsync();
            host.Port = new Uri(host.app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()).Port;
            return host;
        }
        public async ValueTask DisposeAsync()
        { if (app is not null) { await app.StopAsync(); await app.DisposeAsync(); } certificate?.Dispose(); }
    }
}
