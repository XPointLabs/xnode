using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task StoreExpiryPreservesOriginalAndAllowsLaterCursorWithoutLateCompletion(bool mutation, bool reopen)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.Sender.Node.ExactGrant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host,
            MailboxCapabilityDomain.Deposit, 0x51, expires: 1106);
        var originalClient = f.ClientStoreFrame();
        if (mutation) f.Sender.Fault.Action = point =>
        { if (point == MailboxPeerMutationFaultPoint.StoreReserved) throw new IOException("Test-owned Pending interruption."); };
        else f.OpenLedger(new IntentWriteFault(beforeReplace: false));
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(originalClient).AsTask());
        f.Sender.Fault.Action = null;
        if (reopen) f.Reopen(); else if (!mutation) f.OpenLedger();
        var original = Assert.Single(f.ExactIntents);
        var first = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!["operations"]!.AsObject().Single();
        var originalRow = first.Value!.ToJsonString();
        var pendingFile = mutation ? Assert.Single(f.Sender.MutationFiles) : null;
        var pendingBytes = pendingFile is null ? null : File.ReadAllBytes(pendingFile);
        f.Signed.Sample = 101; // [1096,1106]: original admission lost, exclusion not yet proven.
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Coordinator.StoreClientAsync(DifferentGrantStore(f, expires: 1120)).AsTask());
        Assert.Single(f.ExactIntents); Assert.Equal(0, f.AllHttpRequests);
        f.Signed.Sample = 111; // [1106,1116]: exact lower boundary, independently current host.
        var empty = ExpiryPage(await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, grantExpiry: 1120)), f);
        Assert.Empty(empty.Items); // Not settlement or evidence of no possible past remote effect.
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(DifferentGrantStore(f, expires: 1120))).Status);
        Assert.Equal(new ulong[] { 1, 2 }, f.ExactIntents.Select(bytes => MailboxPeerWireV2Codec.Decode(bytes).Cursor));
        var old = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!["operations"]![first.Key]!;
        Assert.Equal(originalRow, old.ToJsonString());
        Assert.Equal(original, f.ExactIntents.Single(bytes => MailboxPeerWireV2Codec.Decode(bytes).Cursor == 1));
        if (pendingFile is not null) Assert.Equal(pendingBytes, File.ReadAllBytes(pendingFile));
        var http = f.AllHttpRequests;
        await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.StoreClientAsync(originalClient).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => f.Recipient.Receiver.ReceiveAsync(original,
            MailboxPeerReplicationOperation.Store).AsTask());
        Assert.Equal(http, f.AllHttpRequests);
        f.Reopen(); f.Signed.Sample = 111;
        foreach (var receiver in new[] { f.Sender.Receiver, f.Recipient.Receiver })
        {
            var page = ExpiryPage(await receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 2, operation: 0x76, grantExpiry: 1120)), f);
            Assert.Equal(2UL, Assert.Single(page.Items).Cursor);
        }
    }

    [Theory]
    [InlineData("missing-quorum")]
    [InlineData("corrupt-quorum")]
    [InlineData("bad-original")]
    public async Task StoreExpiryCannotLaunderBrokenDurableCustody(string defect)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.Sender.Node.ExactGrant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host,
            MailboxCapabilityDomain.Deposit, 0x51, expires: 1106);
        _ = await f.Coordinator.StoreClientAsync(f.ClientStoreFrame());
        var document = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!;
        var row = document["operations"]!.AsObject().Single().Value!;
        if (defect == "missing-quorum") row["receipt"] = "";
        else if (defect == "corrupt-quorum")
        { var quorum = Convert.FromBase64String(row["receipt"]!.GetValue<string>()); quorum[^1] ^= 1; row["receipt"] = Convert.ToBase64String(quorum); }
        else
        {
            var peer = MailboxPeerWireV2Codec.Decode(Convert.FromBase64String(row["peerRequest"]!.GetValue<string>()));
            var signature = peer.Signature.ToArray(); signature[^1] ^= 1;
            row["peerRequest"] = Convert.ToBase64String(MailboxPeerWireV2Codec.Encode(peer with { Signature = signature }));
        }
        await f.InstallTestOwnedDocumentAsync(System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
        f.Reopen(); f.Signed.Sample = 111;
        var before = File.ReadAllBytes(f.LedgerFile); var http = f.AllHttpRequests;
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(DifferentGrantStore(f, expires: 1120)).AsTask()));
        Assert.Equal(before, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(http, f.AllHttpRequests);
        Assert.Single(f.ExactIntents);
    }

    [Fact]
    public async Task StoreExpiryCannotTurnMissingRemoteOriginalIntoEmptyMailbox()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.Sender.Node.ExactGrant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host,
            MailboxCapabilityDomain.Deposit, 0x51, expires: 1106);
        f.Recipient.Fault.Action = point =>
        { if (point == MailboxPeerMutationFaultPoint.StoreReserved) throw new IOException("Test-owned remote Pending interruption."); };
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        f.Recipient.Fault.Action = null;
        var pending = File.ReadAllBytes(Assert.Single(f.Recipient.MutationFiles));
        f.Reopen(); f.Signed.Sample = 111;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, grantExpiry: 1120)).AsTask());
        Assert.Equal(pending, File.ReadAllBytes(Assert.Single(f.Recipient.MutationFiles)));
        // Local completed object remains readable even without quorum custody.
        Assert.Single(ExpiryPage(await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, grantExpiry: 1120)), f).Items);
    }

    [Fact]
    public async Task StoreExpiryCannotSkipPendingOnObjectUpperTimeOverlap()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.Sender.Node.ExactGrant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host,
            MailboxCapabilityDomain.Deposit, 0x51, expires: 1106);
        f.Sender.Fault.Action = point =>
        { if (point == MailboxPeerMutationFaultPoint.StoreReserved) throw new IOException("Test-owned Pending interruption."); };
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with
        { CreatedAtUnixSeconds = 1048, ExpiresAtUnixSeconds = 1108 }; // Canonical minimum60s object, already created before Store.
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(
            f.ClientStoreFrame(MailboxClientCodec.EncodeEncryptedEnvelope(body))).AsTask());
        f.Sender.Fault.Action = null;
        var pending = File.ReadAllBytes(Assert.Single(f.Sender.MutationFiles));
        f.Reopen(); f.Signed.Sample = 103; // [1098,1108]: object upper overlap is not original-grant exclusion.
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f)).AsTask());
        Assert.Equal(pending, File.ReadAllBytes(Assert.Single(f.Sender.MutationFiles)));
    }

    [Fact]
    public async Task StoreExpiryRechecksEarlierPendingAfterLaterBlobCallback()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.Sender.Node.ExactGrant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host,
            MailboxCapabilityDomain.Deposit, 0x51, expires: 1106);
        f.Sender.Fault.Action = point =>
        { if (point == MailboxPeerMutationFaultPoint.StoreReserved) throw new IOException("Test-owned Pending interruption."); };
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(f.ClientStoreFrame()).AsTask());
        f.Sender.Fault.Action = null; var pending = Assert.Single(f.Sender.MutationFiles);
        f.Signed.Sample = 111;
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(DifferentGrantStore(f, expires: 1120))).Status);
        var callbacks = 0;
        f.Sender.Fault.Action = point =>
        {
            if (point != MailboxPeerMutationFaultPoint.RetrieveBlobRead) return;
            callbacks++;
            var changed = JsonNode.Parse(File.ReadAllBytes(pending))!; changed["state"] = "completed";
            File.WriteAllText(pending, changed.ToJsonString()); // Hostile test producer, not runtime recovery.
        };
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, grantExpiry: 1120)).AsTask());
        Assert.Equal(1, callbacks);
    }

    private static MailboxRetrievePage ExpiryPage(ReadOnlyMemory<byte> bytes, Fixture f) =>
        MailboxClientCodec.DecodeRetrievePage(bytes.Span, new()
        {
            NowUnixSeconds = checked(f.Signed.Freshness.TrustedUpperUnixSeconds + f.Signed.Sample - f.Signed.Freshness.MonotonicSample),
            EpochWindow = new()
            {
                CurrentEpoch = f.Sender.Node.Host.SelectionEpoch, CurrentNotBeforeUnixSeconds = 1090,
                CurrentExpiresAtUnixSeconds = 1120, NextEpoch = 0,
                NextNotBeforeUnixSeconds = 0, NextExpiresAtUnixSeconds = 0
            },
            CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = 1 }
        });
}
