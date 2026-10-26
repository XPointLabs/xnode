using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using static XNode.IntegrationTests.Runtime.MailboxGrantRevocationStoreTests;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxReplicaReceiverTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(1000)]
    [InlineData(10000)]
    public async Task StoreIntentCustodyReadSegmentHasTwoActualChecksAtEveryNativePrefixSize(int count)
    {
        await using var f = await Fixture.CreateAsync();
        var corpus = await InstallSyntheticNativePrefixAsync(f, count);
        await f.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            var reads = f.Node.Signed.PublicationReads;
            CurrentMailboxDiagnostics.WorkSummary? work = null;
            using (CurrentMailboxDiagnostics.BeginWork(result => work = result))
                await f.Mutations.RequireCurrentStoreIntentCustodyAsync(corpus.Next,
                    corpus.Membership, corpus.Document, scope.Lease, token);
            Assert.Equal(2, work!.LeaseChecks);
            Assert.Equal(2, f.Node.Signed.PublicationReads - reads);
            Assert.Equal(count, f.MutationFiles.Length);
            return true;
        });
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("same-length")]
    [InlineData("missing-intent")]
    public async Task StoreIntentCustodyReadSegmentStillReadsAndJoinsTheMiddleNativeRecord(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var corpus = await InstallSyntheticNativePrefixAsync(f, 5);
        var path = corpus.Paths[2]; var original = File.ReadAllBytes(path);
        if (defect == "missing") File.Delete(path);
        else if (defect == "same-length")
        {
            var changed = JsonNode.Parse(original)!;
            changed["operationId"] = Convert.ToHexStringLower(Unique(16, 900));
            var encoded = JsonSerializer.SerializeToUtf8Bytes(changed, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.Equal(original.Length, encoded.Length);
            File.WriteAllBytes(path, encoded);
        }
        else corpus.Document.Operations.Remove(corpus.Document.Operations.Single(pair => pair.Value.Cursor == 3).Key);
        var damaged = File.Exists(path) ? File.ReadAllBytes(path) : null;
        await f.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Mutations.RequireCurrentStoreIntentCustodyAsync(
                corpus.Next, corpus.Membership, corpus.Document, scope.Lease, token));
            return true;
        });
        if (damaged is null) Assert.False(File.Exists(path)); else Assert.Equal(damaged, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData("revoked-floor")]
    [InlineData("missing-floor")]
    [InlineData("cancel")]
    [InlineData("expiry")]
    public async Task StoreIntentCustodyReadSegmentFinalActualCheckRejectsChanges(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var corpus = await InstallSyntheticNativePrefixAsync(f, 5);
        var floorPath = f.Node.DepositFloorFile;
        var anchorPath = Path.Combine(Path.GetDirectoryName(floorPath)!, "anchor.bin");
        var floor = File.ReadAllBytes(floorPath); var anchor = File.ReadAllBytes(anchorPath);
        var prior = (await f.Node.Deposit.ReadProtectedAsync()).ToArray();
        var revoked = Snapshot(f.Node.Signed, generation: 2, prior: prior, serials: [Bytes(16, 0x51)]);
        var native = corpus.Paths.Select(File.ReadAllBytes).ToArray();
        var intent = JsonSerializer.SerializeToUtf8Bytes(corpus.Document);
        using var cancellation = new CancellationTokenSource();
        await f.Node.Admission.WithGrantAsync(f.Node.ExactGrant, MailboxCapabilityDomain.Deposit, async (scope, token) =>
        {
            var checks = 0;
            var guarded = new MailboxCurrentOperationLease(async ct =>
            {
                if (++checks == 2)
                {
                    if (defect == "revoked-floor")
                    {
                        var provider = DataProtectionProvider.Create(new DirectoryInfo(f.Node.ProtectionRoot),
                            builder => builder.SetApplicationName("XPoint.XNode.MGR1.NativeTests.v1"));
                        var custodyScope = Path.GetFileName(Path.GetDirectoryName(floorPath))!;
                        File.WriteAllBytes(floorPath, provider.CreateProtector("Deep.XNode.MGR1.Floor.v1", custodyScope).Protect(revoked));
                        File.WriteAllBytes(anchorPath, provider.CreateProtector("Deep.XNode.MGR1.Anchor.v1", custodyScope).Protect(revoked));
                    }
                    else if (defect == "missing-floor") File.Delete(floorPath);
                    else if (defect == "cancel") cancellation.Cancel();
                    else f.Node.Signed.Sample = 105;
                }
                return await scope.Lease.CheckAsync(ct);
            }, scope.Lease.RequireActive);
            try
            {
                var error = await Record.ExceptionAsync(() => f.Mutations.RequireCurrentStoreIntentCustodyAsync(
                    corpus.Next, scope.Grant.MembershipCommitment, corpus.Document, guarded, cancellation.Token));
                if (defect == "cancel") Assert.IsAssignableFrom<OperationCanceledException>(error);
                else if (defect == "missing-floor")
                    Assert.Equal("MGR1 protected enrollment/floor/anchor are missing, split or rolled back.",
                        Assert.IsType<InvalidDataException>(error).Message);
                else if (defect == "revoked-floor")
                    Assert.Equal("The MGR1 capability is not the current protected floor.",
                        Assert.IsType<CryptographicException>(error).Message);
                else
                {
                    Assert.IsType<CryptographicException>(error);
                    Assert.Equal("GrantExpiry", CurrentMailboxDiagnostics.AuthorityFailureCheck(error));
                }
                Assert.Equal(2, checks);
                Assert.Equal(intent, JsonSerializer.SerializeToUtf8Bytes(corpus.Document));
                for (var index = 0; index < corpus.Paths.Length; index++)
                    Assert.Equal(native[index], File.ReadAllBytes(corpus.Paths[index]));
            }
            finally
            {
                f.Node.Signed.Sample = 100;
                File.WriteAllBytes(floorPath, floor); File.WriteAllBytes(anchorPath, anchor);
                new MailboxStorageSecurity().SecureFile(floorPath); new MailboxStorageSecurity().SecureFile(anchorPath);
            }
            // The failed walk also released its native owner.
            await f.Mutations.RequireCurrentStoreIntentCustodyAsync(corpus.Next,
                scope.Grant.MembershipCommitment, corpus.Document, scope.Lease, token);
            return true;
        });
    }

    [Fact]
    public async Task StoreIntentCustodyReadSegmentKeepsOriginalCursorRecoveryScope()
    {
        await using var f = await Fixture.CreateAsync();
        var corpus = await InstallSyntheticNativePrefixAsync(f, 5);
        File.Delete(corpus.Paths[2]); // unrelated loss must still block NEW allocation
        var original = corpus.Document.Operations.Values.Single(value => value.Cursor == 1);
        var request = MailboxPeerWireV2Codec.Decode(Convert.FromBase64String(original.PeerRequest));
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Payload.Span);
        await f.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            await f.Mutations.RequireCurrentStoreIntentCustodyAsync(envelope,
                corpus.Membership, corpus.Document, scope.Lease, token);
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Mutations.RequireCurrentStoreIntentCustodyAsync(corpus.Next,
                corpus.Membership, corpus.Document, scope.Lease, token));
            return true;
        });
    }

    private sealed record NativePrefixCorpus(MailboxClientLedgerDocument Document, MailboxEncryptedEnvelope Next,
        ReadOnlyMemory<byte> Membership, string[] Paths);

    // Isolated native reader scaling only, not complete recovered host/RPC
    // authority. One genuine Store supplies framing. The synthetic records use
    // canonical request/body/hash bindings and copied signatures, with no 10k
    // signers, network mutations or fsync setup. Real RPC integration is separate.
    private static async Task<NativePrefixCorpus> InstallSyntheticNativePrefixAsync(Fixture f, int count)
    {
        await f.Receiver.ReceiveAsync(f.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store);
        var path = Assert.Single(f.MutationFiles); var mutation = JsonNode.Parse(File.ReadAllBytes(path))!;
        var directory = Path.GetDirectoryName(path)!; File.Delete(path);
        var baseline = MailboxPeerWireV2Codec.Decode(f.Frame(MailboxPeerReplicationOperation.Store));
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Envelope);
        var document = new MailboxClientLedgerDocument(8, 0, 0, new(), new(), new(), new(), new());
        var paths = new string[count];
        for (var index = 0; index < count; index++)
        {
            var ordinal = checked((ulong)index + 1);
            var envelope = body with { OperationId = Unique(16, ordinal), DeduplicationDigest = Unique(32, ordinal) };
            var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
            var peer = baseline with
            {
                OperationId = envelope.OperationId, Cursor = ordinal, ReplayNonce = Unique(32, ordinal),
                Payload = binding.CanonicalRequest, PayloadDigest = SHA256.HashData(binding.CanonicalRequest.Span)
            };
            var exact = MailboxPeerWireV2Codec.Encode(peer);
            var mailbox = Convert.ToHexStringLower(peer.BlindedMailboxId.Span);
            var operation = Convert.ToHexStringLower(peer.OperationId.Span);
            var digest = Convert.ToHexStringLower(envelope.DeduplicationDigest.Span);
            var blob = Convert.ToHexStringLower(peer.PayloadDigest.Span);
            mutation["cursor"] = ordinal; mutation["operationId"] = operation; mutation["envelopeDigest"] = digest;
            mutation["replayNonce"] = Convert.ToHexStringLower(peer.ReplayNonce.Span); mutation["blobId"] = blob;
            paths[index] = Path.Combine(directory, MailboxPeerMutationStore.RecordKey(peer.Epoch,
                peer.BlindedMailboxId.Span, envelope.DeduplicationDigest.Span) + ".json");
            File.WriteAllBytes(paths[index], JsonSerializer.SerializeToUtf8Bytes(mutation, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            document.Operations.Add(MailboxClientOperationLedger.BuildOperationKey(peer.Epoch, peer.BlindedMailboxId.Span, peer.OperationId.Span),
                new(peer.Epoch, mailbox, operation, Convert.ToHexStringLower(binding.RequestDigest.Span), digest, blob,
                    Convert.ToHexStringLower(peer.PlacementCommitment.Span), Convert.ToHexStringLower(peer.MembershipCommitment.Span),
                    [Convert.ToHexStringLower(peer.SenderRouterId.Span), Convert.ToHexStringLower(peer.RecipientRouterId.Span)],
                    ordinal, peer.ExpiresAtUnixSeconds, "reserved", "", 0, "", 0, "", "", "", false, 0, false, Convert.ToBase64String(exact)));
        }
        f.Reopen(); // actual native index reads/hashes/validates each bounded file's grammar
        await f.Node.Signed.RefreshNetworkProofAsync(100, 1_100); // genuine proof after cold fixture setup
        return new(document, body with { OperationId = Unique(16, checked((ulong)count + 100)),
            DeduplicationDigest = Unique(32, checked((ulong)count + 100)) }, baseline.MembershipCommitment, paths);
    }

    private static byte[] Unique(int length, ulong value)
    {
        var bytes = new byte[length]; BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(length - 8), value); return bytes;
    }
}
