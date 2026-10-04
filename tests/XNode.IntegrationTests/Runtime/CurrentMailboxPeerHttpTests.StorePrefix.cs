using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CurrentStoreDifferentGrantCannotPassIntentBeforeOrAfterLocalMutation(bool mutation, bool reopen)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var original = f.ClientStoreFrame();
        if (mutation)
            f.Sender.Fault.Action = point => { if (point == XNode.Core.Mailbox.MailboxPeerMutationFaultPoint.StoreReserved) throw new IOException("Test-owned pending mutation."); };
        else
            f.OpenLedger(new IntentWriteFault(beforeReplace: false));
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(original, f.Ledger!).AsTask());
        f.Sender.Fault.Action = null;
        if (reopen) f.Reopen(); else if (!mutation) f.OpenLedger();
        var next = DifferentGrantStore(f);
        var before = File.ReadAllBytes(f.LedgerFile);
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Coordinator.StoreClientAsync(next, f.Ledger!).AsTask());
        Assert.Equal(before, File.ReadAllBytes(f.LedgerFile));
        Assert.Single(f.ExactIntents); Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
        Assert.Equal(XNode.Core.Mailbox.MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(original, f.Ledger!)).Status);
        Assert.Equal(XNode.Core.Mailbox.MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(next, f.Ledger!)).Status);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        Assert.Equal(new ulong[] { 1, 2 }, page.Items.Select(item => item.Cursor));
        Assert.Equal(2, f.AllHttpRequests);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("unsigned-durable")]
    [InlineData("other-intent")]
    public async Task CurrentStoreHostileSavedSettlementCannotAdvancePrefix(string defect)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var first = await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!);
        var doc = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!;
        var item = doc["operations"]!.AsObject().Single().Value!;
        var quorum = first.CanonicalMqr3.ToArray();
        if (defect == "signature") quorum[^1] ^= 1;
        if (defect == "other-intent")
        {
            var peer = MailboxPeerWireV2Codec.Decode(Convert.FromBase64String(item["peerRequest"]!.GetValue<string>()));
            var nonce = peer.ReplayNonce.ToArray(); nonce[^1] ^= 1;
            item["peerRequest"] = Convert.ToBase64String(MailboxPeerWireV2Codec.Encode(
                f.Sender.Crypto.SignRequest(peer with { ReplayNonce = nonce }, f.Recipient.SenderSeed)));
        }
        item["receipt"] = defect == "unsigned-durable" ? "" : Convert.ToBase64String(quorum);
        await f.InstallTestOwnedDocumentAsync(System.Text.Encoding.UTF8.GetBytes(doc.ToJsonString())); f.Reopen();
        var before = File.ReadAllBytes(f.LedgerFile);
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.StoreClientAsync(DifferentGrantStore(f), f.Ledger!).AsTask()));
        Assert.Equal(before, File.ReadAllBytes(f.LedgerFile)); Assert.Single(f.ExactIntents);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles); Assert.Equal(1, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentStoreSettlementAuthenticatesExpiredGrantWithoutRestoringAdmissionAuthority()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = f.ClientStoreFrame(); var stored = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        var peer = Assert.Single(f.ExactIntents); f.Signed.Sample = 105;
        await f.Sender.Node.Host.VerifyStoreSettlementAsync(peer, stored.CanonicalMqr3);
        var grant = MailboxAuthenticatedClientRequestCodec.Decode(client).Presentation.Grant;
        await Assert.ThrowsAsync<CryptographicException>(() => f.Sender.Node.Host.EnsureGrantCurrentAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask());
        Assert.Single(f.ExactIntents); Assert.Equal(1, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentStoreQuorumPersistenceFailureRecoversOriginalIntentWithoutNewHttp(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(new SettlementWriteFault(beforeReplace));
        var client = f.ClientStoreFrame();
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(client, f.Ledger!).AsTask());
        Assert.Equal(1, f.Sender.Node.OutcomeCount); Assert.Equal(1, f.AllHttpRequests);
        var exact = Assert.Single(f.ExactIntents); f.Reopen();
        Assert.Equal(XNode.Core.Mailbox.MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, f.Ledger!)).Status);
        Assert.Equal(exact, Assert.Single(f.ExactIntents)); Assert.Equal(1, f.AllHttpRequests);
        Assert.Equal(XNode.Core.Mailbox.MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(DifferentGrantStore(f), f.Ledger!)).Status);
        Assert.Equal(2, f.AllHttpRequests);
    }

    private sealed class SettlementWriteFault(bool beforeReplace) : XNode.Core.Mailbox.IMailboxDurabilityBarrier
    {
        private readonly XNode.Core.Mailbox.MailboxDurabilityBarrier native = new(); private bool firstFlushed;
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (firstFlushed && beforeReplace) throw new IOException("Test-owned pre-settlement replace failure.");
            native.ReplaceFile(temporaryPath, finalPath);
        }
        public void FlushFileAndParentDirectory(string path)
        {
            native.FlushFileAndParentDirectory(path);
            if (firstFlushed && !beforeReplace) throw new IOException("Test-owned post-settlement flush failure.");
            firstFlushed = true;
        }
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
    }

    private static byte[] DifferentGrantStore(Fixture f)
    {
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with
        { OperationId = Enumerable.Repeat((byte)0x82, 16).ToArray(), DeduplicationDigest = Enumerable.Repeat((byte)0x92, 32).ToArray() };
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(body);
        var grant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host, MailboxCapabilityDomain.Deposit, 0x62);
        return MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding,
            Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(
                MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant), binding, 1, Enumerable.Repeat((byte)0x57, 32).ToArray())
        });
    }

    private static byte[] PeerForClient(Fixture f, byte[] client, ulong cursor)
    {
        var request = MailboxAuthenticatedClientRequestCodec.Decode(client);
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Binding.CanonicalRequest.Span);
        var baseline = MailboxPeerWireV2Codec.Decode(f.Recipient.Frame(MailboxPeerReplicationOperation.Store));
        byte[] proof = [.. f.Sender.Node.Host.ProjectionReference.Span, .. MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant)];
        return MailboxPeerWireV2Codec.Encode(f.Sender.Crypto.SignRequest(baseline with
        {
            OperationId = envelope.OperationId, Cursor = cursor, ReplayNonce = RandomNumberGenerator.GetBytes(32),
            Payload = request.Binding.CanonicalRequest, PayloadDigest = SHA256.HashData(request.Binding.CanonicalRequest.Span),
            SenderMembershipProof = baseline.SenderMembershipProof with { CanonicalInclusionProof = proof },
            RecipientMembershipProof = baseline.RecipientMembershipProof with { CanonicalInclusionProof = proof }
        }, f.Recipient.SenderSeed));
    }
}
