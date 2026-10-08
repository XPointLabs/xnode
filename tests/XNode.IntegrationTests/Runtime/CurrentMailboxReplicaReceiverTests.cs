using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.ContactV1;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using static XNode.IntegrationTests.Runtime.MailboxGrantRevocationStoreTests;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Actual signed current peer proofs, native replay/blob/mutation
/// custody and descriptor-key receipt. Not HTTP/TLS, quorum or device evidence.</summary>
public sealed class CurrentMailboxReplicaReceiverTests
{
    [Fact]
    public async Task CorrectlySignedNonWriterPeerStoreRejectsBeforeReplayAndMutationAfterReopen()
    {
        // Both proof keys and the peer signature are genuine. Only rank is wrong.
        await using var f = await Fixture.CreateAsync(localReplicaIndex: 0);
        var exact = f.Frame(MailboxPeerReplicationOperation.Store);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            await Assert.ThrowsAsync<CryptographicException>(() => f.Receiver.ReceiveAsync(exact,
                MailboxPeerReplicationOperation.Store).AsTask());
            Assert.Empty(f.ReplayFiles); Assert.Empty(f.MutationFiles); Assert.Null(await f.ReadBlobAsync());
            f.Reopen();
        }
    }

    [Fact]
    public async Task StoreReadTombstoneAndExactReplaysUseNativeCurrentCustodyWithoutUtc()
    {
        await using var f = await Fixture.CreateAsync();
        var store = f.Frame(MailboxPeerReplicationOperation.Store);
        var response = await f.Receiver.ReceiveAsync(store, MailboxPeerReplicationOperation.Store);
        var receipt = MailboxReceiptV2Codec.DecodeReplica(response.Span);
        Assert.Equal(MailboxReplicaDisposition.Stored, receipt.Disposition);
        Assert.True(f.Crypto.Verify(f.Node.Replicas.Single(replica => replica.NodeId.Span.SequenceEqual(f.Node.Node)).SigningPublicKey.Span,
            MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt), receipt.Signature.Span));
        Assert.Equal(f.Envelope, (await f.ReadBlobAsync())!);
        f.Reopen();
        Assert.Equal(response.ToArray(), (await f.Receiver.ReceiveAsync(store, MailboxPeerReplicationOperation.Store)).ToArray());
        var tombstone = f.Frame(MailboxPeerReplicationOperation.Tombstone);
        var removed = await f.Receiver.ReceiveAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(MailboxReplicaDisposition.Tombstone, MailboxReceiptV2Codec.DecodeReplica(removed.Span).Disposition);
        Assert.Null(await f.ReadBlobAsync());
        f.Reopen();
        Assert.Equal(removed.ToArray(), (await f.Receiver.ReceiveAsync(tombstone, MailboxPeerReplicationOperation.Tombstone)).ToArray());
        // An exact historical Store receipt is not a new write. A newly signed
        // replay nonce must not resurrect the retained tombstone.
        Assert.Equal(response.ToArray(), (await f.Receiver.ReceiveAsync(store, MailboxPeerReplicationOperation.Store)).ToArray());
        var freshStore = MailboxPeerWireV2Codec.Decode(store) with { ReplayNonce = Bytes(32, 0x67) };
        var fresh = MailboxPeerWireV2Codec.Encode(f.Crypto.SignRequest(freshStore, f.SenderSeed));
        Assert.NotNull(await Record.ExceptionAsync(() => f.Receiver.ReceiveAsync(fresh, MailboxPeerReplicationOperation.Store).AsTask()));
        Assert.Null(await f.ReadBlobAsync());
    }

    [Theory]
    [InlineData(1_600UL)]
    [InlineData(2_593_090UL)]
    public async Task AcceptedObjectLifetimeOutlivesCurrentAuthorityWithoutLosingTombstoneReplay(ulong objectExpiry)
    {
        // Genuine still-current signed role/holder/node authority and native
        // custody. Object retention is not a longer grant or epoch admission.
        await using var f = await Fixture.CreateAsync(envelopeExpiry: objectExpiry);
        var store = f.Frame(MailboxPeerReplicationOperation.Store);
        var response = await f.Receiver.ReceiveAsync(store, MailboxPeerReplicationOperation.Store);
        var receipt = MailboxReceiptV2Codec.DecodeReplica(response.Span);
        Assert.Equal(MailboxReplicaDisposition.Stored, receipt.Disposition);
        Assert.Equal(objectExpiry, receipt.ExpiresAtUnixSeconds);
        Assert.Equal(f.Envelope, await f.ReadBlobAsync());
        f.Reopen();
        Assert.Equal(response.ToArray(), (await f.Receiver.ReceiveAsync(store, MailboxPeerReplicationOperation.Store)).ToArray());
        var tombstone = f.Frame(MailboxPeerReplicationOperation.Tombstone);
        var removed = await f.Receiver.ReceiveAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(objectExpiry, MailboxReceiptV2Codec.DecodeReplica(removed.Span).ExpiresAtUnixSeconds);
        Assert.Null(await f.ReadBlobAsync());
        f.Reopen();
        Assert.Equal(removed.ToArray(), (await f.Receiver.ReceiveAsync(tombstone, MailboxPeerReplicationOperation.Tombstone)).ToArray());
        var fresh = MailboxPeerWireV2Codec.Decode(store) with { ReplayNonce = Bytes(32, 0x67) };
        Assert.NotNull(await Record.ExceptionAsync(() => f.Receiver.ReceiveAsync(
            MailboxPeerWireV2Codec.Encode(f.Crypto.SignRequest(fresh, f.SenderSeed)), MailboxPeerReplicationOperation.Store).AsTask()));
        Assert.Null(await f.ReadBlobAsync());
    }

    [Fact]
    public async Task RetainedObjectReadAndAckUseOriginalEpochAfterSignedProjectionAdvanceAndNativePeerColdReopen()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(
            distinctNodeIdentities: true, shortMailboxProjection: true);
        await using var f = await Fixture.CreateAsync(signed, envelopeExpiry: 1_600);
        var originalProjection = signed.Projection.ToArray();
        var originalEpochEnd = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("PMT2", originalProjection).Field(12).Span);
        Assert.Equal(DeepIdV2PublicationAuthorityFixture.ShortMailboxProjectionExpiry, originalEpochEnd);
        Assert.True(originalEpochEnd < 1_500);
        var originalTimeUpper = signed.Freshness.TrustedUpperUnixSeconds;
        await signed.RefreshInitialMailboxLeaseAsync();
        Assert.Equal(originalProjection, signed.Projection.ToArray());
        Assert.Equal(originalTimeUpper, signed.Freshness.TrustedUpperUnixSeconds);
        var store = f.Frame(MailboxPeerReplicationOperation.Store);
        var stored = await f.Receiver.ReceiveAsync(store, MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxReplicaDisposition.Stored, MailboxReceiptV2Codec.DecodeReplica(stored.Span).Disposition);
        f.Reopen();
        Assert.Equal(stored.ToArray(), (await f.Receiver.ReceiveAsync(store, MailboxPeerReplicationOperation.Store)).ToArray());

        await signed.AdvanceMailboxProjectionAsync();
        var current = await Host(signed);
        Assert.Equal(checked(f.Node.Host.SelectionEpoch + 1), current.SelectionEpoch);
        Assert.True(signed.Freshness.TrustedLowerUnixSeconds >= originalEpochEnd);
        foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
        {
            var owner = role == MailboxCapabilityDomain.Deposit ? f.Node.Deposit : f.Node.Retrieve;
            var prior = (await owner.ReadProtectedAsync()).ToArray();
            await owner.AdvanceAsync(current, Snapshot(signed, role, 2, prior, expires: 1_300, issued: originalEpochEnd));
        }
        var retrieve = Grant(signed, f.Node.Host, MailboxCapabilityDomain.Retrieve, 0x52, expires: 1_300,
            notBefore: originalEpochEnd + 1);
        Assert.True(MailboxAuthenticatedCapabilityCodec.DecodeGrant(retrieve).NotBeforeUnixSeconds > originalEpochEnd);
        await Assert.ThrowsAsync<CryptographicException>(() => current.ResolveGrantReplicasAsync(retrieve).AsTask());
        var originalReplicas = await current.GetSelectedRetainedReadReplicasAsync(retrieve);
        Assert.Equal(f.Node.Replicas.SelectMany(value => value.NodeId.ToArray()), originalReplicas.SelectMany(value => value.NodeId.ToArray()));
        Assert.Equal(f.Node.Replicas.SelectMany(value => value.SigningPublicKey.ToArray()), originalReplicas.SelectMany(value => value.SigningPublicKey.ToArray()));
        var wrongEpoch = MailboxAuthenticatedCapabilityCodec.DecodeGrant(retrieve) with { Epoch = current.SelectionEpoch };
        var remixed = MailboxAuthenticatedCapabilityCodec.EncodeGrant(new SodiumMailboxCapabilityCrypto().SignGrant(wrongEpoch, Bytes(32, 0x32)));
        var originalAck = MailboxPeerWireV2Codec.Decode(f.Frame(MailboxPeerReplicationOperation.Tombstone, retrieve));
        byte[] wrongProof = [.. f.Node.Host.ProjectionReference.Span, .. remixed];
        var hostile = originalAck with
        {
            Epoch = current.SelectionEpoch,
            SenderMembershipProof = originalAck.SenderMembershipProof with
            { Epoch = current.SelectionEpoch, CanonicalInclusionProof = wrongProof },
            RecipientMembershipProof = originalAck.RecipientMembershipProof with
            { Epoch = current.SelectionEpoch, CanonicalInclusionProof = wrongProof }
        };
        var hostileFrame = MailboxPeerWireV2Codec.Encode(f.Crypto.SignRequest(hostile, f.SenderSeed));
        var reservations = f.ReplayFiles.Length;
        var authorityReads = signed.PublicationReads;
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Receiver.ReceiveAsync(
            hostileFrame, MailboxPeerReplicationOperation.Tombstone).AsTask());
        Assert.True(signed.PublicationReads > authorityReads);
        Assert.Equal(reservations, f.ReplayFiles.Length);
        Assert.Equal(f.Envelope, await f.ReadBlobAsync(retrieve));
        var tombstone = f.Frame(MailboxPeerReplicationOperation.Tombstone, retrieve);
        var removed = await f.Receiver.ReceiveAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(MailboxReplicaDisposition.Tombstone, MailboxReceiptV2Codec.DecodeReplica(removed.Span).Disposition);
        Assert.Equal(1_600UL, MailboxReceiptV2Codec.DecodeReplica(removed.Span).ExpiresAtUnixSeconds);
        f.Node.ReopenRuntime();
        f.Reopen();
        Assert.Equal(removed.ToArray(), (await f.Receiver.ReceiveAsync(tombstone, MailboxPeerReplicationOperation.Tombstone)).ToArray());
        Assert.Null(await f.ReadBlobAsync(retrieve));
        var freshStore = MailboxPeerWireV2Codec.Decode(store) with { ReplayNonce = Bytes(32, 0x67) };
        await Assert.ThrowsAsync<CryptographicException>(() => f.Receiver.ReceiveAsync(
            MailboxPeerWireV2Codec.Encode(f.Crypto.SignRequest(freshStore, f.SenderSeed)), MailboxPeerReplicationOperation.Store).AsTask());
        Assert.Null(await f.ReadBlobAsync(retrieve));
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("second-grant")]
    [InlineData("descriptor-key")]
    [InlineData("p04")]
    [InlineData("operation")]
    [InlineData("placement")]
    public async Task HostilePeerProofOrBodyRejectsBeforeNativeReservation(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var request = MailboxPeerWireV2Codec.Decode(f.Frame(MailboxPeerReplicationOperation.Store));
        if (defect == "signature") request = request with { Signature = Bytes(64, 0x77) };
        if (defect == "second-grant") request = request with
        { RecipientMembershipProof = request.RecipientMembershipProof with { CanonicalInclusionProof = f.Proof(MailboxCapabilityDomain.Deposit, 0x61) } };
        if (defect == "descriptor-key") request = request with
        { RecipientMembershipProof = request.RecipientMembershipProof with { SigningPublicKey = Bytes(32, 0x78) } };
        if (defect == "p04") request = request with
        { SenderMembershipProof = request.SenderMembershipProof with { CanonicalInclusionProof = new byte[] { 1 } } };
        if (defect == "placement") request = request with { PlacementCommitment = Bytes(32, 0x79) };
        if (defect != "signature") request = f.Crypto.SignRequest(request, f.SenderSeed);
        var canonical = MailboxPeerWireV2Codec.Encode(request);
        var expected = defect == "operation" ? MailboxPeerReplicationOperation.Tombstone : MailboxPeerReplicationOperation.Store;
        var authorityReads = f.Node.Signed.PublicationReads;
        Assert.NotNull(await Record.ExceptionAsync(() => f.Receiver.ReceiveAsync(canonical, expected).AsTask()));
        if (defect is "operation" or "second-grant" or "p04")
            Assert.Equal(authorityReads, f.Node.Signed.PublicationReads);
        Assert.Empty(f.ReplayFiles); Assert.Empty(f.MutationFiles);
        Assert.Null(await f.ReadBlobAsync());
    }

    [Theory]
    [InlineData(MailboxPeerMutationFaultPoint.StoreReserved)]
    [InlineData(MailboxPeerMutationFaultPoint.TombstoneBlobDeleted)]
    public async Task ExpiryDuringDurableMutationReleasesNoReceiptAndExactReopenRecovers(MailboxPeerMutationFaultPoint point)
    {
        await using var f = await Fixture.CreateAsync();
        var operation = point == MailboxPeerMutationFaultPoint.StoreReserved ? MailboxPeerReplicationOperation.Store : MailboxPeerReplicationOperation.Tombstone;
        if (operation == MailboxPeerReplicationOperation.Tombstone)
            _ = await f.Receiver.ReceiveAsync(f.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store);
        f.Fault.Action = actual => { if (actual == point) f.Node.Signed.Sample = 105; };
        var exact = f.Frame(operation);
        Assert.NotNull(await Record.ExceptionAsync(() => f.Receiver.ReceiveAsync(exact, operation).AsTask()));
        Assert.Contains(f.ReplayFiles, path => ReadStatus(path) == (byte)MailboxPeerReplayRecordStatus.Pending);
        f.Node.Signed.Sample = 100; f.Fault.Action = null; f.Reopen();
        var response = await f.Receiver.ReceiveAsync(exact, operation);
        Assert.Equal(operation == MailboxPeerReplicationOperation.Store ? MailboxReplicaDisposition.Stored : MailboxReplicaDisposition.Tombstone,
            MailboxReceiptV2Codec.DecodeReplica(response.Span).Disposition);
        Assert.DoesNotContain(f.ReplayFiles, path => ReadStatus(path) == (byte)MailboxPeerReplayRecordStatus.Pending);
    }

    [Fact]
    public async Task RevokedGrantCannotReleaseCompletedPeerReceipt()
    {
        await using var f = await Fixture.CreateAsync();
        var frame = f.Frame(MailboxPeerReplicationOperation.Store);
        _ = await f.Receiver.ReceiveAsync(frame, MailboxPeerReplicationOperation.Store);
        var prior = Snapshot(f.Node.Signed);
        await f.Node.Deposit.AdvanceAsync(f.Node.Host, Snapshot(f.Node.Signed, generation: 2, prior: prior,
            serials: [Bytes(16, 0x51)]));
        Assert.NotNull(await Record.ExceptionAsync(() => f.Receiver.ReceiveAsync(frame, MailboxPeerReplicationOperation.Store).AsTask()));
        Assert.Single(f.ReplayFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, ReadStatus(f.ReplayFiles[0]));
    }

    private static byte ReadStatus(string path)
    { using var document = JsonDocument.Parse(File.ReadAllBytes(path)); return document.RootElement.GetProperty("status").GetByte(); }

    internal sealed class Fixture : IAsyncDisposable
    {
        internal CurrentMailboxAdmissionTests.Fixture Node = null!;
        internal readonly SodiumMailboxPeerReplicationCrypto Crypto = new();
        internal readonly Fault Fault = new();
        private readonly ReplicatedMailboxOptions options = new() { Enabled = true };
        private DurableMailboxPeerReplayJournal replay = null!;
        private MailboxPeerMutationStore mutations = null!;
        private ReplicatedMailboxStore blobs = null!;
        internal CurrentMailboxReplicaReceiver Receiver = null!;
        internal MailboxClientOperationLedger Operations = null!;
        private FileMailboxOperationCustody? operationCustody;
        private byte[] activeSigningSeed = [];
        internal byte[] Envelope = [], SenderSeed = [];
        private ulong envelopeExpiry;
        private readonly BlindedMailboxId mailbox = new(Bytes(32, 0x54));
        private readonly BlindedPlacementId placement = new(Bytes(32, 0x55));
        internal string[] ReplayFiles => Directory.GetFiles(Path.Combine(Node.DataRoot, options.PeerReplayDirectoryName), "*.json");
        internal string[] MutationFiles => Directory.GetFiles(Path.Combine(Node.DataRoot, options.PeerMutationDirectoryName), "*.json");
        internal static async Task<Fixture> CreateAsync(DeepIdV2PublicationAuthorityFixture? signed = null,
            int localReplicaIndex = 1, ulong envelopeExpiry = 1_150)
        {
            var f = new Fixture
            {
                envelopeExpiry = envelopeExpiry,
                Node = await CurrentMailboxAdmissionTests.Fixture.CreateAsync(MailboxAuthenticatedOperation.Store,
                signed: signed, localReplicaIndex: localReplicaIndex)
            };
            f.SenderSeed = f.Node.Signed.Node(f.Node.Replicas[1 - localReplicaIndex].NodeId.Span).Seed;
            f.Envelope = MailboxClientCodec.EncodeEncryptedEnvelope(new()
            {
                Epoch = f.Node.Host.SelectionEpoch,
                MailboxId = f.mailbox,
                PlacementId = f.placement,
                OperationId = Bytes(16, 0x58),
                DeduplicationDigest = Bytes(32, 0x59),
                CreatedAtUnixSeconds = 1_090,
                ExpiresAtUnixSeconds = envelopeExpiry,
                Ciphertext = Bytes(64, 0x60)
            });
            var provider = DataProtectionProvider.Create(new DirectoryInfo(f.Node.ProtectionRoot),
                builder => builder.SetApplicationName("XPoint.XNode.MGR1.NativeTests.v1"));
            f.operationCustody = new(f.Node.DataRoot, f.Node.OperationCustodyRoot, "mailbox-client-intent",
                f.Node.Node, f.Node.Host.NetworkId.Span, provider);
            f.Operations = new(f.Node.DataRoot, new MailboxClientAdapterOptions
            { DirectoryName = "mailbox-client-intent" }, f.operationCustody, clock: new NoUtcClock());
            await f.Node.Admission.EnrollNewOperationsAsync(f.Operations);
            f.Reopen(); return f;
        }
        internal byte[] Proof(MailboxCapabilityDomain role, byte serial = 0x51) =>
            [.. Node.Host.ProjectionReference.Span, .. Grant(Node.Signed, Node.Host, role, serial)];
        internal byte[] Frame(MailboxPeerReplicationOperation operation, byte[]? exactGrant = null)
        {
            var recipient = Node.Replicas.ToList().FindIndex(replica => replica.NodeId.Span.SequenceEqual(Node.Node));
            var sender = 1 - recipient;
            byte[] proof = exactGrant is null
                ? Proof(operation == MailboxPeerReplicationOperation.Store ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve)
                : [.. Node.Host.ProjectionReference.Span, .. exactGrant];
            MailboxReplicaMembershipProof Membership(int index) => new()
            {
                ReplicaId = Node.Replicas[index].NodeId,
                SigningPublicKey = Node.Replicas[index].SigningPublicKey,
                Epoch = Node.Host.SelectionEpoch,
                MembershipCommitment = Node.Host.MembershipCommitment,
                CanonicalInclusionProof = proof
            };
            var payload = operation == MailboxPeerReplicationOperation.Store ? Envelope : Bytes(32, 0x59);
            var unsigned = new MailboxPeerWireRequestV2
            {
                Operation = operation,
                Epoch = Node.Host.SelectionEpoch,
                OperationId = Bytes(16, operation == MailboxPeerReplicationOperation.Store ? (byte)0x58 : (byte)0x62),
                SenderRouterId = Node.Replicas[sender].NodeId,
                RecipientRouterId = Node.Node,
                MembershipCommitment = Node.Host.MembershipCommitment,
                PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
                BlindedMailboxId = mailbox.Bytes,
                Cursor = 1,
                CreatedAtUnixSeconds = 1_100,
                ExpiresAtUnixSeconds = envelopeExpiry,
                ReplayNonce = Bytes(32, operation == MailboxPeerReplicationOperation.Store ? (byte)0x63 : (byte)0x64),
                Payload = payload,
                PayloadDigest = SHA256.HashData(payload),
                SenderMembershipProof = Membership(sender),
                RecipientMembershipProof = Membership(recipient),
                Signature = new byte[64]
            };
            return MailboxPeerWireV2Codec.Encode(Crypto.SignRequest(unsigned, SenderSeed));
        }
        internal void Reopen(IMailboxDurabilityBarrier? mutationDurability = null, int? maximumMutations = null,
            ReadOnlyMemory<byte>? signingSeed = null)
        {
            Receiver?.Dispose(); mutations?.Dispose(); replay?.Dispose();
            if (maximumMutations is not null) options.MaxPeerMutationRecords = maximumMutations.Value;
            var clock = new NoUtcClock();
            blobs = new(Node.DataRoot, options, clock);
            mutations = new(Node.DataRoot, options, blobs, clock, durability: mutationDurability, faults: Fault);
            replay = new(Node.DataRoot, options, clock);
            activeSigningSeed = (signingSeed ?? Node.Signed.Node(Node.Node).Seed).ToArray();
            Receiver = new(Node.Admission, mutations, replay, activeSigningSeed, Operations);
        }
        internal void CloseOperations()
        {
            Operations?.Dispose(); operationCustody?.Dispose(); operationCustody = null;
        }
        internal void AttachOperations(MailboxClientOperationLedger operations)
        {
            Operations = operations;
            Receiver.Dispose();
            Receiver = new(Node.Admission, mutations, replay, activeSigningSeed, Operations);
        }
        internal async Task<byte[]?> ReadBlobAsync(byte[]? exactGrant = null) => await Node.Admission.WithGrantAsync(
            exactGrant ?? Grant(Node.Signed, Node.Host, MailboxCapabilityDomain.Retrieve, 0x52), MailboxCapabilityDomain.Retrieve,
            async (scope, token) =>
            {
                var blob = await blobs.ReadExactCurrentAsync(Convert.ToHexString(mailbox.Bytes.Span).ToLowerInvariant(),
                    Convert.ToHexString(SHA256.HashData(Envelope)).ToLowerInvariant(), scope.Lease, token);
                return blob is null ? null : Convert.FromBase64String(blob.Ciphertext);
            });
        public async ValueTask DisposeAsync()
        { Receiver.Dispose(); mutations.Dispose(); replay.Dispose(); CloseOperations(); await Node.DisposeAsync(); }
    }
    internal sealed class Fault : IMailboxPeerMutationFaultInjector
    { internal Action<MailboxPeerMutationFaultPoint>? Action; public void Inject(MailboxPeerMutationFaultPoint point) => Action?.Invoke(point); }
    private sealed class NoUtcClock : IClock
    { public DateTimeOffset UtcNow => throw new InvalidOperationException("Current peer path must not read host UTC."); }
    private static byte[] Bytes(int count, byte marker) => Enumerable.Repeat(marker, count).ToArray();
}
