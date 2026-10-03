using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace XNode.IntegrationTests.Runtime;

/// <summary>
/// Test-owned identity/network ceremony, not an operator fixture. DID2 root
/// ML-DSA and all account, device, directory, network and inventory signatures
/// are verified through public protocol authors/readers. Only the proof fetch
/// and monotonic clock are in-memory. This does not exercise a KEM exchange,
/// transport/TLS, claim consumption, client composition or physical devices.
/// </summary>
internal sealed class DeepIdV2PublicationAuthorityFixture : IDisposable,
    IDeepIdV2CurrentDirectoryProofSource, IDeepIdV2PreKeyPlacementSource, IDeepIdV2PreKeyClaimPlacementSource,
    IOnionMonotonicClock, IDeepIdV2ContactStoreAuthoritySource
{
    internal static readonly byte[] Network = Bytes(16, 0x11);
    internal static readonly byte[] Boot = Bytes(16, 0xf3);
    internal static readonly byte[] Service = Bytes(32, 0x35);
    private readonly byte[] service;
    private DeepIdV2PublicationAuthorityFixture(byte serviceMarker) => service = Bytes(32, serviceMarker);
    private readonly TestSigner[] nodes = [new(0x70), new(0x71), new(0x72)];
    private TestSigner[] ceremonyWitnesses = [];
    internal PendingXPointNetworkOperationalGenesis PendingOperational { get; private set; } = null!;
    internal AuthoredXPointNetworkOperationalGenesis CompletedOperational { get; private set; } = null!;
    internal int TopologySignatureCalls => ceremonyWitnesses.Sum(w => w.TopologySignatureCalls);
    internal ParsedDid2 Publisher { get; private set; } = null!;
    internal DeepPermanentIdV2 ContactAddress { get; private set; } = null!;
    internal VerifiedDeepIdV2DirectoryFreshness Freshness { get; private set; } = null!;
    internal VerifiedOnionNetworkContext NetworkContext { get; private set; } = null!;
    internal VerifiedXPointNetworkAuthority Authority { get; private set; } = null!;
    internal XPointNetworkGenesisPin GenesisPin { get; private set; } = null!;
    internal ReadOnlyMemory<byte> ExactAuthority { get; private set; }
    internal ReadOnlyMemory<byte> ExactTimePolicy { get; private set; }
    internal ReadOnlyMemory<byte> Policy { get; private set; }
    internal ReadOnlyMemory<byte> View { get; private set; }
    internal ReadOnlyMemory<byte> Head { get; private set; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> Descriptors { get; private set; } = [];
    internal ReadOnlyMemory<byte> Projection { get; private set; }
    internal ReadOnlyMemory<byte> MailboxAuthority { get; private set; }
    internal ContactServicePlacementCapability Placement { get; private set; } = null!;
    internal ParsedXpp1V2 Publication { get; private set; } = null!;
    // Public signed candidates only; no retained authoring key or verified-capability seam.
    internal IReadOnlyList<ParsedXpp1V2> InventoryHistory { get; private set; } = [];
    internal IReadOnlyDictionary<string, ParsedXpp1V2> RotationCandidates { get; private set; } =
        new Dictionary<string, ParsedXpp1V2>();
    internal byte[] Dca { get; private set; } = [];
    internal byte[] Xps { get; private set; } = [];
    internal Xpu1Request ContactPublication { get; private set; } = null!;
    internal VerifiedDeepIdV2ContactRouteClosure ContactRoute { get; private set; } = null!;
    internal ContactRouteAuthorityWireRequest RouteSuccessorRequest { get; private set; } = null!;
    internal ContactRouteAuthorityWireResponse RouteSuccessorResponse { get; private set; } = null!;
    internal AuthoredDeepIdV2ContactObject ContactObject { get; private set; } = null!;
    internal ContactPublicationAuthorityWireRequest ContactOwnedRequest { get; private set; } = null!;
    internal Xpu1Request AlternateContactPublication { get; private set; } = null!;
    internal ulong Sample { get; set; } = 100;
    internal bool RejectProof { get; set; }
    internal int ProofReads { get; private set; }
    internal Queue<OnionMonotonicReading> ClockReadings { get; } = new();
    private DeepIdV2DirectoryProofMaterial proofMaterial = null!;
    private VerifiedDeepIdV2DirectoryQuery proofQuery = null!;
    private AccountDirectoryProtectedLkg initialDirectoryFloor = null!;
    private ReadOnlyMemory<byte> exactDirectoryHead;
    private AuthoredAccountDirectoryHeadMutation directoryMutation = null!;

    internal ValueTask<VerifiedOnionNetworkContext> VerifyHistoryAsync(ReadOnlyMemory<byte> history,
        CancellationToken cancellationToken = default) =>
        OnionNetworkContextVerifier.VerifyFromProtectedHistoryAsync(Authority, Freshness,
            [Policy], [View], [Head], Descriptors, [Projection], history, new(this), cancellationToken);

    internal static async Task<DeepIdV2PublicationAuthorityFixture> CreateAsync(byte serviceMarker = 0x35,
        bool authorContactPublication = false, byte networkCommitmentMarker = 0, byte rootMarker = 0x20,
        bool authorRouteSuccessor = false, ushort lastResortReuseLimit = 1,
        bool authorInventoryRotation = false)
    {
        var fixture = new DeepIdV2PublicationAuthorityFixture(serviceMarker);
        try { await fixture.AuthorAsync(authorContactPublication, networkCommitmentMarker, rootMarker, authorRouteSuccessor, lastResortReuseLimit, authorInventoryRotation); return fixture; }
        catch { fixture.Dispose(); throw; }
    }

    private async Task AuthorAsync(bool authorContactPublication, byte networkCommitmentMarker, byte rootMarker, bool authorRouteSuccessor,
        ushort lastResortReuseLimit, bool authorInventoryRotation)
    {
        using var root = new TestSigner(rootMarker);
        using var w1 = new TestSigner(0x30);
        using var w2 = new TestSigner(0x31);
        using var w3 = new TestSigner(0x32);
        TestSigner[] witnesses = [w1, w2, w3];
        ceremonyWitnesses = witnesses;
        var bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
            new XPointNetworkGenesisAuthoringRequest(Bytes(32, 0x12), Network,
                [new(root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span,
                    root.CustodyDomainHash.Span)], 1,
                witnesses.Select(w => new XPointNetworkBootstrapWitnessKey(
                    w.SignerId.Span, 0, w.Ed25519PublicKey.Span,
                    w.FailureDomainHash.Span)).ToArray(), 2,
                [new(Bytes(32, 0x60), Bytes(32, 0x61), 1, "time1.invalid",
                    4460, Bytes(32, 0x62), 5),
                 new(Bytes(32, 0x63), Bytes(32, 0x64), 1, "time2.invalid",
                    4460, Bytes(32, 0x65), 5)],
                5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [root]);
        var descriptors = nodes.Select((signer, index) =>
            new XPointNetworkOperationalNode(signer,
                Bytes(32, (byte)(0x80 + index)), Bytes(32, (byte)(0x90 + index)),
                Bytes(32, (byte)(0xa0 + index)), Bytes(32, (byte)(0xb0 + index)),
                (uint)(64_500 + index), 840, Bytes(32, (byte)(0xc0 + index)),
                IPAddress.Parse($"192.0.2.{index + 1}"), 443,
                Bytes(32, (byte)(0xd0 + index)), Bytes(32, (byte)(0xd8 + index)),
                ScalarMult.Base(Bytes(32, (byte)(0xe0 + index))),
                ScalarMult.Base(Bytes(32, (byte)(0xe8 + index))),
                Enumerable.Range(0, 5).Select(role => (ReadOnlyMemory<byte>)
                    NodeRolePublicKey((byte)(0x10 + index * 5 + role))).ToArray()))
            .ToArray();
        var pendingOperational = await XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(
            new XPointNetworkOperationalGenesisRequest(Bytes(32, 0x12), bootstrap,
                [root], witnesses, descriptors, networkCommitmentMarker == 0 ? Hash("xcc") : Hash("xcc-" + networkCommitmentMarker),
                Hash("xcb"), Hash("pma"), NodeRolePublicKey(0x31),
                NodeRolePublicKey(0x32), 990, 1_000, 1_500));
        PendingOperational = pendingOperational;

        using var phrase = DeepRecoveryV1.Generate();
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(phrase, Network, 1);
        using var secrets = new OwnedGenesisDeviceSecrets();
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(recovery, 1_000, 1);
        var issued = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, secrets, new IssuancePersistence(),
            1_000, 5_000, 9_000);
        var device = issued.IssuedDevice?.Verified ??
            throw new CryptographicException("Test device issuance did not complete.");
        var identity = ApplicationCoreVerifier.CreateIdentityClosure(device.Identity, [device]);
        var binding = recovery.AuthorGenesisDab2(phrase, identity, 1);
        var directory = recovery.AuthorGenesisDmd1(identity, 1_000);
        var authorization = recovery.AuthorGenesisDca1V2(binding, directory, device, 1_000);
        var checkpoint = recovery.AuthorGenesisAdc1V2(binding, directory, 1_000);
        Publisher = binding.Head.DeepId;
        ContactAddress = DeepIdV2Root.DerivePermanentIdV2(phrase);
        Dca = authorization.Record.CanonicalBytes.ToArray();

        var genesis = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
            bootstrap.Authority, 990, 1_500, witnesses);
        var head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority,
            genesis.ProtectedHead, new([], [], [checkpoint], 990, 1_500, 2), witnesses);
        var material = DeepIdV2DirectoryProofMaterialAuthor.Create(head.ProtectedHead,
            head.ExactAllTransitions, [checkpoint], checkpoint.Checkpoint.DirectoryLeafKey.Span,
            genesis.ProtectedHead);
        var nonce = Bytes(32, 0xf2);
        var request = new AccountDirectoryProofAuthoringRequest(Network, nonce, Boot, 100,
            head.ExactAdh1.Span, pendingOperational.ExactXnv1.Span, 1_100, 5, 1_100, 1_130,
            AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, 1_100, 5), 2);
        using var pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var proof = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(
            bootstrap.Authority, request, material, witnesses, 1, pq);
        var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(Publisher, Network,
            genesis.ProtectedHead.LogGeneration, genesis.CoreHash.Span, 1,
            new byte[38], new byte[32]);
        proofMaterial = material; exactDirectoryHead = head.ExactAdh1; directoryMutation = head;
        initialDirectoryFloor = genesis.ProtectedHead;
        proofQuery = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, Publisher);
        Freshness = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(
            bootstrap.Authority, proof.ExactAdh1, proof.ExactDtt1, proof.ExactAdp1V2,
            nonce, VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, Publisher),
            new(Boot, 100, 100, 100), genesis.ProtectedHead, 1, 2, pq);
        var operational = await XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(pendingOperational, Freshness, new(this));
        CompletedOperational = operational;
        var network = await OnionNetworkContextVerifier.VerifyAsync(bootstrap.Authority,
            Freshness, [operational.ExactXvp1], [operational.ExactXnv1],
            [operational.ExactXnh1], operational.ExactXnd1, [operational.ExactPmt2],
            null, new(this), default);
        NetworkContext = network;
        Authority = bootstrap.Authority;
        GenesisPin = bootstrap.GenesisPin;
        ExactAuthority = bootstrap.ExactXna1;
        ExactTimePolicy = bootstrap.ExactDts1;
        Policy = operational.ExactXvp1;
        View = operational.ExactXnv1;
        Head = operational.ExactXnh1;
        Descriptors = operational.ExactXnd1;
        Projection = operational.ExactPmt2;
        MailboxAuthority = operational.ExactPma2;
        var placement = ContactServicePlacementFactory.Create(network,
            ContactServiceRequestKind.PublishPreKeyInventory, service);
        Placement = ContactServicePlacementCapability.FromNetcodec(placement,
            ContactServiceRequestKind.PublishPreKeyInventory, service,
            Freshness.TrustedUpperUnixSeconds);

        var seed = new byte[32];
        var agreement = new byte[32];
        var id = new byte[32];
        var revocation = new byte[32];
        using var owned = secrets.ExportOwnedPersistenceCopy();
        owned.CopyTo(seed, agreement, id, revocation);
        var key = PublicKeyAuth.GenerateKeyPair(seed);
        try
        {
            var dpd = Reference("DPD1", 1, device.Certificate.CanonicalHash.Span);
            ReadOnlyMemory<byte>[] xpsFields = [Network, service, id, dpd,
                U64(1), new byte[32], U16(DeepIdV2Codec.Suite), U16(32), U16(lastResortReuseLimit),
                U64(1_000), U64(1_400)];
            Xps = DeepIdV2PreKeyServiceCodec.Encode(xpsFields,
                PublicKeyAuth.SignDetached(
                    DeepIdV2PreKeyServiceCodec.CreateSignatureInput(xpsFields), key.PrivateKey));
            // This gate verifies the signatures/custody of public KEM descriptors.
            // No decapsulation/exchange is claimed by these test-only descriptors.
            ParsedDpk2V2 Member(byte marker, Dpk2PrekeyKind kind, ulong epoch, byte variant)
            {
                var prekeyId = epoch == 1 && variant == 0 ? Bytes(32, marker) :
                    Hash($"DID2 test inventory/{epoch}/{variant}/{marker}");
                Dpk2Record Record(byte[] x, byte[] ml, byte[] bundle) => new(
                    Network, authorization.Record.DeepAccountId.Span, id,
                    device.Certificate.DeviceGeneration, dpd, directory.Head.Record.DirectoryGeneration,
                    directory.Head.Record.RecordHash.Span, 1, epoch, Bytes(32, 0x51),
                    1, 1_000, 1_000, 1_400, device.Certificate.DeviceX25519PublicKey.Span,
                    Bytes(32, 0x71), ScalarMult.Base(Bytes(32, 0x81)), x,
                    kind == Dpk2PrekeyKind.OneTime ? prekeyId : [],
                    kind == Dpk2PrekeyKind.OneTime ? ScalarMult.Base(prekeyId) : [],
                    prekeyId, Bytes(1184, marker), kind,
                    kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : lastResortReuseLimit, ml, bundle);
                var placeholder = Record(new byte[64], new byte[64], new byte[64]);
                var x = PublicKeyAuth.SignDetached(
                    DeepIdV2Dpk2Codec.GetX25519SignedPrekeySignatureInput(placeholder), key.PrivateKey);
                var ml = PublicKeyAuth.SignDetached(
                    DeepIdV2Dpk2Codec.GetMlKemPrekeySignatureInput(placeholder), key.PrivateKey);
                var bundle = PublicKeyAuth.SignDetached(
                    DeepIdV2Dpk2Codec.GetPrekeyBundleSignatureInput(Record(x, ml, new byte[64])),
                    key.PrivateKey);
                return DeepIdV2Dpk2Codec.Decode(DeepIdV2Dpk2Codec.Encode(Record(x, ml, bundle)));
            }
            ParsedXpp1V2 Inventory(ulong epoch, byte[] predecessor, byte operation, byte variant = 0)
            {
                var members = Enumerable.Range(0, 32)
                    .Select(i => Member((byte)(0x10 + i), Dpk2PrekeyKind.OneTime, epoch, variant))
                    .OrderBy(member => Convert.ToHexString(member.OneTimePrekeyId.Span), StringComparer.Ordinal).ToArray();
                var last = Member(0x90, Dpk2PrekeyKind.LastResort, epoch, variant);
                ReadOnlyMemory<byte>[] xpiFields = [Network, service, id, dpd, U64(1),
                    Reference("XPS1", 2, SHA256.HashData(Xps)), U64(epoch), predecessor, U16(32),
                    InventoryRoot(members), last.ExactHash, directory.Head.Record.RecordHash,
                    Reference("DRS1", 1, identity.Revocations.Snapshot.CanonicalHash.Span),
                    U64(1_000), U64(1_400)];
                var manifest = DeepIdV2PreKeyManifestCodec.Decode(DeepIdV2PreKeyManifestCodec.Encode(
                    xpiFields, PublicKeyAuth.SignDetached(
                        DeepIdV2PreKeyManifestCodec.CreateSignatureInput(xpiFields), key.PrivateKey)));
                return DeepIdV2PreKeyPublicationCodec.Decode(DeepIdV2PreKeyPublicationCodec.Encode(
                    Network, Bytes(32, operation), Placement.PlacementHash.Span, manifest, members, last));
            }
            Publication = Inventory(1, new byte[32], 0xd1);
            var inventoryHistory = new List<ParsedXpp1V2> { Publication };
            if (authorInventoryRotation)
            {
                for (ulong epoch = 2; epoch <= 14; epoch++)
                    inventoryHistory.Add(Inventory(epoch, inventoryHistory[^1].Manifest.ExactHash.ToArray(),
                        checked((byte)(0xd0 + epoch))));
                RotationCandidates = new Dictionary<string, ParsedXpp1V2>
                {
                    ["same-epoch"] = Inventory(1, new byte[32], 0xf0, variant: 1),
                    ["same-operation"] = Inventory(2, Publication.Manifest.ExactHash.ToArray(), 0xd1),
                    ["wrong-predecessor"] = Inventory(2, Hash("wrong DID2 inventory predecessor"), 0xf2),
                    ["skipped-epoch"] = Inventory(3, Publication.Manifest.ExactHash.ToArray(), 0xf1)
                };
            }
            InventoryHistory = inventoryHistory;
            if (authorContactPublication)
            {
                var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(Freshness,
                    authorization, Boot, Sample);
                var time = new OnionTrustedTimeAuthority(this);
                var advertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(
                    current, network, Authority, secrets, 32, Bytes(32, 0x41), Bytes(32, 0x42),
                    ScalarMult.Base(Bytes(32, 0x43)), 1_000, 1_400, time);
                var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(current,
                    network, Authority, advertisement.CanonicalBytes, witnesses, 1_000, 1_400, time);
                var route = await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(current,
                    network, Authority, secrets, advertisement.CanonicalBytes, threshold, 1, time);
                var resolverCapability = DeepIdV2Root.DerivePermanentIdV2(phrase).ResolverReadCapability.ToArray();
                AuthoredDeepIdV2ContactObject contact;
                try
                {
                    contact = await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(route, secrets,
                        [DeepIdV2PreKeyServiceCodec.Decode(Xps)], "DID2 store QA", resolverCapability);
                }
                finally { CryptographicOperations.ZeroMemory(resolverCapability); }
                var candidate = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(
                    route, contact, secrets, Bytes(32, 0x47), Bytes(32, 0x48), Bytes(32, 0x49));
                var authorized = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(
                    route, candidate.WireRequest, witnesses);
                ContactRoute = route; ContactObject = contact; ContactOwnedRequest = candidate.WireRequest;
                ContactPublication = Xpu1Codec.Decode(authorized.ExactXpu1.Span);
                var alternate = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(
                    route, candidate.WireRequest, witnesses[..2]);
                AlternateContactPublication = Xpu1Codec.Decode(alternate.ExactXpu1.Span);
                if (authorRouteSuccessor)
                {
                    var predecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(current, network,
                        Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
                    var next = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(current, network, Authority,
                        secrets, advertisement.CanonicalBytes, Bytes(32, 0x51), Bytes(32, 0x52),
                        ScalarMult.Base(Bytes(32, 0x53)), 1_450, time);
                    var nextThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(current, network, Authority,
                        predecessor, next.CanonicalBytes, witnesses, 1_450, time);
                    var floor = Freshness.NextProtectedLkg;
                    RouteSuccessorRequest = new(Network, Bytes(32, 0x54), Freshness.QueriedDirectoryLeafKey.Span,
                        floor.LogGeneration, floor.CoreHash.Span, Dca, next.CanonicalBytes.Span,
                        predecessor.ExactXir1V2.Span, predecessor.ExactRouteClosure.Span);
                    RouteSuccessorResponse = new(Network, RouteSuccessorRequest.RequestNonce.Span,
                        nextThreshold.Selection.CanonicalBytes.Span, nextThreshold.LiveRoute.CanonicalBytes.Span,
                        nextThreshold.Successor.CanonicalBytes.Span, Freshness.ExactAdh1.Span);
                }
            }
        }
        finally
        {
            foreach (var value in new[] { seed, agreement, id, revocation, key.PrivateKey })
                CryptographicOperations.ZeroMemory(value);
        }
    }

    internal async Task<VerifiedDeepIdV2ContactRouteClosure> RefreshContactProofAsync(ulong sample, ulong proofTime)
    {
        var current = await RefreshCurrentDirectoryEvidenceAsync(sample, proofTime);
        return await DeepIdV2ContactRouteVerifier.VerifyAsync(current, NetworkContext, Authority,
            ContactRoute.ExactXir1V2, ContactRoute.ExactRouteClosure, new(this));
    }

    internal async Task<DeepIdV2CurrentContactAuthorization> AdvanceDirectoryWithAnotherAccountAsync(VerifiedAdc1V2 additional)
    {
        var original = Freshness.CurrentCheckpoint!;
        using var w1 = new TestSigner(0x30); using var w2 = new TestSigner(0x31); using var w3 = new TestSigner(0x32);
        var next = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(Authority, directoryMutation.ProtectedHead,
            new(directoryMutation.ExactAllTransitions, [original], [additional], 990, 1_500, 2), [w1, w2, w3]);
        // This client already verified the previous head. Advance from that
        // genuine retained floor, not a two-head jump from empty genesis.
        initialDirectoryFloor = directoryMutation.ProtectedHead;
        var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(Publisher, Network,
            initialDirectoryFloor.LogGeneration, initialDirectoryFloor.CoreHash.Span, 1, new byte[38], new byte[32]);
        proofQuery = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, Publisher);
        proofMaterial = DeepIdV2DirectoryProofMaterialAuthor.Create(next.ProtectedHead, next.ExactAllTransitions,
            [original, additional], original.Checkpoint.DirectoryLeafKey.Span, initialDirectoryFloor);
        exactDirectoryHead = next.ExactAdh1; directoryMutation = next;
        return await RefreshCurrentDirectoryEvidenceAsync(Sample, 1_100);
    }

    private async Task<DeepIdV2CurrentContactAuthorization> RefreshCurrentDirectoryEvidenceAsync(ulong sample, ulong proofTime)
    {
        Sample = sample;
        using var w1 = new TestSigner(0x30); using var w2 = new TestSigner(0x31); using var w3 = new TestSigner(0x32);
        using var pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var nonce = Bytes(32, 0xf4);
        var request = new AccountDirectoryProofAuthoringRequest(Network, nonce, Boot, sample,
            exactDirectoryHead.Span, View.Span, proofTime, 5, proofTime, proofTime + 30,
            AccountDirectoryDtt1IssuanceEpoch.Derive(Authority, proofTime, 5), 2);
        var proof = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(Authority, request, proofMaterial,
            [w1, w2, w3], 1, pq);
        Freshness = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(Authority,
            proof.ExactAdh1, proof.ExactDtt1, proof.ExactAdp1V2, nonce, proofQuery,
            new(Boot, sample, sample, sample), initialDirectoryFloor, 1, 2, pq);
        NetworkContext = await OnionNetworkContextVerifier.VerifyAsync(Authority, Freshness,
            [Policy], [View], [Head], Descriptors, [Projection], null, new(this), default);
        var checkpoint = Freshness.CurrentCheckpoint!;
        var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(Dca),
            checkpoint.Binding, checkpoint.Directory);
        return DeepIdV2CurrentContactAuthorizationVerifier.Verify(Freshness, dca, Boot, Sample);
    }

    internal TestSigner Node(ReadOnlySpan<byte> id)
    {
        foreach (var node in nodes)
            if (node.Ed25519PublicKey.Span.SequenceEqual(id)) return node;
        throw new CryptographicException("Unknown test node.");
    }

    internal byte[] TestOnionScalar(ReadOnlySpan<byte> id)
    {
        for (var i = 0; i < nodes.Length; i++)
            if (nodes[i].Ed25519PublicKey.Span.SequenceEqual(id)) return Bytes(32, (byte)(0xe0 + i));
        throw new CryptographicException("Unknown test onion node.");
    }

    public ValueTask<VerifiedDeepIdV2DirectoryFreshness> ReadCurrentAsync(
        ParsedDid2 did2, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProofReads++;
        if (RejectProof || !did2.CanonicalBytes.Span.SequenceEqual(Publisher.CanonicalBytes.Span))
            throw new CryptographicException("Current test DID2 proof unavailable.");
        return ValueTask.FromResult(Freshness);
    }

    public ValueTask<ContactServicePlacementCapability> MintPreKeyPublicationAsync(
        ParsedDid2 publisher, ReadOnlyMemory<byte> serviceCapability, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!publisher.CanonicalBytes.Span.SequenceEqual(Publisher.CanonicalBytes.Span) ||
            !serviceCapability.Span.SequenceEqual(service))
            throw new CryptographicException("Unrelated test publication placement.");
        return ValueTask.FromResult(Placement);
    }

    public ValueTask<ContactServicePlacementCapability> MintPreKeyClaimAsync(
        ReadOnlyMemory<byte> serviceCapability, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!serviceCapability.Span.SequenceEqual(service)) throw new CryptographicException("Unrelated test claim placement.");
        var placement = ContactServicePlacementFactory.Create(NetworkContext,
            ContactServiceRequestKind.ClaimPreKey, serviceCapability);
        return ValueTask.FromResult(ContactServicePlacementCapability.FromNetcodec(placement,
            ContactServiceRequestKind.ClaimPreKey, serviceCapability, Freshness.TrustedUpperUnixSeconds));
    }

    public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (ClockReadings.TryDequeue(out var reading)) return ValueTask.FromResult(reading);
        return ValueTask.FromResult(new OnionMonotonicReading(Boot, Sample));
    }

    public ValueTask<DeepIdV2ContactStoreAuthority> ReadPublicationAuthorityAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (RejectProof) throw new CryptographicException("Current test DID2 proof unavailable.");
        return ValueTask.FromResult(new DeepIdV2ContactStoreAuthority(NetworkContext,
            Authority, Freshness, new OnionTrustedTimeAuthority(this),
            MailboxAuthorityV2Verifier.Verify(Authority, MailboxAuthority.Span,
                Freshness.TrustedLowerUnixSeconds, Freshness.TrustedUpperUnixSeconds)));
    }

    public void Dispose() { foreach (var node in nodes) node.Dispose(); }

    internal static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] Hash(string value) => SHA256.HashData(Encoding.ASCII.GetBytes(value));
    private static byte[] U16(ushort value)
    { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value)
    { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] Reference(string magic, ushort version, ReadOnlySpan<byte> hash)
    {
        var bytes = new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), version);
        hash.CopyTo(bytes.AsSpan(6)); return bytes;
    }
    private static byte[] NodeRolePublicKey(byte marker)
    {
        var seed = Bytes(32, marker); var key = PublicKeyAuth.GenerateKeyPair(seed);
        try { return key.PublicKey.ToArray(); }
        finally { CryptographicOperations.ZeroMemory(seed); CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }
    private static byte[] DomainHash(string label, ReadOnlySpan<byte> value)
    {
        var domain = Encoding.ASCII.GetBytes(label);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(U16(checked((ushort)domain.Length))); hash.AppendData(domain);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length); hash.AppendData(value); return hash.GetHashAndReset();
    }
    // Independent test commitment calculation for the exactly 32-member profile.
    // The production verifier independently recomputes and checks this root.
    private static byte[] InventoryHash(string label, byte[] value)
    {
        var domain = Encoding.ASCII.GetBytes(label);
        var input = new byte[domain.Length + 1 + 4 + value.Length];
        domain.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(domain.Length + 1),
            checked((uint)value.Length));
        value.CopyTo(input, domain.Length + 5);
        return SHA256.HashData(input);
    }
    private static byte[] InventoryRoot(ParsedDpk2V2[] members)
    {
        var level = members.Select((member, i) => InventoryHash(
            "Deep/ContactResolver/V2/prekey-inventory-leaf",
            U16((ushort)i).Concat(member.ExactHash.ToArray()).ToArray())).ToArray();
        while (level.Length > 1)
            level = Enumerable.Range(0, level.Length / 2).Select(i => InventoryHash(
                "Deep/ContactResolver/V2/prekey-inventory-node",
                level[i * 2].Concat(level[i * 2 + 1]).ToArray())).ToArray();
        return level[0];
    }

    internal sealed class TestSigner : IDisposable,
        IXPointNetworkBootstrapRootSigner, IXPointNetworkWitnessSigner,
        IAccountDirectoryAdh1WitnessSigner, IContactRouteAuthorityWitnessSigner,
        IXpa1PublicationAuthorizationWitnessSigner
    {
        private readonly byte marker;
        private readonly KeyPair key;
        internal TestSigner(byte marker)
        {
            this.marker = marker;
            Seed = Bytes(32, marker);
            key = PublicKeyAuth.GenerateKeyPair(Seed);
        }
        internal byte[] Seed { get; }
        internal int TopologySignatureCalls { get; private set; }
        public ReadOnlyMemory<byte> RootKeyId => Bytes(32, marker);
        public ReadOnlyMemory<byte> SignerId => marker >= 0x70 ? key.PublicKey : Bytes(32, marker);
        public ReadOnlyMemory<byte> WitnessId => SignerId;
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, (byte)(marker + 0x40));
        public ReadOnlyMemory<byte> FailureDomainHash => CustodyDomainHash;
        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request,
            Memory<byte> signature64, CancellationToken cancellationToken) =>
            Sign(request.SigningInput, signature64, cancellationToken);
        public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request,
            Memory<byte> signature64, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.Purpose == XPointNetworkOperationalSignaturePurpose.MailboxTopology)
                TopologySignatureCalls++;
            return Sign(request.SigningInput, signature64, cancellationToken);
        }
        public ValueTask<int> SignAsync(ContactRouteAuthoritySigningRequest request,
            Memory<byte> signature64, CancellationToken cancellationToken) =>
            Sign(request.SigningInput, signature64, cancellationToken);
        public ValueTask<ReadOnlyMemory<byte>> SignXpa1Async(ReadOnlyMemory<byte> input,
            CancellationToken cancellationToken) => SignWitness(input, cancellationToken);
        private ValueTask<int> Sign(ReadOnlyMemory<byte> input, Memory<byte> destination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey).CopyTo(destination);
            return ValueTask.FromResult(64);
        }
        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(ReadOnlyMemory<byte> input,
            CancellationToken cancellationToken) => SignWitness(input, cancellationToken);
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input,
            CancellationToken cancellationToken) => SignWitness(input, cancellationToken);
        private ValueTask<ReadOnlyMemory<byte>> SignWitness(ReadOnlyMemory<byte> input,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey));
        }
        public void Dispose()
        { CryptographicOperations.ZeroMemory(Seed); CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }

    /// <summary>One-device, exact-CAS test custody for the shared identity primitive.</summary>
    private sealed class IssuancePersistence : Dnp1IdentityIssuancePersistence
    {
        private static readonly byte[] Catalog = Bytes(32, 0x31);
        private static readonly byte[] DxrKeyId = Bytes(32, 0x32);
        private static readonly byte[] HmacKey = Bytes(32, 0x41);
        private static readonly byte[] NonceKey = Bytes(32, 0x51);
        private DxpReplayMaterial? material;
        private byte[]? current;
        private ulong revision;
        private ulong subjectRevision;
        protected override ValueTask<UntrustedDxpPersistenceProfileReadResult> ReadProfileCoreAsync(
            DxpPersistenceProfileRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new UntrustedDxpPersistenceProfileReadResult(
                Catalog, DxrKeyId, NonceKeyId(1, Network, request.IssuanceScope.Span), 7));
        }
        protected override ValueTask<UntrustedDxpNonceLedgerReadResult> DeriveNonceLedgerCoreAsync(
            DxpNonceLedgerRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            const string label = "Deep/ProtectedState/V2/DXP1-nonce-ledger-key";
            var domain = Encoding.ASCII.GetBytes(label);
            var input = U16((ushort)domain.Length).Concat(domain).Concat([request.SourceKind])
                .Concat(request.Network.ToArray()).Concat(request.IssuanceScope.ToArray())
                .Concat([request.Role]).Concat(request.Nonce.ToArray()).ToArray();
            return ValueTask.FromResult(new UntrustedDxpNonceLedgerReadResult(
                HMACSHA256.HashData(NonceKey, input),
                NonceKeyId(request.SourceKind, request.Network.Span, request.IssuanceScope.Span)));
        }
        private static byte[] NonceKeyId(byte kind, ReadOnlySpan<byte> network, ReadOnlySpan<byte> scope) =>
            DomainHash("Deep/ProtectedState/V2/DXP1-nonce-index-key-id",
                new byte[] { kind }.Concat(network.ToArray()).Concat(scope.ToArray()).Concat(NonceKey).ToArray());
        protected override ValueTask<ReadOnlyMemory<byte>> ComputeDxrTagCoreAsync(
            DxpProtectedTagRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!request.ProtectedStateKeyId.Span.SequenceEqual(DxrKeyId))
                throw new CryptographicException("Unexpected test custody key.");
            var domain = Encoding.ASCII.GetBytes(request.Domain);
            var length = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length,
                checked((uint)request.UnsignedCanonicalDxr1.Length));
            var input = U16((ushort)domain.Length).Concat(domain).Concat(U16(request.Suite))
                .Concat(length).Concat(request.UnsignedCanonicalDxr1.ToArray()).ToArray();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(HmacKey, input));
        }
        private UntrustedDxpReplayReadResult Current() =>
            new(current!, revision, material, subjectRevision);
        protected override ValueTask<UntrustedDxpReplayReadResult?> ReadByDeviceSubjectCoreAsync(
            DxpDeviceSubjectRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(current is null ? null : Current());
        }
        protected override ValueTask<UntrustedDxpReplayReadResult> ReservePendingCoreAsync(
            DxpPendingWriteRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (current is null) { material = request.Material; current = request.CanonicalDxr1.ToArray(); revision = 1; }
            return ValueTask.FromResult(Current());
        }
        protected override ValueTask<UntrustedDxpReplayReadResult> CompareExchangeVerifiedCoreAsync(
            DxpVerifiedCasRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (current is null || revision != request.ExpectedSourceRevision ||
                !current.AsSpan().SequenceEqual(request.CurrentDxr1.Span))
                throw new CryptographicException("Test identity exact CAS failed.");
            current = request.NextDxr1.ToArray(); material = request.Material;
            revision++; subjectRevision = 1; return ValueTask.FromResult(Current());
        }
        protected override ValueTask<UntrustedDxpReplayReadResult> CompareExchangeAbortedCoreAsync(
            DxpAbortedCasRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Test genesis issuance must not abort.");
    }
}
