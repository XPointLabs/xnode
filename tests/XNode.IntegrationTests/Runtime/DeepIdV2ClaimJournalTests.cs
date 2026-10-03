using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

/// <summary>
/// Real DID2/network/inventory/signature closure with local durable journals.
/// No peer RPC, current DCB1, distributed failover, TLS or device claim is proved.
/// </summary>
public sealed class DeepIdV2ClaimJournalTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TwoReplicaJournals_CommitTheSameVerifiedTupleAndReplayAfterRestart(bool lastResort)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        VerifyInventory(fixture);
        var root = TemporaryRoot();
        try
        {
            var placement = Placement(fixture);
            var request = Request(fixture, placement);
            var member = lastResort ? fixture.Publication.LastResortMember : fixture.Publication.OneTimeMembers[0];
            var counter = lastResort ? (ushort)1 : (ushort)0;
            var verified = VerifiedResult(fixture, placement, request, member, counter);
            var receipts = new ParsedXic1V2[2];
            for (var i = 0; i < 2; i++)
            {
                var node = placement.RankedReplicaNodeIds[i];
                using var store = Open(fixture, Path.Combine(root, i.ToString()), node);
                receipts[i] = store.CommitAuthorized(fixture.Publication, 1_100, input => Sign(fixture, node, input));
                if (lastResort) Exhaust(fixture, store, placement, node);
                _ = store.ReserveClaimProposal(request, member, fixture.Publication.Manifest,
                    lastResort ? 33UL : 1UL, counter, 1_095, 1_105, input => Sign(fixture, node, input));
            }
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(fixture.Publication,
                fixture.Placement.VerifiedPlacement, receipts[0], receipts[1]);
            for (var i = 0; i < 2; i++)
            {
                var node = placement.RankedReplicaNodeIds[i];
                using (var store = Open(fixture, Path.Combine(root, i.ToString()), node))
                    Assert.Equal(verified.ExactResult.ToArray(), store.CompleteClaimLocally(verified,
                        input => Sign(fixture, node, input)).ToArray());
                using (var reopened = Open(fixture, Path.Combine(root, i.ToString()), node))
                {
                    Assert.True(reopened.ReserveClaimProposal(request, member, fixture.Publication.Manifest,
                        lastResort ? 33UL : 1UL, counter, 1_095, 1_105, _ => throw new InvalidOperationException("Do not resign.")).ExactReplay);
                    Assert.Equal(verified.ExactResult.ToArray(), reopened.CompleteClaimLocally(verified,
                        _ => throw new InvalidOperationException("Do not rewrite completed results.")).ToArray());
                    var replay = VerifiedResult(fixture, placement, request, member, counter, Xpc1V2Status.Replay);
                    Assert.Equal(verified.ExactResult.ToArray(), reopened.CompleteClaimLocally(replay,
                        _ => throw new InvalidOperationException("Preserve the first completed wire.")).ToArray());
                }
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task ValidTwoSignatures_WithoutLocalReservationCannotCommit()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = TemporaryRoot();
        try
        {
            var placement = Placement(fixture);
            var request = Request(fixture, placement);
            var member = fixture.Publication.LastResortMember;
            var verified = VerifiedResult(fixture, placement, request, member, 1);
            var node = placement.RankedReplicaNodeIds[0];
            using var store = Open(fixture, root, node);
            _ = store.CommitAuthorized(fixture.Publication, 1_100, input => Sign(fixture, node, input));
            Assert.Throws<UnauthorizedAccessException>(() => store.CompleteClaimLocally(verified,
                _ => throw new InvalidOperationException("No signing without durable reservation.")));
            Assert.Empty(Directory.GetFiles(root, "claims.state", SearchOption.AllDirectories));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("active.state")]
    [InlineData("claims.state")]
    public async Task NativeExclusiveReadFailureDoesNotLatchOrDestroyAuthenticatedCustody(string snapshot)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = TemporaryRoot();
        try
        {
            var placement = Placement(fixture); var node = placement.RankedReplicaNodeIds[0];
            var request = Request(fixture, placement); var offering = fixture.Publication.OneTimeMembers[0];
            var verified = VerifiedResult(fixture, placement, request, offering, 0);
            using var store = Open(fixture, root, node);
            _ = store.CommitAuthorized(fixture.Publication, 1_100, input => Sign(fixture, node, input));
            _ = store.ReserveClaimProposal(request, offering, fixture.Publication.Manifest,
                1, 0, 1_095, 1_105, input => Sign(fixture, node, input));
            Assert.Equal(verified.ExactResult.ToArray(), store.CompleteClaimLocally(verified,
                input => Sign(fixture, node, input)).ToArray());
            var path = Assert.Single(Directory.GetFiles(root, snapshot, SearchOption.AllDirectories));
            var before = SHA256.HashData(File.ReadAllBytes(path));
            // Real native FileShare denial, not an injected corrupt byte or a
            // fake filesystem/security owner. No recovery/reset is performed.
            using (var locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                Assert.ThrowsAny<IOException>(() =>
                {
                    if (snapshot == "active.state") _ = store.ReadCurrentManifest();
                    else _ = store.ReserveClaimProposal(request, offering, fixture.Publication.Manifest,
                        1, 0, 1_095, 1_105, _ => throw new InvalidOperationException("Do not resign."));
                });
                Assert.Empty(Directory.GetFiles(root, "fault.marker", SearchOption.AllDirectories));
                Assert.Empty(Directory.GetFiles(root, "*.quarantine.*", SearchOption.AllDirectories));
            }
            Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(path)));
            Assert.Equal(fixture.Publication.Manifest.CanonicalBytes.ToArray(), store.ReadCurrentManifest()!.CanonicalBytes.ToArray());
            Assert.True(store.ReserveClaimProposal(request, offering, fixture.Publication.Manifest,
                1, 0, 1_095, 1_105, _ => throw new InvalidOperationException("Do not resign.")).ExactReplay);
            Assert.Equal(verified.ExactResult.ToArray(), store.CompleteClaimLocally(verified,
                _ => throw new InvalidOperationException("Do not rewrite completed results.")).ToArray());
            store.Dispose();
            using var reopened = Open(fixture, root, node);
            Assert.True(reopened.ReserveClaimProposal(request, offering, fixture.Publication.Manifest,
                1, 0, 1_095, 1_105, _ => throw new InvalidOperationException("Do not resign after restart.")).ExactReplay);
            Assert.Equal(verified.ExactResult.ToArray(), reopened.CompleteClaimLocally(verified,
                _ => throw new InvalidOperationException("Do not rewrite after restart.")).ToArray());
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("active.state")]
    [InlineData("claims.state")]
    public async Task CorruptSignedSnapshotStillLatchesAndPreservesQuarantineAcrossRestart(string snapshot)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = TemporaryRoot();
        try
        {
            var placement = Placement(fixture); var node = placement.RankedReplicaNodeIds[0];
            var request = Request(fixture, placement); var offering = fixture.Publication.OneTimeMembers[0];
            using var store = Open(fixture, root, node);
            _ = store.CommitAuthorized(fixture.Publication, 1_100, input => Sign(fixture, node, input));
            _ = store.ReserveClaimProposal(request, offering, fixture.Publication.Manifest,
                1, 0, 1_095, 1_105, input => Sign(fixture, node, input));
            var path = Assert.Single(Directory.GetFiles(root, snapshot, SearchOption.AllDirectories));
            var damaged = File.ReadAllBytes(path); damaged[^1] ^= 1;
            File.WriteAllBytes(path, damaged);
            Assert.Throws<InvalidDataException>(() =>
            {
                if (snapshot == "active.state") _ = store.ReadCurrentManifest();
                else _ = store.ReserveClaimProposal(request, offering, fixture.Publication.Manifest,
                    1, 0, 1_095, 1_105, _ => throw new InvalidOperationException("Never resign corrupt custody."));
            });
            Assert.Single(Directory.GetFiles(root, "fault.marker", SearchOption.AllDirectories));
            var quarantine = Assert.Single(Directory.GetFiles(root, "active.state.quarantine.*", SearchOption.AllDirectories));
            Assert.Equal(damaged, File.ReadAllBytes(snapshot == "active.state" ? quarantine : path));
            store.Dispose();
            Assert.Throws<InvalidDataException>(() => Open(fixture, root, node));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CrashAtCompletion_ReconcilesOnlyTheSameReservedTuple(bool afterReplace)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = TemporaryRoot();
        try
        {
            var placement = Placement(fixture);
            var request = Request(fixture, placement);
            var member = fixture.Publication.LastResortMember;
            var verified = VerifiedResult(fixture, placement, request, member, 1);
            var node = placement.RankedReplicaNodeIds[0];
            using (var store = Open(fixture, root, node))
            {
                _ = store.CommitAuthorized(fixture.Publication, 1_100, input => Sign(fixture, node, input));
                Exhaust(fixture, store, placement, node);
                _ = store.ReserveClaimProposal(request, member, fixture.Publication.Manifest,
                    33, 1, 1_095, 1_105, input => Sign(fixture, node, input));
            }
            using (var store = Open(fixture, root, node, new CrashOnClaims(afterReplace)))
            {
                Assert.Throws<IOException>(() => store.CompleteClaimLocally(verified,
                    input => Sign(fixture, node, input)));
                Assert.Throws<IOException>(() => store.ReadCurrentPublication());
            }
            var calls = 0;
            using var reopened = Open(fixture, root, node);
            Assert.Equal(verified.ExactResult.ToArray(), reopened.CompleteClaimLocally(verified,
                input => { calls++; return Sign(fixture, node, input); }).ToArray());
            Assert.Equal(afterReplace ? 0 : 1, calls);
            Assert.True(reopened.ReserveClaimProposal(request, member, fixture.Publication.Manifest,
                33, 1, 1_095, 1_105, _ => throw new InvalidOperationException("No new proposal.")).ExactReplay);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task DifferentAvailableOneTimeMembers_AdvanceOneDurableGenerationEach()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = TemporaryRoot();
        try
        {
            var placement = Placement(fixture);
            var node = placement.RankedReplicaNodeIds[0];
            using (var store = Open(fixture, root, node))
            {
                _ = store.CommitAuthorized(fixture.Publication, 1_100, input => Sign(fixture, node, input));
                for (var i = 0; i < 3; i++)
                    Assert.False(store.ReserveClaimProposal(Request(fixture, placement, (byte)(0xb0 + i)),
                        fixture.Publication.OneTimeMembers[i], fixture.Publication.Manifest,
                        (ulong)i + 1, 0, 1_095, 1_105, input => Sign(fixture, node, input)).ExactReplay);
            }
            using var reopened = Open(fixture, root, node);
            Assert.Throws<InvalidOperationException>(() => reopened.ReserveClaimProposal(
                Request(fixture, placement, 0xc0), fixture.Publication.OneTimeMembers[0],
                fixture.Publication.Manifest, 4, 0, 1_095, 1_105, input => Sign(fixture, node, input)));
            Assert.False(reopened.ReserveClaimProposal(Request(fixture, placement, 0xc1),
                fixture.Publication.OneTimeMembers[3], fixture.Publication.Manifest,
                4, 0, 1_095, 1_105, input => Sign(fixture, node, input)).ExactReplay);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void VerifyInventory(DeepIdV2PublicationAuthorityFixture fixture)
    {
        var checkpoint = fixture.Freshness.CurrentCheckpoint!;
        var authorization = DeepIdV2ContactAuthorizationCodec.Verify(
            DeepIdV2ContactAuthorizationCodec.Decode(fixture.Dca), checkpoint.Binding, checkpoint.Directory);
        var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fixture.Freshness,
            authorization, DeepIdV2PublicationAuthorityFixture.Boot, fixture.Sample);
        DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(fixture.Publisher, fixture.Xps,
            current, fixture.Publication, DeepIdV2PublicationAuthorityFixture.Boot, fixture.Sample);
    }

    private static VerifiedContactServicePlacement Placement(DeepIdV2PublicationAuthorityFixture fixture) =>
        ContactServicePlacementFactory.Create(fixture.NetworkContext, ContactServiceRequestKind.ClaimPreKey,
            fixture.Publication.Manifest.Field(2));

    private static ParsedXpk1V2 Request(DeepIdV2PublicationAuthorityFixture fixture,
        VerifiedContactServicePlacement placement, byte operation = 0xb0) =>
        DeepIdV2PreKeyClaimRequestCodec.Decode(DeepIdV2PreKeyClaimRequestCodec.Encode(
            DeepIdV2PublicationAuthorityFixture.Network, Enumerable.Repeat(operation, 32).ToArray(),
            placement.ViewHash.Span, placement.PlacementHash.Span, 1_000, 1_400,
            fixture.Publication.Manifest.Field(2).Span, Enumerable.Repeat((byte)0xb1, 32).ToArray(),
            fixture.Publication.Manifest.Field(6).Span[6..], fixture.Publication.Manifest.Field(3).Span,
            Enumerable.Repeat((byte)0xb2, 32).ToArray()));

    private static VerifiedXpc1V2ReplicaSignatures VerifiedResult(DeepIdV2PublicationAuthorityFixture fixture,
        VerifiedContactServicePlacement placement, ParsedXpk1V2 request, ParsedDpk2V2 offering,
        ushort counter, Xpc1V2Status status = Xpc1V2Status.Claimed)
    {
        var manifest = fixture.Publication.Manifest;
        var generation = offering.Kind == Dpk2PrekeyKind.LastResort ? 33UL : 1UL;
        var input = DeepIdV2PreKeyClaimCommitment.CreateReplicaSignatureInput(
            request.CanonicalBytes.Span, offering.CanonicalBytes.Span, manifest.CanonicalBytes.Span, generation, counter);
        var rows = new byte[193];
        rows[0] = 2;
        var nodes = placement.RankedReplicaNodeIds.OrderBy(id => Convert.ToHexString(id.Span)).ToArray();
        for (var i = 0; i < 2; i++)
        {
            nodes[i].Span.CopyTo(rows.AsSpan(1 + i * 96));
            Sign(fixture, nodes[i], input).CopyTo(rows, 33 + i * 96);
        }
        var proof = offering.Kind == Dpk2PrekeyKind.OneTime ? ProofForIndexZero(fixture.Publication) : [];
        ReadOnlyMemory<byte>[] payload = [offering.CanonicalBytes,
            offering.Kind == Dpk2PrekeyKind.OneTime ? offering.OneTimePrekeyId : new byte[32],
            DeepIdV2PreKeyClaimCommitment.ComputeReceiptHash(request.CanonicalBytes.Span,
                offering.CanonicalBytes.Span, manifest.CanonicalBytes.Span, generation, counter),
            manifest.Field(12), manifest.Field(13), manifest.Field(5), manifest.Field(15),
            U16(counter), U64(generation), rows, manifest.CanonicalBytes,
            U16(offering.Kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : ushort.MaxValue), proof];
        var wire = DeepIdV2PreKeyClaimResultCodec.Encode(request.CanonicalBytes.Span, status,
            Xpc1V2MutationOutcome.DurablyCommitted, 1_100, 0, payload);
        return DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request,
            DeepIdV2PreKeyClaimResultCodec.Decode(wire, request.CanonicalBytes.Span), placement);
    }

    private static byte[] ProofForIndexZero(ParsedXpp1V2 publication)
    {
        var level = publication.OneTimeMembers.Select((member, i) => Hash(
            "Deep/ContactResolver/V2/prekey-inventory-leaf",
            U16((ushort)i).Concat(member.ExactHash.ToArray()).ToArray())).ToArray();
        var siblings = new List<byte>();
        while (level.Length > 1)
        {
            siblings.AddRange(level[1]);
            level = Enumerable.Range(0, level.Length / 2).Select(i => Hash(
                "Deep/ContactResolver/V2/prekey-inventory-node",
                level[i * 2].Concat(level[i * 2 + 1]).ToArray())).ToArray();
        }
        Assert.Equal(publication.Manifest.Field(10).ToArray(), level[0]);
        return siblings.ToArray();
    }

    private static void Exhaust(DeepIdV2PublicationAuthorityFixture fixture,
        DeepIdV2InventoryCommitStore store, VerifiedContactServicePlacement placement, ReadOnlyMemory<byte> node)
    {
        for (var i = 0; i < fixture.Publication.OneTimeMembers.Count; i++)
            _ = store.ReserveClaimProposal(Request(fixture, placement, checked((byte)(0xc0 + i))),
                fixture.Publication.OneTimeMembers[i], fixture.Publication.Manifest,
                (ulong)i + 1, 0, 1_095, 1_105, input => Sign(fixture, node, input));
    }

    private static byte[] Hash(string domain, byte[] value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 5 + value.Length];
        label.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 1), checked((uint)value.Length));
        value.CopyTo(input, label.Length + 5);
        return SHA256.HashData(input);
    }

    private static byte[] Sign(DeepIdV2PublicationAuthorityFixture fixture, ReadOnlyMemory<byte> node, byte[] input)
    {
        var key = PublicKeyAuth.GenerateKeyPair(fixture.Node(node.Span).Seed);
        try { return PublicKeyAuth.SignDetached(input, key.PrivateKey); }
        finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }

    private static DeepIdV2InventoryCommitStore Open(DeepIdV2PublicationAuthorityFixture fixture,
        string root, ReadOnlyMemory<byte> node, IMailboxDurabilityBarrier? durability = null) =>
        new(root, DeepIdV2PublicationAuthorityFixture.Network, fixture.Publication.Manifest.Field(2).Span,
            node.Span, durability: durability);

    private static byte[] U16(ushort value)
    { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value)
    { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static string TemporaryRoot() => Directory.CreateDirectory(Path.Combine(Path.GetTempPath(),
        "xnode-did2-claim-" + Guid.NewGuid().ToString("N"))).FullName;

    private sealed class CrashOnClaims(bool afterReplace) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier inner = new();
        public void FlushFileAndParentDirectory(string path) => inner.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => inner.FlushParentDirectory(path);
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (Path.GetFileName(finalPath) != "claims.state")
            { inner.ReplaceFile(temporaryPath, finalPath); return; }
            if (afterReplace) inner.ReplaceFile(temporaryPath, finalPath);
            throw new IOException("Synthetic crash at completed claim replacement.");
        }
    }
}
