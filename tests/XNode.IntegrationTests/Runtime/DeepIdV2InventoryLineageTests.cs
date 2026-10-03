using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2InventoryLineageTests
{
    [Fact]
    public async Task SignedSuccessorsThroughEpochFourteen_ReopenAndRetainedExactReplay()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorInventoryRotation: true);
        var root = TemporaryRoot();
        try
        {
            Assert.Equal(14, fixture.InventoryHistory.Count);
            var receipts = new List<ParsedXic1V2[]>();
            foreach (var publication in fixture.InventoryHistory)
            {
                var pair = new ParsedXic1V2[2];
                for (var replica = 0; replica < 2; replica++)
                {
                    var directory = ReplicaDirectory(root, replica);
                    pair[replica] = await CommitAsync(fixture, publication, replica, directory);
                    using var reopened = Open(fixture, replica, directory);
                    Assert.Equal(publication.CanonicalBytes.ToArray(),
                        reopened.ReadCurrentPublication()!.CanonicalBytes.ToArray());
                    Assert.Equal(publication.Manifest.ExactHash.ToArray(),
                        reopened.ReadCurrentManifest()!.ExactHash.ToArray());
                    Assert.Equal(pair[replica].CanonicalBytes.ToArray(),
                        reopened.ReadCurrentCommitReceipt()!.CanonicalBytes.ToArray());
                }
                DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(publication,
                    fixture.Placement.VerifiedPlacement, pair[0], pair[1]);
                receipts.Add(pair);
            }

            // The current store retains the latest two inventories. This does
            // not claim older-epoch claim reconciliation or retention closure.
            for (var replica = 0; replica < 2; replica++)
            {
                var directory = ReplicaDirectory(root, replica);
                var before = StateHash(directory);
                foreach (var epoch in new[] { 12, 13 })
                    Assert.Equal(receipts[epoch][replica].CanonicalBytes.ToArray(),
                        (await CommitAsync(fixture, fixture.InventoryHistory[epoch], replica, directory))
                        .CanonicalBytes.ToArray());
                Assert.Equal(before, StateHash(directory));
                using var reopened = Open(fixture, replica, directory);
                Assert.Equal(14UL, BinaryPrimitives.ReadUInt64BigEndian(
                    reopened.ReadCurrentManifest()!.Field(7).Span));
                AssertNoFailureMarker(directory);
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("wrong-predecessor")]
    [InlineData("skipped-epoch")]
    public async Task SignedButUnacceptedLineage_RejectsWithoutMutation_ValidSuccessorStillCommits(string candidate)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorInventoryRotation: true);
        var root = TemporaryRoot();
        try
        {
            var pair = new ParsedXic1V2[2];
            for (var replica = 0; replica < 2; replica++)
            {
                var directory = ReplicaDirectory(root, replica);
                await CommitAsync(fixture, fixture.Publication, replica, directory);
                var before = StateHash(directory);
                var rejection = await Assert.ThrowsAsync<ApplicationCoreFormatException>(async () =>
                    await CommitAsync(fixture, fixture.RotationCandidates[candidate], replica, directory));
                Assert.Equal(ApplicationCoreValidationStage.CryptographicVerification, rejection.Stage);
                Assert.Equal(ApplicationCoreRejection.InvalidLineage, rejection.Rejection);
                Assert.Equal(before, StateHash(directory));
                AssertNoFailureMarker(directory);
                using (var reopened = Open(fixture, replica, directory))
                    Assert.Equal(fixture.Publication.CanonicalBytes.ToArray(),
                        reopened.ReadCurrentPublication()!.CanonicalBytes.ToArray());
                pair[replica] = await CommitAsync(fixture, fixture.InventoryHistory[1], replica, directory);
            }
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(fixture.InventoryHistory[1],
                fixture.Placement.VerifiedPlacement, pair[0], pair[1]);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("same-epoch")]
    [InlineData("same-operation")]
    public async Task AuthorizedInventoryConflict_PersistsForkLatchWithoutReplacingActiveState(string candidate)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorInventoryRotation: true);
        var root = TemporaryRoot();
        try
        {
            for (var replica = 0; replica < 2; replica++)
            {
                var directory = ReplicaDirectory(root, replica);
                await CommitAsync(fixture, fixture.Publication, replica, directory);
                var before = StateHash(directory);
                await Assert.ThrowsAsync<InvalidDataException>(async () =>
                    await CommitAsync(fixture, fixture.RotationCandidates[candidate], replica, directory));
                Assert.Equal(before, StateHash(directory));
                Assert.Single(Directory.GetFiles(directory, "fork.marker", SearchOption.AllDirectories));
                Assert.Throws<InvalidDataException>(() =>
                {
                    using var reopened = Open(fixture, replica, directory);
                });
                // Even the original valid operation cannot clear the latch.
                await Assert.ThrowsAsync<InvalidDataException>(async () =>
                    await CommitAsync(fixture, fixture.Publication, replica, directory));
                Assert.Equal(before, StateHash(directory));
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task UnauthenticatedSameEpochCannotLatchAuthorizedInventory()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorInventoryRotation: true);
        var conflict = fixture.RotationCandidates["same-epoch"];
        var damaged = conflict.Manifest.CanonicalBytes.ToArray();
        damaged[^1] ^= 1;
        var invalid = DeepIdV2PreKeyPublicationCodec.Decode(DeepIdV2PreKeyPublicationCodec.Encode(
            conflict.NetworkId.Span, conflict.PublicationOperationId.Span, conflict.PlacementHash.Span,
            DeepIdV2PreKeyManifestCodec.Decode(damaged), conflict.OneTimeMembers, conflict.LastResortMember));
        var root = TemporaryRoot();
        try
        {
            for (var replica = 0; replica < 2; replica++)
            {
                var directory = ReplicaDirectory(root, replica);
                await CommitAsync(fixture, fixture.Publication, replica, directory);
                var before = StateHash(directory);
                var rejection = await Assert.ThrowsAsync<ApplicationCoreFormatException>(async () =>
                    await CommitAsync(fixture, invalid, replica, directory));
                Assert.Equal(ApplicationCoreValidationStage.CryptographicVerification, rejection.Stage);
                Assert.Equal(ApplicationCoreRejection.VerificationFailed, rejection.Rejection);
                Assert.Equal(before, StateHash(directory));
                AssertNoFailureMarker(directory);
                using var reopened = Open(fixture, replica, directory);
                Assert.Equal(fixture.Publication.CanonicalBytes.ToArray(),
                    reopened.ReadCurrentPublication()!.CanonicalBytes.ToArray());
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static async Task<ParsedXic1V2> CommitAsync(DeepIdV2PublicationAuthorityFixture fixture,
        ParsedXpp1V2 publication, int replica, string directory)
    {
        // Independent, test-owned candidate journals exercise the authorized
        // service CAS after the real current-proof/device/inventory verifier.
        // This helper is not the terminal: its earlier same-operation staging
        // conflict guard is not exercised or claimed as endpoint coverage.
        using var journal = new DeepIdV2PublicationJournal(
            Path.Combine(directory, "test-candidates", Guid.NewGuid().ToString("N")),
            publication.NetworkId.Span, publication.PublicationOperationId.Span,
            fixture.Placement.ViewHash.Span, publication.PlacementHash.Span, publication.Manifest.Field(2).Span);
        var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
            publication.CanonicalBytes.Span, fixture.Placement.ViewHash.Span,
            fixture.Publisher.CanonicalBytes.Span, fixture.Dca, fixture.Xps);
        foreach (var fragment in fragments.Take(fragments.Count - 1))
            Assert.Equal(PublicationStageDisposition.Staged,
                journal.Stage(fragment, fixture.Publisher).Disposition);
        Assert.Equal(PublicationStageDisposition.CandidateReady,
            journal.Stage(fragments[^1], fixture.Publisher).Disposition);
        var local = fixture.Placement.ReplicaIds[replica];
        var node = new RouterNodeOptions
        {
            DataDirectory = directory,
            RouterId = Convert.ToHexString(local.Span),
            Ed25519PrivateKey = Convert.ToHexString(fixture.Node(local.Span).Seed)
        };
        var committer = new DeepIdV2PublicationFinalCommitter(node, new(fixture, fixture),
            fixture, fixture, new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        return await committer.CommitAsync(journal, fixture.Placement, null, default);
    }

    private static DeepIdV2InventoryCommitStore Open(DeepIdV2PublicationAuthorityFixture fixture,
        int replica, string directory) => new(directory, DeepIdV2PublicationAuthorityFixture.Network,
        fixture.Publication.Manifest.Field(2).Span, fixture.Placement.ReplicaIds[replica].Span);

    private static byte[] StateHash(string directory) => SHA256.HashData(File.ReadAllBytes(
        Assert.Single(Directory.GetFiles(directory, "active.state", SearchOption.AllDirectories))));

    private static void AssertNoFailureMarker(string directory)
    {
        Assert.Empty(Directory.GetFiles(directory, "fork.marker", SearchOption.AllDirectories));
        Assert.Empty(Directory.GetFiles(directory, "fault.marker", SearchOption.AllDirectories));
    }

    private static string ReplicaDirectory(string root, int replica) => Path.Combine(root, replica.ToString());

    private static string TemporaryRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "xnode-did2-lineage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
