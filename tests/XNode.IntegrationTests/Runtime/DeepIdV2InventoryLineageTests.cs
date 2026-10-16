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
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DifferentSignedServiceEpochOne_IsNotSameEpochFork_OriginalCustodySurvives(bool expiredPredecessor)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(
            authorServiceSuccessor: true, shortInitialService: expiredPredecessor);
        var root = TemporaryRoot();
        try
        {
            var originals = new ParsedXic1V2[2];
            var successors = new ParsedXic1V2[2];
            for (var replica = 0; replica < 2; replica++)
                originals[replica] = await CommitAsync(fixture, fixture.Publication, replica,
                    ReplicaDirectory(root, replica), productionJournalPath: true);
            if (expiredPredecessor)
            {
                fixture.Sample += 20; // Controlled fixture time, never a live clock override.
                Assert.True(BinaryPrimitives.ReadUInt64BigEndian(DeepIdV2PreKeyServiceCodec.Decode(fixture.Xps).Field(11).Span) <
                    fixture.Freshness.TrustedLowerUnixSeconds + 20, "The predecessor must genuinely be expired at trusted lower time.");
            }
            for (var replica = 0; replica < 2; replica++)
            {
                var directory = ReplicaDirectory(root, replica);
                var original = originals[replica];
                var next = await CommitAsync(fixture, fixture.ServiceSuccessorPublication!, replica, directory,
                    fixture.SuccessorXps, productionJournalPath: true);
                successors[replica] = next;
                AssertNoFailureMarker(directory);
                using (var reopened = Open(fixture, replica, directory))
                {
                    Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(reopened.ReadCurrentManifest()!.Field(5).Span));
                    Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(reopened.ReadCurrentManifest()!.Field(7).Span));
                    Assert.Equal(original.CanonicalBytes.ToArray(), reopened.ReadRetainedExactReceipt(fixture.Publication)!.CanonicalBytes.ToArray());
                }
                var after = StateHash(directory);
                Assert.Equal(next.CanonicalBytes.ToArray(), (await CommitAsync(fixture, fixture.ServiceSuccessorPublication!,
                    replica, directory, fixture.SuccessorXps, productionJournalPath: true)).CanonicalBytes.ToArray());
                if (!expiredPredecessor)
                    Assert.Equal(original.CanonicalBytes.ToArray(),
                        (await CommitAsync(fixture, fixture.Publication, replica, directory, productionJournalPath: true)).CanonicalBytes.ToArray());
                Assert.Equal(after, StateHash(directory));
            }
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(fixture.ServiceSuccessorPublication!,
                fixture.Placement.VerifiedPlacement, successors[0], successors[1]);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HistoricalSupportRead_CannotCrossCurrentnessOrCancellationBeforeCommit(bool cancel)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorServiceSuccessor: true);
        var root = TemporaryRoot();
        try
        {
            var directory = ReplicaDirectory(root, 0);
            await CommitAsync(fixture, fixture.Publication, 0, directory, productionJournalPath: true);
            var path = Path.Combine(directory, "did2-prekey-stage", Convert.ToHexString(fixture.Publication.NetworkId.Span),
                Convert.ToHexString(fixture.Publication.PublicationOperationId.Span), "manifest.xpp1");
            var before = StateHash(directory);
            using var cancellation = new CancellationTokenSource();
            var observer = new HistoricalReadSecurity(path, () =>
            {
                if (cancel) cancellation.Cancel();
                else fixture.Sample = 500;
            });
            Task<ParsedXic1V2> Attempt() => CommitAsync(fixture, fixture.ServiceSuccessorPublication!, 0, directory,
                fixture.SuccessorXps, productionJournalPath: true, observer, cancellation.Token);
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(Attempt);
            else await Assert.ThrowsAsync<Deep.Protocol.AccountDirectoryV1.AccountDirectoryFreshnessVerificationException>(Attempt);
            Assert.Equal(1, observer.Reads);
            Assert.Equal(before, StateHash(directory)); AssertNoFailureMarker(directory);
            fixture.Sample = 100; // Restore only the injected fixture clock fault.
            _ = await CommitAsync(fixture, fixture.ServiceSuccessorPublication!, 0, directory,
                fixture.SuccessorXps, productionJournalPath: true);
            AssertNoFailureMarker(directory);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private sealed class HistoricalReadSecurity(string expectedPath, Action afterReadValidation) : IMailboxStorageSecurity
    {
        private readonly MailboxStorageSecurity inner = new();
        internal int Reads { get; private set; }
        public void SecureDirectory(string path) => inner.SecureDirectory(path);
        public void SecureFile(string path) => inner.SecureFile(path);
        public void ValidateSecureFile(string path)
        {
            inner.ValidateSecureFile(path);
            if (!string.Equals(Path.GetFullPath(path), Path.GetFullPath(expectedPath), StringComparison.Ordinal)) return;
            Reads++; afterReadValidation();
        }
    }

    [Theory]
    [InlineData("predecessor")]
    [InlineData("generation")]
    [InlineData("policy")]
    [InlineData("expiry")]
    public async Task SignedInvalidServiceTransition_RejectsWithoutPoisoningPredecessor(string mutation)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(
            authorServiceSuccessor: true, serviceSuccessorMutation: mutation);
        var root = TemporaryRoot();
        try
        {
            for (var replica = 0; replica < 2; replica++)
            {
                var directory = ReplicaDirectory(root, replica);
                var original = await CommitAsync(fixture, fixture.Publication, replica, directory, productionJournalPath: true);
                var before = StateHash(directory);
                await Assert.ThrowsAsync<CryptographicException>(async () => await CommitAsync(fixture,
                    fixture.ServiceSuccessorPublication!, replica, directory, fixture.SuccessorXps, productionJournalPath: true));
                Assert.Equal(before, StateHash(directory)); AssertNoFailureMarker(directory);
                using var reopened = Open(fixture, replica, directory);
                Assert.Equal(original.CanonicalBytes.ToArray(), reopened.ReadCurrentCommitReceipt()!.CanonicalBytes.ToArray());
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingOrSubstitutedHistoricalSupport_RejectsWithoutMutation_ExactRecoverySucceeds(bool substitute)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorServiceSuccessor: true);
        var root = TemporaryRoot();
        try
        {
            for (var replica = 0; replica < 2; replica++)
            {
                var directory = ReplicaDirectory(root, replica);
                await CommitAsync(fixture, fixture.Publication, replica, directory, productionJournalPath: true);
                var path = Path.Combine(directory, "did2-prekey-stage", Convert.ToHexString(fixture.Publication.NetworkId.Span),
                    Convert.ToHexString(fixture.Publication.PublicationOperationId.Span), "manifest.xpp1");
                var exact = await File.ReadAllBytesAsync(path);
                if (substitute)
                {
                    var other = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(fixture.ServiceSuccessorPublication!.CanonicalBytes.Span,
                        fixture.Placement.ViewHash.Span, fixture.Publisher.CanonicalBytes.Span, fixture.Dca, fixture.SuccessorXps)[0];
                    await File.WriteAllBytesAsync(path, other);
                }
                else File.Move(path, path + ".held");
                var before = StateHash(directory);
                await Assert.ThrowsAsync<InvalidDataException>(async () => await CommitAsync(fixture,
                    fixture.ServiceSuccessorPublication!, replica, directory, fixture.SuccessorXps, productionJournalPath: true));
                Assert.Equal(before, StateHash(directory)); AssertNoFailureMarker(directory);
                if (substitute) await File.WriteAllBytesAsync(path, exact);
                else File.Move(path + ".held", path);
                _ = await CommitAsync(fixture, fixture.ServiceSuccessorPublication!, replica, directory,
                    fixture.SuccessorXps, productionJournalPath: true);
                AssertNoFailureMarker(directory);
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

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
        ParsedXpp1V2 publication, int replica, string directory, byte[]? exactService = null,
        bool productionJournalPath = false, IMailboxStorageSecurity? security = null, CancellationToken ct = default)
    {
        // Independent, test-owned candidate journals exercise the authorized
        // service CAS after the real current-proof/device/inventory verifier.
        // This helper is not the terminal: its earlier same-operation staging
        // conflict guard is not exercised or claimed as endpoint coverage.
        using var journal = new DeepIdV2PublicationJournal(
            productionJournalPath ? Path.Combine(directory, "did2-prekey-stage", Convert.ToHexString(publication.NetworkId.Span),
                Convert.ToHexString(publication.PublicationOperationId.Span)) :
                Path.Combine(directory, "test-candidates", Guid.NewGuid().ToString("N")),
            publication.NetworkId.Span, publication.PublicationOperationId.Span,
            fixture.Placement.ViewHash.Span, publication.PlacementHash.Span, publication.Manifest.Field(2).Span);
        var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
            publication.CanonicalBytes.Span, fixture.Placement.ViewHash.Span,
            fixture.Publisher.CanonicalBytes.Span, fixture.Dca, exactService ?? fixture.Xps);
        var retained = journal.ReadCommitted();
        var replay = retained is not null;
        if (replay)
        {
            Assert.Equal(publication.CanonicalBytes.ToArray(), retained!.Candidate!.CanonicalBytes.ToArray());
            Assert.Equal(exactService ?? fixture.Xps, retained.PublisherXps1.ToArray());
        }
        foreach (var fragment in fragments.Take(fragments.Count - 1))
            Assert.Equal(replay ? PublicationStageDisposition.ExactReplay : PublicationStageDisposition.Staged,
                journal.Stage(fragment, fixture.Publisher).Disposition);
        Assert.Equal(replay ? PublicationStageDisposition.ExactReplay : PublicationStageDisposition.CandidateReady,
            journal.Stage(fragments[^1], fixture.Publisher).Disposition);
        var local = fixture.Placement.ReplicaIds[replica];
        var node = new RouterNodeOptions
        {
            DataDirectory = directory,
            RouterId = Convert.ToHexString(local.Span),
            Ed25519PrivateKey = Convert.ToHexString(fixture.Node(local.Span).Seed)
        };
        var committer = new DeepIdV2PublicationFinalCommitter(node, new(fixture, fixture),
            fixture, fixture, security ?? new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        return await committer.CommitAsync(journal, fixture.Placement, null, ct);
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
