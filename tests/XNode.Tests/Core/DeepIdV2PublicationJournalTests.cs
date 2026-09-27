using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using XNode.Core.ContactPreKey;

namespace XNode.Tests.Core;

public sealed class DeepIdV2PublicationJournalTests
{
    private static readonly byte[] Network = Bytes(16, 0x11);
    private static readonly byte[] Operation = Bytes(32, 0x12);
    private static readonly byte[] View = Bytes(32, 0x13);

    [Fact]
    public void CompletePublication_SurvivesRestart_AndExactReplayDoesNotMutate()
    {
        using var fixture = new Fixture();
        var aggregate = Aggregate();
        var sequence = Sequence(aggregate, View);
        using (var journal = fixture.Open())
        {
            Assert.Equal(PublicationStageDisposition.Incomplete,
                journal.Stage(sequence[^1]).Disposition);
            Assert.Equal(PublicationStageDisposition.Staged,
                journal.Stage(sequence[0]).Disposition);
            Assert.Equal(PublicationStageDisposition.ExactReplay,
                journal.Stage(sequence[0]).Disposition);
            Assert.Equal(PublicationStageDisposition.Staged,
                journal.Stage(sequence[1]).Disposition);
            Assert.Equal(PublicationStageDisposition.ExactReplay,
                journal.Stage(sequence[1]).Disposition);
            Assert.Equal(PublicationStageDisposition.Incomplete,
                journal.Stage(sequence[^1]).Disposition);
            Assert.Null(journal.ReadCommitted());
        }
        using (var journal = fixture.Open())
        {
            Assert.Equal(PublicationStageDisposition.Staged,
                journal.Stage(sequence[2]).Disposition);
            var completed = journal.Stage(sequence[^1]);
            Assert.Equal(PublicationStageDisposition.CandidateReady, completed.Disposition);
            Assert.Equal(aggregate, completed.Candidate!.CanonicalBytes.ToArray());
            Assert.Equal(Did2(), completed.PublisherDid2!.CanonicalBytes.ToArray());
            Assert.Equal(Bytes(DeepIdV2ContactAuthorizationCodec.CanonicalLength,
                0xd1), completed.PublisherDca1.ToArray());
            Assert.Equal(Bytes(DeepIdV2BoundedPreKeyPublicationCodec.Xps1Length,
                0xe1), completed.PublisherXps1.ToArray());
            Assert.Equal(PublicationStageDisposition.ExactReplay,
                journal.Stage(sequence[^1]).Disposition);
        }
        using (var journal = fixture.Open())
        {
            var committed = journal.ReadCommitted()!;
            Assert.Equal(aggregate, committed.Candidate!.CanonicalBytes.ToArray());
            Assert.Equal(Did2(), committed.PublisherDid2!.CanonicalBytes.ToArray());
            Assert.Equal(Bytes(DeepIdV2ContactAuthorizationCodec.CanonicalLength,
                0xd1), committed.PublisherDca1.ToArray());
            Assert.Equal(Bytes(DeepIdV2BoundedPreKeyPublicationCodec.Xps1Length,
                0xe1), committed.PublisherXps1.ToArray());
        }
    }

    [Fact]
    public void DifferentManifestForSameOperation_LatchesForkAcrossRestart()
    {
        using var fixture = new Fixture();
        var first = Sequence(
            Aggregate(), View);
        var second = Sequence(
            Aggregate(placement: 0x51), View);
        using (var journal = fixture.Open())
        {
            Assert.Equal(PublicationStageDisposition.Staged,
                journal.Stage(first[0]).Disposition);
            Assert.Equal(PublicationStageDisposition.ForkLatched,
                journal.Stage(second[0]).Disposition);
        }
        using (var journal = fixture.Open())
            Assert.Equal(PublicationStageDisposition.ForkLatched,
                journal.Stage(first[0]).Disposition);
    }

    [Fact]
    public void ChunkFromDifferentView_LatchesForkBeforeAnyChunkIsWritten()
    {
        using var fixture = new Fixture();
        var aggregate = Aggregate();
        var first = Sequence(
            aggregate, View);
        var changedView = Sequence(
            aggregate, Bytes(32, 0x73));
        using var journal = fixture.Open();
        Assert.Equal(PublicationStageDisposition.Staged,
            journal.Stage(first[0]).Disposition);
        Assert.Equal(PublicationStageDisposition.ForkLatched,
            journal.Stage(changedView[1]).Disposition);
        Assert.False(File.Exists(Path.Combine(fixture.DirectoryPath,
            "chunk-000.xpp1")));
        Assert.Throws<InvalidDataException>(() => journal.ReadCommitted());
    }

    [Fact]
    public void CorruptDurableChunk_QuarantinesAndNeverResetsOperation()
    {
        using var fixture = new Fixture();
        var sequence = Sequence(
            Aggregate(), View);
        using (var journal = fixture.Open())
        {
            journal.Stage(sequence[0]);
            journal.Stage(sequence[1]);
        }
        var chunkPath = Path.Combine(fixture.DirectoryPath, "chunk-000.xpp1");
        var damaged = File.ReadAllBytes(chunkPath);
        damaged[^1] ^= 1;
        File.WriteAllBytes(chunkPath, damaged);
        Assert.Throws<InvalidDataException>(() => fixture.Open());
        Assert.True(File.Exists(Path.Combine(fixture.DirectoryPath, "fault.marker")));
        Assert.Contains(Directory.EnumerateFiles(fixture.DirectoryPath),
            path => Path.GetFileName(path).StartsWith(
                "chunk-000.xpp1.quarantine.", StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => fixture.Open());
    }

    [Fact]
    public void ExactCommitReplay_QuarantinesDamagedDurableChunkWithoutRestart()
    {
        using var fixture = new Fixture();
        var sequence = Sequence(Aggregate(), View);
        using var journal = fixture.Open();
        foreach (var fragment in sequence)
            journal.Stage(fragment);

        var chunkPath = Path.Combine(fixture.DirectoryPath, "chunk-000.xpp1");
        var damaged = File.ReadAllBytes(chunkPath);
        damaged[^1] ^= 1;
        File.WriteAllBytes(chunkPath, damaged);

        Assert.Throws<InvalidDataException>(() => journal.Stage(sequence[^1]));
        Assert.True(File.Exists(Path.Combine(fixture.DirectoryPath,
            "fault.marker")));
        Assert.Throws<InvalidDataException>(() => journal.ReadCommitted());
    }

    [Fact]
    public void LostManifestWithStagedChunk_QuarantinesBeforeOperationCanRestart()
    {
        using var fixture = new Fixture();
        var sequence = Sequence(Aggregate(), View);
        using var journal = fixture.Open();
        Assert.Equal(PublicationStageDisposition.Staged,
            journal.Stage(sequence[0]).Disposition);
        Assert.Equal(PublicationStageDisposition.Staged,
            journal.Stage(sequence[1]).Disposition);
        File.Delete(Path.Combine(fixture.DirectoryPath, "manifest.xpp1"));

        Assert.Throws<InvalidDataException>(() => journal.Stage(sequence[0]));
        Assert.True(File.Exists(Path.Combine(fixture.DirectoryPath,
            "fault.marker")));
        Assert.False(File.Exists(Path.Combine(fixture.DirectoryPath,
            "manifest.xpp1")));
        Assert.Throws<InvalidDataException>(() => journal.Stage(sequence[0]));
    }

    [Fact]
    public void WrongOperation_DoesNotCreatePublicationState()
    {
        using var fixture = new Fixture();
        var aggregate = Aggregate(operation: Bytes(32, 0x72));
        var sequence = Sequence(
            aggregate, View);
        using var journal = fixture.Open();
        Assert.Equal(PublicationStageDisposition.WrongScope,
            journal.Stage(sequence[0]).Disposition);
        Assert.False(File.Exists(Path.Combine(fixture.DirectoryPath, "manifest.xpp1")));
    }

    [Fact]
    public void WrongViewOrServiceCapability_CannotBeginOperation()
    {
        using var fixture = new Fixture();
        var aggregate = Aggregate();
        var wrongView = Sequence(
            aggregate, Bytes(32, 0x74));
        var wrongCapability = Sequence(
            Aggregate(capability: 0x76), View);
        using var journal = fixture.Open();
        Assert.Equal(PublicationStageDisposition.WrongScope,
            journal.Stage(wrongView[0]).Disposition);
        Assert.Equal(PublicationStageDisposition.WrongScope,
            journal.Stage(wrongCapability[0]).Disposition);
        Assert.False(File.Exists(Path.Combine(fixture.DirectoryPath, "manifest.xpp1")));
    }

    [Fact]
    public void PersistedManifestWithDifferentShard_IsQuarantinedOnRestart()
    {
        using var fixture = new Fixture();
        var original = Sequence(
            Aggregate(), View);
        var substituted = Sequence(
            Aggregate(capability: 0x76), View);
        using (var journal = fixture.Open())
            Assert.Equal(PublicationStageDisposition.Staged,
                journal.Stage(original[0]).Disposition);
        File.WriteAllBytes(Path.Combine(fixture.DirectoryPath, "manifest.xpp1"),
            substituted[0]);
        Assert.Throws<InvalidDataException>(() => fixture.Open());
        Assert.True(File.Exists(Path.Combine(fixture.DirectoryPath,
            "fault.marker")));
    }

    [Fact]
    public void ChangedPublisherDid2_LatchesSameOperationBeforeCommit()
    {
        using var fixture = new Fixture();
        var aggregate = Aggregate();
        var original = Sequence(aggregate, View);
        var changed = Sequence(aggregate, View, DeepIdV2Codec.AuthorDid2(
            Bytes(32, 0xa4), Bytes(1952, 0xa2), Bytes(16, 0xa3))
            .CanonicalBytes.ToArray());
        using var journal = fixture.Open();
        Assert.Equal(PublicationStageDisposition.Staged,
            journal.Stage(original[0]).Disposition);
        Assert.Equal(PublicationStageDisposition.ForkLatched,
            journal.Stage(changed[0]).Disposition);
    }

    [Fact]
    public void ReplicaPublisherHint_MustMatchDurableManifestBeforeAnyChunkMutation()
    {
        using var fixture = new Fixture();
        var sequence = Sequence(Aggregate(), View);
        var publisher = DeepIdV2Codec.DecodeDid2(Did2());
        var changed = DeepIdV2Codec.AuthorDid2(
            Bytes(32, 0xa4), Bytes(1952, 0xa2), Bytes(16, 0xa3));
        using var journal = fixture.Open();

        Assert.Equal(PublicationStageDisposition.WrongScope,
            journal.Stage(sequence[0], changed).Disposition);
        Assert.False(File.Exists(Path.Combine(fixture.DirectoryPath,
            "manifest.xpp1")));
        Assert.Equal(PublicationStageDisposition.Staged,
            journal.Stage(sequence[0], publisher).Disposition);
        Assert.Equal(PublicationStageDisposition.ForkLatched,
            journal.Stage(sequence[1], changed).Disposition);
        Assert.False(File.Exists(Path.Combine(fixture.DirectoryPath,
            "chunk-000.xpp1")));
        Assert.Equal(PublicationStageDisposition.ForkLatched,
            journal.Stage(sequence[1], publisher).Disposition);
    }

    [Fact]
    public void ReplicaPublisherHint_AllowsCompleteExactReplayOnlyForSameDid2()
    {
        using var fixture = new Fixture();
        var sequence = Sequence(Aggregate(), View);
        var publisher = DeepIdV2Codec.DecodeDid2(Did2());
        using var journal = fixture.Open();
        foreach (var fragment in sequence)
            _ = journal.Stage(fragment, publisher);
        var committed = journal.ReadCommitted();
        Assert.NotNull(committed);
        Assert.Equal(PublicationStageDisposition.CandidateReady,
            committed.Disposition);
        Assert.Equal(Did2(), committed.PublisherDid2!.CanonicalBytes.ToArray());
        Assert.Equal(PublicationStageDisposition.ExactReplay,
            journal.Stage(sequence[^1], publisher).Disposition);
    }

    private static IReadOnlyList<byte[]> Sequence(byte[] aggregate, byte[] view,
        byte[]? did2 = null) =>
        DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
            aggregate, view, did2 ?? Did2(),
            Bytes(DeepIdV2ContactAuthorizationCodec.CanonicalLength, 0xd1),
            Bytes(DeepIdV2BoundedPreKeyPublicationCodec.Xps1Length, 0xe1));

    private static byte[] Did2() => DeepIdV2Codec.AuthorDid2(
        Bytes(32, 0xa1), Bytes(1952, 0xa2), Bytes(16, 0xa3))
        .CanonicalBytes.ToArray();

    private static byte[] Aggregate(byte placement = 0x14, byte[]? operation = null,
        byte capability = 0x35)
    {
        var oneTime = DeepIdV2Dpk2Codec.Decode(DeepIdV2Dpk2Codec.Encode(
            Record(Dpk2PrekeyKind.OneTime)));
        var lastResort = DeepIdV2Dpk2Codec.Decode(DeepIdV2Dpk2Codec.Encode(
            Record(Dpk2PrekeyKind.LastResort)));
        ReadOnlyMemory<byte>[] fields =
        [
            Network, Bytes(32, capability), Bytes(32, 0x21),
            Reference("DPD1", Bytes(32, 0x25)), Be64(1),
            Reference("XPS1", Bytes(32, 0x45)), Be64(1),
            new byte[32], Be16(32), Bytes(32, 0x65),
            lastResort.ExactHash, Bytes(32, 0x20),
            Reference("DRS1", Bytes(32, 0x85)), Be64(100), Be64(100_000)
        ];
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(
            DeepIdV2PreKeyManifestCodec.Encode(fields, Bytes(64, 0x95)));
        return DeepIdV2PreKeyPublicationCodec.Encode(Network,
            operation ?? Operation, Bytes(32, placement), manifest,
            Enumerable.Repeat(oneTime, 32).ToArray(), lastResort);
    }

    private static Dpk2Record Record(Dpk2PrekeyKind kind) => new(
        Network, Bytes(32, 0x22), Bytes(32, 0x21), 1,
        Reference("DPD1", Bytes(32, 0x25)), 1, Bytes(32, 0x20),
        1, 1, Bytes(32, 0x26), 1, 100, 100, 100_000,
        Bytes(32, 0x27), Bytes(32, 0x28), Bytes(32, 0x29),
        Bytes(64, 0x30),
        kind == Dpk2PrekeyKind.OneTime ? Bytes(32, 0x31) : [],
        kind == Dpk2PrekeyKind.OneTime ? Bytes(32, 0x32) : [],
        Bytes(32, 0x33), Bytes(1184, 0x34), kind,
        kind == Dpk2PrekeyKind.LastResort ? (ushort)1 : (ushort)0,
        Bytes(64, 0x36), Bytes(64, 0x37));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static byte[] Be16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Be64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Reference(string magic, byte[] hash)
    {
        var bytes = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        hash.CopyTo(bytes, 6);
        return bytes;
    }

    private sealed class Fixture : IDisposable
    {
        internal string DirectoryPath { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "xnode-did2-journal-" + Guid.NewGuid().ToString("N"));

        internal DeepIdV2PublicationJournal Open() =>
            new(DirectoryPath, Network, Operation, View,
                Bytes(32, 0x14), Bytes(32, 0x35));

        public void Dispose()
        {
            if (Directory.Exists(DirectoryPath))
                Directory.Delete(DirectoryPath, recursive: true);
        }
    }
}
