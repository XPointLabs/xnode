using System.Buffers.Binary;
using System.Text;
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
        var sequence = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(aggregate, View);
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
            Assert.Equal(PublicationStageDisposition.ExactReplay,
                journal.Stage(sequence[^1]).Disposition);
        }
        using (var journal = fixture.Open())
            Assert.Equal(aggregate, journal.ReadCommitted()!.CanonicalBytes.ToArray());
    }

    [Fact]
    public void DifferentManifestForSameOperation_LatchesForkAcrossRestart()
    {
        using var fixture = new Fixture();
        var first = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
            Aggregate(), View);
        var second = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
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
        var first = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
            aggregate, View);
        var changedView = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
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
        var sequence = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
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
    public void WrongOperation_DoesNotCreatePublicationState()
    {
        using var fixture = new Fixture();
        var aggregate = Aggregate(operation: Bytes(32, 0x72));
        var sequence = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
            aggregate, View);
        using var journal = fixture.Open();
        Assert.Equal(PublicationStageDisposition.WrongScope,
            journal.Stage(sequence[0]).Disposition);
        Assert.False(File.Exists(Path.Combine(fixture.DirectoryPath, "manifest.xpp1")));
    }

    private static byte[] Aggregate(byte placement = 0x14, byte[]? operation = null)
    {
        var oneTime = DeepIdV2Dpk2Codec.Decode(DeepIdV2Dpk2Codec.Encode(
            Record(Dpk2PrekeyKind.OneTime)));
        var lastResort = DeepIdV2Dpk2Codec.Decode(DeepIdV2Dpk2Codec.Encode(
            Record(Dpk2PrekeyKind.LastResort)));
        ReadOnlyMemory<byte>[] fields =
        [
            Network, Bytes(32, 0x35), Bytes(32, 0x21),
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
            new(DirectoryPath, Network, Operation);

        public void Dispose()
        {
            if (Directory.Exists(DirectoryPath))
                Directory.Delete(DirectoryPath, recursive: true);
        }
    }
}
