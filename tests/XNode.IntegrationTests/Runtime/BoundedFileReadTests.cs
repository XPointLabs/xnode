namespace XNode.IntegrationTests.Runtime;

public sealed class BoundedFileReadTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4095)]
    [InlineData(4096)]
    [InlineData(65535)]
    [InlineData(65536)]
    public void ExactHandleReadEnforcesTheOriginalClosedByteBound(int length)
    {
        using var files = new Files();
        var bytes = Enumerable.Range(0, length).Select(index => (byte)(index % 251)).ToArray();
        File.WriteAllBytes(files.File, bytes);
        if (length is 0 or > 65535)
            Assert.Throws<InvalidDataException>(() => BoundedFileRead.Read(files.File, 1, 65535, "Closed byte bound."));
        else
            Assert.True(bytes.AsSpan().SequenceEqual(BoundedFileRead.Read(files.File, 1, 65535, "Closed byte bound.")));
        File.Delete(files.File); // No retained reader/handle after either outcome.
        Assert.False(File.Exists(files.File));
    }

    [Fact]
    public void LaterReadReopensActualBytesAndNeverReturnsAnEarlierSnapshot()
    {
        using var files = new Files();
        File.WriteAllBytes(files.File, [1, 2]);
        Assert.True(BoundedFileRead.Read(files.File, 1, 8, "Closed byte bound.").AsSpan().SequenceEqual(new byte[] { 1, 2 }));
        File.WriteAllBytes(files.File, [3, 4, 5]);
        Assert.True(BoundedFileRead.Read(files.File, 1, 8, "Closed byte bound.").AsSpan().SequenceEqual(new byte[] { 3, 4, 5 }));
        File.Delete(files.File);
        Assert.Throws<FileNotFoundException>(() => BoundedFileRead.Read(files.File, 1, 8, "Closed byte bound."));
    }

    [Theory]
    [InlineData(0, 8)]
    [InlineData(8, 7)]
    public void InvalidBoundsCannotAcquireFileBytes(int minimum, int maximum)
    {
        using var files = new Files();
        Assert.Throws<ArgumentOutOfRangeException>(() => BoundedFileRead.Read(files.File, minimum, maximum, "Closed byte bound."));
    }

    [Fact]
    public void ParallelPublicReadsPreserveSourceOrderAndCannotReuseAnOldRead()
    {
        using var files = new Files();
        var paths = Enumerable.Range(0, 9).Select(index => files.File + index).ToArray();
        for (var index = 0; index < paths.Length; index++) File.WriteAllBytes(paths[index], [(byte)(index + 1)]);
        var first = DeepIdV2NetworkAuthorityFileSource.ReadExactMany(paths);
        for (var index = 0; index < paths.Length; index++) Assert.True(first[index].AsSpan().SequenceEqual(new byte[] { (byte)(index + 1) }));
        File.WriteAllBytes(paths[2], [0x71, 0x72]);
        Assert.True(DeepIdV2NetworkAuthorityFileSource.ReadExactMany(paths)[2].AsSpan().SequenceEqual(new byte[] { 0x71, 0x72 }));
        foreach (var path in paths) File.Delete(path);
    }

    [Fact]
    public void ParallelFailureReturnsNoPartialFrameAndKeepsFirstTypedRefusal()
    {
        using var files = new Files();
        var empty = files.File + ".empty";
        File.WriteAllBytes(empty, []);
        File.WriteAllBytes(files.File, [1]);
        Assert.Throws<FileNotFoundException>(() => DeepIdV2NetworkAuthorityFileSource.ReadExactMany(
            [files.File + ".missing", empty, files.File]));
        Assert.Throws<InvalidDataException>(() => DeepIdV2NetworkAuthorityFileSource.ReadExactMany(
            [empty, files.File + ".missing", files.File]));
        File.Delete(empty); File.Delete(files.File);
    }

    [Theory]
    [InlineData(8, true)]
    [InlineData(7, false)]
    public void ParallelAllocationUsesOneExactAggregateBudget(int maximum, bool accepted)
    {
        using var files = new Files();
        var paths = Enumerable.Range(0, 4).Select(index => files.File + index).ToArray();
        foreach (var path in paths) File.WriteAllBytes(path, [1, 2]);
        var budget = new BoundedFileRead.ByteBudget(maximum, "Closed group bound.");
        if (accepted) Assert.Equal(4, DeepIdV2NetworkAuthorityFileSource.ReadExactMany(paths, budget).Length);
        else Assert.Throws<InvalidDataException>(() => DeepIdV2NetworkAuthorityFileSource.ReadExactMany(paths, budget));
        foreach (var path in paths) File.Delete(path);
    }

    private sealed class Files : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "bounded-file-read-" + Guid.NewGuid().ToString("N"));
        internal string File => Path.Combine(root, "record.bin");
        internal Files() => Directory.CreateDirectory(root);
        public void Dispose() => Directory.Delete(root, recursive: true);
    }
}
