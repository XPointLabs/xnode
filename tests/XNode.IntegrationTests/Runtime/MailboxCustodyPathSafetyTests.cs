namespace XNode.IntegrationTests.Runtime;

public sealed class MailboxCustodyPathSafetyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OrdinaryFileAndNotYetCreatedDescendantRemainAllowed(bool missing)
    {
        using var files = new Paths();
        var path = Path.Combine(files.Root, "ordinary.bin");
        if (!missing) File.WriteAllBytes(path, [1]);
        else path = Path.Combine(files.Root, "not-created", "ordinary.bin");
        MailboxCustodyPathSafety.RejectLinks(path, "Rejected linked custody.");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FileLinksRejectEvenWithMissingTarget(bool dangling)
    {
        using var files = new Paths();
        var target = Path.Combine(files.Root, "target.bin");
        if (!dangling) File.WriteAllBytes(target, [1]);
        var link = Path.Combine(files.Root, "link.bin");
        File.CreateSymbolicLink(link, target);
        Assert.Throws<UnauthorizedAccessException>(() =>
            MailboxCustodyPathSafety.RejectLinks(link, "Rejected linked custody."));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void DirectoryLinksRejectIncludingMissingDescendantAndTarget(bool dangling, bool child)
    {
        using var files = new Paths();
        var target = Path.Combine(files.Root, "target");
        if (!dangling) Directory.CreateDirectory(target);
        var link = Path.Combine(files.Root, "link");
        Directory.CreateSymbolicLink(link, target);
        var path = child ? Path.Combine(link, "not-created", "floor.bin") : link;
        Assert.Throws<UnauthorizedAccessException>(() =>
            MailboxCustodyPathSafety.RejectLinks(path, "Rejected linked custody."));
    }

    [Fact]
    public void SuccessfulReadDoesNotCacheAncestorsAcrossLaterLinkInstallation()
    {
        using var files = new Paths();
        var target = Path.Combine(files.Root, "target");
        Directory.CreateDirectory(target);
        var ancestor = Path.Combine(files.Root, "ancestor");
        Directory.CreateDirectory(ancestor);
        var path = Path.Combine(ancestor, "floor.bin");
        MailboxCustodyPathSafety.RejectLinks(path, "Rejected linked custody.");
        Directory.Delete(ancestor);
        Directory.CreateSymbolicLink(ancestor, target);
        Assert.Throws<UnauthorizedAccessException>(() =>
            MailboxCustodyPathSafety.RejectLinks(path, "Rejected linked custody."));
    }

    private sealed class Paths : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "mailbox-path-safety-" + Guid.NewGuid().ToString("N"));
        internal Paths() => Directory.CreateDirectory(Root);
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
