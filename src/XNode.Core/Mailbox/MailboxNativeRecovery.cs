namespace XNode.Core.Mailbox;

// Denial-only native read guards. Recovery never changes permissions, repairs a
// floor, collects records or follows links outside the actual store directory.
internal static class MailboxNativeRecovery
{
    internal static void RequireDirectory(string path, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
            throw new InvalidDataException("Mailbox recovery requires a native directory.");
    }

    internal static void RequireFile(string path, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException("Mailbox recovery requires a regular native file.");
    }

    internal static void RequireNewDirectory(string path, string? ownerLock, CancellationToken token)
    {
        // Refusal only, including links in ancestors. A new blob owner need
        // not have created its directory yet; absence is not an I/O denial.
        for (string? ancestor = path; ancestor is not null; ancestor = Path.GetDirectoryName(ancestor))
        {
            try { RequireDirectory(ancestor, token); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
        try { RequireDirectory(path, token); }
        catch (FileNotFoundException) { return; }
        catch (DirectoryNotFoundException) { return; }
        foreach (var entry in Directory.EnumerateFileSystemEntries(path))
        {
            RequireFile(entry, token);
            if (ownerLock is null || Path.GetFileName(entry) != ownerLock || new FileInfo(entry).Length != 0)
                throw new InvalidDataException("New mailbox enrollment cannot adopt existing native custody.");
        }
    }
}
