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
}
