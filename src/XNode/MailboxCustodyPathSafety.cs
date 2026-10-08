namespace XNode;

internal static class MailboxCustodyPathSafety
{
    internal static void RejectLinks(string path, string message)
    {
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
        {
            if (!OperatingSystem.IsWindows())
            {
                if (current.LinkTarget is not null ||
                    (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0))
                    throw new UnauthorizedAccessException(message);
                continue;
            }

            // On Windows attributes describe the entry itself, including a
            // dangling link. Resolving LinkTarget on every ordinary ancestor
            // needlessly opens a handle for each repeated protected read.
            // Never cache: a link installed between reads must still reject.
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current.FullName); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException(message);
        }
    }
}
