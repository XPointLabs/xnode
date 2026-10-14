namespace XNode;

internal static class MailboxCustodyPathSafety
{
    internal static void RejectLinks(string path, string message)
    {
        // Normalize once per call. DirectoryInfo.Parent reconstructs and
        // normalizes every ancestor; keep the same fresh filesystem checks
        // without allocating a FileSystemInfo for each Windows parent.
        for (var current = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
             current is not null; current = Path.GetDirectoryName(current))
        {
            if (!OperatingSystem.IsWindows())
            {
                var entry = new DirectoryInfo(current);
                if (entry.LinkTarget is not null ||
                    (entry.Exists && (entry.Attributes & FileAttributes.ReparsePoint) != 0))
                    throw new UnauthorizedAccessException(message);
                continue;
            }

            // On Windows attributes describe the entry itself, including a
            // dangling link. Resolving LinkTarget on every ordinary ancestor
            // needlessly opens a handle for each repeated protected read.
            // Never cache: a link installed between reads must still reject.
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException(message);
        }
    }
}
