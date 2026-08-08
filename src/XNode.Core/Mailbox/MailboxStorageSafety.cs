using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;

namespace XNode.Core.Mailbox;

public interface IMailboxStorageSecurity
{
    void SecureDirectory(string path);

    void SecureFile(string path);
}

public sealed class MailboxStorageSecurity : IMailboxStorageSecurity
{
    public void SecureDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            SecureWindowsDirectory(path);
            return;
        }

        Directory.CreateDirectory(path);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var actual = File.GetUnixFileMode(path);
        if (actual != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute))
        {
            throw new UnauthorizedAccessException("Mailbox directory permissions could not be restricted.");
        }
    }

    public void SecureFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            SecureWindowsFile(path);
            return;
        }

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var actual = File.GetUnixFileMode(path);
        if (actual != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
        {
            throw new UnauthorizedAccessException("Mailbox file permissions could not be restricted.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static void SecureWindowsDirectory(string path)
    {
        var sid = GetServiceSid();
        var desired = new DirectorySecurity();
        desired.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        desired.SetOwner(sid);
        desired.AddAccessRule(new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        var directory = new DirectoryInfo(path);
        if (directory.Exists)
        {
            directory.SetAccessControl(desired);
        }
        else
        {
            directory.Create(desired);
        }

        VerifyWindowsAcl(directory.GetAccessControl(), sid);
    }

    [SupportedOSPlatform("windows")]
    private static void SecureWindowsFile(string path)
    {
        var sid = GetServiceSid();
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(sid);
        security.AddAccessRule(new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
        VerifyWindowsAcl(new FileInfo(path).GetAccessControl(), sid);
    }

    [SupportedOSPlatform("windows")]
    private static SecurityIdentifier GetServiceSid() =>
        WindowsIdentity.GetCurrent().User
        ?? throw new InvalidOperationException("The XNode service account SID is unavailable.");

    [SupportedOSPlatform("windows")]
    private static void VerifyWindowsAcl(FileSystemSecurity security, SecurityIdentifier serviceSid)
    {
        if (!security.AreAccessRulesProtected)
        {
            throw new UnauthorizedAccessException("Mailbox ACL inheritance is still enabled.");
        }

        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToArray();
        if (rules.Length == 0
            || rules.Any(rule => rule.IsInherited
                || rule.AccessControlType != AccessControlType.Allow
                || !serviceSid.Equals(rule.IdentityReference))
            || !rules.Any(rule => (rule.FileSystemRights & FileSystemRights.FullControl)
                == FileSystemRights.FullControl))
        {
            throw new UnauthorizedAccessException(
                "Mailbox ACL is not restricted to the XNode service account.");
        }
    }
}

public interface IMailboxDurabilityBarrier
{
    void FlushFileAndParentDirectory(string path);

    void FlushParentDirectory(string deletedPath);

    void ReplaceFile(string temporaryPath, string finalPath)
    {
        File.Move(temporaryPath, finalPath, overwrite: true);
    }

    void DeleteFile(string path)
    {
        File.Delete(path);
        FlushParentDirectory(path);
    }

    void DeleteDirectory(string path)
    {
        Directory.Delete(path);
        FlushParentDirectory(path);
    }
}

public sealed class MailboxDurabilityBarrier : IMailboxDurabilityBarrier
{
    private const uint MoveFileReplaceExisting = 0x1;
    private const uint MoveFileWriteThrough = 0x8;

    public void FlushFileAndParentDirectory(string path)
    {
        using (var handle = File.OpenHandle(
                   path,
                   FileMode.Open,
                   FileAccess.ReadWrite,
                   FileShare.Read,
                   FileOptions.WriteThrough))
        {
            RandomAccess.FlushToDisk(handle);
        }

        if (!OperatingSystem.IsWindows())
        {
            FlushUnixDirectory(Path.GetDirectoryName(path)
                ?? throw new InvalidOperationException("Mailbox file has no parent directory."));
        }
    }

    public void FlushParentDirectory(string deletedPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            FlushUnixDirectory(Path.GetDirectoryName(deletedPath)
                ?? throw new InvalidOperationException("Mailbox file has no parent directory."));
        }
    }

    public void ReplaceFile(string temporaryPath, string finalPath)
    {
        if (OperatingSystem.IsWindows())
        {
            if (!MoveFileEx(
                    temporaryPath,
                    finalPath,
                    MoveFileReplaceExisting | MoveFileWriteThrough))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            return;
        }

        File.Move(temporaryPath, finalPath, overwrite: true);
    }

    public void DeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            FlushParentDirectory(path);
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            var deletedPath = $"{path}.{Guid.NewGuid():N}.deleted";
            if (!MoveFileEx(path, deletedPath, MoveFileWriteThrough))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            // The write-through rename is the durable logical deletion. A crash may leave this
            // anonymous tombstone, which peer-journal startup removes before accepting traffic.
            File.Delete(deletedPath);
            return;
        }

        File.Delete(path);
        FlushParentDirectory(path);
    }

    public void DeleteDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            FlushParentDirectory(path);
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            var deletedPath = $"{path}.{Guid.NewGuid():N}.deleted";
            if (!MoveFileEx(path, deletedPath, MoveFileWriteThrough))
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            Directory.Delete(deletedPath);
            return;
        }

        Directory.Delete(path);
        FlushParentDirectory(path);
    }

    private static void FlushUnixDirectory(string directory)
    {
        var descriptor = Open(directory, 0);
        if (descriptor < 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        try
        {
            if (Fsync(descriptor) != 0)
            {
                var error = Marshal.GetLastPInvokeError();
                // Some otherwise durable filesystems do not implement directory fsync.
                if (error is not (22 or 95))
                {
                    throw new Win32Exception(error);
                }
            }
        }
        finally
        {
            _ = Close(descriptor);
        }
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int descriptor);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int descriptor);

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string existingPath, string newPath, uint flags);
}
