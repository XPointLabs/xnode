using System.Security.AccessControl;
using System.Security.Principal;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class MailboxStorageSecurityReadTests
{
    [Fact]
    public void RepeatedValidationKeepsActualProtectedFileSecurityUnchanged()
    {
        var root = Path.Combine(Path.GetTempPath(), "mailbox-security-read-" + Guid.NewGuid().ToString("N"));
        var security = new MailboxStorageSecurity();
        security.SecureDirectory(root);
        var file = Path.Combine(root, "record.bin");
        try
        {
            File.WriteAllBytes(file, [1]);
            security.SecureFile(file);
            var before = ReadSecurity(file);
            for (var index = 0; index < 256; index++) security.ValidateSecureFile(file);
            Assert.True(before.AsSpan().SequenceEqual(ReadSecurity(file)));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void ValidationRejectsExpandedReadAccessWithoutRepairingIt()
    {
        var root = Path.Combine(Path.GetTempPath(), "mailbox-security-read-" + Guid.NewGuid().ToString("N"));
        var security = new MailboxStorageSecurity();
        security.SecureDirectory(root);
        var file = Path.Combine(root, "record.bin");
        try
        {
            File.WriteAllBytes(file, [1]);
            security.SecureFile(file);
            if (OperatingSystem.IsWindows())
            {
                var acl = new FileInfo(file).GetAccessControl();
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.ReadData, AccessControlType.Allow));
                new FileInfo(file).SetAccessControl(acl);
            }
            else File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            var expanded = ReadSecurity(file);
            Assert.Throws<UnauthorizedAccessException>(() => security.ValidateSecureFile(file));
            Assert.True(expanded.AsSpan().SequenceEqual(ReadSecurity(file)));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static byte[] ReadSecurity(string file) => OperatingSystem.IsWindows()
        ? new FileInfo(file).GetAccessControl().GetSecurityDescriptorBinaryForm()
        : BitConverter.GetBytes((int)File.GetUnixFileMode(file));
}
