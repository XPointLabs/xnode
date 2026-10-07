using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;

namespace XNode;

internal static class NativeCustodyKeyRing
{
    internal static IDataProtectionProvider OpenExisting(string absoluteDirectory, string application,
        IMailboxStorageSecurity security)
    {
        var directory = new DirectoryInfo(absoluteDirectory);
        for (var parent = directory; parent is not null; parent = parent.Parent)
            if (!parent.Exists || (parent.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Native custody key ring is absent or linked; provisioning is explicit.");
        var keys = directory.GetFiles("key-*.xml");
        if (keys.Length == 0)
            throw new InvalidDataException("Native custody key ring is absent; a reader cannot generate keys.");
        foreach (var key in keys)
        {
            if ((key.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new InvalidDataException("Native custody key ring requires regular files.");
            security.ValidateSecureFile(key.FullName);
        }
        return DataProtectionProvider.Create(directory,
            builder => builder.SetApplicationName(application).DisableAutomaticKeyGeneration());
    }
}
