using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

public sealed class ProductionMailboxAuthorityOptions
{
    public bool Enabled { get; set; }
    public string ArtifactPath { get; set; } = "";
    public string RevocationArtifactPath { get; set; } = "";
    public string TopologyArtifactPath { get; set; } = "";
    public string SelectionArtifactDirectory { get; set; } = "";
    public string ReadinessBlindedPlacementId { get; set; } = "";
    public string ReadinessSelectionInputCommitment { get; set; } = "";
    public string ArtifactTrustRoot { get; set; } = "";
    public string LastKnownGoodPath { get; set; } = "";
    public string ClosureDirectory { get; set; } = "";
    public string ClosureStateHmacKeyPath { get; set; } = "";
    public string ClosurePublisherEd25519PublicKey { get; set; } = "";
    public string PinnedMrXPublicKeySha256 { get; set; } = "";
    public string ExpectedNetworkId { get; set; } = "";
    public uint ClockSkewSeconds { get; set; } = 60;
    public int MaximumArtifactBytes { get; set; } = 65_536;
    public int MaximumRevocationArtifactBytes { get; set; } = 131_072;
    public int MaximumTopologyArtifactBytes { get; set; } =
        ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes;
    public int MaximumSelectionArtifactBytes { get; set; } =
        ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes;
    public int MaximumStoredClosures { get; set; } = 100_000;
    public long MaximumClosureStoreBytes { get; set; } = 536_870_912;
    public int MaximumClosureVersionsPerSelection { get; set; } = 4;
    public int MaximumClosureLineagesPerSelection { get; set; } = 4;
    public int MaximumClosureReservations { get; set; } = 128;
    public uint MaximumClosureReservationLifetimeSeconds { get; set; } = 86_400;
    public uint MinimumClosureReservationLifetimeSeconds { get; set; } = 60;
    public int ClosureScheduleAccountingOverheadBytes { get; set; } = 1_024;

    public void Validate(RouterNodeOptions node, bool isProduction)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (!Enabled)
        {
            if (!string.IsNullOrEmpty(ArtifactPath)
                || !string.IsNullOrEmpty(RevocationArtifactPath)
                || !string.IsNullOrEmpty(TopologyArtifactPath)
                || !string.IsNullOrEmpty(SelectionArtifactDirectory)
                || !string.IsNullOrEmpty(ReadinessBlindedPlacementId)
                || !string.IsNullOrEmpty(ReadinessSelectionInputCommitment)
                || !string.IsNullOrEmpty(LastKnownGoodPath)
                || !string.IsNullOrEmpty(ClosureDirectory)
                || !string.IsNullOrEmpty(ClosureStateHmacKeyPath)
                || !string.IsNullOrEmpty(ClosurePublisherEd25519PublicKey)
                || !string.IsNullOrEmpty(ArtifactTrustRoot)
                || !string.IsNullOrEmpty(PinnedMrXPublicKeySha256)
                || !string.IsNullOrEmpty(ExpectedNetworkId))
            {
                throw new InvalidOperationException(
                    "MailboxClientProductionAuthority must be either fully enabled or empty.");
            }

            return;
        }

        if (!isProduction)
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority is valid only in Production.");
        }

        _ = DecodeHex(
            PinnedMrXPublicKeySha256,
            ProductionMailboxAuthorityConstants.HashLength,
            "Mr. X public-key pin");
        _ = DecodeHex(
            ExpectedNetworkId,
            ProductionMailboxAuthorityConstants.NetworkIdLength,
            "network id");
        var readinessPlacementId = DecodeHex(
            ReadinessBlindedPlacementId,
            ProductionMailboxTopologyConstants.HashLength,
            "readiness blinded placement id");
        var readinessSelectionInput = DecodeHex(
            ReadinessSelectionInputCommitment,
            ProductionMailboxTopologyConstants.HashLength,
            "readiness selection-input commitment");
        if (!CryptographicOperations.FixedTimeEquals(
                ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
                    new BlindedPlacementId(readinessPlacementId)),
                readinessSelectionInput))
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority readiness selection commitment mismatch.");
        }
        _ = DecodeHex(ClosurePublisherEd25519PublicKey, 32,
            "closure publisher Ed25519 public key");
        if (ClockSkewSeconds > ProductionMailboxAuthorityConstants.MaximumClockSkewSeconds
            || MaximumArtifactBytes is < 1 or > 1_048_576
            || MaximumRevocationArtifactBytes is < 1 or > 1_048_576
            || MaximumTopologyArtifactBytes is < 1
                or > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes
            || MaximumSelectionArtifactBytes is < 1
                or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || MaximumStoredClosures is < 1 or > 1_000_000
            || MaximumClosureStoreBytes is < 1_048_576 or > 107_374_182_400
            || MaximumClosureVersionsPerSelection is < 2 or > 16
            || MaximumClosureLineagesPerSelection is < 1 or > 16
            || MaximumClosureReservations is < 1 or > 4_096
            || MaximumClosureReservationLifetimeSeconds is < 60 or > 604_800
            || MinimumClosureReservationLifetimeSeconds < 30
            || MinimumClosureReservationLifetimeSeconds
                > MaximumClosureReservationLifetimeSeconds
            || ClosureScheduleAccountingOverheadBytes is < 256 or > 65_536)
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority bounds are invalid.");
        }

        var artifact = RequireAbsolutePath(ArtifactPath, "artifact");
        var revocationArtifact = RequireAbsolutePath(
            RevocationArtifactPath,
            "revocation artifact");
        var topologyArtifact = RequireAbsolutePath(
            TopologyArtifactPath,
            "topology artifact");
        var selectionDirectory = RequireAbsolutePath(
            SelectionArtifactDirectory,
            "selection artifact directory");
        var artifactTrustRoot = RequireAbsolutePath(ArtifactTrustRoot, "artifact trust root");
        var lkg = RequireAbsolutePath(LastKnownGoodPath, "LKG");
        var closureDirectory = RequireAbsolutePath(ClosureDirectory, "closure directory");
        var closureHmacKey = RequireAbsolutePath(ClosureStateHmacKeyPath, "closure HMAC key");
        if (string.Equals(artifact, lkg, PathComparison)
            || string.Equals(revocationArtifact, lkg, PathComparison)
            || string.Equals(topologyArtifact, lkg, PathComparison)
            || string.Equals(artifact, revocationArtifact, PathComparison)
            || string.Equals(artifact, topologyArtifact, PathComparison)
            || string.Equals(revocationArtifact, topologyArtifact, PathComparison))
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority artifact and LKG paths must differ.");
        }

        var dataRoot = Path.GetFullPath(node.DataDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!IsDescendant(lkg, dataRoot))
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority LKG must be inside Node:DataDirectory.");
        }
        if (!IsDescendant(closureDirectory, dataRoot)
            || !IsDescendant(closureHmacKey, dataRoot)
            || string.Equals(closureDirectory, dataRoot, PathComparison))
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority closure state must be inside Node:DataDirectory.");
        }

        if (!IsDescendant(artifact, artifactTrustRoot))
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority artifact must be inside its trust root.");
        }

        if (!IsDescendant(revocationArtifact, artifactTrustRoot))
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority revocation artifact must be inside its trust root.");
        }

        if (!IsDescendant(topologyArtifact, artifactTrustRoot)
            || !IsDescendant(selectionDirectory, artifactTrustRoot))
        {
            throw new InvalidOperationException(
                "MailboxClientProductionAuthority topology/selection artifacts must be inside their trust root.");
        }
    }

    internal byte[] GetPinnedMrXKeyHash() => DecodeHex(
        PinnedMrXPublicKeySha256,
        ProductionMailboxAuthorityConstants.HashLength,
        "Mr. X public-key pin");

    internal byte[] GetExpectedNetworkId() => DecodeHex(
        ExpectedNetworkId,
        ProductionMailboxAuthorityConstants.NetworkIdLength,
        "network id");

    internal byte[] GetReadinessSelectionInputCommitment() => DecodeHex(
        ReadinessSelectionInputCommitment,
        ProductionMailboxTopologyConstants.HashLength,
        "readiness selection-input commitment");

    internal byte[] GetReadinessBlindedPlacementId() => DecodeHex(
        ReadinessBlindedPlacementId,
        ProductionMailboxTopologyConstants.HashLength,
        "readiness blinded placement id");

    internal byte[] GetClosurePublisherPublicKey() => DecodeHex(
        ClosurePublisherEd25519PublicKey, 32,
        "closure publisher Ed25519 public key");

    internal string GetArtifactTrustRoot() => Path.GetFullPath(ArtifactTrustRoot)
        .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static bool IsDescendant(string path, string root)
    {
        var canonicalRoot = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return path.StartsWith(canonicalRoot + Path.DirectorySeparatorChar, PathComparison);
    }

    private static string RequireAbsolutePath(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value))
        {
            throw new InvalidOperationException(
                $"MailboxClientProductionAuthority {name} path must be absolute.");
        }

        return Path.GetFullPath(value);
    }

    private static byte[] DecodeHex(string? value, int length, string name)
    {
        if (value is null
            || value.Length != length * 2
            || value.Any(static character =>
                character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new InvalidOperationException(
                $"MailboxClientProductionAuthority {name} must be canonical lowercase hex.");
        }

        var decoded = Convert.FromHexString(value);
        if (decoded.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidOperationException(
                $"MailboxClientProductionAuthority {name} cannot be all-zero.");
        }

        return decoded;
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
}

public sealed record ProductionMailboxNodeIngress(
    Uri Endpoint,
    ReadOnlyMemory<byte> CurrentSpkiSha256,
    ReadOnlyMemory<byte> NextSpkiSha256);

public sealed record ProductionMailboxAuthorityStatus(
    bool Enabled,
    bool ArtifactVerified,
    bool LastKnownGoodProtected,
    bool RevocationArtifactVerified,
    bool Ready,
    string Reason,
    ulong AuthorityGeneration,
    ulong RevocationGeneration)
{
    public string EndpointRole { get; init; } = "node-ingress";
    public string Transport { get; init; } = "authenticated-mau2";
    public bool AuthorityRevocationReady { get; init; }
    public bool ProductionMailboxRoutesReady { get; init; }
    public bool TopologyArtifactVerified { get; init; }
    public ulong TopologyGeneration { get; init; }
}

public sealed record ProductionMailboxTopologyReplica(
    ReadOnlyMemory<byte> ReplicaId,
    ReadOnlyMemory<byte> CanonicalMembershipProof,
    Uri HttpsEndpoint,
    ReadOnlyMemory<byte> CurrentSpkiSha256,
    ReadOnlyMemory<byte> NextSpkiSha256);

public sealed record ProductionMailboxEpochTopology(
    ulong Epoch,
    ReadOnlyMemory<byte> MembershipCommitment,
    ReadOnlyMemory<byte> MailboxPlacementCommitment,
    ReadOnlyMemory<byte> SelectionInputCommitment,
    IReadOnlyList<ProductionMailboxTopologyReplica> Replicas);

/// <summary>
/// Production PMT1/PMS1 boundary. An implementation must return exactly two distinct replicas,
/// canonical MIP1 proofs bound to the requested epoch/commitments, and public HTTPS endpoints
/// with current/next SPKI pins. PMA1/PMR1 never imply or synthesize these values.
/// </summary>
public interface IProductionMailboxTopologyProvider
{
    bool IsConfigured { get; }

    bool TryResolve(
        ulong epoch,
        ReadOnlyMemory<byte> membershipCommitment,
        ReadOnlyMemory<byte> placementCommitment,
        ReadOnlyMemory<byte> blindedPlacementId,
        ReadOnlyMemory<byte> selectionInputCommitment,
        out ProductionMailboxEpochTopology? topology);
}

public interface IProductionMailboxAuthorityFileSecurity
{
    void ValidateReadOnlyArtifact(string path, string trustRoot);

    void ValidateProtectedLastKnownGood(string path, string trustRoot);

    void ValidateProtectedLock(string path, string trustRoot);
}

public sealed class ProductionMailboxAuthorityFileSecurity : IProductionMailboxAuthorityFileSecurity
{
    public void ValidateReadOnlyArtifact(string path, string trustRoot)
    {
        ValidateRegularPath(path, trustRoot, "authority artifact", writableAncestors: false);
        if (OperatingSystem.IsWindows())
        {
            ValidateWindowsReadOnly(path);
            return;
        }

        if (File.GetUnixFileMode(path) != UnixFileMode.UserRead)
        {
            throw new UnauthorizedAccessException(
                "Production mailbox authority artifact permissions are not read-only and private.");
        }

        ValidateUnixFile(path, UnixFileMode.UserRead, "authority artifact");
    }

    public void ValidateProtectedLastKnownGood(string path, string trustRoot)
    {
        ValidateRegularPath(path, trustRoot, "authority LKG", writableAncestors: true);
        if (OperatingSystem.IsWindows())
        {
            ValidateWindowsFile(path, requireReadOnly: false);
            return;
        }

        if (File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
        {
            throw new UnauthorizedAccessException(
                "Production mailbox authority LKG permissions are not private.");
        }

        ValidateUnixFile(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            "authority LKG");
    }

    public void ValidateProtectedLock(string path, string trustRoot) =>
        ValidateProtectedLastKnownGood(path, trustRoot);

    private static void ValidateRegularPath(
        string path,
        string trustRoot,
        string name,
        bool writableAncestors)
    {
        if (!File.Exists(path))
        {
            throw new InvalidDataException($"Production mailbox {name} is missing.");
        }

        var file = new FileInfo(path);
        if ((file.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
        {
            throw new InvalidDataException($"Production mailbox {name} is not a regular file.");
        }

        var canonicalRoot = Path.GetFullPath(trustRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = file.Directory
            ?? throw new InvalidDataException($"Production mailbox {name} has no parent directory.");
        while (true)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"Production mailbox {name} path traverses a reparse point.");
            }

            ValidateDirectory(current, writableAncestors);
            if (string.Equals(
                    current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                    canonicalRoot,
                    PathComparison))
            {
                break;
            }

            current = current.Parent
                ?? throw new UnauthorizedAccessException(
                    $"Production mailbox {name} is outside its trust root.");
        }
    }

    private static void ValidateDirectory(DirectoryInfo directory, bool writable)
    {
        if (OperatingSystem.IsWindows())
        {
            ValidateWindowsDirectory(directory, writable);
            return;
        }

        ValidateUnixDirectory(directory.FullName, writable);
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateUnixDirectory(string path, bool requireOwnerWrite)
    {
        var mode = File.GetUnixFileMode(path);
        var required = UnixFileMode.UserRead | UnixFileMode.UserExecute
            | (requireOwnerWrite ? UnixFileMode.UserWrite : 0);
        var forbidden = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
        if ((mode & required) != required || (mode & forbidden) != 0)
        {
            throw new UnauthorizedAccessException(
                "Production mailbox authority parent directory permissions are unsafe.");
        }

        ProductionMailboxAuthorityNativeFile.ValidateUnixOwner(path, directory: true);
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateUnixFile(string path, UnixFileMode expected, string name)
    {
        if (File.GetUnixFileMode(path) != expected)
        {
            throw new UnauthorizedAccessException(
                $"Production mailbox {name} permissions are unsafe.");
        }


        ProductionMailboxAuthorityNativeFile.ValidateUnixOwner(path, directory: false);
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsReadOnly(string path)
    {
        var file = new FileInfo(path);
        if ((file.Attributes & FileAttributes.ReadOnly) == 0)
        {
            throw new UnauthorizedAccessException(
                "Production mailbox authority artifact is not read-only.");
        }

        ValidateWindowsFile(path, requireReadOnly: true);
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsFile(string path, bool requireReadOnly)
    {
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new UnauthorizedAccessException("Service SID is unavailable.");
        var security = new FileInfo(path).GetAccessControl();
        ValidateWindowsAcl(security, current, requireReadOnly);
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsDirectory(DirectoryInfo directory, bool writable)
    {
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new UnauthorizedAccessException("Service SID is unavailable.");
        ValidateWindowsAcl(directory.GetAccessControl(), current, requireReadOnly: false);
    }

    [SupportedOSPlatform("windows")]
    internal static void ValidateWindowsAcl(
        FileSystemSecurity security,
        SecurityIdentifier current,
        bool requireReadOnly)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier));
        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToArray();
        const FileSystemRights write = FileSystemRights.Write
            | FileSystemRights.Delete
            | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions
            | FileSystemRights.TakeOwnership;
        if (!security.AreAccessRulesProtected
            || !current.Equals(owner)
            || rules.Length == 0
            || rules.Any(rule => rule.IsInherited)
            || rules.Any(rule => rule.AccessControlType != AccessControlType.Allow
                || !current.Equals(rule.IdentityReference))
            || requireReadOnly && rules.Any(rule => rule.AccessControlType == AccessControlType.Allow
                && (rule.FileSystemRights & write) != 0)
            || !rules.Any(rule => rule.AccessControlType == AccessControlType.Allow
                && current.Equals(rule.IdentityReference)
                && (requireReadOnly
                    ? (rule.FileSystemRights & FileSystemRights.Read) != 0
                    : (rule.FileSystemRights & FileSystemRights.FullControl)
                        == FileSystemRights.FullControl)))
        {
            throw new UnauthorizedAccessException(
                "Production mailbox authority artifact ACL is not protected read-only.");
        }
    }

    private static StringComparison PathComparison => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;
}

internal static class ProductionMailboxAuthorityNativeFile
{
    private const int AtCurrentWorkingDirectory = -100;
    private const int LinuxOpenReadOnly = 0;
    private const int LinuxOpenReadWrite = 2;
    private const int LinuxCreate = 0x40;
    private const int LinuxExclusive = 0x80;
    private const int LinuxNoFollow = 0x20_000;
    private const int LinuxCloseOnExec = 0x80_000;
    private const long LinuxOpenAt2SystemCall = 437;
    private const ulong LinuxResolveNoSymlinks = 0x04;
    private const int LinuxLockExclusive = 2;
    private const int LinuxLockNonBlocking = 4;
    private const int LinuxUnlock = 8;
    private const int AtEmptyPath = 0x1000;
    private const int AtSymlinkNoFollow = 0x100;
    private const uint StatxBasicStats = 0x7ff;
    private const ushort UnixRegularFile = 0x8000;
    private const ushort UnixDirectory = 0x4000;
    private const ushort UnixFileTypeMask = 0xf000;
    private const uint GenericRead = 0x8000_0000;
    private const uint GenericWrite = 0x4000_0000;
    private const uint WriteDac = 0x0004_0000;
    private const uint WriteOwner = 0x0008_0000;
    private const uint ShareRead = 0x1;
    private const uint ShareWrite = 0x2;
    private const uint ShareDelete = 0x4;
    private const uint CreateNew = 1;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x80;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint FileFlagOpenReparsePoint = 0x20_0000;
    private const uint FileFlagWriteThrough = 0x8000_0000;
    private const uint LockfileExclusiveLock = 0x2;
    private const uint LockfileFailImmediately = 0x1;
    private const uint OwnerSecurityInformation = 0x1;
    private const uint DaclSecurityInformation = 0x4;
    private const uint ProtectedDaclSecurityInformation = 0x8000_0000;
    private const ushort UnixPermissionMask = 0x1ff;
    private const ushort UnixPrivateReadWrite = 0x180;

    internal static FileStream OpenStableRead(
        string path,
        Action validate,
        Action? afterActualOpen = null)
    {
        validate();
        using var before = Open(
            path,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            createNew: false);
        var beforeIdentity = Identity(before.SafeFileHandle);
        var actual = Open(
            path,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            createNew: false);
        try
        {
            var actualIdentity = Identity(actual.SafeFileHandle);
            afterActualOpen?.Invoke();
            validate();
            using var after = Open(
                path,
                FileAccess.Read,
                FileShare.Read | FileShare.Delete,
                createNew: false);
            var afterIdentity = Identity(after.SafeFileHandle);
            if (beforeIdentity != actualIdentity || actualIdentity != afterIdentity)
            {
                throw new InvalidDataException(
                    "Production mailbox protected file identity changed while opening.");
            }

            return actual;
        }
        catch
        {
            actual.Dispose();
            throw;
        }
    }

    internal static void ValidateUnixOwner(string path, bool directory)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "Production mailbox protected paths support Windows and Linux only.");
        }

        if (Statx(
                AtCurrentWorkingDirectory,
                path,
                AtSymlinkNoFollow,
                StatxBasicStats,
                out var stat) != 0)
        {
            throw new IOException("Production mailbox path identity is unavailable.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        var expectedType = directory ? UnixDirectory : UnixRegularFile;
        if (stat.UserId != GetEffectiveUserId()
            || (stat.Mode & UnixFileTypeMask) != expectedType)
        {
            throw new UnauthorizedAccessException(
                "Production mailbox path owner or type is unsafe.");
        }
    }

    internal static IDisposable AcquireLock(
        string path,
        Action validate,
        IMailboxDurabilityBarrier durability,
        Action? afterCreateBeforeSecure = null)
    {
        const int maximumAttempts = 50;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return AcquireLockOnce(
                    path,
                    validate,
                    durability,
                    afterCreateBeforeSecure);
            }
            catch (IOException) when (attempt < maximumAttempts)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(10));
            }
        }
    }

    private static IDisposable AcquireLockOnce(
        string path,
        Action validate,
        IMailboxDurabilityBarrier durability,
        Action? afterCreateBeforeSecure)
    {
        FileIdentity? beforeIdentity = null;
        try
        {
            using var before = Open(
                path,
                FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete,
                createNew: false);
            beforeIdentity = Identity(before.SafeFileHandle);
            validate();
        }
        catch (FileNotFoundException)
        {
            // Creation below is exclusive and never follows an existing final-path link.
        }

        FileStream actual;
        var created = false;
        if (beforeIdentity is null)
        {
            actual = Open(
                path,
                FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete,
                createNew: true);
            created = true;
        }
        else
        {
            actual = Open(
                path,
                FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete,
                createNew: false);
        }

        try
        {
            var actualIdentity = Identity(actual.SafeFileHandle);
            if (beforeIdentity is not null && beforeIdentity.Value != actualIdentity)
            {
                throw new InvalidDataException(
                    "Production mailbox lock identity changed while opening.");
            }

            if (created)
            {
                afterCreateBeforeSecure?.Invoke();
                SecureCreatedHandle(actual.SafeFileHandle);
                RandomAccess.FlushToDisk(actual.SafeFileHandle);
                durability.FlushParentDirectory(path);
            }

            validate();
            using var after = Open(
                path,
                FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete,
                createNew: false);
            if (Identity(after.SafeFileHandle) != actualIdentity)
            {
                throw new InvalidDataException(
                    "Production mailbox lock identity changed after validation.");
            }

            return AcquireNativeLock(actual);
        }
        catch
        {
            actual.Dispose();
            throw;
        }
    }

    private static IDisposable AcquireNativeLock(FileStream stream)
    {
        if (OperatingSystem.IsWindows())
        {
            var overlapped = new WindowsOverlapped();
            if (!LockFileEx(
                    stream.SafeFileHandle,
                    LockfileExclusiveLock | LockfileFailImmediately,
                    0,
                    uint.MaxValue,
                    uint.MaxValue,
                    ref overlapped))
            {
                var error = Marshal.GetLastPInvokeError();
                stream.Dispose();
                throw new IOException("Production mailbox lock is already held.",
                    new Win32Exception(error));
            }

            return new NativeLockLease(stream, overlapped);
        }

        if (!OperatingSystem.IsLinux())
        {
            stream.Dispose();
            throw new PlatformNotSupportedException(
                "Production mailbox protected file leases support Windows and Linux only.");
        }

        if (Flock(
                stream.SafeFileHandle.DangerousGetHandle().ToInt32(),
                LinuxLockExclusive | LinuxLockNonBlocking) != 0)
        {
            var error = Marshal.GetLastPInvokeError();
            stream.Dispose();
            throw new IOException("Production mailbox lock is already held.",
                new Win32Exception(error));
        }

        return new NativeLockLease(stream, null);
    }

    private static void SecureCreatedHandle(SafeFileHandle handle)
    {
        if (OperatingSystem.IsWindows())
        {
            SecureWindowsHandle(handle);
            return;
        }

        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "Production mailbox protected file leases support Windows and Linux only.");
        }

        var descriptor = handle.DangerousGetHandle().ToInt32();
        if (Fchmod(descriptor, UnixPrivateReadWrite) != 0)
        {
            throw new UnauthorizedAccessException(
                "Production mailbox lock permissions could not be restricted.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        var stat = LinuxIdentityFor(handle);
        if (stat.UserId != GetEffectiveUserId()
            || (stat.Mode & UnixPermissionMask) != UnixPrivateReadWrite)
        {
            throw new UnauthorizedAccessException(
                "Production mailbox lock handle owner or permissions are unsafe.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static void SecureWindowsHandle(SafeFileHandle handle)
    {
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new UnauthorizedAccessException("Service SID is unavailable.");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(current);
        security.AddAccessRule(new FileSystemAccessRule(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        if (!SetKernelObjectSecurity(
                handle,
                OwnerSecurityInformation
                    | DaclSecurityInformation
                    | ProtectedDaclSecurityInformation,
                descriptor))
        {
            throw new UnauthorizedAccessException(
                "Production mailbox lock handle ACL could not be restricted.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        var verified = ReadWindowsHandleSecurity(handle);
        var dacl = verified.DiscretionaryAcl;
        if ((verified.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0
            || verified.Owner is not SecurityIdentifier owner
            || !current.Equals(owner)
            || dacl is null
            || dacl.Count != 1
            || dacl[0] is not CommonAce ace
            || ace.IsInherited
            || ace.AceQualifier != AceQualifier.AccessAllowed
            || !current.Equals(ace.SecurityIdentifier)
            || ace.AccessMask != (int)FileSystemRights.FullControl)
        {
            throw new UnauthorizedAccessException(
                "Production mailbox lock handle ACL is not exact and protected.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static RawSecurityDescriptor ReadWindowsHandleSecurity(SafeFileHandle handle)
    {
        var requested = OwnerSecurityInformation | DaclSecurityInformation;
        _ = GetKernelObjectSecurity(handle, requested, null, 0, out var required);
        if (required == 0)
        {
            throw new UnauthorizedAccessException(
                "Production mailbox lock handle ACL size is unavailable.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        var descriptor = new byte[required];
        if (!GetKernelObjectSecurity(
                handle,
                requested,
                descriptor,
                checked((uint)descriptor.Length),
                out _))
        {
            throw new UnauthorizedAccessException(
                "Production mailbox lock handle ACL is unavailable.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return new RawSecurityDescriptor(descriptor, 0);
    }

    private static FileStream Open(
        string path,
        FileAccess access,
        FileShare share,
        bool createNew)
    {
        if (OperatingSystem.IsWindows())
        {
            var desired = GenericRead | (access == FileAccess.ReadWrite ? GenericWrite : 0)
                | (createNew ? WriteDac | WriteOwner : 0);
            var nativeShare = (share & FileShare.Read) != 0 ? ShareRead : 0;
            nativeShare |= (share & FileShare.Write) != 0 ? ShareWrite : 0;
            nativeShare |= (share & FileShare.Delete) != 0 ? ShareDelete : 0;
            var handle = CreateFile(
                path,
                desired,
                nativeShare,
                IntPtr.Zero,
                createNew ? CreateNew : OpenExisting,
                FileAttributeNormal | FileFlagOpenReparsePoint
                    | (createNew ? FileFlagWriteThrough : 0),
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                throw NativeOpenException(path, error, createNew);
            }

            var identity = WindowsIdentityFor(handle);
            if ((identity.Attributes & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0)
            {
                handle.Dispose();
                throw new InvalidDataException(
                    "Production mailbox protected path is not a regular file.");
            }

            return new FileStream(handle, access, 4096, isAsync: false);
        }

        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "Production mailbox protected file leases support Windows and Linux only.");
        }

        var flags = (access == FileAccess.ReadWrite ? LinuxOpenReadWrite : LinuxOpenReadOnly)
            | LinuxNoFollow
            | LinuxCloseOnExec
            | (createNew ? LinuxCreate | LinuxExclusive : 0);
        var how = new LinuxOpenHow
        {
            Flags = checked((ulong)flags),
            Mode = createNew ? Convert.ToUInt64("600", 8) : 0,
            Resolve = LinuxResolveNoSymlinks
        };
        var descriptorValue = LinuxSyscall(
            LinuxOpenAt2SystemCall,
            AtCurrentWorkingDirectory,
            path,
            ref how,
            checked((nuint)Marshal.SizeOf<LinuxOpenHow>()));
        var descriptor = checked((int)descriptorValue);
        if (descriptor < 0)
        {
            throw NativeOpenException(path, Marshal.GetLastPInvokeError(), createNew);
        }

        var safeHandle = new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        try
        {
            var identity = LinuxIdentityFor(safeHandle);
            if ((identity.Mode & UnixFileTypeMask) != UnixRegularFile)
            {
                throw new InvalidDataException(
                    "Production mailbox protected path is not a regular file.");
            }

            return new FileStream(safeHandle, access, 4096, isAsync: false);
        }
        catch
        {
            safeHandle.Dispose();
            throw;
        }
    }

    private static Exception NativeOpenException(string path, int error, bool createNew)
    {
        if ((!OperatingSystem.IsWindows() && error == 2)
            || OperatingSystem.IsWindows() && error is 2 or 3)
        {
            return new FileNotFoundException(
                "Production mailbox protected file is missing.", path);
        }

        if (createNew && ((!OperatingSystem.IsWindows() && error == 17)
                          || OperatingSystem.IsWindows() && error is 80 or 183))
        {
            return new IOException("Production mailbox protected file already exists.");
        }

        if (!OperatingSystem.IsWindows() && error == 40)
        {
            return new InvalidDataException(
                "Production mailbox protected path is a symbolic link.");
        }

        return new IOException("Production mailbox protected file could not be opened.",
            new Win32Exception(error));
    }

    private static FileIdentity Identity(SafeFileHandle handle)
    {
        if (OperatingSystem.IsWindows())
        {
            var value = WindowsIdentityFor(handle);
            return new(value.VolumeSerialNumber,
                ((ulong)value.FileIndexHigh << 32) | value.FileIndexLow,
                0,
                0);
        }

        var stat = LinuxIdentityFor(handle);
        return new(((ulong)stat.DeviceMajor << 32) | stat.DeviceMinor,
            stat.Inode,
            stat.UserId,
            stat.Mode);
    }

    [SupportedOSPlatform("windows")]
    private static WindowsFileInformation WindowsIdentityFor(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException("Production mailbox file identity is unavailable.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return information;
    }

    [UnsupportedOSPlatform("windows")]
    private static LinuxStatx LinuxIdentityFor(SafeFileHandle handle)
    {
        if (Statx(
                handle.DangerousGetHandle().ToInt32(),
                "",
                AtEmptyPath | AtSymlinkNoFollow,
                StatxBasicStats,
                out var stat) != 0)
        {
            throw new IOException("Production mailbox file identity is unavailable.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return stat;
    }

    private readonly record struct FileIdentity(
        ulong Device,
        ulong File,
        uint UserId,
        ushort Mode);

    private sealed class NativeLockLease(
        FileStream stream,
        WindowsOverlapped? overlapped) : IDisposable
    {
        public void Dispose()
        {
            if (OperatingSystem.IsWindows() && overlapped is { } windows)
            {
                _ = UnlockFileEx(
                    stream.SafeFileHandle,
                    0,
                    uint.MaxValue,
                    uint.MaxValue,
                    ref windows);
            }
            else if (OperatingSystem.IsLinux())
            {
                _ = Flock(stream.SafeFileHandle.DangerousGetHandle().ToInt32(), LinuxUnlock);
            }

            stream.Dispose();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsOverlapped
    {
        internal IntPtr Internal;
        internal IntPtr InternalHigh;
        internal uint Offset;
        internal uint OffsetHigh;
        internal IntPtr EventHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsFileInformation
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential, Size = 256)]
    private struct LinuxStatx
    {
        internal uint Mask;
        internal uint BlockSize;
        internal ulong Attributes;
        internal uint HardLinks;
        internal uint UserId;
        internal uint GroupId;
        internal ushort Mode;
        internal ushort Reserved;
        internal ulong Inode;
        internal ulong Size;
        internal ulong Blocks;
        internal ulong AttributesMask;
        internal LinuxStatxTimestamp AccessTime;
        internal LinuxStatxTimestamp BirthTime;
        internal LinuxStatxTimestamp ChangeTime;
        internal LinuxStatxTimestamp ModificationTime;
        internal uint RDeviceMajor;
        internal uint RDeviceMinor;
        internal uint DeviceMajor;
        internal uint DeviceMinor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStatxTimestamp
    {
        internal long Seconds;
        internal uint Nanoseconds;
        internal int Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxOpenHow
    {
        internal ulong Flags;
        internal ulong Mode;
        internal ulong Resolve;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true,
        CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out WindowsFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LockFileEx(
        SafeFileHandle handle,
        uint flags,
        uint reserved,
        uint bytesLow,
        uint bytesHigh,
        ref WindowsOverlapped overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnlockFileEx(
        SafeFileHandle handle,
        uint reserved,
        uint bytesLow,
        uint bytesHigh,
        ref WindowsOverlapped overlapped);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(
        SafeFileHandle handle,
        uint securityInformation,
        byte[] securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(
        SafeFileHandle handle,
        uint requestedInformation,
        byte[]? securityDescriptor,
        uint length,
        out uint requiredLength);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true,
        CharSet = CharSet.Ansi)]
    private static extern long LinuxSyscall(
        long number,
        int directoryDescriptor,
        string path,
        ref LinuxOpenHow how,
        nuint size);

    [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static extern int Flock(int descriptor, int operation);

    [DllImport("libc", EntryPoint = "fchmod", SetLastError = true)]
    private static extern int Fchmod(int descriptor, ushort mode);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true,
        CharSet = CharSet.Ansi)]
    private static extern int Statx(
        int directoryDescriptor,
        string path,
        int flags,
        uint mask,
        out LinuxStatx stat);

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();
}

public sealed class ProductionMailboxAuthorityProvider
    : IMailboxCapabilityAuthoritySource,
      IMailboxCapabilityRevocationPolicy,
      IProductionMailboxTopologyProvider
{
    private readonly ProductionMailboxAuthorityOptions _options;
    private readonly string _artifactTrustRoot;
    private readonly string _dataTrustRoot;
    private readonly IClock _clock;
    private readonly IProductionMailboxAuthorityFileSecurity _fileSecurity;
    private readonly IMailboxStorageSecurity _storageSecurity;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly SemaphoreSlim _initializeGate = new(1, 1);
    private ProductionMailboxAuthorityPair? _verified;
    private ProductionMailboxAuthorityStatus _status;

    public ProductionMailboxAuthorityProvider(
        ProductionMailboxAuthorityOptions options,
        RouterNodeOptions node,
        IClock clock,
        IProductionMailboxAuthorityFileSecurity fileSecurity,
        IMailboxStorageSecurity storageSecurity,
        IMailboxDurabilityBarrier durability)
    {
        _options = options;
        _artifactTrustRoot = options.Enabled
            ? options.GetArtifactTrustRoot()
            : string.Empty;
        _dataTrustRoot = Path.GetFullPath(node.DataDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        _clock = clock;
        _fileSecurity = fileSecurity;
        _storageSecurity = storageSecurity;
        _durability = durability;
        _status = new(
            options.Enabled,
            false,
            false,
            false,
            false,
            options.Enabled ? "not-initialized" : "disabled",
            0,
            0);
    }

    public ProductionMailboxAuthorityStatus Status
    {
        get
        {
            var status = Volatile.Read(ref _status);
            var bundle = Volatile.Read(ref _verified);
            return status.Ready && (bundle is null || !IsLive(bundle))
                ? status with
                {
                    Ready = false,
                    Reason = "production-bundle-expired",
                    ProductionMailboxRoutesReady = false
                }
                : status;
        }
    }

    public bool IsConfigured
    {
        get
        {
            var bundle = Volatile.Read(ref _verified);
            return bundle is not null && IsLive(bundle);
        }
    }

    public bool SupportsAdapter(MailboxClientAdapterOptions adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        var bundle = Volatile.Read(ref _verified);
        if (bundle is null || !IsLive(bundle))
        {
            return false;
        }

        var authority = bundle.Authority.Authority;
        return adapter.Enabled
            && adapter.CurrentEpoch == authority.CurrentEpoch.Epoch
            && adapter.NextEpoch == authority.NextEpoch.Epoch
            && TryDecodeCommitment(
                adapter.CurrentMembershipCommitment,
                authority.CurrentEpoch.MembershipCommitment.Span)
            && TryDecodeCommitment(
                adapter.NextMembershipCommitment,
                authority.NextEpoch.MembershipCommitment.Span);
    }

    public bool IsRevoked(MailboxCapabilityRevocationQuery query)
    {
        var pair = Volatile.Read(ref _verified);
        return pair is null || !IsLive(pair) || pair.Revocation.IsRevoked(query);
    }

    public bool TryResolve(
        ulong epoch,
        ReadOnlyMemory<byte> membershipCommitment,
        ReadOnlyMemory<byte> placementCommitment,
        ReadOnlyMemory<byte> blindedPlacementId,
        ReadOnlyMemory<byte> selectionInputCommitment,
        out ProductionMailboxEpochTopology? topology)
    {
        var bundle = Volatile.Read(ref _verified);
        if (bundle is null || !IsLive(bundle))
        {
            topology = null;
            return false;
        }

        try
        {
            var placementId = new BlindedPlacementId(blindedPlacementId.ToArray());
            var computedSelectionInput = ProductionMailboxReplicaSelection
                .ComputeSelectionInputCommitment(placementId);
            if (!Fixed(computedSelectionInput, selectionInputCommitment.Span))
            {
                topology = null;
                return false;
            }
            var selection = VerifySelection(
                bundle.Authority,
                bundle.Topology,
                placementId,
                null);
            var proof = selection.Proof;
            if (proof.Epoch != epoch
                || !Fixed(proof.MembershipCommitment.Span, membershipCommitment.Span)
                || !Fixed(proof.MailboxPlacementCommitment.Span, placementCommitment.Span))
            {
                topology = null;
                return false;
            }

            topology = new(
                proof.Epoch,
                proof.MembershipCommitment.ToArray(),
                proof.MailboxPlacementCommitment.ToArray(),
                proof.SelectionInputCommitment.ToArray(),
                selection.Replicas.Select(static replica =>
                    new ProductionMailboxTopologyReplica(
                        replica.ReplicaId.ToArray(),
                        replica.CanonicalMIP1Proof.ToArray(),
                        new Uri(replica.HttpsEndpoint.AbsoluteUri, UriKind.Absolute),
                        replica.CurrentSpkiSha256.ToArray(),
                        replica.NextSpkiSha256.ToArray())).ToArray());
            return true;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or InvalidDataException
                or ProductionMailboxTopologyException)
        {
            topology = null;
            return false;
        }
    }

    public ProductionMailboxNodeIngress? NodeIngress
    {
        get
        {
            var bundle = Volatile.Read(ref _verified);
            var authority = bundle is not null && IsLive(bundle)
                ? bundle.Authority.Authority
                : null;
            return authority is null
                ? null
                : new(
                    new Uri(authority.NodeIngress.Uri, UriKind.Absolute),
                    authority.NodeIngress.CurrentSpkiSha256.ToArray(),
                    authority.NodeIngress.NextSpkiSha256.ToArray());
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return;
        }

        await _initializeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            InitializeCore();
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or InvalidDataException
                or InvalidOperationException
                or ProductionMailboxAuthorityException
                or ProductionMailboxRevocationSnapshotException
                or ProductionMailboxTopologyException
                or CryptographicException)
        {
            var previous = Volatile.Read(ref _verified);
            Volatile.Write(ref _status, new(
                true,
                previous is not null,
                previous is not null,
                previous is not null,
                false,
                FailureReason(exception),
                previous?.Authority.Authority.AuthorityGeneration ?? 0,
                previous?.Revocation.Snapshot.RevocationGeneration ?? 0)
            {
                AuthorityRevocationReady = previous is not null,
                ProductionMailboxRoutesReady = false,
                TopologyArtifactVerified = previous is not null,
                TopologyGeneration = previous?.Topology.CommittedTopologyGeneration ?? 0
            });
        }
        finally
        {
            _initializeGate.Release();
        }
    }

    public bool TryResolve(
        MailboxCapabilityAuthorityQuery query,
        out MailboxAuthenticatedVerificationPolicy? policy)
    {
        var bundle = Volatile.Read(ref _verified);
        var authority = bundle is not null && IsLive(bundle)
            ? bundle.Authority.Authority
            : null;
        if (authority is null)
        {
            policy = null;
            return false;
        }

        var epoch = query.Epoch == authority.CurrentEpoch.Epoch
            ? authority.CurrentEpoch
            : query.Epoch == authority.NextEpoch.Epoch
                ? authority.NextEpoch
                : null;
        var domainMatches = query.Operation == MailboxAuthenticatedOperation.Store
            ? query.Domain == MailboxCapabilityDomain.Deposit
            : query.Domain == MailboxCapabilityDomain.Retrieve;
        if (epoch is null
            || !domainMatches
            || query.Lifecycle != MailboxCapabilityLifecycle.Active
            || query.Generation != epoch.Generation
            || !Fixed(query.NetworkId.Span, authority.NetworkId.Span)
            || !Fixed(query.IssuerPublicKey.Span, authority.MailboxIssuerEd25519PublicKey.Span)
            || query.PlacementCommitment.Length != 32
            || query.PlacementCommitment.Span.IndexOfAnyExcept((byte)0) < 0
            || !Fixed(query.MembershipCommitment.Span, epoch.MembershipCommitment.Span))
        {
            policy = null;
            return false;
        }

        policy = new()
        {
            NetworkId = authority.NetworkId.ToArray(),
            Epoch = epoch.Epoch,
            PlacementCommitment = query.PlacementCommitment.ToArray(),
            MembershipCommitment = epoch.MembershipCommitment.ToArray(),
            NowUnixSeconds = 0,
            MinimumGeneration = epoch.Generation,
            TrustedIssuers =
            [
                new MailboxCapabilityIssuerAuthority
                {
                    PublicKey = authority.MailboxIssuerEd25519PublicKey.ToArray(),
                    Domain = query.Domain,
                    AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                    MinimumGeneration = epoch.Generation,
                    MaximumGeneration = epoch.Generation,
                    ValidFromUnixSeconds = epoch.NotBeforeUnixSeconds,
                    ValidUntilUnixSeconds = epoch.NotAfterUnixSeconds
                }
            ]
        };
        return true;
    }

    public ulong ReplayValidityEndsAt(
        MailboxCapabilityAuthorityQuery query,
        MailboxAuthenticatedGrant grant)
    {
        var bundle = Volatile.Read(ref _verified);
        var authority = bundle is not null && IsLive(bundle)
            ? bundle.Authority.Authority
            : null;
        if (authority is null)
        {
            return grant.ExpiresAtUnixSeconds;
        }

        return query.Epoch == authority.CurrentEpoch.Epoch
            ? Math.Max(grant.ExpiresAtUnixSeconds, authority.CurrentEpoch.NotAfterUnixSeconds)
            : query.Epoch == authority.NextEpoch.Epoch
                ? Math.Max(grant.ExpiresAtUnixSeconds, authority.NextEpoch.NotAfterUnixSeconds)
                : grant.ExpiresAtUnixSeconds;
    }

    private void InitializeCore()
    {
        _fileSecurity.ValidateReadOnlyArtifact(_options.ArtifactPath, _artifactTrustRoot);
        _fileSecurity.ValidateReadOnlyArtifact(
            _options.RevocationArtifactPath,
            _artifactTrustRoot);
        _fileSecurity.ValidateReadOnlyArtifact(
            _options.TopologyArtifactPath,
            _artifactTrustRoot);
        _fileSecurity.ValidateProtectedLastKnownGood(_options.LastKnownGoodPath, _dataTrustRoot);
        using var processLock = AcquireProcessLock();
        _fileSecurity.ValidateProtectedLastKnownGood(_options.LastKnownGoodPath, _dataTrustRoot);
        var lkg = ProductionMailboxAuthorityLkgCodec.Decode(ReadExactLkg());
        var artifactBytes = ReadBoundedArtifact(
            _options.ArtifactPath,
            _options.MaximumArtifactBytes,
            "authority");
        var authority = ProductionMailboxAuthorityCodec.Decode(artifactBytes);
        var artifactHash = SHA256.HashData(artifactBytes);
        var authorityIdempotent = authority.AuthorityGeneration == lkg.Committed.Generation
            && Fixed(artifactHash, lkg.Committed.AuthorityHash);
        var anchor = authorityIdempotent
            ? lkg.AuthorityVerificationAnchor
                ?? throw new InvalidDataException(
                    "Production mailbox authority LKG lacks its verification anchor.")
            : lkg.Committed;
        var now = checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());
        var verified = ProductionMailboxAuthorityVerifier.Verify(
            authority,
            Context(anchor, now),
            new SodiumProductionMailboxAuthoritySignatureVerifier());
        ValidateCommit(
            verified,
            authority.Revocation,
            authorityIdempotent ? lkg.Committed : null);

        var revocationBytes = ReadBoundedArtifact(
            _options.RevocationArtifactPath,
            _options.MaximumRevocationArtifactBytes,
            "revocation");
        var revocation = ProductionMailboxRevocationSnapshotVerifier.Verify(
            revocationBytes,
            verified,
            now,
            _options.ClockSkewSeconds,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
        ValidateRevocationCommit(
            revocation,
            authorityIdempotent ? lkg.Committed : null);

        var topologyBytes = ReadBoundedArtifact(
            _options.TopologyArtifactPath,
            _options.MaximumTopologyArtifactBytes,
            "topology");
        var decodedTopology = ProductionMailboxTopologyCodec.Decode(topologyBytes);
        var topologyHash = SHA256.HashData(topologyBytes);
        var topologyIdempotent =
            decodedTopology.TopologyGeneration == lkg.Committed.TopologyGeneration
            && Fixed(topologyHash, lkg.Committed.TopologyHash);
        var topologyAnchor = topologyIdempotent
            ? lkg.TopologyVerificationAnchor
                ?? throw new InvalidDataException(
                    "Production mailbox authority LKG lacks its topology verification anchor.")
            : new ProductionMailboxTopologyLkgCommit(
                lkg.Committed.TopologyGeneration,
                lkg.Committed.TopologyHash);
        var verifiedTopology = ProductionMailboxTopologyVerifier.Verify(
            topologyBytes,
            verified,
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = topologyAnchor.Generation,
                LastCommittedTopologyHash = topologyAnchor.Hash,
                NowUnixSeconds = now,
                ClockSkewSeconds = _options.ClockSkewSeconds
            },
            new SodiumProductionMailboxTopologySignatureVerifier());
        if (topologyIdempotent
            && (verifiedTopology.CommittedTopologyGeneration
                    != lkg.Committed.TopologyGeneration
                || !Fixed(
                    verifiedTopology.CanonicalTopologyHash.Span,
                    lkg.Committed.TopologyHash)))
        {
            throw new InvalidDataException(
                "Production mailbox topology artifact conflicts with durable LKG.");
        }

        var readinessSelection = VerifySelection(
            verified,
            verifiedTopology,
            new BlindedPlacementId(_options.GetReadinessBlindedPlacementId()),
            now);

        if (!authorityIdempotent || !topologyIdempotent)
        {
            var next = new ProductionMailboxAuthorityLkg(
                new(
                    verified.NextCommittedGeneration,
                    verified.CanonicalAuthorityHash.ToArray(),
                    authority.Revocation.Generation,
                    authority.Revocation.HeadHash.ToArray(),
                    authority.Revocation.SnapshotHash.ToArray(),
                    verifiedTopology.CommittedTopologyGeneration,
                    verifiedTopology.CanonicalTopologyHash.ToArray()),
                authorityIdempotent
                    ? lkg.AuthorityVerificationAnchor
                    : lkg.Committed,
                topologyIdempotent
                    ? lkg.TopologyVerificationAnchor
                    : new ProductionMailboxTopologyLkgCommit(
                        lkg.Committed.TopologyGeneration,
                        lkg.Committed.TopologyHash));
            SaveLkg(next);
        }

        Volatile.Write(ref _verified, new(
            verified,
            revocation,
            verifiedTopology,
            readinessSelection));
        Volatile.Write(ref _status, new(
            true,
            true,
            true,
            true,
            true,
            "",
            authority.AuthorityGeneration,
            authority.Revocation.Generation)
        {
            AuthorityRevocationReady = true,
            ProductionMailboxRoutesReady = true,
            TopologyArtifactVerified = true,
            TopologyGeneration = verifiedTopology.CommittedTopologyGeneration
        });
    }

    private VerifiedProductionMailboxSelection VerifySelection(
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxTopology topology,
        BlindedPlacementId blindedPlacementId,
        ulong? observedNow)
    {
        var selectionInputCommitment = ProductionMailboxReplicaSelection
            .ComputeSelectionInputCommitment(blindedPlacementId);
        var path = Path.Combine(
            _options.SelectionArtifactDirectory,
            Convert.ToHexString(selectionInputCommitment).ToLowerInvariant() + ".pms1");
        var bytes = ReadBoundedArtifact(
            path,
            _options.MaximumSelectionArtifactBytes,
            "selection");
        return ProductionMailboxSelectionVerifier.Verify(
            bytes,
            authority,
            topology,
            blindedPlacementId,
            observedNow ?? checked((ulong)_clock.UtcNow.ToUnixTimeSeconds()),
            _options.ClockSkewSeconds,
            new SodiumProductionMailboxTopologySignatureVerifier());
    }

    private ProductionMailboxAuthorityVerificationContext Context(
        ProductionMailboxAuthorityLkgCommit anchor,
        ulong nowUnixSeconds) => new()
        {
            PinnedMrXPublicKeySha256 = _options.GetPinnedMrXKeyHash(),
            ExpectedNetworkId = _options.GetExpectedNetworkId(),
            LastCommittedGeneration = anchor.Generation,
            LastCommittedAuthorityHash = anchor.AuthorityHash,
            LastCommittedRevocationGeneration = anchor.RevocationGeneration,
            LastCommittedRevocationHeadHash = anchor.RevocationHeadHash,
            LastCommittedRevocationSnapshotHash = anchor.RevocationSnapshotHash,
            NowUnixSeconds = nowUnixSeconds,
            ClockSkewSeconds = _options.ClockSkewSeconds
        };

    private byte[] ReadBoundedArtifact(string path, int maximumBytes, string name)
    {
        using var stream = ProductionMailboxAuthorityNativeFile.OpenStableRead(
            path,
            () => _fileSecurity.ValidateReadOnlyArtifact(
                path,
                _artifactTrustRoot));
        if (stream.Length <= 0 || stream.Length > maximumBytes)
        {
            throw new InvalidDataException(
                $"Production mailbox {name} artifact size is outside bounds.");
        }

        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private byte[] ReadExactLkg()
    {
        using var stream = ProductionMailboxAuthorityNativeFile.OpenStableRead(
            _options.LastKnownGoodPath,
            () => _fileSecurity.ValidateProtectedLastKnownGood(
                _options.LastKnownGoodPath,
                _dataTrustRoot));
        if (stream.Length != ProductionMailboxAuthorityLkgCodec.EncodedLength)
        {
            throw new InvalidDataException(
                "Production mailbox authority LKG length is invalid.");
        }

        var bytes = new byte[ProductionMailboxAuthorityLkgCodec.EncodedLength];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private IDisposable AcquireProcessLock()
    {
        var path = _options.LastKnownGoodPath + ".lock";
        return ProductionMailboxAuthorityNativeFile.AcquireLock(
            path,
            () => _fileSecurity.ValidateProtectedLock(path, _dataTrustRoot),
            _durability);
    }

    private void SaveLkg(ProductionMailboxAuthorityLkg lkg)
    {
        var bytes = ProductionMailboxAuthorityLkgCodec.Encode(lkg);
        var temporary = $"{_options.LastKnownGoodPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            _storageSecurity.SecureFile(temporary);
            _durability.ReplaceFile(temporary, _options.LastKnownGoodPath);
            _storageSecurity.SecureFile(_options.LastKnownGoodPath);
            _durability.FlushFileAndParentDirectory(_options.LastKnownGoodPath);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static void ValidateCommit(
        VerifiedProductionMailboxAuthority verified,
        ProductionMailboxAuthorityRevocation revocation,
        ProductionMailboxAuthorityLkgCommit? expected)
    {
        if (expected is not null
            && (verified.NextCommittedGeneration != expected.Generation
                || !Fixed(verified.CanonicalAuthorityHash.Span, expected.AuthorityHash)
                || revocation.Generation != expected.RevocationGeneration
                || !Fixed(revocation.HeadHash.Span, expected.RevocationHeadHash)
                || !Fixed(revocation.SnapshotHash.Span, expected.RevocationSnapshotHash)))
        {
            throw new InvalidDataException(
                "Production mailbox authority artifact conflicts with durable LKG.");
        }
    }

    private static void ValidateRevocationCommit(
        VerifiedProductionMailboxRevocationSnapshot revocation,
        ProductionMailboxAuthorityLkgCommit? expected)
    {
        var snapshot = revocation.Snapshot;
        if (expected is not null
            && (snapshot.RevocationGeneration != expected.RevocationGeneration
                || !Fixed(snapshot.RevocationHeadHash.Span, expected.RevocationHeadHash)
                || !Fixed(revocation.CanonicalSnapshotHash.Span, expected.RevocationSnapshotHash)))
        {
            throw new InvalidDataException(
                "Production mailbox revocation artifact conflicts with durable LKG.");
        }
    }

    private static string FailureReason(Exception exception) => exception switch
    {
        UnauthorizedAccessException => "protected-storage-rejected",
        ProductionMailboxAuthorityException authority => authority.Error switch
        {
            ProductionMailboxAuthorityError.AuthorityRollback => "authority-rollback-rejected",
            ProductionMailboxAuthorityError.PreviousHashMismatch => "authority-chain-rejected",
            ProductionMailboxAuthorityError.UntrustedMrXKey => "mr-x-pin-rejected",
            ProductionMailboxAuthorityError.NotYetValid => "authority-not-yet-valid",
            ProductionMailboxAuthorityError.Expired => "authority-expired",
            _ => "authority-verification-rejected"
        },
        ProductionMailboxRevocationSnapshotException revocation => revocation.Error switch
        {
            ProductionMailboxRevocationSnapshotError.NotYetValid => "revocation-not-yet-valid",
            ProductionMailboxRevocationSnapshotError.Expired => "revocation-expired",
            ProductionMailboxRevocationSnapshotError.InvalidSignature => "revocation-signature-rejected",
            ProductionMailboxRevocationSnapshotError.SnapshotHashMismatch => "revocation-hash-rejected",
            _ => "revocation-verification-rejected"
        },
        ProductionMailboxTopologyException topology => topology.Error switch
        {
            ProductionMailboxTopologyError.TopologyRollback => "topology-rollback-rejected",
            ProductionMailboxTopologyError.PreviousHashMismatch => "topology-chain-rejected",
            ProductionMailboxTopologyError.NotYetValid => "topology-not-yet-valid",
            ProductionMailboxTopologyError.Expired => "topology-expired",
            ProductionMailboxTopologyError.InvalidSignature => "topology-signature-rejected",
            ProductionMailboxTopologyError.InvalidMembershipProof => "topology-proof-rejected",
            ProductionMailboxTopologyError.SelectionMismatch => "topology-selection-rejected",
            _ => "topology-verification-rejected"
        },
        InvalidDataException => "authority-state-rejected",
        _ => "authority-initialization-failed"
    };

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool TryDecodeCommitment(string encoded, ReadOnlySpan<byte> expected)
    {
        try
        {
            return Fixed(Convert.FromHexString(encoded), expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private bool IsLive(ProductionMailboxAuthorityPair bundle)
    {
        var now = checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());
        var authority = bundle.Authority.Authority;
        var topology = bundle.Topology.Snapshot;
        var selection = bundle.ReadinessSelection.Proof;
        return Within(
                authority.CurrentEpoch.NotBeforeUnixSeconds,
                authority.CurrentEpoch.NotAfterUnixSeconds,
                now)
            && Within(
                authority.MrXApproval.RolloutNotBeforeUnixSeconds,
                authority.MrXApproval.RolloutNotAfterUnixSeconds,
                now)
            && Within(
                authority.Revocation.IssuedAtUnixSeconds,
                authority.Revocation.ExpiresAtUnixSeconds,
                now)
            && Within(topology.IssuedAtUnixSeconds, topology.ExpiresAtUnixSeconds, now)
            && Within(selection.IssuedAtUnixSeconds, selection.ExpiresAtUnixSeconds, now);
    }

    private bool Within(ulong from, ulong until, ulong now) =>
        (now >= from || from - now <= _options.ClockSkewSeconds)
        && (now <= until || now - until <= _options.ClockSkewSeconds);
}

internal sealed record ProductionMailboxAuthorityPair(
    VerifiedProductionMailboxAuthority Authority,
    VerifiedProductionMailboxRevocationSnapshot Revocation,
    VerifiedProductionMailboxTopology Topology,
    VerifiedProductionMailboxSelection ReadinessSelection);

public sealed class ProductionMailboxAuthorityHostedService(
    ProductionMailboxAuthorityProvider provider) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) =>
        provider.InitializeAsync(cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal sealed record ProductionMailboxAuthorityLkg(
    ProductionMailboxAuthorityLkgCommit Committed,
    ProductionMailboxAuthorityLkgCommit? AuthorityVerificationAnchor,
    ProductionMailboxTopologyLkgCommit? TopologyVerificationAnchor);

internal sealed record ProductionMailboxAuthorityLkgCommit(
    ulong Generation,
    byte[] AuthorityHash,
    ulong RevocationGeneration,
    byte[] RevocationHeadHash,
    byte[] RevocationSnapshotHash,
    ulong TopologyGeneration,
    byte[] TopologyHash);

internal sealed record ProductionMailboxTopologyLkgCommit(
    ulong Generation,
    byte[] Hash);

internal static class ProductionMailboxAuthorityLkgCodec
{
    private const int CommitLength = 8 + 32 + 8 + 32 + 32 + 8 + 32;
    private const int TopologyCommitLength = 8 + 32;
    private const int CommittedOffset = 8;
    private const int AuthorityFlagOffset = CommittedOffset + CommitLength;
    private const int AuthorityAnchorOffset = AuthorityFlagOffset + 1;
    private const int TopologyFlagOffset = AuthorityAnchorOffset + CommitLength;
    private const int TopologyAnchorOffset = TopologyFlagOffset + 1;
    private const int PayloadLength = TopologyAnchorOffset + TopologyCommitLength;
    private const int Length = PayloadLength + 32;
    internal const int EncodedLength = Length;

    public static byte[] Encode(ProductionMailboxAuthorityLkg value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ValidateCommit(value.Committed);
        if (value.AuthorityVerificationAnchor is not null)
        {
            ValidateCommit(value.AuthorityVerificationAnchor);
        }
        if (value.TopologyVerificationAnchor is not null)
        {
            ValidateTopologyCommit(value.TopologyVerificationAnchor);
        }

        var bytes = new byte[Length];
        "PML3"u8.CopyTo(bytes);
        bytes[4] = 1;
        WriteCommit(bytes.AsSpan(CommittedOffset, CommitLength), value.Committed);
        bytes[AuthorityFlagOffset] = value.AuthorityVerificationAnchor is null ? (byte)0 : (byte)1;
        if (value.AuthorityVerificationAnchor is not null)
        {
            WriteCommit(
                bytes.AsSpan(AuthorityAnchorOffset, CommitLength),
                value.AuthorityVerificationAnchor);
        }
        bytes[TopologyFlagOffset] = value.TopologyVerificationAnchor is null ? (byte)0 : (byte)1;
        if (value.TopologyVerificationAnchor is not null)
        {
            WriteTopologyCommit(
                bytes.AsSpan(TopologyAnchorOffset, TopologyCommitLength),
                value.TopologyVerificationAnchor);
        }

        SHA256.HashData(bytes.AsSpan(0, PayloadLength))
            .CopyTo(bytes.AsSpan(PayloadLength, 32));

        return bytes;
    }

    public static ProductionMailboxAuthorityLkg Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length
            || !bytes[..4].SequenceEqual("PML3"u8)
            || bytes[4] != 1
            || bytes.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0
            || bytes[AuthorityFlagOffset] is not (0 or 1)
            || bytes[TopologyFlagOffset] is not (0 or 1)
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(bytes[..PayloadLength]),
                bytes.Slice(PayloadLength, 32)))
        {
            throw new InvalidDataException(
                "Production mailbox authority LKG framing is invalid.");
        }

        var committed = ReadCommit(bytes.Slice(CommittedOffset, CommitLength));
        var hasAuthorityAnchor = bytes[AuthorityFlagOffset] == 1;
        var authorityAnchorBytes = bytes.Slice(AuthorityAnchorOffset, CommitLength);
        var hasTopologyAnchor = bytes[TopologyFlagOffset] == 1;
        var topologyAnchorBytes = bytes.Slice(TopologyAnchorOffset, TopologyCommitLength);
        if (!hasAuthorityAnchor && authorityAnchorBytes.IndexOfAnyExcept((byte)0) >= 0
            || !hasTopologyAnchor && topologyAnchorBytes.IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new InvalidDataException(
                "Production mailbox authority LKG reserved bytes are not zero.");
        }

        var authorityAnchor = hasAuthorityAnchor ? ReadCommit(authorityAnchorBytes) : null;
        var topologyAnchor = hasTopologyAnchor
            ? ReadTopologyCommit(topologyAnchorBytes)
            : null;
        return new(committed, authorityAnchor, topologyAnchor);
    }

    private static void WriteCommit(Span<byte> destination, ProductionMailboxAuthorityLkgCommit value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination[..8], value.Generation);
        value.AuthorityHash.CopyTo(destination.Slice(8, 32));
        BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(40, 8), value.RevocationGeneration);
        value.RevocationHeadHash.CopyTo(destination.Slice(48, 32));
        value.RevocationSnapshotHash.CopyTo(destination.Slice(80, 32));
        BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(112, 8), value.TopologyGeneration);
        value.TopologyHash.CopyTo(destination.Slice(120, 32));
    }

    private static ProductionMailboxAuthorityLkgCommit ReadCommit(ReadOnlySpan<byte> source)
    {
        var value = new ProductionMailboxAuthorityLkgCommit(
            BinaryPrimitives.ReadUInt64BigEndian(source[..8]),
            source.Slice(8, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(source.Slice(40, 8)),
            source.Slice(48, 32).ToArray(),
            source.Slice(80, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(source.Slice(112, 8)),
            source.Slice(120, 32).ToArray());
        ValidateCommit(value);
        return value;
    }

    private static void ValidateCommit(ProductionMailboxAuthorityLkgCommit value)
    {
        if (value.Generation == 0
            || value.AuthorityHash.Length != 32
            || value.AuthorityHash.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.RevocationGeneration == 0
            || value.RevocationHeadHash.Length != 32
            || value.RevocationHeadHash.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.RevocationSnapshotHash.Length != 32
            || value.RevocationSnapshotHash.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidDataException(
                "Production mailbox authority LKG commit is invalid.");
        }
        ValidateTopologyCommit(new(value.TopologyGeneration, value.TopologyHash));
    }

    private static void WriteTopologyCommit(
        Span<byte> destination,
        ProductionMailboxTopologyLkgCommit value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination[..8], value.Generation);
        value.Hash.CopyTo(destination.Slice(8, 32));
    }

    private static ProductionMailboxTopologyLkgCommit ReadTopologyCommit(
        ReadOnlySpan<byte> source)
    {
        var value = new ProductionMailboxTopologyLkgCommit(
            BinaryPrimitives.ReadUInt64BigEndian(source[..8]),
            source.Slice(8, 32).ToArray());
        ValidateTopologyCommit(value);
        return value;
    }

    private static void ValidateTopologyCommit(ProductionMailboxTopologyLkgCommit value)
    {
        var zeroHash = value.Hash.Length == 32
            && value.Hash.AsSpan().IndexOfAnyExcept((byte)0) < 0;
        if (value.Hash.Length != 32 || (value.Generation == 0) != zeroHash)
        {
            throw new InvalidDataException(
                "Production mailbox topology LKG commit is invalid.");
        }
    }
}
