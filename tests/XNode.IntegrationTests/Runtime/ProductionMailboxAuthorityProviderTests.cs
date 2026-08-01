using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed class ProductionMailboxAuthorityProviderTests : IDisposable
{
    private const ulong Now = 2_000_000_000;
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"xnode-production-authority-{Guid.NewGuid():N}");

    [Fact]
    public async Task ValidFirstNextAndIdempotentArtifactsAdvanceExactlyOnce()
    {
        var fixture = Fixture.Create(_root);
        var writes = new CountingBarrier();
        var provider = fixture.Provider(writes);

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.True(provider.Status.ArtifactVerified);
        Assert.True(provider.Status.RevocationArtifactVerified);
        Assert.True(provider.Status.AuthorityRevocationReady);
        Assert.False(provider.Status.ProductionMailboxRoutesReady);
        Assert.False(provider.Status.Ready);
        Assert.Equal("topology-artifact-unavailable", provider.Status.Reason);
        Assert.Equal(7UL, provider.Status.AuthorityGeneration);
        Assert.Equal("https://ingress.example.net/mau2/", provider.NodeIngress!.Endpoint.AbsoluteUri);
        Assert.False(CryptographicOperations.FixedTimeEquals(
            provider.NodeIngress.CurrentSpkiSha256.Span,
            provider.NodeIngress.NextSpkiSha256.Span));
        Assert.Equal(1, writes.ReplaceCount);

        var firstLkg = File.ReadAllBytes(fixture.LkgPath);
        await provider.InitializeAsync();
        Assert.Equal(1, writes.ReplaceCount);
        Assert.Equal(firstLkg, File.ReadAllBytes(fixture.LkgPath));

        var next = fixture.Successor();
        File.WriteAllBytes(fixture.ArtifactPath, ProductionMailboxAuthorityCodec.Encode(next));
        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured, provider.Status.Reason);
        Assert.Equal(8UL, provider.Status.AuthorityGeneration);
        Assert.Equal(7UL, provider.Status.RevocationGeneration);
        Assert.Equal(2, writes.ReplaceCount);
        var persisted = ProductionMailboxAuthorityLkgCodec.Decode(
            File.ReadAllBytes(fixture.LkgPath));
        Assert.Equal(8UL, persisted.Committed.Generation);
        Assert.Equal(7UL, persisted.VerificationAnchor!.Generation);
    }

    [Fact]
    public async Task ConcurrentInitializationSerializesOneAtomicAdvance()
    {
        var fixture = Fixture.Create(_root);
        var writes = new CountingBarrier(delay: TimeSpan.FromMilliseconds(20));
        var provider = fixture.Provider(writes);

        await Task.WhenAll(
            provider.InitializeAsync(),
            provider.InitializeAsync(),
            provider.InitializeAsync());

        Assert.True(provider.IsConfigured);
        Assert.Equal(1, writes.ReplaceCount);
    }

    [Fact]
    public async Task ConcurrentProvidersShareTheDurableProcessLock()
    {
        var fixture = Fixture.Create(_root);
        var writes = new CountingBarrier(delay: TimeSpan.FromMilliseconds(30));
        var first = fixture.Provider(writes);
        var second = fixture.Provider(writes);

        await Task.WhenAll(first.InitializeAsync(), second.InitializeAsync());

        Assert.True(first.IsConfigured, first.Status.Reason);
        Assert.True(second.IsConfigured, second.Status.Reason);
        Assert.Equal(1, writes.ReplaceCount);
    }

    [Fact]
    public async Task VerifiedSnapshotIsExactAndUnknownSerialIsNotRevoked()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.True(provider.IsRevoked(Query(fixture, Bytes(0x10, 16))));
        Assert.False(provider.IsRevoked(Query(fixture, Bytes(0x20, 16))));
        Assert.Throws<ProductionMailboxRevocationSnapshotException>(() =>
            provider.IsRevoked(Query(fixture, Bytes(0x20, 16)) with
            {
                IssuerPublicKey = Bytes(0x30, 32)
            }));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MissingOrCorruptRevocationFailsClosed(bool missing)
    {
        var fixture = Fixture.Create(_root);
        if (missing)
        {
            File.Delete(fixture.RevocationArtifactPath);
        }
        else
        {
            File.WriteAllBytes(fixture.RevocationArtifactPath, [0x01, 0x02]);
        }

        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.False(provider.Status.RevocationArtifactVerified);
        Assert.Equal(
            missing ? "authority-state-rejected" : "revocation-verification-rejected",
            provider.Status.Reason);
    }

    [Fact]
    public async Task InvalidSuccessorRevocationDoesNotAdvanceLkgOrReplacePublishedPair()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var committed = File.ReadAllBytes(fixture.LkgPath);

        var successor = fixture.Successor();
        var snapshot = ProductionMailboxRevocationSnapshotCodec.Decode(
            File.ReadAllBytes(fixture.RevocationArtifactPath));
        var invalid = snapshot with
        {
            IssuerSignature = Bytes(0xF0, 64)
        };
        var invalidBytes = ProductionMailboxRevocationSnapshotCodec.Encode(invalid);
        successor = fixture.Sign(successor with
        {
            Revocation = successor.Revocation with
            {
                SnapshotHash = SHA256.HashData(invalidBytes)
            }
        });
        fixture.WriteArtifact(successor);
        File.WriteAllBytes(fixture.RevocationArtifactPath, invalidBytes);

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.Equal("revocation-signature-rejected", provider.Status.Reason);
        Assert.Equal(7UL, provider.Status.AuthorityGeneration);
        Assert.Equal(committed, File.ReadAllBytes(fixture.LkgPath));
        Assert.True(provider.IsRevoked(Query(fixture, Bytes(0x10, 16))));
    }

    [Fact]
    public async Task SuccessorWithPreviousSnapshotFailsWithoutAdvancingPair()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var committed = File.ReadAllBytes(fixture.LkgPath);
        var previousSnapshot = File.ReadAllBytes(fixture.RevocationArtifactPath);
        var successor = fixture.Successor();
        fixture.WriteArtifact(successor);
        File.WriteAllBytes(fixture.RevocationArtifactPath, previousSnapshot);

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.Equal("revocation-verification-rejected", provider.Status.Reason);
        Assert.Equal(7UL, provider.Status.AuthorityGeneration);
        Assert.Equal(committed, File.ReadAllBytes(fixture.LkgPath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RollbackAndForkFailClosedWithoutChangingLkg(bool fork)
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var committed = File.ReadAllBytes(fixture.LkgPath);
        var rejected = fork
            ? fixture.Successor(previousAuthorityHash: Bytes(0x91, 32))
            : fixture.Sign(fixture.Authority with
            {
                AuthorityGeneration = 6,
                PreviousAuthorityHash = Bytes(0x41, 32)
            });
        File.WriteAllBytes(
            fixture.ArtifactPath,
            ProductionMailboxAuthorityCodec.Encode(rejected));

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.Equal(
            fork ? "authority-chain-rejected" : "authority-rollback-rejected",
            provider.Status.Reason);
        Assert.Equal(committed, File.ReadAllBytes(fixture.LkgPath));
    }

    [Fact]
    public async Task BadMrXPinFailsClosed()
    {
        var fixture = Fixture.Create(_root);
        fixture.Options.PinnedMrXPublicKeySha256 = Hex(Bytes(0xE1, 32));
        var provider = fixture.Provider();

        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.Equal("mr-x-pin-rejected", provider.Status.Reason);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExpiredOrFutureRevocationFailsClosed(bool expired)
    {
        var fixture = Fixture.Create(_root);
        var revocation = fixture.Authority.Revocation with
        {
            IssuedAtUnixSeconds = expired ? Now - 500 : Now + 301,
            ExpiresAtUnixSeconds = expired ? Now - 301 : Now + 600
        };
        fixture.WriteArtifact(fixture.Sign(fixture.Authority with { Revocation = revocation }));
        var provider = fixture.Provider();

        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.Equal(
            expired ? "authority-expired" : "authority-not-yet-valid",
            provider.Status.Reason);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task MissingOrCorruptInputsFailClosed(bool missingArtifact, bool missingLkg)
    {
        var fixture = Fixture.Create(_root);
        if (missingArtifact)
        {
            File.Delete(fixture.ArtifactPath);
        }
        else if (missingLkg)
        {
            File.Delete(fixture.LkgPath);
        }
        else
        {
            File.WriteAllBytes(fixture.LkgPath, [0x01, 0x02, 0x03]);
        }

        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.Equal("authority-state-rejected", provider.Status.Reason);
    }

    [Fact]
    public async Task FailedAtomicReplaceKeepsOldLkgAndPublishesNoAuthority()
    {
        var fixture = Fixture.Create(_root);
        var original = File.ReadAllBytes(fixture.LkgPath);
        var provider = fixture.Provider(new ThrowingBarrier());

        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.Equal(original, File.ReadAllBytes(fixture.LkgPath));
        Assert.Empty(Directory.GetFiles(_root, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ResolverPinsIssuerNetworkEpochGenerationAndCommitments()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var epoch = fixture.Authority.CurrentEpoch;
        var query = new MailboxCapabilityAuthorityQuery(
            MailboxAuthenticatedOperation.Store,
            MailboxCapabilityDomain.Deposit,
            epoch.Epoch,
            epoch.Generation,
            MailboxCapabilityLifecycle.Active,
            fixture.Authority.NetworkId,
            epoch.PlacementCommitment,
            epoch.MembershipCommitment,
            fixture.Authority.MailboxIssuerEd25519PublicKey);

        Assert.True(provider.TryResolve(query, out var policy));
        Assert.NotNull(policy);
        Assert.Equal(epoch.Generation, policy.MinimumGeneration);
        Assert.False(provider.TryResolve(
            query with { Generation = epoch.Generation + 1 },
            out _));
        Assert.False(provider.TryResolve(
            query with { NetworkId = Bytes(0xF1, 16) },
            out _));
    }

    [Fact]
    public void OptionsEnforceProductionOnlyExactPublicConfigurationAndLkgRoot()
    {
        var fixture = Fixture.Create(_root);
        fixture.Options.Validate(fixture.Node, isProduction: true);
        Assert.Throws<InvalidOperationException>(() =>
            fixture.Options.Validate(fixture.Node, isProduction: false));
        fixture.Options.LastKnownGoodPath = Path.Combine(_root, "outside.pml1");
        Assert.Throws<InvalidOperationException>(() =>
            fixture.Options.Validate(fixture.Node, isProduction: true));

        fixture.Options.LastKnownGoodPath = Path.Combine(
            fixture.Node.DataDirectory,
            "authority.pml1");
        fixture.Options.ArtifactTrustRoot = fixture.Node.DataDirectory;
        Assert.Throws<InvalidOperationException>(() =>
            fixture.Options.Validate(fixture.Node, isProduction: true));
    }

    [Fact]
    public void ProtocolRejectsHttpAndOfficialPrivateEndpointPolicyMismatch()
    {
        var fixture = Fixture.Create(_root);
        Assert.Equal(
            ProductionMailboxAuthorityError.InvalidEndpoint,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityCodec.Encode(fixture.Sign(
                    fixture.Authority with
                    {
                        NodeIngress = fixture.Authority.NodeIngress with
                        {
                            Uri = "http://ingress.example.net/mau2/"
                        }
                    }))).Error);
        Assert.Equal(
            ProductionMailboxAuthorityError.InvalidEndpoint,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityCodec.Encode(fixture.Sign(
                    fixture.Authority with
                    {
                        NodeIngress = fixture.Authority.NodeIngress with
                        {
                            Uri = "https://192.168.1.2/mau2/"
                        }
                    }))).Error);
    }

    [Fact]
    public void DefaultSecurityRejectsWritableArtifact()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "authority.pma1");
        File.WriteAllBytes(path, [0x01]);

        Assert.Throws<UnauthorizedAccessException>(() =>
            new ProductionMailboxAuthorityFileSecurity()
                .ValidateReadOnlyArtifact(path, _root));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void WindowsAclValidationRejectsWrongOwnerAndExtraPrincipal()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var current = WindowsIdentity.GetCurrent().User!;
        var other = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
            ExactWindowsSecurity(current, current, FileSystemRights.Read),
            current,
            requireReadOnly: true);
        ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
            ExactWindowsSecurity(current, current, FileSystemRights.FullControl),
            current,
            requireReadOnly: false);
        var wrongOwner = ExactWindowsSecurity(other, other, FileSystemRights.Read);
        Assert.Throws<UnauthorizedAccessException>(() =>
            ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
                wrongOwner,
                current,
                requireReadOnly: true));

        var extraPrincipal = ExactWindowsSecurity(current, current, FileSystemRights.Read);
        extraPrincipal.AddAccessRule(new FileSystemAccessRule(
            other,
            FileSystemRights.Read,
            AccessControlType.Allow));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
                extraPrincipal,
                current,
                requireReadOnly: true));
    }

    [Fact]
    public void DefaultSecurityRejectsInheritedOrWritableAncestor()
    {
        if (OperatingSystem.IsWindows())
        {
            AssertWindowsUnsafeAncestorRejected();
            return;
        }

        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "authority.pma1");
        File.WriteAllBytes(path, [0x01]);
        File.SetUnixFileMode(path, UnixFileMode.UserRead);
        File.SetUnixFileMode(
            _root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupWrite);

        Assert.Throws<UnauthorizedAccessException>(() =>
            new ProductionMailboxAuthorityFileSecurity()
                .ValidateReadOnlyArtifact(path, _root));
    }

    [Fact]
    public void DefaultSecurityAcceptsExactProtectedUnixTree()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_root);
        File.SetUnixFileMode(
            _root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var artifact = Path.Combine(_root, "authority.pma1");
        var lkg = Path.Combine(_root, "authority.pml1");
        File.WriteAllBytes(artifact, [0x01]);
        File.WriteAllBytes(lkg, [0x02]);
        File.SetUnixFileMode(artifact, UnixFileMode.UserRead);
        File.SetUnixFileMode(lkg, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var security = new ProductionMailboxAuthorityFileSecurity();
        security.ValidateReadOnlyArtifact(artifact, _root);
        security.ValidateProtectedLastKnownGood(lkg, _root);
    }

    [Fact]
    public void StableOpenRejectsPathSwap()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "authority.pma1");
        var replacement = Path.Combine(_root, "replacement.pma1");
        var old = Path.Combine(_root, "old.pma1");
        File.WriteAllBytes(path, [0x01]);
        File.WriteAllBytes(replacement, [0x02]);

        Assert.Throws<InvalidDataException>(() =>
        {
            using var ignored = ProductionMailboxAuthorityNativeFile.OpenStableRead(
                path,
                static () => { },
                () =>
                {
                    File.Move(path, old);
                    File.Move(replacement, path);
                });
        });
    }

    [Fact]
    public async Task PlantedLockLinkFailsClosed()
    {
        var fixture = Fixture.Create(_root);
        var target = Path.Combine(_root, "lock-target");
        File.WriteAllBytes(target, [0x01]);
        try
        {
            File.CreateSymbolicLink(fixture.LkgPath + ".lock", target);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        Assert.NotNull(File.ResolveLinkTarget(fixture.LkgPath + ".lock", returnFinalTarget: false));
        Assert.Throws<InvalidDataException>(() =>
        {
            using var ignored = ProductionMailboxAuthorityNativeFile.OpenStableRead(
                fixture.LkgPath + ".lock",
                static () => { });
        });

        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.Equal("authority-state-rejected", provider.Status.Reason);
        Assert.Equal(new byte[] { 0x01 }, File.ReadAllBytes(target));
    }

    [Fact]
    public void CreatedLockIsSecuredThroughItsOpenHandle()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "created.lock");

        using var lease = ProductionMailboxAuthorityNativeFile.AcquireLock(
            path,
            () =>
            {
                if (!File.Exists(path))
                {
                    throw new InvalidDataException("missing lock");
                }
            },
            new MailboxDurabilityBarrier());

        Assert.True(File.Exists(path));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(path));
        }
    }

    [Fact]
    public void CreatedLockPathSwapRejectsWithoutMutatingSubstitute()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "created.lock");
        var displaced = Path.Combine(_root, "created.displaced");
        var substitute = Path.Combine(_root, "substitute.lock");
        File.WriteAllBytes(substitute, [0x5a]);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                substitute,
                UnixFileMode.UserRead | UnixFileMode.UserWrite
                    | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }
        var permissionsBefore = PermissionSnapshot(substitute);

        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxAuthorityNativeFile.AcquireLock(
                path,
                () =>
                {
                    if (!File.Exists(path))
                    {
                        throw new InvalidDataException("missing lock");
                    }
                },
                new MailboxDurabilityBarrier(),
                () =>
                {
                    File.Move(path, displaced);
                    File.Move(substitute, path);
                }));

        Assert.Equal(new byte[] { 0x5a }, File.ReadAllBytes(path));
        Assert.Equal(permissionsBefore, PermissionSnapshot(path));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            foreach (var file in Directory.GetFiles(_root, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(file, FileAttributes.Normal);
            }

            Directory.Delete(_root, recursive: true);
        }
    }

    [SupportedOSPlatform("windows")]
    private static FileSecurity ExactWindowsSecurity(
        SecurityIdentifier owner,
        SecurityIdentifier principal,
        FileSystemRights rights)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(owner);
        security.AddAccessRule(new FileSystemAccessRule(
            principal,
            rights,
            AccessControlType.Allow));
        return security;
    }

    private static string PermissionSnapshot(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return Convert.ToHexString(
                new FileInfo(path).GetAccessControl().GetSecurityDescriptorBinaryForm());
        }

        return File.GetUnixFileMode(path).ToString();
    }

    [SupportedOSPlatform("windows")]
    private static void AssertWindowsUnsafeAncestorRejected()
    {
        var current = WindowsIdentity.GetCurrent().User!;
        var other = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var unsafeDirectory = new DirectorySecurity();
        unsafeDirectory.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        unsafeDirectory.SetOwner(current);
        unsafeDirectory.AddAccessRule(new FileSystemAccessRule(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        unsafeDirectory.AddAccessRule(new FileSystemAccessRule(
            other,
            FileSystemRights.Modify,
            AccessControlType.Allow));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
                unsafeDirectory,
                current,
                requireReadOnly: false));

        var inheritedPolicy = new DirectorySecurity();
        inheritedPolicy.SetOwner(current);
        inheritedPolicy.AddAccessRule(new FileSystemAccessRule(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        Assert.False(inheritedPolicy.AreAccessRulesProtected);
        Assert.Throws<UnauthorizedAccessException>(() =>
            ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
                inheritedPolicy,
                current,
                requireReadOnly: false));
    }

    private static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length)
        .Select(index => unchecked((byte)(seed + index)))
        .ToArray();

    private static string Hex(byte[] value) => Convert.ToHexString(value).ToLowerInvariant();

    private static MailboxCapabilityRevocationQuery Query(
        Fixture fixture,
        byte[] serial) => new()
    {
        IssuerPublicKey = fixture.Authority.MailboxIssuerEd25519PublicKey,
        Serial = serial,
        Domain = MailboxCapabilityDomain.Deposit,
        Generation = fixture.Authority.CurrentEpoch.Generation,
        Epoch = fixture.Authority.CurrentEpoch.Epoch,
        MembershipCommitment = fixture.Authority.CurrentEpoch.MembershipCommitment
    };

    private sealed class Fixture
    {
        private readonly byte[] _privateKey;
        private readonly byte[] _issuerPrivateKey;

        private Fixture(
            RouterNodeOptions node,
            ProductionMailboxAuthorityOptions options,
            ProductionMailboxAuthority authority,
            byte[] privateKey,
            byte[] issuerPrivateKey)
        {
            Node = node;
            Options = options;
            Authority = authority;
            _privateKey = privateKey;
            _issuerPrivateKey = issuerPrivateKey;
        }

        public RouterNodeOptions Node { get; }
        public ProductionMailboxAuthorityOptions Options { get; }
        public ProductionMailboxAuthority Authority { get; private set; }
        public string ArtifactPath => Options.ArtifactPath;
        public string RevocationArtifactPath => Options.RevocationArtifactPath;
        public string LkgPath => Options.LastKnownGoodPath;

        public static Fixture Create(string root)
        {
            var data = Path.Combine(root, "data");
            Directory.CreateDirectory(data);
            var artifactPath = Path.Combine(root, "authority.pma1");
            var revocationArtifactPath = Path.Combine(root, "revocation.pmr1");
            var lkgPath = Path.Combine(data, "authority.pml1");
            var pair = PublicKeyAuth.GenerateKeyPair(Bytes(0x21, 32));
            var issuerPair = PublicKeyAuth.GenerateKeyPair(Bytes(0x22, 32));
            var unsigned = new ProductionMailboxAuthority
            {
                DevelopmentOnly = false,
                Environment = ProductionMailboxAuthorityEnvironment.Production,
                Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
                Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
                EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
                NetworkId = Bytes(0x11, 16),
                AuthorityGeneration = 7,
                PreviousAuthorityHash = Bytes(0x31, 32),
                MailboxIssuerEd25519PublicKey = issuerPair.PublicKey,
                MrXApprovalEd25519PublicKey = pair.PublicKey,
                Coordinator = Endpoint("https://coordinator.example.net/", 0x61),
                NodeIngress = Endpoint("https://ingress.example.net/mau2/", 0x71),
                CurrentEpoch = Epoch(20, 70, Now - 60, Now + 600, 0x81),
                NextEpoch = Epoch(21, 71, Now - 10, Now + 1200, 0x91),
                Revocation = new()
                {
                    SnapshotHash = Bytes(0xA1, 32),
                    HeadHash = Bytes(0xB1, 32),
                    PreviousHeadHash = Bytes(0xC1, 32),
                    Generation = 6,
                    IssuedAtUnixSeconds = Now - 30,
                    ExpiresAtUnixSeconds = Now + 300
                },
                MrXApproval = Approval(Now - 30, Now + 300),
                Signature = new byte[64]
            };
            var fixture = new Fixture(
                new RouterNodeOptions { DataDirectory = data },
                new ProductionMailboxAuthorityOptions
                {
                    Enabled = true,
                    ArtifactPath = artifactPath,
                    RevocationArtifactPath = revocationArtifactPath,
                    ArtifactTrustRoot = root,
                    LastKnownGoodPath = lkgPath,
                    PinnedMrXPublicKeySha256 = Hex(SHA256.HashData(pair.PublicKey)),
                    ExpectedNetworkId = Hex(unsigned.NetworkId.ToArray()),
                    ClockSkewSeconds = 0
                },
                unsigned,
                pair.PrivateKey,
                issuerPair.PrivateKey);
            fixture.Authority = fixture.BindAndSignPair(unsigned);
            fixture.WriteArtifact(fixture.Authority);
            File.WriteAllBytes(lkgPath, ProductionMailboxAuthorityLkgCodec.Encode(new(
                new(6, Bytes(0x31, 32), 5, Bytes(0xC1, 32), Bytes(0xD1, 32)),
                null)));
            return fixture;
        }

        public ProductionMailboxAuthorityProvider Provider(
            IMailboxDurabilityBarrier? durability = null) => new(
            Options,
            Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new PermissiveSecurity(),
            new MailboxStorageSecurity(),
            durability ?? new MailboxDurabilityBarrier());

        public ProductionMailboxAuthority Successor(byte[]? previousAuthorityHash = null)
        {
            var currentHash = ProductionMailboxAuthorityCodec.ComputeCanonicalHash(Authority);
            var successor = BindAndSignPair(Authority with
            {
                AuthorityGeneration = 8,
                PreviousAuthorityHash = previousAuthorityHash ?? currentHash,
                CurrentEpoch = Authority.NextEpoch,
                NextEpoch = Epoch(22, 72, Now + 120, Now + 1800, 0xD2),
                Revocation = Authority.Revocation with
                {
                    SnapshotHash = Bytes(0xE2, 32),
                    PreviousHeadHash = Authority.Revocation.HeadHash,
                    HeadHash = Bytes(0xF2, 32),
                    Generation = 7
                },
                MrXApproval = Approval(Now - 5, Now + 600)
            });
            return successor;
        }

        private ProductionMailboxAuthority BindAndSignPair(
            ProductionMailboxAuthority authority)
        {
            var snapshot = new ProductionMailboxRevocationSnapshot
            {
                NetworkId = authority.NetworkId,
                AuthorityGeneration = authority.AuthorityGeneration,
                AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec
                    .ComputeAuthorityBindingHash(authority),
                RevocationGeneration = authority.Revocation.Generation,
                RevocationHeadHash = authority.Revocation.HeadHash,
                PreviousRevocationHeadHash = authority.Revocation.PreviousHeadHash,
                IssuedAtUnixSeconds = authority.Revocation.IssuedAtUnixSeconds,
                ExpiresAtUnixSeconds = authority.Revocation.ExpiresAtUnixSeconds,
                RevokedGrantSerials = [(ReadOnlyMemory<byte>)Bytes(0x10, 16)],
                IssuerSignature = new byte[64]
            };
            snapshot = snapshot with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(snapshot),
                    _issuerPrivateKey)
            };
            var encoded = ProductionMailboxRevocationSnapshotCodec.Encode(snapshot);
            File.WriteAllBytes(RevocationArtifactPath, encoded);
            return Sign(authority with
            {
                Revocation = authority.Revocation with
                {
                    SnapshotHash = SHA256.HashData(encoded)
                }
            });
        }

        public ProductionMailboxAuthority Sign(ProductionMailboxAuthority authority)
        {
            var bound = authority with
            {
                MrXApproval = authority.MrXApproval with
                {
                    AuthorityPayloadHash = ProductionMailboxAuthorityCodec
                        .ComputePayloadHash(authority)
                },
                Signature = new byte[64]
            };
            return bound with
            {
                Signature = PublicKeyAuth.SignDetached(
                    ProductionMailboxAuthorityCodec.GetSigningBytes(bound),
                    _privateKey)
            };
        }

        public void WriteArtifact(ProductionMailboxAuthority authority) =>
            File.WriteAllBytes(
                ArtifactPath,
                ProductionMailboxAuthorityCodec.Encode(authority));

        private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
        {
            Uri = uri,
            CurrentSpkiSha256 = Bytes(seed, 32),
            NextSpkiSha256 = Bytes(unchecked((byte)(seed + 1)), 32)
        };

        private static ProductionMailboxAuthorityEpoch Epoch(
            ulong epoch,
            ulong generation,
            ulong from,
            ulong until,
            byte seed) => new()
        {
            Epoch = epoch,
            Generation = generation,
            MembershipCommitment = Bytes(seed, 32),
            PlacementCommitment = Bytes(unchecked((byte)(seed + 1)), 32),
            NotBeforeUnixSeconds = from,
            NotAfterUnixSeconds = until
        };

        private static ProductionMailboxAuthorityApproval Approval(ulong from, ulong until) => new()
        {
            AuthorityPayloadHash = Bytes(0x01, 32),
            AllowedAndroidSigningCertificateSha256 = [Bytes(0x02, 32)],
            AllowedWindowsSigningCertificateSha256 = [Bytes(0x03, 32)],
            AndroidReleaseBuildArtifactSha256 = [Bytes(0x04, 32)],
            WindowsReleaseBuildArtifactSha256 = [Bytes(0x05, 32)],
            RolloutNotBeforeUnixSeconds = from,
            RolloutNotAfterUnixSeconds = until
        };
    }

    private sealed class PermissiveSecurity : IProductionMailboxAuthorityFileSecurity
    {
        public void ValidateReadOnlyArtifact(string path, string trustRoot)
        {
            if (!File.Exists(path))
            {
                throw new InvalidDataException("Production mailbox authority artifact is missing.");
            }
        }

        public void ValidateProtectedLastKnownGood(string path, string trustRoot)
        {
            if (!File.Exists(path))
            {
                throw new InvalidDataException("Production mailbox authority LKG is missing.");
            }
        }

        public void ValidateProtectedLock(string path, string trustRoot)
        {
            if (!File.Exists(path))
            {
                throw new InvalidDataException("missing lock");
            }
        }
    }

    private sealed class FixedClock(DateTimeOffset utcNow) : IClock
    {
        public DateTimeOffset UtcNow { get; } = utcNow;
    }

    private sealed class CountingBarrier(TimeSpan? delay = null) : IMailboxDurabilityBarrier
    {
        private int _replaceCount;
        public int ReplaceCount => Volatile.Read(ref _replaceCount);

        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
        }

        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (delay is { } pause)
            {
                Thread.Sleep(pause);
            }

            File.Move(temporaryPath, finalPath, overwrite: true);
            Interlocked.Increment(ref _replaceCount);
        }
    }

    private sealed class ThrowingBarrier : IMailboxDurabilityBarrier
    {
        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
        }

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            throw new IOException("simulated write failure");
    }
}
