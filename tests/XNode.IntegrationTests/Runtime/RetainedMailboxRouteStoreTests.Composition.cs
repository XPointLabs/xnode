using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class RetainedMailboxRouteStoreTests
{
    [Fact]
    public async Task ContactRuntimeConstructionFailureReleasesItsAlreadyOpenedProtectedResolver()
    {
        using var f = ProtectedFiles(); using var provider = ComposeCustody(f);
        await ContactResolverEnrollmentCommand.EnrollConfiguredAsync(provider, default);
        Directory.CreateDirectory(f.Document.Replace("resolver.state", "prekey.state.lock", StringComparison.Ordinal));
        Assert.Throws<UnauthorizedAccessException>(() => new ContactServiceLocalReplicaRuntime(signed.NodeOptions(f.Node, f.Data), f.Clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier(), provider.GetRequiredService<FileContactResolverStateCustody>()));
        using var reopened = OpenComposedStore(f, provider);
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound,
            (await reopened.ResolveProtectedRetainedMailboxRouteAsync(await Request())).Disposition);
    }

    [Fact]
    public async Task ExplicitNativeEnrollmentAndColdDiReopenKeepActualProtectedPublication()
    {
        using var f = ProtectedFiles();
        using (var provider = ComposeCustody(f))
        {
            await ContactResolverEnrollmentCommand.EnrollConfiguredAsync(provider, default);
            using var store = OpenComposedStore(f, provider);
            Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(await Publication()).Disposition);
        }
        var document = File.ReadAllBytes(f.Document); var root = File.ReadAllBytes(f.Checkpoint);
        using (var provider = ComposeCustody(f))
        {
            using var store = OpenComposedStore(f, provider);
            Assert.Equal(RetainedMailboxRouteDisposition.Found,
                (await store.ResolveProtectedRetainedMailboxRouteAsync(await Request())).Disposition);
        }
        Assert.Equal(document, File.ReadAllBytes(f.Document)); Assert.Equal(root, File.ReadAllBytes(f.Checkpoint));
        using var retry = ComposeCustody(f);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ContactResolverEnrollmentCommand.EnrollConfiguredAsync(retry, default).AsTask());
        Assert.Equal(root, File.ReadAllBytes(f.Checkpoint));
    }

    [Fact]
    public void NativeCompositionDoesNotEnrollDuringNormalReopen()
    {
        using var f = ProtectedFiles(); using var provider = ComposeCustody(f);
        Assert.Throws<InvalidDataException>(() => OpenComposedStore(f, provider));
        Assert.False(File.Exists(f.Document)); Assert.False(File.Exists(f.Enrollment)); Assert.False(File.Exists(f.Checkpoint));
    }

    [Fact]
    public async Task LostRootCannotTriggerNativeReenrollmentOrFallback()
    {
        using var f = ProtectedFiles();
        using (var provider = ComposeCustody(f)) await ContactResolverEnrollmentCommand.EnrollConfiguredAsync(provider, default);
        var document = File.ReadAllBytes(f.Document); File.Delete(f.Checkpoint);
        using var reopened = ComposeCustody(f);
        Assert.Throws<InvalidDataException>(() => OpenComposedStore(f, reopened));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ContactResolverEnrollmentCommand.EnrollConfiguredAsync(reopened, default).AsTask());
        Assert.Equal(document, File.ReadAllBytes(f.Document)); Assert.False(File.Exists(f.Checkpoint));
    }

    [Theory]
    [InlineData("key-ring")]
    [InlineData("node-binding")]
    [InlineData("data-binding")]
    public void DeferredNativeCompositionRejectsMissingKeysAndChangedNodeBindings(string fault)
    {
        using var f = ProtectedFiles(); var node = signed.NodeOptions(f.Node, f.Data);
        using var provider = ComposeCustody(f, node);
        if (fault == "key-ring") foreach (var key in Directory.GetFiles(f.Keys)) File.Delete(key);
        if (fault == "node-binding") node.RouterId = new string('1', 64);
        if (fault == "data-binding") node.DataDirectory = Path.Combine(f.Root, "other-data");
        if (fault == "key-ring") Assert.Throws<InvalidDataException>(() => provider.GetRequiredService<FileContactResolverStateCustody>());
        else Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<FileContactResolverStateCustody>());
        Assert.False(File.Exists(f.Document)); Assert.False(Directory.Exists(f.Native));
        if (fault == "key-ring") Assert.Empty(Directory.GetFiles(f.Keys));
    }

    [Theory]
    [InlineData("foreign-network")]
    [InlineData("wrong-signing-key")]
    [InlineData("cancelled")]
    public async Task ExplicitEnrollmentRejectsBeforeWritingDocumentOrProtectedRoot(string fault)
    {
        using var f = ProtectedFiles(); var node = signed.NodeOptions(f.Node, f.Data);
        if (fault == "wrong-signing-key") node.Ed25519PrivateKey = new string('2', 64);
        var network = fault == "foreign-network" ? Enumerable.Repeat((byte)0x91, 16).ToArray() : f.Network;
        using var provider = ComposeCustody(f, node, network);
        using var cancellation = new CancellationTokenSource(); if (fault == "cancelled") cancellation.Cancel();
        await Assert.ThrowsAnyAsync<Exception>(() => ContactResolverEnrollmentCommand.EnrollConfiguredAsync(provider, cancellation.Token).AsTask());
        Assert.False(File.Exists(f.Document)); Assert.False(File.Exists(f.Enrollment)); Assert.False(File.Exists(f.Checkpoint));
    }

    [Fact]
    public async Task EnrollmentAuthorityLossAfterPersistencePreservesExactFloorAndDoesNotReportSuccess()
    {
        using var f = ProtectedFiles(); var source = new LoseSecondEnrollmentSource(signed.AuthoritySource);
        using (var provider = ComposeCustody(f, source: source))
            await Assert.ThrowsAsync<CryptographicException>(() =>
                ContactResolverEnrollmentCommand.EnrollConfiguredAsync(provider, default).AsTask());
        Assert.Equal(2, source.Reads);
        var document = File.ReadAllBytes(f.Document); var root = File.ReadAllBytes(f.Checkpoint);
        using var good = ComposeCustody(f); using var store = OpenComposedStore(f, good);
        Assert.Equal(document, File.ReadAllBytes(f.Document)); Assert.Equal(root, File.ReadAllBytes(f.Checkpoint));
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound,
            (await store.ResolveProtectedRetainedMailboxRouteAsync(await Request())).Disposition);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("reset")]
    public void EnrollmentArgumentsRejectImportAndResetBeforeConfiguration(string fault)
    {
        string[] args = fault switch {
            "missing" => [], "extra" => ["contact-resolver-enroll", "--network", "untrusted"],
            _ => ["contact-resolver-enroll", "--reset"]
        };
        Assert.Throws<ArgumentException>(() => ContactResolverEnrollmentCommand.RequireArguments(args));
        ContactResolverEnrollmentCommand.RequireArguments(["contact-resolver-enroll"]);
    }

    [Theory]
    [InlineData("network")]
    [InlineData("disabled")]
    [InlineData("nested-data")]
    [InlineData("nested-keys")]
    [InlineData("root")]
    [InlineData("relative")]
    public void ResolverConfigurationRejectsAbsentScopeAndNonIndependentPaths(string fault)
    {
        using var f = ProtectedFiles(); var node = signed.NodeOptions(f.Node, f.Data);
        var options = CustodyOptions(f, f.Network);
        if (fault == "network") options.NetworkIdHex = new string('0', 32);
        if (fault == "nested-data") options.IndependentCustodyDirectory = Path.Combine(f.Data, "custody");
        if (fault == "nested-keys") options.DataProtectionKeysDirectory = Path.Combine(f.Native, "keys");
        if (fault == "root") options.IndependentCustodyDirectory = Path.GetPathRoot(f.Native)!;
        if (fault == "relative") options.DataProtectionKeysDirectory = "relative-keys";
        Assert.Throws<InvalidOperationException>(() => options.Validate(node, fault != "disabled"));
        Assert.Null(new ContactResolverCustodyOptions().Validate(node, false));
    }

    private ServiceProvider ComposeCustody(ProtectedResolverFiles f, RouterNodeOptions? node = null,
        byte[]? network = null, IDeepIdV2ContactStoreAuthoritySource? source = null)
    {
        node ??= signed.NodeOptions(f.Node, f.Data);
        var services = new ServiceCollection(); services.AddSingleton(node);
        services.AddSingleton(source ?? signed.AuthoritySource);
        services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        services.AddContactResolverCustody(CustodyOptions(f, network ?? f.Network).Validate(node, true));
        return services.BuildServiceProvider();
    }
    private static ContactResolverCustodyOptions CustodyOptions(ProtectedResolverFiles f, byte[] network) => new()
    {
        NetworkIdHex = Convert.ToHexStringLower(network), IndependentCustodyDirectory = f.Native, DataProtectionKeysDirectory = f.Keys
    };
    private static ContactResolverOpaqueStore OpenComposedStore(ProtectedResolverFiles f, IServiceProvider provider) =>
        new(f.Document, clock: f.Clock, custody: provider.GetRequiredService<FileContactResolverStateCustody>());
    private sealed class LoseSecondEnrollmentSource(IDeepIdV2ContactStoreAuthoritySource actual) : IDeepIdV2ContactStoreAuthoritySource
    {
        internal int Reads;
        public ValueTask<DeepIdV2ContactStoreAuthority> ReadPublicationAuthorityAsync(CancellationToken ct)
        {
            if (++Reads == 2) throw new CryptographicException("Injected current authority loss after enrollment.");
            return actual.ReadPublicationAuthorityAsync(ct);
        }
    }
}
