using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode;

internal static class ContactResolverEnrollmentCommand
{
    internal static void RequireArguments(string[] args)
    {
        if (args.Length != 1 || args[0] != "contact-resolver-enroll")
            throw new ArgumentException("Invalid resolver enrollment arguments.");
    }

    internal static async Task RunAsync(string[] args)
    {
        RequireArguments(args);
        var builder = WebApplication.CreateBuilder(Array.Empty<string>());
        builder.Logging.ClearProviders();
        RetiredAuthorityConfiguration.RequireAbsent(builder.Configuration);
        var node = builder.Configuration.GetSection("Node").Get<RouterNodeOptions>() ?? new();
        var custody = (builder.Configuration.GetSection("ContactResolverCustody")
            .Get<ContactResolverCustodyOptions>(o => o.ErrorOnUnknownConfiguration = true) ?? new()).Validate(node, true)!;
        if (!(builder.Configuration.GetSection("DeepIdV2ContactResolver").Get<DeepIdV2ContactResolverOptions>() ?? new()).Enabled)
            throw new InvalidOperationException("Resolver enrollment requires the configured DID2 resolver.");
        var reviewed = builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("UAT");
        var proof = (builder.Configuration.GetSection("DeepIdV2DirectoryProof").Get<DeepIdV2DirectoryProofOptions>() ?? new())
            .ValidateAndLoad(node, reviewed) ?? throw new InvalidOperationException("Current proof source is required.");
        var placement = (builder.Configuration.GetSection("DeepIdV2NetworkPlacement").Get<DeepIdV2NetworkPlacementOptions>() ?? new())
            .ValidateAndLoad(true, reviewed) ?? throw new InvalidOperationException("Current network source is required.");
        if (placement.Observer is null) throw new InvalidOperationException("Independent current observation is required.");
        builder.Services.AddSingleton(node);
        builder.Services.AddSingleton<IOnionMonotonicClock>(static _ => new LinuxBootOnionMonotonicClock());
        builder.Services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        builder.Services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        builder.Services.AddDeepIdV2DirectoryProof(proof);
        builder.Services.AddDeepIdV2NetworkPlacement(placement);
        builder.Services.AddContactResolverCustody(custody);
        await using var services = builder.Services.BuildServiceProvider();
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        _ = await services.GetRequiredService<DeepIdV2DirectoryProofRuntime>().RestoreHeadAsync(budget.Token).ConfigureAwait(false);
        await services.GetRequiredService<DeepIdV2NetworkPlacementRuntime>().AcquireObservationAsync(budget.Token).ConfigureAwait(false);
        await EnrollConfiguredAsync(services, budget.Token).ConfigureAwait(false);
        Console.WriteLine("Fresh resolver enrollment verified. Retained issuance and runtime activation remain separately gated.");
    }

    internal static async ValueTask EnrollConfiguredAsync(IServiceProvider services, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(services); ct.ThrowIfCancellationRequested();
        var node = services.GetRequiredService<RouterNodeOptions>();
        var source = services.GetRequiredService<IDeepIdV2ContactStoreAuthoritySource>();
        var first = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
        var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(first.Network, first.Authority,
            first.MailboxAuthority.ExactPma2, first.TrustedTime, ct).ConfigureAwait(false);
        var history = OnionNetworkProtectedHistoryCodec.Encode(first.Network);
        var seed = Convert.FromHexString(node.GetEd25519PrivateKey());
        using var signing = CreateSigner(node.GetRouterId().ToBytes(), seed);
        signing.EnsureSigningCustody(first.Network);
        var custody = services.GetRequiredService<FileContactResolverStateCustody>();
        custody.RequireNetwork(first.Network.NetworkId.Span);
        await host.EnsureCurrentAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        using var store = ContactResolverOpaqueStore.EnrollNewProtected(
            Path.Combine(Path.GetFullPath(node.DataDirectory), "contact-service-v1", "resolver.state"), custody,
            storageSecurity: services.GetRequiredService<IMailboxStorageSecurity>(),
            durability: services.GetRequiredService<IMailboxDurabilityBarrier>());
        var final = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(history, OnionNetworkProtectedHistoryCodec.Encode(final.Network)) ||
            !CryptographicOperations.FixedTimeEquals(first.Authority.AuthorityCoreReference.Span, final.Authority.AuthorityCoreReference.Span) ||
            !CryptographicOperations.FixedTimeEquals(first.MailboxAuthority.CoreHash.Span, final.MailboxAuthority.CoreHash.Span))
            throw new CryptographicException("Resolver enrollment crossed a current authority change.");
        signing.EnsureSigningCustody(final.Network); custody.RequireNetwork(final.Network.NetworkId.Span);
        var finalHost = await MailboxHostAuthorityV2Verifier.VerifyAsync(final.Network, final.Authority,
            final.MailboxAuthority.ExactPma2, final.TrustedTime, ct).ConfigureAwait(false);
        await finalHost.EnsureCurrentAsync(ct).ConfigureAwait(false);
        custody.RequireSnapshot(Path.Combine(Path.GetFullPath(node.DataDirectory), "contact-service-v1", "resolver.state"));
        ct.ThrowIfCancellationRequested();
    }

    private static LocalContactServiceReplicaReceiptAuthority CreateSigner(byte[] node, byte[] seed)
    {
        try { return new(node, seed); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }
}
