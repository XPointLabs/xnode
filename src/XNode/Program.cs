using System.Threading.RateLimiting;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using XNode;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using XNode.Core.Runtime;
using XNode.Registry;
using XNode.Registry.Bootstrap;
using XNode.Registry.Heartbeat;
using XNode.Transport.Vless;

var builder = WebApplication.CreateBuilder(args);

var nodeOptions = builder.Configuration.GetSection("Node").Get<RouterNodeOptions>() ?? new RouterNodeOptions();
var vlessOptions = builder.Configuration.GetSection("Vless").Get<VlessTransportOptions>() ?? new VlessTransportOptions();
var heartbeatOptions = builder.Configuration.GetSection("RegistryHeartbeat").Get<RegistrationHeartbeatOptions>()
    ?? new RegistrationHeartbeatOptions();
var registrationOptions = builder.Configuration.GetSection("RegistryRegistration").Get<RegistryRegistrationOptions>()
    ?? new RegistryRegistrationOptions();
var membershipArtifactOptions = builder.Configuration.GetSection("MembershipArtifact")
    .Get<MembershipRouteArtifactOptions>() ?? new MembershipRouteArtifactOptions();
var mailboxOptions = builder.Configuration.GetSection("Mailbox")
    .Get<ReplicatedMailboxOptions>() ?? new ReplicatedMailboxOptions();
var mailboxPeerAuthorityOptions = builder.Configuration.GetSection("MailboxPeerAuthority")
    .Get<MailboxPeerAuthorityOptions>() ?? new MailboxPeerAuthorityOptions();
var mailboxClientActivationOptions = builder.Configuration.GetSection("MailboxClient")
    .Get<MailboxClientActivationOptions>() ?? new MailboxClientActivationOptions();
var mailboxClientAdapterOptions = builder.Configuration.GetSection("MailboxClientAdapter")
    .Get<MailboxClientAdapterOptions>() ?? new MailboxClientAdapterOptions();
var productionMailboxAuthorityOptions = builder.Configuration
    .GetSection("MailboxClientProductionAuthority")
    .Get<ProductionMailboxAuthorityOptions>() ?? new ProductionMailboxAuthorityOptions();
var privacyRoutingOptions = builder.Configuration.GetSection("PrivacyRouting")
    .Get<PrivacyRoutingOptions>() ?? new PrivacyRoutingOptions();
var mailboxAuthorityForwardingOptions = builder.Configuration
    .GetSection("MailboxAuthorityForwarding")
    .Get<MailboxAuthorityForwardingOptions>() ?? new MailboxAuthorityForwardingOptions();
var privacyRouting = privacyRoutingOptions.ValidateAndLoad(
    nodeOptions,
    builder.Environment.IsDevelopment());
mailboxOptions.Validate();
mailboxPeerAuthorityOptions.Validate(mailboxOptions.Enabled);
productionMailboxAuthorityOptions.Validate(
    nodeOptions,
    builder.Environment.IsProduction());
var mailboxClientActivationPlan = MailboxClientComposition.Validate(
    mailboxClientActivationOptions,
    mailboxClientAdapterOptions,
    nodeOptions,
    mailboxOptions,
    builder.Environment.IsDevelopment(),
    mailboxPeerAuthorityOptions,
    productionMailboxAuthorityOptions);
var mailboxAuthorityForwarding = mailboxAuthorityForwardingOptions.Validate(
    mailboxClientActivationPlan,
    privacyRouting,
    nodeOptions,
    productionMailboxAuthorityOptions.Enabled);
if (mailboxOptions.Enabled
    && mailboxPeerAuthorityOptions.CurrentEpochExpiresAtUnixSeconds
        <= checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
{
    throw new InvalidOperationException(
        "MailboxPeerAuthority current epoch is already retired.");
}
if (mailboxOptions.AllowInsecureHttpPeerTransport
    && !builder.Environment.IsDevelopment())
{
    throw new InvalidOperationException(
        "Mailbox:AllowInsecureHttpPeerTransport is Development-only.");
}

VlessProfileGuard.Validate(vlessOptions, builder.Environment.IsDevelopment());

vlessOptions.PublicHost = string.IsNullOrWhiteSpace(vlessOptions.PublicHost) ? nodeOptions.PublicHost : vlessOptions.PublicHost;
vlessOptions.PublicPort = vlessOptions.PublicPort == 0 ? nodeOptions.PublicPort : vlessOptions.PublicPort;

var listenerPlan = NodeListenerConfiguration.Create(nodeOptions);
var apiListenUri = listenerPlan.Api.Url;
var peerRpcListenUri = listenerPlan.Peer.Url;
var managedIngressListenUri = listenerPlan.ManagedIngress?.Url;
var privacyPeerListenUri = listenerPlan.PrivacyPeer?.Url;
vlessOptions.ApiIngressPort = apiListenUri.Port;
if (managedIngressListenUri is null && privacyPeerListenUri is null)
{
    builder.WebHost.UseUrls(nodeOptions.ApiListenUrl, nodeOptions.PeerRpcListenUrl);
}
else
{
    builder.WebHost.ConfigureKestrel(listenerPlan.Configure);
}

builder.Services.AddSingleton<IClock, SystemClock>();
builder.Services.AddSingleton(nodeOptions);
builder.Services.AddSingleton(vlessOptions);
builder.Services.AddSingleton(heartbeatOptions);
builder.Services.AddSingleton(registrationOptions);
builder.Services.AddSingleton(membershipArtifactOptions);
builder.Services.AddSingleton(mailboxOptions);
builder.Services.AddSingleton(mailboxPeerAuthorityOptions);
builder.Services.AddSingleton(mailboxClientActivationOptions);
builder.Services.AddSingleton(mailboxClientAdapterOptions);
builder.Services.AddSingleton(productionMailboxAuthorityOptions);
builder.Services.AddSingleton(privacyRoutingOptions);
builder.Services.AddSingleton(privacyRouting);
builder.Services.AddSingleton(mailboxAuthorityForwardingOptions);
builder.Services.AddSingleton(mailboxAuthorityForwarding);
builder.Services.AddSingleton<PrivacyPeerReplayGuard>();
builder.Services.AddSingleton<MailboxAuthorityForwardingReplayGuard>();
builder.Services.AddSingleton<PrivacyRoutingReplayGuard>();
builder.Services.AddSingleton<PrivacyIngressLimiter>();
builder.Services.AddSingleton<MailboxAuthorityForwardingIngressLimiter>();
builder.Services.AddSingleton<IPrivacyPeerClient, HttpPrivacyPeerClient>();
builder.Services.AddSingleton<NativeMailboxExitDispatcher>();
builder.Services.AddSingleton<ILocalNativeMailboxExitDispatcher>(provider =>
    provider.GetRequiredService<NativeMailboxExitDispatcher>());
builder.Services.AddSingleton<IMailboxAuthorityForwardingClient,
    MailboxAuthorityForwardingClient>();
builder.Services.AddSingleton<RoutedNativeMailboxExitDispatcher>();
builder.Services.AddSingleton<INativeMailboxExitDispatcher>(provider =>
    provider.GetRequiredService<RoutedNativeMailboxExitDispatcher>());
builder.Services.AddSingleton<PrivacyRoutingRuntime>();
builder.Services.AddSingleton(mailboxClientActivationPlan);
builder.Services.AddSingleton<MailboxClientRuntimeReadiness>();
builder.Services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
builder.Services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
builder.Services.AddSingleton<IProductionMailboxAuthorityFileSecurity,
    ProductionMailboxAuthorityFileSecurity>();
    builder.Services.AddSingleton<ProductionMailboxAuthorityProvider>();
    builder.Services.AddSingleton<ProductionMailboxClosureStore>();
builder.Services.AddHostedService<ProductionMailboxAuthorityHostedService>();
if (mailboxClientActivationPlan.DevelopmentFixture)
{
    builder.Services.AddSingleton<
        IMailboxCapabilityAuthoritySource,
        DevelopmentMailboxCapabilityAuthority>();
    builder.Services.AddSingleton<
        IMailboxCapabilityRevocationPolicy,
        DevelopmentMailboxCapabilityRevocations>();
    builder.Services.AddSingleton<
        IMailboxClientReplicaAuthorizer,
        DevelopmentMailboxReplicaAuthority>();
    builder.Services.AddSingleton<DevelopmentMailboxReplicaFanout>();
    builder.Services.AddSingleton<IMailboxClientReplicaFanout>(provider =>
        provider.GetRequiredService<DevelopmentMailboxReplicaFanout>());
    builder.Services.AddSingleton<IMailboxClientTombstoneFanout>(provider =>
        provider.GetRequiredService<DevelopmentMailboxReplicaFanout>());
}
else if (productionMailboxAuthorityOptions.Enabled)
{
    builder.Services.AddSingleton<IMailboxCapabilityAuthoritySource>(provider =>
        provider.GetRequiredService<ProductionMailboxAuthorityProvider>());
    builder.Services.AddSingleton<IMailboxCapabilityRevocationPolicy>(provider =>
        provider.GetRequiredService<ProductionMailboxAuthorityProvider>());
    builder.Services.AddSingleton<IProductionMailboxTopologyProvider>(provider =>
        provider.GetRequiredService<ProductionMailboxAuthorityProvider>());
    builder.Services.AddSingleton<
        IMailboxClientReplicaAuthorizer,
        ProductionMailboxReplicaAuthority>();
    builder.Services.AddSingleton<ProductionMailboxReplicaFanout>();
    builder.Services.AddSingleton<IMailboxClientReplicaFanout>(provider =>
        provider.GetRequiredService<ProductionMailboxReplicaFanout>());
    builder.Services.AddSingleton<IMailboxClientTombstoneFanout>(provider =>
        provider.GetRequiredService<ProductionMailboxReplicaFanout>());
}
else
{
    builder.Services.AddSingleton<
        IMailboxCapabilityAuthoritySource,
        RejectAllMailboxCapabilityAuthoritySource>();
    builder.Services.AddSingleton<
        IMailboxCapabilityRevocationPolicy,
        RejectAllMailboxCapabilityRevocationPolicy>();
}
builder.Services.AddSingleton<
    IMailboxAuthenticatedCapabilityCrypto,
    SodiumMailboxCapabilityCrypto>();
if (mailboxClientActivationPlan.RoutesMapped)
{
    builder.Services.AddSingleton(provider => new DurableMailboxCapabilityReplayJournal(
        nodeOptions.DataDirectory));
    builder.Services.AddSingleton(provider => new MailboxClientCanonicalOutcomeStore(
        nodeOptions.DataDirectory));
    builder.Services.AddSingleton<MailboxAuthenticatedCapabilityRuntime>();
    builder.Services.AddSingleton(provider => new MailboxClientOperationLedger(
        nodeOptions.DataDirectory,
        mailboxClientAdapterOptions,
        provider.GetRequiredService<IClock>()));
    builder.Services.AddSingleton(provider => new MailboxClientReceiptCrypto(
        nodeOptions.GetRouterId(),
        nodeOptions.GetEd25519PrivateKey()));
    builder.Services.AddSingleton<MailboxClientStoreAdapter>();
    builder.Services.AddSingleton<MailboxClientIngressLimiter>();
    builder.Services.AddSingleton<MailboxClientVerifiedHolderLimiter>();
    builder.Services.AddHostedService<MailboxAuthenticatedStateGcHostedService>();
}
builder.Services.AddSingleton<MembershipRouteArtifactPublisher>();
builder.Services.AddSingleton(provider => new ReplicatedMailboxStore(
    nodeOptions.DataDirectory,
    mailboxOptions,
    provider.GetRequiredService<IClock>()));
builder.Services.AddHostedService<MailboxStoreHostedService>();
builder.Services.AddSingleton(provider => new MailboxPeerMutationStore(
    nodeOptions.DataDirectory,
    mailboxOptions,
    provider.GetRequiredService<ReplicatedMailboxStore>(),
    provider.GetRequiredService<IClock>()));
builder.Services.AddSingleton<MailboxPeerRuntimeReadiness>();
builder.Services.AddSingleton<MailboxPeerStoreHostedService>();
builder.Services.AddHostedService(provider =>
    provider.GetRequiredService<MailboxPeerStoreHostedService>());
builder.Services.AddHostedService<MailboxClientAdapterHostedService>();
builder.Services.AddSingleton<DurableMailboxPeerReplayJournal>(provider => new(
    nodeOptions.DataDirectory,
    mailboxOptions,
    provider.GetRequiredService<IClock>()));
builder.Services.AddSingleton<IMailboxPeerReplayJournal>(provider =>
    provider.GetRequiredService<DurableMailboxPeerReplayJournal>());
builder.Services.AddSingleton<IMailboxReplicaMembershipProofVerifier,
    MembershipRoutesMailboxReplicaProofVerifier>();
builder.Services.AddSingleton<IMailboxPeerRequestPolicyResolver>(provider =>
    new MailboxPeerRequestPolicyResolver(
        nodeOptions.GetRouterId(),
        nodeOptions.GetEd25519PrivateKey(),
        mailboxPeerAuthorityOptions,
        provider.GetRequiredService<MailboxPeerMutationStore>()));
builder.Services.AddSingleton(provider => new MailboxReplicaReceiver(
    nodeOptions.GetEd25519PrivateKey(),
    mailboxOptions,
    provider.GetRequiredService<MailboxPeerMutationStore>(),
    provider.GetRequiredService<IMailboxPeerRequestPolicyResolver>(),
    provider.GetRequiredService<IMailboxReplicaMembershipProofVerifier>(),
    provider.GetRequiredService<IMailboxPeerReplayJournal>(),
    provider.GetRequiredService<IClock>()));
builder.Services.AddSingleton<MailboxPeerIngressLimiter>();
builder.Services.AddHttpClient<IMailboxReplicaPeerClient, HttpMailboxReplicaPeerClient>()
    .ConfigurePrimaryHttpMessageHandler(() =>
        MailboxPeerHttpHandler.Create(mailboxOptions));
builder.Services.AddSingleton(provider => new MailboxReplicationCoordinator(
    nodeOptions.GetRouterId(),
    nodeOptions.GetEd25519PrivateKey(),
    mailboxOptions,
    provider.GetRequiredService<MailboxPeerMutationStore>(),
    provider.GetRequiredService<IMailboxReplicaPeerClient>(),
    provider.GetRequiredService<IMailboxReplicaMembershipProofVerifier>(),
    provider.GetRequiredService<IMailboxPeerReplayJournal>()));
builder.Services.AddSingleton<ILocalPrivacyContactProvider, LocalPrivacyContactProvider>();

builder.Services.AddSingleton<XrayConfigGenerator>();
builder.Services.AddSingleton<XraySupervisor>();
builder.Services.AddSingleton<IXraySupervisor>(provider => provider.GetRequiredService<XraySupervisor>());
builder.Services.AddHostedService(provider => provider.GetRequiredService<XraySupervisor>());

builder.Services.AddSingleton<RegistryPayloadFactory>();
builder.Services.AddHttpClient<Bls12381RegistrationProofService>();
builder.Services.AddHttpClient<Bls12381QuorumSigningService>();
builder.Services.AddSingleton<RegistryRegistrationPayloadFactory>();
builder.Services.AddSingleton<ClientBootstrapService>();
builder.Services.AddSingleton<IRegistryClient>(_ => new HttpRegistryClient(new HttpClient(), heartbeatOptions));
builder.Services.AddHostedService<RegistrationHeartbeatService>();
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("bounded-api", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, privacyRoutingOptions.RequestsPerMinute),
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.NewestFirst,
            AutoReplenishment = true
        }));
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

var app = builder.Build();

app.UseManagedIngressProxyTrustBoundary(listenerPlan);

app.Use(async (context, next) =>
{
    if (managedIngressListenUri is not null
        && context.Connection.LocalPort == managedIngressListenUri.Port)
    {
        var managedIngressPath = context.Request.Path;
        if (!managedIngressPath.Equals(ManagedIngressH2Contract.FramePath)
            && !managedIngressPath.Equals(ManagedIngressH2Contract.CapabilitiesPath))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
    }

    if (privacyPeerListenUri is not null
        && context.Connection.LocalPort == privacyPeerListenUri.Port
        && !context.Request.Path.Equals(PrivacyRoutingOptions.PeerFramePath)
        && !MailboxAuthorityForwardingHttpContract.TryOperation(
            context.Request.Path,
            out _)
        && !context.Request.Path.Equals(MailboxWireHttpContract.PeerStoreRoute)
        && !context.Request.Path.Equals(MailboxWireHttpContract.PeerTombstoneRoute))
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }

    if ((MailboxAuthorityForwardingHttpContract.TryOperation(
                context.Request.Path,
                out _)
            || context.Request.Path.Equals(MailboxWireHttpContract.PeerStoreRoute)
            || context.Request.Path.Equals(MailboxWireHttpContract.PeerTombstoneRoute))
        && !HttpMethods.IsPost(context.Request.Method))
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }

    if (context.Connection.LocalPort != peerRpcListenUri.Port)
    {
        await next(context);
        return;
    }

    var path = context.Request.Path;
    var allowed = (privacyPeerListenUri is null
            && path.Equals(PrivacyRoutingOptions.PeerFramePath))
        || MailboxAuthorityForwardingHttpContract.TryOperation(path, out _)
        || path.Equals(ProductionMailboxClosureHttpContract.PrepositionRoute)
        || path.Equals(MailboxWireHttpContract.PeerStoreRoute)
        || path.Equals(MailboxWireHttpContract.PeerTombstoneRoute)
        || path.Equals("/health/live")
        || path.Equals("/health/ready")
        || (path.Equals("/api/staking/quorum/sign")
            && QuorumCoordinatorAccess.IsAllowed(
                context.Connection.RemoteIpAddress,
                nodeOptions.QuorumCoordinatorNetworks));
    if (!allowed)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }

    await next(context);
});
app.Use(async (context, next) =>
{
    var path = context.Request.Path;
    if (path.Equals(ManagedIngressH2Contract.FramePath)
        || path.Equals(PrivacyRoutingOptions.PeerFramePath)
        || MailboxAuthorityForwardingHttpContract.TryOperation(path, out _)
        || path.Equals(ProductionMailboxClosureHttpContract.PrepositionRoute)
        || path.Equals(MailboxWireHttpContract.PeerStoreRoute)
        || path.Equals(MailboxWireHttpContract.PeerTombstoneRoute))
    {
        var maxBodyBytes = path.Equals(ManagedIngressH2Contract.FramePath)
            || path.Equals(PrivacyRoutingOptions.PeerFramePath)
                ? ManagedIngressLimits.MaximumOpaqueFrameBytes
                : MailboxAuthorityForwardingHttpContract.TryOperation(
                    path,
                    out var authorityOperation)
                    ? MailboxAuthorityForwardingHttpContract.Contract(
                        authorityOperation).MaximumRequestBytes
                : path.Equals(ProductionMailboxClosureHttpContract.PrepositionRoute)
                    ? ProductionMailboxPrepositionCommandCodec.MaximumCommandBytes
                    : Math.Max(
                        MailboxWireHttpContract.PeerStore.MaximumRequestBytes,
                        MailboxWireHttpContract.PeerTombstone.MaximumRequestBytes);
        if (context.Request.ContentLength is > 0 and var contentLength && contentLength > maxBodyBytes)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        var feature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (feature is { IsReadOnly: false })
        {
            feature.MaxRequestBodySize = maxBodyBytes;
        }
    }

    await next(context);
});
app.UseRateLimiter();

app.MapGet("/", () => Results.Redirect("/status"));

app.MapGet("/health/live", () => Results.Ok(new { ok = true }));

app.MapGet("/health/ready", (
    IXraySupervisor xray,
    ReplicatedMailboxOptions mailbox,
    MailboxPeerRuntimeReadiness mailboxPeer,
    MailboxClientRuntimeReadiness mailboxClient,
    ProductionMailboxAuthorityProvider productionMailboxAuthority,
    PrivacyRoutingConfiguration privacy) =>
{
    var xrayStatus = xray.Status;
    var transportReady = !xrayStatus.Enabled || xrayStatus.Running || xrayStatus.Degraded;
    var mailboxPeerReady = !mailbox.Enabled || mailboxPeer.Ready;
    var mailboxClientReady =
        !mailboxClientActivationPlan.RoutesMapped || mailboxClient.Ready;
    var privacyReady = XNodeReadinessPolicy.IsPrivacyReady(
        privacy.Enabled,
        app.Environment.IsDevelopment());
    var productionMailboxAuthorityReady =
        !productionMailboxAuthorityOptions.Enabled
        || productionMailboxAuthority.Status.Ready;
    var ready = transportReady
        && privacyReady
        && mailboxPeerReady
        && mailboxClientReady
        && productionMailboxAuthorityReady;
    return ready
        ? Results.Ok(new
        {
            ready = true,
            degraded = xrayStatus.Degraded,
            transportMode = xrayStatus.Mode,
            privacyRouting = privacy.Enabled ? "ready" : "disabled-development",
            mailboxPeer = mailboxPeer.Status,
            mailboxClient = mailboxClient.Status,
            mailboxAuthorityForwarding = mailboxAuthorityForwarding.Role,
            mailboxProductionAuthority = productionMailboxAuthority.Status
        })
        : Results.Json(
            new
            {
                ready = false,
                xray = xrayStatus,
                privacyRouting = privacy.Enabled ? "ready" : "disabled",
                mailboxPeer = mailboxPeer.Status,
                mailboxClient = mailboxClient.Status,
                mailboxAuthorityForwarding = mailboxAuthorityForwarding.Role,
                mailboxProductionAuthority = productionMailboxAuthority.Status
            },
            statusCode: StatusCodes.Status503ServiceUnavailable);
});

app.MapGet("/status", (
    IXraySupervisor xray,
    RegistryPayloadFactory registryPayloadFactory,
    ReplicatedMailboxOptions mailbox,
    MailboxPeerRuntimeReadiness mailboxPeer,
    MailboxClientRuntimeReadiness mailboxClient,
    ProductionMailboxAuthorityProvider productionMailboxAuthority,
    PrivacyRoutingConfiguration privacy,
    IServiceProvider services) =>
{
    object mailboxStatus = mailbox.Enabled
        ? new
        {
            enabled = true,
            peerRuntime = mailboxPeer.Status,
            wire = "prq2-mrr2-mqr3",
            receiver = services.GetRequiredService<MailboxReplicaReceiver>().Metrics
        }
        : new { enabled = false };
    return Results.Ok(new
    {
        router = new
        {
            state = privacy.Enabled ? "running" : "privacy-routing-disabled",
            privacyRouting = privacy.Enabled,
            x25519PublicKey = privacy.Enabled
                ? Convert.ToHexString(privacy.PublicKey).ToLowerInvariant()
                : null
        },
        xray = xray.Status,
        registryPayload = registryPayloadFactory.Create(),
        mailbox = mailboxStatus,
        privacyReplay = privacy.Enabled ? "bounded-ttl" : "disabled",
        mailboxClient = mailboxClient.Status,
        mailboxAuthorityForwarding = mailboxAuthorityForwarding.Role,
        mailboxProductionAuthority = productionMailboxAuthority.Status
    });
});

app.MapGet("/api/bootstrap/client", (ClientBootstrapService bootstrap) => Results.Ok(bootstrap.Create()));

app.MapGet("/api/network/privacy-contact", (ILocalPrivacyContactProvider contactProvider) =>
{
    try
    {
        return Results.Ok(contactProvider.Create());
    }
    catch (InvalidOperationException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.MapGet("/api/network/membership-route-catalog", async (
    MembershipRouteArtifactPublisher publisher,
    CancellationToken cancellationToken) =>
{
    try
    {
        var artifact = await publisher.ReadAsync(cancellationToken);
        return artifact is null
            ? Results.Problem(
                "No quorum-signed membership route artifact is configured.",
                statusCode: StatusCodes.Status503ServiceUnavailable)
            : Results.File(
                artifact,
                "application/vnd.deep.membership-route-catalog",
                enableRangeProcessing: false);
    }
    catch (InvalidDataException)
    {
        return Results.Problem(
            "The configured membership route artifact is invalid.",
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }
    catch (InvalidOperationException)
    {
        return Results.Problem(
            "Membership route artifact publication is misconfigured.",
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }
}).RequireRateLimiting("bounded-api");

if (productionMailboxAuthorityOptions.Enabled)
{
    app.MapPost(ProductionMailboxClosureHttpContract.FetchRoute, async (
        HttpContext context,
        ProductionMailboxClosureStore closures,
        CancellationToken cancellationToken) =>
    {
        context.Response.Headers.CacheControl = "no-store";
        if (context.Request.ContentLength != ProductionMailboxClosureRequestCodec.EncodedLength
            || !string.Equals(context.Request.ContentType,
                ProductionMailboxClosureHttpContract.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Results.NotFound();
        var request = new byte[ProductionMailboxClosureRequestCodec.EncodedLength];
        try
        {
            await context.Request.Body.ReadExactlyAsync(request, cancellationToken);
            var closure = await closures.FetchAsync(request, cancellationToken);
            return closure is null
                ? Results.NotFound()
                : Results.File(closure, ProductionMailboxClosureHttpContract.ClosureMediaType,
                    enableRangeProcessing: false);
        }
        catch (Exception exception) when (exception is IOException
            || exception is OperationCanceledException
                && context.RequestAborted.IsCancellationRequested)
        {
            return Results.NotFound();
        }
    }).RequireRateLimiting("bounded-api");

    app.MapPost(ProductionMailboxClosureHttpContract.PrepositionRoute, async (
        HttpContext context,
        ProductionMailboxClosureStore closures,
        CancellationToken cancellationToken) =>
        await ProductionMailboxClosureHttpEndpoint.HandlePrepositionAsync(
            context, closures, peerRpcListenUri.Port, cancellationToken))
        .RequireRateLimiting("bounded-api");

    app.MapPost(ProductionMailboxClosureHttpContract.CapacityRoute, async (
        HttpContext context,
        ProductionMailboxClosureStore closures,
        CancellationToken cancellationToken) =>
        await ProductionMailboxClosureHttpEndpoint.HandleCapacityAsync(
            context, closures, peerRpcListenUri.Port, cancellationToken))
        .RequireRateLimiting("bounded-api");

    app.MapPost(ProductionMailboxClosureHttpContract.CapacityReconciliationRoute, async (
        HttpContext context,
        ProductionMailboxClosureStore closures,
        CancellationToken cancellationToken) =>
        await ProductionMailboxClosureHttpEndpoint.HandleCapacityReconciliationAsync(
            context, closures, peerRpcListenUri.Port, cancellationToken))
        .RequireRateLimiting("bounded-api");
}

app.MapPost("/api/staking/quorum/sign", async (
    QuorumSignatureRequest request,
    RouterNodeOptions node,
    RegistryRegistrationOptions registration,
    Bls12381QuorumSigningService signer,
    CancellationToken cancellationToken) =>
{
    try
    {
        var signature = await signer.SignAsync(
            registration,
            node.RouterId,
            request,
            cancellationToken);
        return Results.Ok(signature);
    }
    catch (QuorumSignatureRejectedException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status409Conflict);
    }
    catch (InvalidOperationException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
    catch (ArgumentOutOfRangeException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest);
    }
}).RequireRateLimiting("bounded-api");

app.MapPost(ManagedIngressH2Contract.FramePath, (
    HttpContext context,
    PrivacyRoutingConfiguration privacy,
    PrivacyIngressLimiter limiter,
    PrivacyRoutingRuntime runtime,
    IClock clock,
    CancellationToken cancellationToken) =>
    PrivacyRoutingHttpEndpoint.HandlePublicAsync(
        context,
        privacy,
        limiter,
        runtime,
        clock,
        listenerPlan.ManagedIngressPort,
        cancellationToken));

app.MapGet(ManagedIngressH2Contract.CapabilitiesPath, (
    HttpContext context,
    PrivacyRoutingConfiguration privacy) =>
    PrivacyRoutingHttpEndpoint.HandleCapabilities(
        context,
        privacy,
        listenerPlan.ManagedIngressPort));

app.MapPost(PrivacyRoutingOptions.PeerFramePath, (
    HttpContext context,
    PrivacyRoutingConfiguration privacy,
    PrivacyIngressLimiter limiter,
    PrivacyPeerReplayGuard peerReplay,
    PrivacyRoutingRuntime runtime,
    RouterNodeOptions node,
    IClock clock,
    CancellationToken cancellationToken) =>
    PrivacyRoutingHttpEndpoint.HandlePeerAsync(
        context,
        privacy,
        limiter,
        peerReplay,
        runtime,
        node,
        clock,
        listenerPlan.PrivacyPeerPort,
        cancellationToken));

app.MapPost(MailboxAuthorityForwardingHttpContract.StoreRoute, HandleMailboxAuthorityAsync);
app.MapPost(MailboxAuthorityForwardingHttpContract.RetrieveRoute, HandleMailboxAuthorityAsync);
app.MapPost(MailboxAuthorityForwardingHttpContract.AcknowledgeRoute, HandleMailboxAuthorityAsync);

app.MapPost(MailboxWireHttpContract.PeerStoreRoute, (
    HttpContext context,
    ReplicatedMailboxOptions options,
    IServiceProvider services,
    CancellationToken cancellationToken) =>
    HandleMailboxPeerAsync(
        context,
        options,
        services,
        MailboxWireHttpContract.PeerStore,
        MailboxPeerReplicationOperation.Store,
        listenerPlan.PrivacyPeerPort,
        cancellationToken));

app.MapPost(MailboxWireHttpContract.PeerTombstoneRoute, (
    HttpContext context,
    ReplicatedMailboxOptions options,
    IServiceProvider services,
    CancellationToken cancellationToken) =>
    HandleMailboxPeerAsync(
        context,
        options,
        services,
        MailboxWireHttpContract.PeerTombstone,
        MailboxPeerReplicationOperation.Tombstone,
        listenerPlan.PrivacyPeerPort,
        cancellationToken));

app.Run();

static Task<IResult> HandleMailboxAuthorityAsync(
    HttpContext context,
    MailboxAuthorityForwardingConfiguration configuration,
    MailboxAuthorityForwardingIngressLimiter limiter,
    MailboxAuthorityForwardingReplayGuard peerReplay,
    ILocalNativeMailboxExitDispatcher localDispatcher,
    RouterNodeOptions node,
    IClock clock,
    CancellationToken cancellationToken) =>
    MailboxAuthorityForwardingHttpEndpoint.HandleAsync(
        context,
        configuration,
        limiter,
        peerReplay,
        localDispatcher,
        node,
        clock,
        NodeListenerConfiguration.Create(node).PrivacyPeerPort,
        cancellationToken);

static async Task<IResult> HandleMailboxPeerAsync(
    HttpContext context,
    ReplicatedMailboxOptions options,
    IServiceProvider services,
    MailboxHttpEndpointContract contract,
    MailboxPeerReplicationOperation operation,
    int peerListenerPort,
    CancellationToken cancellationToken)
{
    if (!options.Enabled
        || context.Connection.LocalPort != peerListenerPort
        || !context.Request.IsHttps && !options.AllowInsecureHttpPeerTransport)
    {
        return Results.NotFound();
    }

    var limiter = services.GetRequiredService<MailboxPeerIngressLimiter>();
    var clock = services.GetRequiredService<IClock>();
    if (!limiter.TryEnter(
            operation,
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()),
            out var lease))
    {
        return Results.StatusCode(
            MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.RateOrConcurrencyExceeded));
    }

    using (lease)
    using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
    {
        deadline.CancelAfter(TimeSpan.FromSeconds(contract.RequestTimeoutSeconds));
        try
        {
            var preflight = MailboxPeerHttpRequestValidator.Validate(context.Request, contract);
            if (preflight is not null)
            {
                return Results.StatusCode(
                    MailboxWireHttpContract.StatusCode(preflight.Value));
            }

            var contentLength = context.Request.ContentLength!.Value;
            var body = new byte[checked((int)contentLength)];
            await context.Request.Body.ReadExactlyAsync(body, deadline.Token);
            var receiver = services.GetRequiredService<MailboxReplicaReceiver>();
            var result = await receiver.ReceiveAsync(body, operation, deadline.Token);
            if (result.Status == MailboxPeerReceiveStatus.Accepted)
            {
                return Results.Bytes(
                    result.CanonicalResponse.ToArray(),
                    contract.ResponseContentType);
            }

            var failure = result.Status switch
            {
                MailboxPeerReceiveStatus.Malformed =>
                    MailboxHttpFailure.MalformedCanonicalBody,
                MailboxPeerReceiveStatus.AuthenticationFailed =>
                    MailboxHttpFailure.AuthenticationFailed,
                MailboxPeerReceiveStatus.AuthorizationFailed =>
                    MailboxHttpFailure.AuthorizationFailed,
                MailboxPeerReceiveStatus.Conflict =>
                    MailboxHttpFailure.ReplayOrIdempotencyConflict,
                MailboxPeerReceiveStatus.RateLimited =>
                    MailboxHttpFailure.RateOrConcurrencyExceeded,
                MailboxPeerReceiveStatus.DependencyUnavailable =>
                    MailboxHttpFailure.DependencyUnavailable,
                _ => MailboxHttpFailure.AuthorizationFailed
            };
            if (result.Status == MailboxPeerReceiveStatus.Malformed)
            {
                var protocolError = "unknown";
                try
                {
                    _ = MailboxPeerWireV2Codec.Decode(body);
                }
                catch (MailboxPeerReplicationException exception)
                {
                    protocolError = exception.Error.ToString();
                }
                services.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("XNode.MailboxPeerIngress")
                    .LogWarning(
                        "Mailbox peer canonical decode rejected a bounded request: length={RequestLength}, prq2Magic={Prq2Magic}, protocolError={ProtocolError}.",
                        body.Length,
                        body.AsSpan().StartsWith("PRQ2"u8),
                        protocolError);
            }
            return result.Status == MailboxPeerReceiveStatus.Disabled
                ? Results.NotFound()
                : Results.StatusCode(MailboxWireHttpContract.StatusCode(failure));
        }
        catch (EndOfStreamException)
        {
            return Results.StatusCode(
                MailboxWireHttpContract.StatusCode(
                    MailboxHttpFailure.MalformedCanonicalBody));
        }
        catch (OperationCanceledException) when (
            deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return Results.StatusCode(
                MailboxWireHttpContract.StatusCode(MailboxHttpFailure.DeadlineExceeded));
        }
    }
}

public sealed class MailboxStoreHostedService : IHostedService
{
    private readonly ReplicatedMailboxOptions _options;
    private readonly ReplicatedMailboxStore _store;

    public MailboxStoreHostedService(
        ReplicatedMailboxOptions options,
        ReplicatedMailboxStore store)
    {
        _options = options;
        _store = store;
    }

    public Task StartAsync(CancellationToken cancellationToken) =>
        _options.Enabled ? _store.InitializeAsync(cancellationToken) : Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

public sealed class MailboxPeerStoreHostedService : IHostedService
{
    private readonly ReplicatedMailboxOptions _options;
    private readonly IServiceProvider _services;
    private readonly MailboxPeerRuntimeReadiness _readiness;

    public MailboxPeerStoreHostedService(
        ReplicatedMailboxOptions options,
        IServiceProvider services,
        MailboxPeerRuntimeReadiness readiness)
    {
        _options = options;
        _services = services;
        _readiness = readiness;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            _readiness.MarkReady("disabled");
            return;
        }

        try
        {
            // Resolve both durable journals at host startup so lease/corruption failures prevent
            // readiness instead of surfacing on the first authenticated peer request.
            _ = _services.GetRequiredService<DurableMailboxPeerReplayJournal>();
            var store = _services.GetRequiredService<MailboxPeerMutationStore>();
            await store.InitializeAsync(cancellationToken);
            _ = _services.GetRequiredService<MailboxReplicaReceiver>();
            _ = _services.GetRequiredService<MailboxReplicationCoordinator>();
            _readiness.MarkReady("ready");
        }
        catch
        {
            _readiness.MarkFailed();
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

public sealed class MailboxPeerIngressLimiter
{
    private readonly object _rateGate = new();
    private readonly EndpointAdmission _store = new(MailboxWireHttpContract.PeerStore);
    private readonly EndpointAdmission _tombstone = new(MailboxWireHttpContract.PeerTombstone);
    private readonly SemaphoreSlim _globalConcurrency = new(
        checked(
            MailboxWireHttpContract.PeerStore.MaximumConcurrentRequests
            + MailboxWireHttpContract.PeerTombstone.MaximumConcurrentRequests));
    private ulong _globalWindowStartedAt;
    private int _globalWindowCount;

    public bool TryEnter(
        MailboxPeerReplicationOperation operation,
        ulong nowUnixSeconds,
        out IDisposable lease)
    {
        var endpoint = operation == MailboxPeerReplicationOperation.Store
            ? _store
            : operation == MailboxPeerReplicationOperation.Tombstone
                ? _tombstone
                : throw new ArgumentOutOfRangeException(nameof(operation));
        lock (_rateGate)
        {
            ResetWindowIfExpired(
                ref _globalWindowStartedAt,
                ref _globalWindowCount,
                nowUnixSeconds);
            endpoint.ResetWindowIfExpired(nowUnixSeconds);
            var globalLimit = checked(
                MailboxWireHttpContract.PeerStore.RequestsPerMinute
                + MailboxWireHttpContract.PeerTombstone.RequestsPerMinute);
            if (_globalWindowCount >= globalLimit || !endpoint.HasRatePermit)
            {
                lease = EmptyLease.Instance;
                return false;
            }

            _globalWindowCount++;
            endpoint.ConsumeRatePermit();
        }

        if (!_globalConcurrency.Wait(0))
        {
            lease = EmptyLease.Instance;
            return false;
        }

        if (!endpoint.Concurrency.Wait(0))
        {
            _globalConcurrency.Release();
            lease = EmptyLease.Instance;
            return false;
        }

        lease = new Releaser(_globalConcurrency, endpoint.Concurrency);
        return true;
    }

    private static void ResetWindowIfExpired(
        ref ulong startedAt,
        ref int count,
        ulong nowUnixSeconds)
    {
        if (startedAt == 0 || nowUnixSeconds >= startedAt + 60)
        {
            startedAt = nowUnixSeconds;
            count = 0;
        }
    }

    private sealed class EndpointAdmission(MailboxHttpEndpointContract contract)
    {
        private ulong _windowStartedAt;
        private int _windowCount;

        public SemaphoreSlim Concurrency { get; } = new(
            contract.MaximumConcurrentRequests,
            contract.MaximumConcurrentRequests);

        public bool HasRatePermit => _windowCount < contract.RequestsPerMinute;

        public void ConsumeRatePermit() => _windowCount++;

        public void ResetWindowIfExpired(ulong nowUnixSeconds) =>
            MailboxPeerIngressLimiter.ResetWindowIfExpired(
                ref _windowStartedAt,
                ref _windowCount,
                nowUnixSeconds);
    }

    private sealed class Releaser(
        SemaphoreSlim globalConcurrency,
        SemaphoreSlim endpointConcurrency) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                endpointConcurrency.Release();
                globalConcurrency.Release();
            }
        }
    }

    private sealed class EmptyLease : IDisposable
    {
        public static EmptyLease Instance { get; } = new();
        public void Dispose()
        {
        }
    }
}

public sealed class MailboxPeerRuntimeReadiness
{
    private volatile bool _ready;
    private string _status = "starting";

    public bool Ready => _ready;
    public string Status => Volatile.Read(ref _status);

    public void MarkReady(string status)
    {
        Volatile.Write(ref _status, status);
        _ready = true;
    }

    public void MarkFailed()
    {
        _ready = false;
        Volatile.Write(ref _status, "failed");
    }
}

public partial class Program
{
}
