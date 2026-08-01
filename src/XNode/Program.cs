using System.Text.Json;
using System.Threading.RateLimiting;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using XNode;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using XNode.Core.NodeDb;
using XNode.Core.Onion;
using XNode.Core.Paths;
using XNode.Core.Runtime;
using XNode.Core.Session;
using XNode.Registry;
using XNode.Registry.Bootstrap;
using XNode.Registry.Heartbeat;
using XNode.Transport.Vless;

var builder = WebApplication.CreateBuilder(args);

var nodeOptions = builder.Configuration.GetSection("Node").Get<RouterNodeOptions>() ?? new RouterNodeOptions();
var pathOptions = builder.Configuration.GetSection("Paths").Get<PathSelectionOptions>() ?? new PathSelectionOptions();
var runtimeOptions = builder.Configuration.GetSection("Runtime").Get<RouterRuntimeOptions>() ?? new RouterRuntimeOptions();
var vlessOptions = builder.Configuration.GetSection("Vless").Get<VlessTransportOptions>() ?? new VlessTransportOptions();
var registryBootstrapOptions = builder.Configuration.GetSection("RegistryBootstrap").Get<RegistryRelayContactBootstrapOptions>()
    ?? new RegistryRelayContactBootstrapOptions();
var storageRpcOptions = builder.Configuration.GetSection("StorageRpc").Get<SessionStorageRpcOptions>()
    ?? new SessionStorageRpcOptions();
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
if (mailboxOptions.Enabled
    && mailboxPeerAuthorityOptions.CurrentEpochExpiresAtUnixSeconds
        <= checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
{
    throw new InvalidOperationException(
        "MailboxPeerAuthority current epoch is already retired.");
}
if (mailboxOptions.Enabled
    && MailboxWireHttpContract.PeerStore.MaximumRequestBytes
        > runtimeOptions.MaxPeerRequestBodyBytes)
{
    throw new InvalidOperationException(
        "Runtime:MaxPeerRequestBodyBytes is too small for the configured mailbox blob limit.");
}

IPublicPeerEndpointAuthorizer publicPeerEndpointAuthorizer =
    builder.Environment.IsProduction() || !runtimeOptions.AllowPublicPeerEndpoints
        ? DenyAllPublicPeerEndpointAuthorizer.Instance
        : AllowAllPublicPeerEndpointAuthorizer.Instance;
var peerEndpointPolicy = PeerEndpointPolicy.Create(
    runtimeOptions,
    nodeOptions,
    builder.Environment.EnvironmentName,
    publicPeerEndpointAuthorizer);

VlessProfileGuard.Validate(vlessOptions, builder.Environment.IsDevelopment());

vlessOptions.PublicHost = string.IsNullOrWhiteSpace(vlessOptions.PublicHost) ? nodeOptions.PublicHost : vlessOptions.PublicHost;
vlessOptions.PublicPort = vlessOptions.PublicPort == 0 ? nodeOptions.PublicPort : vlessOptions.PublicPort;
vlessOptions.ApiIngressPort = new Uri(nodeOptions.ApiListenUrl).Port;

var apiListenUri = new Uri(nodeOptions.ApiListenUrl);
var peerRpcListenUri = new Uri(nodeOptions.PeerRpcListenUrl);
if (apiListenUri.Port == peerRpcListenUri.Port)
{
    throw new InvalidOperationException("Node API and peer RPC listeners must use different ports.");
}

builder.WebHost.UseUrls(nodeOptions.ApiListenUrl, nodeOptions.PeerRpcListenUrl);

builder.Services.AddSingleton<IClock, SystemClock>();
builder.Services.AddSingleton<OnionPeerReplayGuard>();
builder.Services.AddSingleton(nodeOptions);
builder.Services.AddSingleton(pathOptions);
builder.Services.AddSingleton(runtimeOptions);
builder.Services.AddSingleton(peerEndpointPolicy);
builder.Services.AddSingleton(vlessOptions);
builder.Services.AddSingleton(registryBootstrapOptions);
builder.Services.AddSingleton(storageRpcOptions);
builder.Services.AddSingleton(heartbeatOptions);
builder.Services.AddSingleton(registrationOptions);
builder.Services.AddSingleton(membershipArtifactOptions);
builder.Services.AddSingleton(mailboxOptions);
builder.Services.AddSingleton(mailboxPeerAuthorityOptions);
builder.Services.AddSingleton(mailboxClientActivationOptions);
builder.Services.AddSingleton(mailboxClientAdapterOptions);
builder.Services.AddSingleton(productionMailboxAuthorityOptions);
builder.Services.AddSingleton(mailboxClientActivationPlan);
builder.Services.AddSingleton<MailboxClientRuntimeReadiness>();
builder.Services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
builder.Services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
builder.Services.AddSingleton<IProductionMailboxAuthorityFileSecurity,
    ProductionMailboxAuthorityFileSecurity>();
builder.Services.AddSingleton<ProductionMailboxAuthorityProvider>();
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
    builder.Services.AddSingleton<
        IProductionMailboxTopologyProvider,
        UnavailableProductionMailboxTopologyProvider>();
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
builder.Services.AddSingleton(provider => new DurableMailboxCapabilityReplayJournal(
    nodeOptions.DataDirectory));
builder.Services.AddSingleton(provider => new MailboxClientCanonicalOutcomeStore(
    nodeOptions.DataDirectory));
builder.Services.AddSingleton<MailboxAuthenticatedCapabilityRuntime>();
if (mailboxClientActivationPlan.RoutesMapped)
{
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
}
builder.Services.AddSingleton<MembershipRouteArtifactPublisher>();
builder.Services.AddSingleton(new NodeDbOptions
{
    DataDirectory = nodeOptions.DataDirectory,
    LocalRouterId = nodeOptions.RouterId,
    IsRelay = nodeOptions.IsRelay
});
builder.Services.AddSingleton<NodeDb>();
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
builder.Services.AddHostedService<MailboxAuthenticatedStateGcHostedService>();
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
builder.Services.AddSingleton<PathSelector>();
builder.Services.AddSingleton<IStorageBackend>(provider =>
    string.IsNullOrWhiteSpace(registryBootstrapOptions.BaseUrl)
        ? new NodeDbStorageBackend(provider.GetRequiredService<NodeDb>(), nodeOptions)
        : new RegistryRelayContactBootstrapBackend(
            new HttpClient(),
            registryBootstrapOptions,
            nodeOptions,
            provider.GetRequiredService<IClock>()));
builder.Services.AddSingleton<ISessionStorageRpcBackend>(_ =>
    string.IsNullOrWhiteSpace(storageRpcOptions.BaseUrl)
        ? new DisabledSessionStorageRpcBackend()
        : new HttpSessionStorageRpcBackend(new HttpClient(), storageRpcOptions));
builder.Services.AddHttpClient<IOnionPeerClient, HttpOnionPeerClient>()
    .ConfigurePrimaryHttpMessageHandler(() => OnionPeerHttpHandler.Create(peerEndpointPolicy));
builder.Services.AddHttpClient<IMailboxReplicaPeerClient, HttpMailboxReplicaPeerClient>()
    .ConfigurePrimaryHttpMessageHandler(() => OnionPeerHttpHandler.Create(peerEndpointPolicy));
builder.Services.AddSingleton(provider => new MailboxReplicationCoordinator(
    nodeOptions.GetRouterId(),
    nodeOptions.GetEd25519PrivateKey(),
    mailboxOptions,
    provider.GetRequiredService<MailboxPeerMutationStore>(),
    provider.GetRequiredService<IMailboxReplicaPeerClient>(),
    provider.GetRequiredService<IMailboxReplicaMembershipProofVerifier>(),
    provider.GetRequiredService<IMailboxPeerReplayJournal>()));
builder.Services.AddSingleton<ILocalRelayContactProvider, LocalRelayContactProvider>();
builder.Services.AddSingleton<RouterRuntime>();
builder.Services.AddSingleton<IRouterRuntime>(provider => provider.GetRequiredService<RouterRuntime>());
builder.Services.AddHostedService<RouterRuntimeHostedService>();

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
    options.AddPolicy("peer-onion", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, runtimeOptions.PublicApiPermitLimit),
            Window = runtimeOptions.PublicApiRateLimitWindow <= TimeSpan.Zero
                ? TimeSpan.FromMinutes(1)
                : runtimeOptions.PublicApiRateLimitWindow,
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.NewestFirst,
            AutoReplenishment = true
        }));
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

var app = builder.Build();

app.Use(async (context, next) =>
{
    if ((context.Request.Path.Equals(MailboxWireHttpContract.PeerStoreRoute)
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
    var allowed = path.Equals("/api/peer/onion")
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
    var clientContract = mailboxClientActivationPlan.RoutesMapped
        ? MailboxWireHttpContract.ClientEndpoints.FirstOrDefault(
            endpoint => path.Equals(endpoint.Route))
        : null;
    if (clientContract is not null)
    {
        if (context.Request.ContentLength is > 0 and var clientLength
            && clientLength > clientContract.MaximumRequestBytes)
        {
            context.Response.StatusCode = MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.PayloadTooLarge);
            return;
        }

        var clientFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (clientFeature is { IsReadOnly: false })
        {
            clientFeature.MaxRequestBodySize = clientContract.MaximumRequestBytes;
        }
    }

    if (path.Equals("/api/session/rpc")
        || path.Equals("/api/peer/onion")
        || path.Equals(MailboxWireHttpContract.PeerStoreRoute)
        || path.Equals(MailboxWireHttpContract.PeerTombstoneRoute))
    {
        var maxBodyBytes = Math.Max(1, runtimeOptions.MaxPeerRequestBodyBytes);
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
    IRouterRuntime runtime,
    IXraySupervisor xray,
    ReplicatedMailboxOptions mailbox,
    MailboxPeerRuntimeReadiness mailboxPeer,
    MailboxClientRuntimeReadiness mailboxClient,
    ProductionMailboxAuthorityProvider productionMailboxAuthority) =>
{
    var status = runtime.Status;
    var xrayStatus = xray.Status;
    var transportReady = !xrayStatus.Enabled || xrayStatus.Running || xrayStatus.Degraded;
    if (runtime is RouterRuntime concreteRuntime)
    {
        concreteRuntime.SetXrayReady(transportReady);
    }

    var mailboxPeerReady = !mailbox.Enabled || mailboxPeer.Ready;
    var mailboxClientReady =
        !mailboxClientActivationPlan.RoutesMapped || mailboxClient.Ready;
    var productionMailboxAuthorityReady =
        !productionMailboxAuthorityOptions.Enabled
        || productionMailboxAuthority.Status.Ready;
    var baseReadiness = RouterReadinessEvaluator.Evaluate(
        status,
        transportReady,
        peerEndpointPolicy.IsProductionPublicRoutingReady);
    var ready = baseReadiness.Ready
        && mailboxPeerReady
        && mailboxClientReady
        && productionMailboxAuthorityReady;
    return ready
        ? Results.Ok(new
        {
            ready = true,
            degraded = xrayStatus.Degraded,
            transportMode = xrayStatus.Mode,
            publicPeerAuthorizationMode = peerEndpointPolicy.PublicAuthorizationMode.ToString(),
            privateMembership = status.PrivateMembership,
            mailboxPeer = mailboxPeer.Status,
            mailboxClient = mailboxClient.Status,
            mailboxProductionAuthority = productionMailboxAuthority.Status
        })
        : Results.Json(
            new
            {
                ready = false,
                status,
                xray = xrayStatus,
                publicPeerRoutingReady = peerEndpointPolicy.IsProductionPublicRoutingReady,
                publicPeerAuthorizationMode = peerEndpointPolicy.PublicAuthorizationMode.ToString(),
                mailboxPeer = mailboxPeer.Status,
                mailboxClient = mailboxClient.Status,
                mailboxProductionAuthority = productionMailboxAuthority.Status
            },
            statusCode: StatusCodes.Status503ServiceUnavailable);
});

app.MapGet("/status", (
    IRouterRuntime runtime,
    IXraySupervisor xray,
    RegistryPayloadFactory registryPayloadFactory,
    ReplicatedMailboxOptions mailbox,
    MailboxPeerRuntimeReadiness mailboxPeer,
    MailboxClientRuntimeReadiness mailboxClient,
    ProductionMailboxAuthorityProvider productionMailboxAuthority,
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
        router = runtime.Status,
        xray = xray.Status,
        publicPeerAuthorizationMode = peerEndpointPolicy.PublicAuthorizationMode.ToString(),
        productionPublicRoutingReady = peerEndpointPolicy.IsProductionPublicRoutingReady,
        registryPayload = registryPayloadFactory.Create(),
        mailbox = mailboxStatus,
        onionPeerReplay = "volatile-explicit-debt",
        mailboxClient = mailboxClient.Status,
        mailboxProductionAuthority = productionMailboxAuthority.Status
    });
});

app.MapGet("/api/bootstrap/client", (ClientBootstrapService bootstrap) => Results.Ok(bootstrap.Create()));

app.MapGet("/api/network/contact", (ILocalRelayContactProvider contactProvider) =>
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
}).RequireRateLimiting("peer-onion");

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
}).RequireRateLimiting("peer-onion");

app.MapPost("/api/session/rpc", async (
    SessionRpcRequest request,
    IRouterRuntime runtime,
    CancellationToken cancellationToken) =>
{
    var response = await runtime.HandleRpcAsync(request, cancellationToken);
    return response.Success ? Results.Ok(response) : Results.BadRequest(response);
}).RequireRateLimiting("peer-onion");

app.MapPost("/api/peer/onion", async (
    SignedOnionPeerRequest request,
    NodeDb nodeDb,
    RouterNodeOptions node,
    IClock clock,
    OnionPeerReplayGuard replayGuard,
    IRouterRuntime runtime,
    CancellationToken cancellationToken) =>
{
    var now = clock.UtcNow;
    if (!RouterId.TryParse(request.SenderRouterId, out var senderId)
        || !RouterId.TryParse(request.RecipientRouterId, out var recipientId)
        || recipientId != node.GetRouterId()
        || !SignedOnionPeerRequestAuthenticator.Verify(request, now))
    {
        return Results.Unauthorized();
    }

    var senderContact = nodeDb.GetContact(senderId);
    if (!nodeDb.IsRegistered(senderId)
        || senderContact is null
        || !RelayContactSigner.VerifyFresh(senderContact, now))
    {
        return Results.Unauthorized();
    }

    if (!replayGuard.TryAccept(request.SenderRouterId, request.Nonce, request.TimestampUnixMs, now))
    {
        return Results.Conflict();
    }

    var rpc = new SessionRpcRequest(
        Guid.NewGuid().ToString("N"),
        "onion_request",
        JsonSerializer.SerializeToElement(request.Request, SessionRpc.JsonOptions));
    var response = await runtime.HandleRpcAsync(rpc, cancellationToken);
    return Results.Ok(response);
}).RequireRateLimiting("peer-onion");

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
        peerRpcListenUri.Port,
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
        peerRpcListenUri.Port,
        cancellationToken));

if (mailboxClientActivationPlan.RoutesMapped)
{
    app.MapPost(MailboxWireHttpContract.StoreRoute, (
        HttpContext context,
        IServiceProvider services,
        CancellationToken cancellationToken) =>
        HandleMailboxClientAsync(
            context,
            services,
            MailboxWireHttpContract.Store,
            apiListenUri.Port,
            cancellationToken));
    app.MapPost(MailboxWireHttpContract.RetrieveRoute, (
        HttpContext context,
        IServiceProvider services,
        CancellationToken cancellationToken) =>
        HandleMailboxClientAsync(
            context,
            services,
            MailboxWireHttpContract.Retrieve,
            apiListenUri.Port,
            cancellationToken));
    app.MapPost(MailboxWireHttpContract.AcknowledgeRoute, (
        HttpContext context,
        IServiceProvider services,
        CancellationToken cancellationToken) =>
        HandleMailboxClientAsync(
            context,
            services,
            MailboxWireHttpContract.Acknowledge,
            apiListenUri.Port,
            cancellationToken));
}

app.Run();

static async Task<IResult> HandleMailboxClientAsync(
    HttpContext context,
    IServiceProvider services,
    MailboxHttpEndpointContract contract,
    int apiListenerPort,
    CancellationToken cancellationToken)
{
    var operation = contract.AuthenticatedOperation
        ?? throw new InvalidOperationException(
            "A client mailbox route must declare its authenticated operation.");
    var readiness = services.GetRequiredService<MailboxClientRuntimeReadiness>();
    if (context.Connection.LocalPort != apiListenerPort || !readiness.Ready)
    {
        return Results.StatusCode(
            MailboxWireHttpContract.StatusCode(MailboxHttpFailure.DependencyUnavailable));
    }

    var limiter = services.GetRequiredService<MailboxClientIngressLimiter>();
    var clock = services.GetRequiredService<IClock>();
    if (!limiter.TryEnter(
            contract,
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
        MailboxAuthenticatedRuntimeReservation? authenticated = null;
        try
        {
            var preflight = MailboxPeerHttpRequestValidator.Validate(
                context.Request,
                contract);
            if (preflight is not null)
            {
                return Results.StatusCode(
                    MailboxWireHttpContract.StatusCode(preflight.Value));
            }

            var body = new byte[checked((int)context.Request.ContentLength!.Value)];
            await context.Request.Body.ReadExactlyAsync(body, deadline.Token);
            var runtime =
                services.GetRequiredService<MailboxAuthenticatedCapabilityRuntime>();
            try
            {
                authenticated = runtime.Verify(body);
            }
            catch (MailboxAuthenticatedCapabilityException exception)
            {
                return Failure(AuthenticatedFailure(exception.Error));
            }

            if (authenticated.Verified.Binding.Operation != operation)
            {
                return Failure(MailboxHttpFailure.MalformedCanonicalBody);
            }

            var holderLimiter =
                services.GetRequiredService<MailboxClientVerifiedHolderLimiter>();
            if (!holderLimiter.TryAccept(
                    authenticated.Verified.Capability.Grant.HolderPublicKey.Span,
                    operation,
                    checked((ulong)clock.UtcNow.ToUnixTimeSeconds())))
            {
                return Failure(MailboxHttpFailure.RateOrConcurrencyExceeded);
            }

            if (authenticated.RecoveredOutcome is not null)
            {
                return MapRecoveredOutcome(authenticated.RecoveredOutcome, contract);
            }

            if (!runtime.TryAcquireExecution(authenticated))
            {
                return Failure(MailboxHttpFailure.DependencyUnavailable);
            }

            runtime.ReserveOutcomeCapacity(
                authenticated,
                contract.MaximumResponseBytes);
            var adapter = services.GetRequiredService<MailboxClientStoreAdapter>();
            switch (operation)
            {
                case MailboxAuthenticatedOperation.Store:
                {
                    var envelope =
                        MailboxAuthenticatedRequestTranscript.DecodeStoreBody(
                            authenticated.Verified.Binding.CanonicalRequest.Span);
                    var result = await adapter.StoreVerifiedAsync(
                        authenticated,
                        envelope,
                        deadline.Token);
                    if (result.Status == MailboxClientStoreStatus.Durable)
                    {
                        var outcome = runtime.PersistSuccess(
                            authenticated,
                            result.DurableQuorumReceipt,
                            contract.MaximumResponseBytes);
                        return MapRecoveredOutcome(outcome, contract);
                    }

                    return CompleteStoreFailure(runtime, authenticated, result);
                }
                case MailboxAuthenticatedOperation.Retrieve:
                {
                    var retrieve =
                        MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                            authenticated.Verified.Binding.CanonicalRequest.Span);
                    var result = await adapter.RetrieveVerifiedAsync(
                        authenticated,
                        retrieve,
                        deadline.Token);
                    if (result.Status == MailboxClientRetrieveStatus.Success)
                    {
                        var outcome = runtime.PersistSuccess(
                            authenticated,
                            result.CanonicalPage,
                            contract.MaximumResponseBytes);
                        return MapRecoveredOutcome(outcome, contract);
                    }

                    return CompleteRetrieveFailure(runtime, authenticated, result);
                }
                case MailboxAuthenticatedOperation.Ack:
                {
                    var ack = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                        authenticated.Verified.Binding.CanonicalRequest.Span);
                    var result = await adapter.AcknowledgeVerifiedAsync(
                        authenticated,
                        ack,
                        deadline.Token);
                    if (result.Status == MailboxClientAckStatus.Durable)
                    {
                        var response = MailboxAggregateAckCodec.EncodeMqr3(
                            new MailboxAggregateAckResponse
                            {
                                Epoch = ack.Epoch,
                                OperationId = ack.OperationId.ToArray(),
                                TombstoneQuorums = result.Receipts
                                    .Select(static receipt =>
                                        (ReadOnlyMemory<byte>)receipt
                                            .DurableQuorumReceipt.ToArray())
                                    .ToArray()
                            });
                        var outcome = runtime.PersistSuccess(
                            authenticated,
                            response,
                            contract.MaximumResponseBytes);
                        return MapRecoveredOutcome(outcome, contract);
                    }

                    return CompleteAckFailure(runtime, authenticated, result);
                }
                default:
                    return Results.NotFound();
            }
        }
        catch (EndOfStreamException)
        {
            return Failure(MailboxHttpFailure.MalformedCanonicalBody);
        }
        catch (MailboxAuthenticatedCapabilityException)
        {
            return Failure(MailboxHttpFailure.MalformedCanonicalBody);
        }
        catch (OperationCanceledException) when (
            deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return Failure(MailboxHttpFailure.DeadlineExceeded);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or ArgumentException
                or OverflowException
                or InvalidDataException
                or UnauthorizedAccessException
                or InvalidOperationException
                or MailboxPeerReplicationException
                or MailboxClientCanonicalOutcomePersistenceException
                or MailboxClientCanonicalOutcomeCapacityException
                or MailboxClientCanonicalOutcomeConflictException
                or MailboxClientCanonicalOutcomeMissingException)
        {
            return Failure(MailboxHttpFailure.DependencyUnavailable);
        }
        finally
        {
            if (authenticated is not null)
            {
                services
                    .GetRequiredService<MailboxAuthenticatedCapabilityRuntime>()
                    .CleanupRequest(authenticated);
            }
        }
    }
}

static IResult CompleteStoreFailure(
    MailboxAuthenticatedCapabilityRuntime runtime,
    MailboxAuthenticatedRuntimeReservation authenticated,
    MailboxClientStoreResult result)
{
    switch (result.Status)
    {
        case MailboxClientStoreStatus.Unauthorized:
            runtime.PersistTerminal(
                authenticated,
                MailboxClientTerminalOutcome.AuthorizationRejected);
            return Failure(MailboxHttpFailure.AuthorizationFailed);
        case MailboxClientStoreStatus.Conflict:
            runtime.PersistTerminal(
                authenticated,
                MailboxClientTerminalOutcome.OperationConflict);
            return Failure(MailboxHttpFailure.ReplayOrIdempotencyConflict);
        case MailboxClientStoreStatus.Malformed:
        case MailboxClientStoreStatus.Rejected:
            runtime.PersistTerminal(
                authenticated,
                MailboxClientTerminalOutcome.DurableStateRejected);
            return Failure(MailboxHttpFailure.DependencyUnavailable);
        default:
            return Failure(MailboxHttpFailure.DependencyUnavailable);
    }
}

static IResult CompleteRetrieveFailure(
    MailboxAuthenticatedCapabilityRuntime runtime,
    MailboxAuthenticatedRuntimeReservation authenticated,
    MailboxClientRetrieveResult result)
{
    switch (result.Status)
    {
        case MailboxClientRetrieveStatus.Unauthorized:
            runtime.PersistTerminal(
                authenticated,
                MailboxClientTerminalOutcome.AuthorizationRejected);
            return Failure(MailboxHttpFailure.AuthorizationFailed);
        case MailboxClientRetrieveStatus.Malformed:
        case MailboxClientRetrieveStatus.Rejected:
            runtime.PersistTerminal(
                authenticated,
                MailboxClientTerminalOutcome.DurableStateRejected);
            return Failure(MailboxHttpFailure.DependencyUnavailable);
        default:
            return Failure(MailboxHttpFailure.DependencyUnavailable);
    }
}

static IResult CompleteAckFailure(
    MailboxAuthenticatedCapabilityRuntime runtime,
    MailboxAuthenticatedRuntimeReservation authenticated,
    MailboxClientAckResult result)
{
    switch (result.Status)
    {
        case MailboxClientAckStatus.Unauthorized:
            runtime.PersistTerminal(
                authenticated,
                MailboxClientTerminalOutcome.AuthorizationRejected);
            return Failure(MailboxHttpFailure.AuthorizationFailed);
        case MailboxClientAckStatus.Conflict:
            runtime.PersistTerminal(
                authenticated,
                MailboxClientTerminalOutcome.OperationConflict);
            return Failure(MailboxHttpFailure.ReplayOrIdempotencyConflict);
        case MailboxClientAckStatus.Malformed:
        case MailboxClientAckStatus.Rejected:
            runtime.PersistTerminal(
                authenticated,
                MailboxClientTerminalOutcome.DurableStateRejected);
            return Failure(MailboxHttpFailure.DependencyUnavailable);
        default:
            return Failure(MailboxHttpFailure.DependencyUnavailable);
    }
}

static IResult MapRecoveredOutcome(
    MailboxClientCanonicalOutcome outcome,
    MailboxHttpEndpointContract contract)
{
    if (outcome.Kind == MailboxClientCanonicalOutcomeKind.Success)
    {
        return Results.Bytes(
            outcome.CanonicalBytes.ToArray(),
            contract.ResponseContentType);
    }

    return Failure(outcome.Terminal switch
    {
        MailboxClientTerminalOutcome.AuthorizationRejected =>
            MailboxHttpFailure.AuthorizationFailed,
        MailboxClientTerminalOutcome.OperationConflict =>
            MailboxHttpFailure.ReplayOrIdempotencyConflict,
        MailboxClientTerminalOutcome.DurableStateRejected =>
            MailboxHttpFailure.DependencyUnavailable,
        _ => MailboxHttpFailure.DependencyUnavailable
    });
}

static MailboxHttpFailure AuthenticatedFailure(
    MailboxAuthenticatedCapabilityError error) =>
    error switch
    {
        MailboxAuthenticatedCapabilityError.InvalidIssuerSignature or
        MailboxAuthenticatedCapabilityError.InvalidHolderSignature =>
            MailboxHttpFailure.AuthenticationFailed,
        MailboxAuthenticatedCapabilityError.UntrustedIssuer or
        MailboxAuthenticatedCapabilityError.Revoked or
        MailboxAuthenticatedCapabilityError.GenerationRejected =>
            MailboxHttpFailure.AuthorizationFailed,
        MailboxAuthenticatedCapabilityError.OutsideValidityWindow =>
            MailboxHttpFailure.ExpiredOrStale,
        MailboxAuthenticatedCapabilityError.ReplayRejected or
        MailboxAuthenticatedCapabilityError.ReplayConflict =>
            MailboxHttpFailure.ReplayOrIdempotencyConflict,
        MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation =>
            MailboxHttpFailure.DependencyUnavailable,
        _ => MailboxHttpFailure.MalformedCanonicalBody
    };

static IResult Failure(MailboxHttpFailure failure) =>
    Results.StatusCode(MailboxWireHttpContract.StatusCode(failure));

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

public sealed class RouterRuntimeHostedService : IHostedService
{
    private readonly IRouterRuntime _runtime;

    public RouterRuntimeHostedService(IRouterRuntime runtime)
    {
        _runtime = runtime;
    }

    public Task StartAsync(CancellationToken cancellationToken) => _runtime.StartAsync(cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) => _runtime.StopAsync(cancellationToken);
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
