using System.Threading.RateLimiting;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using XNode;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using XNode.Core.Runtime;
using XNode.Registry;
using XNode.Registry.Bootstrap;
using XNode.Registry.Heartbeat;
using XNode.Transport.Vless;

if (args.Length > 0 && args[0] == "did2-network-floor-audit")
{
    try { DeepIdV2NetworkFloorAudit.Run(args); }
    catch
    {
        // Input/custody paths and key-ring diagnostics must not enter public logs.
        Console.Error.WriteLine("Offline DID2 network-floor audit rejected; no authority or custody change was made.");
        Environment.ExitCode = 1;
    }
    return;
}

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
var currentMailboxCustodyOptions = builder.Configuration.GetSection("CurrentMailboxCustody")
    .Get<CurrentMailboxCustodyOptions>(options => options.ErrorOnUnknownConfiguration = true) ?? new();
var privacyRoutingOptions = builder.Configuration.GetSection("PrivacyRouting")
    .Get<PrivacyRoutingOptions>(options => options.ErrorOnUnknownConfiguration = true) ?? new PrivacyRoutingOptions();
var contactServiceOptions = builder.Configuration.GetSection("ContactService")
    .Get<ContactServicePersistenceOptions>(options => options.ErrorOnUnknownConfiguration = true) ?? new ContactServicePersistenceOptions();
RetiredAuthorityConfiguration.RequireAbsent(builder.Configuration);
var did2DirectoryProofOptions = builder.Configuration.GetSection("DeepIdV2DirectoryProof")
    .Get<DeepIdV2DirectoryProofOptions>() ?? new DeepIdV2DirectoryProofOptions();
var did2NetworkPlacementOptions = builder.Configuration.GetSection("DeepIdV2NetworkPlacement")
    .Get<DeepIdV2NetworkPlacementOptions>() ?? new DeepIdV2NetworkPlacementOptions();
var contactCoordinationOptions = builder.Configuration.GetSection("ContactCoordination")
    .Get<ContactCoordinationOptions>(options => options.ErrorOnUnknownConfiguration = true) ?? new();
var did2ReplicaStageOptions = builder.Configuration.GetSection("DeepIdV2ReplicaStage")
    .Get<DeepIdV2ReplicaStageOptions>() ?? new DeepIdV2ReplicaStageOptions();
var did2ContactResolverOptions = builder.Configuration.GetSection("DeepIdV2ContactResolver")
    .Get<DeepIdV2ContactResolverOptions>(options => options.ErrorOnUnknownConfiguration = true) ?? new();
var groupControlServiceOptions = builder.Configuration.GetSection("GroupControlService")
    .Get<GroupControlServiceOptions>() ?? new GroupControlServiceOptions();
var requiredTerminalServices = builder.Configuration
    .GetSection("RequiredTerminals")
    .Get<RequiredTerminalServicesOptions>()
    ?? new RequiredTerminalServicesOptions();
var developmentUatPrivatePeerAddressOptions = builder.Configuration
    .GetSection("DevelopmentUatPrivatePeerAddresses")
    .Get<DevelopmentUatPrivatePeerAddressOptions>()
    ?? new DevelopmentUatPrivatePeerAddressOptions();
var developmentUatPrivatePeerAddressPolicy =
    developmentUatPrivatePeerAddressOptions.ValidateAndLoad(
        nodeOptions,
        builder.Environment.IsDevelopment(),
        builder.Environment.IsProduction());
var privacyRouting = privacyRoutingOptions.ValidateAndLoad(
    nodeOptions,
    builder.Environment.IsDevelopment(),
    developmentUatPrivatePeerAddressPolicy);
var did2DirectoryProof = did2DirectoryProofOptions.ValidateAndLoad(
    nodeOptions,
    builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("UAT"));
var did2NetworkPlacement = did2NetworkPlacementOptions.ValidateAndLoad(
    did2DirectoryProof is not null,
    builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("UAT"));
var contactCoordinationOrigin = contactCoordinationOptions.Validate(
    privacyRouting.Enabled, did2DirectoryProof is not null && did2NetworkPlacement?.Observer is not null);
mailboxOptions.Validate();
var currentMailboxCustody = currentMailboxCustodyOptions.Validate(nodeOptions, mailboxOptions);
if (mailboxOptions.Enabled && (!privacyRouting.Enabled || did2NetworkPlacement?.Observer is null))
    throw new InvalidOperationException("Current mailbox requires configured current network/time and privacy ingress.");

VlessSecretFileLoader.Load(
    vlessOptions,
    requireProtectedFiles: !builder.Environment.IsDevelopment());
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
builder.Services.AddSingleton<IOnionMonotonicClock>(static _ =>
    new LinuxBootOnionMonotonicClock());
builder.Services.AddSingleton(nodeOptions);
builder.Services.AddSingleton(vlessOptions);
builder.Services.AddSingleton(heartbeatOptions);
builder.Services.AddSingleton(registrationOptions);
builder.Services.AddSingleton(membershipArtifactOptions);
builder.Services.AddSingleton<MembershipRouteArtifactPublisher>();
builder.Services.AddSingleton(mailboxOptions);
builder.Services.AddSingleton(privacyRoutingOptions);
builder.Services.AddSingleton(privacyRouting);
builder.Services.AddSingleton(contactServiceOptions);
builder.Services.AddSingleton(groupControlServiceOptions);
builder.Services.AddSingleton(developmentUatPrivatePeerAddressPolicy);
builder.Services.AddSingleton<PrivacyPeerReplayGuard>();
builder.Services.AddSingleton<PrivacyIngressLimiter>();
builder.Services.AddSingleton<IPrivacyPeerClient, HttpPrivacyPeerClient>();
builder.Services.AddSingleton<NativeMailboxExitDispatcher>();
builder.Services.AddSingleton<ILocalNativeMailboxExitDispatcher>(provider =>
    provider.GetRequiredService<NativeMailboxExitDispatcher>());
if (contactCoordinationOrigin is not null)
{
    builder.Services.AddSingleton(provider => new HttpContactCoordinationBackendClient(
        contactCoordinationOrigin, Convert.FromHexString(did2DirectoryProofOptions.NetworkIdHex),
        provider.GetRequiredService<RouterNodeOptions>(), provider.GetRequiredService<IClock>()));
    builder.Services.AddSingleton<ContactCoordinationOnionDispatcher>();
}
builder.Services.AddSingleton(provider => new PrivacyTerminalExitDispatcher(
    provider.GetRequiredService<NativeMailboxExitDispatcher>(),
    provider.GetRequiredService<IContactServiceOpaqueDispatcher>(),
    provider.GetRequiredService<GroupControlOnionTerminalAdapter>(),
    provider.GetService<ContactCoordinationOnionDispatcher>(),
    provider.GetRequiredService<ILogger<PrivacyTerminalExitDispatcher>>()));
builder.Services.AddSingleton<INativeMailboxExitDispatcher>(provider =>
    provider.GetRequiredService<PrivacyTerminalExitDispatcher>());
builder.Services.AddCurrentMailboxHostRecovery();
builder.Services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
builder.Services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
if (did2DirectoryProof is not null)
    builder.Services.AddDeepIdV2DirectoryProof(did2DirectoryProof);
if (did2NetworkPlacement is not null)
    builder.Services.AddDeepIdV2NetworkPlacement(did2NetworkPlacement);
var contactServicePlan = builder.Services.AddDid2ContactServiceBoundary(contactServiceOptions);
var did2ReplicaStageEnabled = did2ReplicaStageOptions.Validate(
    did2NetworkPlacement is not null,
    builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("UAT"));
if (did2ReplicaStageEnabled)
{
    builder.Services.AddSingleton<DeepIdV2PublicationFinalCommitter>();
    builder.Services.AddSingleton<DeepIdV2ReplicaStageReceiver>();
    builder.Services.AddSingleton<IContactReplicaCommandReceiver>(provider => provider.GetRequiredService<DeepIdV2ReplicaStageReceiver>());
    builder.Services.RemoveAll<IContactServiceOpaqueDispatcher>();
    builder.Services.AddSingleton<IContactServiceOpaqueDispatcher,
        DeepIdV2ContactOnionDispatcher>();
}
var did2ClaimOptions = builder.Configuration.GetSection("DeepIdV2PreKeyClaim")
    .Get<DeepIdV2PreKeyClaimOptions>() ?? new();
var did2ClaimEnabled = did2ClaimOptions.Validate(did2ReplicaStageEnabled,
    did2NetworkPlacement?.Observer is not null,
    builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("UAT"));
if (did2ClaimEnabled)
    builder.Services.AddSingleton<DeepIdV2PreKeyClaimRuntime>();
var did2ContactResolverEnabled = did2ContactResolverOptions.Validate(did2NetworkPlacement?.Observer is not null,
    privacyRouting.Enabled, did2ReplicaStageEnabled);
if (did2ContactResolverEnabled)
    builder.Services.AddDid2ContactResolver(did2ContactResolverOptions);
if (contactServiceOptions.RuntimeActivation && !did2ContactResolverEnabled)
    throw new InvalidOperationException("ContactService activation requires the complete DID2 resolver composition.");
var replicaEndpointActive = contactServicePlan.MapReplicaEndpoint ||
    did2ReplicaStageEnabled;
var groupControlServicePlan = builder.Services.AddGroupControlServiceBoundary(groupControlServiceOptions);
builder.Services.AddProductionPrivacyRoutingBoundary(
    privacyRouting,
    nodeOptions);
builder.Services.AddCurrentMailboxHost(currentMailboxCustody, nodeOptions, mailboxOptions);
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
        && !(replicaEndpointActive
            && context.Request.Path.Equals(ContactReplicaHttpContract.Route))
        && !(groupControlServicePlan.MapReplicaEndpoint
            && context.Request.Path.Equals(GroupControlReplicaHttpContract.Route))
        && !context.Request.Path.Equals(MailboxWireHttpContract.PeerStoreRoute)
        && !context.Request.Path.Equals(MailboxWireHttpContract.PeerTombstoneRoute))
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }

    if ((context.Request.Path.Equals(MailboxWireHttpContract.PeerStoreRoute)
            || context.Request.Path.Equals(MailboxWireHttpContract.PeerTombstoneRoute)
            || replicaEndpointActive
                && context.Request.Path.Equals(ContactReplicaHttpContract.Route)
            || groupControlServicePlan.MapReplicaEndpoint
                && context.Request.Path.Equals(GroupControlReplicaHttpContract.Route))
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
        || replicaEndpointActive
            && path.Equals(ContactReplicaHttpContract.Route)
        || groupControlServicePlan.MapReplicaEndpoint
            && path.Equals(GroupControlReplicaHttpContract.Route)
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
        || replicaEndpointActive
            && path.Equals(ContactReplicaHttpContract.Route)
        || groupControlServicePlan.MapReplicaEndpoint
            && path.Equals(GroupControlReplicaHttpContract.Route)
        || path.Equals(MailboxWireHttpContract.PeerStoreRoute)
        || path.Equals(MailboxWireHttpContract.PeerTombstoneRoute))
    {
        var maxBodyBytes = path.Equals(ManagedIngressH2Contract.FramePath)
            || path.Equals(PrivacyRoutingOptions.PeerFramePath)
                ? ManagedIngressLimits.MaximumOpaqueFrameBytes
                : replicaEndpointActive
                    && path.Equals(ContactReplicaHttpContract.Route)
                    ? ContactReplicaWireCodec.MaximumRequestBytes
                : groupControlServicePlan.MapReplicaEndpoint
                    && path.Equals(GroupControlReplicaHttpContract.Route)
                    ? GroupControlReplicaWireCodec.MaximumRequestBytes
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

app.MapGet("/health/ready", async (
    IXraySupervisor xray,
    ReplicatedMailboxOptions mailbox,
    CurrentMailboxHostRecovery currentMailboxHost,
    PrivacyRoutingConfiguration privacy,
    PrivacyRoutingRuntime privacyRuntime,
    CancellationToken cancellationToken) =>
{
    var currentMailboxRecovery = await currentMailboxHost.CheckAsync(cancellationToken);
    var xrayStatus = xray.Status;
    var transportReady = !xrayStatus.Enabled || xrayStatus.Running || xrayStatus.Degraded;
    var privacyReady = XNodeReadinessPolicy.IsPrivacyReady(
        privacy.Enabled, privacyRuntime.ProductionCapabilityAvailable,
        app.Environment.IsDevelopment());
    var terminalServices = XNodeReadinessPolicy.RequiredTerminals(
        requiredTerminalServices,
        contactServicePlan.RuntimeActivation,
        groupControlServicePlan.RuntimeActivation);
    var ready = transportReady
        && privacyReady
        && currentMailboxRecovery.Recovered
        && terminalServices.Ready;
    return ready
        ? Results.Ok(new
        {
            ready = true,
            degraded = xrayStatus.Degraded,
            transportMode = xrayStatus.Mode,
            privacyRouting = privacyRuntime.ProductionCapabilityAvailable
                ? "ready"
                : "disabled-development",
            currentMailboxHost = currentMailboxRecovery,
            requiredTerminals = terminalServices
        })
        : Results.Json(
            new
            {
                ready = false,
                xray = xrayStatus,
                privacyRouting = privacyRuntime.ProductionCapabilityAvailable
                    ? "ready"
                    : "unavailable",
                currentMailboxHost = currentMailboxRecovery,
                requiredTerminals = terminalServices
            },
            statusCode: StatusCodes.Status503ServiceUnavailable);
});

app.MapGet("/status", async (
    IXraySupervisor xray,
    RegistryPayloadFactory registryPayloadFactory,
    ReplicatedMailboxOptions mailbox,
    PrivacyRoutingConfiguration privacy,
    PrivacyRoutingRuntime privacyRuntime,
    CurrentMailboxHostRecovery currentMailboxHost,
    CancellationToken cancellationToken) =>
{
    var currentMailboxRecovery = await currentMailboxHost.CheckAsync(cancellationToken);
    var terminalServices = XNodeReadinessPolicy.RequiredTerminals(
        requiredTerminalServices,
        contactServicePlan.RuntimeActivation,
        groupControlServicePlan.RuntimeActivation);
    object mailboxStatus = mailbox.Enabled
        ? new
        {
            enabled = true,
            wire = "prq2-mrr2-mqr3",
            currentMailboxHost = currentMailboxRecovery
        }
        : new { enabled = false };
    return Results.Ok(new
    {
        router = new
        {
            state = privacyRuntime.ProductionCapabilityAvailable
                ? "running"
                : "privacy-routing-unavailable",
            privacyRouting = privacyRuntime.ProductionCapabilityAvailable,
            x25519PublicKey = privacy.Enabled
                ? Convert.ToHexString(privacy.PublicKey).ToLowerInvariant()
                : null
        },
        xray = xray.Status,
        registryPayload = registryPayloadFactory.Create(),
        mailbox = mailboxStatus,
        privacyReplay = privacyRuntime.ProductionCapabilityAvailable
            ? "production-capability"
            : "unavailable",
        requiredTerminals = terminalServices
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

app.MapPost("/api/staking/quorum/sign", async (
    HttpContext context,
    QuorumSignatureRequest request,
    RouterNodeOptions node,
    RegistryRegistrationOptions registration,
    Bls12381QuorumSigningService signer,
    CancellationToken cancellationToken) =>
{
    if (!QuorumCoordinatorAccess.IsAllowed(
            context.Connection.LocalPort,
            peerRpcListenUri.Port,
            context.Connection.RemoteIpAddress,
            node.QuorumCoordinatorNetworks))
    {
        return Results.NotFound();
    }

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
    PrivacyRoutingConfiguration privacy,
    PrivacyRoutingRuntime runtime) =>
    PrivacyRoutingHttpEndpoint.HandleCapabilities(
        context,
        privacy,
        runtime,
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

app.MapPost(MailboxWireHttpContract.PeerStoreRoute, (
    HttpContext context,
    ReplicatedMailboxOptions options,
    IServiceProvider services,
    CancellationToken cancellationToken) =>
    HandleCurrentMailboxPeerAsync(
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
    HandleCurrentMailboxPeerAsync(
        context,
        options,
        services,
        MailboxWireHttpContract.PeerTombstone,
        MailboxPeerReplicationOperation.Tombstone,
        listenerPlan.PrivacyPeerPort,
        cancellationToken));

app.MapContactReplicaEndpoint(contactServicePlan, listenerPlan.PrivacyPeerPort);
app.MapDeepIdV2ContactReplicaEndpoint(did2ReplicaStageEnabled,
    listenerPlan.PrivacyPeerPort);
app.MapGroupControlReplicaEndpoint(
    groupControlServicePlan,
    listenerPlan.PrivacyPeerPort);

app.Run();

static async Task<IResult> HandleCurrentMailboxPeerAsync(
    HttpContext context, ReplicatedMailboxOptions options, IServiceProvider services,
    MailboxHttpEndpointContract contract, MailboxPeerReplicationOperation operation,
    int peerListenerPort, CancellationToken cancellationToken)
{
    if (!options.Enabled || context.Connection.LocalPort != peerListenerPort || !context.Request.IsHttps)
        return Results.NotFound();
    var invalid = MailboxPeerHttpRequestValidator.Validate(context.Request, contract);
    if (invalid is not null) return Results.StatusCode(MailboxWireHttpContract.StatusCode(invalid.Value));
    try
    {
        var endpoint = services.GetService<CurrentMailboxPeerHttpEndpoint>();
        return endpoint is null ? Results.StatusCode(StatusCodes.Status503ServiceUnavailable) :
            await endpoint.HandleAsync(context, contract, operation, cancellationToken);
    }
    catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException
        or CryptographicException or InvalidOperationException or ArgumentException)
    { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
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
