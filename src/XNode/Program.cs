using System.Text.Json;
using System.Buffers.Binary;
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
mailboxOptions.Validate();
mailboxPeerAuthorityOptions.Validate(mailboxOptions.Enabled);
var mailboxClientActivationPlan = MailboxClientComposition.Validate(
    mailboxClientActivationOptions,
    mailboxClientAdapterOptions,
    nodeOptions,
    mailboxOptions,
    builder.Environment.IsDevelopment(),
    mailboxPeerAuthorityOptions);
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
builder.Services.AddSingleton(mailboxClientActivationPlan);
builder.Services.AddSingleton<MailboxClientRuntimeReadiness>();
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
builder.Services.AddSingleton<MailboxAuthenticatedCapabilityRuntime>();
if (mailboxClientActivationPlan.RoutesMapped)
{
    builder.Services.AddSingleton<IMailboxClientCapabilityVerifier,
        MailboxAuthenticatedCapabilityVerifier>();
    builder.Services.AddSingleton(provider => new MailboxClientOperationLedger(
        nodeOptions.DataDirectory,
        mailboxClientAdapterOptions,
        provider.GetRequiredService<IClock>()));
    builder.Services.AddSingleton(provider => new MailboxClientReceiptCrypto(
        nodeOptions.GetRouterId(),
        nodeOptions.GetEd25519PrivateKey()));
    builder.Services.AddSingleton<MailboxClientStoreAdapter>();
    builder.Services.AddSingleton<MailboxClientIngressLimiter>();
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
    .ConfigurePrimaryHttpMessageHandler(() => OnionPeerHttpHandler.Create(runtimeOptions));
builder.Services.AddHttpClient<IMailboxReplicaPeerClient, HttpMailboxReplicaPeerClient>()
    .ConfigurePrimaryHttpMessageHandler(() => OnionPeerHttpHandler.Create(runtimeOptions));
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
    MailboxClientRuntimeReadiness mailboxClient) =>
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
    var ready = status.State == "running"
        && transportReady
        && mailboxPeerReady
        && mailboxClientReady;
    return ready
        ? Results.Ok(new
        {
            ready = true,
            degraded = xrayStatus.Degraded,
            transportMode = xrayStatus.Mode,
            mailboxPeer = mailboxPeer.Status,
            mailboxClient = mailboxClient.Status
        })
        : Results.Json(
            new
            {
                ready = false,
                status,
                xray = xrayStatus,
                mailboxPeer = mailboxPeer.Status,
                mailboxClient = mailboxClient.Status
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
        registryPayload = registryPayloadFactory.Create(),
        mailbox = mailboxStatus,
        onionPeerReplay = "volatile-explicit-debt",
        mailboxClient = mailboxClient.Status
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
            MailboxClientOperation.Store,
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
            MailboxClientOperation.Retrieve,
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
            MailboxClientOperation.Acknowledge,
            apiListenUri.Port,
            cancellationToken));
}

app.Run();

static async Task<IResult> HandleMailboxClientAsync(
    HttpContext context,
    IServiceProvider services,
    MailboxHttpEndpointContract contract,
    MailboxClientOperation operation,
    int apiListenerPort,
    CancellationToken cancellationToken)
{
    var readiness = services.GetRequiredService<MailboxClientRuntimeReadiness>();
    if (context.Connection.LocalPort != apiListenerPort || !readiness.Ready)
    {
        return Results.StatusCode(
            MailboxWireHttpContract.StatusCode(MailboxHttpFailure.DependencyUnavailable));
    }

    var limiter = services.GetRequiredService<MailboxClientIngressLimiter>();
    var clock = services.GetRequiredService<IClock>();
    var partition = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    if (!limiter.TryEnter(
            partition,
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
            var adapter = services.GetRequiredService<MailboxClientStoreAdapter>();
            return operation switch
            {
                MailboxClientOperation.Store =>
                    MapStore(await adapter.StoreAsync(body, deadline.Token), contract),
                MailboxClientOperation.Retrieve =>
                    MapRetrieve(await adapter.RetrieveAsync(body, deadline.Token), contract),
                MailboxClientOperation.Acknowledge =>
                    MapAcknowledge(
                        await adapter.AcknowledgeAsync(body, deadline.Token),
                        body,
                        contract),
                _ => Results.StatusCode(StatusCodes.Status404NotFound)
            };
        }
        catch (EndOfStreamException)
        {
            return Failure(MailboxHttpFailure.MalformedCanonicalBody);
        }
        catch (OperationCanceledException) when (
            deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return Failure(MailboxHttpFailure.DeadlineExceeded);
        }
        catch (Exception exception) when (
            exception is IOException
                or InvalidDataException
                or UnauthorizedAccessException
                or InvalidOperationException)
        {
            return Failure(MailboxHttpFailure.DependencyUnavailable);
        }
    }
}

static IResult MapStore(
    MailboxClientStoreResult result,
    MailboxHttpEndpointContract contract) =>
    result.Status == MailboxClientStoreStatus.Durable
        ? Results.Bytes(
            result.DurableQuorumReceipt.ToArray(),
            contract.ResponseContentType)
        : Failure(result.Status switch
        {
            MailboxClientStoreStatus.Malformed =>
                MailboxHttpFailure.MalformedCanonicalBody,
            MailboxClientStoreStatus.Unauthorized
                when result.Error == "capability-binding-rejected" =>
                MailboxHttpFailure.AuthenticationFailed,
            MailboxClientStoreStatus.Unauthorized =>
                MailboxHttpFailure.AuthorizationFailed,
            MailboxClientStoreStatus.Conflict =>
                MailboxHttpFailure.ReplayOrIdempotencyConflict,
            MailboxClientStoreStatus.Rejected
                when result.Error.Contains("capacity", StringComparison.Ordinal) =>
                MailboxHttpFailure.RateOrConcurrencyExceeded,
            MailboxClientStoreStatus.Disabled =>
                MailboxHttpFailure.DependencyUnavailable,
            MailboxClientStoreStatus.NotReady or
            MailboxClientStoreStatus.QuorumUnavailable or
            MailboxClientStoreStatus.Rejected =>
                MailboxHttpFailure.DependencyUnavailable,
            _ => MailboxHttpFailure.AuthorizationFailed
        });

static IResult MapRetrieve(
    MailboxClientRetrieveResult result,
    MailboxHttpEndpointContract contract) =>
    result.Status == MailboxClientRetrieveStatus.Success
        ? Results.Bytes(
            result.CanonicalPage.ToArray(),
            contract.ResponseContentType)
        : Failure(result.Status switch
        {
            MailboxClientRetrieveStatus.Malformed =>
                MailboxHttpFailure.MalformedCanonicalBody,
            MailboxClientRetrieveStatus.Unauthorized
                when result.Error == "capability-binding-rejected" =>
                MailboxHttpFailure.AuthenticationFailed,
            MailboxClientRetrieveStatus.Unauthorized =>
                MailboxHttpFailure.AuthorizationFailed,
            MailboxClientRetrieveStatus.Rejected
                when result.Error.Contains("capacity", StringComparison.Ordinal) =>
                MailboxHttpFailure.RateOrConcurrencyExceeded,
            MailboxClientRetrieveStatus.Disabled or
            MailboxClientRetrieveStatus.NotReady or
            MailboxClientRetrieveStatus.Rejected =>
                MailboxHttpFailure.DependencyUnavailable,
            _ => MailboxHttpFailure.AuthorizationFailed
        });

static IResult MapAcknowledge(
    MailboxClientAckResult result,
    byte[] canonicalRequest,
    MailboxHttpEndpointContract contract)
{
    if (result.Status == MailboxClientAckStatus.Durable)
    {
        var response = MailboxAggregateAckCodec.EncodeMqr3(
            new MailboxAggregateAckResponse
            {
                Epoch = BinaryPrimitives.ReadUInt64BigEndian(
                    canonicalRequest.AsSpan(8, 8)),
                OperationId = canonicalRequest.AsMemory(16, 16).ToArray(),
                TombstoneQuorums = result.Receipts
                    .Select(static receipt =>
                        (ReadOnlyMemory<byte>)receipt.DurableQuorumReceipt.ToArray())
                    .ToArray()
            });
        return Results.Bytes(
            response,
            contract.ResponseContentType);
    }

    return Failure(result.Status switch
    {
        MailboxClientAckStatus.Malformed =>
            MailboxHttpFailure.MalformedCanonicalBody,
        MailboxClientAckStatus.Unauthorized
            when result.Error == "capability-binding-rejected" =>
            MailboxHttpFailure.AuthenticationFailed,
        MailboxClientAckStatus.Unauthorized =>
            MailboxHttpFailure.AuthorizationFailed,
        MailboxClientAckStatus.Conflict =>
            MailboxHttpFailure.ReplayOrIdempotencyConflict,
        MailboxClientAckStatus.Rejected
            when result.Error.Contains("capacity", StringComparison.Ordinal) =>
            MailboxHttpFailure.RateOrConcurrencyExceeded,
        MailboxClientAckStatus.Disabled or
        MailboxClientAckStatus.NotReady or
        MailboxClientAckStatus.QuorumUnavailable or
        MailboxClientAckStatus.Rejected =>
            MailboxHttpFailure.DependencyUnavailable,
        _ => MailboxHttpFailure.AuthorizationFailed
    });
}

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
