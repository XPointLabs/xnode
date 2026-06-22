using XNode;
using XNode.Core;
using XNode.Core.NodeDb;
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

VlessProfileGuard.Validate(vlessOptions, builder.Environment.IsDevelopment());

vlessOptions.PublicHost = string.IsNullOrWhiteSpace(vlessOptions.PublicHost) ? nodeOptions.PublicHost : vlessOptions.PublicHost;
vlessOptions.PublicPort = vlessOptions.PublicPort == 0 ? nodeOptions.PublicPort : vlessOptions.PublicPort;
vlessOptions.ApiIngressPort = new Uri(nodeOptions.ApiListenUrl).Port;

builder.WebHost.UseUrls(nodeOptions.ApiListenUrl);

builder.Services.AddSingleton<IClock, SystemClock>();
builder.Services.AddSingleton(nodeOptions);
builder.Services.AddSingleton(pathOptions);
builder.Services.AddSingleton(runtimeOptions);
builder.Services.AddSingleton(vlessOptions);
builder.Services.AddSingleton(registryBootstrapOptions);
builder.Services.AddSingleton(storageRpcOptions);
builder.Services.AddSingleton(heartbeatOptions);
builder.Services.AddSingleton(registrationOptions);
builder.Services.AddSingleton(new NodeDbOptions
{
    DataDirectory = nodeOptions.DataDirectory,
    LocalRouterId = nodeOptions.RouterId,
    IsRelay = nodeOptions.IsRelay
});
builder.Services.AddSingleton<NodeDb>();
builder.Services.AddSingleton<PathSelector>();
builder.Services.AddSingleton<IStorageBackend>(provider =>
    string.IsNullOrWhiteSpace(registryBootstrapOptions.BaseUrl)
        ? new NodeDbStorageBackend(provider.GetRequiredService<NodeDb>(), nodeOptions)
        : new RegistryRelayContactBootstrapBackend(new HttpClient(), registryBootstrapOptions));
builder.Services.AddSingleton<ISessionStorageRpcBackend>(_ =>
    string.IsNullOrWhiteSpace(storageRpcOptions.BaseUrl)
        ? new DisabledSessionStorageRpcBackend()
        : new HttpSessionStorageRpcBackend(new HttpClient(), storageRpcOptions));
builder.Services.AddHttpClient<IOnionPeerClient, HttpOnionPeerClient>();
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

var app = builder.Build();

app.MapGet("/", () => Results.Redirect("/status"));

app.MapGet("/health/live", () => Results.Ok(new { ok = true }));

app.MapGet("/health/ready", (IRouterRuntime runtime, IXraySupervisor xray) =>
{
    var status = runtime.Status;
    var xrayStatus = xray.Status;
    var transportReady = !xrayStatus.Enabled || xrayStatus.Running || xrayStatus.Degraded;
    if (runtime is RouterRuntime concreteRuntime)
    {
        concreteRuntime.SetXrayReady(transportReady);
    }

    var ready = status.State == "running" && transportReady;
    return ready
        ? Results.Ok(new { ready = true, degraded = xrayStatus.Degraded, transportMode = xrayStatus.Mode })
        : Results.Json(new { ready = false, status, xray = xrayStatus }, statusCode: StatusCodes.Status503ServiceUnavailable);
});

app.MapGet("/status", (IRouterRuntime runtime, IXraySupervisor xray, RegistryPayloadFactory registryPayloadFactory) =>
{
    return Results.Ok(new
    {
        router = runtime.Status,
        xray = xray.Status,
        registryPayload = registryPayloadFactory.Create()
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
    catch (InvalidOperationException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
    catch (ArgumentOutOfRangeException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest);
    }
});

app.MapPost("/api/session/rpc", async (
    SessionRpcRequest request,
    IRouterRuntime runtime,
    CancellationToken cancellationToken) =>
{
    var response = await runtime.HandleRpcAsync(request, cancellationToken);
    return response.Success ? Results.Ok(response) : Results.BadRequest(response);
});

app.Run();

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

public partial class Program
{
}
