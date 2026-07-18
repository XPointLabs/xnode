using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using XNode.Core.NodeDb;
using XNode.Core.Onion;
using XNode.Core.Paths;
using XNode.Core.Session;
using NodeDatabase = XNode.Core.NodeDb.NodeDb;

namespace XNode.Core.Runtime;

public sealed class RouterRuntime : IRouterRuntime
{
    private const int StorageRouteHopCount = 3;

    private readonly RouterNodeOptions _nodeOptions;
    private readonly RouterRuntimeOptions _runtimeOptions;
    private readonly NodeDatabase _nodeDb;
    private readonly IStorageBackend _storageBackend;
    private readonly ISessionStorageRpcBackend _sessionStorageRpcBackend;
    private readonly IOnionPeerClient _onionPeerClient;
    private readonly PeerEndpointPolicy _peerEndpointPolicy;
    private readonly ILocalRelayContactProvider? _localRelayContactProvider;
    private readonly PathSelector _pathSelector;
    private readonly IClock _clock;
    private readonly ILogger<RouterRuntime> _logger;
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private readonly PathSelectionOptions _pathOptions;
    private readonly ConcurrentDictionary<RouterId, int> _pathFailureScores = new();
    private CancellationTokenSource? _backgroundCts;
    private Task? _backgroundLoop;
    private OnionKeyMaterial? _onionKeys;
    private string? _identityPrivateKey;
    private DateTimeOffset _lastPathFailureDecay = DateTimeOffset.UnixEpoch;

    private long _rpcRequests;
    private long _rpcFailures;
    private long _relaySyncCycles;
    private long _relaySyncFailures;
    private long _relayContactsMerged;
    private long _relayContactsRejected;
    private long _heartbeatsSubmitted;
    private long _pathSelectionAttempts;
    private long _pathSelectionFailures;
    private long _pathRepairAttempts;
    private long _pathRepairSuccesses;
    private bool _started;
    private DateTimeOffset _startedAt;
    private bool _xrayReady;

    public RouterRuntime(
        RouterNodeOptions nodeOptions,
        RouterRuntimeOptions runtimeOptions,
        PathSelectionOptions pathOptions,
        NodeDatabase nodeDb,
        IStorageBackend storageBackend,
        ISessionStorageRpcBackend? sessionStorageRpcBackend,
        IOnionPeerClient? onionPeerClient,
        PathSelector pathSelector,
        PeerEndpointPolicy peerEndpointPolicy,
        IClock? clock = null,
        ILogger<RouterRuntime>? logger = null,
        ILocalRelayContactProvider? localRelayContactProvider = null)
    {
        _nodeOptions = nodeOptions;
        _runtimeOptions = runtimeOptions;
        _pathOptions = pathOptions;
        _nodeDb = nodeDb;
        _storageBackend = storageBackend;
        _sessionStorageRpcBackend = sessionStorageRpcBackend ?? new DisabledSessionStorageRpcBackend();
        _onionPeerClient = onionPeerClient ?? new DisabledOnionPeerClient();
        _peerEndpointPolicy = peerEndpointPolicy ?? throw new ArgumentNullException(nameof(peerEndpointPolicy));
        _localRelayContactProvider = localRelayContactProvider;
        _pathSelector = pathSelector;
        _clock = clock ?? new SystemClock();
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<RouterRuntime>.Instance;
    }

    public RouterRuntime(
        RouterNodeOptions nodeOptions,
        RouterRuntimeOptions runtimeOptions,
        PathSelectionOptions pathOptions,
        NodeDatabase nodeDb,
        IStorageBackend storageBackend,
        ISessionStorageRpcBackend? sessionStorageRpcBackend,
        PathSelector pathSelector,
        PeerEndpointPolicy peerEndpointPolicy,
        IClock? clock = null,
        ILogger<RouterRuntime>? logger = null,
        ILocalRelayContactProvider? localRelayContactProvider = null)
        : this(
            nodeOptions,
            runtimeOptions,
            pathOptions,
            nodeDb,
            storageBackend,
            sessionStorageRpcBackend,
            null,
            pathSelector,
            peerEndpointPolicy,
            clock,
            logger,
            localRelayContactProvider)
    {
    }

    public RouterRuntime(
        RouterNodeOptions nodeOptions,
        RouterRuntimeOptions runtimeOptions,
        PathSelectionOptions pathOptions,
        NodeDatabase nodeDb,
        IStorageBackend storageBackend,
        PathSelector pathSelector,
        PeerEndpointPolicy peerEndpointPolicy,
        IClock? clock = null,
        ILogger<RouterRuntime>? logger = null,
        ILocalRelayContactProvider? localRelayContactProvider = null)
        : this(
            nodeOptions,
            runtimeOptions,
            pathOptions,
            nodeDb,
            storageBackend,
            null,
            null,
            pathSelector,
            peerEndpointPolicy,
            clock,
            logger,
            localRelayContactProvider)
    {
    }

    public RouterStatusSnapshot Status => new(
        _started ? "running" : "stopped",
        _nodeOptions.RouterId,
        _nodeOptions.Network,
        _nodeOptions.IsRelay,
        _startedAt,
        _nodeDb.Snapshot(),
        ActiveSessions: 0,
        XrayReady: _xrayReady,
        Metrics: MetricsSnapshot(),
        PrivateMembership: PrivateMembershipStatus());

    public void SetXrayReady(bool ready) => _xrayReady = ready;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_started)
            {
                return;
            }

            ValidatePrivateMembershipIdentity();
            await _nodeDb.InitializeAsync(cancellationToken).ConfigureAwait(false);
            await PublishLocalRelayContactAsync(cancellationToken).ConfigureAwait(false);

            if (_runtimeOptions.BootstrapFromStorage)
            {
                await SyncRelayContactsAsync(cancellationToken).ConfigureAwait(false);
            }

            _startedAt = _clock.UtcNow;
            _lastPathFailureDecay = _startedAt;
            _started = true;
            await SubmitHeartbeatSafeAsync(cancellationToken).ConfigureAwait(false);
            _backgroundCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _backgroundLoop = Task.Run(() => RunBackgroundLoopAsync(_backgroundCts.Token), _backgroundCts.Token);
            _logger.LogInformation("Router runtime started with {RelayContacts} relay contacts.", _nodeDb.Snapshot().KnownRelayContacts);
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _started = false;
            _backgroundCts?.Cancel();
            if (_backgroundLoop is not null)
            {
                try
                {
                    await _backgroundLoop.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }
            _backgroundCts?.Dispose();
            _backgroundCts = null;
            _backgroundLoop = null;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async Task<SessionRpcResponse> HandleRpcAsync(
        SessionRpcRequest request,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _rpcRequests);

        var response = await HandleUnsignedRpcAsync(request, cancellationToken).ConfigureAwait(false);
        return SessionRpcResponseAuthenticator.Sign(
            request,
            response,
            _nodeOptions.GetRouterId(),
            GetIdentityPrivateKey(),
            _clock.UtcNow);
    }

    private async Task<SessionRpcResponse> HandleUnsignedRpcAsync(
        SessionRpcRequest request,
        CancellationToken cancellationToken)
    {

        if (!IsRequestWithinQuota(request))
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "rpc-request-too-large");
        }

        if (!_started)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "router-not-started");
        }

        switch (request.Method)
        {
            case "status":
                return SessionRpcResponse.Ok(request.Id, Status);

            case "path_ping":
                return SessionRpcResponse.Ok(request.Id, new { ok = true, at = _clock.UtcNow });

            case "fetch_rids":
                return SessionRpcResponse.Ok(request.Id, _nodeDb.GetRegisteredRelays().Select(id => id.Value).ToArray());

            case "fetch_rcs":
                return SessionRpcResponse.Ok(
                    request.Id,
                    _nodeDb.Contacts.Take(Math.Max(1, _runtimeOptions.MaxRelayContactsPerResponse)).ToArray());

            case "select_path":
                return SelectPath(request);

            case "storage_route":
                return SelectStorageRoute(request);

            case "onion_request":
                return await HandleOnionRequestAsync(request, cancellationToken).ConfigureAwait(false);

            case "storage_store":
                return await ForwardStorageRpcAsync(request, "/storage/store", cancellationToken).ConfigureAwait(false);

            case "storage_retrieve":
                return await ForwardStorageRpcAsync(request, "/storage/retrieve", cancellationToken).ConfigureAwait(false);

            case "store_rc":
                return await StoreRelayContactAsync(request, cancellationToken).ConfigureAwait(false);

            case "report_path_result":
                return ReportPathResult(request);

            default:
                Interlocked.Increment(ref _rpcFailures);
                return SessionRpcResponse.Fail(request.Id, $"unknown-method:{request.Method}");
        }
    }

    private SessionRpcResponse SelectPath(SessionRpcRequest request)
    {
        if (!request.Payload.TryGetProperty("pivot", out var pivotProperty)
            || !RouterId.TryParse(pivotProperty.GetString(), out var pivot))
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "missing-pivot");
        }

        Interlocked.Increment(ref _pathSelectionAttempts);

        var currentEdges = request.Payload.TryGetProperty("edges", out var edgesProperty)
            ? edgesProperty.EnumerateArray()
                .Select(edge => RouterId.TryParse(edge.GetString(), out var id) ? id : default)
                .Where(id => id.Value.Length > 0)
                .ToHashSet()
            : _nodeDb.Contacts.Select(contact => contact.RouterId).Take(_pathOptions.EdgeConnections).ToHashSet();

        var avoid = request.Payload.TryGetProperty("avoidRouters", out var avoidProperty)
            ? avoidProperty.EnumerateArray()
                .Select(item => RouterId.TryParse(item.GetString(), out var id) ? id : default)
                .Where(id => id.Value.Length > 0)
                .ToHashSet()
            : new HashSet<RouterId>();

        foreach (var routerId in GetChurnBlockedRouters())
        {
            avoid.Add(routerId);
        }

        var selected = _pathSelector.SelectHopsToRemote(
            pivot,
            _pathOptions,
            _nodeDb.Contacts,
            currentEdges,
            isBadForPath: avoid.Contains,
            random: new Random(0));

        var repairAttempted = false;
        if (selected is null)
        {
            repairAttempted = true;
            Interlocked.Increment(ref _pathRepairAttempts);

            var relaxedOptions = BuildRepairOptions(_pathOptions);
            selected = _pathSelector.SelectHopsToRemote(
                pivot,
                relaxedOptions,
                _nodeDb.Contacts,
                currentEdges,
                isBadForPath: avoid.Contains,
                random: new Random(1));

            if (selected is not null)
            {
                Interlocked.Increment(ref _pathRepairSuccesses);
            }
        }

        if (selected is null)
        {
            Interlocked.Increment(ref _pathSelectionFailures);
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "path-not-found");
        }

        return SessionRpcResponse.Ok(request.Id, new
        {
            hops = selected.RouterIds.Select(id => id.Value).ToArray(),
            selected.WasExtendedForEdgeOverlap,
            repairAttempted,
            churnBlockedRouters = avoid.Count
        });
    }

    private async Task<SessionRpcResponse> StoreRelayContactAsync(
        SessionRpcRequest request,
        CancellationToken cancellationToken)
    {
        RelayContact? contact;
        try
        {
            contact = request.Payload.Deserialize<RelayContact>(SessionRpc.JsonOptions);
        }
        catch (JsonException e)
        {
            return SessionRpcResponse.Fail(request.Id, $"invalid-relay-contact:{e.Message}");
        }

        if (contact is null)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "invalid-relay-contact");
        }

        if (_peerEndpointPolicy.PrivateAllowlistActsAsMembership)
        {
            if (!RelayContactSigner.VerifyFresh(contact, _clock.UtcNow))
            {
                Interlocked.Increment(ref _relayContactsRejected);
                Interlocked.Increment(ref _rpcFailures);
                return SessionRpcResponse.Fail(request.Id, "invalid-relay-contact-signature");
            }

            if (!IsExactPrivateMembershipContact(contact))
            {
                Interlocked.Increment(ref _relayContactsRejected);
                Interlocked.Increment(ref _rpcFailures);
                return SessionRpcResponse.Fail(request.Id, "relay-contact-not-in-private-membership");
            }
        }
        else if (!IsRelayContactAccepted(contact, "rpc"))
        {
            Interlocked.Increment(ref _relayContactsRejected);
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "invalid-relay-contact-signature");
        }

        var result = _peerEndpointPolicy.PrivateAllowlistActsAsMembership
            ? await _nodeDb.UpsertAndRegisterAsync(contact, cancellationToken).ConfigureAwait(false)
            : await _nodeDb.UpsertAsync(contact, cancellationToken).ConfigureAwait(false);
        if (!result.Stored)
        {
            Interlocked.Increment(ref _relayContactsRejected);
        }
        else
        {
            Interlocked.Increment(ref _relayContactsMerged);
        }

        return SessionRpcResponse.Ok(request.Id, result);
    }

    private SessionRpcResponse ReportPathResult(SessionRpcRequest request)
    {
        if (!request.Payload.TryGetProperty("success", out var successProperty))
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "missing-success-flag");
        }

        var success = successProperty.GetBoolean();
        var hopIds = request.Payload.TryGetProperty("hops", out var hopsProperty)
            ? hopsProperty.EnumerateArray()
                .Select(item => RouterId.TryParse(item.GetString(), out var id) ? id : default)
                .Where(id => id.Value.Length > 0)
                .ToArray()
            : Array.Empty<RouterId>();

        if (!success)
        {
            foreach (var hopId in hopIds)
            {
                _pathFailureScores.AddOrUpdate(hopId, 1, static (_, score) => score + 1);
            }
        }
        else
        {
            foreach (var hopId in hopIds)
            {
                _pathFailureScores.AddOrUpdate(hopId, 0, static (_, score) => score > 0 ? score - 1 : 0);
            }
        }

        return SessionRpcResponse.Ok(request.Id, new
        {
            success,
            updatedHops = hopIds.Select(id => id.Value).ToArray(),
            churnBlockedRouters = GetChurnBlockedRouters().Count
        });
    }

    private SessionRpcResponse SelectStorageRoute(SessionRpcRequest request)
    {
        var routeNonce = GetRouteNonce(request.Payload);
        if (routeNonce is null)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "invalid-route-nonce");
        }

        var route = BuildStorageRoute(routeNonce);
        if (route.Count == 0)
        {
            Interlocked.Increment(ref _pathSelectionFailures);
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "path-not-found");
        }

        Interlocked.Increment(ref _pathSelectionAttempts);
        return SessionRpcResponse.Ok(request.Id, new
        {
            routeNonce,
            route = ToRouteDocument(route)
        });
    }

    private async Task<SessionRpcResponse> ForwardStorageRpcAsync(
        SessionRpcRequest request,
        string storagePath,
        CancellationToken cancellationToken)
    {
        if (!request.Payload.TryGetProperty("body", out var body) ||
            body.ValueKind is not JsonValueKind.Object)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "missing-storage-body");
        }

        var targetKey = GetStorageTargetKey(request.Payload);
        if (string.IsNullOrWhiteSpace(targetKey))
        {
            targetKey = GetStorageTargetKey(body);
        }

        if (string.IsNullOrWhiteSpace(targetKey))
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "missing-storage-target");
        }

        var route = BuildStorageRoute(targetKey);
        if (route.Count == 0)
        {
            Interlocked.Increment(ref _pathSelectionFailures);
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "path-not-found");
        }

        Interlocked.Increment(ref _pathSelectionAttempts);

        var result = await _sessionStorageRpcBackend.PostAsync(storagePath, body.Clone(), cancellationToken)
            .ConfigureAwait(false);
        RecordPathResult(route, result.IsSuccessStatusCode);

        if (!result.IsSuccessStatusCode)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, result.Error ?? $"storage-rpc-failed:{result.StatusCode}");
        }

        return SessionRpcResponse.Ok(request.Id, new
        {
            targetKey,
            route = ToRouteDocument(route),
            storageStatusCode = result.StatusCode,
            storage = result.Body
        });
    }

    private async Task<SessionRpcResponse> HandleOnionRequestAsync(
        SessionRpcRequest request,
        CancellationToken cancellationToken)
    {
        OnionRequest? onionRequest;
        try
        {
            onionRequest = request.Payload.Deserialize<OnionRequest>(SessionRpc.JsonOptions);
        }
        catch (JsonException e)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, $"invalid-onion-request:{e.Message}");
        }

        if (onionRequest is null)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "invalid-onion-request");
        }

        OnionLayer layer;
        try
        {
            layer = OnionCrypto.DecryptForNode(onionRequest.Envelope, GetOnionKeys().PrivateKey);
        }
        catch (Exception e) when (e is FormatException or ArgumentException or InvalidOperationException)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, $"onion-decrypt-failed:{e.Message}");
        }

        if (GetJsonByteCount(layer) > _runtimeOptions.MaxOnionLayerBytes)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "onion-layer-too-large");
        }

        if (string.Equals(layer.Type, OnionCrypto.RelayLayerType, StringComparison.Ordinal))
        {
            return await ForwardOnionRelayLayerAsync(request, layer, cancellationToken).ConfigureAwait(false);
        }

        if (string.Equals(layer.Type, OnionCrypto.StorageLayerType, StringComparison.Ordinal))
        {
            return await HandleOnionStorageLayerAsync(request, layer, cancellationToken).ConfigureAwait(false);
        }

        Interlocked.Increment(ref _rpcFailures);
        return SessionRpcResponse.Fail(request.Id, "unsupported-onion-layer");
    }

    private async Task<SessionRpcResponse> ForwardOnionRelayLayerAsync(
        SessionRpcRequest request,
        OnionLayer layer,
        CancellationToken cancellationToken)
    {
        if (layer.Inner is null)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "missing-onion-inner");
        }

        if (!RouterId.TryParse(layer.NextRouterId, out var nextRouterId)
            || !_nodeDb.IsRegistered(nextRouterId))
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "unauthorized-onion-next-router");
        }

        var nextContact = _nodeDb.GetContact(nextRouterId);
        if (nextContact is null || !IsStorageRouteContact(nextContact, _clock.UtcNow))
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "unauthorized-onion-next-router");
        }

        var forwarded = await _onionPeerClient.ForwardAsync(
            nextRouterId,
            nextContact.RpcEndpoint,
            new OnionRequest(layer.Inner),
            cancellationToken).ConfigureAwait(false);

        if (!forwarded.Success)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, forwarded.Error ?? "onion-forward-failed");
        }

        return SessionRpcResponse.Ok(request.Id, forwarded.Result);
    }

    private async Task<SessionRpcResponse> HandleOnionStorageLayerAsync(
        SessionRpcRequest request,
        OnionLayer layer,
        CancellationToken cancellationToken)
    {
        if (layer.Body is not { ValueKind: JsonValueKind.Object } body)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "missing-onion-storage-body");
        }

        if (GetJsonByteCount(body) > _runtimeOptions.MaxStoragePayloadBytes)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "onion-storage-body-too-large");
        }

        var storagePath = layer.StoragePath switch
        {
            "/storage/store" => "/storage/store",
            "/storage/retrieve" => "/storage/retrieve",
            _ => null
        };
        if (storagePath is null)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "unsupported-onion-storage-path");
        }

        if (string.IsNullOrWhiteSpace(layer.ResponsePublicKey))
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "missing-onion-response-key");
        }

        byte[] responsePublicKey;
        try
        {
            responsePublicKey = Convert.FromBase64String(layer.ResponsePublicKey);
        }
        catch (FormatException)
        {
            Interlocked.Increment(ref _rpcFailures);
            return SessionRpcResponse.Fail(request.Id, "invalid-onion-response-key");
        }

        var result = await _sessionStorageRpcBackend.PostAsync(storagePath, body.Clone(), cancellationToken)
            .ConfigureAwait(false);

        var onionResponse = OnionCrypto.EncryptResponse(responsePublicKey, new
        {
            storageStatusCode = result.StatusCode,
            storage = result.Body,
            storageError = result.Error
        });

        if (!result.IsSuccessStatusCode)
        {
            Interlocked.Increment(ref _rpcFailures);
        }

        return SessionRpcResponse.Ok(request.Id, new
        {
            onionResponse
        });
    }

    private IReadOnlyList<RelayContact> BuildStorageRoute(string routingEntropy)
    {
        var now = _clock.UtcNow;
        var localRouterId = _nodeOptions.GetRouterId();
        var registered = _nodeDb.GetRegisteredRelays().ToHashSet();
        var contacts = registered
            .Select(_nodeDb.GetContact)
            .Where(static contact => contact is not null)
            .Select(static contact => contact!)
            .Where(contact => IsStorageRouteContact(contact, now))
            .GroupBy(contact => contact.RouterId)
            .ToDictionary(group => group.Key, group => group.OrderByDescending(contact => contact.SignedAt).First());

        if (contacts.Count < StorageRouteHopCount
            || !registered.Contains(localRouterId)
            || !contacts.TryGetValue(localRouterId, out var localContact))
        {
            return [];
        }

        var route = new List<RelayContact>(StorageRouteHopCount) { localContact };
        var onionKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            StorageRouteOnionKey(localContact)
        };
        var rpcEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            NormalizeRpcEndpoint(localContact.RpcEndpoint)
        };
        var blocked = GetChurnBlockedRouters();

        foreach (var contact in contacts.Values
            .Where(contact => contact.RouterId != localRouterId)
            .OrderBy(contact => blocked.Contains(contact.RouterId) ? 1 : 0)
            .ThenBy(contact => XorDistanceHex(contact.RouterId, routingEntropy), StringComparer.Ordinal)
            .ThenBy(contact => contact.RouterId))
        {
            if (!onionKeys.Add(StorageRouteOnionKey(contact))
                || !rpcEndpoints.Add(NormalizeRpcEndpoint(contact.RpcEndpoint)))
            {
                continue;
            }

            route.Add(contact);
            if (route.Count == StorageRouteHopCount)
            {
                break;
            }
        }

        return route.Count == StorageRouteHopCount ? route : [];
    }

    private void RecordPathResult(IReadOnlyList<RelayContact> route, bool success)
    {
        foreach (var contact in route)
        {
            if (success)
            {
                _pathFailureScores.AddOrUpdate(contact.RouterId, 0, static (_, score) => score > 0 ? score - 1 : 0);
            }
            else
            {
                _pathFailureScores.AddOrUpdate(contact.RouterId, 1, static (_, score) => score + 1);
            }
        }
    }

    private static object[] ToRouteDocument(IReadOnlyList<RelayContact> route)
    {
        return route
            .Select((contact, index) => new
            {
                index,
                routerId = contact.RouterId.Value,
                publicHost = contact.PublicHost,
                publicIp = contact.PublicIp,
                publicPort = contact.PublicPort,
                x25519PublicKey = contact.X25519PublicKey,
                rpcEndpoint = contact.RpcEndpoint,
                isReachable = contact.IsReachable,
                capabilities = contact.Capabilities,
                signedAt = contact.SignedAt,
                expiresAt = contact.ExpiresAt,
                routerVersion = contact.RouterVersion,
                signatureAlgorithm = contact.SignatureAlgorithm,
                signature = contact.Signature
            })
            .Cast<object>()
            .ToArray();
    }

    private OnionKeyMaterial GetOnionKeys()
    {
        return _onionKeys ??= OnionCrypto.DeriveNodeKeysFromEd25519Seed(GetIdentityPrivateKey());
    }

    private string GetIdentityPrivateKey()
    {
        return _identityPrivateKey ??= _nodeOptions.GetEd25519PrivateKey();
    }

    private bool IsStorageRouteContact(RelayContact contact, DateTimeOffset now)
    {
        if (!contact.IsReachable
            || !RelayContactSigner.VerifyFresh(contact, now)
            || string.IsNullOrWhiteSpace(contact.X25519PublicKey)
            || string.IsNullOrWhiteSpace(contact.RpcEndpoint)
            || !Uri.TryCreate(contact.RpcEndpoint, UriKind.Absolute, out var endpoint)
            || !_peerEndpointPolicy.TryValidatePeerEndpoint(contact.RouterId, endpoint, out _))
        {
            return false;
        }

        if (!contact.X25519PublicKey.Trim().All(Uri.IsHexDigit) || contact.X25519PublicKey.Trim().Length != 64)
        {
            return false;
        }

        return contact.Capabilities.Any(static value => string.Equals(value, "onion-v1", StringComparison.OrdinalIgnoreCase))
            && contact.Capabilities.Any(static value => string.Equals(value, "session-rpc", StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeRpcEndpoint(string endpoint)
    {
        return new Uri(endpoint.Trim(), UriKind.Absolute).AbsoluteUri.TrimEnd('/');
    }

    private static string StorageRouteOnionKey(RelayContact contact) =>
        contact.X25519PublicKey.Trim();

    private static bool HasUniqueStorageRouteOnionKeys(IEnumerable<RelayContact> contacts)
    {
        var onionKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return contacts.All(contact => onionKeys.Add(StorageRouteOnionKey(contact)));
    }

    private bool IsRequestWithinQuota(SessionRpcRequest request)
    {
        if (request.Id.Length > 128 || request.Method.Length > 64)
        {
            return false;
        }

        if (GetJsonByteCount(request.Payload) > _runtimeOptions.MaxRpcPayloadBytes)
        {
            return false;
        }

        if (!string.Equals(request.Method, "onion_request", StringComparison.Ordinal))
        {
            return true;
        }

        try
        {
            var onionRequest = request.Payload.Deserialize<OnionRequest>(SessionRpc.JsonOptions);
            return onionRequest?.Envelope is not null
                && onionRequest.Envelope.Ciphertext.Length <= _runtimeOptions.MaxOnionEnvelopeBytes * 2
                && GetJsonByteCount(onionRequest) <= _runtimeOptions.MaxOnionEnvelopeBytes;
        }
        catch (JsonException)
        {
            return true;
        }
    }

    private static int GetJsonByteCount<T>(T value)
    {
        return JsonSerializer.SerializeToUtf8Bytes(value, SessionRpc.JsonOptions).Length;
    }

    private static string? GetStorageTargetKey(JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (payload.TryGetProperty("targetKey", out var targetProperty) &&
            targetProperty.ValueKind == JsonValueKind.String)
        {
            return targetProperty.GetString();
        }

        if (payload.TryGetProperty("pubkey", out var pubkeyProperty) &&
            pubkeyProperty.ValueKind == JsonValueKind.String)
        {
            return pubkeyProperty.GetString();
        }

        if (payload.TryGetProperty("body", out var bodyProperty))
        {
            return GetStorageTargetKey(bodyProperty);
        }

        return null;
    }

    private static string? GetRouteNonce(JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object
            || !payload.TryGetProperty("routeNonce", out var nonceProperty)
            || nonceProperty.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        var nonce = nonceProperty.GetString()?.Trim().ToLowerInvariant();
        return nonce is { Length: 64 } && nonce.All(Uri.IsHexDigit)
            ? nonce
            : null;
    }

    private static string XorDistanceHex(RouterId routerId, string routingEntropy)
    {
        var left = routerId.ToBytes();
        var right = SHA256.HashData(Encoding.UTF8.GetBytes(routingEntropy.Trim().ToLowerInvariant()));
        Span<byte> xor = stackalloc byte[RouterId.ByteLength];
        for (var i = 0; i < RouterId.ByteLength; i++)
        {
            xor[i] = (byte)(left[i] ^ right[i]);
        }

        return Convert.ToHexString(xor).ToLowerInvariant();
    }

    private async Task RunBackgroundLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_runtimeOptions.HeartbeatInterval, cancellationToken).ConfigureAwait(false);
                await SyncRelayContactsAsync(cancellationToken).ConfigureAwait(false);
                DecayPathFailureScores();
                await SubmitHeartbeatSafeAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Runtime background loop iteration failed.");
            }
        }
    }

    private async Task SyncRelayContactsAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _relaySyncCycles);
        try
        {
            var contacts = await _storageBackend.GetBootstrapRelayContactsAsync(cancellationToken).ConfigureAwait(false);
            foreach (var contact in contacts)
            {
                if (_peerEndpointPolicy.PrivateAllowlistActsAsMembership
                    && (!RelayContactSigner.VerifyFresh(contact, _clock.UtcNow)
                        || !IsExactPrivateMembershipContact(contact)))
                {
                    Interlocked.Increment(ref _relayContactsRejected);
                    continue;
                }

                if (!_peerEndpointPolicy.PrivateAllowlistActsAsMembership
                    && !IsRelayContactAccepted(contact, "bootstrap"))
                {
                    Interlocked.Increment(ref _relayContactsRejected);
                    continue;
                }

                var result = _peerEndpointPolicy.PrivateAllowlistActsAsMembership
                    ? await _nodeDb.UpsertAndRegisterAsync(contact, cancellationToken).ConfigureAwait(false)
                    : await _nodeDb.UpsertAsync(contact, cancellationToken).ConfigureAwait(false);
                if (result.Stored)
                {
                    Interlocked.Increment(ref _relayContactsMerged);
                }
                else
                {
                    Interlocked.Increment(ref _relayContactsRejected);
                }
            }

            if (!_peerEndpointPolicy.PrivateAllowlistActsAsMembership)
            {
                _nodeDb.SetRegisteredRelays(contacts.Select(contact => contact.RouterId));
            }

            await _nodeDb.PurgeExpiredAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Interlocked.Increment(ref _relaySyncFailures);
            _logger.LogWarning(e, "Relay/contact sync cycle failed.");
        }
    }

    private async Task PublishLocalRelayContactAsync(CancellationToken cancellationToken)
    {
        if (_localRelayContactProvider is null)
        {
            if (_peerEndpointPolicy.PrivateAllowlistActsAsMembership)
            {
                throw new InvalidOperationException(
                    "Private allowlist membership requires a local signed relay contact provider.");
            }

            return;
        }

        if (_peerEndpointPolicy.PrivateAllowlistActsAsMembership)
        {
            var privateContact = _localRelayContactProvider.Create();
            if (!RelayContactSigner.VerifyFresh(privateContact, _clock.UtcNow)
                || !IsExactPrivateMembershipContact(privateContact))
            {
                throw new InvalidOperationException(
                    "The local signed relay contact does not match its exact private membership tuple.");
            }

            var privateResult = await _nodeDb
                .UpsertAndRegisterAsync(privateContact, cancellationToken)
                .ConfigureAwait(false);
            if (privateResult.Stored)
            {
                Interlocked.Increment(ref _relayContactsMerged);
            }
            else
            {
                Interlocked.Increment(ref _relayContactsRejected);
            }

            return;
        }

        try
        {
            var contact = _localRelayContactProvider.Create();
            var result = await _nodeDb.UpsertAsync(contact, cancellationToken).ConfigureAwait(false);
            if (result.Stored)
            {
                Interlocked.Increment(ref _relayContactsMerged);
            }
            else
            {
                Interlocked.Increment(ref _relayContactsRejected);
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            _logger.LogWarning(e, "Failed to publish local relay contact.");
        }
    }

    private void ValidatePrivateMembershipIdentity()
    {
        if (!_peerEndpointPolicy.PrivateAllowlistActsAsMembership)
        {
            return;
        }

        var configured = _nodeOptions.GetRouterId();
        var derived = RelayContactSigner.DeriveRouterId(GetIdentityPrivateKey());
        if (configured != derived)
        {
            throw new InvalidOperationException(
                "Node:RouterId must match the Ed25519 private key in private allowlist membership mode.");
        }
    }

    private bool IsExactPrivateMembershipContact(RelayContact contact)
    {
        return Uri.TryCreate(contact.RpcEndpoint, UriKind.Absolute, out var endpoint)
            && _peerEndpointPolicy.IsExactPrivateMembershipEndpoint(contact.RouterId, endpoint);
    }

    private PrivateAllowlistMembershipStatusSnapshot PrivateMembershipStatus()
    {
        if (!_peerEndpointPolicy.PrivateAllowlistActsAsMembership)
        {
            return new PrivateAllowlistMembershipStatusSnapshot(
                Enabled: false,
                ExpectedRelays: 0,
                RegisteredRelays: 0,
                Ready: true);
        }

        var expected = _peerEndpointPolicy.PrivateMembershipRouterIds;
        var registered = _nodeDb.GetRegisteredRelays().ToHashSet();
        var now = _clock.UtcNow;
        var contacts = expected
            .Select(_nodeDb.GetContact)
            .Where(static contact => contact is not null)
            .Select(static contact => contact!)
            .ToArray();
        var ready = registered.SetEquals(expected)
            && contacts.Length == expected.Count
            && contacts.All(contact => IsStorageRouteContact(contact, now))
            && HasUniqueStorageRouteOnionKeys(contacts);

        return new PrivateAllowlistMembershipStatusSnapshot(
            Enabled: true,
            ExpectedRelays: expected.Count,
            RegisteredRelays: registered.Count,
            Ready: ready);
    }

    private bool IsRelayContactAccepted(RelayContact contact, string source)
    {
        if (!_runtimeOptions.RequireSignedRelayContacts)
        {
            return true;
        }

        var accepted = RelayContactSigner.Verify(contact);
        if (!accepted)
        {
            _logger.LogWarning(
                "Rejected unsigned or invalid relay contact for router {RouterId} from {Source}.",
                contact.RouterId,
                source);
        }

        return accepted;
    }

    private async Task SubmitHeartbeatSafeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _storageBackend.SubmitHeartbeatAsync(Status, cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _heartbeatsSubmitted);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            _logger.LogWarning(e, "Heartbeat submission failed.");
        }
    }

    private void DecayPathFailureScores()
    {
        var now = _clock.UtcNow;
        if (now - _lastPathFailureDecay < _runtimeOptions.PathFailureDecayInterval)
        {
            return;
        }

        _lastPathFailureDecay = now;
        foreach (var routerId in _pathFailureScores.Keys)
        {
            _pathFailureScores.AddOrUpdate(routerId, 0, static (_, score) => score > 0 ? score - 1 : 0);
        }
    }

    private IReadOnlySet<RouterId> GetChurnBlockedRouters()
    {
        var blocked = new HashSet<RouterId>();
        foreach (var (routerId, score) in _pathFailureScores)
        {
            if (score >= _runtimeOptions.PathFailureThreshold)
            {
                blocked.Add(routerId);
            }
        }

        return blocked;
    }

    private RouterRuntimeMetricsSnapshot MetricsSnapshot()
    {
        return new RouterRuntimeMetricsSnapshot(
            RpcRequests: Interlocked.Read(ref _rpcRequests),
            RpcFailures: Interlocked.Read(ref _rpcFailures),
            RelaySyncCycles: Interlocked.Read(ref _relaySyncCycles),
            RelaySyncFailures: Interlocked.Read(ref _relaySyncFailures),
            RelayContactsMerged: Interlocked.Read(ref _relayContactsMerged),
            RelayContactsRejected: Interlocked.Read(ref _relayContactsRejected),
            HeartbeatsSubmitted: Interlocked.Read(ref _heartbeatsSubmitted),
            PathSelectionAttempts: Interlocked.Read(ref _pathSelectionAttempts),
            PathSelectionFailures: Interlocked.Read(ref _pathSelectionFailures),
            PathRepairAttempts: Interlocked.Read(ref _pathRepairAttempts),
            PathRepairSuccesses: Interlocked.Read(ref _pathRepairSuccesses),
            ChurnBlockedRouters: GetChurnBlockedRouters().Count);
    }

    private static PathSelectionOptions BuildRepairOptions(PathSelectionOptions options)
    {
        return new PathSelectionOptions
        {
            EdgeConnections = options.EdgeConnections,
            OutboundPaths = options.OutboundPaths,
            ClientHops = options.ClientHops,
            RelayHops = options.RelayHops,
            InboundPaths = options.InboundPaths,
            InboundHops = options.InboundHops,
            InboundPivotReuse = options.InboundPivotReuse,
            UniqueHopNetmask = 0,
            StrictEdges = options.StrictEdges,
            SnodeBlacklist = options.SnodeBlacklist,
            MinExpiry = options.MinExpiry,
            AcceptableExpiry = options.AcceptableExpiry,
            BuildTimeout = options.BuildTimeout,
            PingInterval = options.PingInterval,
            MaxMissedPings = options.MaxMissedPings
        };
    }
}
