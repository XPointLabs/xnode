using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace XNode.Core.NodeDb;

public sealed class NodeDb
{
    private readonly NodeDbOptions _options;
    private readonly IClock _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _persistenceGate = new(1, 1);
    private readonly Dictionary<RouterId, RelayContact> _contacts = new();
    private readonly HashSet<RouterId> _knownRouterIds = new();
    private readonly HashSet<RouterId> _registeredRelays = new();
    private readonly ulong[] _bucketHashes = new ulong[128];
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public NodeDb(NodeDbOptions options, IClock? clock = null)
    {
        _options = options;
        _clock = clock ?? new SystemClock();
    }

    public string RootDirectory => Path.Combine(_options.DataDirectory, _options.DirectoryName);

    public IReadOnlyCollection<RelayContact> Contacts
    {
        get
        {
            _gate.Wait();
            try
            {
                return _contacts.Values.ToArray();
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(RootDirectory);
        await LoadFromDiskAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task LoadFromDiskAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(RootDirectory);
        var loaded = new List<RelayContact>();
        var purge = new List<string>();

        foreach (var file in Directory.EnumerateFiles(RootDirectory, "*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await using var stream = File.OpenRead(file);
                var contact = await JsonSerializer.DeserializeAsync<RelayContact>(stream, _jsonOptions, cancellationToken)
                    .ConfigureAwait(false);
                if (contact is null || contact.IsExpired(_clock.UtcNow))
                {
                    purge.Add(file);
                    continue;
                }

                var fileRouterId = Path.GetFileNameWithoutExtension(file);
                if (!StringComparer.OrdinalIgnoreCase.Equals(fileRouterId, contact.RouterId.Value))
                {
                    purge.Add(file);
                    continue;
                }

                loaded.Add(contact);
            }
            catch (JsonException)
            {
                purge.Add(file);
            }
            catch (IOException)
            {
                purge.Add(file);
            }
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _contacts.Clear();
            _knownRouterIds.Clear();
            Array.Clear(_bucketHashes);

            foreach (var contact in loaded)
            {
                _contacts[contact.RouterId] = contact;
                _knownRouterIds.Add(contact.RouterId);
            }

            RebuildBucketHashes();
        }
        finally
        {
            _gate.Release();
        }

        foreach (var file in purge)
        {
            File.Delete(file);
        }
    }

    public async Task<NodeDbPutResult> UpsertAsync(
        RelayContact contact,
        CancellationToken cancellationToken = default) =>
        await UpsertCoreAsync(contact, registerRelay: false, cancellationToken).ConfigureAwait(false);

    public async Task<NodeDbPutResult> UpsertAndRegisterAsync(
        RelayContact contact,
        CancellationToken cancellationToken = default) =>
        await UpsertCoreAsync(contact, registerRelay: true, cancellationToken).ConfigureAwait(false);

    private async Task<NodeDbPutResult> UpsertCoreAsync(
        RelayContact contact,
        bool registerRelay,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(RootDirectory);

        NodeDbPutResult result;
        RelayContact? toPersist = null;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (contact.IsExpired(_clock.UtcNow))
            {
                return new NodeDbPutResult(false, false, "expired");
            }

            _knownRouterIds.Add(contact.RouterId);

            if (!_contacts.TryGetValue(contact.RouterId, out var stored))
            {
                _contacts[contact.RouterId] = contact;
                UpdateBucket(contact, previous: null);
                toPersist = contact;
                result = new NodeDbPutResult(true, true, "new");
            }
            else if (!contact.NewerThan(stored, RelayContact.MinGossipAge))
            {
                result = new NodeDbPutResult(false, false, "too-recent");
            }
            else
            {
                var shouldGossip = contact.RouterId == _options.GetLocalRouterId()
                    || contact.NewerThan(stored, RelayContact.OutdatedAge)
                    || contact.AddressChanged(stored);

                _contacts[contact.RouterId] = contact;
                UpdateBucket(contact, stored);
                toPersist = contact;
                result = new NodeDbPutResult(true, shouldGossip, shouldGossip ? "significant-update" : "stored-update");
            }

            if (registerRelay)
            {
                _registeredRelays.Add(contact.RouterId);
            }
        }
        finally
        {
            _gate.Release();
        }

        if (toPersist is not null)
        {
            await PersistIfCurrentAsync(toPersist, cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    public async Task<int> PurgeExpiredAsync(CancellationToken cancellationToken = default)
    {
        List<RouterId> removed = new();

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            foreach (var (routerId, contact) in _contacts.ToArray())
            {
                if (contact.IsExpired(_clock.UtcNow))
                {
                    _contacts.Remove(routerId);
                    _knownRouterIds.Remove(routerId);
                    _registeredRelays.Remove(routerId);
                    removed.Add(routerId);
                }
            }

            if (removed.Count > 0)
            {
                RebuildBucketHashes();
                foreach (var routerId in removed)
                {
                    var file = GetContactPath(routerId);
                    if (File.Exists(file))
                    {
                        File.Delete(file);
                    }
                }
            }
        }
        finally
        {
            _gate.Release();
        }

        return removed.Count;
    }

    public void SetRegisteredRelays(IEnumerable<RouterId> relayIds)
    {
        _gate.Wait();
        try
        {
            _registeredRelays.Clear();
            foreach (var relayId in relayIds)
            {
                _registeredRelays.Add(relayId);
                _knownRouterIds.Add(relayId);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public bool IsRegistered(RouterId routerId)
    {
        _gate.Wait();
        try
        {
            return _registeredRelays.Contains(routerId);
        }
        finally
        {
            _gate.Release();
        }
    }

    public RelayContact? GetContact(RouterId routerId)
    {
        _gate.Wait();
        try
        {
            return _contacts.TryGetValue(routerId, out var contact) ? contact : null;
        }
        finally
        {
            _gate.Release();
        }
    }

    public IReadOnlyList<RouterId> GetRegisteredRelays()
    {
        _gate.Wait();
        try
        {
            return _registeredRelays.Order().ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public RegisteredRelayCatalogSnapshot GetRegisteredRelayCatalogSnapshot()
    {
        _gate.Wait();
        try
        {
            var registeredRelays = _registeredRelays.Order().ToArray();
            var contacts = registeredRelays
                .Where(_contacts.ContainsKey)
                .ToDictionary(
                    static routerId => routerId,
                    routerId => _contacts[routerId]);
            return new RegisteredRelayCatalogSnapshot(registeredRelays, contacts);
        }
        finally
        {
            _gate.Release();
        }
    }

    public IReadOnlyList<RelayContact> GetRandomContacts(
        int count,
        IReadOnlySet<RouterId>? blacklist = null,
        Func<RelayContact, bool>? predicate = null,
        Random? random = null)
    {
        random ??= Random.Shared;
        blacklist ??= new HashSet<RouterId>();

        _gate.Wait();
        try
        {
            var localId = _options.GetLocalRouterId();
            var admissible = _contacts.Values
                .Where(contact => !contact.IsExpired(_clock.UtcNow))
                .Where(contact => contact.RouterId != localId)
                .Where(contact => !blacklist.Contains(contact.RouterId))
                .Where(contact => predicate?.Invoke(contact) ?? true)
                .ToArray();

            return ReservoirSample(admissible, count, random);
        }
        finally
        {
            _gate.Release();
        }
    }

    public IReadOnlyList<RelayContact> GetRandomEdgeContacts(
        int count,
        IReadOnlySet<RouterId> strictEdges,
        IReadOnlySet<RouterId>? blacklist = null,
        Func<RelayContact, bool>? predicate = null,
        Random? random = null)
    {
        return GetRandomContacts(
            strictEdges.Count == 0 ? count : Math.Min(count, strictEdges.Count),
            blacklist,
            contact => (strictEdges.Count == 0 || strictEdges.Contains(contact.RouterId))
                && (predicate?.Invoke(contact) ?? true),
            random);
    }

    public IReadOnlyList<RouterId> FindManyClosestTo(RouterId target, int count)
    {
        if (count <= 0)
        {
            return Array.Empty<RouterId>();
        }

        _gate.Wait();
        try
        {
            var candidateIds = _registeredRelays.Count > 0
                ? _registeredRelays
                : _knownRouterIds;

            var targetMetric = XorCondense(target);
            return candidateIds
                .OrderBy(id => XorCondense(id) ^ targetMetric)
                .ThenBy(id => id)
                .Take(count)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public NodeDbSnapshot Snapshot()
    {
        _gate.Wait();
        try
        {
            return new NodeDbSnapshot(
                _contacts.Count,
                _knownRouterIds.Count,
                _registeredRelays.Count,
                _bucketHashes
                    .Select((value, index) => (value, index))
                    .Where(item => item.value != 0)
                    .ToDictionary(item => item.index, item => item.value));
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task PersistAsync(RelayContact contact, CancellationToken cancellationToken)
    {
        var tempPath = GetContactPath(contact.RouterId) + $".{Guid.NewGuid():N}.tmp";
        var finalPath = GetContactPath(contact.RouterId);

        try
        {
            await File.WriteAllTextAsync(
                tempPath,
                JsonSerializer.Serialize(contact, _jsonOptions),
                Encoding.UTF8,
                cancellationToken).ConfigureAwait(false);

            File.Move(tempPath, finalPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    private async Task PersistIfCurrentAsync(
        RelayContact contact,
        CancellationToken cancellationToken)
    {
        await _persistenceGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _gate.Wait(cancellationToken);
            try
            {
                if (!_contacts.TryGetValue(contact.RouterId, out var current)
                    || current != contact)
                {
                    return;
                }
            }
            finally
            {
                _gate.Release();
            }

            // The state gate is deliberately not held across file I/O. The
            // persistence gate preserves write order; a newer update either
            // skips this stale write or persists immediately after it.
            await PersistAsync(contact, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _persistenceGate.Release();
        }
    }

    private string GetContactPath(RouterId routerId) => Path.Combine(RootDirectory, $"{routerId.Value}.json");

    private void RebuildBucketHashes()
    {
        Array.Clear(_bucketHashes);
        foreach (var contact in _contacts.Values)
        {
            UpdateBucket(contact, previous: null);
        }
    }

    private void UpdateBucket(RelayContact current, RelayContact? previous)
    {
        var bucket = current.RouterId.ToBytes()[16] & 0x7f;
        if (previous is not null)
        {
            _bucketHashes[bucket] ^= ContactHash(previous);
        }

        _bucketHashes[bucket] ^= ContactHash(current);
    }

    private ulong ContactHash(RelayContact contact)
    {
        var payload = contact.Serialized ?? JsonSerializer.Serialize(contact, _jsonOptions);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return BinaryPrimitives.ReadUInt64BigEndian(hash);
    }

    private static ulong XorCondense(RouterId routerId)
    {
        var bytes = routerId.ToBytes();
        return BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0, 8))
            ^ BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(8, 8))
            ^ BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(16, 8))
            ^ BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(24, 8));
    }

    private static IReadOnlyList<RelayContact> ReservoirSample(
        IReadOnlyList<RelayContact> source,
        int count,
        Random random)
    {
        if (count <= 0 || source.Count == 0)
        {
            return Array.Empty<RelayContact>();
        }

        if (source.Count <= count)
        {
            return source.OrderBy(_ => random.Next()).ToArray();
        }

        var reservoir = new RelayContact[count];
        for (var i = 0; i < source.Count; i++)
        {
            if (i < count)
            {
                reservoir[i] = source[i];
                continue;
            }

            var position = random.Next(i + 1);
            if (position < count)
            {
                reservoir[position] = source[i];
            }
        }

        return reservoir.OrderBy(_ => random.Next()).ToArray();
    }
}
