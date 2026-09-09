using System.Buffers.Binary;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using XNode.Core.Mailbox;

namespace XNode.Core.ContactPreKey;

/// <summary>
/// Durable opaque inventory and exact-one-time claim state. Canonical XPS1,
/// XPK1, DPK2 and XPC1 processing remains outside this storage boundary.
/// </summary>
internal sealed partial class ContactPreKeyOpaqueStore : IDisposable
{
    private const int StateVersion = 3;
    private const int EnvelopeOverhead = 8 + sizeof(uint) + 32;
    private static readonly byte[] EnvelopeMagic = "XCPKST01"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly object gate = new();
    private readonly string path;
    private readonly ContactPreKeyStoreOptions options;
    private readonly IClock clock;
    private readonly IMailboxStorageSecurity storageSecurity;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream lifetimeLease;
    private PersistedState state;
    private bool disposed;
    private bool faulted;

    internal ContactPreKeyOpaqueStore(
        string statePath,
        ContactPreKeyStoreOptions? options = null,
        IClock? clock = null,
        IMailboxStorageSecurity? storageSecurity = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        path = Path.GetFullPath(statePath);
        this.options = options ?? new ContactPreKeyStoreOptions();
        this.options.Validate();
        this.clock = clock ?? new SystemClock();
        this.storageSecurity = storageSecurity ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();

        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("The contact pre-key state path has no parent directory.", nameof(statePath));
        this.storageSecurity.SecureDirectory(directory);
        var lockPath = path + ".lock";
        lifetimeLease = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
        this.storageSecurity.SecureFile(lockPath);
        try
        {
            state = LoadState();
        }
        catch
        {
            lifetimeLease.Dispose();
            throw;
        }
    }

    internal ContactPreKeyInventoryResult InstallVerifiedInventory(VerifiedOpaquePreKeyInventory inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        lock (gate)
        {
            ThrowIfUnavailable();
            var now = CurrentUnixSeconds();
            ValidateServiceDeadline(inventory.ServiceExpiresAtUnixSeconds, now);
            ValidateInventoryDeadlines(inventory, now);

            var capability = FindCapability(inventory.ServiceCapability);
            if (capability is null)
            {
                if (state.Capabilities.Count >= options.MaximumCapabilities
                    || TotalOpaqueBytes() + InventoryBytes(inventory) > options.MaximumOpaqueBytes)
                {
                    return new(ContactPreKeyInventoryDisposition.QuotaExceeded);
                }
                if (HasPreKeyReuse(inventory))
                {
                    return new(ContactPreKeyInventoryDisposition.Conflict);
                }
                if (inventory.InventoryEpoch != 1
                    || !ContactPreKeyOpaqueValue.IsZero32(inventory.PredecessorXpi1Hash))
                {
                    return new(ContactPreKeyInventoryDisposition.StaleGeneration);
                }
                capability = new CapabilityState
                {
                    ServiceCapability = inventory.ServiceCapability.ToArray(),
                    LastAcceptedXpi1Hash = new byte[32],
                    LastPublicationOperationId = new byte[32]
                };
                state.Capabilities.Add(capability);
            }
            else
            {
                if (capability.ForkLatched)
                {
                    return new(ContactPreKeyInventoryDisposition.ForkLatched);
                }
                var sameEpoch = capability.Inventories.FirstOrDefault(item =>
                    item.InventoryEpoch == inventory.InventoryEpoch);
                if (sameEpoch is not null)
                {
                    if (InventoryMatches(sameEpoch, inventory))
                    {
                        return new(ContactPreKeyInventoryDisposition.ExactReplay);
                    }
                    LatchAndSave(capability);
                    return new(ContactPreKeyInventoryDisposition.Conflict);
                }

                var current = capability.Inventories.LastOrDefault();
                if (current is not null)
                {
                    if (capability.Inventories.Any(item => ContactPreKeyOpaqueValue.FixedEquals(
                            item.PublicationOperationId, inventory.PublicationOperationId)))
                    {
                        LatchAndSave(capability);
                        return new(ContactPreKeyInventoryDisposition.Conflict);
                    }
                    if (current.InventoryEpoch == ulong.MaxValue
                        || inventory.InventoryEpoch != current.InventoryEpoch + 1)
                    {
                        return new(ContactPreKeyInventoryDisposition.StaleGeneration);
                    }
                    if (!ContactPreKeyOpaqueValue.FixedEquals(
                            inventory.PredecessorXpi1Hash,
                            current.Xpi1Hash))
                    {
                        LatchAndSave(capability);
                        return new(ContactPreKeyInventoryDisposition.Conflict);
                    }
                }
                else if (capability.LastAcceptedInventoryEpoch != 0)
                {
                    if (capability.LastAcceptedInventoryEpoch == ulong.MaxValue
                        || inventory.InventoryEpoch != capability.LastAcceptedInventoryEpoch + 1)
                    {
                        return new(ContactPreKeyInventoryDisposition.StaleGeneration);
                    }
                    if (ContactPreKeyOpaqueValue.FixedEquals(
                            capability.LastPublicationOperationId, inventory.PublicationOperationId)
                        || !ContactPreKeyOpaqueValue.FixedEquals(
                            capability.LastAcceptedXpi1Hash, inventory.PredecessorXpi1Hash))
                    {
                        LatchAndSave(capability);
                        return new(ContactPreKeyInventoryDisposition.Conflict);
                    }
                }
                if (HasPreKeyReuse(inventory))
                {
                    LatchAndSave(capability);
                    return new(ContactPreKeyInventoryDisposition.Conflict);
                }
                if (TotalOpaqueBytes() + InventoryBytes(inventory) > options.MaximumOpaqueBytes)
                {
                    return new(ContactPreKeyInventoryDisposition.QuotaExceeded);
                }
            }

            capability.Inventories.Add(ToState(inventory));
            capability.LastAcceptedInventoryEpoch = inventory.InventoryEpoch;
            capability.LastAcceptedXpi1Hash = inventory.Xpi1Hash.ToArray();
            capability.LastPublicationOperationId = inventory.PublicationOperationId.ToArray();
            capability.Inventories.Sort(static (left, right) =>
                left.InventoryEpoch.CompareTo(right.InventoryEpoch));
            while (capability.Inventories.Count > ContactPreKeyStoreOptions.MaximumActiveInventories)
            {
                capability.Inventories.RemoveAt(0);
            }
            CanonicalizeState();
            SaveState();
            return new(ContactPreKeyInventoryDisposition.Installed);
        }
    }

    internal ContactPreKeyClaimResult Claim(OpaquePreKeyClaimRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfUnavailable();
            var capability = FindCapability(request.ServiceCapability);
            if (capability is null)
            {
                return Empty(ContactPreKeyClaimDisposition.PreKeysUnavailable, request);
            }
            if (capability.ForkLatched)
            {
                return Empty(ContactPreKeyClaimDisposition.ForkLatched, request);
            }

            var prior = capability.Claims.FirstOrDefault(item =>
                ContactPreKeyOpaqueValue.FixedEquals(item.OperationId, request.OperationId));
            if (prior is not null)
            {
                return ContactPreKeyOpaqueValue.FixedEquals(prior.RequestHash, request.RequestHash)
                    ? ToResult(ContactPreKeyClaimDisposition.ExactReplay, prior)
                    : Empty(ContactPreKeyClaimDisposition.Conflict, request);
            }

            var now = CurrentUnixSeconds();
            if (request.RequestExpiresAtUnixSeconds <= now)
            {
                return Empty(ContactPreKeyClaimDisposition.Expired, request);
            }

            var inventory = capability.Inventories.LastOrDefault(item =>
                ContactPreKeyOpaqueValue.FixedEquals(item.ExactXps1Hash, request.ExactXps1Hash));
            if (inventory is null)
            {
                var current = capability.Inventories.LastOrDefault();
                if (current is null)
                {
                    return Empty(ContactPreKeyClaimDisposition.PreKeysUnavailable, request);
                }
                return new(
                    ContactPreKeyClaimDisposition.StaleBundle,
                    request.RequestHash,
                    requiredDcb1Hash: request.ExactDcb1Hash,
                    requiredXps1Hash: current?.ExactXps1Hash ?? [],
                    requiredXpi1Hash: current?.Xpi1Hash ?? []);
            }
            if (!ContactPreKeyOpaqueValue.FixedEquals(inventory.NetworkId, request.NetworkId)
                || !ContactPreKeyOpaqueValue.FixedEquals(
                    inventory.ResponderDeviceId,
                    request.ResponderDeviceId)
                || inventory.SupportedSuite != request.RequestedSuite)
            {
                return Empty(ContactPreKeyClaimDisposition.Conflict, request);
            }
            if (inventory.ServiceExpiresAtUnixSeconds <= now)
            {
                return Empty(ContactPreKeyClaimDisposition.Expired, request);
            }

            var selected = inventory.OneTimeOfferings.FirstOrDefault(item =>
                item.PreKeyExpiresAtUnixSeconds > now
                && !IsOneTimePreKeyClaimed(item.PreKeyId));
            ushort lastResortCounter = 0;
            if (selected is null)
            {
                var lastResort = inventory.LastResortOffering;
                var used = capability.Claims.Count(item =>
                    item.ServiceGeneration == inventory.ServiceGeneration
                    && item.InventoryEpoch == inventory.InventoryEpoch
                    && ContactPreKeyOpaqueValue.IsZero32(item.PreKeyId));
                if (lastResort.PreKeyExpiresAtUnixSeconds <= now
                    || used >= lastResort.LastResortReuseLimit)
                {
                    return Empty(ContactPreKeyClaimDisposition.PreKeysUnavailable, request);
                }
                selected = lastResort;
                lastResortCounter = checked((ushort)(used + 1));
            }

            if (capability.Claims.Count >= options.MaximumClaimsPerCapability
                || TotalOpaqueBytes() + selected.ExactDpk2.Length > options.MaximumOpaqueBytes)
            {
                return Empty(ContactPreKeyClaimDisposition.QuotaExceeded, request);
            }
            if (!ContactPreKeyOpaqueValue.IsZero32(selected.PreKeyId)
                && FindClaimByPreKeyId(selected.PreKeyId) is not null)
            {
                LatchAndSave(capability);
                return Empty(ContactPreKeyClaimDisposition.Conflict, request);
            }
            if (capability.CommitGeneration == ulong.MaxValue)
            {
                LatchAndSave(capability);
                return Empty(ContactPreKeyClaimDisposition.Conflict, request);
            }

            capability.CommitGeneration++;
            var replayUntil = AddSecondsBounded(
                now,
                checked((ulong)ContactPreKeyStoreOptions.ClaimReplayRetention.TotalSeconds));
            var claim = new ClaimState
            {
                OperationId = request.OperationId.ToArray(),
                RequestHash = request.RequestHash.ToArray(),
                ServiceGeneration = inventory.ServiceGeneration,
                ExactDpk2 = selected.ExactDpk2.ToArray(),
                PreKeyId = selected.PreKeyId.ToArray(),
                ExactDpk2Hash = selected.ExactDpk2Hash.ToArray(),
                ExactCurrentDmd1Hash = inventory.ExactCurrentDmd1Hash.ToArray(),
                ExactCurrentDrs1Ref = inventory.ExactCurrentDrs1Ref.ToArray(),
                ExactXpi1 = inventory.ExactXpi1.ToArray(),
                Xpi1Hash = inventory.Xpi1Hash.ToArray(),
                InventoryEpoch = inventory.InventoryEpoch,
                InventoryIndex = selected.InventoryIndex,
                InclusionProof = selected.InclusionProof.ToArray(),
                ReplicaNodeIds = inventory.ReplicaNodeIds.Select(static value => value.ToArray()).ToList(),
                PreKeyExpiresAtUnixSeconds = selected.PreKeyExpiresAtUnixSeconds,
                LastResortUseCounter = lastResortCounter,
                ClaimCommitGeneration = capability.CommitGeneration,
                ClaimedAtUnixSeconds = now,
                RetainUntilUnixSeconds = Math.Max(selected.PreKeyExpiresAtUnixSeconds, replayUntil)
            };
            capability.Claims.Add(claim);
            CanonicalizeState();
            SaveState();
            return ToResult(ContactPreKeyClaimDisposition.Claimed, claim);
        }
    }

    internal void LatchFork(ReadOnlySpan<byte> serviceCapability32)
    {
        var serviceCapability = ContactPreKeyOpaqueValue.CopyNonZero32(
            serviceCapability32,
            nameof(serviceCapability32));
        lock (gate)
        {
            ThrowIfUnavailable();
            var capability = FindCapability(serviceCapability);
            if (capability is null || capability.ForkLatched)
            {
                return;
            }
            LatchAndSave(capability);
        }
    }

    internal int CollectGarbage()
    {
        lock (gate)
        {
            ThrowIfUnavailable();
            var now = CurrentUnixSeconds();
            var removed = 0;
            foreach (var capability in state.Capabilities)
            {
                removed += capability.Claims.RemoveAll(item => item.RetainUntilUnixSeconds <= now);
                removed += capability.Inventories.RemoveAll(item => item.ServiceExpiresAtUnixSeconds <= now);
            }
            removed += state.Capabilities.RemoveAll(item =>
                !item.ForkLatched
                && item.CommitGeneration == 0
                && item.LastAcceptedInventoryEpoch == 0
                && item.Claims.Count == 0
                && item.Inventories.Count == 0);
            if (removed != 0)
            {
                SaveState();
            }
            return removed;
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            lifetimeLease.Dispose();
        }
    }

    private PersistedState LoadState()
    {
        if (!File.Exists(path))
        {
            return new PersistedState();
        }
        try
        {
            var info = new FileInfo(path);
            if (info.Length < EnvelopeOverhead || info.Length > options.MaximumPersistedBytes)
            {
                throw new InvalidDataException("Contact pre-key state envelope length is invalid.");
            }
            var bytes = File.ReadAllBytes(path);
            if (!bytes.AsSpan(0, EnvelopeMagic.Length).SequenceEqual(EnvelopeMagic))
            {
                throw new InvalidDataException("Contact pre-key state envelope magic is invalid.");
            }
            var payloadLength = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(EnvelopeMagic.Length, sizeof(uint)));
            if (payloadLength > int.MaxValue
                || checked(EnvelopeOverhead + (int)payloadLength) != bytes.Length)
            {
                throw new InvalidDataException("Contact pre-key state payload length is invalid.");
            }
            var payload = bytes.AsSpan(EnvelopeMagic.Length + sizeof(uint), (int)payloadLength);
            var digest = bytes.AsSpan(EnvelopeMagic.Length + sizeof(uint) + (int)payloadLength, 32);
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), digest))
            {
                throw new InvalidDataException("Contact pre-key state digest is invalid.");
            }
            var loaded = JsonSerializer.Deserialize<PersistedState>(payload, JsonOptions)
                ?? throw new InvalidDataException("Contact pre-key state payload is empty.");
            ValidateState(loaded);
            return loaded;
        }
        catch (Exception exception) when (exception is InvalidDataException
            or JsonException
            or OverflowException
            or ArgumentException)
        {
            throw QuarantineAndCreateException(exception);
        }
    }

    private void SaveState()
    {
        try
        {
            ValidateState(state);
            var payload = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
            if ((long)payload.Length + EnvelopeOverhead > options.MaximumPersistedBytes)
            {
                throw new InvalidOperationException("The contact pre-key state exceeds its configured durable bound.");
            }
            var envelope = new byte[checked(payload.Length + EnvelopeOverhead)];
            EnvelopeMagic.CopyTo(envelope, 0);
            BinaryPrimitives.WriteUInt32BigEndian(
                envelope.AsSpan(EnvelopeMagic.Length, sizeof(uint)),
                checked((uint)payload.Length));
            payload.CopyTo(envelope.AsSpan(EnvelopeMagic.Length + sizeof(uint)));
            SHA256.HashData(payload).CopyTo(envelope, EnvelopeMagic.Length + sizeof(uint) + payload.Length);
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(
                           temporary,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           64 * 1024,
                           FileOptions.WriteThrough))
                {
                    stream.Write(envelope);
                    stream.Flush(flushToDisk: true);
                }
                storageSecurity.SecureFile(temporary);
                durability.FlushFileAndParentDirectory(temporary);
                ReplaceFileWithBoundedRetry(temporary);
                durability.FlushFileAndParentDirectory(path);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(envelope);
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
        }
        catch
        {
            faulted = true;
            throw;
        }
    }

    private void ReplaceFileWithBoundedRetry(string temporary)
    {
        const int maximumAttempts = 8;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                durability.ReplaceFile(temporary, path);
                return;
            }
            catch (Win32Exception exception) when (
                OperatingSystem.IsWindows()
                && attempt < maximumAttempts
                && exception.NativeErrorCode is 5 or 32)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(1 << (attempt - 1)));
            }
        }
    }

    private ContactPreKeyStoreCorruptException QuarantineAndCreateException(Exception exception)
    {
        try
        {
            if (File.Exists(path))
            {
                var quarantine = path + ".quarantine." + Guid.NewGuid().ToString("N");
                durability.ReplaceFile(path, quarantine);
                durability.FlushFileAndParentDirectory(quarantine);
            }
        }
        catch (Exception quarantineFailure)
        {
            return new ContactPreKeyStoreCorruptException(new AggregateException(exception, quarantineFailure));
        }
        return new ContactPreKeyStoreCorruptException(exception);
    }

    private void ValidateState(PersistedState candidate)
    {
        if (candidate.Version != StateVersion
            || candidate.Capabilities is null
            || candidate.Publications is null
            || candidate.Capabilities.Count > options.MaximumCapabilities)
        {
            throw new InvalidDataException("Contact pre-key state version or capability bounds are invalid.");
        }

        var priorCapability = Array.Empty<byte>();
        var globalOperations = new HashSet<string>(StringComparer.Ordinal);
        var publicationOperations = new HashSet<string>(StringComparer.Ordinal);
        var claimedOneTimeIds = new HashSet<string>(StringComparer.Ordinal);
        long opaqueBytes = 0;
        foreach (var capability in candidate.Capabilities)
        {
            ValidateNonZero(capability.ServiceCapability, 32);
            if (priorCapability.Length != 0
                && priorCapability.AsSpan().SequenceCompareTo(capability.ServiceCapability) >= 0)
            {
                throw new InvalidDataException("Contact pre-key capability order is not canonical.");
            }
            priorCapability = capability.ServiceCapability;
            if (capability.Inventories is null
                || capability.Claims is null
                || capability.Inventories.Count > ContactPreKeyStoreOptions.MaximumActiveInventories
                || capability.Claims.Count > options.MaximumClaimsPerCapability)
            {
                throw new InvalidDataException("Contact pre-key per-capability bounds are invalid.");
            }
            ValidateExact(capability.LastAcceptedXpi1Hash, 32);
            ValidateExact(capability.LastPublicationOperationId, 32);
            if ((capability.LastAcceptedInventoryEpoch == 0)
                != ContactPreKeyOpaqueValue.IsZero32(capability.LastAcceptedXpi1Hash)
                || (capability.LastAcceptedInventoryEpoch == 0)
                != ContactPreKeyOpaqueValue.IsZero32(capability.LastPublicationOperationId))
            {
                throw new InvalidDataException("Contact pre-key XPI1 lineage tombstone is invalid.");
            }

            InventoryState? priorInventory = null;
            var activeInventoryIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var inventory in capability.Inventories)
            {
                ValidateInventoryState(inventory);
                if (!ContactPreKeyOpaqueValue.FixedEquals(
                        inventory.ServiceCapability, capability.ServiceCapability)
                    || !publicationOperations.Add(Convert.ToHexString(inventory.PublicationOperationId))
                    || (priorInventory is not null
                        && (inventory.InventoryEpoch != priorInventory.InventoryEpoch + 1
                            || !ContactPreKeyOpaqueValue.FixedEquals(
                                inventory.PredecessorXpi1Hash, priorInventory.Xpi1Hash))))
                {
                    throw new InvalidDataException("Contact pre-key XPI1 lineage or publication operation is invalid.");
                }
                priorInventory = inventory;
                foreach (var offering in inventory.OneTimeOfferings)
                {
                    if (!activeInventoryIds.Add(Convert.ToHexString(offering.PreKeyId)))
                    {
                        throw new InvalidDataException("A one-time pre-key appears in overlapping inventories.");
                    }
                    opaqueBytes = checked(opaqueBytes + offering.ExactDpk2.Length + offering.InclusionProof.Length);
                }
                opaqueBytes = checked(opaqueBytes + inventory.LastResortOffering.ExactDpk2.Length
                    + inventory.ExactXpi1.Length);
            }
            if (priorInventory is not null
                && (capability.LastAcceptedInventoryEpoch != priorInventory.InventoryEpoch
                    || !ContactPreKeyOpaqueValue.FixedEquals(
                        capability.LastAcceptedXpi1Hash, priorInventory.Xpi1Hash)
                    || !ContactPreKeyOpaqueValue.FixedEquals(
                        capability.LastPublicationOperationId, priorInventory.PublicationOperationId)))
            {
                throw new InvalidDataException("Contact pre-key XPI1 lineage tombstone is not current.");
            }

            ulong priorCommit = 0;
            foreach (var claim in capability.Claims)
            {
                ValidateClaimState(claim);
                if (claim.ClaimCommitGeneration <= priorCommit
                    || claim.ClaimCommitGeneration > capability.CommitGeneration
                    || !globalOperations.Add(Convert.ToHexString(claim.OperationId)))
                {
                    throw new InvalidDataException("Contact pre-key claim sequence or operation ID is invalid.");
                }
                if (!ContactPreKeyOpaqueValue.IsZero32(claim.PreKeyId)
                    && !claimedOneTimeIds.Add(Convert.ToHexString(claim.PreKeyId)))
                {
                    throw new InvalidDataException("A one-time pre-key has multiple durable claims.");
                }
                opaqueBytes = checked(opaqueBytes + claim.ExactDpk2.Length
                    + claim.ExactXpi1.Length + claim.InclusionProof.Length);
                priorCommit = claim.ClaimCommitGeneration;
            }
            // CommitGeneration intentionally remains as a monotonic tombstone
            // after replay records are collected.
        }
        if (opaqueBytes > options.MaximumOpaqueBytes)
        {
            throw new InvalidDataException("Contact pre-key opaque byte quota is exceeded.");
        }
        ValidatePublicationState(candidate, ref opaqueBytes);
        if (opaqueBytes > options.MaximumOpaqueBytes)
        {
            throw new InvalidDataException("Contact pre-key opaque byte quota is exceeded.");
        }
    }

    private static void ValidateInventoryState(InventoryState inventory)
    {
        ValidateNonZero(inventory.ExactXps1Hash, 32);
        ValidateNonZero(inventory.PublicationOperationId, 32);
        ValidateNonZero(inventory.Xpi1Hash, 32);
        ValidateExact(inventory.PredecessorXpi1Hash, 32);
        ValidateNonZero(inventory.NetworkId, 16);
        ValidateNonZero(inventory.ResponderDeviceId, 32);
        ValidateNonZero(inventory.ExactCurrentDmd1Hash, 32);
        ValidateNonZero(inventory.ExactCurrentDrs1Ref, 38);
        if (inventory.SupportedSuite != ContactPreKeyStoreOptions.SupportedSuite
            || inventory.ServiceGeneration == 0
            || inventory.InventoryEpoch is < 1 or > 14
            || inventory.InventoryIssuedAtUnixSeconds == 0
            || inventory.ServiceExpiresAtUnixSeconds == 0
            || inventory.InventoryIssuedAtUnixSeconds >= inventory.ServiceExpiresAtUnixSeconds
            || inventory.ExactXpi1 is not { Length: Xpi1Codec.TotalBytes }
            || inventory.ReplicaNodeIds is not { Count: 2 }
            || inventory.OneTimeOfferings is null
            || inventory.OneTimeOfferings.Count is < ContactPreKeyStoreOptions.MinimumOneTimeOfferings
                or > ContactPreKeyStoreOptions.MaximumOneTimeOfferings
            || inventory.LastResortOffering is null)
        {
            throw new InvalidDataException("Contact pre-key inventory size is invalid.");
        }
        var manifest = Xpi1Codec.Decode(inventory.ExactXpi1);
        var computedXpi1Hash = Xpi1Codec.ComputeHash(inventory.ExactXpi1);
        try
        {
            if (!ContactPreKeyOpaqueValue.FixedEquals(computedXpi1Hash, inventory.Xpi1Hash)
                || !ContactPreKeyOpaqueValue.FixedEquals(manifest.NetworkId.Span, inventory.NetworkId)
                || !ContactPreKeyOpaqueValue.FixedEquals(manifest.ServiceCapability.Span, inventory.ServiceCapability)
                || !ContactPreKeyOpaqueValue.FixedEquals(manifest.ResponderDeviceId.Span, inventory.ResponderDeviceId)
                || manifest.ServiceGeneration != inventory.ServiceGeneration
                || manifest.InventoryEpoch != inventory.InventoryEpoch
                || manifest.IssuedAtUnixSeconds != inventory.InventoryIssuedAtUnixSeconds
                || manifest.ExpiresAtUnixSeconds != inventory.ServiceExpiresAtUnixSeconds
                || !ContactPreKeyOpaqueValue.FixedEquals(manifest.PredecessorXpi1Hash.Span, inventory.PredecessorXpi1Hash)
                || !ContactPreKeyOpaqueValue.FixedEquals(manifest.CurrentDmd1Hash.Span, inventory.ExactCurrentDmd1Hash)
                || !manifest.CurrentDrs1Reference.Span.SequenceEqual(inventory.ExactCurrentDrs1Ref)
                || !manifest.Xps1Reference.Span[6..].SequenceEqual(inventory.ExactXps1Hash))
            {
                throw new InvalidDataException("Persisted XPI1 metadata does not match the exact manifest.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedXpi1Hash);
        }
        if (inventory.ReplicaNodeIds.Any(static value => value is not { Length: 32 }
                || ContactPreKeyOpaqueValue.IsZero32(value))
            || inventory.ReplicaNodeIds[0].AsSpan().SequenceCompareTo(inventory.ReplicaNodeIds[1]) >= 0)
        {
            throw new InvalidDataException("Persisted XIC1 replica identities are not canonical.");
        }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var hashes = new HashSet<string>(StringComparer.Ordinal);
        byte[]? priorId = null;
        for (var index = 0; index < inventory.OneTimeOfferings.Count; index++)
        {
            var offering = inventory.OneTimeOfferings[index];
            ValidateOffering(offering, lastResort: false, inventory.ServiceExpiresAtUnixSeconds);
            if (offering.InventoryIndex != index
                || (priorId is not null && priorId.AsSpan().SequenceCompareTo(offering.PreKeyId) >= 0)
                || !ids.Add(Convert.ToHexString(offering.PreKeyId))
                || !hashes.Add(Convert.ToHexString(offering.ExactDpk2Hash))
                || !VerifyMembership(manifest, offering))
            {
                throw new InvalidDataException("Contact pre-key inventory contains duplicates.");
            }
            priorId = offering.PreKeyId;
        }
        ValidateOffering(inventory.LastResortOffering, lastResort: true, inventory.ServiceExpiresAtUnixSeconds);
        if (!hashes.Add(Convert.ToHexString(inventory.LastResortOffering.ExactDpk2Hash))
            || !VerifyMembership(manifest, inventory.LastResortOffering))
        {
            throw new InvalidDataException("Contact pre-key last-resort DPK2 is duplicated.");
        }
    }

    private static void ValidateOffering(OfferingState offering, bool lastResort, ulong serviceExpiry)
    {
        ValidateExact(offering.PreKeyId, 32);
        ValidateNonZero(offering.ExactDpk2Hash, 32);
        var expectedLength = lastResort
            ? ContactPreKeyStoreOptions.LastResortDpk2Bytes
            : ContactPreKeyStoreOptions.OneTimeDpk2Bytes;
        if (offering.ExactDpk2 is null
            || offering.ExactDpk2.Length != expectedLength
            || offering.PreKeyExpiresAtUnixSeconds == 0
            || offering.PreKeyExpiresAtUnixSeconds > serviceExpiry
            || lastResort != ContactPreKeyOpaqueValue.IsZero32(offering.PreKeyId)
            || (lastResort
                ? offering.LastResortReuseLimit is < 1 or > ContactPreKeyStoreOptions.MaximumLastResortReuse
                : offering.LastResortReuseLimit != 0)
            || (lastResort
                ? offering.InventoryIndex != ushort.MaxValue || offering.InclusionProof.Length != 0
                : offering.InventoryIndex == ushort.MaxValue
                    || offering.InclusionProof.Length is < 160 or > 384
                    || offering.InclusionProof.Length % 32 != 0)
            || !ExactDpk2HashMatches(offering.ExactDpk2, offering.ExactDpk2Hash))
        {
            throw new InvalidDataException("A persisted opaque DPK2 offering is invalid.");
        }
    }

    private static void ValidateClaimState(ClaimState claim)
    {
        ValidateNonZero(claim.OperationId, 32);
        ValidateNonZero(claim.RequestHash, 32);
        ValidateExact(claim.PreKeyId, 32);
        ValidateNonZero(claim.ExactDpk2Hash, 32);
        ValidateNonZero(claim.ExactCurrentDmd1Hash, 32);
        ValidateNonZero(claim.ExactCurrentDrs1Ref, 38);
        ValidateNonZero(claim.Xpi1Hash, 32);
        if (claim.ExactXpi1 is not { Length: Xpi1Codec.TotalBytes }
            || claim.InventoryEpoch is < 1 or > 14
            || claim.ReplicaNodeIds is not { Count: 2 })
        {
            throw new InvalidDataException("A persisted contact pre-key claim has invalid XPI1 metadata.");
        }
        var lastResort = ContactPreKeyOpaqueValue.IsZero32(claim.PreKeyId);
        var expectedLength = lastResort
            ? ContactPreKeyStoreOptions.LastResortDpk2Bytes
            : ContactPreKeyStoreOptions.OneTimeDpk2Bytes;
        if (claim.ExactDpk2 is null
            || claim.ExactDpk2.Length != expectedLength
            || !ExactDpk2HashMatches(claim.ExactDpk2, claim.ExactDpk2Hash)
            || claim.ClaimCommitGeneration == 0
            || claim.ClaimedAtUnixSeconds == 0
            || claim.ClaimedAtUnixSeconds >= claim.RetainUntilUnixSeconds
            || claim.PreKeyExpiresAtUnixSeconds > claim.RetainUntilUnixSeconds
            || (lastResort
                ? claim.LastResortUseCounter is < 1 or > ContactPreKeyStoreOptions.MaximumLastResortReuse
                : claim.LastResortUseCounter != 0))
        {
            throw new InvalidDataException("A persisted contact pre-key claim is invalid.");
        }
        var manifest = Xpi1Codec.Decode(claim.ExactXpi1);
        var offering = new OfferingState
        {
            PreKeyId = claim.PreKeyId,
            ExactDpk2Hash = claim.ExactDpk2Hash,
            ExactDpk2 = claim.ExactDpk2,
            PreKeyExpiresAtUnixSeconds = claim.PreKeyExpiresAtUnixSeconds,
            LastResortReuseLimit = lastResort ? claim.LastResortUseCounter : (ushort)0,
            InventoryIndex = claim.InventoryIndex,
            InclusionProof = claim.InclusionProof
        };
        var computedXpi1Hash = Xpi1Codec.ComputeHash(claim.ExactXpi1);
        try
        {
            var dpk2 = Dpk2Codec.Decode(claim.ExactDpk2);
            if (manifest.InventoryEpoch != claim.InventoryEpoch
                || manifest.ServiceGeneration != claim.ServiceGeneration
                || manifest.ExpiresAtUnixSeconds != claim.PreKeyExpiresAtUnixSeconds
                || !manifest.CurrentDmd1Hash.Span.SequenceEqual(claim.ExactCurrentDmd1Hash)
                || !manifest.CurrentDrs1Reference.Span.SequenceEqual(claim.ExactCurrentDrs1Ref)
                || dpk2.InventoryEpoch != claim.InventoryEpoch
                || dpk2.PrekeyServiceGeneration != claim.ServiceGeneration
                || !ContactPreKeyOpaqueValue.FixedEquals(computedXpi1Hash, claim.Xpi1Hash)
                || !VerifyMembership(manifest, offering)
                || claim.ReplicaNodeIds.Any(static value => value is not { Length: 32 }
                    || ContactPreKeyOpaqueValue.IsZero32(value))
                || claim.ReplicaNodeIds[0].AsSpan().SequenceCompareTo(claim.ReplicaNodeIds[1]) >= 0)
            {
                throw new InvalidDataException("A persisted contact pre-key claim does not close its XPI1 membership.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedXpi1Hash);
        }
    }

    private static bool ExactDpk2HashMatches(ReadOnlySpan<byte> exactDpk2, ReadOnlySpan<byte> expectedHash)
    {
        try
        {
            var computed = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(Dpk2Codec.Decode(exactDpk2));
            try
            {
                return ContactPreKeyOpaqueValue.FixedEquals(computed, expectedHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(computed);
            }
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException
            or CryptographicException or OverflowException)
        {
            return false;
        }
    }

    private static bool VerifyMembership(Xpi1Record manifest, OfferingState offering)
    {
        if (offering.InventoryIndex == ushort.MaxValue)
        {
            return offering.InclusionProof.Length == 0
                && ContactPreKeyOpaqueValue.FixedEquals(
                    manifest.LastResortDpk2Hash.Span, offering.ExactDpk2Hash);
        }
        if (offering.InventoryIndex >= manifest.OneTimeDpk2Count)
        {
            return false;
        }
        var width = 1;
        var depth = 0;
        while (width < manifest.OneTimeDpk2Count)
        {
            width <<= 1;
            depth++;
        }
        if (offering.InclusionProof.Length != depth * 32)
        {
            return false;
        }
        var positionBytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(positionBytes, offering.InventoryIndex);
        var leafInput = new byte[34];
        positionBytes.CopyTo(leafInput, 0);
        offering.ExactDpk2Hash.CopyTo(leafInput, 2);
        var node = ContactPreKeyOpaqueValue.Sha256Domain(
            "Deep/ContactResolver/V1/prekey-inventory-leaf", leafInput);
        try
        {
            var position = offering.InventoryIndex;
            for (var offset = 0; offset < offering.InclusionProof.Length; offset += 32)
            {
                var sibling = offering.InclusionProof.AsSpan(offset, 32);
                var parentInput = new byte[64];
                if ((position & 1) == 0)
                {
                    node.CopyTo(parentInput, 0);
                    sibling.CopyTo(parentInput.AsSpan(32));
                }
                else
                {
                    sibling.CopyTo(parentInput);
                    node.CopyTo(parentInput, 32);
                }
                var parent = ContactPreKeyOpaqueValue.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-node", parentInput);
                CryptographicOperations.ZeroMemory(parentInput);
                CryptographicOperations.ZeroMemory(node);
                node = parent;
                position >>= 1;
            }
            return ContactPreKeyOpaqueValue.FixedEquals(node, manifest.OneTimeMerkleRoot.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leafInput);
            CryptographicOperations.ZeroMemory(node);
        }
    }

    private bool HasPreKeyReuse(VerifiedOpaquePreKeyInventory inventory)
    {
        foreach (var offering in inventory.OneTimeOfferings)
        {
            if (FindClaimByPreKeyId(offering.PreKeyId) is not null
                || state.Capabilities.Any(capability =>
                    capability.Inventories.SelectMany(static item => item.OneTimeOfferings)
                        .Any(existing => ContactPreKeyOpaqueValue.FixedEquals(existing.PreKeyId, offering.PreKeyId))))
            {
                return true;
            }
        }
        return false;
    }

    private CapabilityState? FindCapability(ReadOnlySpan<byte> serviceCapability)
    {
        foreach (var capability in state.Capabilities)
        {
            if (ContactPreKeyOpaqueValue.FixedEquals(capability.ServiceCapability, serviceCapability))
            {
                return capability;
            }
        }
        return null;
    }

    private ClaimState? FindClaimByPreKeyId(ReadOnlySpan<byte> preKeyId)
    {
        foreach (var capability in state.Capabilities)
        {
            foreach (var claim in capability.Claims)
            {
                if (!ContactPreKeyOpaqueValue.IsZero32(claim.PreKeyId)
                    && ContactPreKeyOpaqueValue.FixedEquals(claim.PreKeyId, preKeyId))
                {
                    return claim;
                }
            }
        }
        return null;
    }

    private bool IsOneTimePreKeyClaimed(ReadOnlySpan<byte> preKeyId) =>
        FindClaimByPreKeyId(preKeyId) is not null;

    private long TotalOpaqueBytes() =>
        state.Capabilities.Sum(static capability =>
            capability.Inventories.Sum(static inventory =>
                inventory.OneTimeOfferings.Sum(static offering =>
                    (long)offering.ExactDpk2.Length + offering.InclusionProof.Length)
                + inventory.LastResortOffering.ExactDpk2.Length
                + inventory.ExactXpi1.Length)
            + capability.Claims.Sum(static claim =>
                (long)claim.ExactDpk2.Length + claim.ExactXpi1.Length + claim.InclusionProof.Length));

    private static long InventoryBytes(VerifiedOpaquePreKeyInventory inventory) =>
        inventory.OneTimeOfferings.Sum(static offering =>
            (long)offering.ExactDpk2.Length + offering.InclusionProof.Length)
        + inventory.LastResortOffering.ExactDpk2.Length
        + inventory.ExactXpi1.Length;

    private ulong CurrentUnixSeconds()
    {
        var seconds = clock.UtcNow.ToUnixTimeSeconds();
        if (seconds < 0)
        {
            throw new InvalidOperationException("Contact pre-key trusted service time is before the Unix epoch.");
        }
        return checked((ulong)seconds);
    }

    private static void ValidateServiceDeadline(ulong deadline, ulong now)
    {
        if (deadline <= now
            || deadline - now > (ulong)ContactPreKeyStoreOptions.MaximumServiceLifetime.TotalSeconds)
        {
            throw new ArgumentOutOfRangeException(nameof(deadline), "The verified pre-key service expiry is outside V1 bounds.");
        }
    }

    private static void ValidateInventoryDeadlines(VerifiedOpaquePreKeyInventory inventory, ulong now)
    {
        foreach (var offering in inventory.OneTimeOfferings.Append(inventory.LastResortOffering))
        {
            if (offering.PreKeyExpiresAtUnixSeconds <= now
                || offering.PreKeyExpiresAtUnixSeconds - now
                    > (ulong)ContactPreKeyStoreOptions.MaximumPreKeyLifetime.TotalSeconds)
            {
                throw new ArgumentOutOfRangeException(nameof(inventory), "A verified DPK2 expiry is outside V1 bounds.");
            }
        }
    }

    private static ulong AddSecondsBounded(ulong value, ulong seconds) =>
        value > ulong.MaxValue - seconds ? ulong.MaxValue : value + seconds;

    private void LatchAndSave(CapabilityState capability)
    {
        capability.ForkLatched = true;
        SaveState();
    }

    private static ContactPreKeyClaimResult Empty(
        ContactPreKeyClaimDisposition disposition,
        OpaquePreKeyClaimRequest request) =>
        new(disposition, request.RequestHash);

    private static ContactPreKeyClaimResult ToResult(
        ContactPreKeyClaimDisposition disposition,
        ClaimState claim) =>
        new(
            disposition,
            claim.RequestHash,
            claim.ExactDpk2,
            claim.PreKeyId,
            claim.ExactDpk2Hash,
            claim.ExactCurrentDmd1Hash,
            claim.ExactCurrentDrs1Ref,
            claim.ServiceGeneration,
            claim.PreKeyExpiresAtUnixSeconds,
            claim.LastResortUseCounter,
            claim.ClaimCommitGeneration,
            claim.ClaimedAtUnixSeconds,
            claim.ExactXpi1,
            claim.Xpi1Hash,
            claim.InventoryEpoch,
            claim.InventoryIndex,
            claim.InclusionProof,
            claim.ReplicaNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());

    private static InventoryState ToState(VerifiedOpaquePreKeyInventory inventory) => new()
    {
        NetworkId = inventory.NetworkId.ToArray(),
        ServiceCapability = inventory.ServiceCapability.ToArray(),
        ResponderDeviceId = inventory.ResponderDeviceId.ToArray(),
        SupportedSuite = inventory.SupportedSuite,
        ServiceGeneration = inventory.ServiceGeneration,
        ExactXps1Hash = inventory.ExactXps1Hash.ToArray(),
        ExactCurrentDmd1Hash = inventory.ExactCurrentDmd1Hash.ToArray(),
        ExactCurrentDrs1Ref = inventory.ExactCurrentDrs1Ref.ToArray(),
        PublicationOperationId = inventory.PublicationOperationId.ToArray(),
        ExactXpi1 = inventory.ExactXpi1.ToArray(),
        Xpi1Hash = inventory.Xpi1Hash.ToArray(),
        PredecessorXpi1Hash = inventory.PredecessorXpi1Hash.ToArray(),
        InventoryEpoch = inventory.InventoryEpoch,
        InventoryIssuedAtUnixSeconds = inventory.InventoryIssuedAtUnixSeconds,
        ReplicaNodeIds = inventory.ReplicaNodeIds.Select(static value => value.ToArray()).ToList(),
        ServiceExpiresAtUnixSeconds = inventory.ServiceExpiresAtUnixSeconds,
        OneTimeOfferings = inventory.OneTimeOfferings.Select(ToState).ToList(),
        LastResortOffering = ToState(inventory.LastResortOffering)
    };

    private static OfferingState ToState(OpaquePreKeyOffering offering) => new()
    {
        PreKeyId = offering.PreKeyId.ToArray(),
        ExactDpk2Hash = offering.ExactDpk2Hash.ToArray(),
        ExactDpk2 = offering.ExactDpk2.ToArray(),
        PreKeyExpiresAtUnixSeconds = offering.PreKeyExpiresAtUnixSeconds,
        LastResortReuseLimit = offering.LastResortReuseLimit,
        InventoryIndex = offering.InventoryIndex,
        InclusionProof = offering.InclusionProof.ToArray()
    };

    private static bool InventoryMatches(InventoryState left, VerifiedOpaquePreKeyInventory right)
    {
        if (left.ServiceGeneration != right.ServiceGeneration
            || left.InventoryEpoch != right.InventoryEpoch
            || left.InventoryIssuedAtUnixSeconds != right.InventoryIssuedAtUnixSeconds
            || left.SupportedSuite != right.SupportedSuite
            || left.ServiceExpiresAtUnixSeconds != right.ServiceExpiresAtUnixSeconds
            || !ContactPreKeyOpaqueValue.FixedEquals(left.NetworkId, right.NetworkId)
            || !ContactPreKeyOpaqueValue.FixedEquals(left.ServiceCapability, right.ServiceCapability)
            || !ContactPreKeyOpaqueValue.FixedEquals(left.ResponderDeviceId, right.ResponderDeviceId)
            || !ContactPreKeyOpaqueValue.FixedEquals(left.ExactXps1Hash, right.ExactXps1Hash)
            || !ContactPreKeyOpaqueValue.FixedEquals(left.ExactCurrentDmd1Hash, right.ExactCurrentDmd1Hash)
            || !left.ExactCurrentDrs1Ref.AsSpan().SequenceEqual(right.ExactCurrentDrs1Ref)
            || !ContactPreKeyOpaqueValue.FixedEquals(left.PublicationOperationId, right.PublicationOperationId)
            || !ContactPreKeyOpaqueValue.FixedEquals(left.Xpi1Hash, right.Xpi1Hash)
            || !left.ExactXpi1.AsSpan().SequenceEqual(right.ExactXpi1)
            || !left.PredecessorXpi1Hash.AsSpan().SequenceEqual(right.PredecessorXpi1Hash)
            || left.ReplicaNodeIds.Count != right.ReplicaNodeIds.Count
            || left.ReplicaNodeIds.Where((value, index) =>
                !value.AsSpan().SequenceEqual(right.ReplicaNodeIds[index].Span)).Any()
            || left.OneTimeOfferings.Count != right.OneTimeOfferings.Count)
        {
            return false;
        }
        var offerings = right.OneTimeOfferings;
        for (var index = 0; index < left.OneTimeOfferings.Count; index++)
        {
            if (!OfferingMatches(left.OneTimeOfferings[index], offerings[index]))
            {
                return false;
            }
        }
        return OfferingMatches(left.LastResortOffering, right.LastResortOffering);
    }

    private static bool OfferingMatches(OfferingState left, OpaquePreKeyOffering right) =>
        left.PreKeyExpiresAtUnixSeconds == right.PreKeyExpiresAtUnixSeconds
        && left.LastResortReuseLimit == right.LastResortReuseLimit
        && left.InventoryIndex == right.InventoryIndex
        && ContactPreKeyOpaqueValue.FixedEquals(left.PreKeyId, right.PreKeyId)
        && ContactPreKeyOpaqueValue.FixedEquals(left.ExactDpk2Hash, right.ExactDpk2Hash)
        && left.ExactDpk2.AsSpan().SequenceEqual(right.ExactDpk2)
        && left.InclusionProof.AsSpan().SequenceEqual(right.InclusionProof);

    private void CanonicalizeState()
    {
        state.Capabilities.Sort(static (left, right) =>
            left.ServiceCapability.AsSpan().SequenceCompareTo(right.ServiceCapability));
        foreach (var capability in state.Capabilities)
        {
            capability.Claims.Sort(static (left, right) =>
                left.ClaimCommitGeneration.CompareTo(right.ClaimCommitGeneration));
        }
    }

    private static void ValidateExact(byte[]? value, int length)
    {
        if (value is null || value.Length != length)
        {
            throw new InvalidDataException("A persisted opaque value has the wrong length.");
        }
    }

    private static void ValidateNonZero(byte[]? value, int length)
    {
        ValidateExact(value, length);
        if (value!.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidDataException("A persisted opaque value is zero.");
        }
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted)
        {
            throw new InvalidOperationException("The contact pre-key store is faulted after a durability failure.");
        }
    }

    private sealed class PersistedState
    {
        public int Version { get; set; } = StateVersion;
        public List<CapabilityState> Capabilities { get; set; } = [];
        public List<PublicationState> Publications { get; set; } = [];
    }

    private sealed class CapabilityState
    {
        public byte[] ServiceCapability { get; set; } = [];
        public bool ForkLatched { get; set; }
        public ulong CommitGeneration { get; set; }
        public ulong LastAcceptedInventoryEpoch { get; set; }
        public byte[] LastAcceptedXpi1Hash { get; set; } = [];
        public byte[] LastPublicationOperationId { get; set; } = [];
        public List<InventoryState> Inventories { get; set; } = [];
        public List<ClaimState> Claims { get; set; } = [];
    }

    private sealed class InventoryState
    {
        public byte[] NetworkId { get; set; } = [];
        public byte[] ServiceCapability { get; set; } = [];
        public byte[] ResponderDeviceId { get; set; } = [];
        public ushort SupportedSuite { get; set; }
        public ulong ServiceGeneration { get; set; }
        public byte[] ExactXps1Hash { get; set; } = [];
        public byte[] ExactCurrentDmd1Hash { get; set; } = [];
        public byte[] ExactCurrentDrs1Ref { get; set; } = [];
        public byte[] PublicationOperationId { get; set; } = [];
        public byte[] ExactXpi1 { get; set; } = [];
        public byte[] Xpi1Hash { get; set; } = [];
        public byte[] PredecessorXpi1Hash { get; set; } = [];
        public ulong InventoryEpoch { get; set; }
        public ulong InventoryIssuedAtUnixSeconds { get; set; }
        public List<byte[]> ReplicaNodeIds { get; set; } = [];
        public ulong ServiceExpiresAtUnixSeconds { get; set; }
        public List<OfferingState> OneTimeOfferings { get; set; } = [];
        public OfferingState LastResortOffering { get; set; } = new();
    }

    private sealed class OfferingState
    {
        public byte[] PreKeyId { get; set; } = [];
        public byte[] ExactDpk2Hash { get; set; } = [];
        public byte[] ExactDpk2 { get; set; } = [];
        public ulong PreKeyExpiresAtUnixSeconds { get; set; }
        public ushort LastResortReuseLimit { get; set; }
        public ushort InventoryIndex { get; set; }
        public byte[] InclusionProof { get; set; } = [];
    }

    private sealed class ClaimState
    {
        public byte[] OperationId { get; set; } = [];
        public byte[] RequestHash { get; set; } = [];
        public ulong ServiceGeneration { get; set; }
        public byte[] ExactDpk2 { get; set; } = [];
        public byte[] PreKeyId { get; set; } = [];
        public byte[] ExactDpk2Hash { get; set; } = [];
        public byte[] ExactCurrentDmd1Hash { get; set; } = [];
        public byte[] ExactCurrentDrs1Ref { get; set; } = [];
        public byte[] ExactXpi1 { get; set; } = [];
        public byte[] Xpi1Hash { get; set; } = [];
        public ulong InventoryEpoch { get; set; }
        public ushort InventoryIndex { get; set; }
        public byte[] InclusionProof { get; set; } = [];
        public List<byte[]> ReplicaNodeIds { get; set; } = [];
        public ulong PreKeyExpiresAtUnixSeconds { get; set; }
        public ushort LastResortUseCounter { get; set; }
        public ulong ClaimCommitGeneration { get; set; }
        public ulong ClaimedAtUnixSeconds { get; set; }
        public ulong RetainUntilUnixSeconds { get; set; }
    }
}
