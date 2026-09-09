using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;

namespace XNode.Core.ContactPreKey;

internal enum ContactPreKeyInventoryDisposition
{
    Installed = 1,
    ExactReplay = 2,
    StaleGeneration = 3,
    Conflict = 4,
    ForkLatched = 5,
    QuotaExceeded = 6
}

internal enum ContactPreKeyClaimDisposition
{
    Claimed = 1,
    ExactReplay = 2,
    PreKeysUnavailable = 3,
    Expired = 4,
    StaleBundle = 5,
    Conflict = 6,
    ForkLatched = 7,
    QuotaExceeded = 8
}

internal sealed class ContactPreKeyStoreOptions
{
    internal const ushort SupportedSuite = 0x0201;
    internal const int OneTimeDpk2Bytes = 2_037;
    internal const int LastResortDpk2Bytes = 1_973;
    internal const int MinimumOneTimeOfferings = 32;
    internal const int MaximumOneTimeOfferings = 4_096;
    internal const int MaximumLastResortReuse = 64;
    internal const int MaximumActiveInventories = 2;
    internal static readonly TimeSpan MaximumServiceLifetime = TimeSpan.FromDays(400);
    internal static readonly TimeSpan MaximumPreKeyLifetime = TimeSpan.FromDays(30);
    internal static readonly TimeSpan ClaimReplayRetention = TimeSpan.FromDays(30);

    internal int MaximumCapabilities { get; init; } = 16_384;
    internal int MaximumClaimsPerCapability { get; init; } = 8_256;
    internal long MaximumOpaqueBytes { get; init; } = 256L * 1024 * 1024;
    internal long MaximumPersistedBytes { get; init; } = 384L * 1024 * 1024;

    internal void Validate()
    {
        if (MaximumCapabilities < 1
            || MaximumClaimsPerCapability < MaximumOneTimeOfferings * MaximumActiveInventories
            || MaximumOpaqueBytes < OneTimeDpk2Bytes * MinimumOneTimeOfferings + LastResortDpk2Bytes
            || MaximumPersistedBytes < MaximumOpaqueBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(ContactPreKeyStoreOptions));
        }
    }
}

internal sealed class OpaquePreKeyOffering
{
    private readonly byte[] preKeyId;
    private readonly byte[] exactDpk2Hash;
    private readonly byte[] exactDpk2;
    private readonly byte[] inclusionProof;

    private OpaquePreKeyOffering(
        ReadOnlySpan<byte> oneTimePreKeyId32,
        ReadOnlySpan<byte> exactDpk2Hash32,
        ReadOnlySpan<byte> exactDpk2,
        ulong preKeyExpiresAtUnixSeconds,
        ushort lastResortReuseLimit,
        ushort inventoryIndex,
        ReadOnlySpan<byte> merkleInclusionProof)
    {
        var lastResort = ContactPreKeyOpaqueValue.IsZero32(oneTimePreKeyId32);
        if (oneTimePreKeyId32.Length != 32
            || (!lastResort && lastResortReuseLimit != 0)
            || (lastResort && lastResortReuseLimit is < 1 or > ContactPreKeyStoreOptions.MaximumLastResortReuse))
        {
            throw new ArgumentException("The opaque pre-key kind fields are inconsistent.", nameof(oneTimePreKeyId32));
        }
        var requiredLength = lastResort
            ? ContactPreKeyStoreOptions.LastResortDpk2Bytes
            : ContactPreKeyStoreOptions.OneTimeDpk2Bytes;
        if (exactDpk2.Length != requiredLength)
        {
            throw new ArgumentOutOfRangeException(nameof(exactDpk2));
        }

        preKeyId = oneTimePreKeyId32.ToArray();
        exactDpk2Hash = ContactPreKeyOpaqueValue.CopyNonZero32(exactDpk2Hash32, nameof(exactDpk2Hash32));
        var parsed = Dpk2Codec.Decode(exactDpk2);
        var computedHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(parsed);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(computedHash, exactDpk2Hash32))
            {
                throw new ArgumentException("The exact DPK2 hash does not match its opaque bytes.", nameof(exactDpk2Hash32));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedHash);
        }
        if ((lastResort && (inventoryIndex != ushort.MaxValue || !merkleInclusionProof.IsEmpty))
            || (!lastResort && (inventoryIndex == ushort.MaxValue
                || merkleInclusionProof.Length is < 160 or > 384
                || merkleInclusionProof.Length % 32 != 0)))
        {
            throw new ArgumentException("The XPI1 inventory membership metadata is not canonical.", nameof(inventoryIndex));
        }
        this.exactDpk2 = exactDpk2.ToArray();
        inclusionProof = merkleInclusionProof.ToArray();
        PreKeyExpiresAtUnixSeconds = preKeyExpiresAtUnixSeconds;
        LastResortReuseLimit = lastResortReuseLimit;
        InventoryIndex = inventoryIndex;
    }

    internal ReadOnlySpan<byte> PreKeyId => preKeyId;
    internal ReadOnlySpan<byte> ExactDpk2Hash => exactDpk2Hash;
    internal ReadOnlySpan<byte> ExactDpk2 => exactDpk2;
    internal ulong PreKeyExpiresAtUnixSeconds { get; }
    internal ushort LastResortReuseLimit { get; }
    internal ushort InventoryIndex { get; }
    internal ReadOnlySpan<byte> InclusionProof => inclusionProof;
    internal bool IsLastResort => ContactPreKeyOpaqueValue.IsZero32(preKeyId);

    internal static OpaquePreKeyOffering FromVerifiedMember(
        VerifiedPreKeyInventoryMember member,
        ushort inventoryIndex,
        ReadOnlySpan<byte> inclusionProof)
    {
        ArgumentNullException.ThrowIfNull(member);
        return new OpaquePreKeyOffering(
            member.ClaimPreKeyId.Span,
            member.ExactDpk2Hash.Span,
            member.ExactDpk2.Span,
            member.ExpiresAtUnixSeconds,
            member.ReuseLimit,
            inventoryIndex,
            inclusionProof);
    }

    internal OpaquePreKeyOffering Clone() =>
        new(preKeyId, exactDpk2Hash, exactDpk2, PreKeyExpiresAtUnixSeconds,
            LastResortReuseLimit, InventoryIndex, inclusionProof);
}

internal sealed class VerifiedOpaquePreKeyInventory
{
    private readonly byte[] networkId;
    private readonly byte[] serviceCapability;
    private readonly byte[] responderDeviceId;
    private readonly byte[] exactXps1Hash;
    private readonly byte[] exactCurrentDmd1Hash;
    private readonly byte[] exactCurrentDrs1Ref;
    private readonly byte[] publicationOperationId;
    private readonly byte[] exactXpi1;
    private readonly byte[] xpi1Hash;
    private readonly byte[] predecessorXpi1Hash;
    private readonly byte[][] replicaNodeIds;
    private readonly OpaquePreKeyOffering[] oneTimeOfferings;
    private readonly OpaquePreKeyOffering lastResortOffering;

    private VerifiedOpaquePreKeyInventory(VerifiedPreKeyInventoryPublication publication) : this(
        publication?.NetworkId ?? throw new ArgumentNullException(nameof(publication)),
        publication.ServiceCapability,
        publication.PublicationOperationId,
        publication.ExactXpi1,
        publication.Xpi1Hash,
        publication.PredecessorXpi1Hash,
        publication.InventoryEpoch,
        publication.OneTimeDpk2Count,
        publication.IssuedAtUnixSeconds,
        publication.ExpiresAtUnixSeconds,
        publication.OneTimeMembers,
        publication.LastResortMember,
        publication.ReplicaNodeIds,
        nameof(publication))
    {
    }

    private VerifiedOpaquePreKeyInventory(
        VerifiedPreKeyInventoryInstallationPlan plan,
        IReadOnlyList<ReadOnlyMemory<byte>> replicaNodeIds) : this(
            plan?.NetworkId ?? throw new ArgumentNullException(nameof(plan)),
            plan.ServiceCapability,
            plan.PublicationOperationId,
            plan.ExactXpi1,
            plan.Xpi1Hash,
            Xpi1Codec.Decode(plan.ExactXpi1.Span).PredecessorXpi1Hash,
            plan.InventoryEpoch,
            checked((ushort)plan.OneTimeMembers.Count),
            plan.IssuedAtUnixSeconds,
            plan.ExpiresAtUnixSeconds,
            plan.OneTimeMembers,
            plan.LastResortMember,
            replicaNodeIds,
            nameof(plan))
    {
    }

    private VerifiedOpaquePreKeyInventory(
        ReadOnlyMemory<byte> verifiedNetworkId,
        ReadOnlyMemory<byte> verifiedServiceCapability,
        ReadOnlyMemory<byte> verifiedPublicationOperationId,
        ReadOnlyMemory<byte> verifiedExactXpi1,
        ReadOnlyMemory<byte> verifiedXpi1Hash,
        ReadOnlyMemory<byte> verifiedPredecessorXpi1Hash,
        ulong verifiedInventoryEpoch,
        ushort verifiedOneTimeDpk2Count,
        ulong verifiedIssuedAtUnixSeconds,
        ulong verifiedExpiresAtUnixSeconds,
        IReadOnlyList<VerifiedPreKeyInventoryMember> verifiedOneTimeMembers,
        VerifiedPreKeyInventoryMember verifiedLastResortMember,
        IReadOnlyList<ReadOnlyMemory<byte>> verifiedReplicaNodeIds,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(verifiedOneTimeMembers);
        ArgumentNullException.ThrowIfNull(verifiedLastResortMember);
        ArgumentNullException.ThrowIfNull(verifiedReplicaNodeIds);
        var manifest = Xpi1Codec.Decode(verifiedExactXpi1.Span);
        networkId = ContactPreKeyOpaqueValue.CopyExact(verifiedNetworkId.Span, 16, parameterName);
        serviceCapability = ContactPreKeyOpaqueValue.CopyNonZero32(
            verifiedServiceCapability.Span, parameterName);
        responderDeviceId = ContactPreKeyOpaqueValue.CopyNonZero32(
            manifest.ResponderDeviceId.Span, parameterName);
        publicationOperationId = ContactPreKeyOpaqueValue.CopyNonZero32(
            verifiedPublicationOperationId.Span, parameterName);
        exactXpi1 = verifiedExactXpi1.ToArray();
        xpi1Hash = ContactPreKeyOpaqueValue.CopyNonZero32(verifiedXpi1Hash.Span, parameterName);
        predecessorXpi1Hash = verifiedPredecessorXpi1Hash.ToArray();
        if (predecessorXpi1Hash.Length != 32)
        {
            throw new ArgumentException("The verified predecessor XPI1 hash must be 32 bytes.", parameterName);
        }
        var computedXpi1Hash = Xpi1Codec.ComputeHash(exactXpi1);
        try
        {
            if (!ContactPreKeyOpaqueValue.FixedEquals(computedXpi1Hash, xpi1Hash)
                || !ContactPreKeyOpaqueValue.FixedEquals(manifest.NetworkId.Span, networkId)
                || !ContactPreKeyOpaqueValue.FixedEquals(manifest.ServiceCapability.Span, serviceCapability)
                || manifest.InventoryEpoch != verifiedInventoryEpoch
                || manifest.OneTimeDpk2Count != verifiedOneTimeDpk2Count
                || manifest.IssuedAtUnixSeconds != verifiedIssuedAtUnixSeconds
                || manifest.ExpiresAtUnixSeconds != verifiedExpiresAtUnixSeconds
                || !ContactPreKeyOpaqueValue.FixedEquals(manifest.PredecessorXpi1Hash.Span, predecessorXpi1Hash))
            {
                throw new ArgumentException("The Protocol inventory projection is internally inconsistent.", parameterName);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedXpi1Hash);
        }
        if (verifiedInventoryEpoch is < 1 or > 14)
        {
            throw new ArgumentOutOfRangeException(parameterName, "The verified XPI1 epoch is outside V1 bounds.");
        }
        var xps1Reference = manifest.Xps1Reference.Span;
        if (xps1Reference.Length != 38
            || !xps1Reference[..4].SequenceEqual("XPS1"u8)
            || BinaryPrimitives.ReadUInt16BigEndian(xps1Reference[4..6]) != 1)
        {
            throw new ArgumentException("The verified XPI1 contains a non-canonical XPS1 reference.", parameterName);
        }
        exactXps1Hash = xps1Reference[6..].ToArray();
        exactCurrentDmd1Hash = ContactPreKeyOpaqueValue.CopyNonZero32(
            manifest.CurrentDmd1Hash.Span, parameterName);
        exactCurrentDrs1Ref = ContactPreKeyOpaqueValue.CopyExact(
            manifest.CurrentDrs1Reference.Span, 38, parameterName);
        replicaNodeIds = verifiedReplicaNodeIds.Select(static value => value.ToArray()).ToArray();
        if (replicaNodeIds.Length != 2
            || replicaNodeIds.Any(static value => value.Length != 32 || ContactPreKeyOpaqueValue.IsZero32(value))
            || ContactPreKeyOpaqueValue.FixedEquals(replicaNodeIds[0], replicaNodeIds[1]))
        {
            throw new ArgumentException("The verified inventory must bind exactly two distinct XIC1 replicas.", parameterName);
        }
        Array.Sort(replicaNodeIds, ByteArrayComparer.Instance);

        if (verifiedOneTimeMembers.Count is < ContactPreKeyStoreOptions.MinimumOneTimeOfferings
            or > ContactPreKeyStoreOptions.MaximumOneTimeOfferings)
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }
        var proofs = BuildProofs(verifiedOneTimeMembers);
        oneTimeOfferings = new OpaquePreKeyOffering[verifiedOneTimeMembers.Count];
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var hashes = new HashSet<string>(StringComparer.Ordinal);
        byte[]? priorId = null;
        for (var index = 0; index < verifiedOneTimeMembers.Count; index++)
        {
            var offering = OpaquePreKeyOffering.FromVerifiedMember(
                verifiedOneTimeMembers[index], checked((ushort)index), proofs[index]);
            if (offering.IsLastResort
                || !ids.Add(Convert.ToHexString(offering.PreKeyId))
                || !hashes.Add(Convert.ToHexString(offering.ExactDpk2Hash))
                || offering.PreKeyExpiresAtUnixSeconds != verifiedExpiresAtUnixSeconds
                || (priorId is not null && priorId.AsSpan().SequenceCompareTo(offering.PreKeyId) >= 0))
            {
                throw new ArgumentException("The verified one-time inventory projection is not canonical.", parameterName);
            }
            oneTimeOfferings[index] = offering;
            priorId = offering.PreKeyId.ToArray();
        }
        lastResortOffering = OpaquePreKeyOffering.FromVerifiedMember(
            verifiedLastResortMember, ushort.MaxValue, []);
        if (!lastResortOffering.IsLastResort
            || lastResortOffering.PreKeyExpiresAtUnixSeconds != verifiedExpiresAtUnixSeconds
            || !hashes.Add(Convert.ToHexString(lastResortOffering.ExactDpk2Hash)))
        {
            throw new ArgumentException("The verified last-resort inventory projection is not canonical.", parameterName);
        }

        SupportedSuite = ContactPreKeyStoreOptions.SupportedSuite;
        ServiceGeneration = manifest.ServiceGeneration;
        InventoryEpoch = manifest.InventoryEpoch;
        InventoryIssuedAtUnixSeconds = manifest.IssuedAtUnixSeconds;
        ServiceExpiresAtUnixSeconds = manifest.ExpiresAtUnixSeconds;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ReadOnlySpan<byte> ResponderDeviceId => responderDeviceId;
    internal ushort SupportedSuite { get; }
    internal ulong ServiceGeneration { get; }
    internal ReadOnlySpan<byte> ExactXps1Hash => exactXps1Hash;
    internal ReadOnlySpan<byte> ExactCurrentDmd1Hash => exactCurrentDmd1Hash;
    internal ReadOnlySpan<byte> ExactCurrentDrs1Ref => exactCurrentDrs1Ref;
    internal ReadOnlySpan<byte> PublicationOperationId => publicationOperationId;
    internal ReadOnlySpan<byte> ExactXpi1 => exactXpi1;
    internal ReadOnlySpan<byte> Xpi1Hash => xpi1Hash;
    internal ReadOnlySpan<byte> PredecessorXpi1Hash => predecessorXpi1Hash;
    internal ulong InventoryEpoch { get; }
    internal ulong InventoryIssuedAtUnixSeconds { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(replicaNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    internal ulong ServiceExpiresAtUnixSeconds { get; }
    internal IReadOnlyList<OpaquePreKeyOffering> OneTimeOfferings => oneTimeOfferings.Select(static value => value.Clone()).ToArray();
    internal OpaquePreKeyOffering LastResortOffering => lastResortOffering.Clone();

    internal static VerifiedOpaquePreKeyInventory FromVerifiedPublication(
        VerifiedPreKeyInventoryPublication publication) => new(publication);

    internal static VerifiedOpaquePreKeyInventory FromInstallationPlan(
        VerifiedPreKeyInventoryInstallationPlan plan,
        IReadOnlyList<ReadOnlyMemory<byte>> replicaNodeIds) => new(plan, replicaNodeIds);

    private static byte[][] BuildProofs(IReadOnlyList<VerifiedPreKeyInventoryMember> members)
    {
        var width = 1;
        while (width < members.Count) width <<= 1;
        var levels = new List<byte[][]>();
        var leaves = new byte[width][];
        for (var index = 0; index < width; index++)
        {
            var position = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(position, checked((ushort)index));
            leaves[index] = index < members.Count
                ? ContactPreKeyOpaqueValue.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-leaf",
                    Join(position, members[index].ExactDpk2Hash.Span))
                : ContactPreKeyOpaqueValue.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-empty", position);
        }
        levels.Add(leaves);
        while (levels[^1].Length > 1)
        {
            var current = levels[^1];
            var next = new byte[current.Length / 2][];
            for (var index = 0; index < next.Length; index++)
            {
                next[index] = ContactPreKeyOpaqueValue.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-node",
                    Join(current[index * 2], current[(index * 2) + 1]));
            }
            levels.Add(next);
        }

        var proofs = new byte[members.Count][];
        for (var memberIndex = 0; memberIndex < members.Count; memberIndex++)
        {
            var proof = new byte[(levels.Count - 1) * 32];
            var position = memberIndex;
            for (var level = 0; level < levels.Count - 1; level++)
            {
                levels[level][position ^ 1].CopyTo(proof, level * 32);
                position >>= 1;
            }
            proofs[memberIndex] = proof;
        }
        foreach (var level in levels)
        {
            foreach (var hash in level) CryptographicOperations.ZeroMemory(hash);
        }
        return proofs;
    }

    private static byte[] Join(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var output = new byte[left.Length + right.Length];
        left.CopyTo(output);
        right.CopyTo(output.AsSpan(left.Length));
        return output;
    }
}

internal sealed class OpaquePreKeyClaimRequest
{
    private readonly byte[] networkId;
    private readonly byte[] serviceCapability;
    private readonly byte[] responderDeviceId;
    private readonly byte[] operationId;
    private readonly byte[] requestHash;
    private readonly byte[] exactDcb1Hash;
    private readonly byte[] exactXps1Hash;

    internal OpaquePreKeyClaimRequest(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> responderDeviceId32,
        ushort requestedSuite,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ReadOnlySpan<byte> exactDcb1Hash32,
        ReadOnlySpan<byte> exactXps1Hash32,
        ulong requestExpiresAtUnixSeconds)
    {
        networkId = ContactPreKeyOpaqueValue.CopyExact(networkId16, 16, nameof(networkId16));
        serviceCapability = ContactPreKeyOpaqueValue.CopyNonZero32(serviceCapability32, nameof(serviceCapability32));
        responderDeviceId = ContactPreKeyOpaqueValue.CopyNonZero32(
            responderDeviceId32,
            nameof(responderDeviceId32));
        if (requestedSuite == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(requestedSuite));
        }
        operationId = ContactPreKeyOpaqueValue.CopyNonZero32(operationId32, nameof(operationId32));
        requestHash = ContactPreKeyOpaqueValue.CopyNonZero32(requestHash32, nameof(requestHash32));
        exactDcb1Hash = ContactPreKeyOpaqueValue.CopyNonZero32(exactDcb1Hash32, nameof(exactDcb1Hash32));
        exactXps1Hash = ContactPreKeyOpaqueValue.CopyNonZero32(exactXps1Hash32, nameof(exactXps1Hash32));
        RequestedSuite = requestedSuite;
        RequestExpiresAtUnixSeconds = requestExpiresAtUnixSeconds;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ReadOnlySpan<byte> ResponderDeviceId => responderDeviceId;
    internal ushort RequestedSuite { get; }
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal ReadOnlySpan<byte> ExactDcb1Hash => exactDcb1Hash;
    internal ReadOnlySpan<byte> ExactXps1Hash => exactXps1Hash;
    internal ulong RequestExpiresAtUnixSeconds { get; }
}

internal sealed record ContactPreKeyInventoryResult(ContactPreKeyInventoryDisposition Disposition);

internal sealed class ContactPreKeyClaimResult
{
    private readonly byte[] requestHash;
    private readonly byte[] exactDpk2;
    private readonly byte[] oneTimePreKeyId;
    private readonly byte[] exactDpk2Hash;
    private readonly byte[] exactCurrentDmd1Hash;
    private readonly byte[] exactCurrentDrs1Ref;
    private readonly byte[] exactXpi1;
    private readonly byte[] xpi1Hash;
    private readonly byte[] inclusionProof;
    private readonly byte[][] replicaNodeIds;
    private readonly byte[] requiredDcb1Hash;
    private readonly byte[] requiredXps1Hash;
    private readonly byte[] requiredXpi1Hash;

    internal ContactPreKeyClaimResult(
        ContactPreKeyClaimDisposition disposition,
        ReadOnlySpan<byte> requestHash,
        ReadOnlySpan<byte> exactDpk2 = default,
        ReadOnlySpan<byte> oneTimePreKeyId = default,
        ReadOnlySpan<byte> exactDpk2Hash = default,
        ReadOnlySpan<byte> exactCurrentDmd1Hash = default,
        ReadOnlySpan<byte> exactCurrentDrs1Ref = default,
        ulong serviceGeneration = 0,
        ulong preKeyExpiresAt = 0,
        ushort lastResortUseCounter = 0,
        ulong claimCommitGeneration = 0,
        ulong claimedAtUnixSeconds = 0,
        ReadOnlySpan<byte> exactXpi1 = default,
        ReadOnlySpan<byte> xpi1Hash = default,
        ulong inventoryEpoch = 0,
        ushort inventoryIndex = 0,
        ReadOnlySpan<byte> inclusionProof = default,
        IReadOnlyList<ReadOnlyMemory<byte>>? replicaNodeIds = null,
        ReadOnlySpan<byte> requiredDcb1Hash = default,
        ReadOnlySpan<byte> requiredXps1Hash = default,
        ReadOnlySpan<byte> requiredXpi1Hash = default)
    {
        Disposition = disposition;
        this.requestHash = requestHash.ToArray();
        this.exactDpk2 = exactDpk2.ToArray();
        this.oneTimePreKeyId = oneTimePreKeyId.ToArray();
        this.exactDpk2Hash = exactDpk2Hash.ToArray();
        this.exactCurrentDmd1Hash = exactCurrentDmd1Hash.ToArray();
        this.exactCurrentDrs1Ref = exactCurrentDrs1Ref.ToArray();
        ServiceGeneration = serviceGeneration;
        PreKeyExpiresAt = preKeyExpiresAt;
        LastResortUseCounter = lastResortUseCounter;
        ClaimCommitGeneration = claimCommitGeneration;
        ClaimedAtUnixSeconds = claimedAtUnixSeconds;
        this.exactXpi1 = exactXpi1.ToArray();
        this.xpi1Hash = xpi1Hash.ToArray();
        InventoryEpoch = inventoryEpoch;
        InventoryIndex = inventoryIndex;
        this.inclusionProof = inclusionProof.ToArray();
        this.replicaNodeIds = replicaNodeIds?.Select(static value => value.ToArray()).ToArray() ?? [];
        this.requiredDcb1Hash = requiredDcb1Hash.ToArray();
        this.requiredXps1Hash = requiredXps1Hash.ToArray();
        this.requiredXpi1Hash = requiredXpi1Hash.ToArray();
    }

    internal ContactPreKeyClaimDisposition Disposition { get; }
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal ReadOnlySpan<byte> ExactDpk2 => exactDpk2;
    internal ReadOnlySpan<byte> OneTimePreKeyId => oneTimePreKeyId;
    internal ReadOnlySpan<byte> ExactDpk2Hash => exactDpk2Hash;
    internal ReadOnlySpan<byte> ExactCurrentDmd1Hash => exactCurrentDmd1Hash;
    internal ReadOnlySpan<byte> ExactCurrentDrs1Ref => exactCurrentDrs1Ref;
    internal ulong ServiceGeneration { get; }
    internal ulong PreKeyExpiresAt { get; }
    internal ushort LastResortUseCounter { get; }
    internal ulong ClaimCommitGeneration { get; }
    internal ulong ClaimedAtUnixSeconds { get; }
    internal ReadOnlySpan<byte> ExactXpi1 => exactXpi1;
    internal ReadOnlySpan<byte> Xpi1Hash => xpi1Hash;
    internal ulong InventoryEpoch { get; }
    internal ushort InventoryIndex { get; }
    internal ReadOnlySpan<byte> InclusionProof => inclusionProof;
    internal IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(replicaNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    internal ReadOnlySpan<byte> RequiredDcb1Hash => requiredDcb1Hash;
    internal ReadOnlySpan<byte> RequiredXps1Hash => requiredXps1Hash;
    internal ReadOnlySpan<byte> RequiredXpi1Hash => requiredXpi1Hash;

    internal ContactPreKeyClaimResult Clone() =>
        new(
            Disposition,
            requestHash,
            exactDpk2,
            oneTimePreKeyId,
            exactDpk2Hash,
            exactCurrentDmd1Hash,
            exactCurrentDrs1Ref,
            ServiceGeneration,
            PreKeyExpiresAt,
            LastResortUseCounter,
            ClaimCommitGeneration,
            ClaimedAtUnixSeconds,
            exactXpi1,
            xpi1Hash,
            InventoryEpoch,
            InventoryIndex,
            inclusionProof,
            ReplicaNodeIds,
            requiredDcb1Hash,
            requiredXps1Hash,
            requiredXpi1Hash);
}

internal sealed class ContactPreKeyStoreCorruptException : IOException
{
    internal ContactPreKeyStoreCorruptException(Exception? inner = null)
        : base("The opaque contact pre-key store is corrupt and has been quarantined.", inner)
    {
    }
}

internal static class ContactPreKeyOpaqueValue
{
    internal static byte[] CopyNonZero32(ReadOnlySpan<byte> value, string parameter)
    {
        if (value.Length != 32 || IsZero32(value))
        {
            throw new ArgumentException("A non-zero 32-byte opaque value is required.", parameter);
        }
        return value.ToArray();
    }

    internal static byte[] CopyExact(ReadOnlySpan<byte> value, int length, string parameter)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"A non-zero {length}-byte opaque value is required.", parameter);
        }
        return value.ToArray();
    }

    internal static bool IsZero32(ReadOnlySpan<byte> value) =>
        value.Length == 32 && value.IndexOfAnyExcept((byte)0) < 0;

    internal static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    internal static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(label.Length + 5 + value.Length)];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(label.Length + 1), checked((uint)value.Length));
        value.CopyTo(preimage.AsSpan(label.Length + 5));
        try
        {
            return SHA256.HashData(preimage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
        }
    }
}

internal sealed class ByteArrayComparer : IComparer<byte[]>
{
    internal static readonly ByteArrayComparer Instance = new();
    public int Compare(byte[]? left, byte[]? right) =>
        (left ?? []).AsSpan().SequenceCompareTo(right ?? []);
}
