using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace XNode.Core.ContactPreKey;

internal sealed partial class DeepIdV2InventoryCommitStore
{
    // Local reservation custody only. No peer protocol, XPC1 receipt or quorum
    // authority is minted here. The runtime must independently verify current
    // DCA1, placement, both XIC1 and the selected coordinator before calling.
    private static ReadOnlySpan<byte> ClaimPrefix => [0x00, 0xd2, 0x43, 0x52];
    private const string ClaimStateDomain = "Deep/XNode/V2/prekey-claim-reservations";
    private const int ClaimHeaderLength = 90;
    private const int MaximumClaimReservations = 4096;
    private const int MaximumClaimStateBytes = 96 * 1024 * 1024;
    private bool claimWriteUncertain;

    /// <summary>Selected coordinator only; runtime authority must precede this local CAS.</summary>
    internal DeepIdV2ClaimProposal PrepareNextClaim(ParsedXpk1V2 request,
        ulong trustedLowerUnixSeconds, ulong trustedUpperUnixSeconds,
        Func<byte[], byte[]> signNodeData)
    {
        lock (custodyGate)
        {
            EnsureAvailable();
            ArgumentNullException.ThrowIfNull(request);
            var inventory = ReadState().LastOrDefault()?.Publication ??
                throw new InvalidOperationException("DID2 service has no retained inventory.");
            var reservations = ReadClaimReservations();
            var generation = U64(inventory.Manifest.Field(5).Span);
            var prior = reservations.SingleOrDefault(item =>
                U64(item.Manifest.Field(5).Span) == generation &&
                Fixed(item.Request.Field(2).Span, request.Field(2).Span));
            if (prior is not null)
            {
                if (!Fixed(prior.Request.CanonicalBytes.Span, request.CanonicalBytes.Span))
                    throw new DeepIdV2ClaimConflictException(prior.Request.RequestHash.Span, request.RequestHash.Span);
                return Proposal(prior);
            }
            // Do not skip an uncertain earlier generation at the other replica.
            // Reconcile that exact operation instead of allowing a new selection.
            if (reservations.Any(item => item.CommittedResult is null))
                throw new IOException("DID2 claim has an earlier unresolved reservation.");
            var reserved = reservations.Where(item => item.Offering.Kind == Dpk2PrekeyKind.OneTime)
                .Select(item => Convert.ToHexString(item.Offering.OneTimePrekeyId.Span))
                .ToHashSet(StringComparer.Ordinal);
            var offering = inventory.OneTimeMembers.FirstOrDefault(member =>
                member.NotBefore <= trustedLowerUnixSeconds && member.ExpiresAt > trustedUpperUnixSeconds &&
                !reserved.Contains(Convert.ToHexString(member.OneTimePrekeyId.Span))) ?? inventory.LastResortMember;
            var counter = offering.Kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : checked((ushort)(1 +
                reservations.Count(item => U64(item.Manifest.Field(5).Span) == generation &&
                    item.Offering.Kind == Dpk2PrekeyKind.LastResort)));
            var next = new ClaimReservation(request, offering, inventory.Manifest,
                reservations.Length == 0 ? 1UL : checked(reservations[^1].Generation + 1), counter);
            _ = ReserveClaimProposalCore(request, offering, next.Manifest, next.Generation,
                counter, trustedLowerUnixSeconds, trustedUpperUnixSeconds, signNodeData);
            return Proposal(next);
        }
    }

    /// <summary>
    /// Durably reserves the exact externally selected proposal. Pending keys
    /// stay consumed after restart/expiry/lost responses; they are never freed
    /// on timeout. This is not a committed XPC1 or permission to send DPH2.
    /// </summary>
    internal DeepIdV2LocalClaimReservation ReserveClaimProposal(
        ParsedXpk1V2 request, ParsedDpk2V2 offering, ParsedXpi1V2 manifest,
        ulong commitGeneration, ushort lastResortCounter,
        ulong trustedLowerUnixSeconds, ulong trustedUpperUnixSeconds,
        Func<byte[], byte[]> signNodeData)
    {
        lock (custodyGate)
            return ReserveClaimProposalCore(request, offering, manifest, commitGeneration,
                lastResortCounter, trustedLowerUnixSeconds, trustedUpperUnixSeconds, signNodeData);
    }

    private DeepIdV2LocalClaimReservation ReserveClaimProposalCore(
        ParsedXpk1V2 request, ParsedDpk2V2 offering, ParsedXpi1V2 manifest,
        ulong commitGeneration, ushort lastResortCounter,
        ulong trustedLowerUnixSeconds, ulong trustedUpperUnixSeconds,
        Func<byte[], byte[]> signNodeData)
    {
        EnsureAvailable();
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(offering);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(signNodeData);
        var proposal = new ClaimReservation(request, offering, manifest,
            commitGeneration, lastResortCounter);
        ValidateClaimScope(proposal);
        var reservations = ReadClaimReservations();
        var prior = reservations.SingleOrDefault(item =>
            U64(item.Manifest.Field(5).Span) == U64(manifest.Field(5).Span) &&
            Fixed(item.Request.Field(2).Span, request.Field(2).Span));
        if (prior is not null)
        {
            if (!SameProposal(prior, proposal))
                throw new InvalidOperationException("DID2 claim operation has a conflicting exact proposal.");
            return LocalResult(prior, exactReplay: true);
        }

        if (trustedLowerUnixSeconds > trustedUpperUnixSeconds ||
            trustedLowerUnixSeconds < U64(request.Field(5).Span) ||
            trustedLowerUnixSeconds < offering.NotBefore ||
            trustedUpperUnixSeconds >= U64(request.Field(6).Span) ||
            trustedUpperUnixSeconds >= offering.ExpiresAt)
            throw new InvalidOperationException("DID2 claim proposal is outside its signed validity.");
        var slots = ReadState();
        var inventory = slots.SingleOrDefault(slot => Fixed(
            slot.Manifest.CanonicalBytes.Span, manifest.CanonicalBytes.Span));
        if (inventory is null ||
            !(offering.Kind == Dpk2PrekeyKind.OneTime
                ? inventory.Publication.OneTimeMembers.Any(member => Fixed(
                    member.CanonicalBytes.Span, offering.CanonicalBytes.Span))
                : Fixed(inventory.Publication.LastResortMember.CanonicalBytes.Span,
                    offering.CanonicalBytes.Span)))
            throw new UnauthorizedAccessException("DID2 claim proposal is not in retained local inventory.");
        var reservedIds = reservations.Where(item => item.Offering.Kind == Dpk2PrekeyKind.OneTime)
            .Select(item => Convert.ToHexString(item.Offering.OneTimePrekeyId.Span)).ToHashSet(StringComparer.Ordinal);
        if (offering.Kind == Dpk2PrekeyKind.LastResort &&
            inventory.Publication.OneTimeMembers.Any(member =>
                member.NotBefore <= trustedLowerUnixSeconds &&
                member.ExpiresAt > trustedUpperUnixSeconds &&
                !reservedIds.Contains(Convert.ToHexString(member.OneTimePrekeyId.Span))))
            throw new InvalidOperationException("DID2 last-resort proposal precedes one-time inventory exhaustion.");
        ValidateNextReservation(reservations, proposal);
        if (reservations.Length >= MaximumClaimReservations)
            throw new InvalidOperationException("DID2 claim reservation custody is at capacity.");

        ClaimReservation[] next = [.. reservations, proposal];
        return LocalResult(WriteClaimReservations(next, signNodeData)[^1], exactReplay: false);
    }

    /// <summary>
    /// Records both already-verified replica signatures against this replica's
    /// durable reservation. Read-back proves only this replica's commit; the
    /// coordinator must also obtain the other replica's durable read-back.
    /// </summary>
    internal ReadOnlyMemory<byte> CompleteClaimLocally(
        VerifiedXpc1V2ReplicaSignatures verifiedResult, Func<byte[], byte[]> signNodeData)
    {
        lock (custodyGate)
        {
            EnsureAvailable();
            ArgumentNullException.ThrowIfNull(verifiedResult);
            ArgumentNullException.ThrowIfNull(signNodeData);
            var request = DeepIdV2PreKeyClaimRequestCodec.Decode(verifiedResult.ExactRequest.Span);
            var result = DeepIdV2PreKeyClaimResultCodec.Decode(
                verifiedResult.ExactResult.Span, request.CanonicalBytes.Span);
            var proposal = new ClaimReservation(request,
                DeepIdV2Dpk2Codec.Decode(result.Field(16).Span),
                DeepIdV2PreKeyManifestCodec.Decode(result.Field(26).Span),
                U64(result.Field(24).Span),
                BinaryPrimitives.ReadUInt16BigEndian(result.Field(23).Span),
                verifiedResult.ExactResult.ToArray());
            ValidateClaimScope(proposal);
            ValidateRetainedClaimResult(proposal);
            if (!Fixed(verifiedResult.PlacementHash.Span, request.Field(4).Span))
                throw new UnauthorizedAccessException("DID2 completed claim has another verified placement.");
            var reservations = ReadClaimReservations();
            var index = Array.FindIndex(reservations, item => SameProposal(item, proposal));
            if (index < 0)
                throw new UnauthorizedAccessException("DID2 completed claim has no matching durable reservation.");
            if (reservations[index].CommittedResult is { } committed)
            {
                // Status/time are projections outside the signed tuple. Preserve
                // the first exact completed result on a verified logical replay.
                return committed.ToArray();
            }
            reservations[index] = proposal;
            return WriteClaimReservations(reservations, signNodeData)[index].CommittedResult!.ToArray();
        }
    }

    /// <summary>Runtime calls only after independently verified peer completion
    /// and local durable read-back disagree. Preserve both journals for repair.</summary>
    internal void LatchClaimCompletionFork()
    {
        lock (custodyGate)
        {
            EnsureAvailable();
            WriteFile("fork.marker", [1]);
            throw new InvalidDataException("DID2 completed claim replicas diverged; custody is fork-latched.");
        }
    }

    private ClaimReservation[] WriteClaimReservations(ClaimReservation[] next,
        Func<byte[], byte[]> signNodeData)
    {
        var bytes = EncodeClaimReservations(next, signNodeData);
        try
        {
            // Mark before the first replace. Missing state after this point is
            // uncertain custody, not a fresh service that can reuse the key.
            if (!File.Exists(PathFor("claims-activated.marker")))
                WriteFile("claims-activated.marker", [1]);
            WriteFile("claims.state", bytes);
            var retained = ReadClaimReservations();
            if (retained.Length != next.Length || retained.Where((item, index) =>
                    !SameProposal(item, next[index]) ||
                    !Fixed(item.CommittedResult ?? [], next[index].CommittedResult ?? [])).Any())
                throw new IOException("DID2 claim proposal changed before durable read-back.");
            return retained;
        }
        catch
        {
            claimWriteUncertain = true;
            throw;
        }
    }

    private ClaimReservation[] ReadClaimReservations()
    {
        var path = PathFor("claims.state");
        if (!File.Exists(path))
        {
            if (File.Exists(PathFor("claims-activated.marker")))
                Fault("DID2 claim custody lost or never completed its activated state.");
            return [];
        }
        try
        {
            security.ValidateSecureFile(path);
            RejectExistingLinks(path);
            var info = new FileInfo(path);
            if (info.Length < ClaimHeaderLength + StateSignatureLength ||
                info.Length > MaximumClaimStateBytes)
                throw new InvalidDataException("DID2 claim custody has an invalid size.");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length != info.Length)
                throw new InvalidDataException("DID2 claim custody changed while opening.");
            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1 ||
                !bytes.AsSpan(0, 4).SequenceEqual(ClaimPrefix) ||
                BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(4, 2)) != 2 ||
                !Fixed(bytes.AsSpan(6, 16), networkId) ||
                !Fixed(bytes.AsSpan(22, 32), serviceCapability) ||
                !Fixed(bytes.AsSpan(54, 32), localReplicaId) ||
                !PublicKeyAuth.VerifyDetached(bytes.AsSpan(^StateSignatureLength).ToArray(),
                    HashDomain(ClaimStateDomain, bytes.AsSpan(0, bytes.Length - StateSignatureLength)),
                    localReplicaId))
                throw new InvalidDataException("DID2 claim custody has invalid scope or signature.");
            var count = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(86, 4));
            if (count is < 1 or > MaximumClaimReservations)
                throw new InvalidDataException("DID2 claim custody count is outside its bound.");
            var state = new List<ClaimReservation>(checked((int)count));
            var index = new ClaimReservationIndex();
            var offset = ClaimHeaderLength;
            var end = bytes.Length - StateSignatureLength;
            for (var i = 0; i < count; i++)
            {
                const int fixedLength = DeepIdV2PreKeyClaimRequestCodec.CanonicalLength +
                    DeepIdV2PreKeyManifestCodec.CanonicalLength + 8 + 2 + 4 + 4;
                if (end - offset < fixedLength)
                    throw new InvalidDataException("DID2 claim custody entry is truncated.");
                var request = DeepIdV2PreKeyClaimRequestCodec.Decode(bytes.AsSpan(offset,
                    DeepIdV2PreKeyClaimRequestCodec.CanonicalLength));
                offset += DeepIdV2PreKeyClaimRequestCodec.CanonicalLength;
                var manifest = DeepIdV2PreKeyManifestCodec.Decode(bytes.AsSpan(offset,
                    DeepIdV2PreKeyManifestCodec.CanonicalLength));
                offset += DeepIdV2PreKeyManifestCodec.CanonicalLength;
                var generation = U64(bytes.AsSpan(offset, 8));
                offset += 8;
                var counter = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset, 2));
                offset += 2;
                var length = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset, 4));
                offset += 4;
                if (length > end - offset - 4 || length > 4096)
                    throw new InvalidDataException("DID2 claim offering exceeds its bound.");
                var offering = DeepIdV2Dpk2Codec.Decode(bytes.AsSpan(offset, checked((int)length)));
                offset += checked((int)length);
                var resultLength = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset, 4));
                offset += 4;
                if (resultLength is not (0 or 4096 or 16384) || resultLength > end - offset)
                    throw new InvalidDataException("DID2 completed claim exceeds its closed bound.");
                var result = resultLength == 0 ? null : bytes.AsSpan(offset, (int)resultLength).ToArray();
                offset += (int)resultLength;
                var item = new ClaimReservation(request, offering, manifest, generation, counter, result);
                ValidateClaimScope(item);
                ValidateRetainedClaimResult(item);
                index.Add(item);
                state.Add(item);
            }
            if (offset != end)
                throw new InvalidDataException("DID2 claim custody has trailing bytes.");
            return state.ToArray();
        }
        catch (Exception exception) when (exception is FormatException or InvalidDataException or IOException or
            UnauthorizedAccessException or CryptographicException or InvalidOperationException)
        {
            Fault("DID2 claim custody is corrupt or inconsistent.", exception);
            throw;
        }
    }

    private void ValidateClaimScope(ClaimReservation item)
    {
        if (!Fixed(item.Request.Field(1).Span, networkId) ||
            !Fixed(item.Request.Field(16).Span, serviceCapability))
            throw new UnauthorizedAccessException("DID2 claim proposal belongs to another service.");
        _ = DeepIdV2PreKeyClaimCommitment.CreateTuple(item.Request.CanonicalBytes.Span,
            item.Offering.CanonicalBytes.Span, item.Manifest.CanonicalBytes.Span,
            item.Generation, item.Counter);
        if (item.Offering.Kind == Dpk2PrekeyKind.LastResort &&
            !Fixed(item.Offering.ExactHash.Span, item.Manifest.Field(11).Span))
            throw new CryptographicException("DID2 last-resort proposal differs from the signed manifest.");
    }

    private static void ValidateNextReservation(IReadOnlyList<ClaimReservation> prior,
        ClaimReservation next)
    {
        var index = new ClaimReservationIndex();
        foreach (var item in prior) index.Add(item);
        index.Add(next);
    }

    private void ValidateRetainedClaimResult(ClaimReservation item)
    {
        if (item.CommittedResult is not { } wire) return;
        var result = DeepIdV2PreKeyClaimResultCodec.Decode(wire, item.Request.CanonicalBytes.Span);
        if (result.Status is not (Xpc1V2Status.Claimed or Xpc1V2Status.Replay) ||
            result.MutationOutcome != Xpc1V2MutationOutcome.DurablyCommitted ||
            !SameProposal(item, new(item.Request,
                DeepIdV2Dpk2Codec.Decode(result.Field(16).Span),
                DeepIdV2PreKeyManifestCodec.Decode(result.Field(26).Span),
                U64(result.Field(24).Span),
                BinaryPrimitives.ReadUInt16BigEndian(result.Field(23).Span))))
            throw new InvalidDataException("DID2 completed claim differs from its durable proposal.");
        var rows = result.Field(25).Span;
        ReadOnlySpan<byte> local = Fixed(rows.Slice(1, 32), localReplicaId)
            ? rows.Slice(1, 96) : rows.Slice(97, 96);
        var input = DeepIdV2PreKeyClaimCommitment.CreateReplicaSignatureInput(
            item.Request.CanonicalBytes.Span, item.Offering.CanonicalBytes.Span,
            item.Manifest.CanonicalBytes.Span, item.Generation, item.Counter);
        if (!Fixed(local[..32], localReplicaId) ||
            !PublicKeyAuth.VerifyDetached(local[32..].ToArray(), input, localReplicaId))
            throw new InvalidDataException("DID2 completed claim is not signed by this replica.");
    }

    private byte[] EncodeClaimReservations(IReadOnlyList<ClaimReservation> entries,
        Func<byte[], byte[]> signNodeData)
    {
        using var stream = new MemoryStream();
        var header = new byte[ClaimHeaderLength];
        ClaimPrefix.CopyTo(header);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), 2);
        networkId.CopyTo(header, 6);
        serviceCapability.CopyTo(header, 22);
        localReplicaId.CopyTo(header, 54);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(86), checked((uint)entries.Count));
        stream.Write(header);
        foreach (var entry in entries)
        {
            stream.Write(entry.Request.CanonicalBytes.Span);
            stream.Write(entry.Manifest.CanonicalBytes.Span);
            stream.Write(U64Bytes(entry.Generation));
            var trailer = new byte[6];
            BinaryPrimitives.WriteUInt16BigEndian(trailer, entry.Counter);
            var offering = entry.Offering.CanonicalBytes;
            BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), checked((uint)offering.Length));
            stream.Write(trailer);
            stream.Write(offering.Span);
            var length = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(length,
                checked((uint)(entry.CommittedResult?.Length ?? 0)));
            stream.Write(length);
            if (entry.CommittedResult is { } committed) stream.Write(committed);
        }
        if (stream.Length + StateSignatureLength > MaximumClaimStateBytes)
            throw new InvalidOperationException("DID2 claim reservation custody exceeds its byte capacity.");
        var input = HashDomain(ClaimStateDomain, stream.ToArray());
        var signature = signNodeData(input);
        if (signature is null || signature.Length != StateSignatureLength ||
            !PublicKeyAuth.VerifyDetached(signature, input, localReplicaId))
            throw new CryptographicException("DID2 claim snapshot signer differs from the local replica.");
        stream.Write(signature);
        return stream.ToArray();
    }

    private static bool SameProposal(ClaimReservation left, ClaimReservation right) =>
        left.Generation == right.Generation && left.Counter == right.Counter &&
        Fixed(left.Request.CanonicalBytes.Span, right.Request.CanonicalBytes.Span) &&
        Fixed(left.Offering.CanonicalBytes.Span, right.Offering.CanonicalBytes.Span) &&
        Fixed(left.Manifest.CanonicalBytes.Span, right.Manifest.CanonicalBytes.Span);

    private static DeepIdV2LocalClaimReservation LocalResult(ClaimReservation item, bool exactReplay) =>
        new(exactReplay, DeepIdV2PreKeyClaimCommitment.CreateTuple(
            item.Request.CanonicalBytes.Span, item.Offering.CanonicalBytes.Span,
            item.Manifest.CanonicalBytes.Span, item.Generation, item.Counter));

    private static DeepIdV2ClaimProposal Proposal(ClaimReservation item) => new(
        item.Request, item.Offering, item.Manifest, item.Generation, item.Counter,
        item.CommittedResult ?? []);

    private sealed record ClaimReservation(ParsedXpk1V2 Request, ParsedDpk2V2 Offering,
        ParsedXpi1V2 Manifest, ulong Generation, ushort Counter, byte[]? CommittedResult = null);

    private sealed class ClaimReservationIndex
    {
        private ulong generation;
        private readonly HashSet<(ulong Service, string Operation)> operations = [];
        private readonly HashSet<string> oneTimeIds = new(StringComparer.Ordinal);
        private readonly Dictionary<ulong, ushort> lastResortCounters = [];

        internal void Add(ClaimReservation item)
        {
            var service = U64(item.Manifest.Field(5).Span);
            if (item.Generation != checked(generation + 1) ||
                !operations.Add((service, Convert.ToHexString(item.Request.Field(2).Span))))
                throw new InvalidOperationException("DID2 claim proposal conflicts with the reservation generation.");
            if (item.Offering.Kind == Dpk2PrekeyKind.OneTime)
            {
                if (!oneTimeIds.Add(Convert.ToHexString(item.Offering.OneTimePrekeyId.Span)))
                    throw new InvalidOperationException("DID2 one-time key is already reserved.");
            }
            else
            {
                lastResortCounters.TryGetValue(service, out var previous);
                if (item.Counter != previous + 1)
                    throw new InvalidOperationException("DID2 last-resort counter is not its durable successor.");
                lastResortCounters[service] = item.Counter;
            }
            generation = item.Generation;
        }
    }
}

internal sealed class DeepIdV2ClaimProposal(ParsedXpk1V2 request, ParsedDpk2V2 offering,
    ParsedXpi1V2 manifest, ulong generation, ushort counter, ReadOnlyMemory<byte> completedResult = default)
{
    private readonly byte[] completed = completedResult.ToArray();
    internal ParsedXpk1V2 Request { get; } = request;
    internal ParsedDpk2V2 Offering { get; } = offering;
    internal ParsedXpi1V2 Manifest { get; } = manifest;
    internal ulong Generation { get; } = generation;
    internal ushort Counter { get; } = counter;
    internal ReadOnlyMemory<byte> CompletedResult => completed.ToArray();
}

internal sealed class DeepIdV2ClaimConflictException : InvalidOperationException
{
    private readonly byte[] evidence;
    internal DeepIdV2ClaimConflictException(ReadOnlySpan<byte> previous, ReadOnlySpan<byte> current)
        : base("DID2 claim operation has a different exact request.")
    {
        var bytes = new byte[64]; previous.CopyTo(bytes); current.CopyTo(bytes.AsSpan(32));
        evidence = SHA256.HashData(bytes);
    }
    internal ReadOnlyMemory<byte> EvidenceHash => evidence.ToArray();
}

/// <summary>Local reservation read-back, never a two-replica claim receipt.</summary>
internal sealed class DeepIdV2LocalClaimReservation(bool exactReplay, byte[] tuple)
{
    internal bool ExactReplay { get; } = exactReplay;
    internal ReadOnlyMemory<byte> Tuple => tuple.ToArray();
}
