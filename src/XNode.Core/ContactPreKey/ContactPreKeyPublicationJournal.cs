using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace XNode.Core.ContactPreKey;

internal sealed record ContactPreKeyPublicationApplyResult(
    PreKeyPublicationReplicaTransition Transition,
    Xic1BoundedReceipt? StoredReceipt,
    Xic1BoundedUnsignedFields? UnsignedReceipt);

internal sealed record ContactPreKeyPublicationCommitContext(
    PreKeyPublicationReplicaTransition Transition,
    ReadOnlyMemory<byte> ServiceCapability,
    ReadOnlyMemory<byte> PredecessorExactXpi1,
    ReadOnlyMemory<byte> PredecessorXpi1Hash);

internal sealed partial class ContactPreKeyOpaqueStore
{
    private const string PublicationStateHashDomain =
        "Deep/XNode/V1/contact-prekey-publication-journal";

    internal ReadOnlyMemory<byte> ResolvePublicationServiceCapability(
        Xpp1BoundedRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfUnavailable();
            if (request is Xpp1ManifestRequest manifest)
            {
                return manifest.Manifest.ServiceCapability.ToArray();
            }
            return FindPublication(request)?.ServiceCapability.ToArray()
                ?? throw new InvalidOperationException(
                    "A bounded XPP1 chunk or commit has no durable manifest journal.");
        }
    }

    internal ContactPreKeyPublicationApplyResult ApplyPublicationStage(
        Xpp1BoundedRequest request,
        ReadOnlySpan<byte> replicaId32,
        ulong receiptAtUnixSeconds,
        Func<Xic1BoundedUnsignedFields, byte[]> signReceipt)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signReceipt);
        ValidateReplicaReceiptInputs(request, replicaId32, receiptAtUnixSeconds);
        lock (gate)
        {
            ThrowIfUnavailable();
            var journal = FindPublication(request);
            var stored = FindStoredReceipt(journal, request.RequestHash.Span);
            if (stored is not null)
            {
                return new(
                    Rebuild(journal!).Apply(request),
                    Xic1BoundedCodec.Decode(stored.ExactReceipt),
                    null);
            }

            var current = journal is null
                ? PreKeyPublicationReplicaState.Empty
                : Rebuild(journal);
            var transition = current.Apply(request);
            if (transition.Disposition == PreKeyPublicationReplicaDisposition.ReadyToVerify)
            {
                return new(transition, null, null);
            }

            var (status, outcome) = ReceiptDisposition(transition.Disposition);
            var durable = transition.RequiresDurableWrite;
            if (durable)
            {
                journal ??= CreatePublication(request);
                if (!transition.RequiresStoredReceipt)
                {
                    journal.ExactRequests.Add(request.CanonicalBytes.ToArray());
                }
                journal.ForkLatched = transition.NextState.IsForkLatched;
            }

            var stateHash = ComputePublicationStateHash(journal, request);
            var unsigned = new Xic1BoundedUnsignedFields(
                request,
                status,
                outcome,
                transition.NextState.AcceptedChunkCount,
                transition.NextState.AcceptedTotalLength,
                replicaId32,
                receiptAtUnixSeconds,
                stateHash);
            if (!durable)
            {
                return new(transition, null, unsigned);
            }

            var exactReceipt = signReceipt(unsigned);
            var decoded = Xic1BoundedCodec.Decode(exactReceipt);
            EnsureReceiptBinds(decoded, request, replicaId32);
            journal!.Receipts.Add(new PublicationReceiptState
            {
                RequestHash = request.RequestHash.ToArray(),
                ExactReceipt = exactReceipt.ToArray()
            });
            CanonicalizePublications();
            SaveState();
            return new(transition, decoded, null);
        }
    }

    internal ContactPreKeyPublicationCommitContext ReadPublicationCommit(
        Xpp1CommitRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfUnavailable();
            var journal = FindPublication(request)
                ?? throw new InvalidOperationException("The bounded XPP1 commit has no durable manifest journal.");
            var transition = Rebuild(journal).Apply(request);
            if (transition.Disposition != PreKeyPublicationReplicaDisposition.ReadyToVerify)
            {
                throw new InvalidOperationException("The bounded XPP1 commit is not ready for verification.");
            }
            var capability = FindCapability(journal.ServiceCapability);
            var predecessor = capability?.Inventories.LastOrDefault();
            return new(
                transition,
                journal.ServiceCapability.ToArray(),
                predecessor?.ExactXpi1.ToArray() ?? [],
                predecessor?.Xpi1Hash.ToArray() ?? []);
        }
    }

    internal Xic1BoundedUnsignedFields ActivatePublication(
        Xpp1CommitRequest request,
        VerifiedPreKeyInventoryInstallationPlan plan,
        IReadOnlyList<ReadOnlyMemory<byte>> replicaNodeIds,
        ReadOnlySpan<byte> localReplicaId32,
        ulong receiptAtUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(replicaNodeIds);
        ValidateReplicaReceiptInputs(request, localReplicaId32, receiptAtUnixSeconds);
        lock (gate)
        {
            ThrowIfUnavailable();
            var journal = FindPublication(request)
                ?? throw new InvalidOperationException("The verified bounded XPP1 commit has no durable journal.");
            var priorRequests = journal.ExactRequests.Count;
            var priorActivated = journal.Activated;
            var priorReceiptAt = journal.CommitReceiptAtUnixSeconds;
            var priorHash = journal.ActivatedStateHash.ToArray();
            var transition = Rebuild(journal).Apply(request);
            if (transition.Disposition == PreKeyPublicationReplicaDisposition.ExactReplay
                && journal.Activated)
            {
                return CommitUnsigned(
                    request,
                    journal,
                    localReplicaId32,
                    journal.CommitReceiptAtUnixSeconds);
            }
            if (transition.Disposition != PreKeyPublicationReplicaDisposition.ReadyToVerify
                || !plan.CommitRequestHash.Span.SequenceEqual(request.RequestHash.Span)
                || !plan.PublicationHash.Span.SequenceEqual(request.PublicationHash.Span))
            {
                throw new InvalidOperationException("The installation plan does not bind the exact ready commit.");
            }

            var inventory = VerifiedOpaquePreKeyInventory.FromInstallationPlan(plan, replicaNodeIds);
            var expectedInstall = PreflightInventoryInstallation(inventory);
            if (expectedInstall is not (ContactPreKeyInventoryDisposition.Installed
                or ContactPreKeyInventoryDisposition.ExactReplay))
            {
                throw new InvalidOperationException(
                    $"The verified bounded inventory cannot activate: {expectedInstall}.");
            }
            journal.ExactRequests.Add(request.CanonicalBytes.ToArray());
            journal.Activated = true;
            journal.CommitReceiptAtUnixSeconds = receiptAtUnixSeconds;
            journal.ActivatedStateHash = plan.ActivatedStateHash.ToArray();
            try
            {
                var install = InstallVerifiedInventory(inventory);
                if (install.Disposition is not (ContactPreKeyInventoryDisposition.Installed
                    or ContactPreKeyInventoryDisposition.ExactReplay))
                {
                    throw new InvalidOperationException(
                        $"The verified bounded inventory could not activate: {install.Disposition}.");
                }
                // Installed already persisted the inventory and journal in one envelope.
                // ExactReplay may be recovery of an activated inventory whose journal write
                // was interrupted, so force the repaired journal to stable storage.
                if (install.Disposition == ContactPreKeyInventoryDisposition.ExactReplay)
                {
                    SaveState();
                }
                return CommitUnsigned(request, journal, localReplicaId32, receiptAtUnixSeconds);
            }
            catch
            {
                journal.ExactRequests.RemoveRange(priorRequests, journal.ExactRequests.Count - priorRequests);
                journal.Activated = priorActivated;
                journal.CommitReceiptAtUnixSeconds = priorReceiptAt;
                journal.ActivatedStateHash = priorHash;
                throw;
            }
        }
    }

    // Must run under gate. This mirrors the store's mutation decision without
    // changing fork latches or writing the envelope, so activation metadata is
    // never made visible by a failing inventory install branch.
    private ContactPreKeyInventoryDisposition PreflightInventoryInstallation(
        VerifiedOpaquePreKeyInventory inventory)
    {
        var now = CurrentUnixSeconds();
        ValidateServiceDeadline(inventory.ServiceExpiresAtUnixSeconds, now);
        ValidateInventoryDeadlines(inventory, now);
        var capability = FindCapability(inventory.ServiceCapability);
        if (capability is null)
        {
            if (state.Capabilities.Count >= options.MaximumCapabilities
                || TotalOpaqueBytes() + InventoryBytes(inventory) > options.MaximumOpaqueBytes)
            {
                return ContactPreKeyInventoryDisposition.QuotaExceeded;
            }
            if (HasPreKeyReuse(inventory))
            {
                return ContactPreKeyInventoryDisposition.Conflict;
            }
            return inventory.InventoryEpoch == 1
                && ContactPreKeyOpaqueValue.IsZero32(inventory.PredecessorXpi1Hash)
                    ? ContactPreKeyInventoryDisposition.Installed
                    : ContactPreKeyInventoryDisposition.StaleGeneration;
        }
        if (capability.ForkLatched)
        {
            return ContactPreKeyInventoryDisposition.ForkLatched;
        }
        var sameEpoch = capability.Inventories.FirstOrDefault(item =>
            item.InventoryEpoch == inventory.InventoryEpoch);
        if (sameEpoch is not null)
        {
            return InventoryMatches(sameEpoch, inventory)
                ? ContactPreKeyInventoryDisposition.ExactReplay
                : ContactPreKeyInventoryDisposition.Conflict;
        }
        var current = capability.Inventories.LastOrDefault();
        if (current is not null)
        {
            if (capability.Inventories.Any(item => ContactPreKeyOpaqueValue.FixedEquals(
                    item.PublicationOperationId, inventory.PublicationOperationId))
                || !ContactPreKeyOpaqueValue.FixedEquals(
                    inventory.PredecessorXpi1Hash, current.Xpi1Hash))
            {
                return ContactPreKeyInventoryDisposition.Conflict;
            }
            if (current.InventoryEpoch == ulong.MaxValue
                || inventory.InventoryEpoch != current.InventoryEpoch + 1)
            {
                return ContactPreKeyInventoryDisposition.StaleGeneration;
            }
        }
        else if (capability.LastAcceptedInventoryEpoch != 0)
        {
            if (capability.LastAcceptedInventoryEpoch == ulong.MaxValue
                || inventory.InventoryEpoch != capability.LastAcceptedInventoryEpoch + 1)
            {
                return ContactPreKeyInventoryDisposition.StaleGeneration;
            }
            if (ContactPreKeyOpaqueValue.FixedEquals(
                    capability.LastPublicationOperationId, inventory.PublicationOperationId)
                || !ContactPreKeyOpaqueValue.FixedEquals(
                    capability.LastAcceptedXpi1Hash, inventory.PredecessorXpi1Hash))
            {
                return ContactPreKeyInventoryDisposition.Conflict;
            }
        }
        if (HasPreKeyReuse(inventory))
        {
            return ContactPreKeyInventoryDisposition.Conflict;
        }
        return TotalOpaqueBytes() + InventoryBytes(inventory) > options.MaximumOpaqueBytes
            ? ContactPreKeyInventoryDisposition.QuotaExceeded
            : ContactPreKeyInventoryDisposition.Installed;
    }

    internal Xic1BoundedReceipt StoreActivatedPublicationReceipt(
        Xpp1CommitRequest request,
        ReadOnlySpan<byte> exactReceipt)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfUnavailable();
            var journal = FindPublication(request)
                ?? throw new InvalidOperationException("The activated bounded XPP1 journal is missing.");
            var existing = FindStoredReceipt(journal, request.RequestHash.Span);
            if (existing is not null)
            {
                return Xic1BoundedCodec.Decode(existing.ExactReceipt);
            }
            if (!journal.Activated)
            {
                throw new InvalidOperationException("A final XIC1 cannot precede durable local activation.");
            }
            var decoded = Xic1BoundedCodec.Decode(exactReceipt);
            EnsureReceiptBinds(decoded, request, decoded.ReplicaId.Span);
            journal.Receipts.Add(new PublicationReceiptState
            {
                RequestHash = request.RequestHash.ToArray(),
                ExactReceipt = exactReceipt.ToArray()
            });
            SaveState();
            return decoded;
        }
    }

    private static Xic1BoundedUnsignedFields CommitUnsigned(
        Xpp1CommitRequest request,
        PublicationState journal,
        ReadOnlySpan<byte> replicaId32,
        ulong receiptAtUnixSeconds) => new(
            request,
            Xic1BoundedStatus.Committed,
            Xic1BoundedMutationOutcome.DurablyActivated,
            request.ChunkCount,
            request.InventoryTotalLength,
            replicaId32,
            receiptAtUnixSeconds,
            journal.ActivatedStateHash);

    private PublicationState? FindPublication(Xpp1BoundedRequest request)
    {
        PublicationState? operationMatch = null;
        foreach (var item in state.Publications)
        {
            if (ContactPreKeyOpaqueValue.FixedEquals(
                    item.PublicationOperationId, request.PublicationOperationId.Span))
            {
                operationMatch = item;
                if (ContactPreKeyOpaqueValue.FixedEquals(item.PublicationHash, request.PublicationHash.Span))
                {
                    return item;
                }
            }
        }
        if (request is Xpp1ManifestRequest manifest)
        {
            return state.Publications.FirstOrDefault(item =>
                ContactPreKeyOpaqueValue.FixedEquals(item.EpochJournalKey, manifest.EpochJournalKey.Span))
                ?? operationMatch;
        }
        return operationMatch;
    }

    private PublicationState CreatePublication(Xpp1BoundedRequest request)
    {
        if (request is not Xpp1ManifestRequest manifest)
        {
            throw new InvalidOperationException("A bounded publication journal begins with its manifest.");
        }
        var result = new PublicationState
        {
            EpochJournalKey = manifest.EpochJournalKey.ToArray(),
            ServiceCapability = manifest.Manifest.ServiceCapability.ToArray(),
            PublicationOperationId = manifest.PublicationOperationId.ToArray(),
            PublicationHash = manifest.PublicationHash.ToArray()
        };
        state.Publications.Add(result);
        return result;
    }

    private static PreKeyPublicationReplicaState Rebuild(PublicationState journal)
    {
        var current = PreKeyPublicationReplicaState.Empty;
        foreach (var exact in journal.ExactRequests)
        {
            current = current.Apply(Xpp1BoundedCodec.Decode(exact)).NextState;
        }
        // Activated is a durable host fact minted by the sealed installation plan.
        // Protocol replay reconstructs the ordered ready transition; a missing final
        // receipt is then safely recovered by re-verifying that transition.
        if (current.IsForkLatched != journal.ForkLatched)
        {
            throw new InvalidDataException("The persisted bounded publication transition is inconsistent.");
        }
        return current;
    }

    private static PublicationReceiptState? FindStoredReceipt(
        PublicationState? journal,
        ReadOnlySpan<byte> requestHash)
    {
        if (journal is null)
        {
            return null;
        }
        foreach (var item in journal.Receipts)
        {
            if (ContactPreKeyOpaqueValue.FixedEquals(item.RequestHash, requestHash))
            {
                return item;
            }
        }
        return null;
    }

    private static byte[] ComputePublicationStateHash(
        PublicationState? journal,
        Xpp1BoundedRequest request)
    {
        if (journal is null || journal.ExactRequests.Count == 0)
        {
            return request.RequestHash.ToArray();
        }
        var hashes = journal.ExactRequests
            .Select(static exact => Xpp1BoundedCodec.Decode(exact).RequestHash.ToArray())
            .ToArray();
        var joined = new byte[checked(hashes.Length * 32)];
        for (var index = 0; index < hashes.Length; index++)
        {
            hashes[index].CopyTo(joined, index * 32);
        }
        try
        {
            return ContactPreKeyOpaqueValue.Sha256Domain(PublicationStateHashDomain, joined);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(joined);
            foreach (var hash in hashes) CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static (Xic1BoundedStatus Status, Xic1BoundedMutationOutcome Outcome)
        ReceiptDisposition(PreKeyPublicationReplicaDisposition disposition) => disposition switch
        {
            PreKeyPublicationReplicaDisposition.ManifestAccepted =>
                (Xic1BoundedStatus.ManifestStaged, Xic1BoundedMutationOutcome.DurablyStaged),
            PreKeyPublicationReplicaDisposition.ChunkAccepted =>
                (Xic1BoundedStatus.ChunkStaged, Xic1BoundedMutationOutcome.DurablyStaged),
            PreKeyPublicationReplicaDisposition.ExactReplay =>
                (Xic1BoundedStatus.ExactReplay, Xic1BoundedMutationOutcome.DurablyStaged),
            PreKeyPublicationReplicaDisposition.ForkLatched =>
                (Xic1BoundedStatus.Conflict, Xic1BoundedMutationOutcome.DurablyForkLatched),
            PreKeyPublicationReplicaDisposition.Incomplete or
            PreKeyPublicationReplicaDisposition.OutOfOrder =>
                (Xic1BoundedStatus.Incomplete, Xic1BoundedMutationOutcome.None),
            _ => (Xic1BoundedStatus.TemporarilyUnavailable, Xic1BoundedMutationOutcome.None)
        };

    private static void ValidateReplicaReceiptInputs(
        Xpp1BoundedRequest request,
        ReadOnlySpan<byte> replicaId32,
        ulong receiptAtUnixSeconds)
    {
        if (replicaId32.Length != 32
            || replicaId32.IndexOfAnyExcept((byte)0) < 0
            || receiptAtUnixSeconds < request.IssuedAtUnixSeconds
            || receiptAtUnixSeconds >= request.ExpiresAtUnixSeconds)
        {
            throw new InvalidOperationException("The local XIC1 receipt identity or trusted time is invalid.");
        }
    }

    private static void EnsureReceiptBinds(
        Xic1BoundedReceipt receipt,
        Xpp1BoundedRequest request,
        ReadOnlySpan<byte> replicaId32)
    {
        if (!receipt.RequestHash.Span.SequenceEqual(request.RequestHash.Span)
            || !receipt.PublicationHash.Span.SequenceEqual(request.PublicationHash.Span)
            || !receipt.ReplicaId.Span.SequenceEqual(replicaId32))
        {
            throw new InvalidDataException("The signed XIC1 does not bind the durable request and replica.");
        }
    }

    private static void ValidatePublicationState(PersistedState candidate, ref long opaqueBytes)
    {
        if (candidate.Publications.Count > 16_384)
        {
            throw new InvalidDataException("The bounded publication journal count is invalid.");
        }
        var epochKeys = new HashSet<string>(StringComparer.Ordinal);
        var operations = new HashSet<string>(StringComparer.Ordinal);
        byte[]? prior = null;
        foreach (var journal in candidate.Publications)
        {
            ValidateNonZero(journal.EpochJournalKey, 32);
            ValidateNonZero(journal.ServiceCapability, 32);
            ValidateNonZero(journal.PublicationOperationId, 32);
            ValidateNonZero(journal.PublicationHash, 32);
            if (prior is not null && prior.AsSpan().SequenceCompareTo(journal.EpochJournalKey) >= 0
                || !epochKeys.Add(Convert.ToHexString(journal.EpochJournalKey))
                || !operations.Add(Convert.ToHexString(journal.PublicationOperationId))
                || journal.ExactRequests.Count is < 1 or > Xpp1BoundedCodec.MaximumChunkCount + 2
                || journal.Receipts.Count > journal.ExactRequests.Count)
            {
                throw new InvalidDataException("The bounded publication journal ordering or bounds are invalid.");
            }
            prior = journal.EpochJournalKey;
            var rebuilt = Rebuild(journal);
            if (rebuilt.Manifest is null
                || !rebuilt.Manifest.EpochJournalKey.Span.SequenceEqual(journal.EpochJournalKey)
                || !rebuilt.Manifest.Manifest.ServiceCapability.Span.SequenceEqual(journal.ServiceCapability)
                || !rebuilt.Manifest.PublicationOperationId.Span.SequenceEqual(journal.PublicationOperationId)
                || !rebuilt.Manifest.PublicationHash.Span.SequenceEqual(journal.PublicationHash))
            {
                throw new InvalidDataException("The bounded publication journal manifest binding is invalid.");
            }
            var receiptHashes = new HashSet<string>(StringComparer.Ordinal);
            foreach (var receiptState in journal.Receipts)
            {
                ValidateNonZero(receiptState.RequestHash, 32);
                var receipt = Xic1BoundedCodec.Decode(receiptState.ExactReceipt);
                if (!receipt.RequestHash.Span.SequenceEqual(receiptState.RequestHash)
                    || !receiptHashes.Add(Convert.ToHexString(receiptState.RequestHash)))
                {
                    throw new InvalidDataException("The bounded publication receipt journal is invalid.");
                }
                opaqueBytes = checked(opaqueBytes + receiptState.ExactReceipt.Length);
            }
            if (journal.Activated)
            {
                ValidateNonZero(journal.ActivatedStateHash, 32);
                if (journal.CommitReceiptAtUnixSeconds == 0
                    || journal.ExactRequests[^1] is not { Length: > 0 } exactCommit
                    || Xpp1BoundedCodec.Decode(exactCommit) is not Xpp1CommitRequest)
                {
                    throw new InvalidDataException("The activated bounded publication journal is incomplete.");
                }
            }
            else if (journal.CommitReceiptAtUnixSeconds != 0 || journal.ActivatedStateHash.Length != 0)
            {
                throw new InvalidDataException("A staged bounded publication contains activation metadata.");
            }
            opaqueBytes = checked(opaqueBytes
                + journal.ExactRequests.Sum(static exact => (long)exact.Length));
        }
    }

    private void CanonicalizePublications() => state.Publications.Sort(static (left, right) =>
        left.EpochJournalKey.AsSpan().SequenceCompareTo(right.EpochJournalKey));

    private sealed class PublicationState
    {
        public byte[] EpochJournalKey { get; set; } = [];
        public byte[] ServiceCapability { get; set; } = [];
        public byte[] PublicationOperationId { get; set; } = [];
        public byte[] PublicationHash { get; set; } = [];
        public List<byte[]> ExactRequests { get; set; } = [];
        public bool Activated { get; set; }
        public bool ForkLatched { get; set; }
        public ulong CommitReceiptAtUnixSeconds { get; set; }
        public byte[] ActivatedStateHash { get; set; } = [];
        public List<PublicationReceiptState> Receipts { get; set; } = [];
    }

    private sealed class PublicationReceiptState
    {
        public byte[] RequestHash { get; set; } = [];
        public byte[] ExactReceipt { get; set; } = [];
    }
}
