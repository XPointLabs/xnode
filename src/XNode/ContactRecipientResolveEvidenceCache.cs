using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;

namespace XNode;

internal enum ContactRecipientResolveEvidenceKind : byte
{
    Permanent = 1,
    OneTime = 2
}

/// <summary>
/// Exact, untrusted inputs retained by the XNode recipient-evidence owner. The
/// cache never promotes this object directly; Protocol verification is required
/// both before commit and before every read.
/// </summary>
internal sealed class ContactRecipientResolveEvidenceSubmission
{
    internal const int MaximumAddressBytes = 4_096;
    internal const int MaximumXiq1Bytes = 4_096;
    internal const int MaximumXis1Bytes = 131_072;

    private readonly byte[] networkId;
    private readonly byte[] locatorHandle;
    private readonly byte[] exactAddress;
    private readonly byte[] exactXiq1;
    private readonly byte[] exactXis1;

    internal ContactRecipientResolveEvidenceSubmission(
        ContactRecipientResolveEvidenceKind kind,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> locatorHandle,
        ReadOnlySpan<byte> exactAddress,
        ReadOnlySpan<byte> exactXiq1,
        ReadOnlySpan<byte> exactXis1)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }
        this.networkId = RequiredOpaque(networkId, 16, nameof(networkId));
        this.locatorHandle = RequiredOpaque(locatorHandle, 32, nameof(locatorHandle));
        this.exactAddress = RequiredBounded(
            exactAddress, MaximumAddressBytes, nameof(exactAddress));
        this.exactXiq1 = RequiredBounded(exactXiq1, MaximumXiq1Bytes, nameof(exactXiq1));
        this.exactXis1 = RequiredBounded(exactXis1, MaximumXis1Bytes, nameof(exactXis1));
        Kind = kind;
    }

    internal ContactRecipientResolveEvidenceKind Kind { get; }
    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> LocatorHandle => locatorHandle.ToArray();
    internal ReadOnlyMemory<byte> ExactAddress => exactAddress.ToArray();
    internal ReadOnlyMemory<byte> ExactXiq1 => exactXiq1.ToArray();
    internal ReadOnlyMemory<byte> ExactXis1 => exactXis1.ToArray();

    private static byte[] RequiredOpaque(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                $"{name} must be exactly {length} nonzero opaque bytes.", name);
        }
        return value.ToArray();
    }

    private static byte[] RequiredBounded(ReadOnlySpan<byte> value, int maximum, string name)
    {
        if (value.IsEmpty || value.Length > maximum)
        {
            throw new ArgumentException($"{name} is outside its exact bound.", name);
        }
        return value.ToArray();
    }
}

internal interface IContactRouteRecipientResolveEvidenceOwner
{
    ValueTask ObserveAsync(
        ContactRecipientResolveEvidenceSubmission submission,
        CancellationToken cancellationToken);
}

/// <summary>
/// Bounded production-only scan used when a pre-key publication carries a
/// service capability rather than the locator that keyed the resolve cache.
/// Every returned entry has been unprotected and re-verified through Protocol
/// against the current authority snapshot during this call.
/// </summary>
internal interface IContactPreKeyRecipientResolveEvidenceSource
{
    ValueTask<IReadOnlyList<ContactPreKeyRecipientResolveEvidence>>
        ReadCurrentCandidatesAsync(
            ReadOnlyMemory<byte> networkId,
            CancellationToken cancellationToken);
}

internal sealed record ContactPreKeyRecipientResolveEvidence(
    ReadOnlyMemory<byte> LocatorHash,
    ContactRouteRecipientResolveEvidence Evidence);

internal sealed class VerifiedContactRecipientResolveObservation
{
    private readonly byte[] stableClosureHash;

    internal VerifiedContactRecipientResolveObservation(
        ContactRouteRecipientResolveEvidence evidence,
        ulong publicationGeneration,
        ulong claimCommitGeneration,
        ReadOnlySpan<byte> stableClosureHash)
    {
        if (stableClosureHash.Length != 32
            || stableClosureHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A verified recipient closure hash must be exactly 32 nonzero bytes.",
                nameof(stableClosureHash));
        }
        Evidence = evidence ?? throw new ArgumentNullException(nameof(evidence));
        PublicationGeneration = publicationGeneration;
        ClaimCommitGeneration = claimCommitGeneration;
        this.stableClosureHash = stableClosureHash.ToArray();
    }

    internal ContactRouteRecipientResolveEvidence Evidence { get; }
    internal ulong PublicationGeneration { get; }
    internal ulong ClaimCommitGeneration { get; }
    internal ReadOnlyMemory<byte> StableClosureHash => stableClosureHash.ToArray();
}

internal interface IContactRecipientResolveEvidenceVerifier
{
    ValueTask<VerifiedContactRecipientResolveObservation?> VerifyCurrentAsync(
        ContactRecipientResolveEvidenceSubmission submission,
        CancellationToken cancellationToken);
}

/// <summary>
/// Rebuilds the permanent or one-time identity closure exclusively through the
/// Protocol verification graph and the current XNode authority snapshot.
/// </summary>
internal sealed class ProtocolContactRecipientResolveEvidenceVerifier(
    IContactVerifiedAuthoritySnapshotSource snapshots,
    IOnionMonotonicClock monotonicClock)
    : IContactRecipientResolveEvidenceVerifier
{
    private const string OneTimeLocatorDomain =
        "Deep/ContactResolver/V1/one-time-locator";

    private readonly IContactVerifiedAuthoritySnapshotSource snapshots =
        snapshots ?? throw new ArgumentNullException(nameof(snapshots));
    private readonly IOnionMonotonicClock monotonicClock =
        monotonicClock ?? throw new ArgumentNullException(nameof(monotonicClock));

    public async ValueTask<VerifiedContactRecipientResolveObservation?> VerifyCurrentAsync(
        ContactRecipientResolveEvidenceSubmission submission,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(submission);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var request = Xiq1Codec.Decode(submission.ExactXiq1.Span);
            var result = Xis1Codec.Decode(
                submission.ExactXis1.Span, request.CanonicalBytes.Span);
            RequireSame(submission.NetworkId.Span, request.NetworkId.Span);
            RequireSame(submission.LocatorHandle.Span, request.LocatorHash.Span);

            ParsedDid1? did1 = null;
            ContactRecord? dia1 = null;
            if (submission.Kind == ContactRecipientResolveEvidenceKind.Permanent)
            {
                did1 = ApplicationCoreCodec.DecodeDid1(submission.ExactAddress.Span);
                using var resolution = PermanentContactResolutionDerivation.Derive(
                    submission.NetworkId.Span, did1);
                RequireSame(submission.LocatorHandle.Span, resolution.LocatorHash.Span);
            }
            else
            {
                dia1 = ContactCodec.Decode("DIA1", submission.ExactAddress.Span);
                RequireSame(submission.NetworkId.Span, dia1.Field(1).Span);
                var derived = Sha256Domain(OneTimeLocatorDomain, dia1.Field(5).Span);
                try
                {
                    RequireSame(submission.LocatorHandle.Span, derived);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(derived);
                }
            }

            var snapshot = await snapshots.ReadCurrentAsync(cancellationToken)
                .ConfigureAwait(false);
            snapshot.EnsureConsistent();
            RequireSame(submission.NetworkId.Span, snapshot.Network.NetworkId.Span);
            var placement = ContactServicePlacementFactory.Create(
                snapshot.Network,
                ContactServiceRequestKind.ResolveInvite,
                submission.LocatorHandle);
            var reading = await monotonicClock.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            if (reading is null)
            {
                return null;
            }

            if (submission.Kind == ContactRecipientResolveEvidenceKind.Permanent)
            {
                var closure = PermanentContactResolveVerifier.Verify(
                    did1!, request, result, result.Field(19),
                    snapshot.DirectoryFreshness, placement,
                    reading.BootId.Span, reading.SampleSeconds);
                var stableHash = StableClosureHash(
                    submission.Kind, result, closure.PublicationGeneration, 0);
                try
                {
                    return new(
                        ContactRouteRecipientResolveEvidence.FromPermanent(closure),
                        closure.PublicationGeneration,
                        0,
                        stableHash);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(stableHash);
                }
            }

            var claim = Xis1InviteClaimReceiptVerifier.Verify(request, result, placement);
            var oneTime = ContactClaimClosureVerifier.VerifyOneTimeClaim(
                claim, dia1!, snapshot.DirectoryFreshness,
                reading.BootId.Span, reading.SampleSeconds);
            var oneTimeStableHash = StableClosureHash(
                submission.Kind,
                result,
                claim.PublicationGeneration,
                claim.ClaimCommitGeneration);
            try
            {
                return new(
                    ContactRouteRecipientResolveEvidence.FromOneTime(oneTime),
                    claim.PublicationGeneration,
                    claim.ClaimCommitGeneration,
                    oneTimeStableHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oneTimeStableHash);
            }
        }
        catch (Exception exception) when (ExpectedRejection(exception))
        {
            return null;
        }
    }

    private static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(label.Length + 5 + payload.Length)];
        try
        {
            label.CopyTo(preimage, 0);
            BinaryPrimitives.WriteUInt32BigEndian(
                preimage.AsSpan(label.Length + 1), checked((uint)payload.Length));
            payload.CopyTo(preimage.AsSpan(label.Length + 5));
            return SHA256.HashData(preimage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(label);
            CryptographicOperations.ZeroMemory(preimage);
        }
    }

    private static byte[] StableClosureHash(
        ContactRecipientResolveEvidenceKind kind,
        Xis1Result result,
        ulong publicationGeneration,
        ulong claimCommitGeneration)
    {
        // XIS1 route-closure bytes may legitimately advance independently of a
        // DCB1 publication. Their monotonic lineage is enforced by the existing
        // FileContactRouteClosureLineageStore after full route verification.
        // This cache latches only a same-generation recipient publication fork.
        var input = new byte[1 + 8 + 8 + 8 + 32];
        input[0] = (byte)kind;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(1), publicationGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(
            input.AsSpan(9), BinaryPrimitives.ReadUInt64BigEndian(result.Field(17).Span));
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(17), claimCommitGeneration);
        result.Field(18).Span.CopyTo(input.AsSpan(25, 32));
        try
        {
            return Sha256Domain(
                "Deep/XNode/ContactRecipientResolveEvidence/closure/V1", input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static void RequireSame(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        if (expected.Length != actual.Length
            || !CryptographicOperations.FixedTimeEquals(expected, actual))
        {
            throw new CryptographicException(
                "The recipient resolve evidence does not bind its opaque selector.");
        }
    }

    private static bool ExpectedRejection(Exception exception) =>
        exception is ContactFormatException
            or PermanentContactResolveException
            or Xis1InviteClaimReceiptException
            or ContactClaimClosureException
            or CryptographicException
            or ArgumentException
            or InvalidOperationException
            or OverflowException;
}

internal sealed record ProductionContactRecipientEvidenceCacheConfiguration(
    string StatePath,
    int MaximumProtectedStateBytes,
    int MaximumEntries)
{
    internal static ProductionContactRecipientEvidenceCacheConfiguration FromRouteClosure(
        ProductionContactRouteClosureConfiguration route)
    {
        ArgumentNullException.ThrowIfNull(route);
        var directory = Path.GetDirectoryName(route.StatePath)
            ?? throw new InvalidOperationException("The Contact route LKG has no parent directory.");
        return new(
            Path.Combine(directory, "recipient-resolve-evidence-v1.bin"),
            route.MaximumProtectedStateBytes,
            Math.Min(4_096, Math.Max(16, route.MaximumProtectedStateBytes / 4_096)));
    }
}

/// <summary>
/// Durable bounded owner/cache. The outer state and each evidence envelope are
/// separately authenticated and protected; retained in-memory state contains no
/// DID1, DIA1, account, device, XIQ1 or XIS1 plaintext.
/// </summary>
internal sealed class FileContactRecipientResolveEvidenceCache
    : IContactRouteRecipientResolveClosureSource,
      IContactRouteRecipientResolveEvidenceOwner,
      IContactPreKeyRecipientResolveEvidenceSource,
      IDisposable
{
    private const ushort StateVersion = 1;
    private static ReadOnlySpan<byte> StateMagic => "CRV1"u8;
    private static ReadOnlySpan<byte> EvidenceMagic => "CRE1"u8;
    private const int MaximumProtectedEvidenceBytes = 384 * 1024;
    private readonly ProductionContactRecipientEvidenceCacheConfiguration configuration;
    private readonly IContactRecipientResolveEvidenceVerifier verifier;
    private readonly IDataProtector stateProtector;
    private readonly IDataProtector evidenceProtector;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<string, RecipientState> states = new(StringComparer.Ordinal);
    private bool initialized;
    private bool faulted;
    private bool disposed;

    internal FileContactRecipientResolveEvidenceCache(
        ProductionContactRecipientEvidenceCacheConfiguration configuration,
        IContactRecipientResolveEvidenceVerifier verifier,
        IDataProtectionProvider protection,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        this.configuration = configuration
            ?? throw new ArgumentNullException(nameof(configuration));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        var provider = protection ?? throw new ArgumentNullException(nameof(protection));
        stateProtector = provider.CreateProtector(
            "Deep.XNode.ContactRecipientResolveEvidence.State.V1");
        evidenceProtector = provider.CreateProtector(
            "Deep.XNode.ContactRecipientResolveEvidence.Entry.V1");
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ?? throw new ArgumentNullException(nameof(durability));
        ValidateConfiguration(configuration);
        var stateDirectory = Path.GetDirectoryName(configuration.StatePath)!;
        this.security.SecureDirectory(stateDirectory);
        EnsureRegularPath(stateDirectory, expectFile: false);
    }

    internal string StatePath => configuration.StatePath;

    internal async ValueTask InitializeAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            InitializeCore(cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask ObserveAsync(
        ContactRecipientResolveEvidenceSubmission submission,
        CancellationToken cancellationToken)
    {
        ThrowIfUnavailable();
        ArgumentNullException.ThrowIfNull(submission);
        var verified = await verifier.VerifyCurrentAsync(submission, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Recipient resolve evidence was not current and independently verifiable.");
        var addressHash = SHA256.HashData(submission.ExactAddress.Span);
        var evidenceHash = ComputeEvidenceHash(submission);
        var stableClosureHash = verified.StableClosureHash.ToArray();
        byte[]? protectedEvidence = null;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                InitializeCore(cancellationToken);
                var key = SelectorKey(submission.NetworkId.Span, submission.LocatorHandle.Span);
                if (states.TryGetValue(key, out var prior))
                {
                    if (prior.ForkLatched)
                    {
                        throw new InvalidDataException(
                            "Recipient resolve evidence is permanently fork-latched.");
                    }
                    if (verified.PublicationGeneration < prior.PublicationGeneration
                        || verified.PublicationGeneration == prior.PublicationGeneration
                            && verified.ClaimCommitGeneration < prior.ClaimCommitGeneration)
                    {
                        throw new InvalidDataException("Recipient resolve evidence rolls back.");
                    }
                    var replay = verified.PublicationGeneration == prior.PublicationGeneration
                        && verified.ClaimCommitGeneration == prior.ClaimCommitGeneration
                        && Fixed(prior.EvidenceHash, evidenceHash)
                        && Fixed(prior.StableClosureHash, stableClosureHash);
                    if (replay)
                    {
                        return;
                    }
                    var fork = prior.Kind != submission.Kind
                        || submission.Kind == ContactRecipientResolveEvidenceKind.OneTime
                        || verified.PublicationGeneration == prior.PublicationGeneration
                            && !Fixed(prior.StableClosureHash, stableClosureHash)
                        || !Fixed(prior.AddressHash, addressHash);
                    if (fork)
                    {
                        await LatchForkAsync(key, prior, cancellationToken).ConfigureAwait(false);
                        throw new InvalidDataException("Recipient resolve evidence forked.");
                    }
                }
                else if (states.Count >= configuration.MaximumEntries)
                {
                    throw new InvalidDataException(
                        "Recipient resolve evidence cache reached its entry bound.");
                }

                var exact = EncodeEvidence(submission);
                try
                {
                    protectedEvidence = evidenceProtector.Protect(exact);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(exact);
                }
                if (protectedEvidence.Length > MaximumProtectedEvidenceBytes)
                {
                    throw new InvalidDataException(
                        "Protected recipient resolve evidence exceeds its entry bound.");
                }
                states[key] = new(
                    submission.NetworkId.ToArray(),
                    submission.LocatorHandle.ToArray(),
                    submission.Kind,
                    false,
                    verified.PublicationGeneration,
                    verified.ClaimCommitGeneration,
                    addressHash.ToArray(),
                    stableClosureHash.ToArray(),
                    evidenceHash.ToArray(),
                    protectedEvidence.ToArray());
                await CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(addressHash);
            CryptographicOperations.ZeroMemory(evidenceHash);
            CryptographicOperations.ZeroMemory(stableClosureHash);
            if (protectedEvidence is not null)
            {
                CryptographicOperations.ZeroMemory(protectedEvidence);
            }
        }
    }

    public async ValueTask<ContactRouteRecipientResolveEvidence?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        ThrowIfUnavailable();
        ValidateSelector(networkId.Span, locatorHash.Span);
        byte[] protectedEvidence;
        RecipientState retained;
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            InitializeCore(cancellationToken);
            if (!states.TryGetValue(SelectorKey(networkId.Span, locatorHash.Span), out retained!))
            {
                return null;
            }
            if (retained.ForkLatched)
            {
                throw new InvalidDataException(
                    "Recipient resolve evidence is permanently fork-latched.");
            }
            protectedEvidence = retained.ProtectedEvidence.ToArray();
        }
        finally
        {
            gate.Release();
        }

        byte[] exact;
        try
        {
            exact = evidenceProtector.Unprotect(protectedEvidence);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedEvidence);
        }
        try
        {
            var submission = DecodeEvidence(exact);
            EnsureSelector(submission, networkId.Span, locatorHash.Span);
            var addressHash = SHA256.HashData(submission.ExactAddress.Span);
            var evidenceHash = ComputeEvidenceHash(submission);
            try
            {
                if (!Fixed(retained.AddressHash, addressHash)
                    || !Fixed(retained.EvidenceHash, evidenceHash))
                {
                    await LatchForkAsync(networkId, locatorHash, cancellationToken)
                        .ConfigureAwait(false);
                    throw new InvalidDataException(
                        "Protected recipient resolve evidence does not match its durable lineage.");
                }
                var verified = await verifier.VerifyCurrentAsync(submission, cancellationToken)
                    .ConfigureAwait(false);
                if (verified is null)
                {
                    return null;
                }
                if (verified.PublicationGeneration != retained.PublicationGeneration
                    || verified.ClaimCommitGeneration != retained.ClaimCommitGeneration
                    || !Fixed(retained.StableClosureHash, verified.StableClosureHash.Span))
                {
                    await LatchForkAsync(networkId, locatorHash, cancellationToken)
                        .ConfigureAwait(false);
                    throw new InvalidDataException(
                        "Re-verified recipient evidence changed its durable lineage.");
                }
                return verified.Evidence;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(addressHash);
                CryptographicOperations.ZeroMemory(evidenceHash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
        }
    }

    public async ValueTask<IReadOnlyList<ContactPreKeyRecipientResolveEvidence>>
        ReadCurrentCandidatesAsync(
            ReadOnlyMemory<byte> networkId,
            CancellationToken cancellationToken)
    {
        ThrowIfUnavailable();
        if (networkId.Length != 16 || networkId.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A pre-key recipient scan requires a nonzero 16-byte network ID.",
                nameof(networkId));
        }

        byte[][] locators;
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            InitializeCore(cancellationToken);
            // MaximumEntries is validated at <= 4096. Copy only opaque selectors
            // under the gate; protected evidence is opened and re-verified by the
            // normal exact-selector read path below.
            locators = states.Values
                .Where(value => !value.ForkLatched && Fixed(value.NetworkId, networkId.Span))
                .Select(static value => value.LocatorHandle.ToArray())
                .ToArray();
        }
        finally
        {
            gate.Release();
        }

        var candidates = new List<ContactPreKeyRecipientResolveEvidence>(locators.Length);
        foreach (var locator in locators)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var evidence = await ReadCurrentAsync(networkId, locator, cancellationToken)
                .ConfigureAwait(false);
            if (evidence is not null)
            {
                candidates.Add(new(locator, evidence));
            }
        }
        return candidates.AsReadOnly();
    }

    private void InitializeCore(CancellationToken cancellationToken)
    {
        ThrowIfUnavailable();
        cancellationToken.ThrowIfCancellationRequested();
        if (initialized)
        {
            return;
        }
        if (File.Exists(configuration.StatePath))
        {
            EnsureRegularPath(configuration.StatePath, expectFile: true);
            security.SecureFile(configuration.StatePath);
            var protectedState = File.ReadAllBytes(configuration.StatePath);
            if (protectedState.Length is <= 0
                || protectedState.Length > configuration.MaximumProtectedStateBytes)
            {
                throw new InvalidDataException(
                    "Protected recipient resolve evidence state length is invalid.");
            }
            byte[] exactState;
            try
            {
                exactState = stateProtector.Unprotect(protectedState);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedState);
            }
            try
            {
                states.Clear();
                try
                {
                    DecodeState(exactState);
                    foreach (var state in states.Values)
                    {
                        ValidateProtectedEvidence(state);
                    }
                }
                catch
                {
                    foreach (var state in states.Values)
                    {
                        CryptographicOperations.ZeroMemory(state.ProtectedEvidence);
                    }
                    states.Clear();
                    throw;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(exactState);
            }
        }
        initialized = true;
    }

    private void ValidateProtectedEvidence(RecipientState state)
    {
        byte[] exact;
        try
        {
            exact = evidenceProtector.Unprotect(state.ProtectedEvidence);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Protected recipient resolve evidence is corrupt.", exception);
        }
        try
        {
            var submission = DecodeEvidence(exact);
            EnsureSelector(submission, state.NetworkId, state.LocatorHandle);
            var addressHash = SHA256.HashData(submission.ExactAddress.Span);
            var evidenceHash = ComputeEvidenceHash(submission);
            try
            {
                if (submission.Kind != state.Kind
                    || !Fixed(addressHash, state.AddressHash)
                    || !Fixed(evidenceHash, state.EvidenceHash))
                {
                    throw new InvalidDataException(
                        "Protected recipient resolve evidence fails its durable digest.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(addressHash);
                CryptographicOperations.ZeroMemory(evidenceHash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
        }
    }

    private ValueTask LatchForkAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        var key = SelectorKey(networkId.Span, locatorHash.Span);
        return LatchForkByKeyAsync(key, cancellationToken);
    }

    private async ValueTask LatchForkByKeyAsync(
        string key,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            InitializeCore(cancellationToken);
            if (states.TryGetValue(key, out var state) && !state.ForkLatched)
            {
                await LatchForkAsync(key, state, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private async ValueTask LatchForkAsync(
        string key,
        RecipientState state,
        CancellationToken cancellationToken)
    {
        states[key] = state with { ForkLatched = true };
        await CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask CommitAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var exactState = EncodeState();
        byte[] protectedState;
        try
        {
            protectedState = stateProtector.Protect(exactState);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactState);
        }
        if (protectedState.Length > configuration.MaximumProtectedStateBytes)
        {
            CryptographicOperations.ZeroMemory(protectedState);
            throw new InvalidDataException(
                "Protected recipient resolve evidence state exceeds its configured bound.");
        }
        var temporary = $"{configuration.StatePath}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(protectedState, cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            security.SecureFile(temporary);
            EnsureRegularPath(temporary, expectFile: true);
            if (File.Exists(configuration.StatePath))
            {
                EnsureRegularPath(configuration.StatePath, expectFile: true);
            }
            durability.ReplaceFile(temporary, configuration.StatePath);
            security.SecureFile(configuration.StatePath);
            durability.FlushFileAndParentDirectory(configuration.StatePath);
        }
        catch
        {
            faulted = true;
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedState);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private byte[] EncodeState()
    {
        using var stream = new MemoryStream();
        stream.Write(StateMagic);
        WriteUInt16(stream, StateVersion);
        WriteUInt32(stream, checked((uint)states.Count));
        foreach (var state in states.Values.OrderBy(
                     static value => Convert.ToHexString(value.NetworkId)
                         + Convert.ToHexString(value.LocatorHandle),
                     StringComparer.Ordinal))
        {
            stream.Write(state.NetworkId);
            stream.Write(state.LocatorHandle);
            stream.WriteByte((byte)state.Kind);
            stream.WriteByte(state.ForkLatched ? (byte)1 : (byte)0);
            WriteUInt64(stream, state.PublicationGeneration);
            WriteUInt64(stream, state.ClaimCommitGeneration);
            stream.Write(state.AddressHash);
            stream.Write(state.StableClosureHash);
            stream.Write(state.EvidenceHash);
            WriteBytes(stream, state.ProtectedEvidence);
        }
        return stream.ToArray();
    }

    private void DecodeState(ReadOnlySpan<byte> exact)
    {
        var reader = new EvidenceReader(exact);
        if (!reader.ReadExact(4).SequenceEqual(StateMagic)
            || reader.ReadUInt16() != StateVersion)
        {
            throw new InvalidDataException(
                "Protected recipient resolve evidence state framing is invalid.");
        }
        var count = checked((int)reader.ReadUInt32());
        if (count < 0 || count > configuration.MaximumEntries)
        {
            throw new InvalidDataException(
                "Protected recipient resolve evidence state count is invalid.");
        }
        for (var index = 0; index < count; index++)
        {
            var networkId = reader.ReadOpaque(16);
            var locator = reader.ReadOpaque(32);
            var kind = (ContactRecipientResolveEvidenceKind)reader.ReadByte();
            var fork = reader.ReadByte();
            if (!Enum.IsDefined(kind) || fork > 1)
            {
                throw new InvalidDataException(
                    "Protected recipient resolve evidence metadata is invalid.");
            }
            var publicationGeneration = reader.ReadUInt64();
            var claimCommitGeneration = reader.ReadUInt64();
            if (kind == ContactRecipientResolveEvidenceKind.Permanent
                    && claimCommitGeneration != 0
                || kind == ContactRecipientResolveEvidenceKind.OneTime
                    && claimCommitGeneration == 0)
            {
                throw new InvalidDataException(
                    "Protected recipient resolve evidence lineage is invalid.");
            }
            var addressHash = reader.ReadOpaque(32);
            var stableClosureHash = reader.ReadOpaque(32);
            var evidenceHash = reader.ReadOpaque(32);
            var protectedEvidence = reader.ReadBytes(1, MaximumProtectedEvidenceBytes);
            var key = SelectorKey(networkId, locator);
            if (!states.TryAdd(key, new(
                networkId, locator, kind, fork == 1,
                publicationGeneration, claimCommitGeneration,
                addressHash, stableClosureHash, evidenceHash, protectedEvidence)))
            {
                throw new InvalidDataException(
                    "Protected recipient resolve evidence contains a duplicate selector.");
            }
        }
        reader.EnsureEnd();
    }

    private static byte[] EncodeEvidence(ContactRecipientResolveEvidenceSubmission submission)
    {
        using var stream = new MemoryStream();
        stream.Write(EvidenceMagic);
        WriteUInt16(stream, StateVersion);
        stream.WriteByte((byte)submission.Kind);
        stream.Write(submission.NetworkId.Span);
        stream.Write(submission.LocatorHandle.Span);
        WriteBytes(stream, submission.ExactAddress.Span);
        WriteBytes(stream, submission.ExactXiq1.Span);
        WriteBytes(stream, submission.ExactXis1.Span);
        return stream.ToArray();
    }

    private static ContactRecipientResolveEvidenceSubmission DecodeEvidence(
        ReadOnlySpan<byte> exact)
    {
        var reader = new EvidenceReader(exact);
        if (!reader.ReadExact(4).SequenceEqual(EvidenceMagic)
            || reader.ReadUInt16() != StateVersion)
        {
            throw new InvalidDataException(
                "Protected recipient resolve evidence framing is invalid.");
        }
        var kind = (ContactRecipientResolveEvidenceKind)reader.ReadByte();
        if (!Enum.IsDefined(kind))
        {
            throw new InvalidDataException(
                "Protected recipient resolve evidence kind is invalid.");
        }
        var result = new ContactRecipientResolveEvidenceSubmission(
            kind,
            reader.ReadOpaque(16),
            reader.ReadOpaque(32),
            reader.ReadBytes(1, ContactRecipientResolveEvidenceSubmission.MaximumAddressBytes),
            reader.ReadBytes(1, ContactRecipientResolveEvidenceSubmission.MaximumXiq1Bytes),
            reader.ReadBytes(1, ContactRecipientResolveEvidenceSubmission.MaximumXis1Bytes));
        reader.EnsureEnd();
        return result;
    }

    private static byte[] ComputeEvidenceHash(
        ContactRecipientResolveEvidenceSubmission submission)
    {
        var exact = EncodeEvidence(submission);
        try
        {
            return SHA256.HashData(exact);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
        }
    }

    private static string SelectorKey(ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> locator)
    {
        ValidateSelector(networkId, locator);
        var selector = new byte[48];
        networkId.CopyTo(selector);
        locator.CopyTo(selector.AsSpan(16));
        try
        {
            return Convert.ToHexString(SHA256.HashData(selector));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(selector);
        }
    }

    private static void EnsureSelector(
        ContactRecipientResolveEvidenceSubmission submission,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> locator)
    {
        if (!Fixed(submission.NetworkId.Span, networkId)
            || !Fixed(submission.LocatorHandle.Span, locator))
        {
            throw new InvalidDataException(
                "Protected recipient resolve evidence belongs to another opaque selector.");
        }
    }

    private static void ValidateSelector(ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> locator)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0
            || locator.Length != 32 || locator.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A recipient evidence selector requires nonzero 16-byte network and 32-byte locator values.");
        }
    }

    private static void ValidateConfiguration(
        ProductionContactRecipientEvidenceCacheConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(configuration.StatePath)
            || !Path.IsPathFullyQualified(configuration.StatePath)
            || configuration.MaximumProtectedStateBytes is < 4_096 or > 128 * 1024 * 1024
            || configuration.MaximumEntries is < 1 or > 4_096)
        {
            throw new InvalidOperationException(
                "Recipient resolve evidence cache configuration is invalid.");
        }
    }

    private void EnsureRegularPath(string candidate, bool expectFile)
    {
        var root = Path.GetFullPath(Path.GetDirectoryName(configuration.StatePath)!)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var full = Path.GetFullPath(candidate);
        var relative = Path.GetRelativePath(root, full);
        if (relative == ".."
            || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathFullyQualified(relative))
        {
            throw new UnauthorizedAccessException(
                "Recipient resolve evidence path escaped its trust root.");
        }
        FileSystemInfo current = expectFile
            ? new FileInfo(full)
            : new DirectoryInfo(full);
        while (true)
        {
            if (!current.Exists)
            {
                throw new InvalidDataException(
                    "Recipient resolve evidence path is missing.");
            }
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0
                || current.LinkTarget is not null)
            {
                throw new InvalidDataException(
                    "Recipient resolve evidence path contains a link or reparse point.");
            }
            if (string.Equals(
                Path.GetFullPath(current.FullName).TrimEnd(
                    Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                root,
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal))
            {
                return;
            }
            current = current switch
            {
                FileInfo file => file.Directory
                    ?? throw new InvalidDataException("Evidence file has no parent."),
                DirectoryInfo directory => directory.Parent
                    ?? throw new InvalidDataException("Evidence directory escaped its root."),
                _ => throw new InvalidDataException("Evidence path kind is invalid.")
            };
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);

    private static void WriteBytes(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteUInt32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> encoded = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> encoded = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteUInt64(Stream stream, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted)
        {
            throw new InvalidOperationException(
                "Recipient resolve evidence cache is faulted after a durability failure.");
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        gate.Dispose();
        foreach (var state in states.Values)
        {
            CryptographicOperations.ZeroMemory(state.ProtectedEvidence);
        }
        states.Clear();
    }

    private sealed record RecipientState(
        byte[] NetworkId,
        byte[] LocatorHandle,
        ContactRecipientResolveEvidenceKind Kind,
        bool ForkLatched,
        ulong PublicationGeneration,
        ulong ClaimCommitGeneration,
        byte[] AddressHash,
        byte[] StableClosureHash,
        byte[] EvidenceHash,
        byte[] ProtectedEvidence);

    private ref struct EvidenceReader(ReadOnlySpan<byte> exact)
    {
        private readonly ReadOnlySpan<byte> exact = exact;
        private int offset;

        internal byte ReadByte() => ReadExact(1)[0];
        internal ushort ReadUInt16() => BinaryPrimitives.ReadUInt16BigEndian(ReadExact(2));
        internal uint ReadUInt32() => BinaryPrimitives.ReadUInt32BigEndian(ReadExact(4));
        internal ulong ReadUInt64() => BinaryPrimitives.ReadUInt64BigEndian(ReadExact(8));

        internal byte[] ReadOpaque(int length)
        {
            var result = ReadExact(length).ToArray();
            if (result.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                throw new InvalidDataException(
                    "Protected recipient resolve evidence contains a zero opaque value.");
            }
            return result;
        }

        internal byte[] ReadBytes(int minimum, int maximum)
        {
            var length = checked((int)ReadUInt32());
            if (length < minimum || length > maximum)
            {
                throw new InvalidDataException(
                    "Protected recipient resolve evidence field length is invalid.");
            }
            return ReadExact(length).ToArray();
        }

        internal ReadOnlySpan<byte> ReadExact(int length)
        {
            if (length < 0 || offset > exact.Length - length)
            {
                throw new InvalidDataException(
                    "Protected recipient resolve evidence is truncated.");
            }
            var result = exact.Slice(offset, length);
            offset += length;
            return result;
        }

        internal void EnsureEnd()
        {
            if (offset != exact.Length)
            {
                throw new InvalidDataException(
                    "Protected recipient resolve evidence has trailing bytes.");
            }
        }
    }
}

internal sealed class ContactRecipientResolveEvidenceCacheHostedService(
    FileContactRecipientResolveEvidenceCache cache) : IHostedService
{
    private readonly FileContactRecipientResolveEvidenceCache cache =
        cache ?? throw new ArgumentNullException(nameof(cache));

    public async Task StartAsync(CancellationToken cancellationToken) =>
        await cache.InitializeAsync(cancellationToken).ConfigureAwait(false);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
