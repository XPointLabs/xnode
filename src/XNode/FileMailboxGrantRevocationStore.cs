using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;

namespace XNode;

/// <summary>
/// Current MGR1 custody, not an activated admission endpoint. All protected
/// records live outside replaceable node data. A joint rollback of the whole
/// independent custody/key ring is outside this local store's guarantee.
/// </summary>
internal sealed class FileMailboxGrantRevocationStore : IAsyncDisposable
{
    private const int MaximumProtectedBytes = MailboxGrantRevocationV1Codec.MaximumBytes + 1_024;
    private readonly string directory, floorPath, anchorPath, enrollmentPath, latchPath;
    private readonly byte[] localNode, network, policy;
    private readonly MailboxCapabilityDomain role;
    private readonly IDataProtector floorProtection, anchorProtection, enrollmentProtection, latchProtection;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream writerLease;
    private readonly SemaphoreSlim gate = new(1, 1);
    private bool disposed, faulted, initialized;

    internal FileMailboxGrantRevocationStore(string nodeDataRoot, string independentCustodyRoot,
        ReadOnlySpan<byte> localNodeId32, ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> pma2CoreReference38,
        MailboxCapabilityDomain role, IDataProtectionProvider protection,
        IMailboxStorageSecurity security, IMailboxDurabilityBarrier durability)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeDataRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(independentCustodyRoot);
        ArgumentNullException.ThrowIfNull(protection);
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ?? throw new ArgumentNullException(nameof(durability));
        var data = Path.TrimEndingDirectorySeparator(Path.GetFullPath(nodeDataRoot));
        var custody = Path.TrimEndingDirectorySeparator(Path.GetFullPath(independentCustodyRoot));
        if (IsWithin(data, custody) || IsWithin(custody, data) ||
            custody == Path.TrimEndingDirectorySeparator(Path.GetPathRoot(custody)!))
            throw new ArgumentException("MGR1 custody must be an independent non-root directory, outside node data.");
        if (localNodeId32.Length != 32 || localNodeId32.IndexOfAnyExcept((byte)0) < 0 ||
            networkId16.Length != 16 || networkId16.IndexOfAnyExcept((byte)0) < 0 ||
            pma2CoreReference38.Length != 38 || !pma2CoreReference38[..4].SequenceEqual(ProtocolMagicBytes.PMA2) ||
            pma2CoreReference38[4] != 0 || pma2CoreReference38[5] != 1 ||
            pma2CoreReference38[6..].IndexOfAnyExcept((byte)0) < 0 ||
            role is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve))
            throw new ArgumentException("MGR1 custody scope is invalid.");
        localNode = localNodeId32.ToArray();
        network = networkId16.ToArray(); policy = pma2CoreReference38.ToArray(); this.role = role;
        // Local naming/protection context only; this is not a wire hash or authority.
        var scope = Convert.ToHexString(SHA256.HashData([.. localNodeId32, .. network, .. policy, (byte)role]));
        floorProtection = protection.CreateProtector("Deep.XNode.MGR1.Floor.v1", scope);
        anchorProtection = protection.CreateProtector("Deep.XNode.MGR1.Anchor.v1", scope);
        enrollmentProtection = protection.CreateProtector("Deep.XNode.MGR1.Enrollment.v1", scope);
        latchProtection = protection.CreateProtector("Deep.XNode.MGR1.Fault.v1", scope);
        directory = Path.Combine(custody, scope);
        RejectLinks(custody); RejectLinks(directory);
        security.SecureDirectory(custody); security.SecureDirectory(directory);
        floorPath = Path.Combine(directory, "floor.bin"); anchorPath = Path.Combine(directory, "anchor.bin");
        enrollmentPath = Path.Combine(directory, "enrollment.bin"); latchPath = Path.Combine(directory, "fault.bin");
        var lockPath = Path.Combine(directory, "writer.lock"); RejectLinks(lockPath);
        writerLease = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite,
            FileShare.None, 1, FileOptions.WriteThrough);
        try { security.SecureFile(lockPath); security.ValidateSecureFile(lockPath); }
        catch { writerLease.Dispose(); throw; }
    }

    internal void RequireScope(ReadOnlySpan<byte> nodeId, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> policyReference, MailboxCapabilityDomain domain)
    {
        CheckAvailable();
        if (!Fixed(localNode, nodeId) || !Fixed(network, networkId) ||
            !Fixed(policy, policyReference) || role != domain)
            throw new CryptographicException("MGR1 native owner differs from the current node/network/policy/role.");
    }

    // Preflight is not an enrollment capability: the writer repeats these
    // checks under its own gate. Both roles must pass before either is written.
    internal async ValueTask ValidateNewEnrollmentAsync(VerifiedMailboxHostAuthorityV2 host,
        ReadOnlyMemory<byte> exactInitialSnapshot, CancellationToken token)
    {
        var owned = Capture(exactInitialSnapshot);
        await gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            CheckAvailable();
            if (ReadCore() is not null) throw new InvalidOperationException("The MGR1 scope is already enrolled.");
            _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, owned, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
        }
        finally { gate.Release(); }
    }

    /// <summary>Explicit genuinely new-scope provisioning only; never a missing-floor recovery fallback.</summary>
    internal async ValueTask EnrollAsync(VerifiedMailboxHostAuthorityV2 host, ReadOnlyMemory<byte> exactInitialSnapshot,
        CancellationToken cancellationToken = default)
    {
        var owned = Capture(exactInitialSnapshot);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CheckAvailable();
            if (ReadCore() is not null) throw new InvalidOperationException("The MGR1 scope is already enrolled.");
            var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, owned, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                Write(enrollmentPath, owned, enrollmentProtection);
                Write(anchorPath, owned, anchorProtection); Write(floorPath, owned, floorProtection);
                await VerifyReadBackAsync(plan, cancellationToken).ConfigureAwait(false);
            }
            catch { faulted = true; throw; }
        }
        finally { gate.Release(); }
    }

    internal async ValueTask AdvanceAsync(VerifiedMailboxHostAuthorityV2 host, ReadOnlyMemory<byte> exactCandidate,
        CancellationToken cancellationToken = default)
    {
        var owned = Capture(exactCandidate);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CheckAvailable(); var prior = RequireFloor();
            VerifiedMailboxGrantRevocationPlan plan;
            try { plan = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, prior, owned, cancellationToken).ConfigureAwait(false); }
            catch (MailboxGrantRevocationFloorException error) when
                (error.Error is MailboxGrantRevocationFloorError.SignedFork or MailboxGrantRevocationFloorError.RemovedSerial)
            {
                // Only the verifier's actually authenticated conflict can persist a
                // scope latch. A malformed/signature-invalid input cannot reach it.
                try { Write(latchPath, owned, latchProtection); }
                finally { faulted = true; }
                throw;
            }
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (!Fixed(prior, owned))
                { Write(anchorPath, owned, anchorProtection); Write(floorPath, owned, floorProtection); }
                await VerifyReadBackAsync(plan, cancellationToken).ConfigureAwait(false);
            }
            catch { faulted = true; throw; }
        }
        finally { gate.Release(); }
    }

    /// <summary>One signed sequential historical floor commit; never enrollment or admission authority.</summary>
    internal async ValueTask CatchUpAsync(VerifiedMailboxHostAuthorityV2 host, ReadOnlyMemory<byte> exactCandidate,
        CancellationToken cancellationToken = default)
    {
        var owned = Capture(exactCandidate);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CheckAvailable(); var prior = RequireFloor();
            VerifiedMailboxGrantRevocationHistoryPlan plan;
            try { plan = await MailboxGrantRevocationV1Verifier.PlanCatchUpSuccessorAsync(host, prior, owned, cancellationToken).ConfigureAwait(false); }
            catch (MailboxGrantRevocationFloorException error) when
                (error.Error is MailboxGrantRevocationFloorError.SignedFork or MailboxGrantRevocationFloorError.RemovedSerial)
            {
                try { Write(latchPath, owned, latchProtection); }
                finally { faulted = true; }
                throw;
            }
            cancellationToken.ThrowIfCancellationRequested();
            var reader = new LeasedReader(this);
            try
            {
                if (!Fixed(prior, owned))
                { Write(anchorPath, owned, anchorProtection); Write(floorPath, owned, floorProtection); }
                await MailboxGrantRevocationV1Verifier.VerifyHistoricalCommitAsync(plan, RequireFloor(), reader,
                    cancellationToken).ConfigureAwait(false);
            }
            catch { faulted = true; throw; }
            finally { reader.Close(); }
        }
        finally { gate.Release(); }
    }

    /// <summary>Native restore facts only; caller cannot obtain admission authority from these bytes.</summary>
    internal async ValueTask<ReadOnlyMemory<byte>> ReadProtectedAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { CheckAvailable(); return RequireFloor(); }
        finally { gate.Release(); }
    }

    /// <summary>The same scoped concurrency owner serializes floor replacement
    /// with the complete bounded admission/mutation callback. Capabilities cannot escape this lease.</summary>
    internal async ValueTask<T> WithCurrentAsync<T>(VerifiedMailboxHostAuthorityV2 host,
        Func<CurrentLease, CancellationToken, ValueTask<T>> operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var reader = new LeasedReader(this);
        try
        {
            CheckAvailable(); var exact = RequireFloor();
            var plan = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, exact, exact, cancellationToken).ConfigureAwait(false);
            var capability = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan,
                exact, reader, cancellationToken).ConfigureAwait(false);
            var result = await operation(new(capability, reader.RequireActive), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await capability.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally { reader.Close(); gate.Release(); }
    }

    /// <summary>Native operation-scoped use only. The raw Protocol capability
    /// is never exposed; a callback or async continuation outliving the owner
    /// must fail again after its awaited verification, not only before I/O.</summary>
    internal sealed class CurrentLease(VerifiedMailboxGrantRevocationV1 capability, Action requireActive)
    {
        internal void RequireActive() => requireActive();
        internal async ValueTask EnsureCurrentAsync(CancellationToken token = default)
        {
            requireActive();
            await capability.EnsureCurrentAsync(token).ConfigureAwait(false);
            requireActive();
        }
        internal async ValueTask EnsureGrantNotRevokedAsync(ReadOnlyMemory<byte> exactGrant, CancellationToken token = default)
        {
            requireActive();
            await capability.EnsureGrantNotRevokedAsync(exactGrant, token).ConfigureAwait(false);
            requireActive();
        }
    }

    private async ValueTask VerifyReadBackAsync(VerifiedMailboxGrantRevocationPlan plan, CancellationToken token)
    {
        var reader = new LeasedReader(this);
        try { _ = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, RequireFloor(), reader, token).ConfigureAwait(false); }
        finally { reader.Close(); }
    }

    private sealed class LeasedReader(FileMailboxGrantRevocationStore owner) : IMailboxGrantRevocationFloorReader
    {
        private int active = 1;
        internal void Close() => Volatile.Write(ref active, 0);
        internal void RequireActive()
        {
            if (Volatile.Read(ref active) != 1) throw new InvalidOperationException("The native MGR1 custody lease is closed.");
        }
        public ValueTask<ReadOnlyMemory<byte>> ReadCurrentCoreHashAsync(ReadOnlyMemory<byte> networkId16,
            ReadOnlyMemory<byte> pma2CoreReference38, MailboxCapabilityDomain domain, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            RequireActive();
            owner.CheckAvailable();
            if (!Fixed(owner.network, networkId16.Span) || !Fixed(owner.policy, pma2CoreReference38.Span) || domain != owner.role)
                throw new CryptographicException("The native MGR1 floor reader was called outside its protected scope.");
            var exact = owner.RequireFloor();
            return ValueTask.FromResult(MailboxGrantRevocationV1Codec.Decode(exact).CoreHash);
        }
    }

    private byte[] Capture(ReadOnlyMemory<byte> exact)
    {
        var parsed = MailboxGrantRevocationV1Codec.Decode(exact.Span);
        if (!Fixed(network, parsed.Field(1).Span) || !Fixed(policy, parsed.Field(2).Span) || parsed.Domain != role)
            throw new CryptographicException("MGR1 differs from the native custody scope.");
        return parsed.CanonicalBytes.ToArray();
    }

    private byte[] RequireFloor() => ReadCore() ?? throw new InvalidDataException("MGR1 requires explicit new-scope enrollment or operator recovery.");
    private byte[]? ReadCore()
    {
        RejectLinks(directory);
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            RejectLinks(entry);
            if (Directory.Exists(entry) || Path.GetFileName(entry) is not
                ("writer.lock" or "floor.bin" or "anchor.bin" or "enrollment.bin" or "fault.bin"))
                throw new InvalidDataException("MGR1 custody contains an unknown/partial record.");
        }
        if (File.Exists(latchPath))
        { _ = Read(latchPath, latchProtection); throw new InvalidDataException("MGR1 scope is latched after authenticated issuer equivocation."); }
        var enrollment = Read(enrollmentPath, enrollmentProtection);
        var anchor = Read(anchorPath, anchorProtection); var floor = Read(floorPath, floorProtection);
        if (enrollment is null && anchor is null && floor is null)
        {
            if (initialized) throw new InvalidDataException("The initialized MGR1 custody disappeared.");
            return null;
        }
        if (enrollment is null || anchor is null || floor is null || !Fixed(anchor, floor))
            throw new InvalidDataException("MGR1 protected enrollment/floor/anchor are missing, split or rolled back.");
        var initialGeneration = MailboxGrantRevocationV1Codec.Decode(enrollment).Generation;
        var floorGeneration = MailboxGrantRevocationV1Codec.Decode(floor).Generation;
        if (floorGeneration < initialGeneration ||
            (floorGeneration == initialGeneration && !Fixed(enrollment, floor)))
            throw new InvalidDataException("MGR1 protected enrollment/floor/anchor are missing, split or rolled back.");
        initialized = true;
        return floor;
    }

    private byte[]? Read(string path, IDataProtector protection)
    {
        if (!File.Exists(path)) return null;
        RejectLinks(path); security.ValidateSecureFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > MaximumProtectedBytes) throw new InvalidDataException("MGR1 protected record exceeds its closed bound.");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("MGR1 protected record changed while reading.");
        byte[]? plain = null;
        try { plain = protection.Unprotect(bytes); return Capture(plain); }
        finally { CryptographicOperations.ZeroMemory(bytes); if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }

    private void Write(string path, byte[] exact, IDataProtector protection)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        RejectLinks(path); RejectLinks(temporary);
        var bytes = protection.Protect(exact);
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4_096, FileOptions.WriteThrough)) { stream.Write(bytes); stream.Flush(flushToDisk: true); }
            security.SecureFile(temporary); security.ValidateSecureFile(temporary);
            durability.ReplaceFile(temporary, path);
            security.SecureFile(path); security.ValidateSecureFile(path); durability.FlushFileAndParentDirectory(path);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        // Do not remove a partial file after an uncertain native write. It is
        // quarantine evidence; restart rejects it instead of silently repairing.
    }

    private static bool IsWithin(string root, string candidate)
    {
        var relative = Path.GetRelativePath(root, candidate);
        return relative == "." || (relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar,
            StringComparison.Ordinal) && !Path.IsPathFullyQualified(relative));
    }
    private static void RejectLinks(string path)
    {
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
            if (current.LinkTarget is not null || (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0))
                throw new UnauthorizedAccessException("MGR1 custody cannot traverse links.");
    }
    private void CheckAvailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted) throw new InvalidOperationException("MGR1 custody is faulted after an uncertain commit or signed conflict.");
    }
    public async ValueTask DisposeAsync()
    {
        // Wait for the complete operation before releasing the process-independent
        // writer lease. The managed semaphore remains usable by queued disposal/read
        // attempts so each observes disposed rather than bypassing serialization.
        await gate.WaitAsync().ConfigureAwait(false);
        try { if (!disposed) { disposed = true; writerLease.Dispose(); } }
        finally { gate.Release(); }
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
