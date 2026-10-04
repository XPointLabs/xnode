using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace XNode;

/// <summary>
/// Production implementations must pin the immutable signed DID2 genesis,
/// restore an authenticated genesis or successor head, and durably
/// compare/exchange the verified successor by exact bytes and hash, not object
/// identity. A missing floor never means permission to restart at genesis.
/// </summary>
internal interface IDeepIdV2DirectoryProtectedHeadStore
{
    ValueTask<AccountDirectoryProtectedLkg> RestoreAsync(
        VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken);

    // Observation must not bootstrap a missing floor or repair an index.
    ValueTask<AccountDirectoryProtectedLkg> ReadRetainedAsync(
        VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken);

    ValueTask CommitVerifiedAsync(AccountDirectoryProtectedLkg expected,
        VerifiedDeepIdV2DirectoryFreshness verified,
        CancellationToken cancellationToken);
    ValueTask CommitCatchupAsync(VerifiedDeepIdV2DirectoryCatchup verified,
        CancellationToken cancellationToken);
}

/// <summary>
/// Recipient-specific DID2 proof boundary. Raw Registry artifacts are never
/// promoted until the exact proof is independently verified and its successor
/// head has been durably committed as the local rollback floor.
/// </summary>
internal sealed class DeepIdV2DirectoryCurrentProofReader(
    IDeepIdV2DirectoryProofArtifactSource artifacts,
    IDeepIdV2DirectoryProtectedHeadStore protectedHeads,
    IOnionMonotonicClock clock,
    IDeepMlDsa65Verifier mlDsa65)
{
    private readonly IDeepIdV2DirectoryProofArtifactSource artifacts =
        artifacts ?? throw new ArgumentNullException(nameof(artifacts));
    private readonly IDeepIdV2DirectoryProtectedHeadStore protectedHeads =
        protectedHeads ?? throw new ArgumentNullException(nameof(protectedHeads));
    private readonly IOnionMonotonicClock clock =
        clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly IDeepMlDsa65Verifier mlDsa65 =
        mlDsa65 ?? throw new ArgumentNullException(nameof(mlDsa65));
    private readonly SemaphoreSlim readGate = new(1, 1);

    internal async ValueTask ValidateObservedAsync(VerifiedDeepIdV2DirectoryFreshness freshness,
        VerifiedXPointNetworkAuthority authority, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(authority);
        await readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var retained = await protectedHeads.ReadRetainedAsync(authority, cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException("The observed DID2 floor is absent.");
            var floor = RestoreAuthenticatedFloor(retained, authority);
            if (!CryptographicOperations.FixedTimeEquals(floor.ExactAdh1.Span, freshness.ExactAdh1.Span) ||
                !CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span, freshness.NetworkId.Span))
                throw new CryptographicException("The observed DID2 proof no longer closes the protected floor.");
            var reading = await RequireClockAsync(cancellationToken).ConfigureAwait(false);
            if (freshness.CurrentCheckpoint is null ||
                !freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
                throw new CryptographicException("The observed DID2 proof is no longer current.");
            cancellationToken.ThrowIfCancellationRequested();
        }
        finally { readGate.Release(); }
    }

    internal async ValueTask<VerifiedDeepIdV2DirectoryFreshness>
        ReadCurrentAsync(ParsedDid2 requestedDid2,
            VerifiedXPointNetworkAuthority authority,
            ushort deploymentProfileId, ushort supportedReader,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestedDid2);
        ArgumentNullException.ThrowIfNull(authority);
        if (deploymentProfileId == 0)
            throw new ArgumentOutOfRangeException(nameof(deploymentProfileId));
        if (supportedReader < 2)
            throw new ArgumentOutOfRangeException(nameof(supportedReader));
        await readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            for (var attempt = 0; attempt < 2; attempt++)
            {
            try
            {
            var storedFloor = await protectedHeads.RestoreAsync(authority,
                    cancellationToken).ConfigureAwait(false) ??
                throw new CryptographicException(
                    "The protected DID2 directory head is absent.");
            var floor = RestoreAuthenticatedFloor(storedFloor, authority);
            var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(
                requestedDid2, authority.NetworkId.Span, floor.LogGeneration,
                floor.CoreHash.Span, serviceProfile: 1,
                new byte[38], new byte[32]);
            var query = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup,
                requestedDid2);
            var started = await RequireClockAsync(cancellationToken)
                .ConfigureAwait(false);
            var nonce = RandomNumberGenerator.GetBytes(32);
            try
            {
                var response = await artifacts.FetchAsync(lookup, requestedDid2,
                    nonce, started.BootId, started.SampleSeconds,
                    cancellationToken).ConfigureAwait(false) ??
                    throw new CryptographicException(
                        "The DID2 proof authority returned no artifacts.");
                var received = await RequireClockAsync(cancellationToken)
                    .ConfigureAwait(false);
                var current = await RequireClockAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (!SameBoot(started, received) ||
                    !SameBoot(started, current))
                    throw new CryptographicException(
                        "The DID2 proof request crossed a monotonic boot.");
                var window = new AccountDirectoryMonotonicRequestWindow(
                    started.BootId.Span, started.SampleSeconds,
                    received.SampleSeconds, current.SampleSeconds);
                var verified =
                    DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(
                        authority, response.ExactAdh1, response.ExactDtt1,
                        response.ExactAdp1V2, nonce, query, window, floor,
                        deploymentProfileId, supportedReader, mlDsa65);
                await protectedHeads.CommitVerifiedAsync(floor, verified,
                    cancellationToken).ConfigureAwait(false);
                var storedDurable = await protectedHeads.RestoreAsync(authority,
                    cancellationToken).ConfigureAwait(false) ??
                    throw new CryptographicException(
                        "The protected DID2 successor disappeared.");
                var durable = RestoreAuthenticatedFloor(storedDurable, authority);
                if (!CryptographicOperations.FixedTimeEquals(
                        durable.ExactAdh1.Span,
                        verified.NextProtectedLkg.ExactAdh1.Span))
                    throw new CryptographicException(
                        "The DID2 proof successor was not durably committed.");
                var afterCommit = await RequireClockAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (verified.CurrentCheckpoint is null ||
                    !verified.IsCurrentAtMonotonic(afterCommit.BootId.Span,
                        afterCommit.SampleSeconds))
                    throw new CryptographicException(
                        "The DID2 recipient has no current, live checkpoint.");
                return verified;
            }
            finally { CryptographicOperations.ZeroMemory(nonce); }
            }
            catch (DeepIdV2DirectoryProofUnavailableException exception) when (
                attempt == 0 && exception.StatusCode == System.Net.HttpStatusCode.ServiceUnavailable)
            {
                await CatchupAsync(authority, cancellationToken).ConfigureAwait(false);
            }
            }
            throw new InvalidOperationException("Bounded proof recovery did not return a result.");
        }
        finally { readGate.Release(); }
    }

    private async ValueTask CatchupAsync(VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken)
    {
        var floor = RestoreAuthenticatedFloor(await protectedHeads.RestoreAsync(authority, cancellationToken)
            .ConfigureAwait(false), authority);
        for (var pageIndex = 0; pageIndex < 16; pageIndex++)
        {
            var page = await artifacts.FetchHistoryAsync(floor, cancellationToken).ConfigureAwait(false);
            var successors = page.ExactSuccessors;
            if (successors.Count == 0) return;
            var verified = DeepIdV2DirectoryCatchupVerifier.Verify(authority, floor, successors, page.ConsistencyNodes);
            await protectedHeads.CommitCatchupAsync(verified, cancellationToken).ConfigureAwait(false);
            floor = RestoreAuthenticatedFloor(await protectedHeads.RestoreAsync(authority, cancellationToken)
                .ConfigureAwait(false), authority);
            if (!floor.ExactAdh1.Span.SequenceEqual(verified.ProtectedLkg.ExactAdh1.Span))
                throw new CryptographicException("Historical DID2 floor was not durably committed.");
            if (successors.Count < 64) return;
        }
        throw new DeepIdV2DirectoryProofUnavailableException(System.Net.HttpStatusCode.ServiceUnavailable, TimeSpan.FromSeconds(1));
    }

    private async ValueTask<OnionMonotonicReading> RequireClockAsync(
        CancellationToken cancellationToken) =>
        await clock.ReadAsync(cancellationToken).ConfigureAwait(false) ??
        throw new CryptographicException(
            "The DID2 monotonic clock returned no reading.");

    private static AccountDirectoryProtectedLkg RestoreAuthenticatedFloor(
        AccountDirectoryProtectedLkg stored,
        VerifiedXPointNetworkAuthority authority)
    {
        var floor = stored.LogGeneration == 0
            ? DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority,
                stored.ExactAdh1, stored.CoreHash.Span)
            : AccountDirectoryProtectedLkgFactory.Restore(authority,
                stored.ExactAdh1, stored.CoreHash.Span);
        if (floor.Head.MinimumReader < 2 ||
            !CryptographicOperations.FixedTimeEquals(
                floor.Head.NetworkId.Span, authority.NetworkId.Span))
            throw new CryptographicException(
                "The protected DID2 directory head is cross-network or retired.");
        return floor;
    }

    private static bool SameBoot(OnionMonotonicReading first,
        OnionMonotonicReading second) =>
        CryptographicOperations.FixedTimeEquals(first.BootId.Span,
            second.BootId.Span);
}
