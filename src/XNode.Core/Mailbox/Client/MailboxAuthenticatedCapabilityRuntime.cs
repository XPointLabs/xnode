using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed record MailboxCapabilityAuthorityQuery(
    MailboxAuthenticatedOperation Operation,
    MailboxCapabilityDomain Domain,
    ulong Epoch,
    ulong Generation,
    MailboxCapabilityLifecycle Lifecycle,
    ReadOnlyMemory<byte> NetworkId,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    ReadOnlyMemory<byte> IssuerPublicKey);

/// <summary>
/// Resolves only externally trusted issuer and epoch policy. Implementations must never derive
/// trust from values merely because they appeared in an untrusted MCG2 grant.
/// </summary>
public interface IMailboxCapabilityAuthoritySource
{
    bool IsConfigured { get; }

    bool TryResolve(
        MailboxCapabilityAuthorityQuery query,
        out MailboxAuthenticatedVerificationPolicy? policy);

    ulong ReplayValidityEndsAt(
        MailboxCapabilityAuthorityQuery query,
        MailboxAuthenticatedGrant grant) =>
        grant.ExpiresAtUnixSeconds;
}

public interface IMailboxCapabilityRevocationPolicy : IMailboxCapabilityRevocationSource
{
    bool IsConfigured { get; }
}

public sealed class RejectAllMailboxCapabilityAuthoritySource
    : IMailboxCapabilityAuthoritySource
{
    public bool IsConfigured => false;

    public bool TryResolve(
        MailboxCapabilityAuthorityQuery query,
        out MailboxAuthenticatedVerificationPolicy? policy)
    {
        policy = null;
        return false;
    }
}

public sealed class RejectAllMailboxCapabilityRevocationPolicy
    : IMailboxCapabilityRevocationPolicy
{
    public bool IsConfigured => false;

    public bool IsRevoked(MailboxCapabilityRevocationQuery query) => true;
}

public sealed record MailboxAuthenticatedRuntimeStatus(
    bool StrictMau2Decoder,
    bool Ed25519Verifier,
    bool DurableAtomicReplay,
    bool AuthorityConfigured,
    bool RevocationPolicyConfigured,
    bool Ready,
    string Reason);

/// <summary>
/// Dormant MAU2 verification boundary. This type performs no storage, fanout or route mapping.
/// </summary>
public sealed class MailboxAuthenticatedCapabilityRuntime
{
    private readonly IMailboxCapabilityAuthoritySource _authority;
    private readonly IMailboxCapabilityRevocationPolicy _revocations;
    private readonly DurableMailboxCapabilityReplayJournal _replay;
    private readonly IMailboxAuthenticatedCapabilityCrypto _crypto;
    private readonly IClock _clock;

    public MailboxAuthenticatedCapabilityRuntime(
        IMailboxCapabilityAuthoritySource authority,
        IMailboxCapabilityRevocationPolicy revocations,
        DurableMailboxCapabilityReplayJournal replay,
        IClock? clock = null,
        IMailboxAuthenticatedCapabilityCrypto? crypto = null)
    {
        _authority = authority ?? throw new ArgumentNullException(nameof(authority));
        _revocations = revocations ?? throw new ArgumentNullException(nameof(revocations));
        _replay = replay ?? throw new ArgumentNullException(nameof(replay));
        _clock = clock ?? new SystemClock();
        _crypto = crypto ?? new SodiumMailboxCapabilityCrypto();
    }

    public MailboxAuthenticatedRuntimeStatus Status
    {
        get
        {
            var ready = _authority.IsConfigured && _revocations.IsConfigured;
            return new(
                StrictMau2Decoder: true,
                Ed25519Verifier: true,
                DurableAtomicReplay: true,
                AuthorityConfigured: _authority.IsConfigured,
                RevocationPolicyConfigured: _revocations.IsConfigured,
                Ready: ready,
                Reason: ready ? "" : "issuer-or-revocation-authority-unconfigured");
        }
    }

    public VerifiedMailboxAuthenticatedClientRequest Verify(
        ReadOnlyMemory<byte> canonicalMau2)
    {
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(canonicalMau2.Span);
        var grant = decoded.Presentation.Grant;
        var query = new MailboxCapabilityAuthorityQuery(
            decoded.Binding.Operation,
            grant.Domain,
            grant.Epoch,
            grant.Generation,
            grant.Lifecycle,
            grant.NetworkId.ToArray(),
            grant.PlacementCommitment.ToArray(),
            grant.MembershipCommitment.ToArray(),
            grant.IssuerPublicKey.ToArray());
        if (!_authority.TryResolve(query, out var configured) || configured is null)
        {
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.UntrustedIssuer,
                "Mailbox capability issuer authority is unavailable.");
        }

        var body = decoded.Binding.CanonicalRequest.Span;
        var bodyEpoch = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(8, 8));
        if (bodyEpoch != grant.Epoch)
        {
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.BindingMismatch,
                "Mailbox capability epoch binding failed.");
        }

        var policy = configured with
        {
            NowUnixSeconds = checked((ulong)_clock.UtcNow.ToUnixTimeSeconds())
        };
        var retainUntil = _replay.RetainUntilUnixSeconds(
            Math.Max(
                grant.ExpiresAtUnixSeconds,
                _authority.ReplayValidityEndsAt(query, grant)));
        var replayScope = _replay.CreateEvaluationScope(
            policy.NowUnixSeconds,
            retainUntil);
        return MailboxAuthenticatedClientRequestCodec.Verify(
            canonicalMau2.Span,
            policy,
            _crypto,
            _revocations,
            replayScope);
    }

    public void Complete(
        VerifiedMailboxAuthenticatedClientRequest verified,
        ReadOnlyMemory<byte> canonicalOutcome)
    {
        ArgumentNullException.ThrowIfNull(verified);
        _replay.CompleteAtomically(verified.Capability.ReplayClaim, canonicalOutcome);
    }

    public void Abort(VerifiedMailboxAuthenticatedClientRequest verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        _replay.AbortAtomically(verified.Capability.ReplayClaim);
    }
}
