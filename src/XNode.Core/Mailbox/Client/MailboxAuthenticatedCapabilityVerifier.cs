using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

/// <summary>
/// Verifies the MCP2 presentation carried as the opaque value of the canonical MCP1
/// compatibility envelope. The MCP1 envelope is framing only: authority, signatures,
/// revocation and replay are all decided by the MAU2 runtime.
/// </summary>
public sealed class MailboxAuthenticatedCapabilityVerifier
    : IMailboxClientCapabilityVerifier, IMailboxClientCapabilityCompletion
{
    private readonly MailboxClientAdapterOptions _options;
    private readonly MailboxAuthenticatedCapabilityRuntime _runtime;
    private readonly IClock _clock;
    private readonly Dictionary<string, VerifiedMailboxAuthenticatedClientRequest> _pending =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, byte[]> _completedOutcomes =
        new(StringComparer.Ordinal);
    private readonly object _pendingGate = new();

    public MailboxAuthenticatedCapabilityVerifier(
        MailboxClientAdapterOptions options,
        MailboxAuthenticatedCapabilityRuntime runtime,
        IClock? clock = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _clock = clock ?? new SystemClock();
    }

    public bool IsConfigured => _runtime.Status.Ready;

    public bool ProvidesDurableAtomicReplay => true;

    public ValueTask<MailboxCapabilityBinding?> VerifyAsync(
        ReadOnlyMemory<byte> canonicalRequest,
        MailboxClientOperation operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var decoded = DecodeOuter(canonicalRequest.Span, operation);
            var authenticatedPresentation =
                MailboxAuthenticatedCapabilityCodec.DecodePresentation(
                    decoded.Capability.DomainValue.Bytes.Span);
            if (authenticatedPresentation.ReplayCounter != decoded.Capability.ReplayCounter
                || authenticatedPresentation.Grant.Generation != decoded.Capability.Generation
                || authenticatedPresentation.Grant.Domain != decoded.Domain
                || authenticatedPresentation.Operation != ToAuthenticatedOperation(operation))
            {
                return ValueTask.FromResult<MailboxCapabilityBinding?>(null);
            }

            var mau2 = MailboxAuthenticatedClientRequestCodec.Encode(
                new MailboxAuthenticatedClientRequest
                {
                    Binding = decoded.AuthenticatedBinding,
                    Presentation = authenticatedPresentation
                });
            var verified = _runtime.Verify(mau2);
            lock (_pendingGate)
            {
                var key = DigestKey(SHA256.HashData(canonicalRequest.Span));
                if (!_completedOutcomes.ContainsKey(key))
                {
                    _pending[key] = verified;
                }
            }
            var replayDisposition = verified.Capability.ReplayDisposition switch
            {
                MailboxAuthenticatedReplayDisposition.NewReserved =>
                    MailboxCapabilityReplayDisposition.New,
                MailboxAuthenticatedReplayDisposition.InFlight or
                MailboxAuthenticatedReplayDisposition.IdempotentCompleted =>
                    MailboxCapabilityReplayDisposition.IdempotentReplay,
                _ => throw new InvalidOperationException(
                    "Unknown authenticated replay disposition.")
            };

            return ValueTask.FromResult<MailboxCapabilityBinding?>(new(
                verified.Capability.Grant.Epoch,
                decoded.MailboxId,
                verified.Capability.Grant.PlacementCommitment.ToArray(),
                verified.Capability.Grant.MembershipCommitment.ToArray(),
                operation)
            {
                OuterOperationId = decoded.OperationId,
                CanonicalRequestDigest = SHA256.HashData(canonicalRequest.Span),
                CanonicalCapabilityDigest = SHA256.HashData(
                    MailboxCapabilityCodec.Encode(decoded.Capability)),
                ReplayCounter = decoded.Capability.ReplayCounter,
                IdempotencyKey = decoded.Capability.IdempotencyKey.ToArray(),
                ReplayDisposition = replayDisposition
            });
        }
        catch (Exception exception) when (
            exception is MailboxClientException
                or MailboxCapabilityException
                or MailboxAuthenticatedCapabilityException
                or ArgumentException
                or InvalidOperationException
                or OverflowException)
        {
            return ValueTask.FromResult<MailboxCapabilityBinding?>(null);
        }
    }

    public void Complete(
        ReadOnlyMemory<byte> canonicalRequestDigest,
        ReadOnlyMemory<byte> canonicalOutcome)
    {
        var key = DigestKey(canonicalRequestDigest.Span);
        var outcomeDigest = SHA256.HashData(canonicalOutcome.Span);
        lock (_pendingGate)
        {
            if (_completedOutcomes.TryGetValue(key, out var completed))
            {
                if (!CryptographicOperations.FixedTimeEquals(completed, outcomeDigest))
                {
                    throw new InvalidOperationException(
                        "Completed authenticated replay outcome conflicts.");
                }

                return;
            }

            if (!_pending.Remove(key, out var verified))
            {
                throw new InvalidOperationException(
                    "Authenticated capability completion has no verified reservation.");
            }

            // Replay outcomes are bounded and non-sensitive. The operation ledger remains
            // authoritative for the full canonical response.
            if (verified.Capability.ReplayDisposition
                == MailboxAuthenticatedReplayDisposition.IdempotentCompleted)
            {
                if (!CryptographicOperations.FixedTimeEquals(
                        verified.Capability.CachedOutcome.Span,
                        outcomeDigest))
                {
                    throw new InvalidOperationException(
                        "Completed authenticated replay outcome conflicts.");
                }
            }
            else
            {
                _runtime.Complete(verified, outcomeDigest);
            }

            _completedOutcomes[key] = outcomeDigest;
        }
    }

    private static string DigestKey(ReadOnlySpan<byte> canonicalRequestDigest)
    {
        if (canonicalRequestDigest.Length != 32)
        {
            throw new ArgumentException(
                "Canonical request digest must be SHA-256.",
                nameof(canonicalRequestDigest));
        }

        return Convert.ToHexString(canonicalRequestDigest);
    }

    private DecodedOuterRequest DecodeOuter(
        ReadOnlySpan<byte> canonicalRequest,
        MailboxClientOperation operation)
    {
        var policy = CreateDecodePolicy();
        var replay = new DeferredReplayGuard();
        return operation switch
        {
            MailboxClientOperation.Store => FromStore(
                MailboxClientCodec.DecodeStore(canonicalRequest, policy, replay)),
            MailboxClientOperation.Retrieve => FromRetrieve(
                MailboxClientCodec.DecodeRetrieve(canonicalRequest, policy, replay)),
            MailboxClientOperation.Acknowledge => FromAck(
                MailboxClientCodec.DecodeAck(canonicalRequest, policy, replay)),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
    }

    private static DecodedOuterRequest FromStore(MailboxStoreRequest request) => new(
        request.DepositCapability,
        MailboxCapabilityDomain.Deposit,
        request.Envelope.MailboxId.Bytes.ToArray(),
        request.OperationId.ToArray(),
        MailboxAuthenticatedRequestTranscript.ForStore(request.Envelope));

    private static DecodedOuterRequest FromRetrieve(MailboxRetrieveRequest request) => new(
        request.RetrieveCapability,
        MailboxCapabilityDomain.Retrieve,
        request.MailboxId.Bytes.ToArray(),
        request.OperationId.ToArray(),
        MailboxAuthenticatedRequestTranscript.ForRetrieve(
            request.Epoch,
            request.OperationId.Span,
            request.MailboxId,
            request.PlacementId,
            request.AfterCursor,
            request.MaximumItems,
            request.ContinuationToken.Span));

    private static DecodedOuterRequest FromAck(MailboxAckRequest request) => new(
        request.RetrieveCapability,
        MailboxCapabilityDomain.Retrieve,
        request.MailboxId.Bytes.ToArray(),
        request.OperationId.ToArray(),
        MailboxAuthenticatedRequestTranscript.ForAck(
            request.Epoch,
            request.OperationId.Span,
            request.MailboxId,
            request.PlacementId,
            request.IsFinalPage,
            request.ContinuationToken.Span,
            request.Acknowledgements));

    private MailboxClientDecodePolicy CreateDecodePolicy()
    {
        var now = checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());
        return new()
        {
            NowUnixSeconds = now,
            EpochWindow = _options.EpochWindow(),
            CapabilityPolicy = new MailboxCapabilityDecodePolicy
            {
                CurrentBucket = checked((uint)now),
                MinimumGeneration = _options.CurrentEpoch,
                AllowLegacyMirrorOverlap = false,
                AllowRevoked = false,
                AllowRecovery = false
            },
            AllowLegacyMirrorOverlap = false
        };
    }

    private static MailboxAuthenticatedOperation ToAuthenticatedOperation(
        MailboxClientOperation operation) =>
        operation switch
        {
            MailboxClientOperation.Store => MailboxAuthenticatedOperation.Store,
            MailboxClientOperation.Retrieve => MailboxAuthenticatedOperation.Retrieve,
            MailboxClientOperation.Acknowledge => MailboxAuthenticatedOperation.Ack,
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };

    private sealed record DecodedOuterRequest(
        MailboxCapabilityPresentation Capability,
        MailboxCapabilityDomain Domain,
        ReadOnlyMemory<byte> MailboxId,
        ReadOnlyMemory<byte> OperationId,
        MailboxAuthenticatedRequestBinding AuthenticatedBinding);

    private sealed class DeferredReplayGuard : IMailboxCapabilityReplayGuard
    {
        public MailboxCapabilityReplayEvaluation Evaluate(MailboxCapabilityReplayScope scope) =>
            new()
            {
                Decision = MailboxCapabilityReplayDecision.AcceptedNew,
                CachedOutcome = ReadOnlyMemory<byte>.Empty
            };
    }
}
