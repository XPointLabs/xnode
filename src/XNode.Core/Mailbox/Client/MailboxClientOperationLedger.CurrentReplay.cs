using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

// Metadata in the existing independently anchored operation document, not a
// second replay journal, a response reader, or fresh admission authority.
internal sealed record MailboxCurrentClientReplayFloor(
    ulong HighestCounter, string ClaimDigest, string CanonicalOutcomeDigest);

public sealed partial class MailboxClientOperationLedger
{
    internal async ValueTask RecordCurrentClientReplayAsync(MailboxCapabilityAtomicReplayClaim claim,
        ReadOnlyMemory<byte>? completedOutcome, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        var key = Convert.ToHexString(MailboxCapabilityReplayStateMachine.ComputeScopeKey(claim)).ToLowerInvariant();
        var digest = Convert.ToHexString(claim.ClaimDigest.Span).ToLowerInvariant();
        var outcome = completedOutcome is null ? "" :
            Convert.ToHexString(SHA256.HashData(completedOutcome.Value.Span)).ToLowerInvariant();
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(token, lease).ConfigureAwait(false);
            if (document.ClientReplayFloors.TryGetValue(key, out var prior))
            {
                if (claim.ReplayCounter < prior.HighestCounter || claim.ReplayCounter == prior.HighestCounter &&
                    (!FixedHexEquals(prior.ClaimDigest, digest) ||
                     outcome.Length != 0 && prior.CanonicalOutcomeDigest.Length != 0 &&
                     !FixedHexEquals(prior.CanonicalOutcomeDigest, outcome)))
                    throw new InvalidDataException("Current client replay differs from its independent floor.");
                if (claim.ReplayCounter == prior.HighestCounter &&
                    (outcome.Length == 0 || prior.CanonicalOutcomeDigest == outcome)) return;
            }
            else if (document.ClientReplayFloors.Count >= _maxEntries)
                throw new MailboxClientLedgerCapacityException();
            document.ClientReplayFloors[key] = new(claim.ReplayCounter, digest, outcome);
            await SaveAsync(document, token, lease).ConfigureAwait(false);
            // Save's protected Commit checks the live lease after read-back;
            // successful current saves perform no cleanup callback afterwards.
        }
        finally { _gate.Release(); }
    }
}
