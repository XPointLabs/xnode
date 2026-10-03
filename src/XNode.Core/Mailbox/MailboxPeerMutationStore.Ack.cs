using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox;

internal sealed record MailboxCurrentAckTarget(ulong Cursor, ReadOnlyMemory<byte> EnvelopeDigest,
    ulong ExpiresAtUnixSeconds);

public sealed partial class MailboxPeerMutationStore
{
    internal async Task<IReadOnlyList<MailboxCurrentAckTarget>> ReadCurrentAckTargetsAsync(
        MailboxAuthenticatedAckBody request, ReadOnlyMemory<byte> membership,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var scope = RetrieveScope(request.Epoch, Hex(request.MailboxId.Bytes.Span),
                Hex(MailboxPlacementCommitment.Compute(request.PlacementId)), Hex(membership.Span));
            if (!_retrieveIndex.TryGetValue(scope, out var index)) throw new InvalidDataException("Current ACK target is missing.");
            var targets = new List<MailboxCurrentAckTarget>(request.Acknowledgements.Count);
            foreach (var item in request.Acknowledgements)
            {
                var upper = await lease.CheckAsync(token).ConfigureAwait(false);
                if (!index.TryGetValue(item.Cursor, out var paths) || paths.Count != 1)
                    throw new InvalidDataException("Current ACK cursor custody is missing or ambiguous.");
                var path = paths.Single(); var record = Read(path);
                if (record.State != "completed" || record.Cursor != item.Cursor || RetrieveScope(record) != scope ||
                    Path.GetFileNameWithoutExtension(path) != RecordKey(record.Epoch, record.MailboxId, record.EnvelopeDigest) ||
                    !FixedHex(record.EnvelopeDigest, item.EnvelopeDigest.Span) || record.ExpiresAtUnixSeconds <= upper ||
                    record.StoreCreatedAtUnixSeconds > upper)
                    throw new InvalidDataException("Current ACK differs from completed native Store custody.");
                targets.Add(new(item.Cursor, item.EnvelopeDigest.ToArray(), record.ExpiresAtUnixSeconds));
            }
            var finalUpper = await lease.CheckAsync(token).ConfigureAwait(false);
            if (targets.Any(target => target.ExpiresAtUnixSeconds <= finalUpper))
                throw new InvalidDataException("Current ACK target expired during read.");
            return targets;
        }
        finally { _gate.Release(); }
    }
}
