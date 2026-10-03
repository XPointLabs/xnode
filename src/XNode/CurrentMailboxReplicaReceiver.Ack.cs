using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode;

internal sealed partial class CurrentMailboxReplicaReceiver
{
    internal async ValueTask RequireAckContinuationAsync(CurrentMailboxAdmission.GrantScope scope,
        MailboxAuthenticatedAckBody body, CancellationToken token)
    {
        scope.Lease.RequireActive();
        if (!ReferenceEquals(scope.Owner, admission)) throw new CryptographicException("Current ACK belongs to another native owner.");
        var upper = await scope.Lease.CheckAsync(token).ConfigureAwait(false);
        if (body.IsFinalPage)
        {
            if (!body.ContinuationToken.IsEmpty) throw new CryptographicException("Current final ACK continuation is invalid.");
            return;
        }
        bool Verify(ReadOnlySpan<byte> statement, ReadOnlySpan<byte> signature)
        {
            foreach (var replica in scope.Replicas)
                if (crypto.Verify(replica.SigningPublicKey.Span, statement, signature)) return true;
            return false;
        }
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var cursor = new byte[8];
        foreach (var item in body.Acknowledgements)
        {
            BinaryPrimitives.WriteUInt64BigEndian(cursor, item.Cursor); hash.AppendData(cursor);
            hash.AppendData(item.EnvelopeDigest.Span);
        }
        if (!MailboxContinuationToken.TryRead(body.ContinuationToken.Span, body.Epoch, body.Acknowledgements[^1].Cursor,
                upper, body.MailboxId.Bytes.Span, scope.Grant.PlacementCommitment.Span, scope.Host.MembershipCommitment.Span,
                MailboxContinuationToken.AckPurpose, Verify, out var window) ||
            !Fixed(window.PageAcknowledgementDigest.Span, hash.GetHashAndReset()))
            throw new CryptographicException("Current ACK continuation differs from its exact page.");
    }
}
