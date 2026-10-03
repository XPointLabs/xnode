using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode;

internal sealed partial class CurrentMailboxReplicaReceiver
{
    internal ValueTask<ReadOnlyMemory<byte>> RetrieveClientAsync(ReadOnlyMemory<byte> canonicalClientRequest,
        CancellationToken token = default)
    {
        var client = MailboxAuthenticatedClientRequestCodec.Decode(canonicalClientRequest.Span);
        var owned = MailboxAuthenticatedClientRequestCodec.Encode(client);
        if (client.Binding.Operation != MailboxAuthenticatedOperation.Retrieve)
            throw new CryptographicException("Current Retrieve requires its exact client operation.");
        var body = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(client.Binding.CanonicalRequest.Span);
        return WithClientRequestAsync<ReadOnlyMemory<byte>>(owned, MailboxAuthenticatedOperation.Retrieve,
            async (request, ct) =>
            {
                var scope = request.Scope;
                var local = scope.Replicas.Single(replica => Fixed(replica.NodeId.Span, LocalNodeId.Span));
                if (!Fixed(crypto.GetPublicKey(seed), local.SigningPublicKey.Span))
                    throw new CryptographicException("Current Retrieve signing custody differs from its descriptor.");
                var upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
                // Admission recovered this exact request's native outcome.
                // Pagination expiry must not discard it or remint a page, but
                // independent current grant/time/revocation checks remain required.
                if (request.RecoveredOutcome is { } recovered)
                {
                    if (recovered.Kind != MailboxClientCanonicalOutcomeKind.Success || recovered.Operation != MailboxAuthenticatedOperation.Retrieve)
                        throw new InvalidDataException("Current Retrieve outcome differs from the operation.");
                    var page = MailboxClientCodec.DecodeRetrievePage(recovered.CanonicalBytes.Span, new()
                    {
                        NowUnixSeconds = upper,
                        EpochWindow = new()
                        {
                            CurrentEpoch = scope.Host.SelectionEpoch,
                            NextEpoch = 0,
                            CurrentNotBeforeUnixSeconds = scope.Grant.NotBeforeUnixSeconds,
                            CurrentExpiresAtUnixSeconds = scope.Grant.ExpiresAtUnixSeconds,
                            NextNotBeforeUnixSeconds = 0,
                            NextExpiresAtUnixSeconds = 0
                        },
                        // MRP1 has no capability: this mandatory codec option is
                        // unused by its decoder and grants no admission authority.
                        CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = scope.Grant.Generation }
                    });
                    if (page.Epoch != body.Epoch || !Fixed(page.OperationId.Span, body.OperationId.Span))
                        throw new InvalidDataException("Current Retrieve outcome differs from the request.");
                    return (await request.CompleteRecoveredAsync(ct).ConfigureAwait(false)).CanonicalBytes;
                }
                ulong snapshot = 0;
                if (body.AfterCursor == 0)
                {
                    if (!body.ContinuationToken.IsEmpty) throw new CryptographicException("Current Retrieve continuation is invalid.");
                }
                else
                {
                    bool Verify(ReadOnlySpan<byte> statement, ReadOnlySpan<byte> signature)
                    {
                        foreach (var replica in scope.Replicas)
                            if (crypto.Verify(replica.SigningPublicKey.Span, statement, signature)) return true;
                        return false;
                    }
                    if (!MailboxContinuationToken.TryRead(body.ContinuationToken.Span, body.Epoch, body.AfterCursor,
                            upper, body.MailboxId.Bytes.Span, scope.Grant.PlacementCommitment.Span,
                            scope.Host.MembershipCommitment.Span, MailboxContinuationToken.RetrievePurpose, Verify, out var window) ||
                        body.MaximumItems > window.MaximumItems)
                        throw new CryptographicException("Current Retrieve continuation is invalid.");
                    snapshot = window.SnapshotHighWater;
                }
                if (!await request.TryAcquireExecutionAsync(ct).ConfigureAwait(false))
                    throw new InvalidOperationException("Current Retrieve already has an active execution.");
                var maximum = MailboxWireHttpContract.Retrieve.MaximumResponseBytes;
                await request.ReserveOutcomeCapacityAsync(maximum, ct).ConfigureAwait(false);
                var read = await mutations.ReadCurrentWindowAsync(body, scope.Host.MembershipCommitment,
                    snapshot, scope.Lease, ct).ConfigureAwait(false);
                var selectedCount = Math.Min(body.MaximumItems, read.Items.Count);
                while (true)
                {
                    upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
                    var selected = read.Items.Take(selectedCount).ToArray(); var hasMore = read.Items.Count > selectedCount;
                    if (hasMore && selectedCount == 0) throw new InvalidDataException("Current Retrieve page cannot fit.");
                    if (selected.Any(item => item.Envelope.ExpiresAtUnixSeconds <= upper))
                        throw new InvalidDataException("Current Retrieve object expired before outcome.");
                    var continuation = hasMore ? MailboxContinuationToken.Create(body.Epoch, selected[^1].Cursor,
                        read.SnapshotHighWater, body.MaximumItems, Math.Min(scope.Grant.ExpiresAtUnixSeconds, checked(upper + 600)),
                        body.MailboxId.Bytes.Span, scope.Grant.PlacementCommitment.Span, scope.Host.MembershipCommitment.Span,
                        PageDigest(selected), SignContinuation) : [];
                    var page = new MailboxRetrievePage
                    {
                        Epoch = body.Epoch,
                        OperationId = body.OperationId,
                        NextCursor = selectedCount == 0 ? 0 : selected[^1].Cursor,
                        HasMore = hasMore,
                        ContinuationToken = continuation,
                        Items = selected
                    };
                    byte[] bytes;
                    try { bytes = MailboxClientCodec.EncodeRetrievePage(page); }
                    catch (MailboxClientException error) when (error.Error == MailboxClientError.EncodedLengthOutOfRange && selectedCount > 0)
                    { selectedCount--; continue; }
                    return (await request.PersistSuccessAsync(bytes, maximum, ct).ConfigureAwait(false)).CanonicalBytes;
                }
            }, token);
    }

    private byte[] SignContinuation(ReadOnlySpan<byte> statement)
    {
        var privateKey = seed.Length == 32 ? Sodium.PublicKeyAuth.GenerateKeyPair(seed).PrivateKey : seed.ToArray();
        try { return Sodium.PublicKeyAuth.SignDetached(statement.ToArray(), privateKey); }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }
    private static byte[] PageDigest(IReadOnlyList<MailboxRetrievedEnvelope> items)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> cursor = stackalloc byte[8];
        foreach (var item in items)
        {
            BinaryPrimitives.WriteUInt64BigEndian(cursor, item.Cursor); hash.AppendData(cursor);
            hash.AppendData(item.Envelope.DeduplicationDigest.Span);
        }
        return hash.GetHashAndReset();
    }
}
