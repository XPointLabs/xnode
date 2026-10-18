using System.Security.Cryptography;
using Deep.Protocol.BlobV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core;
using XNode.Core.Blob;
using XNode.Core.Mailbox;

namespace XNode;

internal sealed class BlobChunkOnionDispatcher(IServiceProvider services, RouterNodeOptions node,
    IMailboxStorageSecurity security, IMailboxDurabilityBarrier durability, IOnionMonotonicClock clock) : IDisposable
{
    private readonly SemaphoreSlim capacity = new(4, 4);
    private readonly object gate = new();
    private DurableBlobObjectStore? store;

    internal async Task<NativeMailboxDispatchResult> DispatchAsync(VerifiedCanonicalOnionRequest request, CancellationToken ct)
    {
        if (request.Operation != OnionOperation.Blob || !capacity.Wait(0)) return NativeMailboxDispatchResult.RejectedBeforeForward();
        var mutationStarted = false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            using var parsed = BlobChunkCodec.DecodeRequest(request.CanonicalBytes.Span);
            var source = services.GetService<IDeepIdV2ContactStoreAuthoritySource>() ?? throw new InvalidOperationException("Blob current authority unavailable.");
            var before = await source.ReadPublicationAuthorityAsync(deadline.Token).ConfigureAwait(false);
            var time = await RequireCurrentAsync(before, parsed, request.Network, deadline.Token).ConfigureAwait(false);
            DurableBlobObjectStore owner;
            lock (gate) owner = store ??= new(Path.Combine(node.DataDirectory, "blob-custody"), 1024, 16384, 536_870_912, security, durability);
            mutationStarted = parsed.Operation == BlobChunkOperation.Put;
            var result = owner.Execute(parsed, time.Lower, time.Upper, deadline.Token);
            try
            {
                var after = await source.ReadPublicationAuthorityAsync(deadline.Token).ConfigureAwait(false);
                var returned = await RequireCurrentAsync(after, parsed, request.Network, deadline.Token).ConfigureAwait(false);
                if (result.Status is BlobChunkStatus.Stored or BlobChunkStatus.ExactReplay or BlobChunkStatus.Chunk && returned.Upper >= parsed.Descriptor.ExpiresAtUnixSeconds)
                    throw new CryptographicException("Blob expired before authenticated completion.");
                return new(StatusCodes.Status200OK, BlobChunkCodec.EncodeResponse(parsed, result.Status, result.Ciphertext));
            }
            finally { CryptographicOperations.ZeroMemory(result.Ciphertext); }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or CryptographicException or InvalidOperationException or ArgumentException or OverflowException or OperationCanceledException or OnionBoundaryException)
        { return mutationStarted ? NativeMailboxDispatchResult.OutcomeUnknownAfterForward() : NativeMailboxDispatchResult.RejectedBeforeForward(); }
        finally { capacity.Release(); }
    }

    private async ValueTask<(ulong Lower, ulong Upper)> RequireCurrentAsync(DeepIdV2ContactStoreAuthority authority,
        BlobChunkRequest request, VerifiedOnionNetworkContext received, CancellationToken ct)
    {
        authority.Network.EnsureCurrent(); received.EnsureCurrent();
        if (!authority.Network.NetworkId.Span.SequenceEqual(request.Descriptor.NetworkId.Span) ||
            !received.NetworkId.Span.SequenceEqual(request.Descriptor.NetworkId.Span) ||
            !OnionPathContextFactory.BlobNodeIds(authority.Network, request.Descriptor.ObjectId).Any(id => id.Span.SequenceEqual(node.GetRouterId().ToBytes())))
            throw new CryptographicException("Blob network or local role differs from the verified descriptor roster.");
        var now = await clock.ReadAsync(ct).ConfigureAwait(false) ?? throw new CryptographicException("Blob monotonic clock unavailable.");
        if (!authority.Freshness.IsCurrentAtMonotonic(now.BootId.Span, now.SampleSeconds)) throw new CryptographicException("Blob directory observation expired.");
        var elapsed = checked(now.SampleSeconds - authority.Freshness.MonotonicSample);
        return (checked(authority.Freshness.TrustedLowerUnixSeconds + elapsed), checked(authority.Freshness.TrustedUpperUnixSeconds + elapsed));
    }
    public void Dispose() { lock (gate) { store?.Dispose(); capacity.Dispose(); } }
}
