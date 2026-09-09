using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Rebex.Security.Cryptography;

namespace XNode.Core.GroupControl;

internal sealed class GroupControlReplicaReceiptRequest
{
    private readonly byte[] requestHash;
    private readonly byte[] sealedGcf1Hash;

    internal GroupControlReplicaReceiptRequest(
        ReadOnlySpan<byte> requestHash32,
        ulong controlSequence,
        ReadOnlySpan<byte> sealedGcf1Hash32,
        ulong commitGeneration)
    {
        requestHash = GroupControlOpaqueValue.CopyNonZero32(
            requestHash32,
            nameof(requestHash32));
        sealedGcf1Hash = GroupControlOpaqueValue.CopyNonZero32(
            sealedGcf1Hash32,
            nameof(sealedGcf1Hash32));
        if (controlSequence == 0 || commitGeneration == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(controlSequence),
                "A durable group-control receipt requires non-zero sequence and commit generation.");
        }

        ControlSequence = controlSequence;
        CommitGeneration = commitGeneration;
    }

    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal ulong ControlSequence { get; }
    internal ReadOnlySpan<byte> SealedGcf1Hash => sealedGcf1Hash;
    internal ulong CommitGeneration { get; }
}

internal sealed record GroupControlReplicaReceipt(
    ReadOnlyMemory<byte> ReplicaId,
    ReadOnlyMemory<byte> Signature);

internal interface IGroupControlReplicaReceiptAuthority
{
    ReadOnlyMemory<byte> ReplicaId { get; }

    ValueTask<GroupControlReplicaReceipt> IssueAsync(
        GroupControlReplicaReceiptRequest request,
        CancellationToken cancellationToken);
}

internal sealed record GroupControlReplicaBinding(
    IGroupControlReplica Replica,
    IGroupControlReplicaReceiptAuthority ReceiptAuthority)
{
    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(Replica);
        ArgumentNullException.ThrowIfNull(ReceiptAuthority);
        if (!GroupControlOpaqueValue.FixedEquals(
                Replica.ReplicaId.Span,
                ReceiptAuthority.ReplicaId.Span))
        {
            throw new InvalidOperationException(
                "The group-control store and receipt authority must use one replica identity.");
        }
    }
}

internal sealed class LocalGroupControlReplicaReceiptAuthority :
    IGroupControlReplicaReceiptAuthority,
    IDisposable
{
    private readonly byte[] seed;
    private readonly byte[] replicaId;
    private bool disposed;

    internal LocalGroupControlReplicaReceiptAuthority(ReadOnlySpan<byte> ed25519Seed)
    {
        if (ed25519Seed.Length != 32 || ed25519Seed.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A non-zero 32-byte Ed25519 seed is required.",
                nameof(ed25519Seed));
        }

        seed = ed25519Seed.ToArray();
        var signer = new Ed25519();
        signer.FromSeed(seed);
        replicaId = signer.GetPublicKey();
    }

    public ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();

    public ValueTask<GroupControlReplicaReceipt> IssueAsync(
        GroupControlReplicaReceiptRequest request,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var signer = new Ed25519();
        signer.FromSeed(seed);
        return ValueTask.FromResult(new GroupControlReplicaReceipt(
            replicaId.ToArray(),
            signer.SignMessage(GroupControlReceiptTranscript.SigningInput(request))));
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        CryptographicOperations.ZeroMemory(seed);
    }
}

internal static class GroupControlReceiptTranscript
{
    private const ushort Suite = 0x0201;
    private const int TupleLength = 80;
    private const string Domain = "Deep/Group/V1/control-store-commit";

    internal static byte[] SigningInput(GroupControlReplicaReceiptRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var tuple = new byte[TupleLength];
        request.RequestHash.CopyTo(tuple);
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(32), request.ControlSequence);
        request.SealedGcf1Hash.CopyTo(tuple.AsSpan(40));
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(72), request.CommitGeneration);

        var label = Encoding.ASCII.GetBytes(Domain);
        var output = new byte[label.Length + 7 + tuple.Length];
        label.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(label.Length + 1), Suite);
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(label.Length + 3),
            checked((uint)tuple.Length));
        tuple.CopyTo(output.AsSpan(label.Length + 7));
        CryptographicOperations.ZeroMemory(tuple);
        return output;
    }

    internal static bool Verify(
        ReadOnlySpan<byte> replicaId32,
        GroupControlReplicaReceiptRequest request,
        ReadOnlySpan<byte> signature64)
    {
        if (replicaId32.Length != 32 || signature64.Length != 64)
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(replicaId32.ToArray());
            return verifier.VerifyMessage(
                SigningInput(request),
                signature64.ToArray());
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            return false;
        }
    }

    internal static bool Same(
        GroupControlReplicaReceiptRequest left,
        GroupControlReplicaReceiptRequest right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.ControlSequence == right.ControlSequence
            && left.CommitGeneration == right.CommitGeneration
            && GroupControlOpaqueValue.FixedEquals(left.RequestHash, right.RequestHash)
            && GroupControlOpaqueValue.FixedEquals(left.SealedGcf1Hash, right.SealedGcf1Hash);
    }
}
