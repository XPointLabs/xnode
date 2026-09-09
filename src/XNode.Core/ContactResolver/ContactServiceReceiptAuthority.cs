using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using Rebex.Security.Cryptography;
using XNode.Core.ContactPreKey;

namespace XNode.Core.ContactResolver;

internal enum ContactServiceReceiptKind
{
    PublishCommit = 1,
    UpdateCommit = 2,
    PreKeyClaimCommit = 3,
    InviteClaimCommit = 4
}

internal sealed class ContactServiceReplicaReceiptRequest
{
    private readonly byte[] tuple;

    internal ContactServiceReplicaReceiptRequest(
        ContactServiceReceiptKind kind,
        ReadOnlySpan<byte> canonicalTuple)
    {
        var expectedLength = ContactServiceReceiptTranscript.TupleLength(kind);
        if (canonicalTuple.Length != expectedLength)
        {
            throw new ArgumentException(
                $"The {kind} receipt tuple must contain exactly {expectedLength} bytes.",
                nameof(canonicalTuple));
        }

        Kind = kind;
        tuple = canonicalTuple.ToArray();
    }

    internal ContactServiceReceiptKind Kind { get; }
    internal ReadOnlyMemory<byte> CanonicalTuple => tuple.ToArray();
}

internal sealed record ContactServiceReplicaReceipt(
    ReadOnlyMemory<byte> ReplicaId,
    ReadOnlyMemory<byte> Signature);

internal sealed class ContactServiceReceiptAuthorityException : Exception
{
    internal ContactServiceReceiptAuthorityException(string message)
        : base(message)
    {
    }

    internal ContactServiceReceiptAuthorityException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal interface IContactServiceReplicaReceiptAuthority
{
    ReadOnlyMemory<byte> ReplicaId { get; }

    ValueTask<ContactServiceReplicaReceipt> IssueAsync(
        ContactServiceReplicaReceiptRequest request,
        CancellationToken cancellationToken);
}

internal sealed record ContactServiceReplicaBinding(
    IContactResolverReplica ResolverReplica,
    IContactPreKeyReplica PreKeyReplica,
    IContactServiceReplicaReceiptAuthority ReceiptAuthority);

/// <summary>
/// Local key-backed receipt authority. Production may use this for its one local
/// replica; the remote replica must provide its own authenticated implementation.
/// </summary>
internal sealed class LocalContactServiceReplicaReceiptAuthority :
    IContactServiceReplicaReceiptAuthority,
    IDisposable
{
    private readonly byte[] seed;
    private readonly byte[] replicaId;
    private bool disposed;

    internal LocalContactServiceReplicaReceiptAuthority(ReadOnlySpan<byte> ed25519Seed)
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

    public ValueTask<ContactServiceReplicaReceipt> IssueAsync(
        ContactServiceReplicaReceiptRequest request,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var signer = new Ed25519();
        signer.FromSeed(seed);
        var statement = ContactServiceReceiptTranscript.SigningInput(request);
        var signature = signer.SignMessage(statement);
        return ValueTask.FromResult(new ContactServiceReplicaReceipt(
            replicaId.ToArray(),
            signature));
    }

    internal byte[] SignBoundedPreKeyReceipt(Xic1BoundedUnsignedFields fields)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(fields);
        var signer = new Ed25519();
        signer.FromSeed(seed);
        var statement = Xic1BoundedCodec.CreateSignatureInput(fields);
        try
        {
            return Xic1BoundedCodec.Encode(fields, signer.SignMessage(statement));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(statement);
        }
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

internal static class ContactServiceReceiptTranscript
{
    internal static int TupleLength(ContactServiceReceiptKind kind) => kind switch
    {
        ContactServiceReceiptKind.PublishCommit => 72,
        ContactServiceReceiptKind.UpdateCommit => 80,
        ContactServiceReceiptKind.PreKeyClaimCommit => 138,
        ContactServiceReceiptKind.InviteClaimCommit => 160,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    internal static byte[] SigningInput(ContactServiceReplicaReceiptRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var domain = request.Kind switch
        {
            ContactServiceReceiptKind.PublishCommit =>
                "Deep/ContactResolver/V1/publish-commit",
            ContactServiceReceiptKind.UpdateCommit =>
                "Deep/ContactResolver/V1/update-commit",
            ContactServiceReceiptKind.PreKeyClaimCommit =>
                "Deep/ContactResolver/V1/prekey-claim-commit",
            ContactServiceReceiptKind.InviteClaimCommit =>
                "Deep/ContactResolver/V1/invite-claim-commit",
            _ => throw new ArgumentOutOfRangeException(nameof(request))
        };
        var label = Encoding.ASCII.GetBytes(domain);
        var tuple = request.CanonicalTuple;
        var output = new byte[label.Length + 7 + tuple.Length];
        label.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(label.Length + 1), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(label.Length + 3),
            checked((uint)tuple.Length));
        tuple.Span.CopyTo(output.AsSpan(label.Length + 7));
        return output;
    }

    internal static byte[] PreKeyClaimTuple(ContactPreKeyClaimResult claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        var dpk2 = Dpk2Codec.Decode(claim.ExactDpk2);
        var exactDpk2Hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(dpk2);
        var output = new byte[TupleLength(ContactServiceReceiptKind.PreKeyClaimCommit)];
        claim.RequestHash.CopyTo(output);
        exactDpk2Hash.CopyTo(output, 32);
        claim.Xpi1Hash.CopyTo(output.AsSpan(64));
        claim.OneTimePreKeyId.CopyTo(output.AsSpan(96));
        BinaryPrimitives.WriteUInt64BigEndian(
            output.AsSpan(128),
            claim.ClaimCommitGeneration);
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(136),
            claim.LastResortUseCounter);
        CryptographicOperations.ZeroMemory(exactDpk2Hash);
        return output;
    }

    internal static bool Verify(
        ReadOnlySpan<byte> replicaId,
        ReadOnlySpan<byte> statement,
        ReadOnlySpan<byte> signature)
    {
        if (replicaId.Length != 32 || signature.Length != 64)
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(replicaId.ToArray());
            return verifier.VerifyMessage(statement.ToArray(), signature.ToArray());
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
