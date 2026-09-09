using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.GroupV1;
using Rebex.Security.Cryptography;
using XNode.Core;
using XNode.Core.GroupControl;

namespace XNode;

internal sealed record GroupControlReplicaRpcCommand(
    GroupControlOperation Operation,
    ReadOnlyMemory<byte> CorrelationId,
    ReadOnlyMemory<byte> ExactCanonicalRequest);

internal sealed record GroupControlReplicaRpcResponse(
    GroupControlOperation Operation,
    ReadOnlyMemory<byte> CorrelationId,
    ReadOnlyMemory<byte> ReplicaId,
    ReadOnlyMemory<byte> Payload);

internal interface IGroupControlReplicaPeerClient
{
    ValueTask<GroupControlReplicaRpcResponse> SendAsync(
        GroupControlReplicaRpcCommand command,
        ReadOnlyMemory<byte> expectedRemoteReplicaId,
        CancellationToken cancellationToken);
}

internal sealed record GroupControlReplicaMutationWireResult(
    GroupControlMutationResult Mutation,
    ulong CommitGeneration,
    ReadOnlyMemory<byte> Signature);

internal static class GroupControlReplicaWireCodec
{
    internal const int MaximumRequestBytes = 33_204;
    internal const int MaximumResponseBytes = 2_200_000;
    private const byte Version = 1;
    private static ReadOnlySpan<byte> RequestMagic => "GRQ1"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "GRS1"u8;

    internal static byte[] Encode(GroupControlReplicaRpcCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!Enum.IsDefined(command.Operation)
            || command.CorrelationId.Length != 32
            || command.ExactCanonicalRequest.Length is < 304 or > 33_160)
        {
            throw new InvalidDataException("The group-control replica request is outside its closed bounds.");
        }
        var projection = GroupControlRequestProjection.Decode(command.ExactCanonicalRequest);
        if (projection.Operation != command.Operation)
        {
            throw new InvalidDataException(
                "The group-control replica operation does not bind its exact canonical request.");
        }
        var output = new byte[44 + command.ExactCanonicalRequest.Length];
        RequestMagic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)command.Operation;
        command.CorrelationId.Span.CopyTo(output.AsSpan(8));
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(40),
            checked((uint)command.ExactCanonicalRequest.Length));
        command.ExactCanonicalRequest.Span.CopyTo(output.AsSpan(44));
        return output;
    }

    internal static GroupControlReplicaRpcCommand DecodeRequest(ReadOnlySpan<byte> exact)
    {
        if (exact.Length is < 348 or > MaximumRequestBytes
            || !exact[..4].SequenceEqual(RequestMagic)
            || exact[4] != Version
            || !Enum.IsDefined((GroupControlOperation)exact[5])
            || exact[6] != 0
            || exact[7] != 0
            || BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(40, 4)) != exact.Length - 44)
        {
            throw new InvalidDataException("The group-control replica request envelope is malformed.");
        }
        var request = exact[44..].ToArray();
        var projection = GroupControlRequestProjection.Decode(request);
        var operation = (GroupControlOperation)exact[5];
        if (projection.Operation != operation)
        {
            throw new InvalidDataException("The group-control replica operation does not bind its exact request.");
        }
        return new GroupControlReplicaRpcCommand(operation, exact.Slice(8, 32).ToArray(), request);
    }

    internal static byte[] Encode(GroupControlReplicaRpcResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!Enum.IsDefined(response.Operation)
            || response.CorrelationId.Length != 32
            || response.ReplicaId.Length != 32
            || GroupControlOpaqueValue.IsZero(response.ReplicaId.Span)
            || response.Payload.Length > MaximumResponseBytes - 76)
        {
            throw new InvalidDataException("The group-control replica response is outside its closed bounds.");
        }
        if (response.Operation == GroupControlOperation.Write)
        {
            _ = DecodeMutation(response.Payload.Span);
        }
        else
        {
            _ = DecodeRead(response.Payload.Span);
        }
        var output = new byte[76 + response.Payload.Length];
        ResponseMagic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)response.Operation;
        response.CorrelationId.Span.CopyTo(output.AsSpan(8));
        response.ReplicaId.Span.CopyTo(output.AsSpan(40));
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(72),
            checked((uint)response.Payload.Length));
        response.Payload.Span.CopyTo(output.AsSpan(76));
        return output;
    }

    internal static GroupControlReplicaRpcResponse DecodeResponse(ReadOnlySpan<byte> exact)
    {
        if (exact.Length is < 76 or > MaximumResponseBytes
            || !exact[..4].SequenceEqual(ResponseMagic)
            || exact[4] != Version
            || !Enum.IsDefined((GroupControlOperation)exact[5])
            || exact[6] != 0
            || exact[7] != 0
            || BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(72, 4)) != exact.Length - 76)
        {
            throw new InvalidDataException("The group-control replica response envelope is malformed.");
        }
        return new GroupControlReplicaRpcResponse(
            (GroupControlOperation)exact[5],
            exact.Slice(8, 32).ToArray(),
            exact.Slice(40, 32).ToArray(),
            exact[76..].ToArray());
    }

    internal static byte[] EncodeMutation(
        GroupControlMutationResult result,
        ulong commitGeneration,
        ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(result);
        var durable = result.Disposition is GroupControlMutationDisposition.Committed
            or GroupControlMutationDisposition.ExactReplay;
        if (durable != (result.ControlSequence != 0
            && result.SealedGcf1Hash.Length == 32
            && commitGeneration != 0
            && signature.Length == 64))
        {
            throw new InvalidDataException("The group-control replica mutation receipt shape is invalid.");
        }
        if (!durable && (commitGeneration != 0 || signature.Length != 0))
        {
            throw new InvalidDataException("A rejected group-control mutation cannot carry a receipt.");
        }
        if (!durable)
        {
            var hasHead = result.ControlSequence != 0
                && result.SealedGcf1Hash.Length == 32
                && !GroupControlOpaqueValue.IsZero(result.SealedGcf1Hash);
            if ((result.Disposition == GroupControlMutationDisposition.StaleSequence) != hasHead
                || !hasHead
                    && (result.ControlSequence != 0 || result.SealedGcf1Hash.Length != 0))
            {
                throw new InvalidDataException("The rejected group-control mutation head is invalid.");
            }
        }
        var output = new byte[116];
        output[0] = 1;
        output[1] = checked((byte)result.Disposition);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(4), result.ControlSequence);
        if (result.SealedGcf1Hash.Length == 32)
        {
            result.SealedGcf1Hash.CopyTo(output, 12);
        }
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(44), commitGeneration);
        if (signature.Length == 64)
        {
            signature.CopyTo(output.AsSpan(52));
        }
        return output;
    }

    internal static GroupControlReplicaMutationWireResult DecodeMutation(ReadOnlySpan<byte> exact)
    {
        if (exact.Length != 116
            || exact[0] != 1
            || !Enum.IsDefined((GroupControlMutationDisposition)exact[1])
            || exact[2] != 0
            || exact[3] != 0)
        {
            throw new InvalidDataException("The group-control replica mutation response is malformed.");
        }
        var disposition = (GroupControlMutationDisposition)exact[1];
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8));
        var hash = exact.Slice(12, 32);
        var generation = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(44, 8));
        var signature = exact.Slice(52, 64);
        var durable = disposition is GroupControlMutationDisposition.Committed
            or GroupControlMutationDisposition.ExactReplay;
        if (durable)
        {
            if (sequence == 0 || GroupControlOpaqueValue.IsZero(hash)
                || generation == 0 || GroupControlOpaqueValue.IsZero(signature))
            {
                throw new InvalidDataException("The durable group-control replica receipt is incomplete.");
            }
        }
        else
        {
            var hasHead = sequence != 0 && !GroupControlOpaqueValue.IsZero(hash);
            if (generation != 0
                || !GroupControlOpaqueValue.IsZero(signature)
                || (disposition == GroupControlMutationDisposition.StaleSequence) != hasHead
                || !hasHead && (sequence != 0 || !GroupControlOpaqueValue.IsZero(hash)))
            {
                throw new InvalidDataException(
                    "A rejected group-control mutation carries forbidden receipt fields.");
            }
        }
        return new GroupControlReplicaMutationWireResult(
            new GroupControlMutationResult(
                disposition,
                sequence,
                GroupControlOpaqueValue.IsZero(hash) ? [] : hash.ToArray()),
            generation,
            durable ? signature.ToArray() : ReadOnlyMemory<byte>.Empty);
    }

    internal static byte[] EncodeRead(GroupControlReadResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        ValidateReadShape(result);
        if (result.Records.Count > GroupControlOpaqueStoreOptions.MaximumFetchRecords)
        {
            throw new InvalidDataException("The group-control replica page is oversized.");
        }
        var total = checked(48 + result.Records.Sum(GroupControlGss1Payload.EncodedRecordLength));
        if (total > MaximumResponseBytes - 76)
        {
            throw new InvalidDataException("The group-control replica page exceeds its transport bound.");
        }
        var output = new byte[total];
        output[0] = 2;
        output[1] = checked((byte)result.Disposition);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(4), result.CurrentControlSequence);
        if (result.CurrentControlHash.Length == 32)
        {
            result.CurrentControlHash.CopyTo(output, 12);
        }
        output[44] = result.HasMore ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(45), checked((ushort)result.Records.Count));
        var offset = 48;
        foreach (var record in result.Records)
        {
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), record.ControlSequence);
            offset += 8;
            record.PredecessorControlHash.CopyTo(output, offset);
            offset += 32;
            record.SealedGcf1Hash.CopyTo(output, offset);
            offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), record.EffectiveExpiresAtUnixSeconds);
            offset += 8;
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), checked((uint)record.SealedGcf1.Length));
            offset += 4;
            record.SealedGcf1.CopyTo(output, offset);
            offset += record.SealedGcf1.Length;
        }
        return output;
    }

    internal static GroupControlReadResult DecodeRead(ReadOnlySpan<byte> exact)
    {
        if (exact.Length < 48
            || exact[0] != 2
            || !Enum.IsDefined((GroupControlReadDisposition)exact[1])
            || exact[2] != 0
            || exact[3] != 0
            || exact[44] > 1
            || exact[47] != 0)
        {
            throw new InvalidDataException("The group-control replica read response is malformed.");
        }
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(45, 2));
        if (count > GroupControlOpaqueStoreOptions.MaximumFetchRecords)
        {
            throw new InvalidDataException("The group-control replica page count is invalid.");
        }
        var records = new List<OpaqueGroupControlRecord>(count);
        var offset = 48;
        for (var index = 0; index < count; index++)
        {
            if (exact.Length - offset < 84)
            {
                throw new InvalidDataException("The group-control replica record is truncated.");
            }
            var sequence = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(offset, 8));
            var predecessor = exact.Slice(offset + 8, 32).ToArray();
            var hash = exact.Slice(offset + 40, 32).ToArray();
            var expires = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(offset + 72, 8));
            var length = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(offset + 80, 4));
            offset += 84;
            if (length is < 1 or > GroupControlOpaqueStoreOptions.MaximumSealedGcf1Bytes
                || length > exact.Length - offset)
            {
                throw new InvalidDataException("The group-control replica ciphertext length is invalid.");
            }
            var ciphertext = exact.Slice(offset, checked((int)length)).ToArray();
            offset += checked((int)length);
            if (sequence == 0
                || predecessor.Length != 32
                || (sequence == 1) != GroupControlOpaqueValue.IsZero(predecessor)
                || GroupControlOpaqueValue.IsZero(hash)
                || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(ciphertext), hash))
            {
                throw new InvalidDataException("The group-control replica record is not self-consistent.");
            }
            records.Add(new OpaqueGroupControlRecord(sequence, predecessor, hash, ciphertext, expires));
        }
        if (offset != exact.Length)
        {
            throw new InvalidDataException("The group-control replica response has trailing bytes.");
        }
        var currentSequence = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8));
        var currentHash = exact.Slice(12, 32);
        if ((currentSequence == 0) != GroupControlOpaqueValue.IsZero(currentHash))
        {
            throw new InvalidDataException("The group-control replica head is invalid.");
        }
        var result = new GroupControlReadResult(
            (GroupControlReadDisposition)exact[1],
            records,
            currentSequence,
            currentSequence == 0 ? [] : currentHash.ToArray(),
            exact[44] == 1);
        ValidateReadShape(result);
        return result;
    }

    private static void ValidateReadShape(GroupControlReadResult result)
    {
        var events = result.Disposition == GroupControlReadDisposition.Events;
        if ((events && result.Records.Count == 0)
            || (!events && (result.Records.Count != 0 || result.HasMore))
            || result.Records.Count > GroupControlOpaqueStoreOptions.MaximumFetchRecords
            || (result.CurrentControlSequence == 0)
                != (result.CurrentControlHash.Length == 0)
            || result.CurrentControlHash.Length is not 0 and not 32
            || result.CurrentControlHash.Length == 32
                && GroupControlOpaqueValue.IsZero(result.CurrentControlHash)
            || result.Disposition == GroupControlReadDisposition.NotFound
                != (result.CurrentControlSequence == 0))
        {
            throw new InvalidDataException("The group-control replica read result shape is invalid.");
        }

        OpaqueGroupControlRecord? previous = null;
        foreach (var record in result.Records)
        {
            if (record.ControlSequence == 0
                || record.PredecessorControlHash.Length != 32
                || (record.ControlSequence == 1)
                    != GroupControlOpaqueValue.IsZero(record.PredecessorControlHash)
                || record.SealedGcf1Hash.Length != 32
                || GroupControlOpaqueValue.IsZero(record.SealedGcf1Hash)
                || record.SealedGcf1.Length is < 1
                    or > GroupControlOpaqueStoreOptions.MaximumSealedGcf1Bytes
                || record.EffectiveExpiresAtUnixSeconds == 0
                || !CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(record.SealedGcf1),
                    record.SealedGcf1Hash)
                || previous is not null
                    && (record.ControlSequence != previous.ControlSequence + 1
                        || !GroupControlOpaqueValue.FixedEquals(
                            record.PredecessorControlHash,
                            previous.SealedGcf1Hash)))
            {
                throw new InvalidDataException(
                    "The group-control replica record chain is not self-consistent.");
            }
            previous = record;
        }

        if (previous is not null
            && (previous.ControlSequence > result.CurrentControlSequence
                || previous.ControlSequence == result.CurrentControlSequence
                    && !GroupControlOpaqueValue.FixedEquals(
                        previous.SealedGcf1Hash,
                        result.CurrentControlHash)
                || !result.HasMore
                    && previous.ControlSequence != result.CurrentControlSequence))
        {
            throw new InvalidDataException(
                "The group-control replica page does not bind its current head.");
        }
    }
}

internal sealed class AuthenticatedRemoteGroupControlReplica :
    IGroupControlReplica,
    IGroupControlReplicaReceiptAuthority
{
    private readonly VerifiedGroupControlRequestAuthority authority;
    private readonly IGroupControlReplicaPeerClient peerClient;
    private readonly byte[] replicaId;
    private readonly byte[] exactRequest;
    private readonly object receiptGate = new();
    private GroupControlReplicaReceiptRequest? receiptRequest;
    private byte[]? receiptSignature;

    internal AuthenticatedRemoteGroupControlReplica(
        VerifiedGroupControlRequestAuthority authority,
        ReadOnlySpan<byte> localReplicaId,
        IGroupControlReplicaPeerClient peerClient,
        ReadOnlyMemory<byte> exactCanonicalRequest)
    {
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        this.peerClient = peerClient ?? throw new ArgumentNullException(nameof(peerClient));
        replicaId = authority.OtherReplica(localReplicaId);
        exactRequest = exactCanonicalRequest.ToArray();
    }

    public ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();

    public async ValueTask<GroupControlMutationResult> WriteAsync(
        OpaqueGroupControlWriteRequest request,
        CancellationToken cancellationToken)
    {
        var projection = GroupControlRequestProjection.Decode(exactRequest);
        if (projection.Operation != GroupControlOperation.Write
            || !CryptographicOperations.FixedTimeEquals(projection.RequestHash.Span, request.RequestHash))
        {
            throw new InvalidDataException("The remote group-control write is not bound to its exact GSW1.");
        }
        var response = await SendAsync(GroupControlOperation.Write, cancellationToken).ConfigureAwait(false);
        var decoded = GroupControlReplicaWireCodec.DecodeMutation(response.Payload.Span);
        if (decoded.Mutation.Disposition is GroupControlMutationDisposition.Committed
            or GroupControlMutationDisposition.ExactReplay)
        {
            var expected = new GroupControlReplicaReceiptRequest(
                request.RequestHash,
                decoded.Mutation.ControlSequence,
                decoded.Mutation.SealedGcf1Hash,
                decoded.CommitGeneration);
            if (!GroupControlReceiptTranscript.Verify(replicaId, expected, decoded.Signature.Span))
            {
                throw new InvalidDataException("The remote group-control receipt signature is invalid.");
            }
            lock (receiptGate)
            {
                receiptRequest = expected;
                receiptSignature = decoded.Signature.ToArray();
            }
        }
        return decoded.Mutation;
    }

    public async ValueTask<GroupControlReadResult> FetchAsync(
        OpaqueGroupControlFetchRequest request,
        CancellationToken cancellationToken)
    {
        var projection = GroupControlRequestProjection.Decode(exactRequest);
        if (projection.Operation != GroupControlOperation.Fetch
            || !CryptographicOperations.FixedTimeEquals(projection.RequestHash.Span, request.RequestHash))
        {
            throw new InvalidDataException("The remote group-control fetch is not bound to its exact GSQ1.");
        }
        var response = await SendAsync(GroupControlOperation.Fetch, cancellationToken).ConfigureAwait(false);
        return GroupControlReplicaWireCodec.DecodeRead(response.Payload.Span);
    }

    public ValueTask<GroupControlReplicaReceipt> IssueAsync(
        GroupControlReplicaReceiptRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (receiptGate)
        {
            if (receiptRequest is null
                || receiptSignature is null
                || !GroupControlReceiptTranscript.Same(receiptRequest, request))
            {
                throw new InvalidOperationException(
                    "No exact authenticated remote group-control write is bound to this receipt.");
            }
            return ValueTask.FromResult(new GroupControlReplicaReceipt(
                replicaId.ToArray(),
                receiptSignature.ToArray()));
        }
    }

    private async ValueTask<GroupControlReplicaRpcResponse> SendAsync(
        GroupControlOperation operation,
        CancellationToken cancellationToken)
    {
        var correlation = RandomNumberGenerator.GetBytes(32);
        var response = await peerClient.SendAsync(
            new GroupControlReplicaRpcCommand(operation, correlation, exactRequest),
            replicaId,
            cancellationToken).ConfigureAwait(false);
        if (response.Operation != operation
            || !CryptographicOperations.FixedTimeEquals(response.CorrelationId.Span, correlation)
            || !CryptographicOperations.FixedTimeEquals(response.ReplicaId.Span, replicaId))
        {
            throw new IOException("The group-control replica response binding is invalid.");
        }
        return response;
    }
}

internal sealed class ProductionGroupControlReplicaBindingSource : IGroupControlReplicaBindingSource
{
    private readonly GroupControlLocalReplicaRuntime local;
    private readonly IGroupControlReplicaPeerClient peerClient;

    internal ProductionGroupControlReplicaBindingSource(
        GroupControlLocalReplicaRuntime local,
        IGroupControlReplicaPeerClient peerClient)
    {
        this.local = local ?? throw new ArgumentNullException(nameof(local));
        this.peerClient = peerClient ?? throw new ArgumentNullException(nameof(peerClient));
    }

    public ValueTask<IReadOnlyList<GroupControlReplicaBinding>> ResolveAsync(
        VerifiedGroupControlRequestAuthority authority,
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var localId = local.Binding.Replica.ReplicaId.Span;
        if (!authority.ContainsReplica(localId))
        {
            throw new GroupControlAuthorityUnavailableException();
        }
        var remote = new AuthenticatedRemoteGroupControlReplica(
            authority,
            localId,
            peerClient,
            exactCanonicalRequest);
        return ValueTask.FromResult<IReadOnlyList<GroupControlReplicaBinding>>(
            [local.Binding, new GroupControlReplicaBinding(remote, remote)]);
    }
}

internal sealed class GroupControlReplicaRequestReceiver
{
    private readonly IGroupControlAuthoritySource authoritySource;
    private readonly GroupControlLocalReplicaRuntime local;
    private readonly IClock clock;

    internal GroupControlReplicaRequestReceiver(
        IGroupControlAuthoritySource authoritySource,
        GroupControlLocalReplicaRuntime local,
        IClock clock)
    {
        this.authoritySource = authoritySource ?? throw new ArgumentNullException(nameof(authoritySource));
        this.local = local ?? throw new ArgumentNullException(nameof(local));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    internal async ValueTask<GroupControlReplicaRpcResponse> ReceiveAsync(
        GroupControlReplicaRpcCommand command,
        RouterId authenticatedSender,
        CancellationToken cancellationToken)
    {
        var projection = GroupControlRequestProjection.Decode(command.ExactCanonicalRequest);
        if (projection.Operation != command.Operation)
        {
            throw new InvalidDataException("The group-control replica command operation is invalid.");
        }
        var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        var authority = await authoritySource.AuthorizeAsync(
            command.Operation,
            projection.Record,
            cancellationToken).ConfigureAwait(false);
        authority.EnsureBinds(projection, now);
        var localId = local.Binding.Replica.ReplicaId.Span;
        if (!authority.ContainsReplica(localId)
            || !authority.ContainsReplica(authenticatedSender.ToBytes())
            || CryptographicOperations.FixedTimeEquals(localId, authenticatedSender.ToBytes()))
        {
            throw new GroupControlAuthorityUnavailableException();
        }

        byte[] payload;
        if (command.Operation == GroupControlOperation.Write)
        {
            var result = await local.Binding.Replica.WriteAsync(
                projection.ToWrite(),
                cancellationToken).ConfigureAwait(false);
            var durable = result.Disposition is GroupControlMutationDisposition.Committed
                or GroupControlMutationDisposition.ExactReplay;
            if (durable)
            {
                var receiptRequest = new GroupControlReplicaReceiptRequest(
                    projection.RequestHash.Span,
                    result.ControlSequence,
                    result.SealedGcf1Hash,
                    result.ControlSequence);
                var receipt = await local.Binding.ReceiptAuthority.IssueAsync(
                    receiptRequest,
                    cancellationToken).ConfigureAwait(false);
                payload = GroupControlReplicaWireCodec.EncodeMutation(
                    result,
                    result.ControlSequence,
                    receipt.Signature.Span);
            }
            else
            {
                payload = GroupControlReplicaWireCodec.EncodeMutation(result, 0, []);
            }
        }
        else
        {
            var result = await local.Binding.Replica.FetchAsync(
                projection.ToFetch(),
                cancellationToken).ConfigureAwait(false);
            payload = GroupControlReplicaWireCodec.EncodeRead(result);
        }

        return new GroupControlReplicaRpcResponse(
            command.Operation,
            command.CorrelationId.ToArray(),
            local.Binding.Replica.ReplicaId.ToArray(),
            payload);
    }
}

internal sealed record GroupControlReplicaAuthenticationHeaders(
    string SenderReplicaId,
    string RecipientReplicaId,
    long TimestampUnixMilliseconds,
    string Nonce,
    string Correlation,
    string Signature);

internal static class GroupControlReplicaPeerAuthenticator
{
    internal const string SenderHeader = "Deep-Group-Replica-Sender";
    internal const string RecipientHeader = "Deep-Group-Replica-Recipient";
    internal const string TimestampHeader = "Deep-Group-Replica-Timestamp";
    internal const string NonceHeader = "Deep-Group-Replica-Nonce";
    internal const string CorrelationHeader = "Deep-Group-Replica-Correlation";
    internal const string SignatureHeader = "Deep-Group-Replica-Signature";
    internal static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(2);
    private static ReadOnlySpan<byte> RequestMagic => "GRA1"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "GRA2"u8;

    internal static GroupControlReplicaAuthenticationHeaders SignRequest(
        RouterId sender,
        RouterId recipient,
        string localPrivateSeedHex,
        ReadOnlySpan<byte> correlation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now) => Sign(
            RequestMagic, sender, recipient, localPrivateSeedHex,
            correlation32, exactBody, now);

    internal static GroupControlReplicaAuthenticationHeaders SignResponse(
        RouterId sender,
        RouterId recipient,
        string localPrivateSeedHex,
        ReadOnlySpan<byte> correlation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now) => Sign(
            ResponseMagic, sender, recipient, localPrivateSeedHex,
            correlation32, exactBody, now);

    internal static bool VerifyRequest(
        GroupControlReplicaAuthenticationHeaders headers,
        RouterId expectedRecipient,
        ReadOnlySpan<byte> expectedCorrelation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now,
        out RouterId sender,
        out byte[] nonce) => Verify(
            RequestMagic, headers, expectedRecipient, expectedCorrelation32,
            exactBody, now, out sender, out nonce);

    internal static bool VerifyResponse(
        GroupControlReplicaAuthenticationHeaders headers,
        RouterId expectedRecipient,
        RouterId expectedSender,
        ReadOnlySpan<byte> expectedCorrelation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now)
    {
        var valid = Verify(
            ResponseMagic, headers, expectedRecipient, expectedCorrelation32,
            exactBody, now, out var sender, out _);
        return valid && sender == expectedSender;
    }

    private static GroupControlReplicaAuthenticationHeaders Sign(
        ReadOnlySpan<byte> magic,
        RouterId sender,
        RouterId recipient,
        string localPrivateSeedHex,
        ReadOnlySpan<byte> correlation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now)
    {
        if (correlation32.Length != 32)
        {
            throw new ArgumentException("Group-control replica correlation must be 32 bytes.");
        }
        var seed = PrivacyRoutingOptions.DecodeHex32(
            localPrivateSeedHex.Trim(),
            "Group-control replica local Ed25519 seed");
        var nonce = RandomNumberGenerator.GetBytes(16);
        try
        {
            var signer = new Ed25519();
            signer.FromSeed(seed);
            if (RouterId.FromBytes(signer.GetPublicKey()) != sender)
            {
                throw new InvalidOperationException(
                    "The group-control replica key does not match the local node identity.");
            }
            var timestamp = now.ToUnixTimeMilliseconds();
            var signature = signer.SignMessage(BuildTranscript(
                magic, sender, recipient, timestamp, nonce, correlation32, exactBody));
            return new GroupControlReplicaAuthenticationHeaders(
                sender.Value,
                recipient.Value,
                timestamp,
                Convert.ToHexStringLower(nonce),
                Convert.ToHexStringLower(correlation32),
                Convert.ToHexStringLower(signature));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private static bool Verify(
        ReadOnlySpan<byte> magic,
        GroupControlReplicaAuthenticationHeaders headers,
        RouterId expectedRecipient,
        ReadOnlySpan<byte> expectedCorrelation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now,
        out RouterId sender,
        out byte[] nonce)
    {
        sender = default;
        nonce = [];
        if (expectedCorrelation32.Length != 32
            || !RouterId.TryParse(headers.SenderReplicaId, out sender)
            || !RouterId.TryParse(headers.RecipientReplicaId, out var recipient)
            || sender == recipient
            || recipient != expectedRecipient
            || headers.Nonce.Length != 32
            || headers.Correlation.Length != 64
            || headers.Signature.Length != 128
            || !headers.Nonce.All(IsLowerHex)
            || !headers.Correlation.All(IsLowerHex)
            || !headers.Signature.All(IsLowerHex))
        {
            return false;
        }
        try
        {
            var signedAt = DateTimeOffset.FromUnixTimeMilliseconds(headers.TimestampUnixMilliseconds);
            var correlation = Convert.FromHexString(headers.Correlation);
            if ((now - signedAt).Duration() > MaximumClockSkew
                || !CryptographicOperations.FixedTimeEquals(correlation, expectedCorrelation32))
            {
                return false;
            }
            nonce = Convert.FromHexString(headers.Nonce);
            var verifier = new Ed25519();
            verifier.FromPublicKey(sender.ToBytes());
            return verifier.VerifyMessage(
                BuildTranscript(
                    magic, sender, recipient, headers.TimestampUnixMilliseconds,
                    nonce, correlation, exactBody),
                Convert.FromHexString(headers.Signature));
        }
        catch (Exception exception) when (exception is ArgumentException
            or ArgumentOutOfRangeException
            or CryptographicException
            or InvalidOperationException)
        {
            nonce = [];
            return false;
        }
    }

    private static byte[] BuildTranscript(
        ReadOnlySpan<byte> magic,
        RouterId sender,
        RouterId recipient,
        long timestamp,
        ReadOnlySpan<byte> nonce16,
        ReadOnlySpan<byte> correlation32,
        ReadOnlySpan<byte> exactBody)
    {
        var routeHash = SHA256.HashData(Encoding.ASCII.GetBytes(GroupControlReplicaHttpContract.Route));
        var bodyHash = SHA256.HashData(exactBody);
        var output = new byte[188];
        magic.CopyTo(output);
        sender.ToBytes().CopyTo(output, 4);
        recipient.ToBytes().CopyTo(output, 36);
        routeHash.CopyTo(output, 68);
        BinaryPrimitives.WriteInt64BigEndian(output.AsSpan(100), timestamp);
        nonce16.CopyTo(output.AsSpan(108));
        correlation32.CopyTo(output.AsSpan(124));
        bodyHash.CopyTo(output, 156);
        return output;
    }

    private static bool IsLowerHex(char value) =>
        value is >= '0' and <= '9' or >= 'a' and <= 'f';
}

internal sealed class GroupControlReplicaReplayGuard
{
    private readonly ConcurrentDictionary<string, long> accepted = new(StringComparer.Ordinal);
    private readonly object gate = new();
    private readonly int capacity;
    private readonly TimeSpan ttl;
    private long lastPruned;

    public GroupControlReplicaReplayGuard(GroupControlServiceOptions options)
    {
        capacity = options.ReplayCapacity;
        ttl = options.ReplayTtl;
    }

    internal bool TryAccept(
        RouterId sender,
        ReadOnlySpan<byte> nonce,
        long timestamp,
        DateTimeOffset now)
    {
        lock (gate)
        {
            Prune(now);
            if (accepted.Count >= capacity)
            {
                return false;
            }
            return accepted.TryAdd(
                string.Concat(sender.Value, ":", Convert.ToHexStringLower(nonce)),
                timestamp);
        }
    }

    private void Prune(DateTimeOffset now)
    {
        var current = now.ToUnixTimeMilliseconds();
        var prior = Interlocked.Read(ref lastPruned);
        if (current - prior < TimeSpan.FromMinutes(1).TotalMilliseconds
            || Interlocked.CompareExchange(ref lastPruned, current, prior) != prior)
        {
            return;
        }
        var cutoff = now.Subtract(ttl).ToUnixTimeMilliseconds();
        foreach (var item in accepted)
        {
            if (item.Value < cutoff)
            {
                accepted.TryRemove(item.Key, out _);
            }
        }
    }
}

internal static class GroupControlReplicaHttpContract
{
    internal const string Route = "/api/peer/group-control/v1/execute";
    internal const string MediaType = "application/vnd.deep.group-control-replica-v1";
}

internal sealed class HttpGroupControlReplicaPeerClient : IGroupControlReplicaPeerClient
{
    private readonly RouterNodeOptions node;
    private readonly PrivacyRoutingConfiguration privacy;
    private readonly GroupControlServiceOptions options;
    private readonly IClock clock;
    private readonly Func<PrivacyPeer, HttpMessageHandler> handlerFactory;

    public HttpGroupControlReplicaPeerClient(
        RouterNodeOptions node,
        PrivacyRoutingConfiguration privacy,
        GroupControlServiceOptions options,
        IClock clock)
        : this(node, privacy, options, clock, static peer => HttpPrivacyPeerClient.CreatePinnedHandler(peer))
    {
    }

    internal HttpGroupControlReplicaPeerClient(
        RouterNodeOptions node,
        PrivacyRoutingConfiguration privacy,
        GroupControlServiceOptions options,
        IClock clock,
        Func<PrivacyPeer, HttpMessageHandler> handlerFactory)
    {
        this.node = node;
        this.privacy = privacy;
        this.options = options;
        this.clock = clock;
        this.handlerFactory = handlerFactory;
    }

    public async ValueTask<GroupControlReplicaRpcResponse> SendAsync(
        GroupControlReplicaRpcCommand command,
        ReadOnlyMemory<byte> expectedRemoteReplicaId,
        CancellationToken cancellationToken)
    {
        var local = node.GetRouterId();
        var remote = RouterId.FromBytes(expectedRemoteReplicaId.Span);
        if (!privacy.Enabled
            || !privacy.Peers.TryGetValue(remote, out var peer)
            || peer.Endpoint.Scheme != Uri.UriSchemeHttps)
        {
            throw new IOException(
                "The verified group-control replica has no authenticated HTTPS peer binding.");
        }
        var body = GroupControlReplicaWireCodec.Encode(command);
        var authentication = GroupControlReplicaPeerAuthenticator.SignRequest(
            local, remote, node.GetEd25519PrivateKey(), command.CorrelationId.Span, body, clock.UtcNow);
        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(GroupControlReplicaHttpContract.MediaType);
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(peer.Endpoint, GroupControlReplicaHttpContract.Route))
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = content
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(GroupControlReplicaHttpContract.MediaType));
        AddHeaders(request, authentication);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ReplicaTimeout);
        try
        {
            using var handler = handlerFactory(peer);
            using var client = new HttpClient(handler, disposeHandler: false);
            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            if (response.Version != HttpVersion.Version20
                || response.StatusCode != HttpStatusCode.OK
                || response.Content.Headers.ContentLength is not long length
                || length is < 76 or > GroupControlReplicaWireCodec.MaximumResponseBytes
                || !string.Equals(
                    response.Content.Headers.ContentType?.ToString(),
                    GroupControlReplicaHttpContract.MediaType,
                    StringComparison.Ordinal)
                || response.Content.Headers.ContentEncoding.Count != 0)
            {
                throw new IOException("The group-control replica response envelope is not exact.");
            }
            var exact = await HttpPrivacyPeerClient.ReadExactlyBoundedAsync(
                response.Content,
                checked((int)length),
                timeout.Token).ConfigureAwait(false);
            var decoded = GroupControlReplicaWireCodec.DecodeResponse(exact);
            if (!GroupControlReplicaPeerAuthenticator.VerifyResponse(
                    ReadHeaders(response),
                    local,
                    remote,
                    command.CorrelationId.Span,
                    exact,
                    clock.UtcNow)
                || decoded.Operation != command.Operation
                || !CryptographicOperations.FixedTimeEquals(
                    decoded.CorrelationId.Span,
                    command.CorrelationId.Span)
                || !CryptographicOperations.FixedTimeEquals(
                    decoded.ReplicaId.Span,
                    expectedRemoteReplicaId.Span))
            {
                throw new IOException("The group-control replica response authentication is invalid.");
            }
            return decoded;
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IOException("The group-control replica outcome is unknown.", exception);
        }
        catch (Exception exception) when (exception is HttpRequestException
            or InvalidDataException
            or CryptographicException)
        {
            throw new IOException("The group-control replica outcome is unknown.", exception);
        }
    }

    private static void AddHeaders(
        HttpRequestMessage request,
        GroupControlReplicaAuthenticationHeaders headers)
    {
        request.Headers.TryAddWithoutValidation(GroupControlReplicaPeerAuthenticator.SenderHeader, headers.SenderReplicaId);
        request.Headers.TryAddWithoutValidation(GroupControlReplicaPeerAuthenticator.RecipientHeader, headers.RecipientReplicaId);
        request.Headers.TryAddWithoutValidation(GroupControlReplicaPeerAuthenticator.TimestampHeader,
            headers.TimestampUnixMilliseconds.ToString(CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(GroupControlReplicaPeerAuthenticator.NonceHeader, headers.Nonce);
        request.Headers.TryAddWithoutValidation(GroupControlReplicaPeerAuthenticator.CorrelationHeader, headers.Correlation);
        request.Headers.TryAddWithoutValidation(GroupControlReplicaPeerAuthenticator.SignatureHeader, headers.Signature);
    }

    private static GroupControlReplicaAuthenticationHeaders ReadHeaders(HttpResponseMessage response) => new(
        Single(response, GroupControlReplicaPeerAuthenticator.SenderHeader),
        Single(response, GroupControlReplicaPeerAuthenticator.RecipientHeader),
        long.TryParse(Single(response, GroupControlReplicaPeerAuthenticator.TimestampHeader),
            NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp) ? timestamp : long.MinValue,
        Single(response, GroupControlReplicaPeerAuthenticator.NonceHeader),
        Single(response, GroupControlReplicaPeerAuthenticator.CorrelationHeader),
        Single(response, GroupControlReplicaPeerAuthenticator.SignatureHeader));

    private static string Single(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values)
            ? values.SingleOrDefault() ?? ""
            : "";
}
