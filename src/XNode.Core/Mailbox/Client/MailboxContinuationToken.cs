using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

internal delegate byte[] SignMailboxContinuation(ReadOnlySpan<byte> statement);
internal delegate bool VerifyMailboxContinuation(ReadOnlySpan<byte> statement, ReadOnlySpan<byte> signature);

// Existing neutral XCT1 pagination framing, not grant, placement or receipt authority.
// The caller owns admission and supplies its checked time and actual signer keys.
internal static class MailboxContinuationToken
{
    internal const byte RetrievePurpose = 1, AckPurpose = 2;
    private const int SigningLength = 168, Length = SigningLength + 64;
    internal readonly record struct Window(ulong SnapshotHighWater, ushort MaximumItems,
        ReadOnlyMemory<byte> PageAcknowledgementDigest);

    internal static byte[] Create(ulong epoch, ulong cursor, ulong highWater, ushort maximumItems,
        ulong expiresAt, ReadOnlySpan<byte> mailbox, ReadOnlySpan<byte> placement,
        ReadOnlySpan<byte> membership, ReadOnlySpan<byte> pageDigest, SignMailboxContinuation sign)
    {
        if (epoch == 0 || cursor == 0 || highWater < cursor || expiresAt == 0 ||
            maximumItems is 0 or > MailboxClientLimits.MaximumPageItems ||
            mailbox.Length != 32 || placement.Length != 32 || membership.Length != 32 || pageDigest.Length != 32)
            throw new InvalidOperationException("Continuation token window is invalid.");
        var token = new byte[Length]; "XCT1"u8.CopyTo(token);
        token[4] = 1; token[5] = RetrievePurpose | AckPurpose;
        BinaryPrimitives.WriteUInt16BigEndian(token.AsSpan(6), maximumItems);
        BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(8), epoch);
        BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(16), cursor);
        BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(24), expiresAt);
        BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(32), highWater);
        mailbox.CopyTo(token.AsSpan(40)); placement.CopyTo(token.AsSpan(72));
        membership.CopyTo(token.AsSpan(104)); pageDigest.CopyTo(token.AsSpan(136));
        var signature = sign(token.AsSpan(0, SigningLength));
        if (signature.Length != 64) throw new CryptographicException("Continuation signature length is invalid.");
        signature.CopyTo(token, SigningLength); return token;
    }

    internal static bool TryRead(ReadOnlySpan<byte> token, ulong epoch, ulong cursor, ulong now,
        ReadOnlySpan<byte> mailbox, ReadOnlySpan<byte> placement, ReadOnlySpan<byte> membership,
        byte purpose, VerifyMailboxContinuation verify, out Window window)
    {
        window = default;
        if (token.Length != Length || !token[..4].SequenceEqual("XCT1"u8) || token[4] != 1 ||
            token[5] != (RetrievePurpose | AckPurpose) || purpose is not (RetrievePurpose or AckPurpose) ||
            BinaryPrimitives.ReadUInt16BigEndian(token[6..]) is 0 or > MailboxClientLimits.MaximumPageItems ||
            BinaryPrimitives.ReadUInt64BigEndian(token[8..]) != epoch || cursor == 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(token[16..]) != cursor ||
            BinaryPrimitives.ReadUInt64BigEndian(token[24..]) <= now ||
            BinaryPrimitives.ReadUInt64BigEndian(token[32..]) < cursor ||
            !CryptographicOperations.FixedTimeEquals(token.Slice(40, 32), mailbox) ||
            !CryptographicOperations.FixedTimeEquals(token.Slice(72, 32), placement) ||
            !CryptographicOperations.FixedTimeEquals(token.Slice(104, 32), membership) ||
            !verify(token[..SigningLength], token[SigningLength..])) return false;
        window = new(BinaryPrimitives.ReadUInt64BigEndian(token[32..]),
            BinaryPrimitives.ReadUInt16BigEndian(token[6..]), token.Slice(136, 32).ToArray());
        return true;
    }
}
