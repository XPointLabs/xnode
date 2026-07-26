using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Rebex.Security.Cryptography;

namespace XNode.Core.Mailbox.Client;

public sealed class MailboxClientReceiptCrypto : IMailboxReceiptCrypto
{
    private readonly RouterId _localRouterId;
    private readonly byte[] _privateKeySeed;

    public MailboxClientReceiptCrypto(RouterId localRouterId, string privateKeySeedHex)
    {
        _localRouterId = localRouterId;
        _privateKeySeed = DecodeFixedHex(privateKeySeedHex, RouterId.ByteLength);
        var signer = new Ed25519();
        signer.FromSeed(_privateKeySeed);
        if (RouterId.FromBytes(signer.GetPublicKey()) != localRouterId)
        {
            throw new InvalidOperationException("Mailbox client receipt signer does not match router id.");
        }
    }

    public byte[] Digest(ReadOnlySpan<byte> statement) => SHA256.HashData(statement);

    public bool VerifyReplica(
        ReadOnlySpan<byte> replicaId,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        Verify(replicaId, signingBytes, signature);

    public bool VerifyCoordinator(
        ReadOnlySpan<byte> coordinatorId,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        Verify(coordinatorId, signingBytes, signature);

    public byte[] SignLocal(ReadOnlySpan<byte> statement)
    {
        var signer = new Ed25519();
        signer.FromSeed(_privateKeySeed);
        return signer.SignMessage(statement.ToArray());
    }

    public byte[] LocalRouterId => _localRouterId.ToBytes();

    private static bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> statement,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != RouterId.ByteLength || signature.Length != 64)
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(publicKey.ToArray());
            return verifier.VerifyMessage(statement.ToArray(), signature.ToArray());
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static byte[] DecodeFixedHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.", nameof(value));
        }

        return Convert.FromHexString(normalized);
    }
}
