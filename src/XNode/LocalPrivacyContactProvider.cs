using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Rebex.Security.Cryptography;
using XNode.Core;
using XNode.Registry;

namespace XNode;

public sealed class LocalPrivacyContactProvider : ILocalPrivacyContactProvider
{
    private static ReadOnlySpan<byte> Magic => "DPC1"u8;
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
    private readonly RouterNodeOptions _node;
    private readonly PrivacyRoutingConfiguration _privacy;
    private readonly IClock _clock;

    public LocalPrivacyContactProvider(
        RouterNodeOptions node,
        PrivacyRoutingConfiguration privacy,
        IClock clock)
    {
        _node = node;
        _privacy = privacy;
        _clock = clock;
    }

    public NativePrivacyContact Create()
    {
        if (!_privacy.Enabled)
        {
            throw new InvalidOperationException("Privacy routing is disabled.");
        }

        var signedAt = _clock.UtcNow;
        var expiresAt = signedAt.Add(Lifetime);
        var unsigned = new NativePrivacyContact(
            _node.GetRouterId().Value,
            Convert.ToHexString(_privacy.PublicKey).ToLowerInvariant(),
            _privacy.PublicPeerEndpoint.ToString(),
            ["privacy-routing-v1"],
            signedAt.ToUnixTimeSeconds(),
            expiresAt.ToUnixTimeSeconds(),
            "");
        var seed = PrivacyRoutingOptions.DecodeHex32(
            _node.GetEd25519PrivateKey(),
            "Node Ed25519 private seed");
        try
        {
            var signer = new Ed25519();
            signer.FromSeed(seed);
            if (RouterId.FromBytes(signer.GetPublicKey()) != _node.GetRouterId())
            {
                throw new InvalidOperationException(
                    "Native privacy contact signer does not match router identity.");
            }

            return unsigned with
            {
                Signature = Convert.ToHexString(
                    signer.SignMessage(BuildTranscript(unsigned)))
                    .ToLowerInvariant()
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    internal static byte[] BuildTranscript(NativePrivacyContact contact)
    {
        var endpoint = Encoding.UTF8.GetBytes(contact.PeerEndpoint);
        var capability = Encoding.ASCII.GetBytes("privacy-routing-v1");
        var transcript = new byte[
            4 + 32 + 32 + 8 + 8 + 2 + endpoint.Length + 1 + capability.Length];
        Magic.CopyTo(transcript);
        RouterId.FromHex(contact.RouterId).ToBytes().CopyTo(transcript, 4);
        Convert.FromHexString(contact.X25519PublicKey).CopyTo(transcript, 36);
        BinaryPrimitives.WriteInt64BigEndian(
            transcript.AsSpan(68, 8), contact.SignedAtUnixSeconds);
        BinaryPrimitives.WriteInt64BigEndian(
            transcript.AsSpan(76, 8), contact.ExpiresAtUnixSeconds);
        BinaryPrimitives.WriteUInt16BigEndian(
            transcript.AsSpan(84, 2), checked((ushort)endpoint.Length));
        endpoint.CopyTo(transcript, 86);
        transcript[86 + endpoint.Length] = checked((byte)capability.Length);
        capability.CopyTo(transcript, 87 + endpoint.Length);
        return transcript;
    }
}
