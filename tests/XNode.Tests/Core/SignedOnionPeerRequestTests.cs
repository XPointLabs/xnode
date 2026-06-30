using System.Security.Cryptography;
using Sodium;
using XNode.Core;
using XNode.Core.Onion;

namespace XNode.Tests.Core;

public sealed class SignedOnionPeerRequestTests
{
    [Fact]
    public void SignAndVerify_AcceptsValidRequest()
    {
        var (routerId, privateSeed) = CreateIdentity();
        var now = DateTimeOffset.UtcNow;
        var request = SignedOnionPeerRequestAuthenticator.Sign(
            routerId,
            privateSeed,
            Onion(),
            now,
            "00112233445566778899aabbccddeeff");

        Assert.True(SignedOnionPeerRequestAuthenticator.Verify(request, now));
    }

    [Fact]
    public void Verify_RejectsTamperedCiphertext()
    {
        var (routerId, privateSeed) = CreateIdentity();
        var now = DateTimeOffset.UtcNow;
        var request = SignedOnionPeerRequestAuthenticator.Sign(routerId, privateSeed, Onion(), now);
        var tampered = request with
        {
            Request = new OnionRequest(request.Request.Envelope with { Ciphertext = "tampered" })
        };

        Assert.False(SignedOnionPeerRequestAuthenticator.Verify(tampered, now));
    }

    [Fact]
    public void Verify_RejectsExpiredTimestamp()
    {
        var (routerId, privateSeed) = CreateIdentity();
        var signedAt = DateTimeOffset.UtcNow.Subtract(TimeSpan.FromMinutes(3));
        var request = SignedOnionPeerRequestAuthenticator.Sign(routerId, privateSeed, Onion(), signedAt);

        Assert.False(SignedOnionPeerRequestAuthenticator.Verify(request, DateTimeOffset.UtcNow));
    }

    private static OnionRequest Onion() => new(new OnionEnvelope(
        OnionCrypto.EnvelopeVersion,
        Convert.ToBase64String(new byte[32]),
        Convert.ToBase64String(new byte[24]),
        Convert.ToBase64String(new byte[64])));

    private static (RouterId RouterId, string PrivateSeed) CreateIdentity()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var keyPair = PublicKeyAuth.GenerateKeyPair(seed);
        return (RouterId.FromBytes(keyPair.PublicKey), Convert.ToHexString(seed).ToLowerInvariant());
    }
}
