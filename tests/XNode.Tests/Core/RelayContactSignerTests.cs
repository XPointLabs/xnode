using XNode.Core;

namespace XNode.Tests.Core;

public sealed class RelayContactSignerTests
{
    private const string Seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    [Fact]
    public void Sign_ProducesVerifiableRelayContact()
    {
        var routerId = RelayContactSigner.DeriveRouterId(Seed);
        var contact = new RelayContact
        {
            RouterId = routerId,
            PublicHost = "node-1.example.org",
            PublicIp = "203.0.113.10",
            PublicPort = 443,
            SignedAt = TestData.Now,
            ExpiresAt = TestData.Now.AddHours(1),
            RouterVersion = "1.2.3",
            Capabilities = ["session-rpc", "vless-ingress"]
        };

        var signed = RelayContactSigner.Sign(contact, Seed);

        Assert.Equal("ed25519", signed.SignatureAlgorithm);
        Assert.Equal(128, signed.Signature.Length);
        Assert.True(RelayContactSigner.Verify(signed));
    }

    [Fact]
    public void Verify_RejectsTamperedRelayContact()
    {
        var routerId = RelayContactSigner.DeriveRouterId(Seed);
        var signed = RelayContactSigner.Sign(new RelayContact
        {
            RouterId = routerId,
            PublicHost = "node-1.example.org",
            PublicPort = 443,
            SignedAt = TestData.Now,
            ExpiresAt = TestData.Now.AddHours(1)
        }, Seed);

        var tampered = signed with { PublicPort = 8443 };

        Assert.False(RelayContactSigner.Verify(tampered));
    }
}
