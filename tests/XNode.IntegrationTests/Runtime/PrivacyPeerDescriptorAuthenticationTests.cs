using System.Security.Cryptography;
using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed class PrivacyPeerDescriptorAuthenticationTests
{
    [Fact]
    public async Task DistinctNodeIdAndDescriptorKeyAuthenticateWithoutIdentityKeyAlias()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true);
        var sender = RouterId.FromBytes(signed.NodeIds[0].Span);
        var recipient = RouterId.FromBytes(signed.NodeIds[1].Span);
        Assert.False(sender.ToBytes().AsSpan().SequenceEqual(signed.Node(sender.ToBytes()).Ed25519PublicKey.Span));
        var frame = RandomNumberGenerator.GetBytes(176); var now = DateTimeOffset.UtcNow;
        var authentication = PrivacyPeerAuthenticator.Sign(signed.NetworkContext, sender, recipient,
            Convert.ToHexString(signed.Node(sender.ToBytes()).Seed).ToLowerInvariant(), frame, now);
        Assert.True(PrivacyPeerAuthenticator.Verify(signed.NetworkContext, authentication, recipient,
            frame, now, out var actualSender, out var nonce));
        Assert.Equal(sender, actualSender); Assert.Equal(16, nonce.Length);
        Assert.Throws<InvalidOperationException>(() => PrivacyPeerAuthenticator.Sign(signed.NetworkContext,
            sender, recipient, Convert.ToHexString(signed.Node(recipient.ToBytes()).Seed).ToLowerInvariant(), frame, now));
    }

    [Theory]
    [InlineData("body")]
    [InlineData("sender-key-alias")]
    [InlineData("recipient")]
    [InlineData("signature")]
    [InlineData("nonce")]
    [InlineData("timestamp")]
    [InlineData("expired-network")]
    public async Task DescriptorAuthenticationRejectsForeignOrStaleBinding(string defect)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true);
        var sender = RouterId.FromBytes(signed.NodeIds[0].Span);
        var recipient = RouterId.FromBytes(signed.NodeIds[1].Span);
        // Genuine same-key signed proof near the unchanged1500 hard upper:
        // uncertainty gives1499, leaving one second of actual network lease.
        var network = defect == "expired-network"
            ? await signed.VerifyNetworkAtAsync(100, 1_494) : signed.NetworkContext;
        var frame = RandomNumberGenerator.GetBytes(176); var now = DateTimeOffset.UtcNow;
        var authentication = PrivacyPeerAuthenticator.Sign(network, sender, recipient,
            Convert.ToHexString(signed.Node(sender.ToBytes()).Seed).ToLowerInvariant(), frame, now);
        switch (defect)
        {
            case "body": frame[0] ^= 1; break;
            case "sender-key-alias": authentication = authentication with
                { SenderRouterId = RouterId.FromBytes(signed.Node(sender.ToBytes()).Ed25519PublicKey.Span).Value }; break;
            case "recipient": recipient = RouterId.FromBytes(signed.NodeIds[2].Span); break;
            case "signature": authentication = authentication with { Signature = new string('0', 128) }; break;
            case "nonce": authentication = authentication with { Nonce = "invalid" }; break;
            case "timestamp": now += PrivacyPeerAuthenticator.MaximumClockSkew + TimeSpan.FromMilliseconds(1); break;
            // The verified network owns a real elapsed-time lease. Changing the
            // fixture's sample cannot invalidate an already minted capability.
            case "expired-network": await Task.Delay(TimeSpan.FromSeconds(2)); break;
            default: throw new ArgumentOutOfRangeException(nameof(defect));
        }
        Assert.False(PrivacyPeerAuthenticator.Verify(network, authentication, recipient,
            frame, now, out _, out _));
    }
}
