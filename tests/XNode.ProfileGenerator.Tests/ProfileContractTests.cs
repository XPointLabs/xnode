using Deep.Protocol.DeepExtension.Membership;

namespace XNode.ProfileGenerator.Tests;

public sealed class ProfileContractTests
{
    [Fact]
    public void Compose_IsByteDeterministic_AndInspectorRoundTrips()
    {
        var first = DormantProfileComposer.Compose(
            TestOnlyProfileFixture.Input(),
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());
        var second = DormantProfileComposer.Compose(
            TestOnlyProfileFixture.Input(),
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());

        Assert.Equal(first.FilePayload.ToArray(), second.FilePayload.ToArray());
        var inspected = DormantProfileInspector.Inspect(
            first.FilePayload.Span,
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());
        Assert.Equal(first.FilePayload.ToArray(), inspected.FilePayload.ToArray());
        Assert.Equal(first.Fingerprint, inspected.Fingerprint);
        Assert.Equal("protocol:1-3", inspected.Compatibility);
        Assert.Equal(4, inspected.ComponentCount);
    }

    [Fact]
    public void InputPermutations_HaveOneCanonicalOutput()
    {
        var canonical = DormantProfileComposer.Compose(
            TestOnlyProfileFixture.Input(bridgeCount: 2),
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());
        var permuted = DormantProfileComposer.Compose(
            TestOnlyProfileFixture.Input(
                reverseGenesisSignatures: true,
                reverseBridges: true,
                bridgeCount: 2),
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());

        Assert.Equal(canonical.FilePayload.ToArray(), permuted.FilePayload.ToArray());
    }

    [Fact]
    public void QrText_DecodesToExactFileBytes_AndFallsBackToFileOnly()
    {
        var compact = DormantProfileComposer.Compose(
            TestOnlyProfileFixture.Input(),
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());
        Assert.NotNull(compact.QrText);
        Assert.True(DormantProfileQr.TryDecode(compact.QrText!, out var decoded));
        Assert.Equal(compact.FilePayload.ToArray(), decoded);

        var large = DormantProfileComposer.Compose(
            TestOnlyProfileFixture.Input(contactLength: 510),
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());
        Assert.Null(large.QrText);
        Assert.InRange(large.FilePayload.Length, 1, ProfileComposerLimits.MaximumFilePayloadBytes);
    }

    [Fact]
    public void SigningRequests_AreExactP04DomainFrames_WithStableIds()
    {
        var input = TestOnlyProfileFixture.Input();
        var genesis = ProfileSigningRequestBuilder.ForGenesis(input.CanonicalGenesis.Span);
        var delegation = MembershipContractCodec.DecodeSignedDelegation(input.CanonicalSignedDelegation.Span);
        var delegationCanonical = MembershipContractCodec.GetDelegationSigningBytes(delegation);
        var delegationRequest = ProfileSigningRequestBuilder.ForDelegation(delegationCanonical);
        var bridge = MembershipContractCodec.DecodeSignedBridge(input.CanonicalSignedBridges[0].Span);
        var bridgeCanonical = MembershipContractCodec.GetBridgeSigningBytes(bridge.Statement);
        var bridgeRequest = ProfileSigningRequestBuilder.ForBridge(bridgeCanonical);

        Assert.Equal(
            MembershipSigningDomains.Frame(MembershipSignatureDomain.Genesis, input.CanonicalGenesis.Span),
            genesis.SigningBytes.ToArray());
        Assert.Equal(
            MembershipSigningDomains.Frame(MembershipSignatureDomain.OfflineDelegation, delegationCanonical),
            delegationRequest.SigningBytes.ToArray());
        Assert.Equal(
            MembershipSigningDomains.Frame(MembershipSignatureDomain.Bridge, bridgeCanonical),
            bridgeRequest.SigningBytes.ToArray());
        Assert.Equal(genesis.RequestId, ProfileSigningRequestBuilder.ForGenesis(input.CanonicalGenesis.Span).RequestId);
        Assert.NotEqual(genesis.RequestId, delegationRequest.RequestId);
        Assert.NotEqual(delegationRequest.RequestId, bridgeRequest.RequestId);
    }
}
