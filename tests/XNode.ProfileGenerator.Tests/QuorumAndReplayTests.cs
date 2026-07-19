using Deep.Protocol.DeepExtension.Membership;

namespace XNode.ProfileGenerator.Tests;

public sealed class QuorumAndReplayTests
{
    [Fact]
    public void ExactThreeOfFiveRoots_AndTwoOfThreeOnline_AreRequired()
    {
        var scheme = TestOnlyProfileFixture.SignatureScheme();
        var input = TestOnlyProfileFixture.Input();

        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithGenesisSignatures(input.GenesisSignatures.Take(2)),
                TestOnlyProfileFixture.Options(),
                scheme));
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithGenesisSignatures(
                    input.GenesisSignatures.Concat([input.GenesisSignatures[0]])),
                TestOnlyProfileFixture.Options(),
                scheme));

        var genesis = MembershipContractCodec.DecodeGenesis(input.CanonicalGenesis.Span);
        var fourthGenesis = new ProfilePublicSignature(
            genesis.OfflineRoots[3].SignerId.Span,
            MembershipSignatureDomain.Genesis,
            scheme.Sign(
                genesis.OfflineRoots[3],
                MembershipSignatureDomain.Genesis,
                input.CanonicalGenesis.Span));
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithGenesisSignatures(input.GenesisSignatures.Concat([fourthGenesis])),
                TestOnlyProfileFixture.Options(),
                scheme));

        var delegation = MembershipContractCodec.DecodeSignedDelegation(
            input.CanonicalSignedDelegation.Span);
        var delegationCanonical = MembershipContractCodec.GetDelegationSigningBytes(delegation);
        var excessDelegation = delegation with
        {
            Signatures = TestOnlyProfileFixture.Signatures(
                genesis.OfflineRoots,
                MembershipSignatureDomain.OfflineDelegation,
                delegationCanonical,
                4,
                scheme)
        };
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithDelegation(MembershipContractCodec.EncodeSignedDelegation(excessDelegation)),
                TestOnlyProfileFixture.Options(),
                scheme));

        var bridge = MembershipContractCodec.DecodeSignedBridge(input.CanonicalSignedBridges[0].Span);
        var oneSignature = MembershipContractCodec.EncodeSignedBridge(
            bridge with { Signatures = bridge.Signatures.Take(1).ToArray() });
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithBridges([oneSignature]),
                TestOnlyProfileFixture.Options(),
                scheme));

        var bridgeCanonical = MembershipContractCodec.GetBridgeSigningBytes(bridge.Statement);
        var excessBridge = bridge with
        {
            Signatures = TestOnlyProfileFixture.Signatures(
                delegation.OnlineSigners,
                MembershipSignatureDomain.Bridge,
                bridgeCanonical,
                3,
                scheme)
        };
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithBridges([MembershipContractCodec.EncodeSignedBridge(excessBridge)]),
                TestOnlyProfileFixture.Options(),
                scheme));

        var weakPolicy = genesis.Policy with { OfflineThreshold = 1 };
        Assert.Throws<MembershipContractException>(() =>
            ProfileSigningRequestBuilder.ForGenesis(
                MembershipContractCodec.EncodeGenesis(genesis with { Policy = weakPolicy })));
    }

    [Fact]
    public void DuplicateSigner_WrongDomain_AndSignatureReplayFailClosed()
    {
        var scheme = TestOnlyProfileFixture.SignatureScheme();
        var input = TestOnlyProfileFixture.Input();
        var duplicate = input.GenesisSignatures
            .Select((signature, index) => index == 1 ? input.GenesisSignatures[0] : signature)
            .ToArray();
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithGenesisSignatures(duplicate),
                TestOnlyProfileFixture.Options(),
                scheme));

        var wrongDomain = input.GenesisSignatures
            .Select((signature, index) => index == 0
                ? new ProfilePublicSignature(
                    signature.SignerId.Span,
                    MembershipSignatureDomain.OfflineDelegation,
                    signature.Signature.Span)
                : signature)
            .ToArray();
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithGenesisSignatures(wrongDomain),
                TestOnlyProfileFixture.Options(),
                scheme));

        var signedDelegation = MembershipContractCodec.DecodeSignedDelegation(
            input.CanonicalSignedDelegation.Span);
        var replayed = signedDelegation with
        {
            ValidUntilUnixSeconds = signedDelegation.ValidUntilUnixSeconds + 1
        };
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithDelegation(MembershipContractCodec.EncodeSignedDelegation(replayed)),
                TestOnlyProfileFixture.Options(),
                scheme));

        var crossArtifact = signedDelegation with
        {
            Signatures = input.GenesisSignatures.Select(signature =>
                new MembershipSignature
                {
                    SignerId = signature.SignerId.ToArray(),
                    Domain = MembershipSignatureDomain.OfflineDelegation,
                    Signature = signature.Signature.ToArray()
                }).ToArray()
        };
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithDelegation(MembershipContractCodec.EncodeSignedDelegation(crossArtifact)),
                TestOnlyProfileFixture.Options(),
                scheme));
    }

    [Fact]
    public void NetworkRevisionRollbackFutureAndExpiryAreRejectedByP04()
    {
        var scheme = TestOnlyProfileFixture.SignatureScheme();
        var input = TestOnlyProfileFixture.Input();
        var bridge = MembershipContractCodec.DecodeSignedBridge(input.CanonicalSignedBridges[0].Span);

        var otherNetwork = bridge with
        {
            Statement = bridge.Statement with
            {
                NetworkId = TestOnlyProfileFixture.Range(0x20, MembershipLimits.NetworkIdLength)
            }
        };
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithBridges([MembershipContractCodec.EncodeSignedBridge(otherNetwork)]),
                TestOnlyProfileFixture.Options(),
                scheme));

        var future = bridge with
        {
            Statement = bridge.Statement with { Sequence = bridge.Statement.Sequence + 2 }
        };
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithBridges([MembershipContractCodec.EncodeSignedBridge(future)]),
                TestOnlyProfileFixture.Options(),
                scheme));

        var rollback = bridge with
        {
            Statement = bridge.Statement with { Sequence = bridge.Statement.Sequence - 1 }
        };
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithBridges([MembershipContractCodec.EncodeSignedBridge(rollback)]),
                TestOnlyProfileFixture.Options(),
                scheme));

        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input,
                TestOnlyProfileFixture.Options(time: 3_000),
                scheme));
    }

    [Fact]
    public void AmbiguousSameSequenceBridgeCandidatesFailClosed()
    {
        var scheme = TestOnlyProfileFixture.SignatureScheme();
        var input = TestOnlyProfileFixture.Input(bridgeCount: 2);
        var first = MembershipContractCodec.DecodeSignedBridge(input.CanonicalSignedBridges[0].Span);
        var second = MembershipContractCodec.DecodeSignedBridge(input.CanonicalSignedBridges[1].Span);
        var ambiguous = second with
        {
            Statement = second.Statement with
            {
                Sequence = first.Statement.Sequence,
                PreviousHash = first.Statement.PreviousHash.ToArray()
            }
        };

        Assert.Throws<ProfileContractException>(() =>
            DormantProfileComposer.Compose(
                input.WithBridges(
                [
                    input.CanonicalSignedBridges[0],
                    MembershipContractCodec.EncodeSignedBridge(ambiguous)
                ]),
                TestOnlyProfileFixture.Options(),
                scheme));
    }
}
