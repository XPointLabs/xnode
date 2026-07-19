using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace XNode.ProfileGenerator.Tests;

public sealed class SharedCarrierAdoptionTests
{
    [Fact]
    public void AcceptedGoldenVectorsRemainExactAndSharedVerifierAcceptsThem()
    {
        var vectors = ReadVectors();
        Assert.Equal(
            "eff452368fa4cb1324c5b3c8ee06e2f10e96b835",
            vectors.SourceCommit);
        foreach (var vector in vectors.Vectors)
        {
            var payload = File.ReadAllBytes(Fixture(vector.File));
            Assert.Equal(vector.Bytes, payload.Length);
            Assert.Equal(vector.Sha256, Sha256(payload));
            var verified = ProfileCarrierVerifier.VerifyExact(
                payload,
                SharedOptions(),
                TestOnlyProfileFixture.SignatureScheme());
            Assert.Equal(vector.ComponentCount, verified.ComponentCount);
        }

        Assert.Equal(
            File.ReadAllBytes(Fixture("accepted-eff4523-default.dpf")),
            ComposeLocal(TestOnlyProfileFixture.Input()).FilePayload.ToArray());
        Assert.Equal(
            File.ReadAllBytes(Fixture("accepted-eff4523-two-bridges.dpf")),
            ComposeLocal(TestOnlyProfileFixture.Input(bridgeCount: 2)).FilePayload.ToArray());
    }

    [Fact]
    public void LocalAndSharedCompositionAreByteIdenticalAcrossInputOrder()
    {
        foreach (var input in new[]
                 {
                     TestOnlyProfileFixture.Input(),
                     TestOnlyProfileFixture.Input(reverseGenesisSignatures: true),
                     TestOnlyProfileFixture.Input(bridgeCount: 2),
                     TestOnlyProfileFixture.Input(
                         reverseGenesisSignatures: true,
                         reverseBridges: true,
                         bridgeCount: 2)
                 })
        {
            var local = ComposeLocal(input);
            var shared = ProfileCarrierComposer.ComposeExact(
                SharedInput(input),
                SharedOptions(),
                TestOnlyProfileFixture.SignatureScheme());
            Assert.Equal(shared.FilePayload.ToArray(), local.FilePayload.ToArray());
            Assert.Equal(shared.Fingerprint, local.Fingerprint);
            Assert.Equal(shared.ComponentCount, local.ComponentCount);
        }
    }

    [Fact]
    public void InvalidSharedOptionsMapToSanitizedXNodeInputErrors()
    {
        var input = TestOnlyProfileFixture.Input();
        var invalidProtocol = Assert.Throws<ProfileContractException>(() =>
            ComposeLocal(input, new ProfileVerificationOptions(
                TestOnlyProfileFixture.VerificationTime,
                30,
                0)));
        Assert.Equal("The dormant profile input is invalid.", invalidProtocol.Message);

        var invalidSkew = Assert.Throws<ProfileContractException>(() =>
            ComposeLocal(input, new ProfileVerificationOptions(
                TestOnlyProfileFixture.VerificationTime,
                MembershipLimits.MaximumClockSkewSeconds + 1,
                TestOnlyProfileFixture.Protocol)));
        Assert.Equal("The dormant profile input is invalid.", invalidSkew.Message);
    }

    [Fact]
    public void DuplicateBridgeMapsToSanitizedXNodeVerificationError()
    {
        var input = TestOnlyProfileFixture.Input();
        var bridge = input.CanonicalSignedBridges[0];
        var duplicate = Assert.Throws<ProfileContractException>(() =>
            ComposeLocal(input.WithBridges([bridge, bridge])));
        Assert.Equal("P04 rejected a dormant profile artifact.", duplicate.Message);
    }

    [Fact]
    public void InvalidFramingMapsToSanitizedXNodeFramingError()
    {
        var malformed = File.ReadAllBytes(Fixture("accepted-eff4523-default.dpf"));
        malformed[4] = 2;
        var framing = Assert.Throws<ProfileContractException>(() =>
            DormantProfileInspector.Inspect(
                malformed,
                TestOnlyProfileFixture.Options(),
                TestOnlyProfileFixture.SignatureScheme()));
        Assert.Equal("The dormant profile framing is invalid.", framing.Message);
    }

    [Fact]
    public void ProductionGraphUsesOnlyTheSharedCarrierCodecAndVerifier()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var source = Path.Combine(root, "src", "XNode.ProfileGenerator");
        Assert.False(File.Exists(Path.Combine(source, "ProfileFraming.cs")));

        var composer = File.ReadAllText(Path.Combine(source, "DormantProfileComposer.cs"));
        Assert.Contains("ProfileCarrierComposer.ComposeExact", composer);
        Assert.DoesNotContain("MembershipContractVerifier.", composer);
        Assert.DoesNotContain("EncodeGenesisApprovals", composer);
        Assert.DoesNotContain("DecodeGenesisApprovals", composer);

        var inspector = File.ReadAllText(Path.Combine(source, "DormantProfileInspector.cs"));
        Assert.Contains("ProfileCarrierVerifier.VerifyExact", inspector);
        Assert.DoesNotContain("ProfileFraming.", inspector);
    }

    private static DormantProfileDocument ComposeLocal(
        ProfileAssemblyInput input,
        ProfileVerificationOptions? options = null) =>
        DormantProfileComposer.Compose(
            input,
            options ?? TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());

    private static ProfileCarrierAssemblyInput SharedInput(ProfileAssemblyInput input) =>
        new(
            input.CanonicalGenesis,
            input.GenesisSignatures.Select(static signature => new MembershipSignature
            {
                SignerId = signature.SignerId.ToArray(),
                Domain = signature.Domain,
                Signature = signature.Signature.ToArray()
            }),
            input.CanonicalSignedDelegation,
            input.CanonicalSignedBridges);

    private static ProfileCarrierVerificationOptions SharedOptions() =>
        new(
            TestOnlyProfileFixture.VerificationTime,
            30,
            TestOnlyProfileFixture.Protocol);

    private static string Fixture(string name) => Path.Combine(
        P04PackagePinTests.RepositoryRoot(),
        "tests",
        "XNode.ProfileGenerator.Tests",
        "Fixtures",
        name);

    private static GoldenVectors ReadVectors()
    {
        var value = JsonSerializer.Deserialize<GoldenVectors>(
            File.ReadAllBytes(Fixture("accepted-eff4523-vectors.json")),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        return Assert.IsType<GoldenVectors>(value);
    }

    private static string Sha256(byte[] value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private sealed record GoldenVectors(string SourceCommit, GoldenVector[] Vectors);
    private sealed record GoldenVector(
        string File,
        int Bytes,
        string Sha256,
        int ComponentCount,
        int? QrCharacters);
}
