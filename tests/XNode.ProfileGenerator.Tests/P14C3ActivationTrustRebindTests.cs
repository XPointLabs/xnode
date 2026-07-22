using System.Reflection;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;
using Sodium;

namespace XNode.ProfileGenerator.Tests;

public sealed class P14C3ActivationTrustRebindTests
{
    private const string VerifierTypeName =
        "Deep.Protocol.DeepExtension.SelfHostedProfiles.SodiumEd25519MembershipSignatureVerifier";
    private const string TransitionTypeName =
        "Deep.Protocol.DeepExtension.SelfHostedProfiles.ProfileCarrierTransitionVerifier";

    // RFC 8032 section 7.1 test 1 public key. The second signature is a
    // separately precomputed signature over P04 fixed-tag || canonical bytes.
    private static readonly byte[] PublicKey = Convert.FromHexString(
        "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
    private static readonly byte[] RfcSignature = Convert.FromHexString(
        "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
        "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");
    private static readonly byte[] TaggedMessage = Convert.FromHexString(
        "444545502D47454E2D56310000000000" +
        "73796E7468657469632D63616E6F6E6963616C2D73746174656D656E742D7631");
    private static readonly byte[] TaggedSignature = Convert.FromHexString(
        "CD1C153F2688C5C846A9063C7C10C951A0707A28E10EBA41FAFC14401192FBBE" +
        "94D4D17811C6BA7B15EAA1D63591EBB8D8B5B2AC77EB3F55D5F14EC720823B0C");

    [Fact]
    public void AcceptedCarrierExportsDormantVerifyOnlyTransitionSurface()
    {
        var assembly = typeof(ProfileCarrierComposer).Assembly;
        var verifierType = assembly.GetType(VerifierTypeName, throwOnError: false);
        var transitionType = assembly.GetType(TransitionTypeName, throwOnError: false);

        Assert.NotNull(verifierType);
        Assert.NotNull(transitionType);
        Assert.Contains(typeof(IMembershipSignatureVerifier), verifierType!.GetInterfaces());
        Assert.NotNull(transitionType!.GetMethod(
            "VerifyExact",
            BindingFlags.Public | BindingFlags.Static));

        var publicSurface = string.Join(
            "\n",
            assembly.GetExportedTypes().SelectMany(static type =>
                type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                    .Select(member => $"{type.FullName}.{member}")));
        foreach (var forbidden in new[]
                 {
                     "SignDetached", "GenerateKeyPair", "PrivateKey", "SecretKey",
                     "Seed", "KeyGeneration", "DependencyInjection", "HttpClient"
                 })
        {
            Assert.DoesNotContain(forbidden, publicSurface, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void P04TaggedEd25519KatIsAcceptedAndMutationsFailClosed()
    {
        Assert.True(PublicKeyAuth.VerifyDetached(RfcSignature, [], PublicKey));
        var corruptedRfc = RfcSignature.ToArray();
        corruptedRfc[0] ^= 0x80;
        Assert.False(PublicKeyAuth.VerifyDetached(corruptedRfc, [], PublicKey));

        var verifier = CreateVerifier();
        var signerId = new byte[MembershipLimits.SignerIdLength];

        Assert.True(verifier.Verify(
            signerId,
            PublicKey,
            MembershipSignatureDomain.Genesis,
            TaggedMessage,
            TaggedSignature));

        var corrupted = TaggedSignature.ToArray();
        corrupted[0] ^= 0x80;
        Assert.False(verifier.Verify(
            signerId, PublicKey, MembershipSignatureDomain.Genesis, TaggedMessage, corrupted));

        var wrongKey = PublicKey.ToArray();
        wrongKey[0] ^= 0x80;
        Assert.False(verifier.Verify(
            signerId, wrongKey, MembershipSignatureDomain.Genesis, TaggedMessage, TaggedSignature));

        var wrongTag = TaggedMessage.ToArray();
        wrongTag[0] ^= 0x80;
        Assert.False(verifier.Verify(
            signerId, PublicKey, MembershipSignatureDomain.Genesis, wrongTag, TaggedSignature));

        var nonCanonicalScalar = TaggedSignature.ToArray();
        nonCanonicalScalar.AsSpan(32).Fill(0xff);
        Assert.False(verifier.Verify(
            signerId,
            PublicKey,
            MembershipSignatureDomain.Genesis,
            TaggedMessage,
            nonCanonicalScalar));

        Assert.False(verifier.Verify(
            signerId,
            PublicKey,
            MembershipSignatureDomain.Bridge,
            TaggedMessage,
            TaggedSignature));
    }

    [Fact]
    public void CurrentDeterministicFixtureSignatureIsRejectedByEd25519Verifier()
    {
        var fixture = TestOnlyProfileFixture.Input();
        var genesis = MembershipContractCodec.DecodeGenesis(fixture.CanonicalGenesis.Span);
        var signature = fixture.GenesisSignatures[0];

        Assert.False(CreateVerifier().Verify(
            signature.SignerId.Span,
            genesis.OfflineRoots[0].PublicKey.Span,
            MembershipSignatureDomain.Genesis,
            MembershipSigningDomains.Frame(
                MembershipSignatureDomain.Genesis,
                fixture.CanonicalGenesis.Span),
            signature.Signature.Span));
    }

    [Fact]
    public void ActualTransitionVerifierAcceptsReplayAndForwardSameGenesis()
    {
        var previous = ComposeCarrier(TestOnlyProfileFixture.Input());
        var candidate = ComposeCarrier(TestOnlyProfileFixture.Input(bridgeCount: 2));

        Assert.Equal(
            ProfileCarrierTransitionDecision.Idempotent,
            VerifyTransition(previous, previous));
        Assert.Equal(
            ProfileCarrierTransitionDecision.ForwardSameGenesis,
            VerifyTransition(previous, candidate));
    }

    [Fact]
    public void ActualTransitionVerifierRejectsMalformedLengthsAndBoundaries()
    {
        var valid = ComposeCarrier(TestOnlyProfileFixture.Input());
        var nonMinimalBodyLength = valid.ToList();
        var finalBodyLengthByte = 6;
        while ((nonMinimalBodyLength[finalBodyLengthByte] & 0x80) != 0)
            finalBodyLengthByte++;
        nonMinimalBodyLength[finalBodyLengthByte] |= 0x80;
        nonMinimalBodyLength.Insert(finalBodyLengthByte + 1, 0);

        var malformed = new[]
        {
            Array.Empty<byte>(),
            valid.AsSpan(0, valid.Length - 1).ToArray(),
            valid.Append((byte)0).ToArray(),
            nonMinimalBodyLength.ToArray(),
            new byte[ProfileCarrierLimits.MaximumFilePayloadBytes + 1]
        };
        foreach (var candidate in malformed)
        {
            Assert.Equal(
                ProfileCarrierTransitionDecision.TrustRejected,
                VerifyTransition(valid, candidate));
            Assert.Equal(
                ProfileCarrierTransitionDecision.TrustRejected,
                VerifyTransition(candidate, valid));
        }
    }

    [Fact]
    public void ActualTransitionVerifierRejectsInvalidTrustPolicyInputs()
    {
        var payload = ComposeCarrier(TestOnlyProfileFixture.Input());
        var validOptions = CarrierOptions();
        var policyNegatives = new[]
        {
            new ProfileCarrierVerificationOptions(969, 30, TestOnlyProfileFixture.Protocol),
            new ProfileCarrierVerificationOptions(2_031, 30, TestOnlyProfileFixture.Protocol),
            new ProfileCarrierVerificationOptions(
                TestOnlyProfileFixture.VerificationTime,
                30,
                4)
        };

        foreach (var invalidOptions in policyNegatives)
        {
            Assert.Equal(
                ProfileCarrierTransitionDecision.TrustRejected,
                ProfileCarrierTransitionVerifier.VerifyExact(
                    payload,
                    validOptions,
                    payload,
                    invalidOptions,
                    TestOnlyProfileFixture.SignatureScheme()));
        }
        Assert.Equal(
            ProfileCarrierTransitionDecision.TrustRejected,
            ProfileCarrierTransitionVerifier.VerifyExact(
                payload,
                null!,
                payload,
                validOptions,
                TestOnlyProfileFixture.SignatureScheme()));
        Assert.Equal(
            ProfileCarrierTransitionDecision.TrustRejected,
            ProfileCarrierTransitionVerifier.VerifyExact(
                payload,
                validOptions,
                payload,
                validOptions,
                null!));
    }

    [Fact]
    public void RuntimeProjectsNeitherReferenceNorConstructActivationTrustSurface()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var runtimeProjects = Directory.GetFiles(
            Path.Combine(root, "src"),
            "*.csproj",
            SearchOption.AllDirectories)
            .Where(path => !path.Contains(
                $"{Path.DirectorySeparatorChar}XNode.ProfileGenerator{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal));

        Assert.All(runtimeProjects, path =>
        {
            var project = File.ReadAllText(path);
            Assert.DoesNotContain("Deep.Protocol.ProfileCarrier", project, StringComparison.Ordinal);
            Assert.DoesNotContain("XNode.ProfileGenerator", project, StringComparison.Ordinal);
        });

        var runtimeSources = Directory.GetFiles(
            Path.Combine(root, "src"),
            "*.cs",
            SearchOption.AllDirectories)
            .Where(path => !path.Contains(
                $"{Path.DirectorySeparatorChar}XNode.ProfileGenerator{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal));
        Assert.All(runtimeSources, path =>
        {
            var source = File.ReadAllText(path);
            Assert.DoesNotContain("SodiumEd25519MembershipSignatureVerifier", source,
                StringComparison.Ordinal);
            Assert.DoesNotContain("ProfileCarrierTransitionVerifier", source,
                StringComparison.Ordinal);
        });
    }

    private static IMembershipSignatureVerifier CreateVerifier()
    {
        var type = typeof(ProfileCarrierComposer).Assembly.GetType(
            VerifierTypeName,
            throwOnError: false);
        Assert.NotNull(type);
        return Assert.IsAssignableFrom<IMembershipSignatureVerifier>(
            Activator.CreateInstance(type!)!);
    }

    private static byte[] ComposeCarrier(ProfileAssemblyInput input) =>
        DormantProfileComposer.Compose(
            input,
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme()).FilePayload.ToArray();

    private static ProfileCarrierVerificationOptions CarrierOptions() =>
        new(
            TestOnlyProfileFixture.VerificationTime,
            30,
            TestOnlyProfileFixture.Protocol);

    private static ProfileCarrierTransitionDecision VerifyTransition(
        byte[] previous,
        byte[] candidate) =>
        ProfileCarrierTransitionVerifier.VerifyExact(
            previous,
            CarrierOptions(),
            candidate,
            CarrierOptions(),
            TestOnlyProfileFixture.SignatureScheme());
}
