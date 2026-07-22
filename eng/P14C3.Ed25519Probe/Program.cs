using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;
using Sodium;

const string Arm64AssetSha256 =
    "54f416a70e0d982a63e7f2402ff6f2a8666bf0a430404a4205ed8eee1868b9db";
const string X64AssetSha256 =
    "963416833246938fd6983e4aa96248dbccb2f95b30095c4a94678d6fb903404b";

var rfcPublicKey = Convert.FromHexString(
    "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
var rfcSignature = Convert.FromHexString(
    "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
    "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");
var taggedMessage = Convert.FromHexString(
    "444545502D47454E2D56310000000000" +
    "73796E7468657469632D63616E6F6E6963616C2D73746174656D656E742D7631");
var taggedSignature = Convert.FromHexString(
    "CD1C153F2688C5C846A9063C7C10C951A0707A28E10EBA41FAFC14401192FBBE" +
    "94D4D17811C6BA7B15EAA1D63591EBB8D8B5B2AC77EB3F55D5F14EC720823B0C");

Require(RuntimeInformation.IsOSPlatform(OSPlatform.Linux), "os");
Require(
    RuntimeInformation.ProcessArchitecture is Architecture.Arm64 or Architecture.X64,
    "architecture");

// This direct RFC KAT proves the provider primitive independently of P04
// framing. It also loads the native asset selected by the current process RID.
Require(PublicKeyAuth.VerifyDetached(rfcSignature, [], rfcPublicKey), "rfc8032-kat");

var verifier = new SodiumEd25519MembershipSignatureVerifier();
var signerId = new byte[MembershipLimits.SignerIdLength];
Require(verifier.Verify(
    signerId,
    rfcPublicKey,
    MembershipSignatureDomain.Genesis,
    taggedMessage,
    taggedSignature), "p04-tagged-kat");

var corrupted = taggedSignature.ToArray();
corrupted[0] ^= 0x80;
Require(!verifier.Verify(
    signerId,
    rfcPublicKey,
    MembershipSignatureDomain.Genesis,
    taggedMessage,
    corrupted), "corrupted-signature");

var wrongKey = rfcPublicKey.ToArray();
wrongKey[0] ^= 0x80;
Require(!verifier.Verify(
    signerId,
    wrongKey,
    MembershipSignatureDomain.Genesis,
    taggedMessage,
    taggedSignature), "wrong-key");

var wrongTag = taggedMessage.ToArray();
wrongTag[0] ^= 0x80;
Require(!verifier.Verify(
    signerId,
    rfcPublicKey,
    MembershipSignatureDomain.Genesis,
    wrongTag,
    taggedSignature), "wrong-domain-tag");

var nonCanonicalScalar = taggedSignature.ToArray();
nonCanonicalScalar.AsSpan(32).Fill(0xff);
Require(!verifier.Verify(
    signerId,
    rfcPublicKey,
    MembershipSignatureDomain.Genesis,
    taggedMessage,
    nonCanonicalScalar), "noncanonical-scalar");

var sodiumModule = Process.GetCurrentProcess().Modules
    .Cast<ProcessModule>()
    .SingleOrDefault(static module =>
        Path.GetFileName(module.FileName)
            .Contains("libsodium", StringComparison.OrdinalIgnoreCase));
Require(sodiumModule is not null, "native-module");
var nativeSha256 = Sha256(sodiumModule!.FileName);
var expectedSha256 = RuntimeInformation.ProcessArchitecture switch
{
    Architecture.Arm64 => Arm64AssetSha256,
    Architecture.X64 => X64AssetSha256,
    _ => throw new InvalidOperationException("P14C3_PROBE_FAIL=architecture")
};
Require(
    nativeSha256.Equals(expectedSha256, StringComparison.Ordinal),
    "native-asset-identity");

Console.WriteLine("P14C3_ED25519_PROBE=PASS");
Console.WriteLine("OS=linux");
Console.WriteLine($"ARCH={RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}");
Console.WriteLine($"NATIVE_FILE={Path.GetFileName(sodiumModule.FileName)}");
Console.WriteLine($"NATIVE_SHA256={nativeSha256}");
return 0;

static string Sha256(string path)
{
    using var stream = File.OpenRead(path);
    return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
}

static void Require(bool condition, string category)
{
    if (!condition)
        throw new InvalidOperationException($"P14C3_PROBE_FAIL={category}");
}
