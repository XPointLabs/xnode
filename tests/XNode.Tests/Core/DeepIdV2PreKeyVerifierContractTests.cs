using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace XNode.Tests.Core;

public sealed class DeepIdV2PreKeyVerifierContractTests
{
    [Fact]
    public void PublicVerifierRequiresCurrentRecipientPlacementAndProtectedTime_NotRawServerKeys()
    {
        Func<ParsedXpk1V2, ParsedXpc1V2, VerifiedContactServicePlacement,
            DeepIdV2CurrentContactAuthorization, ParsedDcr1V2,
            OnionTrustedTimeAuthority, CancellationToken,
            ValueTask<VerifiedXpc1V2PreKeyClaimReceipt>> verify =
            DeepIdV2PreKeyClaimReceiptVerifier.VerifyAsync;
        Assert.NotNull(verify);
        Assert.All(typeof(DeepIdV2PreKeyClaimReceiptVerifier).GetMethods()
            .Where(static method => method.Name.StartsWith("Verify", StringComparison.Ordinal)),
            static method => Assert.DoesNotContain(method.GetParameters(), static parameter =>
                parameter.ParameterType == typeof(byte[])
                || parameter.ParameterType == typeof(ReadOnlyMemory<byte>)
                || parameter.ParameterType == typeof(bool)));
        Assert.Empty(typeof(VerifiedXpc1V2PreKeyClaimReceipt).GetConstructors());
    }
}
