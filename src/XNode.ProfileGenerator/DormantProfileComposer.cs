using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace XNode.ProfileGenerator;

public static class DormantProfileComposer
{
    public const string Status =
        "XNODE-SHARED-CARRIER-GO / BYTE-IDENTITY-GO / " +
        "PRODUCTION-SIGNER-NO-GO / CLIENT-VERIFIER-PENDING / " +
        "SELF-HOSTED-RUNTIME-NO-GO";

    public static DormantProfileDocument Compose(
        ProfileAssemblyInput input,
        ProfileVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        if (input is null || options is null || verifier is null)
            throw ProfileErrors.InvalidInput();

        try
        {
            var composition = ProfileCarrierComposer.ComposeExact(
                input.ToCarrier(),
                options.ToCarrier(),
                verifier);
            return DormantProfileDocumentFactory.Create(
                composition.FilePayload.Span,
                composition.Fingerprint,
                composition.MinimumProtocol,
                composition.MaximumProtocol,
                composition.ComponentCount,
                composition.BridgeCount);
        }
        catch (ProfileCarrierException exception)
        {
            throw ProfileErrors.FromCarrier(exception);
        }
        catch (ProfileContractException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw ProfileErrors.Verification();
        }
    }
}
