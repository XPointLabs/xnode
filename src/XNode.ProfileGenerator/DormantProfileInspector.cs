using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace XNode.ProfileGenerator;

public static class DormantProfileInspector
{
    public static DormantProfileDocument Inspect(
        ReadOnlySpan<byte> filePayload,
        ProfileVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        if (options is null || verifier is null)
            throw ProfileErrors.InvalidInput();

        try
        {
            var verification = ProfileCarrierVerifier.VerifyExact(
                filePayload,
                options.ToCarrier(),
                verifier);
            return DormantProfileDocumentFactory.Create(
                filePayload,
                verification.Fingerprint,
                verification.MinimumProtocol,
                verification.MaximumProtocol,
                verification.ComponentCount,
                verification.BridgeCount);
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
            throw ProfileErrors.Framing();
        }
    }
}

public static class DormantProfileQr
{
    private const string Prefix = "deep-profile-v1:";

    internal static string? EncodeOrNull(ReadOnlySpan<byte> filePayload)
    {
        var encoded = Convert.ToBase64String(filePayload)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        var result = Prefix + encoded;
        return ProfileComposerLimits.IsQrTextLengthAllowed(result.Length)
            ? result
            : null;
    }

    public static bool TryDecode(string qrText, out byte[] filePayload)
    {
        filePayload = [];
        if (string.IsNullOrEmpty(qrText) ||
            !ProfileComposerLimits.IsQrTextLengthAllowed(qrText.Length) ||
            !qrText.StartsWith(Prefix, StringComparison.Ordinal))
            return false;
        var encoded = qrText[Prefix.Length..];
        if (encoded.Length == 0 ||
            encoded.Any(static value => value > 0x7f || value == '='))
            return false;
        var padded = encoded.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => "\0"
        };
        if (padded.Contains('\0', StringComparison.Ordinal))
            return false;
        try
        {
            var decoded = Convert.FromBase64String(padded);
            if (!ProfileComposerLimits.IsFilePayloadLengthAllowed(decoded.Length) ||
                !string.Equals(EncodeOrNull(decoded), qrText, StringComparison.Ordinal))
                return false;
            filePayload = decoded;
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
