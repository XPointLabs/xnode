using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode;

public static class MailboxPeerHttpRequestValidator
{
    public static MailboxHttpFailure? Validate(
        HttpRequest request,
        MailboxHttpEndpointContract contract)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(contract);
        if (request.ContentLength is null)
        {
            return MailboxHttpFailure.MissingContentLength;
        }

        if (!string.Equals(
                request.ContentType,
                contract.RequestContentType,
                StringComparison.Ordinal)
            || request.Headers.ContentEncoding.Count != 0)
        {
            return MailboxHttpFailure.UnsupportedContentTypeOrEncoding;
        }

        if (request.ContentLength < contract.MinimumRequestBytes)
        {
            return MailboxHttpFailure.MalformedCanonicalBody;
        }

        return request.ContentLength > contract.MaximumRequestBytes
            ? MailboxHttpFailure.PayloadTooLarge
            : null;
    }
}
