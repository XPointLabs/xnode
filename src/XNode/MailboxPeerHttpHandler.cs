using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using XNode.Core.Mailbox;

namespace XNode;

public static class MailboxPeerHttpHandler
{
    internal static readonly HttpRequestOptionsKey<string> ExpectedPeerPathOption =
        new("XNode.MailboxPeer.ExpectedPath");

    public static SocketsHttpHandler Create(
        ReplicatedMailboxOptions mailboxOptions,
        ReadOnlyMemory<byte> currentSpkiSha256 = default,
        ReadOnlyMemory<byte> nextSpkiSha256 = default) => Create(
            mailboxOptions,
            currentSpkiSha256,
            nextSpkiSha256,
            DevelopmentUatPrivatePeerAddressPolicy.Disabled);

    internal static SocketsHttpHandler Create(
        ReplicatedMailboxOptions mailboxOptions,
        ReadOnlyMemory<byte> currentSpkiSha256,
        ReadOnlyMemory<byte> nextSpkiSha256,
        DevelopmentUatPrivatePeerAddressPolicy privatePeerAddressPolicy)
    {
        ArgumentNullException.ThrowIfNull(mailboxOptions);
        ArgumentNullException.ThrowIfNull(privatePeerAddressPolicy);
        var hasPins = !currentSpkiSha256.IsEmpty || !nextSpkiSha256.IsEmpty;
        var current = currentSpkiSha256.ToArray();
        var next = nextSpkiSha256.ToArray();
        if (hasPins && (current.Length != 32
            || next.Length != 32
            || CryptographicOperations.FixedTimeEquals(current, next)))
        {
            throw new ArgumentException("Mailbox peer SPKI pins are invalid.");
        }

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = (context, cancellationToken) => ConnectAsync(
                context.DnsEndPoint,
                context.InitialRequestMessage,
                mailboxOptions.AllowInsecureHttpPeerTransport || hasPins,
                hasPins ? privatePeerAddressPolicy : DevelopmentUatPrivatePeerAddressPolicy.Disabled,
                cancellationToken)
        };
        if (hasPins)
        {
            handler.SslOptions.RemoteCertificateValidationCallback =
                (_, certificate, _, errors) =>
                {
                    if (errors != SslPolicyErrors.None
                        || certificate is not X509Certificate2 certificate2)
                    {
                        return false;
                    }

                    return MatchesPinnedSpki(certificate2, current, next);
                };
        }

        return handler;
    }

    internal static bool MatchesPinnedSpki(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> currentSpkiSha256,
        ReadOnlySpan<byte> nextSpkiSha256)
    {
        if (currentSpkiSha256.Length != 32 || nextSpkiSha256.Length != 32)
        {
            return false;
        }

        var observed = SHA256.HashData(
            certificate.PublicKey.ExportSubjectPublicKeyInfo());
        return CryptographicOperations.FixedTimeEquals(observed, currentSpkiSha256)
            || CryptographicOperations.FixedTimeEquals(observed, nextSpkiSha256);
    }

    private static async ValueTask<Stream> ConnectAsync(
        DnsEndPoint endpoint,
        HttpRequestMessage request,
        bool allowPinnedPrivate,
        DevelopmentUatPrivatePeerAddressPolicy privatePeerAddressPolicy,
        CancellationToken cancellationToken)
    {
        if (request.RequestUri is null
            || !request.Options.TryGetValue(ExpectedPeerPathOption, out var expectedPath)
            || !string.Equals(
                request.RequestUri.AbsolutePath,
                expectedPath,
                StringComparison.Ordinal)
            || !string.IsNullOrEmpty(request.RequestUri.Query)
            || !string.IsNullOrEmpty(request.RequestUri.UserInfo)
            || !string.IsNullOrEmpty(request.RequestUri.Fragment))
        {
            throw new HttpRequestException(
                "Mailbox peer request is missing an exact route binding.");
        }

        var addresses = await Dns.GetHostAddressesAsync(endpoint.Host, cancellationToken)
            .ConfigureAwait(false);
        var literalHost = IPAddress.TryParse(request.RequestUri.Host, out var literal);
        var permitted = addresses.Where(address => IsPermittedResolvedAddress(
                address,
                allowPinnedPrivate,
                literalHost ? literal : null,
                privatePeerAddressPolicy))
            .ToArray();
        if (permitted.Length == 0)
        {
            throw new HttpRequestException("Mailbox peer resolved only to blocked addresses.");
        }

        Exception? last = null;
        foreach (var address in permitted)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(
                    new IPEndPoint(address, endpoint.Port), cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception exception) when (
                exception is SocketException or OperationCanceledException)
            {
                socket.Dispose();
                last = exception;
            }
        }

        throw new HttpRequestException("Unable to connect to mailbox peer.", last);
    }

    internal static bool IsPermittedResolvedAddress(
        IPAddress address,
        bool allowPinnedPrivate,
        IPAddress? literalHost,
        DevelopmentUatPrivatePeerAddressPolicy privatePeerAddressPolicy)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(privatePeerAddressPolicy);
        return PeerNetworkAddressGuard.IsPubliclyRoutable(address)
            || allowPinnedPrivate
                && PeerNetworkAddressGuard.IsPrivate(address)
                && (literalHost?.Equals(address) == true
                    || privatePeerAddressPolicy.Allows(address));
    }

}
