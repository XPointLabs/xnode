using System.Security.Cryptography;
using System.Text;

namespace XNode.Transport.Vless;

internal static class VlessSecretFileLoader
{
    private const int MaximumSecretFileBytes = 128;

    internal static void Load(VlessTransportOptions options, bool requireProtectedFiles = false)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.Enabled)
        {
            return;
        }

        if (requireProtectedFiles && string.IsNullOrWhiteSpace(options.ClientIdFile))
        {
            throw new InvalidOperationException(
                "Production VLESS requires a protected client-id file.");
        }

        if (!string.IsNullOrWhiteSpace(options.ClientIdFile))
        {
            var clientId = ReadSingleLine(options.ClientIdFile, "VLESS client-id");
            if (!Guid.TryParseExact(clientId, "D", out var parsed)
                || !string.Equals(clientId, parsed.ToString("D"), StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The protected VLESS client-id file is not one canonical lowercase UUID.");
            }

            options.ClientId = clientId;
        }

        if (requireProtectedFiles
            && options.TransportMode == VlessTransportMode.Reality
            && string.IsNullOrWhiteSpace(options.Reality.PrivateKeyFile))
        {
            throw new InvalidOperationException(
                "Production REALITY requires a protected private-key file.");
        }

        if (options.TransportMode == VlessTransportMode.Reality
            && !string.IsNullOrWhiteSpace(options.Reality.PrivateKeyFile))
        {
            var privateKey = ReadSingleLine(
                options.Reality.PrivateKeyFile,
                "REALITY private-key");
            if (privateKey.Length != 43 || privateKey.Any(static value =>
                    !char.IsAsciiLetterOrDigit(value) && value is not '_' and not '-'))
            {
                throw new InvalidDataException(
                    "The protected REALITY private-key file is not one canonical Xray key.");
            }

            options.Reality.PrivateKey = privateKey;
        }
    }

    private static string ReadSingleLine(string configuredPath, string label)
    {
        if (!Path.IsPathFullyQualified(configuredPath))
        {
            throw new InvalidOperationException($"The {label} file path must be absolute.");
        }

        var path = Path.GetFullPath(configuredPath);
        byte[]? bytes = null;
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128,
                FileOptions.SequentialScan);
            if (stream.Length is < 1 or > MaximumSecretFileBytes)
            {
                throw new InvalidDataException($"The protected {label} file has an invalid length.");
            }

            bytes = GC.AllocateUninitializedArray<byte>(checked((int)stream.Length));
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1)
            {
                throw new InvalidDataException($"The protected {label} file changed while it was read.");
            }

            var length = bytes.Length;
            if (length > 0 && bytes[length - 1] == (byte)'\n')
            {
                length--;
                if (length > 0 && bytes[length - 1] == (byte)'\r')
                {
                    length--;
                }
            }

            if (length == 0
                || bytes.AsSpan(0, length).IndexOfAny((byte)'\r', (byte)'\n', (byte)'\0') >= 0
                || bytes.AsSpan(length).IndexOfAnyExcept((byte)'\r', (byte)'\n') >= 0)
            {
                throw new InvalidDataException($"The protected {label} file must contain one line.");
            }

            return new UTF8Encoding(false, true).GetString(bytes, 0, length);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException($"The protected {label} file is unavailable.", exception);
        }
        finally
        {
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }
}
