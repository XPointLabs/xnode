using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace XNode.Registry;

public sealed class QuorumSigningPolicyValidator
{
    private const int G1EipBytes = 128;
    private const int MaxRpcAttempts = 3;

    private readonly HttpClient _httpClient;

    public QuorumSigningPolicyValidator(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task ValidateAsync(
        RegistryRegistrationOptions options,
        IReadOnlyList<string> rpcUrls,
        string messageType,
        QuorumSignatureRequest request,
        string localBlsPublicKey,
        CancellationToken cancellationToken)
    {
        if (!options.EnforceQuorumSigningPolicy)
        {
            throw new InvalidOperationException("RegistryRegistration:EnforceQuorumSigningPolicy cannot be disabled for quorum signing.");
        }

        if (rpcUrls.Count == 0)
        {
            throw new InvalidOperationException("RegistryRegistration:EthereumRpcUrl is required for quorum signing policy validation.");
        }

        if (string.IsNullOrWhiteSpace(options.ServiceNodeRewardsAddress))
        {
            throw new InvalidOperationException("RegistryRegistration:ServiceNodeRewardsAddress is required for quorum signing policy validation.");
        }

        await RequireActiveServiceNodeAsync(
            rpcUrls,
            options.ServiceNodeRewardsAddress,
            localBlsPublicKey,
            "local signer",
            cancellationToken).ConfigureAwait(false);

        switch (messageType)
        {
            case "reward":
                await ValidateRewardAsync(options, rpcUrls, request, cancellationToken).ConfigureAwait(false);
                break;
            case "exit":
            case "liquidate":
                ValidateTimestampFresh(options, request.Timestamp);
                await RequireActiveServiceNodeAsync(
                    rpcUrls,
                    options.ServiceNodeRewardsAddress,
                    request.BlsPublicKey,
                    "target service node",
                    cancellationToken).ConfigureAwait(false);
                await VerifyExitEligibilityAsync(
                    options,
                    messageType,
                    request.BlsPublicKey,
                    cancellationToken).ConfigureAwait(false);
                break;
            default:
                throw new InvalidOperationException($"Unsupported quorum signing message type '{request.Type}'.");
        }
    }

    private async Task ValidateRewardAsync(
        RegistryRegistrationOptions options,
        IReadOnlyList<string> rpcUrls,
        QuorumSignatureRequest request,
        CancellationToken cancellationToken)
    {
        if (request.Amount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Amount), "Reward amount cannot be negative.");
        }

        var recipient = NormalizeAddress(request.RecipientAddress);
        if (string.IsNullOrWhiteSpace(request.PolicyQuote))
        {
            throw new QuorumSignatureRejectedException(
                "Reward quorum signing rejected: policy quote is required.");
        }

        var expectedRewards = await ReadBackendRewardSignatureAmountAsync(
            options,
            recipient,
            request.PolicyQuote,
            cancellationToken).ConfigureAwait(false);
        if (request.Amount != expectedRewards)
        {
            throw new QuorumSignatureRejectedException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Reward quorum signing rejected: requested cumulative reward balance {request.Amount} does not match backend projection {expectedRewards}."));
        }

        var currentRewards = await ReadRecipientRewardsAsync(
            rpcUrls,
            options.ServiceNodeRewardsAddress,
            recipient,
            cancellationToken).ConfigureAwait(false);
        var requestedRewards = new BigInteger(request.Amount);
        if (requestedRewards <= currentRewards)
        {
            throw new QuorumSignatureRejectedException(
                "Reward quorum signing rejected: requested cumulative reward balance is not above the current on-chain balance.");
        }

        if (options.MaxRewardSignatureIncreaseAtomic > 0)
        {
            var maxIncrease = new BigInteger(options.MaxRewardSignatureIncreaseAtomic);
            var increase = requestedRewards - currentRewards;
            if (increase > maxIncrease)
            {
                throw new QuorumSignatureRejectedException(
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"Reward quorum signing rejected: requested increase {increase} exceeds configured cap {maxIncrease}."));
            }
        }
        else
        {
            throw new InvalidOperationException("RegistryRegistration:MaxRewardSignatureIncreaseAtomic must be positive.");
        }
    }

    private static void ValidateTimestampFresh(RegistryRegistrationOptions options, long timestamp)
    {
        if (timestamp <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timestamp), "Exit/liquidation timestamp must be positive.");
        }

        var skew = Math.Max(1, options.MaxQuorumSignatureTimestampSkewSeconds);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (timestamp < now - skew || timestamp > now + skew)
        {
            throw new QuorumSignatureRejectedException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Exit/liquidation quorum signing rejected: timestamp is outside the configured {skew}s freshness window."));
        }
    }

    private async Task RequireActiveServiceNodeAsync(
        IReadOnlyList<string> rpcUrls,
        string serviceNodeRewardsAddress,
        string blsPublicKey,
        string label,
        CancellationToken cancellationToken)
    {
        var normalized = NormalizeHex(blsPublicKey, G1EipBytes);
        var data = EncodeDynamicBytesCall("serviceNodeIDs(bytes)", HexToBytes(normalized));
        var result = await EthCallAsync(
            rpcUrls,
            serviceNodeRewardsAddress,
            data,
            cancellationToken).ConfigureAwait(false);
        if (DecodeUInt256(result) <= BigInteger.Zero)
        {
            throw new QuorumSignatureRejectedException(
                $"Quorum signing rejected: {label} BLS public key is not active on ServiceNodeRewards.");
        }
    }

    private async Task<long> ReadBackendRewardSignatureAmountAsync(
        RegistryRegistrationOptions options,
        string recipient,
        string policyQuote,
        CancellationToken cancellationToken)
    {
        var root = RequirePolicyBackendUri(options);
        var document = await GetJsonAsync(
            root,
            $"api/staking/rewards/{Uri.EscapeDataString(recipient)}/quotes/{Uri.EscapeDataString(policyQuote)}",
            options.QuorumPolicyBackendTimeoutSeconds,
            cancellationToken).ConfigureAwait(false);
        using (document)
        {
            var rootElement = document.RootElement;
            var quoteId = ReadStringProperty(rootElement, "quoteId", "quote_id");
            if (!string.Equals(quoteId, policyQuote, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Quorum policy backend returned a different reward quote id.");
            }

            var quotedRecipient = ReadStringProperty(rootElement, "address");
            if (!string.Equals(NormalizeAddress(quotedRecipient), recipient, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Quorum policy backend returned a reward quote for a different recipient.");
            }

            var expiresAtUnixSeconds = ReadLongProperty(
                rootElement,
                "expiresAtUnixSeconds",
                "expires_at_unix_seconds");
            if (expiresAtUnixSeconds < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                throw new QuorumSignatureRejectedException("Reward quorum signing rejected: policy quote is expired.");
            }

            return ReadLongProperty(rootElement, "amountAtomic", "amount_atomic");
        }
    }

    private async Task VerifyExitEligibilityAsync(
        RegistryRegistrationOptions options,
        string messageType,
        string blsPublicKey,
        CancellationToken cancellationToken)
    {
        var targetKey = NormalizeHex(blsPublicKey, G1EipBytes);
        var root = RequirePolicyBackendUri(options);
        var document = await GetJsonAsync(
            root,
            "obligations",
            options.QuorumPolicyBackendTimeoutSeconds,
            cancellationToken).ConfigureAwait(false);
        using (document)
        {
            if (!document.RootElement.TryGetProperty("nodes", out var nodes)
                || nodes.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidOperationException("Quorum policy backend obligations response did not contain a nodes array.");
            }

            foreach (var node in nodes.EnumerateArray())
            {
                var nodeKey = ReadStringProperty(node, "bls_public_key", "blsPublicKey");
                if (!string.Equals(NormalizeHex(nodeKey, G1EipBytes), targetKey, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var eligible = string.Equals(messageType, "exit", StringComparison.OrdinalIgnoreCase)
                    ? ReadBoolProperty(node, "exit_signature_eligible", "exitSignatureEligible")
                    : ReadBoolProperty(node, "liquidation_signature_eligible", "liquidationSignatureEligible");
                if (!eligible)
                {
                    throw new QuorumSignatureRejectedException(
                        $"Quorum signing rejected: target service node is not {messageType} eligible according to the policy backend.");
                }

                return;
            }
        }

        throw new QuorumSignatureRejectedException(
            "Quorum signing rejected: target service node was not found in policy backend obligations.");
    }

    private Uri RequirePolicyBackendUri(RegistryRegistrationOptions options)
    {
        if (!Uri.TryCreate(options.QuorumPolicyBackendBaseUrl, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException(
                "RegistryRegistration:QuorumPolicyBackendBaseUrl must be an absolute http(s) URL for quorum signing policy validation.");
        }

        var value = uri.AbsoluteUri.EndsWith("/", StringComparison.Ordinal) ? uri.AbsoluteUri : uri.AbsoluteUri + "/";
        return new Uri(value, UriKind.Absolute);
    }

    private async Task<JsonDocument> GetJsonAsync(
        Uri baseUri,
        string relativePath,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, timeoutSeconds)));
        using var response = await _httpClient.GetAsync(new Uri(baseUri, relativePath), timeoutCts.Token)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Quorum policy backend returned HTTP {(int)response.StatusCode} for {relativePath}.");
        }
        return await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(timeoutCts.Token).ConfigureAwait(false),
            cancellationToken: timeoutCts.Token).ConfigureAwait(false);
    }

    private async Task<BigInteger> ReadRecipientRewardsAsync(
        IReadOnlyList<string> rpcUrls,
        string serviceNodeRewardsAddress,
        string recipient,
        CancellationToken cancellationToken)
    {
        var selector = Epoche.Keccak256.ComputeEthereumFunctionSelector("recipients(address)", true);
        var data = selector + Strip0x(recipient).PadLeft(64, '0');
        var result = await EthCallAsync(
            rpcUrls,
            serviceNodeRewardsAddress,
            data,
            cancellationToken).ConfigureAwait(false);
        var hex = Strip0x(result);
        if (hex.Length < 128)
        {
            throw new InvalidOperationException(
                string.Create(CultureInfo.InvariantCulture, $"recipients(address) returned {hex.Length / 2} bytes; expected 64 bytes."));
        }

        return DecodeUInt256("0x" + hex[..64]);
    }

    private async Task<string> EthCallAsync(
        IReadOnlyList<string> rpcUrls,
        string to,
        string data,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "eth_call",
            @params = new object[]
            {
                new { to = NormalizeAddress(to), data },
                "latest"
            }
        });

        Exception? lastException = null;
        foreach (var rpcUrl in rpcUrls)
        {
            for (var attempt = 1; attempt <= MaxRpcAttempts; attempt++)
            {
                try
                {
                    using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                    using var response = await _httpClient.PostAsync(rpcUrl, content, cancellationToken)
                        .ConfigureAwait(false);
                    response.EnsureSuccessStatusCode();

                    var document = await JsonDocument.ParseAsync(
                        await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    if (document.RootElement.TryGetProperty("error", out var error))
                    {
                        throw new InvalidOperationException($"Ethereum RPC eth_call failed: {error}");
                    }

                    var result = document.RootElement.GetProperty("result").GetString();
                    if (string.IsNullOrWhiteSpace(result))
                    {
                        throw new InvalidOperationException("Ethereum RPC eth_call returned an empty result.");
                    }

                    return result;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    lastException = ex;
                    await Task.Delay(TimeSpan.FromMilliseconds(100 * attempt), cancellationToken)
                        .ConfigureAwait(false);
                }
            }
        }

        throw new InvalidOperationException("Ethereum RPC eth_call failed for all configured endpoints.", lastException);
    }

    private static string EncodeDynamicBytesCall(string signature, byte[] value)
    {
        var selector = Epoche.Keccak256.ComputeEthereumFunctionSelector(signature, true);
        var paddedLength = ((value.Length + 31) / 32) * 32;
        var padded = new byte[paddedLength];
        value.CopyTo(padded, 0);
        return string.Concat(
            selector,
            UInt256ToBytes32Hex(32),
            UInt256ToBytes32Hex(value.Length),
            Convert.ToHexString(padded).ToLowerInvariant());
    }

    private static BigInteger DecodeUInt256(string value)
    {
        var hex = Strip0x(value);
        if (hex.Length < 64)
        {
            throw new InvalidOperationException("Ethereum uint256 result was shorter than 32 bytes.");
        }

        return new BigInteger(HexToBytes(hex[..64]), isUnsigned: true, isBigEndian: true);
    }

    private static long ReadLongProperty(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (!element.TryGetProperty(name, out var value))
            {
                continue;
            }

            return value.ValueKind == JsonValueKind.String
                ? long.Parse(value.GetString() ?? "", CultureInfo.InvariantCulture)
                : value.GetInt64();
        }

        throw new InvalidOperationException($"JSON response did not contain any of: {string.Join(", ", names)}.");
    }

    private static bool ReadBoolProperty(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (element.TryGetProperty(name, out var value))
            {
                return value.GetBoolean();
            }
        }

        throw new InvalidOperationException($"JSON response did not contain any of: {string.Join(", ", names)}.");
    }

    private static string ReadStringProperty(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (element.TryGetProperty(name, out var value))
            {
                return value.GetString() ?? "";
            }
        }

        throw new InvalidOperationException($"JSON response did not contain any of: {string.Join(", ", names)}.");
    }

    private static string UInt256ToBytes32Hex(long value)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "uint256 value cannot be negative.");
        }

        return value.ToString("x", CultureInfo.InvariantCulture).PadLeft(64, '0');
    }

    private static string NormalizeAddress(string address)
    {
        var normalized = Strip0x(address.Trim()).ToLowerInvariant();
        if (normalized.Length != 40 || !normalized.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException("Expected 20-byte Ethereum address hex value.");
        }

        return "0x" + normalized;
    }

    private static string NormalizeHex(string value, int expectedBytes)
    {
        var normalized = Strip0x(value.Trim()).ToLowerInvariant();
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException($"Expected {expectedBytes}-byte hex value.");
        }

        return normalized;
    }

    private static string Strip0x(string value)
    {
        return value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
    }

    private static byte[] HexToBytes(string value)
    {
        return Convert.FromHexString(Strip0x(value));
    }
}
