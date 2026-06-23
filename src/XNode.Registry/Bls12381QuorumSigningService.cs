using System.Numerics;
using System.Text;
using System.Text.Json;
using Neo.Cryptography.BLS12_381;

namespace XNode.Registry;

public sealed class Bls12381QuorumSigningService
{
    private const int G1EipBytes = 128;
    private const int G2EipBytes = 256;
    private const int MaxRpcAttempts = 3;
    private const string MapFp2ToG2Precompile = "0x0000000000000000000000000000000000000011";

    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _tagGate = new(1, 1);
    private ServiceNodeContractTags? _tags;

    public Bls12381QuorumSigningService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<QuorumSignatureResponse> SignAsync(
        RegistryRegistrationOptions options,
        string nodeId,
        QuorumSignatureRequest request,
        CancellationToken cancellationToken)
    {
        var privateKey = options.GetBlsPrivateKey();

        var rpcUrls = options.GetEthereumRpcUrls();
        if (rpcUrls.Count == 0)
        {
            throw new InvalidOperationException("RegistryRegistration:EthereumRpcUrl is required for quorum signing.");
        }

        if (string.IsNullOrWhiteSpace(options.ServiceNodeRewardsAddress))
        {
            throw new InvalidOperationException("RegistryRegistration:ServiceNodeRewardsAddress is required for quorum signing.");
        }

        var scalar = ScalarFromBigEndianHex(privateKey);
        var publicKey = ToAffine(G1Affine.Generator * scalar);
        var eipPublicKey = NeoG1ToEip(publicKey.ToUncompressed());
        var tags = await GetTagsAsync(options, rpcUrls, cancellationToken).ConfigureAwait(false);
        var messageType = NormalizeMessageType(request.Type);
        var encodedMessage = BuildEncodedMessage(messageType, request, tags);
        var digest = Epoche.Keccak256.ComputeHash(Concat(tags.HashToG2Tag, encodedMessage));
        var mapInput = Concat(new byte[32], digest, new byte[32], new byte[32]);
        var mappedEip = await EthCallAsync(
            rpcUrls,
            MapFp2ToG2Precompile,
            "0x" + Hex(mapInput),
            cancellationToken).ConfigureAwait(false);
        var hashPoint = G2Affine.FromUncompressed(EipG2ToNeo(HexToBytes(mappedEip)));
        var signature = ToAffine(hashPoint * scalar);

        return new QuorumSignatureResponse
        {
            Type = messageType,
            NodeId = NormalizeHex(nodeId, 32),
            BlsPublicKey = Hex(eipPublicKey),
            Amount = request.Amount,
            Timestamp = request.Timestamp,
            MessageToSign = Hex(encodedMessage),
            Signature = Hex(NeoG2ToEip(signature.ToUncompressed()))
        };
    }

    private static byte[] BuildEncodedMessage(
        string messageType,
        QuorumSignatureRequest request,
        ServiceNodeContractTags tags)
    {
        return messageType switch
        {
            "reward" => BuildRewardMessage(request, tags),
            "exit" => BuildExitMessage(request, tags.ExitTag),
            "liquidate" => BuildExitMessage(request, tags.LiquidateTag),
            _ => throw new InvalidOperationException($"Unsupported quorum signing message type '{request.Type}'.")
        };
    }

    private static byte[] BuildRewardMessage(QuorumSignatureRequest request, ServiceNodeContractTags tags)
    {
        if (request.Amount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Amount), "Reward amount cannot be negative.");
        }

        var normalizedAddress = NormalizeAddress(request.RecipientAddress);
        return Concat(
            tags.RewardTag,
            HexToBytes(Strip0x(normalizedAddress)),
            UInt256ToBytes32(request.Amount));
    }

    private static byte[] BuildExitMessage(QuorumSignatureRequest request, byte[] tag)
    {
        if (request.Timestamp <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Timestamp), "Exit/liquidation timestamp must be positive.");
        }

        var blsPublicKey = NormalizeHex(request.BlsPublicKey, G1EipBytes);
        return Concat(
            tag,
            HexToBytes(blsPublicKey),
            UInt256ToBytes32(request.Timestamp));
    }

    private async Task<ServiceNodeContractTags> GetTagsAsync(
        RegistryRegistrationOptions options,
        IReadOnlyList<string> rpcUrls,
        CancellationToken cancellationToken)
    {
        if (_tags is { } cached)
        {
            return cached;
        }

        await _tagGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_tags is { } cachedInside)
            {
                return cachedInside;
            }

            if (ServiceNodeContractTagBuilder.TryBuild(options) is { } configuredTags)
            {
                _tags = configuredTags;
                return configuredTags;
            }

            var rewardTag = await EthCallAsync(
                rpcUrls,
                options.ServiceNodeRewardsAddress,
                Epoche.Keccak256.ComputeEthereumFunctionSelector("rewardTag()", true),
                cancellationToken).ConfigureAwait(false);
            var exitTag = await EthCallAsync(
                rpcUrls,
                options.ServiceNodeRewardsAddress,
                Epoche.Keccak256.ComputeEthereumFunctionSelector("exitTag()", true),
                cancellationToken).ConfigureAwait(false);
            var liquidateTag = await EthCallAsync(
                rpcUrls,
                options.ServiceNodeRewardsAddress,
                Epoche.Keccak256.ComputeEthereumFunctionSelector("liquidateTag()", true),
                cancellationToken).ConfigureAwait(false);
            var hashToG2Tag = await EthCallAsync(
                rpcUrls,
                options.ServiceNodeRewardsAddress,
                Epoche.Keccak256.ComputeEthereumFunctionSelector("hashToG2Tag()", true),
                cancellationToken).ConfigureAwait(false);

            var loaded = new ServiceNodeContractTags(
                Array.Empty<byte>(),
                HexToBytes(rewardTag),
                HexToBytes(exitTag),
                HexToBytes(liquidateTag),
                HexToBytes(hashToG2Tag));
            _tags = loaded;
            return loaded;
        }
        finally
        {
            _tagGate.Release();
        }
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

        Exception? lastTransient = null;
        foreach (var rpcUrl in rpcUrls)
        {
            for (var attempt = 1; attempt <= MaxRpcAttempts; attempt++)
            {
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var response = await _httpClient.PostAsync(rpcUrl, content, cancellationToken).ConfigureAwait(false);
                var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    var exception = new HttpRequestException(
                        $"eth_call HTTP {(int)response.StatusCode} {response.ReasonPhrase}: {Truncate(body)}",
                        null,
                        response.StatusCode);
                    if (IsTransient(response.StatusCode))
                    {
                        lastTransient = exception;
                        if (attempt < MaxRpcAttempts)
                        {
                            await Task.Delay(RetryDelay(attempt), cancellationToken).ConfigureAwait(false);
                            continue;
                        }

                        break;
                    }

                    throw exception;
                }

                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("error", out var error))
                {
                    if (IsTransientJsonRpcError(error))
                    {
                        lastTransient = new InvalidOperationException($"eth_call failed: {error}");
                        if (attempt < MaxRpcAttempts)
                        {
                            await Task.Delay(RetryDelay(attempt), cancellationToken).ConfigureAwait(false);
                            continue;
                        }

                        break;
                    }

                    throw new InvalidOperationException($"eth_call failed: {error}");
                }

                return doc.RootElement.GetProperty("result").GetString()
                    ?? throw new InvalidOperationException("eth_call response did not include result.");
            }
        }

        throw new InvalidOperationException("All configured Arbitrum RPC endpoints failed.", lastTransient);
    }

    private static bool IsTransient(System.Net.HttpStatusCode statusCode)
    {
        var code = (int)statusCode;
        return statusCode == System.Net.HttpStatusCode.TooManyRequests
            || statusCode == System.Net.HttpStatusCode.RequestTimeout
            || code >= 500;
    }

    private static bool IsTransientJsonRpcError(JsonElement error)
    {
        if (error.TryGetProperty("code", out var code)
            && code.ValueKind == JsonValueKind.Number
            && code.TryGetInt32(out var numericCode)
            && (numericCode == 429 || numericCode == -32005))
        {
            return true;
        }

        var message = error.ToString();
        return message.Contains("rate", StringComparison.OrdinalIgnoreCase)
            || message.Contains("too many", StringComparison.OrdinalIgnoreCase)
            || message.Contains("timeout", StringComparison.OrdinalIgnoreCase)
            || message.Contains("temporar", StringComparison.OrdinalIgnoreCase);
    }

    private static TimeSpan RetryDelay(int attempt) =>
        TimeSpan.FromSeconds(Math.Min(10, Math.Pow(2, attempt)));

    private static string Truncate(string value) =>
        value.Length <= 512 ? value : value[..512] + "...";

    private static Scalar ScalarFromBigEndianHex(string hex)
    {
        var bytes = UInt256HexToBytes32(hex);
        Array.Reverse(bytes);
        return Scalar.FromBytes(bytes);
    }

    private static G1Affine ToAffine(G1Projective point)
    {
        var source = new[] { point };
        var target = new G1Affine[1];
        G1Projective.BatchNormalize(source, target);
        return target[0];
    }

    private static G2Affine ToAffine(G2Projective point)
    {
        var source = new[] { point };
        var target = new G2Affine[1];
        G2Projective.BatchNormalize(source, target);
        return target[0];
    }

    private static byte[] NeoG1ToEip(byte[] neo)
    {
        if (neo.Length != 96)
        {
            throw new ArgumentException("BLS12-381 G1 uncompressed point must be 96 bytes.", nameof(neo));
        }

        return Concat(Pad48To64(neo.AsSpan(0, 48)), Pad48To64(neo.AsSpan(48, 48)));
    }

    private static byte[] NeoG2ToEip(byte[] neo)
    {
        if (neo.Length != 192)
        {
            throw new ArgumentException("BLS12-381 G2 uncompressed point must be 192 bytes.", nameof(neo));
        }

        var parts = Split(neo, 48);
        return Concat(Pad48To64(parts[1]), Pad48To64(parts[0]), Pad48To64(parts[3]), Pad48To64(parts[2]));
    }

    private static byte[] EipG2ToNeo(byte[] eip)
    {
        if (eip.Length != G2EipBytes)
        {
            throw new ArgumentException("EIP-2537 G2 point must be 256 bytes.", nameof(eip));
        }

        var parts = Split(eip, 64).Select(Trim64To48).ToArray();
        return Concat(parts[1], parts[0], parts[3], parts[2]);
    }

    private static byte[][] Split(byte[] bytes, int size)
    {
        if (bytes.Length % size != 0)
        {
            throw new ArgumentException("Input length is not divisible by chunk size.", nameof(bytes));
        }

        var result = new byte[bytes.Length / size][];
        for (var i = 0; i < result.Length; i++)
        {
            result[i] = bytes.AsSpan(i * size, size).ToArray();
        }

        return result;
    }

    private static byte[] Pad48To64(ReadOnlySpan<byte> value)
    {
        if (value.Length != 48)
        {
            throw new ArgumentException("BLS12-381 field element must be 48 bytes.", nameof(value));
        }

        var result = new byte[64];
        value.CopyTo(result.AsSpan(16));
        return result;
    }

    private static byte[] Trim64To48(byte[] value)
    {
        if (value.Length != 64)
        {
            throw new ArgumentException("EIP-2537 field element must be 64 bytes.", nameof(value));
        }

        for (var i = 0; i < 16; i++)
        {
            if (value[i] != 0)
            {
                throw new ArgumentException("EIP-2537 field element has non-zero padding.", nameof(value));
            }
        }

        return value.AsSpan(16).ToArray();
    }

    private static byte[] UInt256ToBytes32(long value)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "uint256 value cannot be negative.");
        }

        var integer = new BigInteger(value);
        var bytes = integer.ToByteArray(isUnsigned: true, isBigEndian: true);
        return PadUInt256(bytes);
    }

    private static byte[] UInt256HexToBytes32(string hex)
    {
        var bytes = HexToBytes(hex);
        return PadUInt256(bytes);
    }

    private static byte[] PadUInt256(byte[] bytes)
    {
        if (bytes.Length > 32)
        {
            throw new ArgumentException("Value does not fit into uint256.", nameof(bytes));
        }

        var result = new byte[32];
        bytes.CopyTo(result, 32 - bytes.Length);
        return result;
    }

    private static string NormalizeMessageType(string? type)
    {
        var normalized = (type ?? "").Trim().ToLowerInvariant();
        return normalized switch
        {
            "reward" or "rewards" => "reward",
            "exit" => "exit",
            "liquidate" or "liquidation" => "liquidate",
            _ => throw new InvalidOperationException($"Unsupported quorum signing message type '{type}'.")
        };
    }

    private static string NormalizeHex(string hex, int expectedBytes)
    {
        var normalized = Strip0x(hex).ToLowerInvariant();
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException($"Expected {expectedBytes}-byte hex value.");
        }

        return normalized;
    }

    private static string NormalizeAddress(string address)
    {
        var normalized = Strip0x(address);
        if (normalized.Length != 40 || !normalized.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException("Expected 20-byte Ethereum address.");
        }

        return "0x" + normalized.ToLowerInvariant();
    }

    private static byte[] HexToBytes(string hex)
    {
        var normalized = Strip0x(hex);
        if (normalized.Length % 2 == 1)
        {
            normalized = "0" + normalized;
        }

        return Convert.FromHexString(normalized);
    }

    private static string Strip0x(string value) =>
        value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static byte[] Concat(params byte[][] chunks)
    {
        var result = new byte[chunks.Sum(static item => item.Length)];
        var offset = 0;
        foreach (var chunk in chunks)
        {
            Buffer.BlockCopy(chunk, 0, result, offset, chunk.Length);
            offset += chunk.Length;
        }

        return result;
    }

}
