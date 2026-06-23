using System.Text;
using System.Text.Json;
using Neo.Cryptography.BLS12_381;

namespace XNode.Registry;

public sealed class Bls12381RegistrationProofService
{
    private const int G1EipBytes = 128;
    private const int G2EipBytes = 256;
    private const int MaxRpcAttempts = 5;
    private const string MapFp2ToG2Precompile = "0x0000000000000000000000000000000000000011";

    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _proofGate = new(1, 1);
    private BlsRegistrationProof? _cachedProof;

    public Bls12381RegistrationProofService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<BlsRegistrationProof> CreateProofAsync(
        RegistryRegistrationOptions options,
        string serviceNodePubkey,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(options.BlsPublicKey)
            && !string.IsNullOrWhiteSpace(options.BlsSignature))
        {
            return new BlsRegistrationProof(
                NormalizeHex(options.BlsPublicKey, G1EipBytes),
                NormalizeHex(options.BlsSignature, G2EipBytes));
        }

        var privateKey = options.GetBlsPrivateKey();
        if (string.IsNullOrWhiteSpace(privateKey))
        {
            throw new InvalidOperationException("RegistryRegistration:BlsPrivateKey or BlsPublicKey+BlsSignature is required.");
        }

        var rpcUrls = options.GetEthereumRpcUrls();
        if (rpcUrls.Count == 0)
        {
            throw new InvalidOperationException("RegistryRegistration:EthereumRpcUrl is required when deriving BLS proof.");
        }

        if (string.IsNullOrWhiteSpace(options.ServiceNodeRewardsAddress))
        {
            throw new InvalidOperationException("RegistryRegistration:ServiceNodeRewardsAddress is required when deriving BLS proof.");
        }

        if (_cachedProof is not null)
        {
            return _cachedProof;
        }

        await _proofGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_cachedProof is not null)
            {
                return _cachedProof;
            }

            _cachedProof = await DeriveProofAsync(options, rpcUrls, privateKey, serviceNodePubkey, cancellationToken)
                .ConfigureAwait(false);
            return _cachedProof;
        }
        finally
        {
            _proofGate.Release();
        }
    }

    private async Task<BlsRegistrationProof> DeriveProofAsync(
        RegistryRegistrationOptions options,
        IReadOnlyList<string> rpcUrls,
        string privateKey,
        string serviceNodePubkey,
        CancellationToken cancellationToken)
    {
        var scalar = ScalarFromBigEndianHex(privateKey);
        var pubkey = ToAffine(G1Affine.Generator * scalar);
        var eipPubkey = NeoG1ToEip(pubkey.ToUncompressed());
        var tags = ServiceNodeContractTagBuilder.TryBuild(options);

        var proofOfPossessionTag = tags?.ProofOfPossessionTag
            ?? HexToBytes(await EthCallAsync(
                rpcUrls,
                options.ServiceNodeRewardsAddress,
                Epoche.Keccak256.ComputeEthereumFunctionSelector("proofOfPossessionTag()", true),
                cancellationToken).ConfigureAwait(false));
        var hashToG2Tag = tags?.HashToG2Tag
            ?? HexToBytes(await EthCallAsync(
                rpcUrls,
                options.ServiceNodeRewardsAddress,
                Epoche.Keccak256.ComputeEthereumFunctionSelector("hashToG2Tag()", true),
                cancellationToken).ConfigureAwait(false));

        var encodedMessage = Concat(
            proofOfPossessionTag,
            eipPubkey,
            HexToBytes(NormalizeAddress(options.OperatorAddress)),
            UInt256HexToBytes32(serviceNodePubkey));
        var digest = Epoche.Keccak256.ComputeHash(Concat(hashToG2Tag, encodedMessage));
        var mapInput = Concat(new byte[32], digest, new byte[32], new byte[32]);
        var mappedEip = await EthCallAsync(
            rpcUrls,
            MapFp2ToG2Precompile,
            "0x" + Hex(mapInput),
            cancellationToken).ConfigureAwait(false);

        var hashPoint = G2Affine.FromUncompressed(EipG2ToNeo(HexToBytes(mappedEip)));
        var signature = ToAffine(hashPoint * scalar);

        return new BlsRegistrationProof(
            Hex(eipPubkey),
            Hex(NeoG2ToEip(signature.ToUncompressed())));
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
        TimeSpan.FromSeconds(Math.Min(30, Math.Pow(2, attempt)));

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

    private static byte[] UInt256HexToBytes32(string hex)
    {
        var bytes = HexToBytes(hex);
        if (bytes.Length > 32)
        {
            throw new ArgumentException("Value does not fit into uint256.", nameof(hex));
        }

        var result = new byte[32];
        bytes.CopyTo(result, 32 - bytes.Length);
        return result;
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

public sealed record BlsRegistrationProof(
    string PublicKey,
    string Signature);
