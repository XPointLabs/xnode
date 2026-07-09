using System.Numerics;
using System.Text.Json;
using XNode.Registry;

namespace XNode.Tests.Registry;

public sealed class QuorumSigningPolicyValidatorTests
{
    private const string RewardsContract = "0x1111111111111111111111111111111111111111";
    private static readonly string BlsPublicKey = new('a', 256);
    private static readonly string Recipient = "0x2222222222222222222222222222222222222222";

    [Fact]
    public async Task ValidateAsync_AllowsRewardWithinConfiguredIncrease()
    {
        using var http = new HttpClient(new PolicyHandler(
            serviceNodeId: 1,
            recipientRewards: 100,
            backendLifetimeRewards: 150,
            backendClaimedStakes: 0));
        var validator = new QuorumSigningPolicyValidator(http);

        await validator.ValidateAsync(
            Options(maxRewardIncrease: 100),
            ["http://rpc/"],
            "reward",
            new QuorumSignatureRequest
            {
                Type = "reward",
                RecipientAddress = Recipient,
                Amount = 150,
                PolicyQuote = "quote-1"
            },
            BlsPublicKey,
            CancellationToken.None);
    }

    [Fact]
    public async Task ValidateAsync_RejectsRewardAboveConfiguredIncrease()
    {
        using var http = new HttpClient(new PolicyHandler(
            serviceNodeId: 1,
            recipientRewards: 100,
            backendLifetimeRewards: 250,
            backendClaimedStakes: 0));
        var validator = new QuorumSigningPolicyValidator(http);

        var ex = await Assert.ThrowsAsync<QuorumSignatureRejectedException>(() =>
            validator.ValidateAsync(
                Options(maxRewardIncrease: 100),
                ["http://rpc/"],
                "reward",
                new QuorumSignatureRequest
                {
                    Type = "reward",
                    RecipientAddress = Recipient,
                    Amount = 250,
                    PolicyQuote = "quote-1"
                },
                BlsPublicKey,
                CancellationToken.None));

        Assert.Contains("exceeds configured cap", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_RejectsRewardThatDoesNotMatchBackendProjection()
    {
        using var http = new HttpClient(new PolicyHandler(
            serviceNodeId: 1,
            recipientRewards: 100,
            backendLifetimeRewards: 150,
            backendClaimedStakes: 0));
        var validator = new QuorumSigningPolicyValidator(http);

        var ex = await Assert.ThrowsAsync<QuorumSignatureRejectedException>(() =>
            validator.ValidateAsync(
                Options(maxRewardIncrease: 100),
                ["http://rpc/"],
                "reward",
                new QuorumSignatureRequest
                {
                    Type = "reward",
                    RecipientAddress = Recipient,
                    Amount = 149,
                    PolicyQuote = "quote-1"
                },
                BlsPublicKey,
                CancellationToken.None));

        Assert.Contains("does not match backend projection", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_RejectsInactiveLocalSigner()
    {
        using var http = new HttpClient(new PolicyHandler(serviceNodeId: 0, recipientRewards: 0));
        var validator = new QuorumSigningPolicyValidator(http);

        var ex = await Assert.ThrowsAsync<QuorumSignatureRejectedException>(() =>
            validator.ValidateAsync(
                Options(maxRewardIncrease: 100),
                ["http://rpc/"],
                "reward",
                new QuorumSignatureRequest
                {
                    Type = "reward",
                    RecipientAddress = Recipient,
                    Amount = 1,
                    PolicyQuote = "quote-1"
                },
                BlsPublicKey,
                CancellationToken.None));

        Assert.Contains("local signer", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_RejectsStaleExitTimestamp()
    {
        using var http = new HttpClient(new PolicyHandler(serviceNodeId: 1, recipientRewards: 0));
        var validator = new QuorumSigningPolicyValidator(http);

        var ex = await Assert.ThrowsAsync<QuorumSignatureRejectedException>(() =>
            validator.ValidateAsync(
                Options(timestampSkewSeconds: 10),
                ["http://rpc/"],
                "exit",
                new QuorumSignatureRequest
                {
                    Type = "exit",
                    BlsPublicKey = BlsPublicKey,
                    Timestamp = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds()
                },
                BlsPublicKey,
                CancellationToken.None));

        Assert.Contains("freshness window", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_RejectsActiveExitTargetThatIsNotExitEligible()
    {
        using var http = new HttpClient(new PolicyHandler(
            serviceNodeId: 1,
            recipientRewards: 0,
            exitEligible: false));
        var validator = new QuorumSigningPolicyValidator(http);

        var ex = await Assert.ThrowsAsync<QuorumSignatureRejectedException>(() =>
            validator.ValidateAsync(
                Options(),
                ["http://rpc/"],
                "exit",
                new QuorumSignatureRequest
                {
                    Type = "exit",
                    BlsPublicKey = BlsPublicKey,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                },
                BlsPublicKey,
                CancellationToken.None));

        Assert.Contains("not exit eligible", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_RejectsWhenPolicyBackendIsMissing()
    {
        using var http = new HttpClient(new PolicyHandler(serviceNodeId: 1, recipientRewards: 100));
        var validator = new QuorumSigningPolicyValidator(http);
        var options = Options();
        options.QuorumPolicyBackendBaseUrl = "";

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            validator.ValidateAsync(
                options,
                ["http://rpc/"],
                "reward",
                new QuorumSignatureRequest
                {
                    Type = "reward",
                    RecipientAddress = Recipient,
                    Amount = 150,
                    PolicyQuote = "quote-1"
                },
                BlsPublicKey,
                CancellationToken.None));

        Assert.Contains("QuorumPolicyBackendBaseUrl", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_RejectsRewardWithoutPolicyQuote()
    {
        using var http = new HttpClient(new PolicyHandler(serviceNodeId: 1, recipientRewards: 100));
        var validator = new QuorumSigningPolicyValidator(http);

        var ex = await Assert.ThrowsAsync<QuorumSignatureRejectedException>(() =>
            validator.ValidateAsync(
                Options(maxRewardIncrease: 100),
                ["http://rpc/"],
                "reward",
                new QuorumSignatureRequest
                {
                    Type = "reward",
                    RecipientAddress = Recipient,
                    Amount = 150
                },
                BlsPublicKey,
                CancellationToken.None));

        Assert.Contains("policy quote", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_RejectsExpiredRewardPolicyQuote()
    {
        using var http = new HttpClient(new PolicyHandler(
            serviceNodeId: 1,
            recipientRewards: 100,
            backendLifetimeRewards: 150,
            quoteExpired: true));
        var validator = new QuorumSigningPolicyValidator(http);

        var ex = await Assert.ThrowsAsync<QuorumSignatureRejectedException>(() =>
            validator.ValidateAsync(
                Options(maxRewardIncrease: 100),
                ["http://rpc/"],
                "reward",
                new QuorumSignatureRequest
                {
                    Type = "reward",
                    RecipientAddress = Recipient,
                    Amount = 150,
                    PolicyQuote = "quote-1"
                },
                BlsPublicKey,
                CancellationToken.None));

        Assert.Contains("expired", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static RegistryRegistrationOptions Options(
        long maxRewardIncrease = 1_000_000_000,
        int timestampSkewSeconds = 300)
    {
        return new RegistryRegistrationOptions
        {
            EthereumRpcUrl = "http://rpc/",
            ServiceNodeRewardsAddress = RewardsContract,
            QuorumPolicyBackendBaseUrl = "http://staking/",
            MaxRewardSignatureIncreaseAtomic = maxRewardIncrease,
            MaxQuorumSignatureTimestampSkewSeconds = timestampSkewSeconds
        };
    }

    private static string AbiUInt256(BigInteger value)
    {
        return value.ToString("x").PadLeft(64, '0');
    }

    private sealed class PolicyHandler : HttpMessageHandler
    {
        private readonly long _serviceNodeId;
        private readonly long _recipientRewards;
        private readonly long _backendLifetimeRewards;
        private readonly long _backendClaimedStakes;
        private readonly bool _exitEligible;
        private readonly bool _liquidationEligible;
        private readonly bool _quoteExpired;
        private readonly string _serviceNodeIdsSelector =
            Epoche.Keccak256.ComputeEthereumFunctionSelector("serviceNodeIDs(bytes)", true);
        private readonly string _recipientsSelector =
            Epoche.Keccak256.ComputeEthereumFunctionSelector("recipients(address)", true);

        public PolicyHandler(
            long serviceNodeId,
            long recipientRewards,
            long backendLifetimeRewards = 0,
            long backendClaimedStakes = 0,
            bool exitEligible = false,
            bool liquidationEligible = false,
            bool quoteExpired = false)
        {
            _serviceNodeId = serviceNodeId;
            _recipientRewards = recipientRewards;
            _backendLifetimeRewards = backendLifetimeRewards;
            _backendClaimedStakes = backendClaimedStakes;
            _exitEligible = exitEligible;
            _liquidationEligible = liquidationEligible;
            _quoteExpired = quoteExpired;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Get)
            {
                return HandleBackendRequest(request);
            }

            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(body);
            var call = document.RootElement.GetProperty("params")[0];
            var data = call.GetProperty("data").GetString()!;
            var result = data.StartsWith(_serviceNodeIdsSelector, StringComparison.OrdinalIgnoreCase)
                ? AbiUInt256(_serviceNodeId)
                : data.StartsWith(_recipientsSelector, StringComparison.OrdinalIgnoreCase)
                    ? AbiUInt256(_recipientRewards) + AbiUInt256(0)
                    : throw new InvalidOperationException($"Unexpected eth_call data {data}.");

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, result = "0x" + result }),
                    System.Text.Encoding.UTF8,
                    "application/json")
            };
        }

        private HttpResponseMessage HandleBackendRequest(HttpRequestMessage request)
        {
            var path = request.RequestUri?.AbsolutePath ?? "";
            object payload = path.Equals($"/api/staking/rewards/{Recipient}/quotes/quote-1", StringComparison.OrdinalIgnoreCase)
                ? new
                {
                    address = Recipient,
                    quoteId = "quote-1",
                    amountAtomic = checked(_backendLifetimeRewards + _backendClaimedStakes),
                    expiresAtUnixSeconds = DateTimeOffset.UtcNow.AddSeconds(_quoteExpired ? -1 : 30).ToUnixTimeSeconds()
                }
                : path.Equals("/obligations", StringComparison.OrdinalIgnoreCase)
                    ? new
                    {
                        nodes = new[]
                        {
                            new
                            {
                                bls_public_key = BlsPublicKey,
                                exit_signature_eligible = _exitEligible,
                                liquidation_signature_eligible = _liquidationEligible
                            }
                        }
                    }
                    : throw new InvalidOperationException($"Unexpected policy backend request {request.Method} {path}.");

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(payload),
                    System.Text.Encoding.UTF8,
                    "application/json")
            };
        }
    }
}
