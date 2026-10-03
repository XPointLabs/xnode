using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Ingress ordering only; fixture readiness is not current production admission.</summary>
public sealed class NativeMailboxIngressBindingTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(),
        $"xnode-mailbox-ingress-binding-{Guid.NewGuid():N}");

    [Theory]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Ack)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Ack)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Retrieve)]
    public async Task WrongOuterOperationRejectsBeforeAuthorityOrDurableReplay(
        OnionOperation outer, MailboxAuthenticatedOperation inner)
    {
        using var fixture = new Fixture(root);
        var result = await fixture.Dispatcher.DispatchAsync(outer, Frame(inner), default);

        Assert.Equal(400, result.StatusCode);
        Assert.Empty(result.CanonicalBody.ToArray());
        Assert.Equal(0, fixture.Authority.Calls);
        Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
        Assert.Equal(0UL, fixture.Replay.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);
    }

    [Theory]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Ack)]
    public async Task MatchingOperationStillRequiresAuthority(
        OnionOperation outer, MailboxAuthenticatedOperation inner)
    {
        using var fixture = new Fixture(root);
        var result = await fixture.Dispatcher.DispatchAsync(outer, Frame(inner), default);

        Assert.Equal(403, result.StatusCode);
        Assert.Equal(1, fixture.Authority.Calls);
        Assert.Equal(inner, fixture.Authority.LastOperation);
        Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
    }

    [Theory]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Ack)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Ack)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Retrieve)]
    public async Task WrongOuterOperationCannotReserveAnOtherwiseValidSignedRequest(
        OnionOperation outer, MailboxAuthenticatedOperation inner)
    {
        var exact = Frame(inner);
        var grant = MailboxAuthenticatedClientRequestCodec.Decode(exact).Presentation.Grant;
        using var fixture = new Fixture(root, acceptedGrant: grant);
        var result = await fixture.Dispatcher.DispatchAsync(outer, exact, default);

        Assert.Equal(400, result.StatusCode);
        Assert.Equal(0, fixture.Authority.Calls);
        Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
        Assert.Equal(0UL, fixture.Replay.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);

        // The same signed request/counter remains admissible to its actual operation.
        // This exercises the real signatures and native replay owner, not a fake verifier.
        var valid = fixture.Runtime.Verify(exact);
        Assert.Equal(MailboxAuthenticatedReplayDisposition.NewReserved, valid.ReplayDisposition);
        Assert.Equal(inner, valid.Verified.Binding.Operation);
        Assert.Equal(1, fixture.Authority.Calls);
        Assert.Equal(1, fixture.Replay.Diagnostics.ScopeCount);
        fixture.Runtime.CleanupRequest(valid);
    }

    [Fact]
    public async Task MalformedCanonicalRequestsStillConsumeTheExistingIngressBudget()
    {
        var malformed = Frame(MailboxAuthenticatedOperation.Store);
        malformed[6] = 1;
        using var fixture = new Fixture(root);
        for (var index = 0; index < MailboxWireHttpContract.Store.RequestsPerMinute; index++)
        {
            var rejected = await fixture.Dispatcher.DispatchAsync(OnionOperation.Store, malformed, default);
            Assert.Equal(400, rejected.StatusCode);
        }

        var throttled = await fixture.Dispatcher.DispatchAsync(OnionOperation.Store, malformed, default);
        Assert.Equal(429, throttled.StatusCode);
        Assert.Empty(throttled.CanonicalBody.ToArray());
        Assert.Equal(0, fixture.Authority.Calls);
        Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
    }

    [Fact]
    public async Task CallerBufferCannotChangeOperationDuringDependencyCallback()
    {
        var original = Frame(MailboxAuthenticatedOperation.Store);
        var replacement = Frame(MailboxAuthenticatedOperation.Retrieve);
        using var fixture = new Fixture(root, () =>
        {
            original.AsSpan().Clear();
            replacement.CopyTo(original, 0);
        });
        var result = await fixture.Dispatcher.DispatchAsync(OnionOperation.Store, original, default);

        Assert.Equal(403, result.StatusCode);
        Assert.Equal(1, fixture.Authority.Calls);
        Assert.Equal(MailboxAuthenticatedOperation.Store, fixture.Authority.LastOperation);
        Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
    }

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ServiceProvider services;
        private readonly MailboxClientCanonicalOutcomeStore outcomes;
        public CountingAuthority Authority { get; }
        public DurableMailboxCapabilityReplayJournal Replay { get; }
        public MailboxAuthenticatedCapabilityRuntime Runtime { get; }
        public ILocalNativeMailboxExitDispatcher Dispatcher { get; }

        public Fixture(string root, Action? clockCallback = null,
            MailboxAuthenticatedGrant? acceptedGrant = null)
        {
            Authority = new(acceptedGrant);
            Replay = new(root);
            outcomes = new(root);
            IClock clock = new CallbackClock(clockCallback);
            Runtime = new(Authority, new FixtureRevocations(), Replay, outcomes, clock);
            var readiness = new MailboxClientRuntimeReadiness(new(
                new MailboxClientActivationOptions(), new MailboxClientAdapterOptions(),
                RoutesMapped: true, DevelopmentFixture: false, ProductionTopology: false));
            // Exercise the ingress after its readiness gate, not a production-ready host.
            readiness.MarkReady(new(true, true, true, true, true, true, true, ""),
                new(true, true, true, true, true, ""));
            services = new ServiceCollection().AddSingleton(readiness).AddSingleton(clock)
                .AddSingleton(new MailboxClientIngressLimiter()).AddSingleton(Runtime)
                .BuildServiceProvider();
            Dispatcher = new NativeMailboxExitDispatcher(services);
        }

        public void Dispose()
        {
            services.Dispose();
            outcomes.Dispose();
            Replay.Dispose();
        }
    }

    private sealed class CountingAuthority(MailboxAuthenticatedGrant? grant)
        : IMailboxCapabilityAuthoritySource
    {
        public bool IsConfigured => grant is not null;
        public int Calls { get; private set; }
        public MailboxAuthenticatedOperation LastOperation { get; private set; }
        public bool TryResolve(MailboxCapabilityAuthorityQuery query,
            out MailboxAuthenticatedVerificationPolicy? policy)
        {
            Calls++;
            LastOperation = query.Operation;
            // Explicit fixture pin, never trust inferred from the incoming query.
            policy = grant is null ? null : new()
            {
                NetworkId = grant.NetworkId.ToArray(), Epoch = grant.Epoch,
                PlacementCommitment = grant.PlacementCommitment.ToArray(),
                MembershipCommitment = grant.MembershipCommitment.ToArray(),
                MinimumGeneration = grant.Generation, NowUnixSeconds = 1_000,
                TrustedIssuers = [new()
                {
                    PublicKey = grant.IssuerPublicKey.ToArray(), Domain = grant.Domain,
                    AllowedLifecycle = grant.Lifecycle, MinimumGeneration = grant.Generation,
                    MaximumGeneration = grant.Generation,
                    ValidFromUnixSeconds = grant.NotBeforeUnixSeconds,
                    ValidUntilUnixSeconds = grant.ExpiresAtUnixSeconds
                }]
            };
            return policy is not null;
        }
    }

    private sealed class FixtureRevocations : IMailboxCapabilityRevocationPolicy
    {
        public bool IsConfigured => true;
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    private sealed class CallbackClock(Action? callback) : IClock
    {
        public DateTimeOffset UtcNow
        {
            get
            {
                callback?.Invoke();
                return DateTimeOffset.FromUnixTimeSeconds(1_000);
            }
        }
    }

    private static byte[] Frame(MailboxAuthenticatedOperation operation)
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var mailbox = new BlindedMailboxId(Range(0x20, 32));
        var placement = new BlindedPlacementId(Range(0x90, 32));
        var id = Range(0xd0, 16);
        var binding = operation switch
        {
            MailboxAuthenticatedOperation.Store => MailboxAuthenticatedRequestTranscript.ForStore(new()
            {
                Epoch = 7, MailboxId = mailbox, PlacementId = placement, OperationId = id,
                DeduplicationDigest = Range(0xe0, 32), CreatedAtUnixSeconds = 1_000,
                ExpiresAtUnixSeconds = 1_060, Ciphertext = Range(1, 64)
            }),
            MailboxAuthenticatedOperation.Retrieve => MailboxAuthenticatedRequestTranscript.ForRetrieve(
                7, id, mailbox, placement, 0, 10, []),
            MailboxAuthenticatedOperation.Ack => MailboxAuthenticatedRequestTranscript.ForAck(
                7, id, mailbox, placement, true, [], [new()
                { Cursor = 1, EnvelopeDigest = Range(0xe0, 32) }]),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
        var grant = crypto.SignGrant(new()
        {
            Domain = operation == MailboxAuthenticatedOperation.Store
                ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve,
            Lifecycle = MailboxCapabilityLifecycle.Active, NetworkId = Range(0x70, 16),
            Epoch = 7, Generation = 9, Serial = Range(0x80, 16),
            NotBeforeUnixSeconds = 900, ExpiresAtUnixSeconds = 1_100, OverlapUntilUnixSeconds = 0,
            PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
            MembershipCommitment = Range(0xb0, 32), IssuerPublicKey = crypto.GetPublicKey(issuerSeed),
            HolderPublicKey = crypto.GetPublicKey(holderSeed), SelectionInput = Range(0xa0, 32),
            IssuerSignature = ReadOnlyMemory<byte>.Empty
        }, issuerSeed);
        return MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding, Presentation = crypto.SignPresentation(grant, binding, 11, holderSeed)
        });
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(value => (byte)value).ToArray();
}
