using System.Reflection;
using System.Runtime.CompilerServices;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed class PrivacyRoutingRuntimeTests
{
    [Fact]
    public void EnabledOptionsRejectIncompleteProductionStateConfiguration()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new PrivacyRoutingOptions { Enabled = true }.ValidateAndLoad(
                new RouterNodeOptions(),
                isDevelopment: true));

        Assert.Contains("X25519PrivateKeyPath", exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void PublicFailClosedRuntimeHasNoProductionCapability()
    {
        var effects = new Effects();
        var runtime = Runtime(PrivacyRoutingConfiguration.Disabled, effects);

        Assert.False(runtime.ProductionCapabilityAvailable);
        var root = FindRepositoryRoot();
        var program = File.ReadAllText(Path.Combine(root, "src", "XNode", "Program.cs"));

        Assert.Contains("AddProductionPrivacyRoutingBoundary", program,
            StringComparison.Ordinal);
    }

    [Fact]
    public void EnabledCompositionRejectsMissingVerifiedAuthoritySource()
    {
        var services = new ServiceCollection();
        using var configuration = EnabledTestConfiguration();

        var failure = Assert.Throws<InvalidOperationException>(() =>
            services.AddProductionPrivacyRoutingBoundary(
                configuration,
                new RouterNodeOptions
                {
                    RouterId = new string('1', RouterId.HexLength),
                    IsRelay = true
                }));

        Assert.Contains(nameof(IContactVerifiedAuthoritySnapshotSource), failure.Message,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            services,
            static descriptor => descriptor.ServiceType == typeof(PrivacyRoutingRuntime));
    }

    [Fact]
    public void ProductionCompositionConnectsAuthenticatedContactResolveClientWhenOwnerExists()
    {
        var services = new ServiceCollection();
        using var configuration = EnabledTestConfiguration();
        services.AddSingleton<IContactVerifiedAuthoritySnapshotSource>(static _ => null!);
        services.AddSingleton<IPrivacyRoutedContactRecipientResolveEvidenceIngestion>(
            static _ => null!);

        services.AddProductionPrivacyRoutingBoundary(
            configuration,
            new RouterNodeOptions
            {
                RouterId = new string('1', RouterId.HexLength),
                IsRelay = true
            });

        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IPrivacyRoutedContactRecipientResolveClient)
            && descriptor.ImplementationType
                == typeof(PrivacyRoutedContactRecipientResolveClient));
    }

    [Fact]
    public async Task CompleteCurrentBindingActivatesOnlyTheFullyComposedRuntime()
    {
        var effects = new Effects();
        using var configuration = EnabledTestConfiguration();
        var capability = new PrivacyRoutingProductionCapability(
            configuration,
            new FixedBindingSource(Binding(configuration)));
        var keyAgreement = new OnionKeyAgreementAuthority(new NoOpVault());
        var replay = new OnionReplayAuthority(new NoOpReplayStore());
        var codec = new PrivacyRoutingCodec(
            new OnionEntropyAuthority(new NoOpEntropyLedger()),
            keyAgreement);
        var runtime = new PrivacyRoutingRuntime(
            configuration,
            effects,
            Terminal(effects),
            capability,
            keyAgreement,
            replay,
            codec);

        Assert.False(runtime.ProductionCapabilityAvailable);
        await capability.StartAsync(default);
        Assert.True(runtime.ProductionCapabilityAvailable);
        await capability.StopAsync(default);
        Assert.False(runtime.ProductionCapabilityAvailable);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StaleOrMismatchedBindingNeverActivates(bool stale)
    {
        using var configuration = EnabledTestConfiguration();
        var binding = stale
            ? new OnionHostReceiveBinding(
                (VerifiedOnionNetworkContext)RuntimeHelpers.GetUninitializedObject(
                    typeof(VerifiedOnionNetworkContext)),
                configuration.ReceivePosition,
                Bytes(0x51),
                configuration.KeyHandleId.Span)
            : Binding(configuration, OnionReceivePosition.Core);
        var capability = new PrivacyRoutingProductionCapability(
            configuration,
            new FixedBindingSource(binding));

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await capability.StartAsync(default));

        Assert.False(capability.IsVerified);
    }

    [Fact]
    public void RuntimeUsesOnlyProtocolOwnedReceiveAndNextHopCapabilities()
    {
        var root = FindRepositoryRoot();
        var runtime = File.ReadAllText(Path.Combine(
            root, "src", "XNode", "PrivacyRoutingRuntime.cs"));

        Assert.Contains("OnionLocalNodeKeyFactory.Bind", runtime,
            StringComparison.Ordinal);
        Assert.Contains("OnionReceiveContextSelector.Select", runtime,
            StringComparison.Ordinal);
        Assert.Contains("relay.NextHop", runtime, StringComparison.Ordinal);
        Assert.DoesNotContain("NextRouterId", runtime, StringComparison.Ordinal);
        Assert.DoesNotContain("configuration.Peers", runtime, StringComparison.Ordinal);
        Assert.DoesNotContain("RouterId.FromBytes", runtime, StringComparison.Ordinal);

        var forward = Assert.Single(typeof(IPrivacyPeerClient).GetMethods());
        Assert.Equal(
            typeof(VerifiedOnionNextHopTransport),
            forward.GetParameters()[0].ParameterType);
    }

    [Fact]
    public void PartialVerifiedBoundaryCompositionIsRejected()
    {
        var effects = new Effects();
        var exception = Assert.Throws<ArgumentException>(() =>
            new PrivacyRoutingRuntime(
                PrivacyRoutingConfiguration.Disabled,
                effects,
                Terminal(effects),
                new PrivacyRoutingProductionCapability(
                    PrivacyRoutingConfiguration.Disabled,
                    new UnavailableBindingSource()),
                keyAgreement: null,
                replay: null,
                codec: null));

        Assert.Contains("must be supplied atomically", exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task RuntimeIsUnavailableWithoutForwardingContactOrMailboxEffects()
    {
        var effects = new Effects();
        var runtime = Runtime(PrivacyRoutingConfiguration.Disabled, effects);

        var result = await runtime.ProcessAsync("attacker-controlled-frame"u8.ToArray(), default);

        Assert.Equal(PrivacyRuntimeOutcome.UnavailableBeforeForward, result.Outcome);
        Assert.Empty(result.OpaqueReply.ToArray());
        Assert.Equal(0, effects.PeerCalls);
        Assert.Equal(0, effects.ContactCalls);
        Assert.Equal(0, effects.MailboxCalls);
        Assert.Equal(0, effects.AuthorityForwardingCalls);
    }

    [Fact]
    public async Task DisabledPublicIngressReturnsCoarse503WithoutAnySideEffects()
    {
        var effects = new Effects();
        var configuration = PrivacyRoutingConfiguration.Disabled;
        var context = new DefaultHttpContext();
        context.Connection.LocalPort = 8443;
        context.Response.Body = new MemoryStream();

        var result = await PrivacyRoutingHttpEndpoint.HandlePublicAsync(
            context,
            configuration,
            new PrivacyIngressLimiter(configuration),
            Runtime(configuration, effects),
            new FixedClock(),
            apiListenerPort: 8443,
            default);
        await result.ExecuteAsync(context);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, context.Response.StatusCode);
        Assert.Equal(ManagedIngressH2Contract.ErrorMediaType, context.Response.ContentType);
        Assert.Equal(0, effects.PeerCalls);
        Assert.Equal(0, effects.ContactCalls);
        Assert.Equal(0, effects.MailboxCalls);
        Assert.Equal(0, effects.AuthorityForwardingCalls);
    }

    [Fact]
    public async Task EvenDirectEnabledConfigurationCannotBypassInactiveCapability()
    {
        var effects = new Effects();
        using var configuration = EnabledTestConfiguration();
        var runtime = Runtime(configuration, effects);

        var result = await runtime.ProcessAsync(new byte[4096], default);

        Assert.Equal(PrivacyRuntimeOutcome.UnavailableBeforeForward, result.Outcome);
        Assert.Equal(0, effects.PeerCalls);
        Assert.Equal(0, effects.ContactCalls);
        Assert.Equal(0, effects.MailboxCalls);
        Assert.Equal(0, effects.AuthorityForwardingCalls);
    }

    private static PrivacyRoutingRuntime Runtime(
        PrivacyRoutingConfiguration configuration,
        Effects effects)
        => new(configuration, effects, Terminal(effects));

    private static PrivacyTerminalExitDispatcher Terminal(Effects effects)
    {
        var routedMailbox = new RoutedNativeMailboxExitDispatcher(
            new MailboxAuthorityForwardingConfiguration(
                authority: null,
                allowedExitRouterIds: new HashSet<RouterId>()),
            effects,
            effects);
        return new PrivacyTerminalExitDispatcher(routedMailbox, effects);
    }

    private static PrivacyRoutingConfiguration EnabledTestConfiguration() => new(
        enabled: true,
        privateKey: Enumerable.Repeat((byte)0x31, 32).ToArray(),
        publicKey: Enumerable.Repeat((byte)0x32, 32).ToArray(),
        publicPeerEndpoint: new Uri("https://disabled.invalid/"),
        peers: new Dictionary<RouterId, PrivacyPeer>(),
        maximumConcurrentRequests: 1,
        requestsPerMinute: 1,
        requestTimeout: TimeSpan.FromSeconds(1),
        replyPaddingBlockBytes: 1024,
        replayCapacity: 1,
        replayTtl: TimeSpan.FromSeconds(1),
        stateProtectionKeyPath: Path.Combine(Path.GetTempPath(), "xnode-privacy-test", "state.key"),
        replayStatePath: Path.Combine(Path.GetTempPath(), "xnode-privacy-test", "replay.bin"),
        entropyStatePath: Path.Combine(Path.GetTempPath(), "xnode-privacy-test", "entropy.bin"),
        keyVaultDirectory: Path.Combine(Path.GetTempPath(), "xnode-privacy-test", "vault"),
        receivePosition: OnionReceivePosition.Ingress);

    private static OnionHostReceiveBinding Binding(
        PrivacyRoutingConfiguration configuration,
        OnionReceivePosition? position = null) => new(
            CompleteNetwork(),
            position ?? configuration.ReceivePosition,
            Bytes(0x41),
            configuration.KeyHandleId.Span);

    private static VerifiedOnionNetworkContext CompleteNetwork()
    {
        var protocol = typeof(VerifiedOnionNetworkContext).Assembly;
        var lease = (OnionTrustedTimeLease)RuntimeHelpers.GetUninitializedObject(
            typeof(OnionTrustedTimeLease));
        SetField(lease, "_timeProvider", TimeProvider.System);
        SetField(lease, "_createdTimestamp", TimeProvider.System.GetTimestamp());
        SetField(lease, "_lifetime", TimeSpan.FromMinutes(1));
        SetField(lease, "_bootId", Bytes(0x31));
        var closureType = protocol.GetType(
            "Deep.Protocol.XPointNetworkV1.VerifiedOnionNetworkClosure",
            throwOnError: true)!;
        var closure = RuntimeHelpers.GetUninitializedObject(closureType);
        var lkg = new XPointNetworkProtectedLkg(
            Enumerable.Repeat((byte)0x11, 16).ToArray(),
            Reference("XNH1", 0x21),
            1,
            Bytes(0x22),
            Reference("XNV1", 0x23),
            0,
            Reference("XNA1", 0x24));
        var network = (VerifiedOnionNetworkContext)RuntimeHelpers.GetUninitializedObject(
            typeof(VerifiedOnionNetworkContext));
        SetField(network, "_networkId", Enumerable.Repeat((byte)0x11, 16).ToArray());
        SetField(network, "<TrustedTime>k__BackingField", lease);
        SetField(network, "<Closure>k__BackingField", closure);
        SetField(network, "<ProtectedLkg>k__BackingField", lkg);
        return network;
    }

    private static void SetField(object target, string name, object value) =>
        target.GetType().GetField(
            name,
            BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(target, value);

    private static byte[] Reference(string magic, byte marker)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic, value);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4, 2), 1);
        value.AsSpan(6).Fill(marker);
        return value;
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("XNode repository root was not found.");
    }

    private sealed class Effects :
        IPrivacyPeerClient,
        ILocalNativeMailboxExitDispatcher,
        IMailboxAuthorityForwardingClient,
        IContactServiceOpaqueDispatcher
    {
        public int PeerCalls { get; private set; }
        public int MailboxCalls { get; private set; }
        public int AuthorityForwardingCalls { get; private set; }
        public int ContactCalls { get; private set; }

        public Task<PrivacyForwardResult> ForwardAsync(
            VerifiedOnionNextHopTransport nextHop,
            ReadOnlyMemory<byte> innerFrame,
            CancellationToken cancellationToken)
        {
            PeerCalls++;
            return Task.FromResult(PrivacyForwardResult.Rejected);
        }

        Task<NativeMailboxDispatchResult> ILocalNativeMailboxExitDispatcher.DispatchAsync(
            OnionOperation privacyOperation,
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken)
        {
            MailboxCalls++;
            return Task.FromResult(NativeMailboxDispatchResult.RejectedBeforeForward());
        }

        Task<NativeMailboxDispatchResult> IMailboxAuthorityForwardingClient.ForwardAsync(
            OnionOperation operation,
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken)
        {
            AuthorityForwardingCalls++;
            return Task.FromResult(NativeMailboxDispatchResult.RejectedBeforeForward());
        }

        public ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
            ContactServiceOperation operation,
            ReadOnlyMemory<byte> canonicalRequest,
            CancellationToken cancellationToken)
        {
            ContactCalls++;
            return ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
        }
    }

    private sealed class UnavailableBindingSource : IOnionHostReceiveBindingSource
    {
        public ValueTask<OnionHostReceiveBinding> GetCurrentAsync(
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Not expected by this test.");
    }

    private sealed class FixedBindingSource(OnionHostReceiveBinding binding)
        : IOnionHostReceiveBindingSource
    {
        public ValueTask<OnionHostReceiveBinding> GetCurrentAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(binding);
        }
    }

    private sealed class NoOpVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(
            OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Bytes(0x61));
    }

    private sealed class NoOpReplayStore : IOnionDurableReplayStore
    {
        public ValueTask<IOnionDurableReplayTransaction> BeginAsync(
            OnionReplayScope scope,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<IOnionDurableReplayTransaction>(new NoOpReplayTransaction());
    }

    private sealed class NoOpReplayTransaction : IOnionDurableReplayTransaction
    {
        public ValueTask<OnionReplayCommitOutcome> CommitAsync(
            ReadOnlyMemory<byte> replayId,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(OnionReplayCommitOutcome.Committed);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoOpEntropyLedger : IOnionEntropyUniquenessLedger
    {
        public ValueTask<OnionEntropyCommitOutcome> CommitAsync(
            OnionEntropyCommitmentBatch batch,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(OnionEntropyCommitOutcome.Committed);
    }

    private sealed class FixedClock : IClock
    {
        public DateTimeOffset UtcNow { get; } =
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    }
}
