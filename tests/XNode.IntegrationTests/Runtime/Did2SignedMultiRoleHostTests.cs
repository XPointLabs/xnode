using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Http;
using Sodium;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.PrivacyRouting;

namespace XNode.IntegrationTests.Runtime;

/// <summary>
/// Real DID2/NETCODEC, encrypted vaults, durable replay/entropy and three host
/// runtimes. Peer calls are in-process, not TLS/physical device evidence. The
/// exit deliberately returns unavailable: no staged publication is claimed.
/// </summary>
public sealed class Did2SignedMultiRoleHostTests
{
    [Theory]
    [InlineData(0, 1, 2)]
    [InlineData(0, 2, 1)]
    [InlineData(1, 0, 2)]
    [InlineData(1, 2, 0)]
    [InlineData(2, 0, 1)]
    [InlineData(2, 1, 0)]
    public async Task AllSixSignedPathsOpenAndRestartRejectsReplay(int ingress, int core, int exit)
    {
        using var selection = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var candidateIds = OnionPathCandidateSnapshotFactory.Create(selection.NetworkContext).Candidates;
        byte marker = 1;
        for (; marker < 65; marker++)
        {
            var placement = ContactServicePlacementFactory.Create(selection.NetworkContext,
                ContactServiceRequestKind.PublishPreKeyInventory, Bytes(marker));
            if (placement.RankedReplicaNodeIds.Any(id => id.Span.SequenceEqual(candidateIds[exit].NodeId.Span))) break;
        }
        Assert.True(marker < 65);
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(marker);
        var network = signed.NetworkContext;
        var candidates = OnionPathCandidateSnapshotFactory.Create(network).Candidates;
        var placementCurrent = ContactServicePlacementFactory.Create(network,
            ContactServiceRequestKind.PublishPreKeyInventory, Bytes(marker));
        var path = OnionPathContextFactory.CreateContactResolver(network, placementCurrent,
            candidates[ingress].NodeId, candidates[core].NodeId, candidates[exit].NodeId);
        var sequence = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(signed.Publication.CanonicalBytes.Span,
            placementCurrent.ViewHash.Span, signed.Publisher.CanonicalBytes.Span, signed.Dca, signed.Xps);
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(network, OnionOperation.ContactResolve, sequence[^1]);
        var root = Path.Combine(Path.GetTempPath(), "did2-multirole-host-" + Guid.NewGuid().ToString("N"));
        var hosts = new List<Host>();
        var security = new MailboxStorageSecurity();
        security.SecureDirectory(root);
        var clientKey = Path.Combine(root, "client.key");
        File.WriteAllBytes(clientKey, Bytes(0xf6)); security.SecureFile(clientKey);
        try
        {
            using var clientEntropy = new DurableOnionEntropyUniquenessLedger(Path.Combine(root, "client.entropy"), clientKey);
            using var clientVault = new FileOnionKeyAgreementVault(Path.Combine(root, "client.vault"), clientKey);
            var client = new PrivacyRoutingCodec(new(clientEntropy), new(clientVault));
            var peers = new Peers();
            var terminal = new UnavailableTerminal();
            for (var i = 0; i < candidates.Count; i++)
            {
                var host = new Host(Path.Combine(root, "node-" + i), signed, candidates[i], peers, terminal);
                hosts.Add(host); peers.Hosts.Add(Convert.ToHexString(candidates[i].NodeId.Span), host);
                await host.Capability.StartAsync(default);
            }
            using var built = await client.BuildAsync(path, request, default);
            var result = await hosts[ingress].Runtime.ProcessAsync(built.Frame, default);
            Assert.True(result.Outcome == PrivacyRuntimeOutcome.Completed,
                $"Outcome={result.Outcome}; peer calls={peers.Calls}; terminal calls={terminal.Calls}; forwarded outcomes={string.Join(',', peers.Outcomes)}");
            var response = await client.OpenResponseAsync(result.OpaqueReply, built.ReplyContext, default);
            Assert.Equal(OnionFailureCode.Unavailable, response.Result.FailureCode);
            Assert.Equal(2, peers.Calls);
            Assert.Equal(1, terminal.Calls);
            Assert.Equal(request.CanonicalBytes.ToArray(), terminal.Request);
            hosts[ingress].RestartReplay();
            var replay = await hosts[ingress].Runtime.ProcessAsync(built.Frame, default);
            Assert.Equal(PrivacyRuntimeOutcome.ReplayedBeforeForward, replay.Outcome);
            Assert.Equal(2, peers.Calls);
            Assert.Equal(1, terminal.Calls);
        }
        finally
        {
            foreach (var host in hosts) host.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] Bytes(byte marker) => Enumerable.Repeat(marker, 32).ToArray();

    internal sealed class Host : IDisposable
    {
        private readonly string replayPath, keyPath;
        private readonly FileOnionKeyAgreementVault vault;
        private readonly DurableOnionEntropyUniquenessLedger entropy;
        private DurableOnionReplayStore replay;
        private readonly PrivacyRoutingConfiguration config;
        private readonly IPrivacyPeerClient peers;
        private readonly INativeMailboxExitDispatcher terminal;
        internal PrivacyRoutingProductionCapability Capability { get; }
        internal PrivacyRoutingRuntime Runtime { get; private set; }

        internal Host(string root, DeepIdV2PublicationAuthorityFixture signed,
            VerifiedOnionPathCandidate candidate, IPrivacyPeerClient peers, INativeMailboxExitDispatcher terminal)
        {
            this.peers = peers; this.terminal = terminal;
            var security = new MailboxStorageSecurity(); security.SecureDirectory(root);
            keyPath = Path.Combine(root, "state.key"); replayPath = Path.Combine(root, "replay.state");
            File.WriteAllBytes(keyPath, RandomNumberGenerator.GetBytes(32)); security.SecureFile(keyPath);
            var scalar = signed.TestOnionScalar(candidate.NodeId.Span);
            config = new(true, scalar, ScalarMult.Base(scalar), new Uri("https://node.invalid/"),
                new Dictionary<RouterId, PrivacyPeer>(), 1, 1, TimeSpan.FromSeconds(5), 1024, 100, TimeSpan.FromSeconds(5),
                keyPath, replayPath, Path.Combine(root, "entropy.state"), Path.Combine(root, "vault"));
            FileOnionKeyAgreementVault.EnsureSlot(config.KeyVaultDirectory, config.KeyHandleId.Span, scalar, keyPath);
            vault = new(config.KeyVaultDirectory, keyPath);
            replay = new(replayPath, keyPath);
            entropy = new(config.EntropyStatePath, keyPath);
            var bindings = new VerifiedOnionHostReceiveBindingSource(new SignedNetwork(signed),
                new RouterNodeOptions { RouterId = Convert.ToHexString(candidate.RouterOwnerId.Span).ToLowerInvariant() }, config);
            Capability = new(config, bindings);
            Runtime = Compose();
        }
        private PrivacyRoutingRuntime Compose()
        {
            var keys = new OnionKeyAgreementAuthority(vault);
            return new(config, peers, terminal, Capability, keys, new(replay),
                new PrivacyRoutingCodec(new(entropy), keys));
        }
        internal void RestartReplay() { replay.Dispose(); replay = new(replayPath, keyPath); Runtime = Compose(); }
        public void Dispose() { replay.Dispose(); entropy.Dispose(); vault.Dispose(); config.Dispose(); }
    }

    private sealed class SignedNetwork(DeepIdV2PublicationAuthorityFixture signed) : IDeepIdV2ReceiveNetworkSource
    {
        public ValueTask<VerifiedOnionNetworkContext> ReadCurrentAsync(ReadOnlyMemory<byte> owner,
            ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> nextKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = OnionPathCandidateSnapshotFactory.Create(signed.NetworkContext).Candidates.Single(node =>
                node.RouterOwnerId.Span.SequenceEqual(owner.Span));
            OnionLocalNodeKeyFactory.EnsureInstalledPublicKey(signed.NetworkContext, candidate.NodeId, key);
            return ValueTask.FromResult(signed.NetworkContext);
        }
    }

    internal sealed class Peers : IPrivacyPeerClient
    {
        internal Dictionary<string, Host> Hosts { get; } = new(StringComparer.Ordinal);
        internal int Calls { get; private set; }
        internal List<PrivacyRuntimeOutcome> Outcomes { get; } = [];
        public async Task<PrivacyForwardResult> ForwardAsync(VerifiedOnionNextHopTransport nextHop,
            VerifiedOnionNetworkContext network,
            ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
        {
            Calls++;
            var result = await Hosts[Convert.ToHexString(nextHop.NodeId.Span)].Runtime.ProcessAsync(frame, cancellationToken);
            Outcomes.Add(result.Outcome);
            return result.Outcome == PrivacyRuntimeOutcome.Completed
                ? new(result.OpaqueReply, PrivacyForwardFailure.None) : PrivacyForwardResult.Rejected;
        }
    }

    private sealed class UnavailableTerminal : INativeMailboxExitDispatcher
    {
        internal int Calls { get; private set; }
        internal byte[]? Request { get; private set; }
        public Task<NativeMailboxDispatchResult> DispatchAsync(VerifiedCanonicalOnionRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++; Request = request.CanonicalBytes.ToArray();
            return Task.FromResult(new NativeMailboxDispatchResult(StatusCodes.Status503ServiceUnavailable, ReadOnlyMemory<byte>.Empty));
        }
    }

}
