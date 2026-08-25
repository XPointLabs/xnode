using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;
using System.Net;
using XNode;
using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed class PrivacyRoutingRuntimeTests
{
    [Fact]
    public async Task Relay_UsesOnlyPinnedRouterIdAndForwardsOpaqueInnerFrame()
    {
        using var first = PublicKeyBox.GenerateKeyPair();
        using var second = PublicKeyBox.GenerateKeyPair();
        using var exit = PublicKeyBox.GenerateKeyPair();
        var ids = new[] { Id(1), Id(2), Id(3) };
        using var request = PrivacyRoutingRequestBuilder.Build(
            Route(ids, first.PublicKey, second.PublicKey, exit.PublicKey),
            PrivacyRoutingOperation.Store,
            Bytes(41),
            Bytes(51),
            [7, 8, 9],
            256);
        var forwardedReply = Enumerable.Repeat((byte)0x6a, 256).ToArray();
        var peerClient = new RecordingPeerClient(forwardedReply);
        using var configuration = Configuration(
            first.PrivateKey,
            first.PublicKey,
            ids[1]);
        var runtime = Runtime(
            configuration,
            ids[0],
            peerClient,
            new RecordingMailboxDispatcher());

        var result = await runtime.ProcessAsync(request.Frame, default);

        Assert.Equal(PrivacyRuntimeOutcome.Completed, result.Outcome);
        Assert.Equal(forwardedReply, result.OpaqueReply);
        Assert.Equal(ids[1], peerClient.Peer!.RouterId);
        var openedSecond = PrivacyRoutingRequestCodec.Open(
            peerClient.Frame.Span,
            second.PrivateKey);
        Assert.IsType<PrivacyRoutingRelayLayer>(openedSecond);
    }

    [Fact]
    public async Task Relay_RejectsNextRouterAbsentFromPinnedInventoryBeforeForward()
    {
        using var first = PublicKeyBox.GenerateKeyPair();
        using var second = PublicKeyBox.GenerateKeyPair();
        using var exit = PublicKeyBox.GenerateKeyPair();
        var ids = new[] { Id(1), Id(2), Id(3) };
        using var request = PrivacyRoutingRequestBuilder.Build(
            Route(ids, first.PublicKey, second.PublicKey, exit.PublicKey),
            PrivacyRoutingOperation.Store,
            Bytes(41),
            Bytes(51),
            [7, 8, 9],
            256);
        var peerClient = new RecordingPeerClient(new byte[256]);
        using var configuration = Configuration(
            first.PrivateKey,
            first.PublicKey,
            Id(99));
        var runtime = Runtime(
            configuration,
            ids[0],
            peerClient,
            new RecordingMailboxDispatcher());

        var result = await runtime.ProcessAsync(request.Frame, default);

        Assert.Equal(
            PrivacyRuntimeOutcome.UnauthorizedNextHopBeforeForward,
            result.Outcome);
        Assert.Null(peerClient.Peer);
    }

    [Fact]
    public async Task Exit_SealsCanonicalDpr1SuccessToClientReplyKey()
    {
        using var first = PublicKeyBox.GenerateKeyPair();
        using var second = PublicKeyBox.GenerateKeyPair();
        using var exit = PublicKeyBox.GenerateKeyPair();
        var ids = new[] { Id(1), Id(2), Id(3) };
        var mau2 = new byte[] { 7, 8, 9 };
        using var request = PrivacyRoutingRequestBuilder.Build(
            Route(ids, first.PublicKey, second.PublicKey, exit.PublicKey),
            PrivacyRoutingOperation.Store,
            Bytes(41),
            Bytes(51),
            mau2,
            256);
        var firstLayer = Assert.IsType<PrivacyRoutingRelayLayer>(
            PrivacyRoutingRequestCodec.Open(request.Frame.Span, first.PrivateKey));
        var secondLayer = Assert.IsType<PrivacyRoutingRelayLayer>(
            PrivacyRoutingRequestCodec.Open(firstLayer.InnerFrame.Span, second.PrivateKey));
        var mailbox = new RecordingMailboxDispatcher
        {
            Result = new NativeMailboxDispatchResult(200, new byte[] { 4, 5, 6 })
        };
        using var configuration = Configuration(
            exit.PrivateKey,
            exit.PublicKey,
            ids[0]);
        var runtime = Runtime(
            configuration,
            ids[2],
            new RecordingPeerClient(new byte[256]),
            mailbox);

        var result = await runtime.ProcessAsync(secondLayer.InnerFrame, default);

        Assert.Equal(PrivacyRuntimeOutcome.Completed, result.Outcome);
        Assert.Equal(mau2, mailbox.Payload);
        var opened = PrivacyRoutingResponseCodec.Open(
            result.OpaqueReply.Span,
            request.ReplyContext);
        var terminal = PrivacyRoutingResultCodec.Decode(opened.Payload.Span);
        Assert.Equal(PrivacyRoutingResultKind.Success, terminal.Kind);
        Assert.Equal(new byte[] { 4, 5, 6 }, terminal.Body);
    }

    [Fact]
    public void Options_RequireCanonicalIndependentKeyAndDevelopmentOnlyHttp()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "xnode-privacy-options-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var keyPath = Path.Combine(root, "x25519.key");
            File.WriteAllText(keyPath, new string('a', 64));
            var options = new PrivacyRoutingOptions
            {
                Enabled = true,
                X25519PrivateKeyPath = keyPath,
                PublicPeerBaseUrl = "http://10.0.0.10:8081/",
                AllowInsecureHttpPeerTransport = true,
                Peers =
                [
                    new PrivacyPeerOptions
                    {
                        RouterId = Id(2).Value,
                        BaseUrl = "http://10.0.0.11:8081/"
                    }
                ]
            };

            using var configuration = options.ValidateAndLoad(
                NodeOptions(),
                isDevelopment: true);

            Assert.Equal(
                ScalarMult.Base(Convert.FromHexString(new string('a', 64))),
                configuration.PublicKey);
            Assert.Throws<InvalidOperationException>(() =>
                options.ValidateAndLoad(
                    NodeOptions(),
                    isDevelopment: false));
            File.WriteAllText(keyPath, new string('A', 64));
            Assert.Throws<InvalidOperationException>(() =>
                options.ValidateAndLoad(
                    NodeOptions(),
                    isDevelopment: true));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void PeerAuthentication_BindsFrameRecipientAndCanonicalHeaders()
    {
        var seed = Enumerable.Range(1, 32).Select(static item => (byte)item).ToArray();
        var signer = new Rebex.Security.Cryptography.Ed25519();
        signer.FromSeed(seed);
        var sender = RouterId.FromBytes(signer.GetPublicKey());
        var recipient = Id(99);
        var frame = Enumerable.Repeat((byte)0x51, 256).ToArray();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = PrivacyPeerAuthenticator.Sign(
            sender,
            recipient,
            Convert.ToHexString(seed).ToLowerInvariant(),
            frame,
            now);

        Assert.True(PrivacyPeerAuthenticator.Verify(
            headers,
            recipient,
            frame,
            now,
            out var verified,
            out _));
        Assert.Equal(sender, verified);
        Assert.False(PrivacyPeerAuthenticator.Verify(
            headers with { Signature = headers.Signature.ToUpperInvariant() },
            recipient,
            frame,
            now,
            out _,
            out _));
        frame[0] ^= 1;
        Assert.False(PrivacyPeerAuthenticator.Verify(
            headers,
            recipient,
            frame,
            now,
            out _,
            out _));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.20.30.40")]
    [InlineData("100.64.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("192.0.2.1")]
    [InlineData("::1")]
    [InlineData("fc00::1")]
    [InlineData("2001:db8::1")]
    public void PeerAddressGuard_BlocksNonPublicAndSpecialPurposeTargets(string value)
    {
        Assert.False(PeerNetworkAddressGuard.IsPubliclyRoutable(IPAddress.Parse(value)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("2606:4700:4700::1111")]
    public void PeerAddressGuard_AllowsGlobalTargets(string value)
    {
        Assert.True(PeerNetworkAddressGuard.IsPubliclyRoutable(IPAddress.Parse(value)));
    }

    private static PrivacyRoutingRuntime Runtime(
        PrivacyRoutingConfiguration configuration,
        RouterId localId,
        IPrivacyPeerClient peerClient,
        INativeMailboxExitDispatcher mailbox) => new(
            configuration,
            new PrivacyRoutingReplayGuard(configuration),
            peerClient,
            mailbox,
            new RouterNodeOptions { RouterId = localId.Value },
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)));

    private static PrivacyRoutingConfiguration Configuration(
        byte[] privateKey,
        byte[] publicKey,
        RouterId peerId) => new(
            true,
            privateKey.ToArray(),
            publicKey.ToArray(),
            new Uri("https://node.example/"),
            new Dictionary<RouterId, PrivacyPeer>
            {
                [peerId] = new PrivacyPeer(
                    peerId,
                    new Uri("https://peer.example/api/peer/privacy/v1/frame"),
                    Bytes(61),
                    Bytes(71),
                    false)
            },
            8,
            60,
            TimeSpan.FromSeconds(10),
            256,
            1000,
            TimeSpan.FromMinutes(5));

    private static IReadOnlyList<PrivacyRoutingHop> Route(
        RouterId[] ids,
        byte[] first,
        byte[] second,
        byte[] exit) =>
        [
            new PrivacyRoutingHop(ids[0].ToBytes(), first),
            new PrivacyRoutingHop(ids[1].ToBytes(), second),
            new PrivacyRoutingHop(ids[2].ToBytes(), exit)
        ];

    private static RouterId Id(byte value) => RouterId.FromBytes(Bytes(value));

    private static RouterNodeOptions NodeOptions() => new()
    {
        RouterId = Id(1).Value,
        Ed25519PrivateKey = new string('b', 64),
        IsRelay = true
    };

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();

    private sealed class RecordingPeerClient(byte[] reply) : IPrivacyPeerClient
    {
        public PrivacyPeer? Peer { get; private set; }
        public ReadOnlyMemory<byte> Frame { get; private set; }

        public Task<PrivacyForwardResult> ForwardAsync(
            PrivacyPeer peer,
            ReadOnlyMemory<byte> innerFrame,
            CancellationToken cancellationToken)
        {
            Peer = peer;
            Frame = innerFrame;
            return Task.FromResult(new PrivacyForwardResult(
                reply,
                PrivacyForwardFailure.None));
        }
    }

    private sealed class RecordingMailboxDispatcher : INativeMailboxExitDispatcher
    {
        public NativeMailboxDispatchResult Result { get; init; } =
            new(503, ReadOnlyMemory<byte>.Empty);
        public ReadOnlyMemory<byte> Payload { get; private set; }

        public Task<NativeMailboxDispatchResult> DispatchAsync(
            PrivacyRoutingOperation privacyOperation,
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken)
        {
            Payload = canonicalMau2;
            return Task.FromResult(Result);
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow { get; } = now;
    }
}
