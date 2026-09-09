using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.GroupV1;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rebex.Security.Cryptography;
using XNode.Core;
using XNode.Core.GroupControl;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class GroupControlServiceRuntimeTests : IDisposable
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-09-08T08:00:00Z");
    private readonly PairFixture pair = new(Now);

    [Fact]
    public async Task UatWriteFetchExactReplayAndRestartReturnCanonicalGss1()
    {
        pair.OpenStores();
        var write = Request.Write("restart", 1, new byte[32], Now);
        var dispatcher = pair.Dispatcher();

        var committed = await dispatcher.DispatchAsync(write, default);
        var replay = await dispatcher.DispatchAsync(write, default);

        AssertStatus(committed, 1, operation: 1);
        AssertStatus(replay, 2, operation: 1);
        Assert.Equal(replay.CanonicalGss1.ToArray(),
            (await pair.Dispatcher().DispatchAsync(write, default)).CanonicalGss1.ToArray());

        pair.CloseStores();
        pair.OpenStores();
        AssertStatus(
            await pair.Dispatcher().DispatchAsync(write, default),
            2,
            operation: 1);
        var fetch = Request.Fetch("restart-fetch", 0, Now, paddingClass: 2);
        var fetched = await pair.Dispatcher().DispatchAsync(fetch, default);

        var record = AssertStatus(fetched, 3, operation: 2);
        Assert.Equal(2, fetched.ResponsePaddingClass);
        Assert.Equal((ushort)1, U16(record.Field(17).Span));
        Assert.Equal(Request.SealedBody("restart"), DecodeFirstEvent(record.Field(18).Span));
    }

    [Fact]
    public async Task LostReplicaAcknowledgementIsOutcomeUnknownAndRetryReconcilesExactly()
    {
        pair.OpenStores();
        var second = new LoseAcknowledgementReplica(pair.SecondReplica)
        {
            LoseAfterMutation = true
        };
        var source = new FixedGroupControlReplicaBindingSource(
            pair.FirstBinding,
            new GroupControlReplicaBinding(second, pair.SecondReceiptAuthority));
        var dispatcher = pair.Dispatcher(source: source);
        var write = Request.Write("unknown", 1, new byte[32], Now);

        AssertStatus(await dispatcher.DispatchAsync(write, default), 9, operation: 1);

        second.LoseAfterMutation = false;
        AssertStatus(await dispatcher.DispatchAsync(write, default), 2, operation: 1);
        AssertStatus(
            await pair.Dispatcher().DispatchAsync(
                Request.Fetch("unknown-fetch", 0, Now, 2), default),
            3,
            operation: 2);
    }

    [Fact]
    public async Task StaleForkAndInvalidAuthorityNeverCreateAnUnauthorizedCommit()
    {
        pair.OpenStores();
        var first = Request.Write("authority", 1, new byte[32], Now);
        var rejectedAuthority = new TestAuthoritySource(
            pair.ReplicaIds,
            Now,
            mismatchPlacement: true);

        var unavailable = await new GroupControlOnionTerminalAdapter(
                pair.Dispatcher(rejectedAuthority))
            .DispatchAsync(first, default);
        Assert.Equal(503, unavailable.StatusCode);
        Assert.Equal(
            NativeMailboxDispatchCertainty.RejectedBeforeForward,
            unavailable.Certainty);

        var dispatcher = pair.Dispatcher();
        AssertStatus(await dispatcher.DispatchAsync(first, default), 1, operation: 1);

        var firstHash = SHA256.HashData(Request.SealedBody("authority"));
        var stale = Request.Write("stale", 3, firstHash, Now);
        var staleResult = AssertStatus(
            await dispatcher.DispatchAsync(stale, default), 7, operation: 1);
        Assert.Equal((ulong)1, U64(staleResult.Field(17).Span));
        Assert.Equal(firstHash, staleResult.Field(18).ToArray());

        var fork = Request.Write("fork", 1, new byte[32], Now);
        AssertStatus(await dispatcher.DispatchAsync(fork, default), 8, operation: 1);
        AssertStatus(
            await dispatcher.DispatchAsync(
                Request.Fetch("fork-fetch", 0, Now, 2), default),
            8,
            operation: 2);
    }

    [Fact]
    public async Task CorruptReplicaStateIsQuarantinedAndRuntimeCannotSilentlyRestart()
    {
        pair.OpenStores();
        var write = Request.Write("corrupt", 1, new byte[32], Now);
        AssertStatus(
            await pair.Dispatcher().DispatchAsync(write, default),
            1,
            operation: 1);
        pair.CloseStores();

        var bytes = File.ReadAllBytes(pair.FirstStatePath);
        bytes[^1] ^= 0x80;
        File.WriteAllBytes(pair.FirstStatePath, bytes);

        Assert.Throws<GroupControlStoreCorruptException>(pair.OpenStores);
        Assert.False(File.Exists(pair.FirstStatePath));
        Assert.Single(Directory.GetFiles(pair.Root, "*.quarantine.*"));
    }

    [Fact]
    public async Task ProductionCompositionIsDormantEvenWhenConfigurationRequestsActivation()
    {
        var services = new ServiceCollection();
        var plan = services.AddGroupControlServiceBoundary(new GroupControlServiceOptions
        {
            RuntimeActivation = true,
            MapReplicaEndpoint = true
        });
        using var provider = services.BuildServiceProvider();

        Assert.False(plan.RuntimeActivation);
        Assert.False(plan.MapReplicaEndpoint);
        var result = await provider.GetRequiredService<GroupControlOnionTerminalAdapter>()
            .DispatchAsync(Request.Write("dormant", 1, new byte[32], Now), default);
        Assert.Equal(503, result.StatusCode);
        Assert.Equal(NativeMailboxDispatchCertainty.RejectedBeforeForward, result.Certainty);
    }

    [Fact]
    public async Task ExplicitUatInjectionActivatesOnlyTheOnionTerminalBoundary()
    {
        pair.OpenStores();
        var services = new ServiceCollection();
        services.AddSingleton<IClock>(pair.Clock);
        var plan = services.AddUatGroupControlServiceBoundary(
            new GroupControlServiceOptions
            {
                RuntimeActivation = true,
                MapReplicaEndpoint = false
            },
            pair.Authority,
            pair.Source);
        using var provider = services.BuildServiceProvider();

        Assert.True(plan.RuntimeActivation);
        Assert.False(plan.MapReplicaEndpoint);
        var result = await provider.GetRequiredService<GroupControlOnionTerminalAdapter>()
            .DispatchAsync(Request.Write("uat", 1, new byte[32], Now), default);
        Assert.Equal(200, result.StatusCode);
        AssertStatus(
            new GroupControlTerminalDispatchResult(result.CanonicalBody, 0),
            1,
            operation: 1);
    }

    [Fact]
    public void ExplicitProductionCompositionResolvesTerminalAndReplicaHttpRuntime()
    {
        var localIdentity = Identity(0x71);
        var remoteIdentity = Identity(0x72);
        var node = new RouterNodeOptions
        {
            RouterId = localIdentity.Id.Value,
            Ed25519PrivateKey = localIdentity.SeedHex,
            DataDirectory = Path.Combine(pair.Root, "production-composition")
        };
        var authority = new TestAuthoritySource(
            [localIdentity.Id.ToBytes(), remoteIdentity.Id.ToBytes()],
            Now);
        var privacy = new PrivacyRoutingConfiguration(
            true,
            Hash("privacy-private"),
            Hash("privacy-public"),
            new Uri("https://local.example/api/peer/privacy/v1/frame"),
            new Dictionary<RouterId, PrivacyPeer>
            {
                [remoteIdentity.Id] = new PrivacyPeer(
                    remoteIdentity.Id,
                    new Uri("https://remote.example/api/peer/privacy/v1/frame"),
                    Hash("tls-spki"),
                    Hash("kem-key"),
                    false)
            },
            64,
            600,
            TimeSpan.FromSeconds(30),
            4_096,
            100_000,
            TimeSpan.FromMinutes(5));
        var services = new ServiceCollection();
        services.AddSingleton(node);
        services.AddSingleton<IClock>(pair.Clock);
        services.AddSingleton<IMailboxStorageSecurity>(new TestStorageSecurity());
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        services.AddSingleton(privacy);

        var plan = services.AddProductionGroupControlServiceBoundary(
            new GroupControlServiceOptions
            {
                RuntimeActivation = true,
                MapReplicaEndpoint = true
            },
            authority);
        using var provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        Assert.True(plan.RuntimeActivation);
        Assert.True(plan.MapReplicaEndpoint);
        Assert.IsType<ProductionGroupControlTerminalDispatcher>(
            provider.GetRequiredService<IGroupControlTerminalDispatcher>());
        Assert.NotNull(provider.GetRequiredService<GroupControlReplicaRequestReceiver>());
        Assert.NotNull(provider.GetRequiredService<GroupControlReplicaReplayGuard>());
    }

    [Fact]
    public async Task MalformedCanonicalRequestIsRejectedBeforeAuthorityAndMutation()
    {
        pair.OpenStores();
        var authority = new TestAuthoritySource(pair.ReplicaIds, Now);
        var adapter = new GroupControlOnionTerminalAdapter(
            pair.Dispatcher(authority));
        var exact = Request.Write("malformed", 1, new byte[32], Now);
        var withTrailingByte = exact.Append((byte)0).ToArray();

        var result = await adapter.DispatchAsync(withTrailingByte, default);

        Assert.Equal(400, result.StatusCode);
        Assert.Equal(0, authority.Calls);
        AssertStatus(
            await pair.Dispatcher().DispatchAsync(exact, default),
            1,
            operation: 1);
    }

    [Fact]
    public void ReplicaAuthenticationAndReplayAreExactAndBounded()
    {
        var sender = Identity(0x51);
        var recipient = Identity(0x52);
        var exactRequest = Request.Fetch("replica-auth", 0, Now, 2);
        var command = new GroupControlReplicaRpcCommand(
            GroupControlOperation.Fetch,
            Hash("correlation"),
            exactRequest);
        var body = GroupControlReplicaWireCodec.Encode(command);
        var headers = GroupControlReplicaPeerAuthenticator.SignRequest(
            sender.Id,
            recipient.Id,
            sender.SeedHex,
            command.CorrelationId.Span,
            body,
            Now);

        Assert.True(GroupControlReplicaPeerAuthenticator.VerifyRequest(
            headers,
            recipient.Id,
            command.CorrelationId.Span,
            body,
            Now,
            out var authenticated,
            out var nonce));
        var guard = new GroupControlReplicaReplayGuard(new GroupControlServiceOptions());
        Assert.True(guard.TryAccept(authenticated, nonce, headers.TimestampUnixMilliseconds, Now));
        Assert.False(guard.TryAccept(authenticated, nonce, headers.TimestampUnixMilliseconds, Now));

        body[^1] ^= 1;
        Assert.False(GroupControlReplicaPeerAuthenticator.VerifyRequest(
            headers,
            recipient.Id,
            command.CorrelationId.Span,
            body,
            Now,
            out _,
            out _));
        Assert.ThrowsAny<Exception>(() =>
            GroupControlReplicaWireCodec.DecodeRequest(body.AsSpan(0, body.Length - 1)));
    }

    [Fact]
    public async Task HttpReplicaEndpointAcceptsOneAuthenticatedPeerAttemptAndRejectsReplay()
    {
        var sender = Identity(0x61);
        var recipient = Identity(0x62);
        var node = new RouterNodeOptions
        {
            RouterId = recipient.Id.Value,
            Ed25519PrivateKey = recipient.SeedHex,
            DataDirectory = Path.Combine(pair.Root, "http-local")
        };
        using var local = new GroupControlLocalReplicaRuntime(
            node,
            pair.Clock,
            new TestStorageSecurity(),
            new MailboxDurabilityBarrier());
        var authority = new TestAuthoritySource(
            [sender.Id.ToBytes(), recipient.Id.ToBytes()],
            Now);
        var receiver = new GroupControlReplicaRequestReceiver(authority, local, pair.Clock);
        var options = new GroupControlServiceOptions
        {
            RuntimeActivation = true,
            MapReplicaEndpoint = true
        };
        var plan = new GroupControlServiceHostCompositionPlan(true, true);
        var guard = new GroupControlReplicaReplayGuard(options);
        var command = new GroupControlReplicaRpcCommand(
            GroupControlOperation.Write,
            Hash("http-correlation"),
            Request.Write("http", 1, new byte[32], Now));
        var body = GroupControlReplicaWireCodec.Encode(command);
        var authentication = GroupControlReplicaPeerAuthenticator.SignRequest(
            sender.Id,
            recipient.Id,
            sender.SeedHex,
            command.CorrelationId.Span,
            body,
            Now);

        var accepted = HttpContext(body, authentication);
        var acceptedResult = await GroupControlReplicaHttpEndpoint.HandleAsync(
            accepted,
            plan,
            options,
            guard,
            receiver,
            node,
            pair.Clock,
            9443,
            default);
        await acceptedResult.ExecuteAsync(accepted);

        Assert.Equal(200, accepted.Response.StatusCode);
        var exactResponse = ((MemoryStream)accepted.Response.Body).ToArray();
        var decoded = GroupControlReplicaWireCodec.DecodeResponse(exactResponse);
        Assert.Equal(GroupControlMutationDisposition.Committed,
            GroupControlReplicaWireCodec.DecodeMutation(decoded.Payload.Span).Mutation.Disposition);
        Assert.Equal("no-store", accepted.Response.Headers.CacheControl);

        var replay = HttpContext(body, authentication);
        var replayResult = await GroupControlReplicaHttpEndpoint.HandleAsync(
            replay,
            plan,
            options,
            guard,
            receiver,
            node,
            pair.Clock,
            9443,
            default);
        await replayResult.ExecuteAsync(replay);
        Assert.Equal(404, replay.Response.StatusCode);
    }

    public void Dispose() => pair.Dispose();

    private static GroupControlResultRecord AssertStatus(
        GroupControlTerminalDispatchResult result,
        ushort status,
        byte operation)
    {
        var decoded = Assert.IsType<GroupControlResultRecord>(
            GroupCodec.Decode(result.CanonicalGss1.Span));
        Assert.Equal(result.CanonicalGss1.ToArray(), decoded.CanonicalBytes.ToArray());
        Assert.Equal(status, U16(decoded.Field(4).Span));
        Assert.Equal(operation, Assert.Single(decoded.Field(16).ToArray()));
        return decoded;
    }

    private static byte[] DecodeFirstEvent(ReadOnlySpan<byte> events)
    {
        Assert.True(events.Length >= 84);
        var length = BinaryPrimitives.ReadUInt32BigEndian(events.Slice(80, 4));
        Assert.Equal(events.Length, checked(84 + (int)length));
        return events.Slice(84, checked((int)length)).ToArray();
    }

    private static ushort U16(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt16BigEndian(value);

    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);

    private static byte[] Hash(string value) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(value));

    private static IdentityFixture Identity(byte fill)
    {
        var seed = Enumerable.Repeat(fill, 32).ToArray();
        var signer = new Ed25519();
        signer.FromSeed(seed);
        return new(
            RouterId.FromBytes(signer.GetPublicKey()),
            Convert.ToHexStringLower(seed));
    }

    private sealed record IdentityFixture(RouterId Id, string SeedHex);

    private static DefaultHttpContext HttpContext(
        byte[] body,
        GroupControlReplicaAuthenticationHeaders authentication)
    {
        var services = new ServiceCollection()
            .AddLogging(builder => builder.SetMinimumLevel(LogLevel.None))
            .BuildServiceProvider();
        var context = new DefaultHttpContext
        {
            RequestServices = services
        };
        context.Connection.LocalPort = 9443;
        context.Request.Scheme = Uri.UriSchemeHttps;
        context.Request.Method = HttpMethods.Post;
        context.Request.Protocol = "HTTP/2";
        context.Request.ContentType = GroupControlReplicaHttpContract.MediaType;
        context.Request.ContentLength = body.Length;
        context.Request.Body = new MemoryStream(body);
        context.Response.Body = new MemoryStream();
        context.Request.Headers[GroupControlReplicaPeerAuthenticator.SenderHeader] =
            authentication.SenderReplicaId;
        context.Request.Headers[GroupControlReplicaPeerAuthenticator.RecipientHeader] =
            authentication.RecipientReplicaId;
        context.Request.Headers[GroupControlReplicaPeerAuthenticator.TimestampHeader] =
            authentication.TimestampUnixMilliseconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
        context.Request.Headers[GroupControlReplicaPeerAuthenticator.NonceHeader] =
            authentication.Nonce;
        context.Request.Headers[GroupControlReplicaPeerAuthenticator.CorrelationHeader] =
            authentication.Correlation;
        context.Request.Headers[GroupControlReplicaPeerAuthenticator.SignatureHeader] =
            authentication.Signature;
        return context;
    }

    private sealed class PairFixture : IDisposable
    {
        private readonly LocalGroupControlReplicaReceiptAuthority firstAuthority;
        private readonly LocalGroupControlReplicaReceiptAuthority secondAuthority;
        private GroupControlOpaqueStore? firstStore;
        private GroupControlOpaqueStore? secondStore;

        internal PairFixture(DateTimeOffset now)
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "xnode-group-control-runtime-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
            Clock = new FixedClock(now);
            firstAuthority = new LocalGroupControlReplicaReceiptAuthority(
                Enumerable.Repeat((byte)0x41, 32).ToArray());
            secondAuthority = new LocalGroupControlReplicaReceiptAuthority(
                Enumerable.Repeat((byte)0x42, 32).ToArray());
            ReplicaIds =
                [firstAuthority.ReplicaId.ToArray(), secondAuthority.ReplicaId.ToArray()];
            Authority = new TestAuthoritySource(ReplicaIds, now);
        }

        internal string Root { get; }
        internal string FirstStatePath => Path.Combine(Root, "first.state");
        internal FixedClock Clock { get; }
        internal IReadOnlyList<ReadOnlyMemory<byte>> ReplicaIds { get; }
        internal TestAuthoritySource Authority { get; }
        internal IGroupControlReplica FirstReplica => FirstBinding.Replica;
        internal IGroupControlReplica SecondReplica => SecondBinding.Replica;
        internal IGroupControlReplicaReceiptAuthority SecondReceiptAuthority => secondAuthority;
        internal GroupControlReplicaBinding FirstBinding => new(
            new GroupControlStoreReplica(firstAuthority.ReplicaId.Span, firstStore!),
            firstAuthority);
        internal GroupControlReplicaBinding SecondBinding => new(
            new GroupControlStoreReplica(secondAuthority.ReplicaId.Span, secondStore!),
            secondAuthority);
        internal FixedGroupControlReplicaBindingSource Source => new(
            FirstBinding,
            SecondBinding);

        internal void OpenStores()
        {
            CloseStores();
            firstStore = Open(FirstStatePath);
            try
            {
                secondStore = Open(Path.Combine(Root, "second.state"));
            }
            catch
            {
                firstStore.Dispose();
                firstStore = null;
                throw;
            }
        }

        internal void CloseStores()
        {
            firstStore?.Dispose();
            secondStore?.Dispose();
            firstStore = null;
            secondStore = null;
        }

        internal ProductionGroupControlTerminalDispatcher Dispatcher(
            IGroupControlAuthoritySource? authority = null,
            IGroupControlReplicaBindingSource? source = null) => new(
                authority ?? Authority,
                source ?? Source,
                Clock,
                new GroupControlServiceOptions
                {
                    RuntimeActivation = true,
                    MapReplicaEndpoint = false
                });

        public void Dispose()
        {
            CloseStores();
            firstAuthority.Dispose();
            secondAuthority.Dispose();
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }

        private GroupControlOpaqueStore Open(string path) => new(
            path,
            clock: Clock,
            storageSecurity: new TestStorageSecurity(),
            durability: new MailboxDurabilityBarrier());
    }

    private sealed class TestAuthoritySource : IGroupControlAuthoritySource
    {
        private readonly IReadOnlyList<ReadOnlyMemory<byte>> replicas;
        private readonly DateTimeOffset now;
        private readonly bool mismatchPlacement;

        internal TestAuthoritySource(
            IReadOnlyList<ReadOnlyMemory<byte>> replicas,
            DateTimeOffset now,
            bool mismatchPlacement = false)
        {
            this.replicas = replicas;
            this.now = now;
            this.mismatchPlacement = mismatchPlacement;
        }

        internal int Calls { get; private set; }

        public ValueTask<VerifiedGroupControlRequestAuthority> AuthorizeAsync(
            GroupControlOperation operation,
            GroupRecord exactRequest,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            var placement = mismatchPlacement
                ? Hash("wrong-current-placement")
                : exactRequest.Field(4).ToArray();
            return ValueTask.FromResult(new VerifiedGroupControlRequestAuthority(
                operation,
                exactRequest.Field(1).Span,
                exactRequest.Field(3).Span,
                placement,
                exactRequest.Field(16).Span,
                exactRequest.Field(17).Span,
                Hash("verified-route-closure"),
                checked((ulong)now.AddMinutes(10).ToUnixTimeSeconds()),
                replicas));
        }
    }

    private sealed class LoseAcknowledgementReplica(IGroupControlReplica inner)
        : IGroupControlReplica
    {
        internal bool LoseAfterMutation { get; set; }
        public ReadOnlyMemory<byte> ReplicaId => inner.ReplicaId;

        public async ValueTask<GroupControlMutationResult> WriteAsync(
            OpaqueGroupControlWriteRequest request,
            CancellationToken cancellationToken)
        {
            var result = await inner.WriteAsync(request, cancellationToken);
            if (LoseAfterMutation)
            {
                throw new IOException("Injected loss after durable mutation.");
            }
            return result;
        }

        public ValueTask<GroupControlReadResult> FetchAsync(
            OpaqueGroupControlFetchRequest request,
            CancellationToken cancellationToken) =>
            inner.FetchAsync(request, cancellationToken);
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }

    private static class Request
    {
        private static readonly ushort[] WriteTags = [1, 2, 3, 4, 5, 6, 16, 17, 18, 19, 20, 21, 22];
        private static readonly ushort[] FetchTags = [1, 2, 3, 4, 5, 6, 16, 17, 18, 19, 20];
        private static readonly byte[] Network = Hash("network")[..16];
        private static readonly byte[] View = Hash("view");
        private static readonly byte[] Placement = Hash("placement");
        private static readonly byte[] Capability = Hash("service-capability");
        private static readonly byte[] Gsr = Hash("exact-gsr1");

        internal static byte[] Write(
            string operation,
            ulong sequence,
            byte[] predecessor,
            DateTimeOffset now)
        {
            var sealedBody = SealedBody(operation);
            return Encode("GSW1", WriteTags,
            [
                Network,
                Hash("operation/" + operation),
                View,
                Placement,
                Be(checked((ulong)now.AddSeconds(-1).ToUnixTimeSeconds())),
                Be(checked((ulong)now.AddMinutes(5).ToUnixTimeSeconds())),
                Capability,
                Gsr,
                Be(sequence),
                predecessor,
                SHA256.HashData(sealedBody),
                Lp32(sealedBody),
                Be(checked((ulong)now.AddDays(1).ToUnixTimeSeconds()))
            ]);
        }

        internal static byte[] Fetch(
            string operation,
            ulong after,
            DateTimeOffset now,
            ushort paddingClass) => Encode("GSQ1", FetchTags,
            [
                Network,
                Hash("operation/" + operation),
                View,
                Placement,
                Be(checked((ulong)now.AddSeconds(-1).ToUnixTimeSeconds())),
                Be(checked((ulong)now.AddMinutes(5).ToUnixTimeSeconds())),
                Capability,
                Gsr,
                Be(after),
                Be((ushort)64),
                Be(paddingClass)
            ]);

        internal static byte[] SealedBody(string operation)
        {
            var seed = Hash("sealed/" + operation);
            return seed.Concat(seed).ToArray();
        }

        private static byte[] Encode(
            string magic,
            IReadOnlyList<ushort> tags,
            IReadOnlyList<byte[]> fields)
        {
            var output = new byte[checked(12 + fields.Sum(static value => 8 + value.Length))];
            Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), 0x0201);
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
            var offset = 12;
            for (var index = 0; index < fields.Count; index++)
            {
                BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), tags[index]);
                BinaryPrimitives.WriteUInt32BigEndian(
                    output.AsSpan(offset + 4),
                    checked((uint)fields[index].Length));
                offset += 8;
                fields[index].CopyTo(output, offset);
                offset += fields[index].Length;
            }
            Assert.Equal(output, GroupCodec.Decode(output).CanonicalBytes.ToArray());
            return output;
        }

        private static byte[] Lp32(byte[] value)
        {
            var output = new byte[4 + value.Length];
            BinaryPrimitives.WriteUInt32BigEndian(output, checked((uint)value.Length));
            value.CopyTo(output, 4);
            return output;
        }

        private static byte[] Be(ushort value)
        {
            var output = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(output, value);
            return output;
        }

        private static byte[] Be(ulong value)
        {
            var output = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(output, value);
            return output;
        }
    }
}
