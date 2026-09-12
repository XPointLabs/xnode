using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class HttpsContactAuthorityArtifactPackageSourceTests
{
    private static readonly byte[] NetworkId = Bytes(16, 0x11);
    private static readonly byte[] GenesisHash = Bytes(32, 0x22);
    private static readonly byte[] LeafKey = Bytes(32, 0x33);
    private static readonly byte[] Nonce = Bytes(32, 0x44);
    private static readonly byte[] BootId = Bytes(16, 0x55);

    [Fact]
    public async Task ExactCdq1IsPostedAndBoundedCdr1IsDecodedWithoutTransportTrust()
    {
        byte[]? observed = null;
        var handler = new DelegateHandler(async request =>
        {
            observed = await request.Content!.ReadAsByteArrayAsync();
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal(
                "https://registry.example/api/v1/directory/contact-resolve-packages",
                request.RequestUri!.AbsoluteUri);
            Assert.True(request.Headers.CacheControl!.NoStore);
            Assert.Equal(ContactAuthorityDirectoryCodec.RequestMediaType,
                request.Content.Headers.ContentType!.MediaType);
            Assert.Equal(ContactAuthorityDirectoryCodec.ResponseMediaType,
                Assert.Single(request.Headers.Accept).MediaType);
            return Response(request, EncodeResponse(observed));
        });
        var source = Source(handler);

        var package = await source.FetchAsync(Request(), default);

        Assert.NotNull(package);
        Assert.NotNull(observed);
        Assert.Equal(84, observed.Length);
        Assert.Equal("CDQ1", System.Text.Encoding.ASCII.GetString(observed, 0, 4));
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(observed.AsSpan(4, 2)));
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(observed.AsSpan(6, 2)));
        Assert.Equal((uint)84, BinaryPrimitives.ReadUInt32BigEndian(observed.AsSpan(8, 4)));
        Assert.Equal(NetworkId, observed.AsSpan(12, 16).ToArray());
        Assert.Equal(Nonce, observed.AsSpan(28, 32).ToArray());
        Assert.Equal(BootId, observed.AsSpan(60, 16).ToArray());
        Assert.Equal((ulong)123, BinaryPrimitives.ReadUInt64BigEndian(observed.AsSpan(76, 8)));
        Assert.Equal(new byte[] { 0xa1 }, package.ExactXna1AuthorityChain[0].ToArray());
        Assert.Equal(new byte[] { 0xaa }, package.ExactOrderedPmt2Chain[0].ToArray());
    }

    [Fact]
    public async Task RestartRequestCarriesExactEmptyGenesisDirectoryFloor()
    {
        byte[]? observed = null;
        var directoryHash = Bytes(32, 0x61);
        var handler = new DelegateHandler(async request =>
        {
            observed = await request.Content!.ReadAsByteArrayAsync();
            return Response(request, EncodeResponse(observed));
        });
        var source = Source(handler);
        var request = new ContactAuthorityArtifactRequest(
            Nonce,
            BootId,
            123,
            LeafKey,
            directoryTreeSize: 0,
            directoryHash);

        _ = await source.FetchAsync(request, default);

        Assert.NotNull(observed);
        Assert.Equal(124, observed.Length);
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(observed.AsSpan(6, 2)));
        Assert.Equal((uint)124, BinaryPrimitives.ReadUInt32BigEndian(observed.AsSpan(8, 4)));
        Assert.Equal((ulong)0, BinaryPrimitives.ReadUInt64BigEndian(observed.AsSpan(84, 8)));
        Assert.Equal(directoryHash, observed.AsSpan(92, 32).ToArray());
    }

    [Theory]
    [InlineData("http://registry.example")]
    [InlineData("https://user@registry.example")]
    [InlineData("https://registry.example/path")]
    [InlineData("https://registry.example?query=1")]
    [InlineData("https://registry.example/#fragment")]
    [InlineData("https://registry.example/%2e%2e/")]
    [InlineData("https://registry.example\\evil")]
    [InlineData(" https://registry.example")]
    public void HostileOrNonOriginRegistryAddressIsRejected(string origin)
    {
        Assert.Throws<ArgumentException>(() => Options(origin));
    }

    [Fact]
    public async Task RedirectOrChangedFinalEndpointIsRejected()
    {
        var handler = new DelegateHandler(async request =>
        {
            var cdq = await request.Content!.ReadAsByteArrayAsync();
            var response = Response(request, EncodeResponse(cdq));
            response.RequestMessage = new HttpRequestMessage(
                HttpMethod.Post,
                "https://other.example/api/v1/directory/contact-resolve-packages");
            return response;
        });

        var failure = await Assert.ThrowsAsync<ContactAuthorityHttpException>(async () =>
            await Source(handler).FetchAsync(Request(), default));

        Assert.Equal("endpoint-changed", failure.Code);
    }

    [Fact]
    public async Task ResponseRequiresExactMediaTypeAndNoStore()
    {
        var handler = new DelegateHandler(async request =>
        {
            var cdq = await request.Content!.ReadAsByteArrayAsync();
            var response = Response(request, EncodeResponse(cdq));
            response.Headers.CacheControl = null;
            response.Content.Headers.ContentType!.CharSet = "utf-8";
            return response;
        });

        var failure = await Assert.ThrowsAsync<ContactAuthorityHttpException>(async () =>
            await Source(handler).FetchAsync(Request(), default));

        Assert.Equal("unexpected-media-type", failure.Code);
    }

    [Fact]
    public async Task MissingNoStoreIsRejectedBeforeBodyDecode()
    {
        var handler = new DelegateHandler(async request =>
        {
            var cdq = await request.Content!.ReadAsByteArrayAsync();
            var response = Response(request, EncodeResponse(cdq));
            response.Headers.CacheControl = new CacheControlHeaderValue { Private = true };
            return response;
        });

        var failure = await Assert.ThrowsAsync<ContactAuthorityHttpException>(async () =>
            await Source(handler).FetchAsync(Request(), default));

        Assert.Equal("no-store-required", failure.Code);
    }

    [Theory]
    [InlineData(-1, "trailing-response")]
    [InlineData(1, "truncated-response")]
    public async Task ContentLengthMustExactlyBoundTheResponse(int delta, string expectedCode)
    {
        var handler = new DelegateHandler(async request =>
        {
            var cdq = await request.Content!.ReadAsByteArrayAsync();
            var body = EncodeResponse(cdq);
            var response = Response(request, body, useStream: true);
            response.Content.Headers.ContentLength = body.Length + delta;
            return response;
        });

        var failure = await Assert.ThrowsAsync<ContactAuthorityHttpException>(async () =>
            await Source(handler).FetchAsync(Request(), default));

        Assert.Equal(expectedCode, failure.Code);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(84)]
    public async Task UnknownFlagsOrWrongRequestEchoAreRejected(int corruptOffset)
    {
        var handler = new DelegateHandler(async request =>
        {
            var cdq = await request.Content!.ReadAsByteArrayAsync();
            var body = EncodeResponse(cdq);
            body[corruptOffset] ^= 0x40;
            return Response(request, body);
        });

        var failure = await Assert.ThrowsAsync<ContactAuthorityHttpException>(async () =>
            await Source(handler).FetchAsync(Request(), default));

        Assert.Equal("invalid-cdr1", failure.Code);
    }

    [Fact]
    public async Task OversizedDeclaredResponseIsRejectedWithoutReadingBody()
    {
        var handler = new DelegateHandler(request =>
        {
            var response = Response(request, [1]);
            response.Content.Headers.ContentLength =
                ContactAuthorityDirectoryCodec.AbsoluteMaximumEnvelopeBytes + 1L;
            return Task.FromResult(response);
        });

        var failure = await Assert.ThrowsAsync<ContactAuthorityHttpException>(async () =>
            await Source(handler).FetchAsync(Request(), default));

        Assert.Equal("response-too-large", failure.Code);
    }

    [Fact]
    public void DefaultConfigurationIsDormantAndPartialConfigurationFailsClosed()
    {
        using var temporary = new TemporaryDirectory();
        var node = new RouterNodeOptions { DataDirectory = temporary.Path };
        var contact = new ContactServicePersistenceOptions();

        Assert.Null(new ProductionContactAuthorityOptions().ValidateAndLoad(node, contact));
        Assert.Throws<InvalidOperationException>(() =>
            new ProductionContactAuthorityOptions
            {
                RegistryOrigin = "https://registry.example"
            }.ValidateAndLoad(node, contact));
        Assert.Throws<InvalidOperationException>(() =>
            new ProductionContactAuthorityOptions { Enabled = true }
                .ValidateAndLoad(node, contact));
    }

    [Fact]
    public void FullExplicitConfigurationComposesHttpsSourceAndProductionBoundary()
    {
        using var temporary = new TemporaryDirectory();
        var node = Node(temporary.Path);
        var contact = ActiveContactOptions();
        var configuration = CompleteOptions().ValidateAndLoad(node, contact)!;
        var services = new ServiceCollection();
        services.AddSingleton(node);
        services.AddSingleton<IClock, SystemClock>();
        services.AddSingleton<IOnionMonotonicClock>(new TestMonotonicClock());
        services.AddSingleton<IMailboxStorageSecurity, NoOpStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, TestDurability>();

        var plan = services.AddProductionContactAuthorityBoundary(
            node,
            contact,
            configuration);
        using var provider = services.BuildServiceProvider();

        Assert.True(plan.RuntimeActivation);
        Assert.True(plan.MapReplicaEndpoint);
        Assert.IsType<HttpsContactAuthorityArtifactPackageSource>(
            provider.GetRequiredService<IContactAuthorityArtifactPackageSource>());
        Assert.IsType<ClosedVerifiedContactRouteClosureSource>(
            provider.GetRequiredService<IVerifiedContactRouteClosureSource>());
        Assert.Contains(services,
            descriptor => descriptor.ServiceType == typeof(IContactServiceOpaqueDispatcher)
                && descriptor.ImplementationFactory is not null);
    }

    [Fact]
    public async Task ProtectedAuthorityStateCanBeReadAfterProcessStyleRestart()
    {
        using var temporary = new TemporaryDirectory();
        var stateDirectory = System.IO.Path.Combine(temporary.Path, "contact-authority-v1");
        var keys = System.IO.Path.Combine(stateDirectory, "dataprotection-keys");
        var statePath = System.IO.Path.Combine(stateDirectory, "authority.state");
        Directory.CreateDirectory(stateDirectory);
        Directory.CreateDirectory(keys);
        var expected = State();

        var firstProvider = DataProtectionProvider.Create(
            new DirectoryInfo(keys),
            builder => builder.SetApplicationName("XPoint.XNode.ContactAuthority.v1"));
        var first = Store(statePath, temporary.Path, firstProvider);
        await first.CommitAsync(expected, default);

        var restartedProvider = DataProtectionProvider.Create(
            new DirectoryInfo(keys),
            builder => builder.SetApplicationName("XPoint.XNode.ContactAuthority.v1"));
        var restarted = Store(statePath, temporary.Path, restartedProvider);
        var actual = await restarted.ReadAsync(default);

        Assert.NotNull(actual);
        Assert.Equal(expected.NetworkId, actual.NetworkId);
        Assert.Equal(expected.GenesisAuthorityCoreHash, actual.GenesisAuthorityCoreHash);
        Assert.Equal(expected.ViewGeneration, actual.ViewGeneration);
        Assert.Equal(expected.Xna1Chain[0], actual.Xna1Chain[0]);
    }

    [Fact]
    public async Task EmptyDirectoryGenesisStateCanBeReadAfterProcessStyleRestart()
    {
        using var temporary = new TemporaryDirectory();
        var stateDirectory = System.IO.Path.Combine(temporary.Path, "contact-authority-v1");
        var keys = System.IO.Path.Combine(stateDirectory, "dataprotection-keys");
        var statePath = System.IO.Path.Combine(stateDirectory, "authority.state");
        Directory.CreateDirectory(stateDirectory);
        Directory.CreateDirectory(keys);
        var expected = State(adhTreeSize: 0);

        var firstProvider = DataProtectionProvider.Create(
            new DirectoryInfo(keys),
            builder => builder.SetApplicationName("XPoint.XNode.ContactAuthority.v1"));
        await Store(statePath, temporary.Path, firstProvider).CommitAsync(expected, default);

        var restartedProvider = DataProtectionProvider.Create(
            new DirectoryInfo(keys),
            builder => builder.SetApplicationName("XPoint.XNode.ContactAuthority.v1"));
        var actual = await Store(statePath, temporary.Path, restartedProvider).ReadAsync(default);

        Assert.NotNull(actual);
        Assert.Equal((ulong)0, actual.AdhTreeSize);
        Assert.Equal(expected.Adh1CoreHash, actual.Adh1CoreHash);
    }

    private static HttpsContactAuthorityArtifactPackageSource Source(HttpMessageHandler handler) =>
        new(new HttpClient(handler), Options("https://registry.example"));

    private static ContactAuthorityHttpSourceOptions Options(string origin) => new(
        origin,
        new XPointNetworkGenesisPin(NetworkId, GenesisHash),
        LeafKey,
        ContactAuthorityDirectoryCodec.AbsoluteMaximumEnvelopeBytes,
        TimeSpan.FromSeconds(5));

    private static ContactAuthorityArtifactRequest Request() =>
        new(Nonce, BootId, 123, LeafKey);

    private static HttpResponseMessage Response(
        HttpRequestMessage request,
        byte[] body,
        bool useStream = false)
    {
        HttpContent content = useStream
            ? new StreamContent(new MemoryStream(body, writable: false))
            : new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(
            ContactAuthorityDirectoryCodec.ResponseMediaType);
        content.Headers.ContentLength = body.Length;
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = content
        };
        response.Headers.CacheControl = new CacheControlHeaderValue
        {
            Private = true,
            NoStore = true,
            MustRevalidate = true,
            MaxAge = TimeSpan.Zero
        };
        return response;
    }

    private static byte[] EncodeResponse(byte[] cdq)
    {
        using var stream = new MemoryStream();
        stream.Write("CDR1"u8);
        WriteU16(stream, 1);
        WriteU16(stream, 0);
        WriteU32(stream, 0);
        stream.Write(cdq, 12, 16);
        stream.Write(cdq, 28, 32);
        stream.Write(cdq, 60, 16);
        stream.Write(cdq, 76, 8);
        stream.Write(LeafKey);
        Chain(stream, 0xa1);
        Chain(stream, 0xa2);
        Artifact(stream, 0xa3);
        Artifact(stream, 0xa4);
        Artifact(stream, 0xa5);
        Chain(stream, 0xa6);
        Chain(stream, 0xa7);
        Chain(stream, 0xa8);
        Chain(stream, 0xa9);
        Chain(stream, 0xaa);
        var encoded = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8, 4), checked((uint)encoded.Length));
        return encoded;
    }

    private static void Chain(Stream stream, byte marker)
    {
        WriteU32(stream, 1);
        Artifact(stream, marker);
    }

    private static void Artifact(Stream stream, byte marker)
    {
        WriteU32(stream, 1);
        stream.WriteByte(marker);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static ProductionContactAuthorityOptions CompleteOptions() => new()
    {
        Enabled = true,
        RegistryOrigin = "https://registry.example",
        NetworkIdHex = Convert.ToHexString(NetworkId),
        XPointNetworkGenesisPinHex = Convert.ToHexString(GenesisHash),
        DirectoryLeafKeyHex = Convert.ToHexString(LeafKey),
        StateRelativePath = "contact-authority-v1/authority.state",
        SupportedDirectoryReader = 1,
        MaximumResponseBytes = ContactAuthorityDirectoryCodec.AbsoluteMaximumEnvelopeBytes,
        MaximumProtectedStateBytes = 80 * 1024 * 1024,
        RequestTimeoutSeconds = 5
    };

    private static ContactServicePersistenceOptions ActiveContactOptions() => new()
    {
        RuntimeActivation = true,
        MapReplicaEndpoint = true
    };

    private static RouterNodeOptions Node(string dataDirectory) => new()
    {
        DataDirectory = dataDirectory,
        RouterId = Convert.ToHexString(Bytes(32, 0x66)),
        Ed25519PrivateKey = Convert.ToHexString(Bytes(32, 0x77))
    };

    private static FileContactAuthorityDurableStateStore Store(
        string path,
        string root,
        IDataProtectionProvider provider) => new(
            path,
            root,
            80 * 1024 * 1024,
            new DataProtectionContactAuthorityStateProtector(provider),
            new NoOpStorageSecurity(),
            new TestDurability());

    private static ContactAuthorityDurableState State(ulong adhTreeSize = 2)
    {
        var chain = new[] { Bytes(4, 0x41) };
        return new ContactAuthorityDurableState
        {
            NetworkId = NetworkId.ToArray(),
            GenesisAuthorityCoreHash = GenesisHash.ToArray(),
            ExactAdh1 = Bytes(16, 0x50),
            Adh1CoreHash = Bytes(32, 0x60),
            AdhGeneration = 1,
            AdhTreeSize = adhTreeSize,
            HeadCoreReference = Reference("XNH1", 0x71),
            HeadTreeSize = 2,
            HeadRoot = Bytes(32, 0x71),
            ViewCoreReference = Reference("XNV1", 0x72),
            ViewGeneration = 1,
            AuthorityCoreReference = Reference("XNA1", 0x73),
            LastForwardCheckpointCoreReference = [],
            LastForwardCheckpointGeneration = null,
            Xna1Chain = Clone(chain),
            Dts1Chain = Clone(chain),
            Xvp1Chain = Clone(chain),
            Xnv1Chain = Clone(chain),
            Xnh1Chain = Clone(chain),
            Pmt2Chain = Clone(chain)
        };
    }

    private static byte[] Reference(string magic, byte marker)
    {
        var output = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic, output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4, 2), 1);
        output.AsSpan(6).Fill(marker);
        return output;
    }

    private static byte[][] Clone(byte[][] values) =>
        values.Select(value => value.ToArray()).ToArray();

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> send)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return send(request);
        }
    }

    private sealed class NoOpStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) => _ = path;
    }

    private sealed class TestMonotonicClock : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(BootId, 123));
        }
    }

    private sealed class TestDurability : IMailboxDurabilityBarrier
    {
        public void FlushFileAndParentDirectory(string path) => _ = path;
        public void FlushParentDirectory(string deletedPath) => _ = deletedPath;
        public void ReplaceFile(string temporaryPath, string finalPath) =>
            File.Move(temporaryPath, finalPath, overwrite: true);
        public void DeleteFile(string path) => File.Delete(path);
        public void DeleteDirectory(string path) => Directory.Delete(path);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        internal TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"xnode-contact-authority-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        internal string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
