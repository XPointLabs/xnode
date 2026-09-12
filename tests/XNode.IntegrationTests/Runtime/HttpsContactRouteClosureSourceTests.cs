using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class HttpsContactRouteClosureSourceTests
{
    private static readonly byte[] NetworkId = Bytes(16, 0x11);
    private static readonly byte[] LocatorHash = Bytes(32, 0x22);

    [Fact]
    public void OptionsAreDormantByDefaultAndRejectPartialConfiguration()
    {
        using var temporary = new TemporaryDirectory();
        var node = new RouterNodeOptions { DataDirectory = temporary.Path };
        Assert.Null(new ProductionContactRouteClosureOptions()
            .ValidateAndLoad(node, contactAuthorityEnabled: false));

        var partial = new ProductionContactRouteClosureOptions
        {
            RegistryOrigin = "https://registry.example"
        };
        Assert.Throws<InvalidOperationException>(() =>
            partial.ValidateAndLoad(node, contactAuthorityEnabled: true));

        var enabled = ValidOptions();
        Assert.Throws<InvalidOperationException>(() =>
            enabled.ValidateAndLoad(node, contactAuthorityEnabled: false));
        Assert.NotNull(enabled.ValidateAndLoad(node, contactAuthorityEnabled: true));
    }

    [Theory]
    [InlineData("http://registry.example")]
    [InlineData("https://registry.example/path")]
    [InlineData("https://user@registry.example")]
    [InlineData("https://registry.example/?query=1")]
    [InlineData("https://registry.example/%2e")]
    public void EndpointRequiresCanonicalHttpsOrigin(string origin)
    {
        Assert.Throws<ArgumentException>(() =>
            new ContactRouteClosureHttpSourceOptions(origin, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task HttpSourceWritesCanonicalRequestAndAcceptsExactEnvelope()
    {
        var envelope = Envelope();
        var handler = new DelegateHandler(async request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://registry.example/api/v1/contact-route-closures",
                request.RequestUri!.AbsoluteUri);
            Assert.True(request.Headers.CacheControl?.NoStore);
            Assert.Equal(HttpsContactRouteClosureArtifactSource.ResponseMediaType,
                Assert.Single(request.Headers.Accept).MediaType);
            Assert.Equal(HttpsContactRouteClosureArtifactSource.RequestMediaType,
                request.Content!.Headers.ContentType!.MediaType);
            Assert.Equal(50, request.Content.Headers.ContentLength);
            var body = await request.Content.ReadAsByteArrayAsync();
            Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(body));
            Assert.Equal(NetworkId, body.AsSpan(2, 16).ToArray());
            Assert.Equal(LocatorHash, body.AsSpan(18, 32).ToArray());
            var response = Response(HttpStatusCode.OK, envelope);
            response.RequestMessage = request;
            return response;
        });
        using var client = new HttpClient(handler);
        var source = Source(client);

        var result = await source.FetchAsync(NetworkId, LocatorHash, default);

        Assert.NotNull(result);
        Assert.Equal("XRR1", result.Reachability.Magic);
        Assert.Equal("PMS2", result.Selection.Magic);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task HttpSourceNormalizes404And503ToUnavailable(HttpStatusCode status)
    {
        using var client = new HttpClient(new DelegateHandler(request =>
        {
            var response = new HttpResponseMessage(status)
            {
                RequestMessage = request
            };
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            return Task.FromResult(response);
        }));

        Assert.Null(await Source(client).FetchAsync(NetworkId, LocatorHash, default));
    }

    [Theory]
    [InlineData("media")]
    [InlineData("length")]
    [InlineData("no-store")]
    [InlineData("encoding")]
    [InlineData("transfer-encoding")]
    [InlineData("redirect")]
    [InlineData("count")]
    [InlineData("trailing")]
    [InlineData("truncated")]
    public async Task HttpSourceRejectsHostileResponse(string mutation)
    {
        var exact = Envelope();
        if (mutation == "count")
        {
            exact[0] = 5;
        }
        else if (mutation == "trailing")
        {
            exact[^1] ^= 1;
            BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(1), 642);
        }
        else if (mutation == "truncated")
        {
            BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(1), uint.MaxValue);
        }

        using var client = new HttpClient(new DelegateHandler(request =>
        {
            var response = Response(HttpStatusCode.OK, exact);
            response.RequestMessage = request;
            switch (mutation)
            {
                case "media":
                    response.Content.Headers.ContentType =
                        new MediaTypeHeaderValue("application/octet-stream");
                    break;
                case "length":
                    response.Content.Headers.ContentLength = null;
                    break;
                case "no-store":
                    response.Headers.CacheControl = null;
                    break;
                case "encoding":
                    response.Content.Headers.ContentEncoding.Add("gzip");
                    break;
                case "transfer-encoding":
                    response.Headers.TransferEncodingChunked = true;
                    break;
                case "redirect":
                    response.RequestMessage = new HttpRequestMessage(
                        HttpMethod.Post, "https://other.example/api/v1/contact-route-closures");
                    break;
            }
            return Task.FromResult(response);
        }));

        await Assert.ThrowsAsync<ContactRouteClosureTransportException>(async () =>
            await Source(client).FetchAsync(NetworkId, LocatorHash, default));
    }

    [Fact]
    public async Task HttpSourceNormalizesInternalTimeoutWithoutMaskingCallerCancellation()
    {
        using var timedOutClient = new HttpClient(new DelegateHandler(_ =>
            Task.FromException<HttpResponseMessage>(new TaskCanceledException("timeout"))));
        var timeout = await Assert.ThrowsAsync<ContactRouteClosureTransportException>(async () =>
            await Source(timedOutClient).FetchAsync(NetworkId, LocatorHash, default));
        Assert.Equal("request-timeout", timeout.Code);

        using var callerCancellation = new CancellationTokenSource();
        callerCancellation.Cancel();
        using var cancelledClient = new HttpClient(new DelegateHandler(_ =>
            Task.FromException<HttpResponseMessage>(new TaskCanceledException("cancelled"))));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await Source(cancelledClient).FetchAsync(
                NetworkId, LocatorHash, callerCancellation.Token));
    }

    [Fact]
    public async Task VerifiedSourceDoesNotFetchWhenTypedAuthorityIsUnavailable()
    {
        var artifacts = new RecordingArtifactSource(Package());
        var source = new HttpsVerifiedContactRouteClosureSource(
            artifacts,
            new FixedAuthoritySource(null),
            new FakeProtocolVerifier(),
            new MemoryLineageStore());

        Assert.Null(await source.ReadCurrentAsync(NetworkId, LocatorHash, default));
        Assert.Equal(0, artifacts.Calls);
    }

    [Fact]
    public async Task VerifiedSourceCoarsensAuthorityAndTransportFailuresWithoutFallback()
    {
        var artifacts = new RecordingArtifactSource(Package());
        var unavailableAuthority = new HttpsVerifiedContactRouteClosureSource(
            artifacts,
            new ThrowingAuthoritySource(new IOException("authority unavailable")),
            new FakeProtocolVerifier(),
            new MemoryLineageStore());

        Assert.Null(await unavailableAuthority.ReadCurrentAsync(NetworkId, LocatorHash, default));
        Assert.Equal(0, artifacts.Calls);

        var unavailableTransport = new HttpsVerifiedContactRouteClosureSource(
            new ThrowingArtifactSource(new HttpRequestException("registry unavailable")),
            new FixedAuthoritySource(new(Raw("XIR1", 611, 0x61), Authority(NetworkId))),
            new FakeProtocolVerifier(),
            new MemoryLineageStore());
        Assert.Null(await unavailableTransport.ReadCurrentAsync(NetworkId, LocatorHash, default));
    }

    [Fact]
    public void ProductionCodecDoesNotPromoteStructurallyShapedUnverifiedBytes()
    {
        Assert.Throws<ContactFormatException>(() =>
            new ContactRouteClosureArtifactCodec().Decode(
                "XRR1", Raw("XRR1", 643, 0x44)));
    }

    [Fact]
    public void ProductionVerifierRequiresExactProtocolDecodedXir1()
    {
        Assert.Throws<ContactFormatException>(() =>
            new ContactRouteClosureProtocolVerifier().Verify(
                Raw("XIR1", 611, 0x45),
                Package(),
                Authority(NetworkId)));
    }

    [Fact]
    public void ExplicitCompositionReplacesClosedRouteSourceWithHttpsAdapter()
    {
        using var temporary = new TemporaryDirectory();
        var services = new ServiceCollection();
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(temporary.Path, "keys")));
        services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();

        services.AddProductionContactRouteClosure(Configuration(temporary.Path));

        var route = services.Last(descriptor =>
            descriptor.ServiceType == typeof(IVerifiedContactRouteClosureSource));
        Assert.NotNull(route.ImplementationFactory);
        Assert.DoesNotContain(services, descriptor =>
            descriptor.ServiceType == typeof(IVerifiedContactRouteClosureSource)
            && descriptor.ImplementationType == typeof(ClosedVerifiedContactRouteClosureSource));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteVerifiedAuthoritySnapshotSource)
            && descriptor.ImplementationType
                == typeof(ProductionContactRouteVerifiedAuthoritySnapshotSource));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteRecipientAuthoritySource)
            && descriptor.ImplementationType
                == typeof(ProtocolContactRouteRecipientAuthoritySource));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteRecipientResolveClosureSource)
            && descriptor.ImplementationFactory is not null);
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteRecipientResolveEvidenceOwner));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(FileContactRecipientResolveEvidenceCache));
        Assert.DoesNotContain(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteRecipientResolveClosureSource)
            && descriptor.ImplementationType
                == typeof(ClosedContactRouteRecipientResolveClosureSource));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteRecipientEvidenceProjector)
            && descriptor.ImplementationType
                == typeof(ProtocolContactRouteRecipientEvidenceProjector));
    }

    [Fact]
    public async Task ExplicitCompositionActivatesProtocolMintedAuthorityProducer()
    {
        using var temporary = new TemporaryDirectory();
        var current = new FixedCurrentAuthoritySource(CurrentAuthority());
        var recipient = new FixedRecipientAuthoritySource(RecipientAuthority());
        var mint = new FakeNetworkAuthorityVerifier(Authority(
            NetworkId, authorityGeneration: 7, trustedLower: 100, trustedUpper: 200));
        var services = new ServiceCollection();
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(temporary.Path, "keys")));
        services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        services.AddSingleton<IContactRouteCurrentNetworkAuthoritySource>(current);
        services.AddSingleton<IContactRouteRecipientAuthoritySource>(recipient);
        services.AddSingleton<IContactRouteNetworkAuthorityVerifier>(mint);
        services.AddSingleton<IContactRouteClosureArtifactCodec, FakeArtifactCodec>();
        services.AddSingleton<IContactRecipientResolveEvidenceVerifier,
            RejectingRecipientResolveEvidenceVerifier>();
        services.AddProductionContactRouteClosure(Configuration(temporary.Path));
        await using var provider = services.BuildServiceProvider();

        var source = provider.GetRequiredService<IContactRouteVerifiedAuthoritySnapshotSource>();
        var routeSource = provider.GetRequiredService<IVerifiedContactRouteClosureSource>();
        var hostedServices = provider.GetServices<IHostedService>().ToArray();
        var result = await source.ReadCurrentAsync(NetworkId, LocatorHash, default);

        Assert.IsType<ProductionContactRouteVerifiedAuthoritySnapshotSource>(source);
        Assert.IsType<HttpsVerifiedContactRouteClosureSource>(routeSource);
        Assert.Contains(hostedServices,
            service => service is ContactRecipientResolveEvidenceCacheHostedService);
        Assert.Contains(hostedServices,
            service => service is ContactRouteClosureLineageHostedService);
        Assert.NotNull(result);
        Assert.Equal(1, current.Calls);
        Assert.Equal(1, recipient.Calls);
        Assert.Equal(1, mint.Calls);
    }

    [Fact]
    public async Task AuthorityProducerRejectsWrongCurrentNetworkBeforeRecipientLookup()
    {
        var recipient = new FixedRecipientAuthoritySource(RecipientAuthority());
        var mint = new FakeNetworkAuthorityVerifier(Authority(
            NetworkId, authorityGeneration: 7, trustedLower: 100, trustedUpper: 200));
        var source = new ProductionContactRouteVerifiedAuthoritySnapshotSource(
            new FixedCurrentAuthoritySource(CurrentAuthority(Bytes(16, 0x71))),
            recipient,
            new FakeArtifactCodec(),
            mint);

        Assert.Null(await source.ReadCurrentAsync(NetworkId, LocatorHash, default));
        Assert.Equal(0, recipient.Calls);
        Assert.Equal(0, mint.Calls);
    }

    [Fact]
    public async Task AuthorityProducerRejectsInviteForWrongLocatorBeforeMinting()
    {
        var invite = Record("XIR1", 611, generationTag: 3);
        RecordFields(invite)[1] = Bytes(32, 0x72);
        var mint = new FakeNetworkAuthorityVerifier(Authority(
            NetworkId, authorityGeneration: 7, trustedLower: 100, trustedUpper: 200));
        var source = new ProductionContactRouteVerifiedAuthoritySnapshotSource(
            new FixedCurrentAuthoritySource(CurrentAuthority()),
            new FixedRecipientAuthoritySource(RecipientAuthority()),
            new FixedArtifactCodec(invite),
            mint);

        Assert.Null(await source.ReadCurrentAsync(NetworkId, LocatorHash, default));
        Assert.Equal(0, mint.Calls);
    }

    [Theory]
    [InlineData((ulong)6, (ulong)100, (ulong)200)]
    [InlineData((ulong)7, (ulong)99, (ulong)200)]
    [InlineData((ulong)7, (ulong)100, (ulong)201)]
    public async Task StaleOrMismatchedMintedAuthorityFailsClosedBeforeRegistry(
        ulong authorityGeneration,
        ulong trustedLower,
        ulong trustedUpper)
    {
        var mint = new FakeNetworkAuthorityVerifier(Authority(
            NetworkId, authorityGeneration, trustedLower, trustedUpper));
        var authoritySource = new ProductionContactRouteVerifiedAuthoritySnapshotSource(
            new FixedCurrentAuthoritySource(CurrentAuthority()),
            new FixedRecipientAuthoritySource(RecipientAuthority()),
            new FakeArtifactCodec(),
            mint);
        var artifacts = new RecordingArtifactSource(Package());
        var source = new HttpsVerifiedContactRouteClosureSource(
            artifacts,
            authoritySource,
            new FakeProtocolVerifier(),
            new MemoryLineageStore());

        Assert.Null(await source.ReadCurrentAsync(NetworkId, LocatorHash, default));
        Assert.Equal(0, artifacts.Calls);
        Assert.Equal(1, mint.Calls);
    }

    [Fact]
    public async Task VerifiedSourceUsesIndependentXirAndTypedAuthorityThenCommitsLkg()
    {
        var package = Package();
        var xir = Raw("XIR1", 611, 0x61);
        var authority = Authority(NetworkId);
        var lineage = new MemoryLineageStore();
        var verifier = new FakeProtocolVerifier();
        var source = new HttpsVerifiedContactRouteClosureSource(
            new RecordingArtifactSource(package),
            new FixedAuthoritySource(new(xir, authority)),
            verifier,
            lineage);

        var result = await source.ReadCurrentAsync(NetworkId, LocatorHash, default);

        Assert.NotNull(result);
        Assert.Equal(1, verifier.Calls);
        Assert.Equal(1, lineage.Observations);
    }

    [Fact]
    public async Task FileLkgSurvivesRestartAndPermanentlyLatchesSameGenerationFork()
    {
        using var temporary = new TemporaryDirectory();
        var configuration = Configuration(temporary.Path);
        var protection = DataProtectionProvider.Create(
            new DirectoryInfo(Path.Combine(temporary.Path, "keys")));
        var first = Store(configuration, protection);
        var accepted = Observation(generation: 7, hashFill: 0x31);
        await first.ObserveAsync(accepted, default);

        var restarted = Store(configuration, protection);
        await restarted.ObserveAsync(accepted, default);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ObserveAsync(Observation(6, 0x31), default));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ObserveAsync(Observation(7, 0x32), default));

        var afterForkRestart = Store(configuration, protection);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await afterForkRestart.ObserveAsync(Observation(8, 0x33), default));
    }

    [Fact]
    public async Task FileLkgRejectsProtectedStateCorruptionOnStartup()
    {
        using var temporary = new TemporaryDirectory();
        var configuration = Configuration(temporary.Path);
        var protection = DataProtectionProvider.Create(
            new DirectoryInfo(Path.Combine(temporary.Path, "keys")));
        await Store(configuration, protection)
            .ObserveAsync(Observation(1, 0x41), default);
        var bytes = File.ReadAllBytes(configuration.StatePath);
        bytes[^1] ^= 1;
        File.WriteAllBytes(configuration.StatePath, bytes);

        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await Store(configuration, protection).InitializeAsync(default));
    }

    private static ProductionContactRouteClosureOptions ValidOptions() => new()
    {
        Enabled = true,
        RegistryOrigin = "https://registry.example",
        StateRelativePath = "contact-route-closure-v1/lkg.bin",
        MaximumProtectedStateBytes = 4 * 1024 * 1024,
        RequestTimeoutSeconds = 5
    };

    private static ProductionContactRouteClosureConfiguration Configuration(string root) => new(
        new ContactRouteClosureHttpSourceOptions(
            "https://registry.example", TimeSpan.FromSeconds(5)),
        Path.Combine(root, "state", "lkg.bin"),
        4 * 1024 * 1024);

    private static FileContactRouteClosureLineageStore Store(
        ProductionContactRouteClosureConfiguration configuration,
        IDataProtectionProvider protection) => new(
            configuration,
            protection,
            new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());

    private static HttpsContactRouteClosureArtifactSource Source(HttpClient client) => new(
        client,
        new ContactRouteClosureHttpSourceOptions(
            "https://registry.example", TimeSpan.FromSeconds(5)),
        new FakeArtifactCodec());

    private static HttpResponseMessage Response(HttpStatusCode status, byte[] body)
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new ByteArrayContent(body)
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue(
            HttpsContactRouteClosureArtifactSource.ResponseMediaType);
        response.Content.Headers.ContentLength = body.Length;
        response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
        return response;
    }

    private static byte[] Envelope()
    {
        var package = Package();
        ContactRecord[] records =
        [
            package.Reachability,
            package.Authorization,
            package.Route,
            package.Successor,
            package.Projection,
            package.Selection
        ];
        var length = 1 + records.Sum(static record => 4 + record.CanonicalBytes.Length);
        var result = new byte[length];
        result[0] = 6;
        var offset = 1;
        foreach (var record in records)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                result.AsSpan(offset), checked((uint)record.CanonicalBytes.Length));
            offset += 4;
            record.CanonicalBytes.Span.CopyTo(result.AsSpan(offset));
            offset += record.CanonicalBytes.Length;
        }
        Assert.Equal(4_143, result.Length);
        return result;
    }

    private static ContactRouteClosureArtifactPackage Package() => new(
        Record("XRR1", 643, generationTag: 3),
        Record("XRA1", 550, generationTag: 3),
        Record("XRC1", 940, generationTag: 3),
        Record("XSS1", 643, generationTag: 3),
        Record("PMT2", 842, generationTag: 2),
        Record("PMS2", 500, generationTag: 4));

    private static ContactRecord Record(string magic, int length, int generationTag)
    {
        var record = (ContactRecord)RuntimeHelpers.GetUninitializedObject(typeof(ContactRecord));
        RecordMagic(record) = magic;
        RecordCanonical(record) = Raw(magic, length, 0x5a);
        var fields = Enumerable.Range(0, Math.Max(4, generationTag))
            .Select(index => Bytes(index == 1 ? 32 : index == generationTag - 1 ? 8 : 32,
                checked((byte)(0x60 + index))))
            .ToArray();
        fields[0] = NetworkId.ToArray();
        fields[1] = LocatorHash.ToArray();
        fields[generationTag - 1] = new byte[8];
        RecordFields(record) = fields;
        return record;
    }

    private static byte[] Raw(string magic, int length, byte fill)
    {
        var bytes = Bytes(length, fill);
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        return bytes;
    }

    private static ContactRouteClosureLineageObservation Observation(
        ulong generation,
        byte hashFill) => new(
            NetworkId.ToArray(),
            LocatorHash.ToArray(),
            Enumerable.Range(0, 8)
                .Select(index => new ContactRouteClosureLineagePart(
                    generation,
                    Bytes(32, checked((byte)(hashFill + index))),
                    Bytes(32, checked((byte)(0x70 + index)))))
                .ToArray());

    private static ContactRouteCurrentNetworkAuthorityMaterial CurrentAuthority(
        byte[]? networkId = null) => new(
            (ContactVerifiedAuthoritySnapshot)RuntimeHelpers.GetUninitializedObject(
                typeof(ContactVerifiedAuthoritySnapshot)),
            networkId ?? NetworkId,
            authorityGeneration: 7,
            trustedLowerUnixSeconds: 100,
            trustedUpperUnixSeconds: 200,
            Raw("XNV1", 64, 0x31),
            Raw("XNH1", 64, 0x32),
            Raw("ADH1", 64, 0x33),
            Raw("PMT2", 842, 0x34));

    private static ContactRouteRecipientAuthorityMaterial RecipientAuthority() => new(
        Raw("XIR1", 611, 0x41),
        (VerifiedDevice)RuntimeHelpers.GetUninitializedObject(typeof(VerifiedDevice)),
        (CurrentlyAuthoritativeDca1)RuntimeHelpers.GetUninitializedObject(
            typeof(CurrentlyAuthoritativeDca1)),
        Raw("PMS2", 500, 0x42));

    private static VerifiedContactNetworkAuthority Authority(
        byte[] networkId,
        ulong authorityGeneration = 0,
        ulong trustedLower = 0,
        ulong trustedUpper = 0)
    {
        var result = (VerifiedContactNetworkAuthority)RuntimeHelpers
            .GetUninitializedObject(typeof(VerifiedContactNetworkAuthority));
        AuthorityNetworkId(result) = networkId.ToArray();
        AuthorityCoreReference(result) = Raw("XNA1", 38, 0x33);
        AuthorityRecipientDeviceId(result) = Bytes(32, 0x34);
        AuthorityGeneration(result) = authorityGeneration;
        AuthorityTrustedLower(result) = trustedLower;
        AuthorityTrustedUpper(result) = trustedUpper;
        return result;
    }

    private static VerifiedContactRouteClosure Closure(
        ContactRecord xir,
        ContactRouteClosureArtifactPackage package,
        VerifiedContactNetworkAuthority authority)
    {
        var result = (VerifiedContactRouteClosure)RuntimeHelpers
            .GetUninitializedObject(typeof(VerifiedContactRouteClosure));
        Invite(result) = xir;
        Reachability(result) = package.Reachability;
        Authorization(result) = package.Authorization;
        Route(result) = package.Route;
        Successor(result) = package.Successor;
        Projection(result) = package.Projection;
        Selection(result) = package.Selection;
        ClosureAuthority(result) = authority;
        return result;
    }

    private static byte[] Bytes(int length, byte fill) =>
        Enumerable.Repeat(fill, length).ToArray();


    private sealed class DelegateHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => handler(request);
    }

    private sealed class RecordingArtifactSource(ContactRouteClosureArtifactPackage package)
        : IContactRouteClosureArtifactSource
    {
        public int Calls { get; private set; }
        public ValueTask<ContactRouteClosureArtifactPackage?> FetchAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromResult<ContactRouteClosureArtifactPackage?>(package);
        }
    }

    private sealed class FixedAuthoritySource(ContactRouteVerifiedAuthoritySnapshot? snapshot)
        : IContactRouteVerifiedAuthoritySnapshotSource
    {
        public ValueTask<ContactRouteVerifiedAuthoritySnapshot?> ReadCurrentAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken) => ValueTask.FromResult(snapshot);
    }

    private sealed class RejectingRecipientResolveEvidenceVerifier
        : IContactRecipientResolveEvidenceVerifier
    {
        public ValueTask<VerifiedContactRecipientResolveObservation?> VerifyCurrentAsync(
            ContactRecipientResolveEvidenceSubmission submission,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<VerifiedContactRecipientResolveObservation?>(null);
    }

    private sealed class FixedCurrentAuthoritySource(
        ContactRouteCurrentNetworkAuthorityMaterial current)
        : IContactRouteCurrentNetworkAuthoritySource
    {
        public int Calls { get; private set; }

        public ValueTask<ContactRouteCurrentNetworkAuthorityMaterial>
            ReadCurrentRouteAuthorityAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(current);
        }
    }

    private sealed class FixedRecipientAuthoritySource(
        ContactRouteRecipientAuthorityMaterial? recipient)
        : IContactRouteRecipientAuthoritySource
    {
        public int Calls { get; private set; }

        public ValueTask<ContactRouteRecipientAuthorityMaterial?> ReadCurrentAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(recipient);
        }
    }

    private sealed class FakeNetworkAuthorityVerifier(VerifiedContactNetworkAuthority result)
        : IContactRouteNetworkAuthorityVerifier
    {
        public int Calls { get; private set; }

        public ValueTask<VerifiedContactNetworkAuthority> VerifyAsync(
            ContactRouteCurrentNetworkAuthorityMaterial current,
            ContactRouteRecipientAuthorityMaterial recipient,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(result);
        }
    }

    private sealed class ThrowingAuthoritySource(Exception failure)
        : IContactRouteVerifiedAuthoritySnapshotSource
    {
        public ValueTask<ContactRouteVerifiedAuthoritySnapshot?> ReadCurrentAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<ContactRouteVerifiedAuthoritySnapshot?>(failure);
    }

    private sealed class ThrowingArtifactSource(Exception failure)
        : IContactRouteClosureArtifactSource
    {
        public ValueTask<ContactRouteClosureArtifactPackage?> FetchAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<ContactRouteClosureArtifactPackage?>(failure);
    }

    private sealed class FakeProtocolVerifier : IContactRouteClosureProtocolVerifier
    {
        public int Calls { get; private set; }
        public VerifiedContactRouteClosure Verify(
            ReadOnlyMemory<byte> exactXir1,
            ContactRouteClosureArtifactPackage package,
            VerifiedContactNetworkAuthority authority)
        {
            Calls++;
            return Closure(Record("XIR1", 611, generationTag: 3), package, authority);
        }
    }

    private sealed class FakeArtifactCodec : IContactRouteClosureArtifactCodec
    {
        public ContactRecord Decode(string expectedMagic, ReadOnlySpan<byte> exact)
        {
            if (exact.Length < 4
                || !exact[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(expectedMagic)))
            {
                throw new InvalidDataException("MagicMismatch");
            }
            var generationTag = expectedMagic switch
            {
                "PMT2" => 2,
                "PMS2" => 4,
                _ => 3
            };
            var result = Record(expectedMagic, exact.Length, generationTag);
            RecordCanonical(result) = exact.ToArray();
            return result;
        }
    }

    private sealed class FixedArtifactCodec(ContactRecord record)
        : IContactRouteClosureArtifactCodec
    {
        public ContactRecord Decode(string expectedMagic, ReadOnlySpan<byte> exact)
        {
            Assert.Equal("XIR1", expectedMagic);
            return record;
        }
    }

    private sealed class MemoryLineageStore : IContactRouteClosureLineageStore
    {
        public int Observations { get; private set; }
        public ValueTask InitializeAsync(CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;
        public ValueTask ObserveAsync(
            ContactRouteClosureLineageObservation observation,
            CancellationToken cancellationToken)
        {
            Observations++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        internal TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "xnode-contact-route-" + Guid.NewGuid().ToString("N"));
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

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "networkId")]
    private static extern ref byte[] AuthorityNetworkId(VerifiedContactNetworkAuthority value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "authorityCoreReference")]
    private static extern ref byte[] AuthorityCoreReference(VerifiedContactNetworkAuthority value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "recipientDeviceId")]
    private static extern ref byte[] AuthorityRecipientDeviceId(VerifiedContactNetworkAuthority value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<AuthorityGeneration>k__BackingField")]
    private static extern ref ulong AuthorityGeneration(VerifiedContactNetworkAuthority value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<TrustedLowerUnixSeconds>k__BackingField")]
    private static extern ref ulong AuthorityTrustedLower(VerifiedContactNetworkAuthority value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<TrustedUpperUnixSeconds>k__BackingField")]
    private static extern ref ulong AuthorityTrustedUpper(VerifiedContactNetworkAuthority value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Invite>k__BackingField")]
    private static extern ref ContactRecord Invite(VerifiedContactRouteClosure value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Reachability>k__BackingField")]
    private static extern ref ContactRecord Reachability(VerifiedContactRouteClosure value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Authorization>k__BackingField")]
    private static extern ref ContactRecord Authorization(VerifiedContactRouteClosure value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Route>k__BackingField")]
    private static extern ref ContactRecord Route(VerifiedContactRouteClosure value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Successor>k__BackingField")]
    private static extern ref ContactRecord Successor(VerifiedContactRouteClosure value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Projection>k__BackingField")]
    private static extern ref ContactRecord Projection(VerifiedContactRouteClosure value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Selection>k__BackingField")]
    private static extern ref ContactRecord Selection(VerifiedContactRouteClosure value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Authority>k__BackingField")]
    private static extern ref VerifiedContactNetworkAuthority ClosureAuthority(
        VerifiedContactRouteClosure value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Magic>k__BackingField")]
    private static extern ref string RecordMagic(ContactRecord value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "canonical")]
    private static extern ref byte[] RecordCanonical(ContactRecord value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "fields")]
    private static extern ref byte[][] RecordFields(ContactRecord value);
}
