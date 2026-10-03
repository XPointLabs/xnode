using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using XNode.Core.Mailbox;
using Peer = XNode.IntegrationTests.Runtime.CurrentMailboxReplicaReceiverTests.Fixture;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Real local TLS/H2 and two independent native stores under actual
/// signed test-owned network/grants/floors. Not Program/ONION or device evidence.</summary>
public sealed class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task CurrentPeerClientDeliversToPinnedEndpoint()
    {
        await using var f = await Fixture.CreateAsync();
        ReadOnlyMemory<byte>? reply = null;
        var error = await Record.ExceptionAsync(async () => reply = await new CurrentMailboxReplicaPeerClient().SendAsync(
            f.Recipient.Node.Replicas[0].Transport, MailboxPeerReplicationOperation.Store,
            f.Recipient.Frame(MailboxPeerReplicationOperation.Store), CancellationToken.None));
        Assert.True(error is null, $"Failure={error?.GetType().Name}; HTTP error={(error as HttpRequestException)?.HttpRequestError}; inner={error?.InnerException?.GetType().Name}.");
        Assert.NotNull(reply);
        Assert.Equal(MailboxWireHttpContract.PeerStore.MaximumResponseBytes, reply.Value.Length);
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
        Assert.Equal(1, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task TwoStoresThroughPinnedHttp2PersistReadTombstoneAndReopen()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var first = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.True(first.Status == MailboxPeerQuorumStatus.Durable,
            $"Quorum={first.Status}; peer calls={f.PeerClient.Calls}; failure={f.PeerClient.Failure}; HTTP requests={f.RemoteHost.Requests}; status={f.RemoteHost.LastStatus}; bytes={f.RemoteHost.LastBytes}; remote replay={f.Recipient.ReplayFiles.Length}.");
        Assert.Equal(2, first.DurableReplicaCount);
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(first.CanonicalMqr3.Span);
        Assert.NotEqual(quorum.FirstReplica.ReplicaId.ToArray(), quorum.SecondReplica.ReplicaId.ToArray());
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
        Assert.Equal(1, f.RemoteHost.Requests);
        f.Reopen();
        var retry = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.Equal(first.CanonicalMqr3.ToArray(), retry.CanonicalMqr3.ToArray());
        Assert.Equal(1, f.RemoteHost.Requests); // Completed native response, no second HTTP write.
        var tombstone = f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone);
        var removed = await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, removed.Status);
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
        f.Reopen();
        var replay = await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(removed.CanonicalMqr3.ToArray(), replay.CanonicalMqr3.ToArray());
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
    }

    [Fact]
    public async Task ConcurrentExactRetryHasOneRemoteWriteAndOneMutationPerStore()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store).AsTask()));
        Assert.All(results, result =>
        {
            Assert.Equal(MailboxPeerQuorumStatus.Durable, result.Status);
            Assert.Equal(2, result.DurableReplicaCount);
            Assert.Equal(results[0].CanonicalMqr3.ToArray(), result.CanonicalMqr3.ToArray());
        });
        Assert.Equal(1, f.RemoteHost.Requests); Assert.Equal(1, f.PeerClient.Calls);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Single(f.Sender.ReplayFiles); Assert.Single(f.Recipient.ReplayFiles);
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
    }

    [Fact]
    public async Task LostRemoteResponseLeavesSenderPendingAndExactReopenReconcilesBothStores()
    {
        await using var f = await Fixture.CreateAsync();
        f.RemoteHost.DropNext = true;
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var unknown = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, unknown.Status); Assert.True(unknown.CanonicalMqr3.IsEmpty);
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Sender.ReplayFiles)));
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(Assert.Single(f.Recipient.ReplayFiles)));
        f.Reopen();
        var resumed = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, resumed.Status); Assert.Equal(2, resumed.DurableReplicaCount);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(Assert.Single(f.Sender.ReplayFiles)));
        Assert.Equal(2, f.RemoteHost.Requests);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("duplicate-local")]
    [InlineData("expiry")]
    [InlineData("source-loss")]
    public async Task HostileOrExpiredHttpCallbackCannotProduceQuorum(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        f.RemoteHost.AfterReceive = response =>
        {
            if (defect == "signature") { var changed = response.ToArray(); changed[^1] ^= 1; return changed; }
            if (defect == "duplicate-local")
            {
                var remote = MailboxReceiptV2Codec.DecodeReplica(response.Span);
                var local = remote with { ReplicaId = f.Sender.Node.Node, Signature = new byte[64] };
                return MailboxReceiptV2Codec.EncodeReplica(f.Sender.Crypto.SignReplicaResponse(local,
                    f.Signed.Node(f.Sender.Node.Node).Seed));
            }
            if (defect == "expiry") f.Signed.Sample = 105;
            if (defect == "source-loss") f.Signed.RejectProof = true;
            return response;
        };
        if (defect is "expiry" or "source-loss")
            Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store).AsTask()));
        else
        {
            var rejected = await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store);
            Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, rejected.Status); Assert.True(rejected.CanonicalMqr3.IsEmpty);
        }
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Sender.ReplayFiles)));
        f.Signed.Sample = 100; f.Signed.RejectProof = false; f.RemoteHost.AfterReceive = null;
        f.Reopen();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store)).Status);
    }

    [Fact]
    public async Task WrongSignedTlsPinCannotContactRemoteOrClaimQuorum()
    {
        await using var f = await Fixture.CreateAsync(wrongPin: true);
        var failed = await f.Coordinator.ReplicateAsync(f.Recipient.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, failed.Status); Assert.True(failed.CanonicalMqr3.IsEmpty);
        Assert.Equal(0, f.RemoteHost.Requests); Assert.Empty(f.Recipient.ReplayFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Sender.ReplayFiles)));
    }

    [Fact]
    public async Task PeerEndpointRejectsWrongOperationAndMediaBeforeMutation()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        using var client = new HttpClient(HttpPrivacyPeerClient.CreatePinnedHandler(f.Recipient.Node.Replicas[0].Transport));
        foreach (var defect in new[] { "operation", "media" })
        {
            using var content = new ByteArrayContent(exact);
            content.Headers.ContentType = new MediaTypeHeaderValue(defect == "media" ? "application/json" : MailboxWireHttpContract.Prq2ContentType);
            var route = defect == "operation" ? MailboxWireHttpContract.PeerTombstoneRoute : MailboxWireHttpContract.PeerStoreRoute;
            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://127.0.0.1:{f.RemoteHost.Port}{route}")
            { Content = content, Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
            using var response = await client.SendAsync(request);
            Assert.Equal(defect == "media" ? HttpStatusCode.UnsupportedMediaType : HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync());
            Assert.Empty(f.Recipient.ReplayFiles); Assert.Empty(f.Recipient.MutationFiles);
        }
    }

    private static byte Status(string path)
    { using var json = JsonDocument.Parse(File.ReadAllBytes(path)); return json.RootElement.GetProperty("status").GetByte(); }

    private sealed class Fixture : IAsyncDisposable
    {
        internal DeepIdV2PublicationAuthorityFixture Signed = null!;
        private readonly List<Host> hosts = [];
        internal Host RemoteHost = null!;
        internal Peer Sender = null!, Recipient = null!;
        internal CurrentMailboxReplicationCoordinator Coordinator = null!;
        internal ObservedPeerClient PeerClient = new();
        internal static async Task<Fixture> CreateAsync(bool wrongPin = false)
        {
            var f = new Fixture();
            try
            {
                for (var i = 0; i < 3; i++) f.hosts.Add(await Host.CreateAsync());
                var origins = f.hosts.Select(host => new DeepIdV2PublicationAuthorityFixture.TransportOrigin(
                    IPAddress.Loopback, checked((ushort)host.Port), wrongPin ? SHA256.HashData(host.Pin) : host.Pin, SHA256.HashData(host.Pin))).ToArray();
                // The next pin must remain distinct even in the intentionally wrong-current-pin case.
                if (wrongPin) origins = origins.Select(origin => origin with { NextSpki = SHA256.HashData(origin.NextSpki.Span) }).ToArray();
                f.Signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(transportOrigins: origins);
                f.Recipient = await Peer.CreateAsync(f.Signed, 0); f.Sender = await Peer.CreateAsync(f.Signed, 1);
                f.RemoteHost = f.hosts.Single(host => host.Port == f.Recipient.Node.Replicas[0].Transport.Port);
                f.Bind(); return f;
            }
            catch { await f.DisposeAsync(); throw; }
        }
        private void Bind()
        {
            RemoteHost.Endpoint = new(Recipient.Receiver, RemoteHost.Port);
            Coordinator = new(Sender.Receiver, PeerClient, new ReplicatedMailboxOptions { Enabled = true });
        }
        internal void Reopen() { Sender.Reopen(); Recipient.Reopen(); Bind(); }
        public async ValueTask DisposeAsync()
        {
            foreach (var host in hosts) await host.DisposeAsync();
            if (Sender is not null) await Sender.DisposeAsync(); if (Recipient is not null) await Recipient.DisposeAsync();
            Signed?.Dispose();
        }
    }

    private sealed class ObservedPeerClient : ICurrentMailboxReplicaPeerClient
    {
        internal int Calls;
        internal string? Failure;
        public async ValueTask<ReadOnlyMemory<byte>?> SendAsync(VerifiedOnionNextHopTransport recipient,
            MailboxPeerReplicationOperation operation, ReadOnlyMemory<byte> exactRequest, CancellationToken token)
        {
            Calls++;
            try { return await new CurrentMailboxReplicaPeerClient().SendAsync(recipient, operation, exactRequest, token); }
            catch (Exception error)
            {
                Failure = $"{error.GetType().Name}/{(error as HttpRequestException)?.HttpRequestError}/{error.InnerException?.GetType().Name}";
                throw;
            }
        }
    }

    private sealed class Host : IAsyncDisposable
    {
        private WebApplication app = null!;
        private X509Certificate2 certificate = null!;
        internal int Port, Requests, LastStatus, LastBytes;
        internal byte[] Pin = [];
        internal CurrentMailboxPeerHttpEndpoint? Endpoint;
        internal bool DropNext;
        internal Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>? AfterReceive;
        internal static async Task<Host> CreateAsync()
        {
            var host = new Host(); using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            using var issued = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            // Windows Schannel needs an imported key handle, not the ephemeral
            // CertificateRequest key. DefaultKeySet deletes the imported test
            // key with the certificate; no operator store/import is used.
            var pfx = issued.Export(X509ContentType.Pfx);
            try { host.certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.DefaultKeySet); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
            host.Pin = SHA256.HashData(host.certificate.PublicKey.ExportSubjectPublicKeyInfo());
            var builder = WebApplication.CreateSlimBuilder(); builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
                listen => { listen.Protocols = HttpProtocols.Http2; listen.UseHttps(host.certificate); }));
            host.app = builder.Build();
            foreach (var operation in new[] { MailboxPeerReplicationOperation.Store, MailboxPeerReplicationOperation.Tombstone })
            {
                var contract = operation == MailboxPeerReplicationOperation.Store ? MailboxWireHttpContract.PeerStore : MailboxWireHttpContract.PeerTombstone;
                host.app.MapPost(contract.Route, async (HttpContext context, CancellationToken token) =>
                {
                    Interlocked.Increment(ref host.Requests);
                    if (host.Endpoint is null) return Results.StatusCode(503);
                    // Capture the actual product endpoint's bytes so only test-owned
                    // network fault injection changes/drops the outgoing response.
                    var original = context.Response.Body; using var captured = new MemoryStream(); context.Response.Body = captured;
                    var result = await host.Endpoint.HandleAsync(context, contract, operation, token);
                    await result.ExecuteAsync(context); context.Response.Body = original;
                    host.LastStatus = context.Response.StatusCode; host.LastBytes = checked((int)captured.Length);
                    if (host.DropNext && context.Response.StatusCode == 200) { host.DropNext = false; context.Abort(); return Results.Empty; }
                    var bytes = captured.ToArray();
                    if (context.Response.StatusCode != 200) return Results.StatusCode(context.Response.StatusCode);
                    var response = host.AfterReceive?.Invoke(bytes) ?? bytes;
                    return Results.Bytes(response.ToArray(), contract.ResponseContentType);
                });
            }
            await host.app.StartAsync();
            host.Port = new Uri(host.app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()).Port;
            return host;
        }
        public async ValueTask DisposeAsync()
        { if (app is not null) { await app.StopAsync(); await app.DisposeAsync(); } certificate?.Dispose(); }
    }
}
