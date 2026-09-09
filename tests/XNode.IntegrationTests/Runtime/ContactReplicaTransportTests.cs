using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Rebex.Security.Cryptography;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactReplicaTransportTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "xnode-contact-replica-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void MaximumBoundedXpp1FitsExactReplicaRpcEnvelopeWithoutAggregateFraming()
    {
        var placement = ContactServicePlacementCapability.FromUntrustedProjection(
            ContactServiceRequestKind.PublishPreKeyInventory,
            Bytes(0x11, 16),
            Bytes(0x12, 32),
            Bytes(0x13, 32),
            Bytes(0x14, 32),
            7,
            500,
            [Bytes(0x15, 32), Bytes(0x16, 32)]);
        var payload = Bytes(0x21, Xpp1BoundedCodec.MaximumCanonicalRequestBytes);
        var command = new ContactReplicaRpcCommand(
            placement,
            ContactReplicaRpcOperation.ApplyPreKeyPublication,
            Bytes(0x22, 32),
            payload);

        var wire = ContactReplicaWireCodec.Encode(command);
        var decoded = ContactReplicaWireCodec.DecodeRequest(wire);

        Assert.True(wire.Length < ContactReplicaWireCodec.MaximumRequestBytes);
        Assert.True(payload.Length < 1_048_576);
        Assert.Equal(ContactReplicaRpcOperation.ApplyPreKeyPublication, decoded.Operation);
        Assert.Equal(payload, decoded.Payload.ToArray());
        Assert.Throws<InvalidDataException>(() => ContactReplicaWireCodec.Encode(
            command with { Payload = Bytes(0x23, ContactReplicaWireCodec.MaximumRequestBytes) }));
        Assert.Throws<InvalidOperationException>(() => _ = placement.VerifiedPlacement);
    }

    [Fact]
    public void ClaimPreKeyReplicaPayloadRoundTripsEveryExactSelectorAndRejectsTruncation()
    {
        var exact = Xpk1Codec.Encode(
            Bytes(0x11, 16),
            Bytes(0x12, 32),
            Bytes(0x13, 32),
            Bytes(0x14, 32),
            100,
            200,
            Bytes(0x15, 32),
            Bytes(0x16, 32),
            Bytes(0x17, 32),
            Bytes(0x18, 32),
            Bytes(0x19, 32));
        var canonical = Xpk1Codec.Decode(exact);
        var request = new OpaquePreKeyClaimRequest(
            canonical.NetworkId.Span,
            canonical.ServiceCapability.Span,
            canonical.ResponderDeviceId.Span,
            canonical.RequestedSuite,
            canonical.OperationId.Span,
            canonical.RequestHash.Span,
            canonical.Dcb1Hash.Span,
            canonical.Xps1Hash.Span,
            canonical.ExpiresAtUnixSeconds);

        var payload = ContactReplicaPayloadCodec.Encode(request);
        var decoded = ContactReplicaPayloadCodec.DecodePreKeyClaimRequest(payload);

        Assert.Equal(request.NetworkId.ToArray(), decoded.NetworkId.ToArray());
        Assert.Equal(request.ServiceCapability.ToArray(), decoded.ServiceCapability.ToArray());
        Assert.Equal(request.ResponderDeviceId.ToArray(), decoded.ResponderDeviceId.ToArray());
        Assert.Equal(request.RequestedSuite, decoded.RequestedSuite);
        Assert.Equal(request.OperationId.ToArray(), decoded.OperationId.ToArray());
        Assert.Equal(request.RequestHash.ToArray(), decoded.RequestHash.ToArray());
        Assert.Equal(request.ExactDcb1Hash.ToArray(), decoded.ExactDcb1Hash.ToArray());
        Assert.Equal(request.ExactXps1Hash.ToArray(), decoded.ExactXps1Hash.ToArray());
        Assert.Equal(request.RequestExpiresAtUnixSeconds, decoded.RequestExpiresAtUnixSeconds);
        Assert.Throws<InvalidDataException>(() =>
            ContactReplicaPayloadCodec.DecodePreKeyClaimRequest(payload.AsSpan(0, payload.Length - 1)));
    }

    [Fact]
    public void PreKeyClaimResultRoundTripsCompleteXpi1MembershipAndReplicaSet()
    {
        var replicas = new ReadOnlyMemory<byte>[] { Bytes(0x71, 32), Bytes(0x72, 32) };
        var result = new ContactPreKeyClaimResult(
            ContactPreKeyClaimDisposition.Claimed,
            Bytes(0x31, 32),
            Bytes(0x32, ContactPreKeyStoreOptions.OneTimeDpk2Bytes),
            Bytes(0x33, 32),
            Bytes(0x34, 32),
            Bytes(0x35, 32),
            Bytes(0x36, 38),
            7,
            230,
            0,
            9,
            200,
            Bytes(0x37, 560),
            Bytes(0x38, 32),
            2,
            3,
            Bytes(0x39, 160),
            replicas,
            Bytes(0x3a, 32),
            Bytes(0x3b, 32),
            Bytes(0x3c, 32));

        var payload = ContactReplicaPayloadCodec.Encode(result);
        var decoded = ContactReplicaPayloadCodec.DecodePreKeyClaim(payload);

        Assert.Equal(result.Disposition, decoded.Disposition);
        Assert.Equal(result.ExactXpi1.ToArray(), decoded.ExactXpi1.ToArray());
        Assert.Equal(result.Xpi1Hash.ToArray(), decoded.Xpi1Hash.ToArray());
        Assert.Equal(result.InventoryEpoch, decoded.InventoryEpoch);
        Assert.Equal(result.InventoryIndex, decoded.InventoryIndex);
        Assert.Equal(result.InclusionProof.ToArray(), decoded.InclusionProof.ToArray());
        Assert.Equal(result.ReplicaNodeIds.Select(static value => value.ToArray()),
            decoded.ReplicaNodeIds.Select(static value => value.ToArray()));
        Assert.Equal(result.RequiredXpi1Hash.ToArray(), decoded.RequiredXpi1Hash.ToArray());
        Assert.Throws<InvalidDataException>(() =>
            ContactReplicaPayloadCodec.DecodePreKeyClaim(payload.AsSpan(0, payload.Length - 1)));
    }

    [Fact]
    public void ReplayGuardRejectsTheSameAuthenticatedAttempt()
    {
        var sender = Identity(0x11);
        var recipient = Identity(0x22);
        var now = DateTimeOffset.Parse("2026-09-07T10:00:00Z");
        var correlation = Bytes(0x31, 32);
        var body = Bytes(0x41, 512);
        var headers = ContactReplicaPeerAuthenticator.SignRequest(
            sender.Id,
            recipient.Id,
            sender.SeedHex,
            correlation,
            body,
            now);

        Assert.True(ContactReplicaPeerAuthenticator.VerifyRequest(
            headers,
            recipient.Id,
            correlation,
            body,
            now,
            out var verifiedSender,
            out var nonce));
        var guard = new ContactReplicaReplayGuard(Options());
        Assert.True(guard.TryAccept(verifiedSender, nonce, headers.TimestampUnixMilliseconds, now));
        Assert.False(guard.TryAccept(verifiedSender, nonce, headers.TimestampUnixMilliseconds, now));
    }

    [Fact]
    public void ReplayGuardNeverExceedsItsCapacityUnderConcurrentAdmission()
    {
        var sender = Identity(0x19);
        var now = DateTimeOffset.Parse("2026-09-07T10:00:00Z");
        var guard = new ContactReplicaReplayGuard(Options());
        var admitted = 0;

        Parallel.For(0, 2_000, index =>
        {
            Span<byte> nonce = stackalloc byte[16];
            BinaryPrimitives.WriteInt32BigEndian(nonce, index + 1);
            if (guard.TryAccept(sender.Id, nonce, now.ToUnixTimeMilliseconds(), now))
            {
                Interlocked.Increment(ref admitted);
            }
        });

        Assert.Equal(1_000, admitted);
        Span<byte> overflow = stackalloc byte[16];
        BinaryPrimitives.WriteInt32BigEndian(overflow, 2_001);
        Assert.False(guard.TryAccept(sender.Id, overflow, now.ToUnixTimeMilliseconds(), now));
    }

    [Theory]
    [InlineData("peer")]
    [InlineData("placement")]
    [InlineData("network")]
    public async Task ReceiverRejectsWrongPeerOrNonCurrentPlacementWithoutMutation(
        string mismatch)
    {
        var sender = Identity(0x12);
        var recipient = Identity(0x23, root);
        var stranger = Identity(0x34);
        var now = DateTimeOffset.Parse("2026-09-07T10:00:00Z");
        var shard = Bytes(0x45, 32);
        var current = Placement(
            ContactServiceRequestKind.PublishInvite,
            shard,
            sender.Id,
            recipient.Id,
            now.AddHours(1),
            networkFill: 0x51,
            placementFill: 0x61);
        var received = mismatch switch
        {
            "placement" => Placement(
                ContactServiceRequestKind.PublishInvite,
                shard,
                sender.Id,
                recipient.Id,
                now.AddHours(1),
                networkFill: 0x51,
                placementFill: 0x62),
            "network" => Placement(
                ContactServiceRequestKind.PublishInvite,
                shard,
                sender.Id,
                recipient.Id,
                now.AddHours(1),
                networkFill: 0x52,
                placementFill: 0x61),
            _ => current
        };
        using var local = Local(recipient, now);
        var receiver = Receiver(recipient, current, local, now);
        var command = new ContactReplicaRpcCommand(
            received,
            ContactReplicaRpcOperation.PublishDcr,
            Bytes(0x71, 32),
            Bytes(0x70, 1));

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await receiver.ReceiveAsync(
                command,
                mismatch == "peer" ? stranger.Id : sender.Id,
                default));

        var read = await local.Binding.ResolverReplica.ResolveCurrentDcrAsync(shard, default);
        Assert.Equal(ContactResolverReadDisposition.NotFound, read.Disposition);
    }

    [Fact]
    public async Task HttpTransportTimeoutIsOutcomeUnknown()
    {
        var sender = Identity(0x13);
        var recipient = Identity(0x24);
        var now = DateTimeOffset.Parse("2026-09-07T10:00:00Z");
        var shard = Bytes(0x46, 32);
        var placement = Placement(
            ContactServiceRequestKind.PublishInvite,
            shard,
            sender.Id,
            recipient.Id,
            now.AddHours(1));
        using var privacy = Privacy(sender.Id, recipient.Id);
        var options = Options();
        options.ReplicaTimeoutSeconds = 1;
        var client = new HttpContactReplicaPeerClient(
            sender.Options,
            privacy,
            options,
            new FixedClock(now),
            _ => new DelegateHandler(async (_, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                throw new InvalidOperationException();
            }));
        var command = new ContactReplicaRpcCommand(
            placement,
            ContactReplicaRpcOperation.ReadCurrentDcr,
            Bytes(0x72, 32),
            ContactReplicaPayloadCodec.EncodeFixed32(shard));

        var failure = await Assert.ThrowsAsync<IOException>(async () =>
            await client.SendAsync(command, default));
        Assert.Contains("deadline", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HttpTransportRejectsAResponseSignedByTheWrongPeer()
    {
        var sender = Identity(0x15);
        var recipient = Identity(0x26);
        var stranger = Identity(0x37);
        var now = DateTimeOffset.Parse("2026-09-07T10:00:00Z");
        var shard = Bytes(0x48, 32);
        var placement = Placement(
            ContactServiceRequestKind.PublishInvite,
            shard,
            sender.Id,
            recipient.Id,
            now.AddHours(1));
        using var privacy = Privacy(sender.Id, recipient.Id);
        var client = new HttpContactReplicaPeerClient(
            sender.Options,
            privacy,
            Options(),
            new FixedClock(now),
            _ => new DelegateHandler((request, _) =>
            {
                var correlation = Convert.FromHexString(
                    request.Headers.GetValues(
                        ContactReplicaPeerAuthenticator.CorrelationHeader).Single());
                var responseBody = ContactReplicaWireCodec.Encode(
                    new ContactReplicaRpcResponse(
                        ContactReplicaRpcOperation.ReadCurrentDcr,
                        correlation,
                        recipient.Id.ToBytes(),
                        ReadOnlyMemory<byte>.Empty));
                var authentication = ContactReplicaPeerAuthenticator.SignResponse(
                    stranger.Id,
                    sender.Id,
                    stranger.SeedHex,
                    correlation,
                    responseBody,
                    now);
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Version = HttpVersion.Version20,
                    Content = new ByteArrayContent(responseBody)
                };
                response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
                    ContactReplicaHttpContract.MediaType);
                AddResponseHeaders(response, authentication);
                return Task.FromResult(response);
            }));
        var command = new ContactReplicaRpcCommand(
            placement,
            ContactReplicaRpcOperation.ReadCurrentDcr,
            Bytes(0x76, 32),
            ContactReplicaPayloadCodec.EncodeFixed32(shard));

        await Assert.ThrowsAsync<IOException>(async () =>
            await client.SendAsync(command, default));
    }

    [Fact]
    public async Task LostResponseIsOutcomeUnknownThenReplicaRestartExactReplaysDurableMutation()
    {
        var sender = Identity(0x14);
        var recipient = Identity(0x25, root);
        var now = DateTimeOffset.Parse("2026-09-07T10:00:00Z");
        var shard = Bytes(0x47, 32);
        var placement = Placement(
            ContactServiceRequestKind.PublishContactUpdate,
            shard,
            sender.Id,
            recipient.Id,
            now.AddHours(1));
        var write = XurRequest(shard, now);

        using (var firstLocal = Local(recipient, now))
        {
            var firstReceiver = Receiver(recipient, placement, firstLocal, now);
            var losingClient = new ReceiverPeerClient(firstReceiver, sender.Id)
            {
                LoseResponseAfterCommit = true
            };
            var remote = new AuthenticatedRemoteContactServiceReplica(
                placement,
                sender.Id.ToBytes(),
                losingClient);
            using var senderStore = new ContactResolverOpaqueStore(
                Path.Combine(root, "sender-resolver.state"),
                clock: new FixedClock(now));
            using var coordinator = new ContactResolverTwoReplicaCoordinator(
                new ContactResolverStoreReplica(sender.Id.ToBytes(), senderStore),
                remote);
            var unknown = await coordinator.WriteXurAsync(write, default);
            Assert.Equal(ContactResolverApplicationStatus.OutcomeUnknown, unknown.Status);
            Assert.Equal(
                ContactResolverApplicationMutationOutcome.OutcomeUnknown,
                unknown.MutationOutcome);
            Assert.Equal(1, unknown.DurableReplicaCount);
        }

        using var restartedLocal = Local(recipient, now.AddMinutes(1));
        var restartedReceiver = Receiver(
            recipient,
            placement,
            restartedLocal,
            now.AddMinutes(1));
        var retryClient = new ReceiverPeerClient(restartedReceiver, sender.Id);
        var retriedRemote = new AuthenticatedRemoteContactServiceReplica(
            placement,
            sender.Id.ToBytes(),
            retryClient);
        var replay = await retriedRemote.WriteXurSuccessorAsync(write, default);

        Assert.Equal(ContactResolverMutationDisposition.ExactReplay, replay.Disposition);
        Assert.Equal(1, retryClient.Calls);
    }

    [Fact]
    public async Task RemoteReceiptAuthoritySignsOnlyItsDurableExactResult()
    {
        var sender = Identity(0x16);
        var recipient = Identity(0x27, root);
        var now = DateTimeOffset.Parse("2026-09-07T10:00:00Z");
        var capability = Bytes(0x49, 32);
        var placement = Placement(
            ContactServiceRequestKind.PublishContactUpdate,
            capability,
            sender.Id,
            recipient.Id,
            now.AddHours(1));
        var write = XurRequest(capability, now);
        using var local = Local(recipient, now);
        var remote = new AuthenticatedRemoteContactServiceReplica(
            placement,
            sender.Id.ToBytes(),
            new ReceiverPeerClient(Receiver(recipient, placement, local, now), sender.Id));

        var committed = await remote.WriteXurSuccessorAsync(write, default);
        Assert.Equal(ContactResolverMutationDisposition.Committed, committed.Disposition);
        var tuple = Concat(
            write.RequestHash.ToArray(),
            U64(committed.Generation),
            committed.ObjectHash,
            U64(committed.Generation));
        var request = new ContactServiceReplicaReceiptRequest(
            ContactServiceReceiptKind.UpdateCommit,
            tuple);
        var receipt = await remote.IssueAsync(request, default);
        Assert.Equal(recipient.Id.ToBytes(), receipt.ReplicaId.ToArray());
        Assert.True(ContactServiceReceiptTranscript.Verify(
            receipt.ReplicaId.Span,
            ContactServiceReceiptTranscript.SigningInput(request),
            receipt.Signature.Span));

        tuple[0] ^= 0xff;
        await Assert.ThrowsAsync<ContactServiceReceiptAuthorityException>(async () =>
            await remote.IssueAsync(
                new ContactServiceReplicaReceiptRequest(
                    ContactServiceReceiptKind.UpdateCommit,
                    tuple),
                default));
    }

    [Fact]
    public void HostCompositionRequiresAuthorityObjectsAndKeepsDefaultDispatcherClosed()
    {
        var options = Options();
        options.RuntimeActivation = true;
        options.MapReplicaEndpoint = true;
        Assert.Throws<InvalidOperationException>(() =>
            ContactServiceHostCompositionPlan.Create(options, authorities: null));

        options.RuntimeActivation = false;
        options.MapReplicaEndpoint = false;
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddContactServiceBoundary(options);
        using var provider = services.BuildServiceProvider();
        Assert.IsType<UnavailableContactServiceOpaqueDispatcher>(
            provider.GetRequiredService<IContactServiceOpaqueDispatcher>());
    }

    [Fact]
    public async Task DormantCompositionMapsNoReplicaEndpoint()
    {
        var builder = WebApplication.CreateBuilder();
        var plan = builder.Services.AddContactServiceBoundary(Options());
        var app = builder.Build();

        app.MapContactReplicaEndpoint(plan, peerListenerPort: 8083);

        Assert.DoesNotContain(
            ((IEndpointRouteBuilder)app).DataSources.SelectMany(static source => source.Endpoints),
            endpoint => endpoint.DisplayName?.Contains(
                ContactReplicaHttpContract.Route,
                StringComparison.Ordinal) == true);
        await app.DisposeAsync();
    }

    [Fact]
    public void AuthorityObjectsComposeOneLocalKeyAndAuthenticatedRemoteTransport()
    {
        var local = Identity(0x17, root);
        var remote = Identity(0x28);
        var now = DateTimeOffset.Parse("2026-09-07T10:00:00Z");
        var placement = Placement(
            ContactServiceRequestKind.PublishContactUpdate,
            Bytes(0x4a, 32),
            local.Id,
            remote.Id,
            now.AddHours(1));
        var options = Options();
        options.RuntimeActivation = true;
        options.MapReplicaEndpoint = true;
        var services = new ServiceCollection();
        services.AddSingleton(local.Options);
        services.AddSingleton<IClock>(new FixedClock(now));
        services.AddSingleton(Privacy(local.Id, remote.Id));
        services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        services.AddContactServiceBoundary(
            options,
            ContactServiceAuthoritySources.ForTransportTests(
                new FixedPlacementSource(placement)));

        using var provider = services.BuildServiceProvider();
        Assert.IsType<ProductionContactServiceOpaqueDispatcher>(
            provider.GetRequiredService<IContactServiceOpaqueDispatcher>());
        Assert.NotNull(provider.GetRequiredService<ContactReplicaRequestReceiver>());
        Assert.Equal(
            local.Id.ToBytes(),
            provider.GetRequiredService<ContactServiceLocalReplicaRuntime>()
                .Binding.ReceiptAuthority.ReplicaId.ToArray());
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private ContactServiceLocalReplicaRuntime Local(IdentityFixture identity, DateTimeOffset now)
    {
        Directory.CreateDirectory(root);
        identity.Options.DataDirectory = root;
        return new ContactServiceLocalReplicaRuntime(
            identity.Options,
            new FixedClock(now),
            new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
    }

    private static ContactReplicaRequestReceiver Receiver(
        IdentityFixture identity,
        ContactServicePlacementCapability placement,
        ContactServiceLocalReplicaRuntime local,
        DateTimeOffset now) => new(
            identity.Options,
            ContactServiceAuthoritySources.ForTransportTests(
                new FixedPlacementSource(placement)),
            local,
            new FixedClock(now));

    private static OpaqueXurWriteRequest XurRequest(
        byte[] capability,
        DateTimeOffset now)
    {
        var ciphertext = Bytes(0x77, 128);
        return new OpaqueXurWriteRequest(
            capability,
            Bytes(0x78, 32),
            Bytes(0x79, 32),
            Bytes(0x7a, 32),
            1,
            new byte[32],
            Bytes(0x7b, 32),
            SHA256.HashData(ciphertext),
            ciphertext,
            checked((ulong)now.AddDays(1).ToUnixTimeSeconds()));
    }

    private static ContactServicePlacementCapability Placement(
        ContactServiceRequestKind kind,
        byte[] shard,
        RouterId first,
        RouterId second,
        DateTimeOffset validUntil,
        byte networkFill = 0x50,
        byte placementFill = 0x60) =>
        ContactServicePlacementCapability.FromUntrustedProjection(
            kind,
            Bytes(networkFill, 16),
            Bytes(0x55, 32),
            Bytes(placementFill, 32),
            shard,
            7,
            checked((ulong)validUntil.ToUnixTimeSeconds()),
            [first.ToBytes(), second.ToBytes()]);

    private static ContactServicePersistenceOptions Options() => new()
    {
        ReplicaTimeoutSeconds = 5,
        ReplayCapacity = 1_000,
        ReplayTtlSeconds = 300
    };

    private static PrivacyRoutingConfiguration Privacy(RouterId local, RouterId peer) => new(
        true,
        Bytes(0x81, 32),
        Bytes(0x82, 32),
        new Uri("https://local.example/api/peer/privacy/v1/frame"),
        new Dictionary<RouterId, PrivacyPeer>
        {
            [peer] = new PrivacyPeer(
                peer,
                new Uri("https://peer.example/api/peer/privacy/v1/frame"),
                Bytes(0x83, 32),
                Bytes(0x84, 32),
                false)
        },
        64,
        600,
        TimeSpan.FromSeconds(30),
        1024,
        1_000,
        TimeSpan.FromMinutes(5));

    private static IdentityFixture Identity(byte fill, string? data = null)
    {
        var seed = Bytes(fill, 32);
        var signer = new Ed25519();
        signer.FromSeed(seed);
        var id = RouterId.FromBytes(signer.GetPublicKey());
        return new IdentityFixture(
            id,
            Convert.ToHexStringLower(seed),
            new RouterNodeOptions
            {
                RouterId = id.Value,
                Ed25519PrivateKey = Convert.ToHexStringLower(seed),
                DataDirectory = data ?? Path.GetTempPath()
            });
    }

    private static byte[] Bytes(byte value, int count) =>
        Enumerable.Repeat(value, count).ToArray();

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Concat(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static void AddResponseHeaders(
        HttpResponseMessage response,
        ContactReplicaAuthenticationHeaders headers)
    {
        response.Headers.TryAddWithoutValidation(
            ContactReplicaPeerAuthenticator.SenderHeader,
            headers.SenderReplicaId);
        response.Headers.TryAddWithoutValidation(
            ContactReplicaPeerAuthenticator.RecipientHeader,
            headers.RecipientReplicaId);
        response.Headers.TryAddWithoutValidation(
            ContactReplicaPeerAuthenticator.TimestampHeader,
            headers.TimestampUnixMilliseconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
        response.Headers.TryAddWithoutValidation(
            ContactReplicaPeerAuthenticator.NonceHeader,
            headers.Nonce);
        response.Headers.TryAddWithoutValidation(
            ContactReplicaPeerAuthenticator.CorrelationHeader,
            headers.Correlation);
        response.Headers.TryAddWithoutValidation(
            ContactReplicaPeerAuthenticator.SignatureHeader,
            headers.Signature);
    }

    private sealed record IdentityFixture(
        RouterId Id,
        string SeedHex,
        RouterNodeOptions Options);

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed class FixedPlacementSource(ContactServicePlacementCapability placement)
        : IContactServicePlacementAuthoritySource
    {
        public ValueTask<ContactServicePlacementCapability> MintAsync(
            ContactServiceRequestKind requestKind,
            ReadOnlyMemory<byte> shardKey,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(placement);
        }
    }

    private sealed class ReceiverPeerClient(
        ContactReplicaRequestReceiver receiver,
        RouterId sender) : IContactReplicaPeerClient
    {
        public bool LoseResponseAfterCommit { get; init; }
        public int Calls { get; private set; }

        public async ValueTask<ContactReplicaRpcResponse> SendAsync(
            ContactReplicaRpcCommand command,
            CancellationToken cancellationToken)
        {
            Calls++;
            var response = await receiver.ReceiveAsync(command, sender, cancellationToken);
            if (LoseResponseAfterCommit)
            {
                throw new IOException("Simulated lost authenticated response.");
            }
            return response;
        }
    }

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => handler(request, cancellationToken);
    }
}
