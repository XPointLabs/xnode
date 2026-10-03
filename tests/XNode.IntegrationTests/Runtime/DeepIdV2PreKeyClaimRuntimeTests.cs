using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

/// <summary>
/// Actual DID2 proof/publication/journals plus production HTTP peer client,
/// endpoint authentication/replay and exact wire codec in an in-process handler.
/// The handler is not a real socket/TLS/SPKI or physical ONION/device test.
/// </summary>
public sealed class DeepIdV2PreKeyClaimRuntimeTests
{
    [Fact]
    public async Task BothAnonymousExits_UseOneCoordinatorAndDistinctDurableKeys_ThenRestartReplay()
    {
        using var harness = await Harness.CreateAsync();
        var first = harness.Request(0xb0); var second = harness.Request(0xb1);
        var results = await Task.WhenAll(
            harness.Claims[0].ReceiveTerminalAsync(first.CanonicalBytes, default).AsTask(),
            harness.Claims[1].ReceiveTerminalAsync(second.CanonicalBytes, default).AsTask());
        var a = harness.Verify(first, results[0]); var b = harness.Verify(second, results[1]);
        Assert.NotEqual(a.Field(17).ToArray(), b.Field(17).ToArray());
        Assert.Equal(new ulong[] { 1, 2 }, new[] { U64(a.Field(24).Span), U64(b.Field(24).Span) }.Order());
        Assert.True(harness.HttpCalls >= 7);
        harness.Reopen();
        Assert.Equal(results[0].ToArray(), (await harness.Claims[1].ReceiveTerminalAsync(first.CanonicalBytes, default)).ToArray());
        Assert.Equal(results[1].ToArray(), (await harness.Claims[0].ReceiveTerminalAsync(second.CanonicalBytes, default)).ToArray());
    }

    [Theory]
    [InlineData((byte)ContactReplicaRpcOperation.PrepareDid2PreKeyClaim)]
    [InlineData((byte)ContactReplicaRpcOperation.CompleteDid2PreKeyClaim)]
    public async Task LostAuthenticatedResponse_ExactRetryAfterRestartDoesNotSelectAnotherKey(byte lostOperation)
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        harness.LoseNextResponse = (ContactReplicaRpcOperation)lostOperation;
        var unknown = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[0].ReceiveTerminalAsync(
            request.CanonicalBytes, default)).Span, request.CanonicalBytes.Span);
        Assert.Equal(Xpc1V2Status.OutcomeUnknown, unknown.Status);
        Assert.Equal(Xpc1V2MutationOutcome.OutcomeUnknown, unknown.MutationOutcome);
        var originalKey = harness.Signed.Publication.OneTimeMembers[0].OneTimePrekeyId.ToArray();
        harness.Reopen();
        var resumed = await harness.Claims[1].ReceiveTerminalAsync(request.CanonicalBytes, default);
        var verified = harness.Verify(request, resumed);
        Assert.Equal(originalKey, verified.Field(17).ToArray());
        Assert.Equal(1UL, U64(verified.Field(24).Span));
        Assert.Equal(resumed.ToArray(), (await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default)).ToArray());
        var next = harness.Request(0xb1);
        var nextResult = harness.Verify(next, await harness.Claims[0].ReceiveTerminalAsync(next.CanonicalBytes, default));
        Assert.Equal(2UL, U64(nextResult.Field(24).Span));
        Assert.Equal(harness.Signed.Publication.OneTimeMembers[1].OneTimePrekeyId.ToArray(), nextResult.Field(17).ToArray());
    }

    [Fact]
    public async Task ChangedRequestForSameOperation_ReturnsConflictWithoutAnotherReservation()
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        var original = await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default);
        var changed = harness.Request(ephemeral: 0xb4);
        var conflict = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[1].ReceiveTerminalAsync(
            changed.CanonicalBytes, default)).Span, changed.CanonicalBytes.Span);
        Assert.Equal(Xpc1V2Status.Conflict, conflict.Status);
        Assert.Equal(32, conflict.Field(16).Length);
        Assert.Equal(original.ToArray(), (await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default)).ToArray());
    }

    [Fact]
    public async Task UnavailableCurrentRecipientProof_CannotCreateClaimState()
    {
        using var harness = await Harness.CreateAsync();
        harness.Signed.RejectProof = true;
        await Assert.ThrowsAnyAsync<System.Security.Cryptography.CryptographicException>(async () =>
            await harness.Claims[0].ReceiveTerminalAsync(harness.Request().CanonicalBytes, default));
        Assert.Empty(Directory.GetFiles(harness.Root, "claims.state", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task AuthorityExpiryAfterPeerPrepare_ReturnsUnknownAndLeavesKeyReserved()
    {
        using var harness = await Harness.CreateAsync();
        harness.ExpireAfterPrepare = true;
        var request = harness.Request();
        var response = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[0].ReceiveTerminalAsync(
            request.CanonicalBytes, default)).Span, request.CanonicalBytes.Span);
        Assert.Equal(Xpc1V2Status.OutcomeUnknown, response.Status);
        Assert.Equal(2, Directory.GetFiles(harness.Root, "claims.state", SearchOption.AllDirectories).Length);
        using var store = new DeepIdV2InventoryCommitStore(harness.Nodes[0].DataDirectory,
            DeepIdV2PublicationAuthorityFixture.Network, DeepIdV2PublicationAuthorityFixture.Service,
            harness.Nodes[0].GetRouterId().ToBytes());
        var proposal = store.PrepareNextClaim(request, 1_095, 1_105,
            _ => throw new InvalidOperationException("Existing pending reservation must not change."));
        Assert.Empty(proposal.CompletedResult.ToArray());
        Assert.Equal(harness.Signed.Publication.OneTimeMembers[0].OneTimePrekeyId.ToArray(), proposal.Offering.OneTimePrekeyId.ToArray());
    }

    [Fact]
    public async Task LegacyOrWrongPlacementCannotReachV2ClaimMutation()
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request().CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4), 1);
        await Assert.ThrowsAnyAsync<FormatException>(async () => await harness.Claims[0].ReceiveTerminalAsync(request, default));
        var valid = harness.Request();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await harness.Receivers[0].ReceiveAsync(
            new(harness.Placement, ContactReplicaRpcOperation.ClaimPreKey, new byte[32], valid.CanonicalBytes),
            harness.Nodes[1].GetRouterId(), default));
        var projection = ContactServicePlacementCapability.FromUntrustedProjection(ContactServiceRequestKind.ClaimPreKey,
            harness.Placement.NetworkId.Span, harness.Placement.ViewHash.Span, Enumerable.Repeat((byte)0xfb, 32).ToArray(),
            harness.Placement.ShardKey.Span, harness.Placement.SelectionEpoch, harness.Placement.ValidUntilUnixSeconds,
            harness.Placement.ReplicaIds);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await harness.Claims[0].ReceiveAsync(
            new(projection, ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim, new byte[32], valid.CanonicalBytes),
            harness.Nodes[1].GetRouterId(), default));
        Assert.Empty(Directory.GetFiles(harness.Root, "claims.state", SearchOption.AllDirectories));
    }

    [Fact]
    public void ClaimFlag_RequiresObserverAndDID2OnlyPublicationBoundary()
    {
        var options = new DeepIdV2PreKeyClaimOptions { Enabled = true };
        Assert.True(options.Validate(true, true, true));
        Assert.Throws<InvalidOperationException>(() => options.Validate(false, true, true));
        Assert.Throws<InvalidOperationException>(() => options.Validate(true, false, true));
        Assert.Throws<InvalidOperationException>(() => options.Validate(true, true, false));
    }

    [Fact]
    public async Task UnknownCapabilityLookup_DoesNotCreateCustodyDirectory()
    {
        using var harness = await Harness.CreateAsync();
        var directories = Directory.GetDirectories(harness.Root, "*", SearchOption.AllDirectories).Order().ToArray();
        Assert.Throws<InvalidOperationException>(() => DeepIdV2InventoryCommitStore.OpenExisting(
            harness.Nodes[0].DataDirectory, DeepIdV2PublicationAuthorityFixture.Network,
            Enumerable.Repeat((byte)0xfc, 32).ToArray(), harness.Nodes[0].GetRouterId().ToBytes(),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));
        Assert.Equal(directories, Directory.GetDirectories(harness.Root, "*", SearchOption.AllDirectories).Order().ToArray());
    }

    [Fact]
    public async Task PeerProposal_IsClosedAndCannotBePreparedByTheSecondRankedReplica()
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        var proposal = new DeepIdV2ClaimProposal(request, harness.Signed.Publication.OneTimeMembers[0],
            harness.Signed.Publication.Manifest, 1, 0);
        ParsedXic1V2 Receipt(int index)
        {
            using var store = DeepIdV2InventoryCommitStore.OpenExisting(harness.Nodes[index].DataDirectory,
                DeepIdV2PublicationAuthorityFixture.Network, DeepIdV2PublicationAuthorityFixture.Service,
                harness.Nodes[index].GetRouterId().ToBytes(), new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
            return store.ReadCurrentCommitReceipt()!;
        }
        var exact = DeepIdV2ClaimPeerPayloadCodec.EncodePrepare(proposal, Receipt(0), Receipt(1), new byte[64]);
        Assert.Equal(request.CanonicalBytes.ToArray(),
            DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(exact).Proposal.Request.CanonicalBytes.ToArray());
        Assert.Throws<InvalidDataException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(exact[..^1]));
        Assert.Throws<InvalidDataException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare([.. exact, 0]));
        var hostileLength = exact.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(hostileLength.AsSpan(438 + 560 + 8 + 2), uint.MaxValue);
        Assert.Throws<InvalidDataException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(hostileLength));
        var old = exact.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(old.AsSpan(4), 1);
        Assert.ThrowsAny<FormatException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(old));
        var wrongSuite = exact.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(wrongSuite.AsSpan(6), 0x0201);
        Assert.ThrowsAny<FormatException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(wrongSuite));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await harness.Claims[0].ReceiveAsync(
            new(harness.Placement, ContactReplicaRpcOperation.PrepareDid2PreKeyClaim, new byte[32], exact),
            harness.Nodes[1].GetRouterId(), default));
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
            await harness.Claims[1].ReceiveAsync(new(harness.Placement,
                ContactReplicaRpcOperation.PrepareDid2PreKeyClaim, new byte[32], exact),
                harness.Nodes[0].GetRouterId(), default));
        Assert.Empty(Directory.GetFiles(harness.Root, "claims.state", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task CompletionForkLatch_SurvivesReopenAndPreservesInventory()
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        _ = harness.Verify(request, await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default));
        using (var store = DeepIdV2InventoryCommitStore.OpenExisting(harness.Nodes[0].DataDirectory,
            DeepIdV2PublicationAuthorityFixture.Network, DeepIdV2PublicationAuthorityFixture.Service,
            harness.Nodes[0].GetRouterId().ToBytes(), new MailboxStorageSecurity(), new MailboxDurabilityBarrier()))
        {
            Assert.Throws<InvalidDataException>(() => store.LatchClaimCompletionFork());
            Assert.Throws<InvalidDataException>(() => store.ReadCurrentPublication());
        }
        Assert.Single(Directory.GetFiles(harness.Nodes[0].DataDirectory, "claims.state", SearchOption.AllDirectories));
        Assert.Single(Directory.GetFiles(harness.Nodes[0].DataDirectory, "active.state", SearchOption.AllDirectories));
        Assert.Throws<InvalidDataException>(() => DeepIdV2InventoryCommitStore.OpenExisting(
            harness.Nodes[0].DataDirectory, DeepIdV2PublicationAuthorityFixture.Network,
            DeepIdV2PublicationAuthorityFixture.Service, harness.Nodes[0].GetRouterId().ToBytes(),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));
    }

    private static ulong U64(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);

    private sealed class Harness : IDisposable
    {
        internal string Root { get; } = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(),
            "did2-claim-runtime-" + Guid.NewGuid().ToString("N"))).FullName;
        internal DeepIdV2PublicationAuthorityFixture Signed { get; private set; } = null!;
        internal ContactServicePlacementCapability Placement { get; private set; } = null!;
        internal RouterNodeOptions[] Nodes { get; private set; } = [];
        internal DeepIdV2PreKeyClaimRuntime[] Claims { get; private set; } = [];
        internal DeepIdV2ReplicaStageReceiver[] Receivers { get; private set; } = [];
        private PrivacyRoutingConfiguration[] privacy = [];
        private readonly ServiceProvider services = new ServiceCollection().AddLogging().AddRouting().BuildServiceProvider();
        private readonly IClock clock = new FixedClock();
        private readonly ContactServicePersistenceOptions options = new() { ReplicaTimeoutSeconds = 20 };
        private ContactReplicaReplayGuard[] replays = [];
        internal ContactReplicaRpcOperation? LoseNextResponse { get; set; }
        internal bool ExpireAfterPrepare { get; set; }
        internal int HttpCalls { get; private set; }

        internal static async Task<Harness> CreateAsync()
        {
            var harness = new Harness();
            try
            {
                harness.Signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
                harness.Placement = await harness.Signed.MintPreKeyClaimAsync(DeepIdV2PublicationAuthorityFixture.Service, default);
                harness.Nodes = harness.Placement.ReplicaIds.Select((id, i) => new RouterNodeOptions
                {
                    RouterId = Convert.ToHexString(id.Span), Ed25519PrivateKey = Convert.ToHexString(harness.Signed.Node(id.Span).Seed),
                    DataDirectory = Path.Combine(harness.Root, i.ToString())
                }).ToArray();
                harness.privacy = Enumerable.Range(0, 2).Select(i => Privacy(harness.Nodes[i].GetRouterId(),
                    harness.Nodes[1 - i].GetRouterId())).ToArray();
                harness.Reopen();
                var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(harness.Signed.Publication.CanonicalBytes.Span,
                    harness.Signed.Placement.ViewHash.Span, harness.Signed.Publisher.CanonicalBytes.Span,
                    harness.Signed.Dca, harness.Signed.Xps);
                var receipts = new ParsedXic1V2[2];
                for (var i = 0; i < 2; i++)
                    foreach (var fragment in fragments)
                    {
                        var result = await harness.Receivers[i].ReceiveTerminalAsync(fragment, default);
                        if (fragment == fragments[^1]) receipts[i] = DeepIdV2PreKeyCommitReceiptCodec.Decode(result.Span);
                    }
                DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(harness.Signed.Publication,
                    harness.Signed.Placement.VerifiedPlacement, receipts[0], receipts[1]);
                return harness;
            }
            catch { harness.Dispose(); throw; }
        }

        internal void Reopen()
        {
            replays = [new(options), new(options)]; Claims = new DeepIdV2PreKeyClaimRuntime[2];
            Receivers = new DeepIdV2ReplicaStageReceiver[2];
            for (var i = 0; i < 2; i++)
            {
                var nodeIndex = i;
                var peer = new HttpContactReplicaPeerClient(Nodes[i], privacy[i], options, clock,
                    _ => new Handler((request, token) => HttpAsync(1 - nodeIndex, request, token)));
                var candidates = new DeepIdV2PublicationCandidateAuthority(Signed, Signed);
                var security = new MailboxStorageSecurity(); var durability = new MailboxDurabilityBarrier();
                Claims[i] = new(Nodes[i], Signed, candidates, peer, Signed, clock, security, durability);
                Receivers[i] = new(Nodes[i], Signed, security, durability,
                    new(Nodes[i], candidates, Signed, Signed, security, durability), Claims[i]);
            }
        }

        internal ParsedXpk1V2 Request(byte operation = 0xb0, byte ephemeral = 0xb2) =>
            DeepIdV2PreKeyClaimRequestCodec.Decode(DeepIdV2PreKeyClaimRequestCodec.Encode(Placement.NetworkId.Span,
                Enumerable.Repeat(operation, 32).ToArray(), Placement.ViewHash.Span, Placement.PlacementHash.Span,
                1_000, 1_400, Placement.ShardKey.Span, Enumerable.Repeat((byte)0xb3, 32).ToArray(),
                Signed.Publication.Manifest.Field(6).Span[6..], Signed.Publication.Manifest.Field(3).Span,
                Enumerable.Repeat(ephemeral, 32).ToArray()));

        internal ParsedXpc1V2 Verify(ParsedXpk1V2 request, ReadOnlyMemory<byte> response)
        {
            var parsed = DeepIdV2PreKeyClaimResultCodec.Decode(response.Span, request.CanonicalBytes.Span);
            _ = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request, parsed, Placement.VerifiedPlacement);
            Assert.Equal(Xpc1V2Status.Claimed, parsed.Status); return parsed;
        }

        private async Task<HttpResponseMessage> HttpAsync(int nodeIndex, HttpRequestMessage request, CancellationToken token)
        {
            HttpCalls++;
            Assert.Equal(HttpVersion.Version20, request.Version);
            Assert.Equal(HttpVersionPolicy.RequestVersionExact, request.VersionPolicy);
            Assert.Equal(ContactReplicaHttpContract.Route, request.RequestUri!.AbsolutePath);
            var body = await request.Content!.ReadAsByteArrayAsync(token);
            var command = ContactReplicaWireCodec.DecodeRequest(body);
            var context = new DefaultHttpContext { RequestServices = services };
            context.Connection.LocalPort = 7443; context.Request.Scheme = "https";
            context.Request.Method = "POST"; context.Request.Protocol = "HTTP/2";
            context.Request.ContentType = ContactReplicaHttpContract.MediaType;
            context.Request.ContentLength = body.Length; context.Request.Body = new MemoryStream(body);
            foreach (var header in request.Headers) context.Request.Headers[header.Key] = header.Value.ToArray();
            context.Response.Body = new MemoryStream();
            var result = await ContactReplicaHttpEndpoint.HandleCoreAsync(context, true, options,
                replays[nodeIndex], Receivers[nodeIndex], Nodes[nodeIndex], clock, 7443, token);
            await result.ExecuteAsync(context);
            if (command.Operation == ContactReplicaRpcOperation.PrepareDid2PreKeyClaim && ExpireAfterPrepare)
            { ExpireAfterPrepare = false; Signed.Sample = Signed.Freshness.FreshnessDeadlineMonotonicSeconds; }
            if (LoseNextResponse == command.Operation)
            { LoseNextResponse = null; throw new HttpRequestException("Synthetic authenticated-response loss after receiver processing."); }
            var response = new HttpResponseMessage((HttpStatusCode)context.Response.StatusCode)
            { Version = HttpVersion.Version20, Content = new ByteArrayContent(((MemoryStream)context.Response.Body).ToArray()) };
            if (context.Response.ContentType is { } contentType)
                response.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
            foreach (var header in context.Response.Headers)
                if (!header.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                    response.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            return response;
        }

        private static PrivacyRoutingConfiguration Privacy(RouterId local, RouterId peer) => new(true,
            Enumerable.Repeat((byte)0x81, 32).ToArray(), Sodium.ScalarMult.Base(Enumerable.Repeat((byte)0x81, 32).ToArray()), new Uri("https://local.invalid/api/peer/privacy/v1/frame"),
            new Dictionary<RouterId, PrivacyPeer> { [peer] = new(peer,
                new Uri("https://peer.invalid/api/peer/privacy/v1/frame"), Enumerable.Repeat((byte)0x83, 32).ToArray(),
                Sodium.ScalarMult.Base(Enumerable.Repeat((byte)0x84, 32).ToArray()), false) },
            64, 600, TimeSpan.FromSeconds(30), 1024, 1_000, TimeSpan.FromMinutes(5));

        public void Dispose()
        { foreach (var item in privacy) item.Dispose(); Signed?.Dispose(); services.Dispose(); if (Directory.Exists(Root)) Directory.Delete(Root, true); }
    }

    private sealed class FixedClock : IClock { public DateTimeOffset UtcNow => DateTimeOffset.FromUnixTimeSeconds(1_100); }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => handler(request, token);
    }
}
