using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using Microsoft.Extensions.Logging;

namespace XNode.IntegrationTests.Runtime;

// Real public DID2/network ceremony and independently signed peer headers;
// HTTP handler and proof/clock retrieval are in-process. No socket/device claim.
public sealed class ContactCoordinationOnionDispatcherTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BothCanonicalTargetsBindSelectedGatewayAndRejectSubstitutionWithoutSuccess(bool successor)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true, authorRouteSuccessor: successor);
        var route = fixture.ContactRoute;
        var floor = fixture.Freshness.NextProtectedLkg;
        var request = successor ? fixture.RouteSuccessorRequest : new ContactRouteAuthorityWireRequest(fixture.NetworkContext.NetworkId.Span,
            DeepIdV2PublicationAuthorityFixture.Bytes(32, 0x58), fixture.Freshness.QueriedDirectoryLeafKey.Span,
            floor.LogGeneration, floor.CoreHash.Span, fixture.Dca, route.Route.Authorization.CanonicalBytes.Span);
        var routeBody = ContactRouteAuthorityWireCodec.EncodeRequest(request);
        var routeResponse = ContactRouteAuthorityWireCodec.EncodeResponse(request, successor ? fixture.RouteSuccessorResponse :
            new(request.NetworkId.Span, request.RequestNonce.Span, route.Route.Selection.CanonicalBytes.Span,
                route.Route.Route.CanonicalBytes.Span, route.Route.Successor.CanonicalBytes.Span,
                fixture.Freshness.ExactAdh1.Span));
        var publicationBody = ContactPublicationAuthorityWireCodec.EncodeRequest(fixture.ContactOwnedRequest);
        Assert.Equal(3, BinaryPrimitives.ReadUInt16BigEndian(publicationBody));
        var publicationResponse = ContactPublicationAuthorityWireCodec.EncodeResponse(fixture.ContactOwnedRequest,
            new(fixture.ContactOwnedRequest.NetworkId.Span, fixture.ContactOwnedRequest.RequestNonce.Span,
                fixture.ContactPublication.CanonicalBytes.Span));
        var placement = ContactServicePlacementFactory.Create(fixture.NetworkContext,
            ContactServiceRequestKind.CoordinateContact, route.Route.Authorization.Field(6));
        var signer = fixture.Node(placement.RankedReplicaNodeIds[0].Span);
        var node = new RouterNodeOptions { RouterId = Convert.ToHexStringLower(signer.Ed25519PublicKey.Span),
            Ed25519PrivateKey = Convert.ToHexStringLower(signer.Seed) };
        var calls = 0; var rejectAfterForward = false; var corruptPair = false;
        var backend = new HttpContactCoordinationBackendClient(new("https://authority.example/"),
            DeepIdV2PublicationAuthorityFixture.Network, node, new SystemClock(), () => new Handler(async (message, ct) =>
            {
                calls++;
                var exact = await message.Content!.ReadAsByteArrayAsync(ct);
                var target = message.RequestUri!.AbsolutePath == "/api/v2/contact-route-authority" ?
                    ContactCoordinationTarget.Route : ContactCoordinationTarget.Publication;
                Assert.Equal(target == ContactCoordinationTarget.Route ? routeBody : publicationBody, exact);
                var headers = new ContactCoordinationPeerHeaders(
                    message.Headers.GetValues(ContactCoordinationPeerAuthentication.NodeHeader).Single(),
                    message.Headers.GetValues(ContactCoordinationPeerAuthentication.TimestampHeader).Single(),
                    message.Headers.GetValues(ContactCoordinationPeerAuthentication.NonceHeader).Single(),
                    message.Headers.GetValues(ContactCoordinationPeerAuthentication.SignatureHeader).Single());
                Assert.True(ContactCoordinationPeerAuthentication.Verify(headers,
                    DeepIdV2PublicationAuthorityFixture.Network, target, exact, DateTimeOffset.UtcNow));
                if (rejectAfterForward) fixture.RejectProof = true;
                var body = (target == ContactCoordinationTarget.Route ? routeResponse : publicationResponse).ToArray();
                if (corruptPair) body[24] ^= 1;
                var result = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
                result.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(target == ContactCoordinationTarget.Route ?
                    ContactRouteAuthorityWireCodec.ResponseMediaType : ContactPublicationAuthorityWireCodec.ResponseMediaType);
                return result;
            }));
        var logger = new DiagnosticLogger();
        var dispatcher = new ContactCoordinationOnionDispatcher(fixture, backend, node, fixture, logger);
        foreach (var (target, body, response) in new[] {
            (ContactCoordinationTarget.Route, routeBody, routeResponse),
            (ContactCoordinationTarget.Publication, publicationBody, publicationResponse) })
        {
            var exact = ContactCoordinationOnionCodec.EncodeRequest(target, body);
            var parsed = ContactCoordinationOnionCodec.DecodeRequest(exact);
            Assert.Equal(body, parsed.ExactBody.ToArray());
            Assert.Equal(route.Route.Authorization.Field(5).ToArray(), parsed.ProjectionReference.ToArray());
            var verified = OnionTerminalPayloadVerifierV1.VerifyRequest(fixture.NetworkContext,
                OnionOperation.ContactResolve, exact);
            var result = await dispatcher.DispatchAsync(verified, default);
            Assert.True(result.Success);
            Assert.Equal(response, ContactCoordinationOnionCodec.DecodeResponse(parsed, result.CanonicalBody.Span));
            var count = calls;
            foreach (var mutation in new[] { "version", "body-version", "reserved", "target", "length", "trailing", "short" })
            {
                var invalid = exact.ToArray();
                if (mutation == "version") invalid[5] = 1;
                if (mutation == "body-version") invalid[ContactCoordinationOnionCodec.HeaderBytes + 1] = 2;
                if (mutation == "reserved") invalid[7] = 1;
                if (mutation == "target") invalid[6] = 3;
                if (mutation == "length") invalid[11] ^= 1;
                if (mutation == "trailing") invalid = invalid.Append((byte)0).ToArray();
                if (mutation == "short") invalid = invalid[..8];
                Assert.Throws<FormatException>(() => ContactCoordinationOnionCodec.DecodeRequest(invalid));
                RejectCanonical(() => OnionTerminalPayloadVerifierV1.VerifyRequest(
                    fixture.NetworkContext, OnionOperation.ContactResolve, invalid));
            }
            RejectCanonical(() => OnionTerminalPayloadVerifierV1.VerifyRequest(
                fixture.NetworkContext, OnionOperation.Store, exact));
            var crossNetwork = exact.ToArray(); crossNetwork[ContactCoordinationOnionCodec.HeaderBytes + 8] ^= 1;
            Assert.Throws<CryptographicException>(() => ContactCoordinationOnionCodec.DecodeRequest(crossNetwork));
            var wrappedResponse = ContactCoordinationOnionCodec.EncodeResponse(parsed, response);
            wrappedResponse[6] = target == ContactCoordinationTarget.Route ? (byte)2 : (byte)1;
            Assert.Throws<FormatException>(() => ContactCoordinationOnionCodec.DecodeResponse(parsed, wrappedResponse));
            Assert.Equal(count, calls);
        }
        Assert.Equal(2, calls);
        Assert.Empty(logger.Entries);
        var pending = OnionTerminalPayloadVerifierV1.VerifyRequest(fixture.NetworkContext,
            OnionOperation.ContactResolve, ContactCoordinationOnionCodec.EncodeRequest(ContactCoordinationTarget.Route, routeBody));
        var badProjection = routeBody.ToArray();
        var offset = FindField(request.ExactXra1.Span, 5);
        badProjection[601 + offset + 37] ^= 1;
        var foreignProjection = OnionTerminalPayloadVerifierV1.VerifyRequest(fixture.NetworkContext,
            OnionOperation.ContactResolve, ContactCoordinationOnionCodec.EncodeRequest(ContactCoordinationTarget.Route, badProjection));
        Assert.Equal(NativeMailboxDispatchCertainty.RejectedBeforeForward,
            (await dispatcher.DispatchAsync(foreignProjection, default)).Certainty);
        Assert.Equal("DID2 coordination rejected: phase=CurrentnessBefore, check=Projection, certainty=RejectedBeforeForward, category=cryptographic.", logger.Entries[^1]);
        var warningCount = logger.Entries.Count;
        Assert.Equal(NativeMailboxDispatchCertainty.RejectedBeforeForward,
            (await dispatcher.DispatchAsync(foreignProjection, default)).Certainty);
        Assert.Equal(warningCount, logger.Entries.Count); // Bounded metadata, unchanged rejection.
        Assert.Equal(2, calls);
        var missingNode = new RouterNodeOptions { RouterId = new string('f', 64) };
        var foreign = new ContactCoordinationOnionDispatcher(fixture, backend, missingNode, fixture, logger);
        Assert.Equal(NativeMailboxDispatchCertainty.RejectedBeforeForward,
            (await foreign.DispatchAsync(pending, default)).Certainty);
        Assert.Equal("DID2 coordination rejected: phase=CurrentnessBefore, check=Gateway, certainty=RejectedBeforeForward, category=cryptographic.", logger.Entries[^1]);
        fixture.RejectProof = true;
        Assert.Equal(NativeMailboxDispatchCertainty.RejectedBeforeForward,
            (await dispatcher.DispatchAsync(pending, default)).Certainty);
        Assert.Equal("DID2 coordination rejected: phase=AuthorityBefore, check=None, certainty=RejectedBeforeForward, category=cryptographic.", logger.Entries[^1]);
        fixture.RejectProof = false; Assert.Equal(2, calls);
        corruptPair = true;
        Assert.Equal(NativeMailboxDispatchCertainty.OutcomeUnknownAfterForward,
            (await dispatcher.DispatchAsync(pending, default)).Certainty);
        // The bounded backend intentionally converts malformed response pairing
        // to IOException without retaining its exception text.
        Assert.Equal("DID2 coordination rejected: phase=Backend, check=None, certainty=OutcomeUnknownAfterForward, category=io.", logger.Entries[^1]);
        corruptPair = false; rejectAfterForward = true;
        Assert.Equal(NativeMailboxDispatchCertainty.OutcomeUnknownAfterForward,
            (await dispatcher.DispatchAsync(pending, default)).Certainty);
        Assert.Equal("DID2 coordination rejected: phase=AuthorityAfter, check=None, certainty=OutcomeUnknownAfterForward, category=cryptographic.", logger.Entries[^1]);
        fixture.RejectProof = false; rejectAfterForward = false;
        fixture.Sample = 500;
        Assert.Equal(NativeMailboxDispatchCertainty.RejectedBeforeForward,
            (await dispatcher.DispatchAsync(pending, default)).Certainty);
        Assert.Equal("DID2 coordination rejected: phase=CurrentnessBefore, check=ProofFreshness, certainty=RejectedBeforeForward, category=cryptographic.", logger.Entries[^1]);
        Assert.Equal(4, calls);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        warningCount = logger.Entries.Count;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => dispatcher.DispatchAsync(pending, cancelled.Token));
        Assert.Equal(4, calls);
        Assert.Equal(warningCount, logger.Entries.Count);
        Assert.All(logger.Entries, entry => Assert.DoesNotContain("Current test DID2 proof unavailable", entry));
    }

    [Fact]
    public void ConfigurationNeverActivatesPartialDirectOrUnverifiedComposition()
    {
        Assert.Null(new ContactCoordinationOptions().Validate(false, false));
        Assert.Throws<InvalidOperationException>(() => new ContactCoordinationOptions { BackendOrigin = "https://authority.example/" }.Validate(true, true));
        foreach (var origin in new[] { "http://authority.example/", "https://authority.example/path", "https://u:p@authority.example/", "https://authority.example/?x=1", "https://authority.example/#x" })
            Assert.Throws<InvalidOperationException>(() => new ContactCoordinationOptions { Enabled = true, BackendOrigin = origin }.Validate(true, true));
        var valid = new ContactCoordinationOptions { Enabled = true, BackendOrigin = "https://authority.example/" };
        Assert.Throws<InvalidOperationException>(() => valid.Validate(false, true));
        Assert.Throws<InvalidOperationException>(() => valid.Validate(true, false));
        Assert.Equal(new Uri("https://authority.example/"), valid.Validate(true, true));
    }

    private static int FindField(ReadOnlySpan<byte> exact, ushort tag)
    {
        for (var offset = 12; offset < exact.Length;)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(offset + 4, 4)));
            if (BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(offset, 2)) == tag) return offset + 8;
            offset += 8 + length;
        }
        throw new InvalidOperationException("Missing fixture field.");
    }
    private static void RejectCanonical(Action validate)
    {
        // The canonical verifier's closed parser exception is assembly-internal.
        // Assert its exact existing type, not a catch-all exception/early return.
        var error = Record.Exception(validate);
        Assert.NotNull(error);
        Assert.Equal("Deep.Protocol.DeepExtension.PrivacyRouting.PrivacyRoutingProtocolException", error.GetType().FullName);
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct); }

    private sealed class DiagnosticLogger : ILogger<ContactCoordinationOnionDispatcher>
    {
        internal List<string> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Assert.Equal(LogLevel.Warning, logLevel);
            Assert.Null(exception);
            Entries.Add(formatter(state, exception));
        }
    }
}
