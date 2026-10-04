using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.ApplicationCore;
using Sodium;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2OpaquePublicationConsumerTests
{
    [Fact]
    public async Task DirectoryAdmissionKeepsRetainedContactRouteCurrentWithoutReminting()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        using var additional = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var placements = new VerifiedContactServicePlacementAuthoritySource(ceremony, ceremony);
        var published = ceremony.ContactPublication;
        var publicationPlacement = await placements.MintAsync(ContactServiceRequestKind.PublishInvite, published.LocatorHash, default);
        var root = Path.Combine(Path.GetTempPath(), "did2-directory-anchor-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
        ReadOnlyMemory<byte> commit;
        using (var publisher = OpenFacade(root, verifier, publicationPlacement, ceremony))
            commit = await publisher.DispatchAsync(ContactServiceFacadeOperation.PublishDcr, published.CanonicalBytes, default);
        var originalIdentity = ceremony.Freshness.CurrentCheckpoint!.Binding.Record.CanonicalBytes.ToArray();
        var priorHead = ceremony.Freshness.ExactAdh1.ToArray();
        var priorRecipient = ceremony.ContactRoute.Recipient;
        var current = await ceremony.AdvanceDirectoryWithAnotherAccountAsync(additional.Freshness.CurrentCheckpoint!);
        Assert.Equal(originalIdentity, ceremony.Freshness.CurrentCheckpoint!.Binding.Record.CanonicalBytes.ToArray());
        Assert.False(priorHead.AsSpan().SequenceEqual(ceremony.Freshness.ExactAdh1.Span));
        var query = await DeepIdV2PermanentContactResolveRequestAuthor.AuthorAsync(ceremony.ContactAddress,
            current, ceremony.NetworkContext, ceremony.Authority, new(ceremony));
        // DR42: retained audit anchor is not latest mutable ADH authority.
        // New issuance must still reject this old-head threshold below.
        var retained = await DeepIdV2ContactRouteVerifier.VerifyAsync(current, ceremony.NetworkContext, ceremony.Authority,
            ceremony.ContactRoute.ExactXir1V2, ceremony.ContactRoute.ExactRouteClosure, new(ceremony));
        Assert.Equal(ceremony.ContactRoute.ExactRouteClosure.ToArray(), retained.ExactRouteClosure.ToArray());
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2ContactRouteVerifier.VerifyAsync(priorRecipient, ceremony.NetworkContext, ceremony.Authority,
                retained.ExactXir1V2, retained.ExactRouteClosure, new(ceremony)));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2ContactRouteVerifier.VerifyThresholdAsync(current, ceremony.NetworkContext, ceremony.Authority,
                retained.Route.Authorization.CanonicalBytes, new(retained.Route.Selection.CanonicalBytes.Span,
                    retained.Route.Route.CanonicalBytes.Span, retained.Route.Successor.CanonicalBytes.Span), new(ceremony)));
        // The original ciphertext/commit survive a real directory admission
        // and two-store restart. No republish or new ciphertext is involved.
        var resolvePlacement = await placements.MintAsync(ContactServiceRequestKind.ResolveInvite, query.LocatorHash, default);
        ReadOnlyMemory<byte> exactResult;
        using (var resolver = OpenFacade(root, verifier, resolvePlacement, ceremony))
            exactResult = await resolver.DispatchAsync(ContactServiceFacadeOperation.ResolveDcr, query.CanonicalBytes, default);
        var candidate = DeepIdV2PermanentContactResolveVerifier.OpenCandidate(ceremony.ContactAddress, query.CanonicalBytes, exactResult);
        var resolved = await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate, ceremony.Freshness,
            ceremony.NetworkContext, ceremony.Authority, new(ceremony));
        Assert.Equal(ceremony.ContactObject.Closure.CanonicalBytes.ToArray(), resolved.Contact.CanonicalBytes.ToArray());
        Assert.Equal(ceremony.ContactObject.ProtectedDcr1.ToArray(), candidate.Result.Field(19).ToArray());
        var restored = await DeepIdV2ContactObjectAuthor.RestoreAsync(retained, ceremony.ContactObject.Closure.CanonicalBytes,
            ceremony.ContactObject.ProtectedDcr1, ceremony.ContactAddress.ResolverReadCapability);
        var historical = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(retained, restored,
            ceremony.ContactOwnedRequest, published.CanonicalBytes, commit);
        Assert.Equal(commit.ToArray(), historical.ExactXpo1.ToArray());
        var forged = exactResult.ToArray(); forged[FieldOffset(forged, 22) + 192] ^= 1;
        var forgedCandidate = DeepIdV2PermanentContactResolveVerifier.OpenCandidate(ceremony.ContactAddress,
            query.CanonicalBytes, forged);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(forgedCandidate, ceremony.Freshness,
                ceremony.NetworkContext, ceremony.Authority, new(ceremony)));
        // Historical commit is not fresh dispatch authorization after ADH moves.
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(retained,
                ceremony.ContactOwnedRequest, published.CanonicalBytes));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task RealDid2PublicationResolvesFromCompactAddressAndActualTwoNodeRead()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var placements = new VerifiedContactServicePlacementAuthoritySource(ceremony, ceremony);
        var published = ceremony.ContactPublication;
        var publicationPlacement = await placements.MintAsync(ContactServiceRequestKind.PublishInvite, published.LocatorHash, default);
        var root = Path.Combine(Path.GetTempPath(), "did2-permanent-read-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using (var publisher = OpenFacade(root, verifier, publicationPlacement, ceremony))
                _ = await publisher.DispatchAsync(ContactServiceFacadeOperation.PublishDcr, published.CanonicalBytes, default);
            var query = await DeepIdV2PermanentContactResolveRequestAuthor.AuthorAsync(ceremony.ContactAddress,
                ceremony.ContactRoute.Recipient, ceremony.NetworkContext, ceremony.Authority, new(ceremony));
            Assert.Equal(312, query.CanonicalBytes.Length);
            Assert.Equal(published.LocatorHash.ToArray(), query.LocatorHash.ToArray());
            var resolvePlacement = await placements.MintAsync(ContactServiceRequestKind.ResolveInvite, query.LocatorHash, default);
            ReadOnlyMemory<byte> exactResult;
            using (var resolver = OpenFacade(root, verifier, resolvePlacement, ceremony))
                exactResult = await resolver.DispatchAsync(ContactServiceFacadeOperation.ResolveDcr, query.CanonicalBytes, default);
            var candidate = DeepIdV2PermanentContactResolveVerifier.OpenCandidate(ceremony.ContactAddress,
                query.CanonicalBytes, exactResult);
            Assert.Equal(ceremony.Publisher.CanonicalBytes.ToArray(), candidate.ExactDid2.CanonicalBytes.ToArray());
            var verified = await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate, ceremony.Freshness,
                ceremony.NetworkContext, ceremony.Authority, new(ceremony));
            Assert.Equal(published.ExactRouteClosure.ToArray(), verified.Route.ExactRouteClosure.ToArray());
            Assert.Equal(ceremony.ContactObject.Closure.CanonicalBytes.ToArray(), verified.Contact.CanonicalBytes.ToArray());
            Assert.Equal(0ul, verified.PublicationGeneration);
            var observed = await verified.Route.ReadCurrentTimeAsync();
            Assert.Equal(ceremony.Sample, observed.MonotonicSample);
            Assert.Equal(DeepIdV2PublicationAuthorityFixture.Boot, observed.BootId.ToArray());
            var exposedBoot = observed.BootId.ToArray(); exposedBoot[0] ^= 1;
            Assert.Equal(DeepIdV2PublicationAuthorityFixture.Boot, observed.BootId.ToArray());
            using var other = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate, other.Freshness,
                    ceremony.NetworkContext, ceremony.Authority, new(ceremony)));
            Assert.Throws<CryptographicException>(() => DeepIdV2PermanentContactResolveVerifier.OpenCandidate(
                other.ContactAddress, query.CanonicalBytes, exactResult));
            Assert.Throws<CryptographicException>(() => DeepIdV2PermanentContactResolveVerifier.OpenCandidate(
                ceremony.ContactAddress, new byte[313], exactResult));
            Assert.Throws<CryptographicException>(() => DeepIdV2PermanentContactResolveVerifier.OpenCandidate(
                ceremony.ContactAddress, query.CanonicalBytes, new byte[131_073]));
            var notFound = Xis1Codec.Encode(query.CanonicalBytes.Span, Xis1Status.NotFound,
                ContactServiceMutationOutcome.None, 1_100, 0, ContactServicePaddingClass.Bytes256, []);
            Assert.Throws<CryptographicException>(() => DeepIdV2PermanentContactResolveVerifier.OpenCandidate(
                ceremony.ContactAddress, query.CanonicalBytes, notFound));
            // The neutral receipts do not sign serverTime; changing it cannot
            // move any authenticated current identity/time boundary.
            var serverClock = exactResult.ToArray();
            BinaryPrimitives.WriteUInt64BigEndian(serverClock.AsSpan(FieldOffset(serverClock, 6)), ulong.MaxValue);
            var unsignedClock = DeepIdV2PermanentContactResolveVerifier.OpenCandidate(ceremony.ContactAddress,
                query.CanonicalBytes, serverClock);
            var unaffected = await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(unsignedClock,
                ceremony.Freshness, ceremony.NetworkContext, ceremony.Authority, new(ceremony));
            Assert.Equal(verified.Authorization.TrustedUpperUnixSeconds, unaffected.Authorization.TrustedUpperUnixSeconds);
            var counter = new ResolveClock(_ => new(DeepIdV2PublicationAuthorityFixture.Boot, ceremony.Sample));
            _ = await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate, ceremony.Freshness,
                ceremony.NetworkContext, ceremony.Authority, new(counter));
            var releaseRead = counter.Calls; Assert.True(releaseRead >= 2);
            foreach (var last in new[]
            {
                new OnionMonotonicReading(DeepIdV2PublicationAuthorityFixture.Bytes(16, 0x77), ceremony.Sample),
                new OnionMonotonicReading(DeepIdV2PublicationAuthorityFixture.Boot, ceremony.Sample - 1),
                new OnionMonotonicReading(DeepIdV2PublicationAuthorityFixture.Boot, ceremony.Freshness.FreshnessDeadlineMonotonicSeconds)
            })
            {
                var interrupted = new ResolveClock(call => call == releaseRead ? last :
                    new(DeepIdV2PublicationAuthorityFixture.Boot, ceremony.Sample));
                await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                    await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate, ceremony.Freshness,
                        ceremony.NetworkContext, ceremony.Authority, new(interrupted)));
            }
            var reversed = new ResolveClock(call => new(DeepIdV2PublicationAuthorityFixture.Boot,
                call == 1 ? ceremony.Sample + 1 : ceremony.Sample));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate, ceremony.Freshness,
                    ceremony.NetworkContext, ceremony.Authority, new(reversed)));
            var receipts = exactResult.ToArray(); receipts[FieldOffset(receipts, 22) + 192] ^= 1;
            var corrupt = DeepIdV2PermanentContactResolveVerifier.OpenCandidate(ceremony.ContactAddress,
                query.CanonicalBytes, receipts);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(corrupt, ceremony.Freshness,
                    ceremony.NetworkContext, ceremony.Authority, new(ceremony)));
            var malformed = exactResult.ToArray(); malformed[FieldOffset(malformed, 19)] ^= 1;
            Assert.Throws<ContactFormatException>(() => DeepIdV2PermanentContactResolveVerifier.OpenCandidate(
                ceremony.ContactAddress, query.CanonicalBytes, malformed));
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate, ceremony.Freshness,
                    ceremony.NetworkContext, ceremony.Authority, new(ceremony), cancelled.Token));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task RealDid2AuthorizationCommitsOpaqueObjectAndReplaysAfterRestart()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var request = ceremony.ContactPublication;
        var proof = await verifier.VerifyAsync(request, default);
        await proof.EnsureCurrentAsync();
        Assert.Equal(request.RequestHash.ToArray(), proof.RequestHash.ToArray());
        Assert.Equal(0ul, proof.Generation);
        var root = Path.Combine(Path.GetTempPath(), "did2-opaque-publication-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using (var runtime = Open(root, verifier))
            {
                var result = await runtime.Service.PublishAsync(request, default);
                Assert.Equal(ContactResolverMutationDisposition.Committed, result.Disposition);
            }
            using (var runtime = Open(root, verifier))
            {
                var result = await runtime.Service.PublishAsync(request, default);
                Assert.Equal(ContactResolverMutationDisposition.ExactReplay, result.Disposition);
                var stored = await runtime.Replica.ResolveCurrentDcrAsync(request.LocatorHash, default);
                Assert.Equal(ContactResolverReadDisposition.Current, stored.Disposition);
                Assert.Equal(request.ObjectCiphertextHash.ToArray(), stored.Publication!.ObjectCiphertextHash);
                ceremony.RejectProof = true;
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await runtime.Service.PublishAsync(request, default));
                ceremony.RejectProof = false;
                ceremony.Sample += 120;
                await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () =>
                    await proof.EnsureCurrentAsync());
                await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () =>
                    await runtime.Service.PublishAsync(request, default));
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static Runtime Open(string root, IContactPublicationAuthorizationVerifier verifier)
    {
        var clock = new FixedClock();
        var store = new ContactResolverOpaqueStore(Path.Combine(root, "resolver.state"), clock: clock);
        var replica = new ContactResolverStoreReplica(Enumerable.Repeat((byte)0x51, 32).ToArray(), store);
        var saga = new ContactPublicationAuthorizationSaga(Path.Combine(root, "publication.state"),
            Path.Combine(root, "publication.key"));
        return new(store, saga, replica, new ContactAuthorizedPublicationReplica(replica, verifier, saga, clock));
    }

    [Fact]
    public async Task RealDid2PublicationBindsTwoDurableReceiptsAndResponseLossReplay()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var request = ceremony.ContactPublication;
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var placements = new VerifiedContactServicePlacementAuthoritySource(ceremony, ceremony);
        var placement = await placements.MintAsync(ContactServiceRequestKind.PublishInvite, request.LocatorHash, default);
        var root = Path.Combine(Path.GetTempPath(), "did2-dual-publication-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // The response is deliberately discarded: only exact durable replay may recover it.
            using (var facade = OpenFacade(root, verifier, placement, ceremony))
            {
                var first = Xpo1Codec.Decode((await facade.DispatchAsync(ContactServiceFacadeOperation.PublishDcr,
                    request.CanonicalBytes, default)).Span, request.CanonicalBytes.Span);
                Assert.Equal(Xpo1Status.Committed, first.Status);
                VerifyReceipts(first, request, placement);
                var owned = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(ceremony.ContactRoute,
                    ceremony.ContactObject, ceremony.ContactOwnedRequest, request.CanonicalBytes, first.WireBytes);
                Assert.Equal(first.WireBytes.ToArray(), owned.ExactXpo1.ToArray());
                Assert.Equal(request.RequestHash.ToArray(), owned.RequestHash.ToArray());
                Assert.Equal(request.ObjectCiphertextHash.ToArray(), owned.ObjectCiphertextHash.ToArray());
                var exposed = owned.ExactXpo1.ToArray(); exposed[0] ^= 1;
                Assert.Equal(first.WireBytes.ToArray(), owned.ExactXpo1.ToArray());
                var badReceipt = first.WireBytes.ToArray();
                badReceipt[FieldOffset(badReceipt, 19) + 192] ^= 1;
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(ceremony.ContactRoute,
                        ceremony.ContactObject, ceremony.ContactOwnedRequest, request.CanonicalBytes, badReceipt));
                var unavailable = Xpo1Codec.Encode(request.CanonicalBytes.Span, Xpo1Status.TemporarilyUnavailable,
                    ContactServiceMutationOutcome.None, 1_100, 0, ContactServicePaddingClass.Bytes256, []);
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(ceremony.ContactRoute,
                        ceremony.ContactObject, ceremony.ContactOwnedRequest, request.CanonicalBytes, unavailable));
                var wrongObject = first.Field(17).ToArray(); wrongObject[0] ^= 1;
                var substitutedObject = Xpo1Codec.Encode(request.CanonicalBytes.Span, Xpo1Status.Committed,
                    ContactServiceMutationOutcome.DurablyCommitted, 1_100, 0, ContactServicePaddingClass.Bytes1024,
                    [first.Field(16), wrongObject, first.Field(18), first.Field(19)]);
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(ceremony.ContactRoute,
                        ceremony.ContactObject, ceremony.ContactOwnedRequest, request.CanonicalBytes, substitutedObject));
                // Genuine authority over the same body is not this request's commit.
                await Assert.ThrowsAsync<ContactFormatException>(async () =>
                    await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(ceremony.ContactRoute,
                        ceremony.ContactObject, ceremony.ContactOwnedRequest,
                        ceremony.AlternateContactPublication.CanonicalBytes, first.WireBytes));
            }
            using (var facade = OpenFacade(root, verifier, placement, ceremony))
            {
                var replay = Xpo1Codec.Decode((await facade.DispatchAsync(ContactServiceFacadeOperation.PublishDcr,
                    request.CanonicalBytes, default)).Span, request.CanonicalBytes.Span);
                Assert.Equal(Xpo1Status.ExactReplay, replay.Status);
                VerifyReceipts(replay, request, placement);
                _ = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(ceremony.ContactRoute,
                    ceremony.ContactObject, ceremony.ContactOwnedRequest, request.CanonicalBytes, replay.WireBytes);
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(ceremony.ContactRoute,
                        ceremony.ContactObject, ceremony.ContactOwnedRequest, request.CanonicalBytes,
                        replay.WireBytes, cancelled.Token));
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(ceremony.ContactRoute,
                        ceremony.ContactObject, ceremony.ContactOwnedRequest, request.CanonicalBytes, new byte[16_385]));
                // Reissue an actual nonce-bound directory proof, without changing
                // the published object/route or pretending the old proof is fresh.
                var afterDispatch = checked(request.ExpiresAtUnixSeconds + 10);
                var currentRoute = await ceremony.RefreshContactProofAsync(100 + afterDispatch - 1_100, afterDispatch);
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(currentRoute,
                        ceremony.ContactOwnedRequest, request.CanonicalBytes));
                var historical = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(currentRoute,
                    ceremony.ContactObject, ceremony.ContactOwnedRequest, request.CanonicalBytes, replay.WireBytes);
                Assert.Equal(replay.WireBytes.ToArray(), historical.ExactXpo1.ToArray());
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static ContactServiceOpaqueFacade OpenFacade(string root,
        IContactPublicationAuthorizationVerifier verifier, ContactServicePlacementCapability placement,
        DeepIdV2PublicationAuthorityFixture ceremony)
    {
        var receipts = placement.ReplicaIds.Select(id => new LocalContactServiceReplicaReceiptAuthority(
            id.Span, ceremony.Node(id.Span).Seed)).ToArray();
        return new ContactServiceOpaqueFacade(ceremony.NetworkContext, Path.Combine(root, "a.state"), Path.Combine(root, "b.state"),
            Path.Combine(root, "pa.state"), Path.Combine(root, "pb.state"), receipts,
            new ExactContactRequestContextVerifier(placement), verifier, new FixedClock());
    }

    private static void VerifyReceipts(Xpo1Result result, Xpu1Request request,
        ContactServicePlacementCapability placement)
    {
        Assert.Equal(request.RequestHash.ToArray(), result.RequestHash.ToArray());
        Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, result.MutationOutcome);
        Assert.Equal(request.ObjectCiphertextHash.ToArray(), result.Field(17).ToArray());
        Assert.Equal(1ul, BinaryPrimitives.ReadUInt64BigEndian(result.Field(18).Span));
        var tuple = request.RequestHash.ToArray().Concat(request.ObjectCiphertextHash.ToArray())
            .Concat(result.Field(18).ToArray()).ToArray();
        var signingInput = ContactServiceReceiptTranscript.SigningInput(
            new(ContactServiceReceiptKind.PublishCommit, tuple));
        var receipts = result.Field(19).ToArray();
        Assert.Equal(2, receipts[0]);
        for (var i = 0; i < 2; i++)
        {
            var id = receipts.AsSpan(1 + i * 96, 32).ToArray();
            Assert.Contains(placement.ReplicaIds, value => value.Span.SequenceEqual(id));
            Assert.True(PublicKeyAuth.VerifyDetached(receipts.AsSpan(33 + i * 96, 64).ToArray(), signingInput,
                placement.VerifiedPlacement.Network.ResolveNodeIdentityPublicKey(id).ToArray()));
        }
    }

    [Fact]
    public async Task SoleV2CodecRoundTripsAndRejectsDowngradeBodyAndWitnessSubstitution()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var request = ceremony.ContactPublication;
        var exact = Xpu1Codec.Encode(request.NetworkId.Span, request.OperationId.Span, request.ViewHash.Span,
            request.PlacementHash.Span, request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds,
            request.LocatorHash.Span, request.Xir1Hash.Span, request.Generation, request.PredecessorObjectHash.Span,
            request.ObjectCiphertext.Span, request.UsageLimit, request.EffectiveExpiresAtUnixSeconds,
            request.ExactRouteClosure.Span, request.ExactXpa1.Span, request.OwnerRetrieveCapability.Span);
        Assert.Equal(request.CanonicalBytes.ToArray(), exact);
        Assert.Equal(request.AuthorizedBodyHash.ToArray(), Xpu1Codec.ComputeAuthorizedBodyHash(request.NetworkId.Span,
            request.OperationId.Span, request.ViewHash.Span, request.PlacementHash.Span, request.IssuedAtUnixSeconds,
            request.ExpiresAtUnixSeconds, request.LocatorHash.Span, request.Xir1Hash.Span, request.Generation,
            request.PredecessorObjectHash.Span, request.ObjectCiphertext.Span, request.UsageLimit,
            request.EffectiveExpiresAtUnixSeconds, request.ExactRouteClosure.Span, request.OwnerRetrieveCapability.Span));
        foreach (var headerOffset in new[] { 5, 6, 7, 10, 11 })
        {
            var changed = exact.ToArray(); changed[headerOffset] ^= 1;
            Assert.Throws<ApplicationCoreFormatException>(() => Xpu1Codec.Decode(changed));
        }
        foreach (var tag in new ushort[] { 2, 21, 25, 27 })
        {
            var changed = exact.ToArray(); changed[FieldOffset(changed, tag)] ^= 1;
            Assert.Throws<ApplicationCoreFormatException>(() => Xpu1Codec.Decode(changed));
        }
        var badWitness = exact.ToArray();
        badWitness[FieldOffset(badWitness, 26) + request.ExactXpa1.Length - 1] ^= 1;
        var parsed = Xpu1Codec.Decode(badWitness); // Grammar does not authenticate signatures.
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () =>
            await verifier.VerifyAsync(parsed, default));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await verifier.VerifyAsync(request, cancelled.Token));
    }

    [Fact]
    public async Task AuthorityRejectsWrongPlacementAndClockDiscontinuityAtRelease()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var request = ceremony.ContactPublication;
        var placement = ContactServicePlacementFactory.Create(ceremony.NetworkContext,
            ContactServiceRequestKind.PublishInvite, request.LocatorHash);
        var wrong = ContactServicePlacementFactory.Create(ceremony.NetworkContext,
            ContactServiceRequestKind.PublishInvite, DeepIdV2PublicationAuthorityFixture.Bytes(32, 0x7a));
        await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () =>
            await Xpa1PublicationAuthorizationVerifier.VerifyAsync(request, ceremony.Authority, ceremony.Freshness,
                wrong, new(ceremony), default));
        foreach (var final in new[]
        {
            new OnionMonotonicReading(DeepIdV2PublicationAuthorityFixture.Bytes(16, 0x7b), 100),
            new OnionMonotonicReading(DeepIdV2PublicationAuthorityFixture.Boot, 99),
            new OnionMonotonicReading(DeepIdV2PublicationAuthorityFixture.Boot, 220)
        })
        {
            ceremony.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 100));
            ceremony.ClockReadings.Enqueue(final);
            await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () =>
                await Xpa1PublicationAuthorizationVerifier.VerifyAsync(request, ceremony.Authority, ceremony.Freshness,
                    placement, new(ceremony), default));
            Assert.Empty(ceremony.ClockReadings);
        }
        ceremony.Sample = 105;
        var minted = await new VerifiedContactPublicationAuthorizationVerifier(ceremony).VerifyAsync(request, default);
        ceremony.Sample = 102; // Still within original proof window, but before this capability's mint.
        await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () => await minted.EnsureCurrentAsync());
    }

    private static int FieldOffset(byte[] bytes, ushort wanted)
    {
        var offset = 12;
        for (var i = 0; i < BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(8)); i++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset + 4)));
            offset += 8;
            if (tag == wanted) return offset;
            offset += length;
        }
        throw new InvalidDataException("Test field is absent.");
    }

    [Fact]
    public async Task ReplicaReceiptRechecksCurrentAuthorityAndExactCommittedRequest()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var request = ceremony.ContactPublication;
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var clock = new FixedClock();
        var placements = new VerifiedContactServicePlacementAuthoritySource(ceremony, ceremony);
        var placement = await placements.MintAsync(ContactServiceRequestKind.PublishInvite, request.LocatorHash, default);
        var localId = placement.ReplicaIds[0].ToArray();
        var sender = RouterId.FromBytes(placement.ReplicaIds[1].ToArray());
        var root = Path.Combine(Path.GetTempPath(), "did2-peer-publication-" + Guid.NewGuid().ToString("N"));
        var node = new RouterNodeOptions { DataDirectory = root, RouterId = Convert.ToHexString(localId),
            Ed25519PrivateKey = Convert.ToHexString(ceremony.Node(localId).Seed) };
        try
        {
            using var runtime = new ContactServiceLocalReplicaRuntime(node, clock,
                new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
            var receiver = new ContactReplicaRequestReceiver(node, new(placements, verifier), runtime, clock);
            ContactReplicaRpcCommand Command(ContactReplicaRpcOperation operation, byte[] payload) =>
                new(placement, operation, DeepIdV2PublicationAuthorityFixture.Bytes(32, 0x53), payload);
            var publish = ContactReplicaPayloadCodec.EncodeAuthorizedPublish(request.CanonicalBytes.Span);
            var committed = await receiver.ReceiveAsync(Command(ContactReplicaRpcOperation.PublishDcr, publish), sender, default);
            Assert.Equal(ContactResolverMutationDisposition.Committed,
                ContactReplicaPayloadCodec.DecodeMutation(committed.Payload.Span).Disposition);

            byte[] ReceiptPayload(Xpu1Request exact)
            {
                var generation = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(generation, 1);
                var tuple = exact.RequestHash.ToArray().Concat(exact.ObjectCiphertextHash.ToArray()).Concat(generation).ToArray();
                return ContactReplicaPayloadCodec.EncodeReceiptRequest(new(ContactServiceReceiptKind.PublishCommit, tuple),
                    ContactReplicaRpcOperation.PublishDcr, ContactReplicaPayloadCodec.EncodeAuthorizedPublish(exact.CanonicalBytes.Span));
            }
            var valid = await receiver.ReceiveAsync(Command(ContactReplicaRpcOperation.IssueReceipt, ReceiptPayload(request)), sender, default);
            Assert.Equal(localId, ContactReplicaPayloadCodec.DecodeReceipt(valid.Payload.Span).ReplicaId.ToArray());
            var substituted = request.CanonicalBytes.ToArray();
            substituted[FieldOffset(substituted, 26) + request.ExactXpa1.Length - 1] ^= 1;
            var forged = Xpu1Codec.Decode(substituted);
            await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () =>
                await receiver.ReceiveAsync(Command(ContactReplicaRpcOperation.IssueReceipt, ReceiptPayload(forged)), sender, default));
            // A second genuine threshold subset is valid, but it was never committed here.
            _ = await verifier.VerifyAsync(ceremony.AlternateContactPublication, default);
            Assert.NotEqual(request.RequestHash.ToArray(), ceremony.AlternateContactPublication.RequestHash.ToArray());
            await Assert.ThrowsAsync<ContactServiceReceiptAuthorityException>(async () =>
                await receiver.ReceiveAsync(Command(ContactReplicaRpcOperation.IssueReceipt,
                    ReceiptPayload(ceremony.AlternateContactPublication)), sender, default));
            ceremony.Sample += 120;
            await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () =>
                await receiver.ReceiveAsync(Command(ContactReplicaRpcOperation.IssueReceipt, ReceiptPayload(request)), sender, default));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private sealed class FixedClock : IClock
    { public DateTimeOffset UtcNow => DateTimeOffset.FromUnixTimeSeconds(1_100); }

    private sealed class ResolveClock(Func<int, OnionMonotonicReading> read) : IOnionMonotonicClock
    {
        internal int Calls { get; private set; }
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult(read(++Calls)); }
    }

    private sealed record Runtime(ContactResolverOpaqueStore Store, ContactPublicationAuthorizationSaga Saga,
        ContactResolverStoreReplica Replica, ContactAuthorizedPublicationReplica Service) : IDisposable
    { public void Dispose() { Saga.Dispose(); Store.Dispose(); } }
}
