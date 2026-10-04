using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ContactV1;
using Rebex.Security.Cryptography;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactServiceOpaqueFacadeTests : IClassFixture<CurrentContactPublicationFixture>
{
    private readonly CurrentContactPublicationFixture PublicationAuthorizations;
    public ContactServiceOpaqueFacadeTests(CurrentContactPublicationFixture publicationAuthorizations) =>
        PublicationAuthorizations = publicationAuthorizations;

    [Fact]
    public async Task ContextMismatchDoesNotMutateAndAcceptedPublishDurablyExactReplays()
    {
        using var fixture = new Fixture(PublicationAuthorizations);
        var request = Xpu();
        fixture.Context.Status = ContactRequestContextStatus.StaleView;

        var staleBytes = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var stale = Xpo1Codec.Decode(staleBytes.Span, request);
        Assert.Equal(Xpo1Status.StaleView, stale.Status);

        fixture.Context.Status = ContactRequestContextStatus.Accepted;
        var committedBytes = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var committed = Xpo1Codec.Decode(committedBytes.Span, request);
        Assert.Equal(Xpo1Status.Committed, committed.Status);
        Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, committed.MutationOutcome);
        await PublicationAuthorizations.VerifyCommittedAsync(committed);

        var replayBytes = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var replay = Xpo1Codec.Decode(replayBytes.Span, request);
        Assert.Equal(Xpo1Status.ExactReplay, replay.Status);
        Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, replay.MutationOutcome);
        await PublicationAuthorizations.VerifyCommittedAsync(replay);
    }

    [Fact]
    public async Task ResolveUsesPublishedRouteClosureWithoutExternalLocatorLookup()
    {
        using var fixture = new Fixture(PublicationAuthorizations);
        var publish = Xpu();
        var publication = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, publish);
        Assert.Equal(Xpo1Status.Committed, Xpo1Codec.Decode(publication.Span, publish).Status);
        var resolve = Xiq();

        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ResolveDcr, resolve);
        var decoded = Xis1Codec.Decode(response.Span, resolve);

        Assert.Equal(Xis1Status.Success, decoded.Status);
        Assert.Equal(ContactServiceMutationOutcome.None, decoded.MutationOutcome);
        Assert.Equal(
            Xpu1Codec.Decode(publish).ExactRouteClosure.ToArray(),
            decoded.Field(21).ToArray());
    }

    [Fact]
    public async Task PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays()
    {
        var oneTime = new CurrentContactPublicationFixture(oneTime: true);
        await oneTime.InitializeAsync();
        try
        {
            using var fixture = new Fixture(oneTime);
            var publish = oneTime.Request.CanonicalBytes.ToArray();
            Assert.Equal(1u, oneTime.Request.UsageLimit);
            var publication = await fixture.Facade.DispatchAsync(
                ContactServiceFacadeOperation.PublishDcr, publish);
            Assert.Equal(Xpo1Status.Committed, Xpo1Codec.Decode(publication.Span, publish).Status);
            var resolve = Xiq(operationByte: 31, publication: oneTime);

            var first = await fixture.Facade.DispatchAsync(
                ContactServiceFacadeOperation.ResolveDcr, resolve);
            var decoded = Xis1Codec.Decode(first.Span, resolve);
            Assert.Equal(Xis1Status.Success, decoded.Status);
            Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted,
                decoded.MutationOutcome);
            AssertResolveClaimReceipts(decoded, Xiq1Codec.Decode(resolve));

            fixture.Clock.UtcNow = fixture.Clock.UtcNow.AddSeconds(1);
            var replay = await fixture.Facade.DispatchAsync(
                ContactServiceFacadeOperation.ResolveDcr, resolve);
            Assert.Equal(first.ToArray(), replay.ToArray());
            Assert.Equal(Xis1Status.Success,
                Xis1Codec.Decode(replay.Span, resolve).Status);

            var competing = Xiq(operationByte: 32, publication: oneTime);
            var competingResponse = await fixture.Facade.DispatchAsync(
                ContactServiceFacadeOperation.ResolveDcr, competing);
            Assert.Equal(
                Xis1Status.AlreadyClaimed,
                Xis1Codec.Decode(competingResponse.Span, competing).Status);
        }
        finally { await oneTime.DisposeAsync(); }
    }

    [Fact]
    public async Task MissingPreKeyInventoryReturnsClosedCanonicalStatus()
    {
        using var fixture = new Fixture(PublicationAuthorizations);
        var request = Xpk();
        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ClaimPreKey, request);
        var decoded = Xpc1Codec.Decode(response.Span, request);
        Assert.Equal(Xpc1Status.PreKeysUnavailable, decoded.Status);
    }

    [Fact]
    public async Task RemoteShapedAuthoritiesAreDelegatedAndReceiptsStayCanonicallySorted()
    {
        using var fixture = new InjectedFixture(PublicationAuthorizations);
        var request = Xpu();

        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var decoded = Xpo1Codec.Decode(response.Span, request);

        Assert.Equal(Xpo1Status.Committed, decoded.Status);
        Assert.Equal(1, fixture.FirstAuthority.IssueCount);
        Assert.Equal(1, fixture.SecondAuthority.IssueCount);
        await PublicationAuthorizations.VerifyCommittedAsync(decoded);
        var receipts = decoded.Field(19).Span;
        Assert.Equal(193, receipts.Length);
        Assert.True(receipts.Slice(1, 32).SequenceCompareTo(receipts.Slice(97, 32)) < 0);
    }

    [Fact]
    public async Task CrossReplicaReceiptSubstitutionFailsClosedWithoutReceiptEmission()
    {
        using var fixture = new InjectedFixture(PublicationAuthorizations,
            secondBehavior: ReceiptAuthorityBehavior.SubstituteFirstReplica);
        var request = Xpu();

        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var decoded = Xpo1Codec.Decode(response.Span, request);

        Assert.Equal(Xpo1Status.OutcomeUnknown, decoded.Status);
        Assert.Equal(ContactServiceMutationOutcome.OutcomeUnknown, decoded.MutationOutcome);
        Assert.True(decoded.Field(19).IsEmpty);
    }

    [Fact]
    public async Task InvalidSignatureSizeFailsClosedWithoutReceiptEmission()
    {
        using var fixture = new InjectedFixture(PublicationAuthorizations,
            secondBehavior: ReceiptAuthorityBehavior.InvalidSignatureSize);
        var request = Xpu();

        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var decoded = Xpo1Codec.Decode(response.Span, request);

        Assert.Equal(Xpo1Status.OutcomeUnknown, decoded.Status);
        Assert.True(decoded.Field(19).IsEmpty);
    }

    [Fact]
    public async Task PartialAuthorityFailureNeverEmitsTheSuccessfulPartialReceipt()
    {
        using var fixture = new InjectedFixture(PublicationAuthorizations,
            secondBehavior: ReceiptAuthorityBehavior.Unavailable);
        var request = Xpu();

        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var decoded = Xpo1Codec.Decode(response.Span, request);

        Assert.Equal(1, fixture.FirstAuthority.IssueCount);
        Assert.Equal(1, fixture.SecondAuthority.IssueCount);
        Assert.Equal(Xpo1Status.OutcomeUnknown, decoded.Status);
        Assert.True(decoded.Field(19).IsEmpty);
    }

    [Fact]
    public async Task ReceiptIssuanceHonorsCallerCancellationWithoutReturningAResponse()
    {
        using var fixture = new InjectedFixture(PublicationAuthorizations,
            secondBehavior: ReceiptAuthorityBehavior.WaitForCancellation);
        using var cancellation = new CancellationTokenSource();
        var pending = fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, Xpu(), cancellation.Token).AsTask();
        try
        {
            await Task.WhenAny(pending, fixture.SecondAuthority.ReceiptEntered)
                .WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(fixture.SecondAuthority.ReceiptEntered.IsCompletedSuccessfully,
                "The cancellation scenario must reach the second receipt authority.");
        }
        finally
        {
            cancellation.Cancel();
        }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
        Assert.Equal(1, fixture.FirstAuthority.IssueCount);
        Assert.Equal(1, fixture.SecondAuthority.IssueCount);
    }

    [Fact]
    public void ReplicaBindingsRejectMismatchedAndDuplicateAuthorityIds()
    {
        using var first = new LocalContactServiceReplicaReceiptAuthority(B(32, 41));
        using var second = new LocalContactServiceReplicaReceiptAuthority(B(32, 42));
        var firstAuthority = new RecordingReceiptAuthority(first, first);
        var secondAuthority = new RecordingReceiptAuthority(second, first);
        var firstId = first.ReplicaId;
        var secondId = second.ReplicaId;

        Assert.Throws<ArgumentException>(() => CreateIdentityFacade(
        [
            Binding(firstId, secondId, firstAuthority),
            Binding(secondId, secondId, secondAuthority)
        ]));

        Assert.Throws<ArgumentException>(() => CreateIdentityFacade(
        [
            Binding(firstId, firstId, firstAuthority),
            Binding(firstId, firstId, firstAuthority)
        ]));

        var shapeShiftingSingleAuthority = new AlternatingIdentityReceiptAuthority(
            firstId,
            secondId);
        Assert.Throws<ArgumentException>(() => CreateIdentityFacade(
        [
            Binding(firstId, firstId, shapeShiftingSingleAuthority),
            Binding(secondId, secondId, shapeShiftingSingleAuthority)
        ]));
    }

    [Fact]
    public async Task ReservedFailpointNeverReturnsCommittedAndRestartFinishesExactRequest()
    {
        var directory = TemporaryDirectory("xnode-xpa1-reserved-restart-");
        try
        {
            var request = Xpu();
            using (var interrupted = CreatePathFacade(
                       directory,
                       new OneShotSagaFaults(ContactPublicationAuthorizationSagaFailpoint.AfterReservePersist)))
            {
                var first = Xpo1Codec.Decode((await interrupted.DispatchAsync(
                    ContactServiceFacadeOperation.PublishDcr, request)).Span, request);
                Assert.Equal(Xpo1Status.OutcomeUnknown, first.Status);
                Assert.Equal(ContactServiceMutationOutcome.OutcomeUnknown, first.MutationOutcome);
                Assert.True(first.Field(19).IsEmpty);
            }

            using var recovered = CreatePathFacade(directory);
            var second = Xpo1Codec.Decode((await recovered.DispatchAsync(
                ContactServiceFacadeOperation.PublishDcr, request)).Span, request);
            Assert.Equal(Xpo1Status.Committed, second.Status);
            Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, second.MutationOutcome);
            Assert.False(second.Field(19).IsEmpty);
            await PublicationAuthorizations.VerifyCommittedAsync(second);
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task CommittedFailpointReturnsUnknownWithoutReceiptsAndRestartExactReplays()
    {
        var directory = TemporaryDirectory("xnode-xpa1-commit-restart-");
        try
        {
            var request = Xpu();
            using (var interrupted = CreatePathFacade(
                       directory,
                       new OneShotSagaFaults(ContactPublicationAuthorizationSagaFailpoint.AfterCommitPersist)))
            {
                var first = Xpo1Codec.Decode((await interrupted.DispatchAsync(
                    ContactServiceFacadeOperation.PublishDcr, request)).Span, request);
                Assert.Equal(Xpo1Status.OutcomeUnknown, first.Status);
                Assert.True(first.Field(19).IsEmpty);
            }

            using var recovered = CreatePathFacade(directory);
            var replay = Xpo1Codec.Decode((await recovered.DispatchAsync(
                ContactServiceFacadeOperation.PublishDcr, request)).Span, request);
            Assert.Equal(Xpo1Status.ExactReplay, replay.Status);
            Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, replay.MutationOutcome);
            Assert.False(replay.Field(19).IsEmpty);
            await PublicationAuthorizations.VerifyCommittedAsync(replay);
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task SameAuthorizationDifferentValidWitnessSetPermanentlyLatchesConflict()
    {
        using var fixture = new Fixture(PublicationAuthorizations);
        var original = Xpu();
        var changed = PublicationAuthorizations.AlternateRequest.CanonicalBytes.ToArray();
        var originalAuthorization = await PublicationAuthorizations.Verifier.VerifyAsync(
            PublicationAuthorizations.Request, default);
        var alternateAuthorization = await PublicationAuthorizations.Verifier.VerifyAsync(
            PublicationAuthorizations.AlternateRequest, default);
        Assert.Equal(originalAuthorization.AuthorizationId.ToArray(), alternateAuthorization.AuthorizationId.ToArray());
        Assert.Equal(PublicationAuthorizations.Request.AuthorizedBodyHash.ToArray(),
            PublicationAuthorizations.AlternateRequest.AuthorizedBodyHash.ToArray());
        Assert.NotEqual(original, changed);

        Assert.Equal(Xpo1Status.Committed, Xpo1Codec.Decode((await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, original)).Span, original).Status);
        Assert.Equal(Xpo1Status.Conflict, Xpo1Codec.Decode((await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, changed)).Span, changed).Status);
        Assert.Equal(Xpo1Status.Conflict, Xpo1Codec.Decode((await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, original)).Span, original).Status);
    }

    [Fact]
    public async Task ConcurrentExactAuthorizationIsConsumedOnceAndOnlyExactReplaysFollow()
    {
        using var fixture = new Fixture(PublicationAuthorizations);
        var request = Xpu();

        var responses = await Task.WhenAll(Enumerable.Range(0, 16).Select(async _ =>
            Xpo1Codec.Decode((await fixture.Facade.DispatchAsync(
                ContactServiceFacadeOperation.PublishDcr, request)).Span, request)));

        Assert.Single(responses, static item => item.Status == Xpo1Status.Committed);
        Assert.Equal(15, responses.Count(static item => item.Status == Xpo1Status.ExactReplay));
        Assert.All(responses, static item =>
            Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, item.MutationOutcome));
        foreach (var response in responses)
            await PublicationAuthorizations.VerifyCommittedAsync(response);
    }

    [Fact]
    public async Task PartialReplicaCommitStaysReservedWithoutReceiptsThenReconciles()
    {
        using var fixture = new PartialReplicaFixture(PublicationAuthorizations);
        var request = Xpu();

        var partial = Xpo1Codec.Decode((await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request)).Span, request);
        Assert.Equal(Xpo1Status.OutcomeUnknown, partial.Status);
        Assert.Equal(0, fixture.FirstAuthority.IssueCount);
        Assert.Equal(0, fixture.SecondAuthority.IssueCount);

        var recovered = Xpo1Codec.Decode((await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request)).Span, request);
        Assert.Equal(Xpo1Status.Committed, recovered.Status);
        Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, recovered.MutationOutcome);
        Assert.Equal(1, fixture.FirstAuthority.IssueCount);
        Assert.Equal(1, fixture.SecondAuthority.IssueCount);
        await PublicationAuthorizations.VerifyCommittedAsync(recovered);
    }

    private byte[] Xpu()
    {
        var request = PublicationAuthorizations.Request;
        Assert.Equal(0u, request.UsageLimit);
        return request.CanonicalBytes.ToArray();
    }

    private byte[] Xiq(byte operationByte = 13, CurrentContactPublicationFixture? publication = null)
    {
        var request = (publication ?? PublicationAuthorizations).Request;
        return Xiq1Codec.Encode(request.NetworkId.Span, B(32, operationByte),
            request.ViewHash.Span, request.PlacementHash.Span,
            request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds,
            request.LocatorHash.Span, 0, Xiq1AntiSpamTokenType.None, [],
            ContactServicePaddingClass.Bytes256);
    }

    private byte[] Xpk()
    {
        var placement = PublicationAuthorizations.ClaimPlacement;
        return Xpk1Codec.Encode(placement.NetworkId.Span, B(32, 14),
            placement.ViewHash.Span, placement.PlacementHash.Span, 1_100, 1_120,
            placement.ShardKey.Span, B(32, 16), B(32, 17), B(32, 18), B(32, 19));
    }

    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }

    private static void AssertResolveClaimReceipts(Xis1Result result, Xiq1Request request)
    {
        var tuple = Concat(
            result.RequestHash.ToArray(),
            request.LocatorHash.ToArray(),
            result.Field(16).ToArray(),
            result.Field(17).ToArray(),
            result.Field(18).ToArray(),
            result.Field(20).ToArray(),
            result.Field(22).ToArray(),
            U64(result.ServerTimeUnixSeconds));
        Assert.Equal(160, tuple.Length);

        var statement = SignatureInput(
            "Deep/ContactResolver/V1/invite-claim-commit", tuple);
        var receipts = result.Field(23).Span;
        Assert.Equal(193, receipts.Length);
        Assert.Equal(2, receipts[0]);
        for (var offset = 1; offset < receipts.Length; offset += 96)
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(receipts.Slice(offset, 32).ToArray());
            Assert.True(verifier.VerifyMessage(
                statement, receipts.Slice(offset + 32, 64).ToArray()));
        }
    }

    private static byte[] SignatureInput(string domain, ReadOnlySpan<byte> tuple)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var output = new byte[label.Length + 7 + tuple.Length];
        label.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(label.Length + 1), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(label.Length + 3), checked((uint)tuple.Length));
        tuple.CopyTo(output.AsSpan(label.Length + 7));
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

    private static ContactServiceReplicaBinding Binding(
        ReadOnlyMemory<byte> resolverId,
        ReadOnlyMemory<byte> preKeyId,
        IContactServiceReplicaReceiptAuthority authority) => new(
            new IdentityResolverReplica(resolverId),
            new IdentityPreKeyReplica(preKeyId),
            authority);

    private ContactServiceOpaqueFacade CreatePathFacade(
        string directory,
        IContactPublicationAuthorizationSagaFaults? faults = null)
    {
        var security = new TestStorageSecurity();
        var durability = new MailboxDurabilityBarrier();
        return new ContactServiceOpaqueFacade(
            Path.Combine(directory, "resolver-a.state"),
            Path.Combine(directory, "resolver-b.state"),
            Path.Combine(directory, "prekey-a.state"),
            Path.Combine(directory, "prekey-b.state"),
            PublicationAuthorizations.CreateReceiptAuthorities(),
            new StaticFixtureContextVerifier(PublicationAuthorizations),
            PublicationAuthorizations.Verifier,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1100)),
            security,
            durability,
            authorizationSagaFaults: faults);
    }

    private static string TemporaryDirectory(string prefix) =>
        Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));

    private static void DeleteDirectory(string directory)
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private ContactServiceOpaqueFacade CreateIdentityFacade(
        IReadOnlyList<ContactServiceReplicaBinding> bindings)
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "xnode-contact-identity-" + Guid.NewGuid().ToString("N"));
        var security = new TestStorageSecurity();
        var durability = new MailboxDurabilityBarrier();
        var saga = CreateSaga(directory, security, durability);
        try
        {
            return new ContactServiceOpaqueFacade(
                bindings,
                new StaticFixtureContextVerifier(PublicationAuthorizations),
                PublicationAuthorizations.Verifier,
                saga,
                new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1100)));
        }
        catch
        {
            saga.Dispose();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
            throw;
        }
    }

    private static ContactPublicationAuthorizationSaga CreateSaga(
        string directory,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability,
        IContactPublicationAuthorizationSagaFaults? faults = null) => new(
            Path.Combine(directory, "xpa1-saga.state"),
            Path.Combine(directory, "xpa1-saga.key"),
            security: security,
            durability: durability,
            faults: faults);

    private enum ReceiptAuthorityBehavior
    {
        Valid = 1,
        SubstituteFirstReplica = 2,
        InvalidSignatureSize = 3,
        Unavailable = 4,
        WaitForCancellation = 5
    }

    private sealed class OneShotSagaFaults(ContactPublicationAuthorizationSagaFailpoint target)
        : IContactPublicationAuthorizationSagaFaults
    {
        private int hit;

        public void Hit(ContactPublicationAuthorizationSagaFailpoint failpoint)
        {
            if (failpoint == target && Interlocked.Exchange(ref hit, 1) == 0)
            {
                throw new InvalidOperationException("Injected XPA1 saga crash boundary.");
            }
        }
    }

    private sealed class RecordingReceiptAuthority(
        LocalContactServiceReplicaReceiptAuthority identity,
        LocalContactServiceReplicaReceiptAuthority signingAuthority,
        ReceiptAuthorityBehavior behavior = ReceiptAuthorityBehavior.Valid)
        : IContactServiceReplicaReceiptAuthority
    {
        private readonly TaskCompletionSource receiptEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int IssueCount { get; private set; }
        internal Task ReceiptEntered => receiptEntered.Task;
        public ReadOnlyMemory<byte> ReplicaId => identity.ReplicaId;

        public async ValueTask<ContactServiceReplicaReceipt> IssueAsync(
            ContactServiceReplicaReceiptRequest request,
            CancellationToken cancellationToken)
        {
            IssueCount++;
            receiptEntered.TrySetResult();
            switch (behavior)
            {
                case ReceiptAuthorityBehavior.Unavailable:
                    throw new IOException("Simulated remote receipt authority outage.");
                case ReceiptAuthorityBehavior.WaitForCancellation:
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                    throw new InvalidOperationException("Unreachable after cancellation.");
                case ReceiptAuthorityBehavior.InvalidSignatureSize:
                    return new ContactServiceReplicaReceipt(ReplicaId, new byte[63]);
                case ReceiptAuthorityBehavior.SubstituteFirstReplica:
                    var substituted = await signingAuthority.IssueAsync(
                        request,
                        cancellationToken);
                    return new ContactServiceReplicaReceipt(
                        ReplicaId,
                        substituted.Signature);
                default:
                    return await signingAuthority.IssueAsync(request, cancellationToken);
            }
        }
    }

    private sealed class AlternatingIdentityReceiptAuthority(
        ReadOnlyMemory<byte> firstReplicaId,
        ReadOnlyMemory<byte> secondReplicaId)
        : IContactServiceReplicaReceiptAuthority
    {
        private int reads;

        public ReadOnlyMemory<byte> ReplicaId =>
            Interlocked.Increment(ref reads) == 1
                ? firstReplicaId.ToArray()
                : secondReplicaId.ToArray();

        public ValueTask<ContactServiceReplicaReceipt> IssueAsync(
            ContactServiceReplicaReceiptRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class InjectedFixture : IDisposable
    {
        private readonly string directory = Path.Combine(
            Path.GetTempPath(), "xnode-contact-bound-facade-" + Guid.NewGuid().ToString("N"));
        private readonly ContactResolverOpaqueStore firstResolverStore;
        private readonly ContactResolverOpaqueStore secondResolverStore;
        private readonly ContactPreKeyOpaqueStore firstPreKeyStore;
        private readonly ContactPreKeyOpaqueStore secondPreKeyStore;
        private readonly ContactPublicationAuthorizationSaga authorizationSaga;
        private readonly LocalContactServiceReplicaReceiptAuthority firstLocal;
        private readonly LocalContactServiceReplicaReceiptAuthority secondLocal;

        internal InjectedFixture(
            CurrentContactPublicationFixture publicationAuthorizations,
            ReceiptAuthorityBehavior secondBehavior = ReceiptAuthorityBehavior.Valid)
        {
            var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1100));
            var security = new TestStorageSecurity();
            var durability = new MailboxDurabilityBarrier();
            var authorities = publicationAuthorizations.CreateReceiptAuthorities();
            firstLocal = authorities[0];
            secondLocal = authorities[1];
            FirstAuthority = new RecordingReceiptAuthority(firstLocal, firstLocal);
            SecondAuthority = new RecordingReceiptAuthority(
                secondLocal,
                secondBehavior == ReceiptAuthorityBehavior.SubstituteFirstReplica
                    ? firstLocal
                    : secondLocal,
                secondBehavior);

            firstResolverStore = new ContactResolverOpaqueStore(
                Path.Combine(directory, "resolver-a.state"),
                clock: clock,
                storageSecurity: security,
                durability: durability);
            secondResolverStore = new ContactResolverOpaqueStore(
                Path.Combine(directory, "resolver-b.state"),
                clock: clock,
                storageSecurity: security,
                durability: durability);
            firstPreKeyStore = new ContactPreKeyOpaqueStore(
                Path.Combine(directory, "prekey-a.state"),
                clock: clock,
                storageSecurity: security,
                durability: durability);
            secondPreKeyStore = new ContactPreKeyOpaqueStore(
                Path.Combine(directory, "prekey-b.state"),
                clock: clock,
                storageSecurity: security,
                durability: durability);
            authorizationSaga = CreateSaga(directory, security, durability);

            var firstId = firstLocal.ReplicaId;
            var secondId = secondLocal.ReplicaId;
            Facade = new ContactServiceOpaqueFacade(
            [
                new ContactServiceReplicaBinding(
                    new ContactResolverStoreReplica(secondId.Span, secondResolverStore),
                    new ContactPreKeyStoreReplica(secondId.Span, secondPreKeyStore),
                    SecondAuthority),
                new ContactServiceReplicaBinding(
                    new ContactResolverStoreReplica(firstId.Span, firstResolverStore),
                    new ContactPreKeyStoreReplica(firstId.Span, firstPreKeyStore),
                    FirstAuthority)
            ],
            new StaticFixtureContextVerifier(publicationAuthorizations),
            publicationAuthorizations.Verifier,
            authorizationSaga,
            clock);
        }

        internal ContactServiceOpaqueFacade Facade { get; }
        internal RecordingReceiptAuthority FirstAuthority { get; }
        internal RecordingReceiptAuthority SecondAuthority { get; }

        public void Dispose()
        {
            Facade.Dispose();
            authorizationSaga.Dispose();
            firstResolverStore.Dispose();
            secondResolverStore.Dispose();
            firstPreKeyStore.Dispose();
            secondPreKeyStore.Dispose();
            firstLocal.Dispose();
            secondLocal.Dispose();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private sealed class PartialReplicaFixture : IDisposable
    {
        private readonly string directory = TemporaryDirectory("xnode-contact-partial-");
        private readonly ContactResolverOpaqueStore firstResolverStore;
        private readonly ContactResolverOpaqueStore secondResolverStore;
        private readonly ContactPreKeyOpaqueStore firstPreKeyStore;
        private readonly ContactPreKeyOpaqueStore secondPreKeyStore;
        private readonly ContactPublicationAuthorizationSaga authorizationSaga;
        private readonly LocalContactServiceReplicaReceiptAuthority firstLocal;
        private readonly LocalContactServiceReplicaReceiptAuthority secondLocal;

        internal PartialReplicaFixture(CurrentContactPublicationFixture publicationAuthorizations)
        {
            var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1100));
            var security = new TestStorageSecurity();
            var durability = new MailboxDurabilityBarrier();
            var authorities = publicationAuthorizations.CreateReceiptAuthorities();
            firstLocal = authorities[0];
            secondLocal = authorities[1];
            FirstAuthority = new RecordingReceiptAuthority(firstLocal, firstLocal);
            SecondAuthority = new RecordingReceiptAuthority(secondLocal, secondLocal);
            firstResolverStore = new ContactResolverOpaqueStore(
                Path.Combine(directory, "resolver-a.state"), clock: clock,
                storageSecurity: security, durability: durability);
            secondResolverStore = new ContactResolverOpaqueStore(
                Path.Combine(directory, "resolver-b.state"), clock: clock,
                storageSecurity: security, durability: durability);
            firstPreKeyStore = new ContactPreKeyOpaqueStore(
                Path.Combine(directory, "prekey-a.state"), clock: clock,
                storageSecurity: security, durability: durability);
            secondPreKeyStore = new ContactPreKeyOpaqueStore(
                Path.Combine(directory, "prekey-b.state"), clock: clock,
                storageSecurity: security, durability: durability);
            authorizationSaga = CreateSaga(directory, security, durability);
            var firstId = firstLocal.ReplicaId;
            var secondId = secondLocal.ReplicaId;
            Facade = new ContactServiceOpaqueFacade(
            [
                new ContactServiceReplicaBinding(
                    new ContactResolverStoreReplica(firstId.Span, firstResolverStore),
                    new ContactPreKeyStoreReplica(firstId.Span, firstPreKeyStore),
                    FirstAuthority),
                new ContactServiceReplicaBinding(
                    new OneShotUnavailableResolverReplica(
                        new ContactResolverStoreReplica(secondId.Span, secondResolverStore)),
                    new ContactPreKeyStoreReplica(secondId.Span, secondPreKeyStore),
                    SecondAuthority)
            ],
            new StaticFixtureContextVerifier(publicationAuthorizations),
            publicationAuthorizations.Verifier,
            authorizationSaga,
            clock);
        }

        internal ContactServiceOpaqueFacade Facade { get; }
        internal RecordingReceiptAuthority FirstAuthority { get; }
        internal RecordingReceiptAuthority SecondAuthority { get; }

        public void Dispose()
        {
            Facade.Dispose();
            authorizationSaga.Dispose();
            firstResolverStore.Dispose();
            secondResolverStore.Dispose();
            firstPreKeyStore.Dispose();
            secondPreKeyStore.Dispose();
            firstLocal.Dispose();
            secondLocal.Dispose();
            DeleteDirectory(directory);
        }
    }

    private sealed class OneShotUnavailableResolverReplica(IContactResolverReplica inner)
        : IContactResolverReplica
    {
        private int publishCalls;

        public ReadOnlyMemory<byte> ReplicaId => inner.ReplicaId;

        public ValueTask<ContactResolverMutationResult> PublishDcrAsync(
            OpaqueDcrPublishRequest request,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref publishCalls) == 1)
            {
                throw new IOException("Injected second-replica outage.");
            }
            return inner.PublishDcrAsync(request, cancellationToken);
        }

        public ValueTask<ContactResolverDcrReadResult> ResolveCurrentDcrAsync(
            ReadOnlyMemory<byte> locatorHash32,
            CancellationToken cancellationToken) =>
            inner.ResolveCurrentDcrAsync(locatorHash32, cancellationToken);

        public ValueTask<ContactMailboxGrantRouteResult> ResolveMailboxGrantRouteAsync(
            ReadOnlyMemory<byte> locatorHash32,
            ReadOnlyMemory<byte> capability32,
            ContactMailboxGrantRole role,
            CancellationToken cancellationToken) => inner.ResolveMailboxGrantRouteAsync(
                locatorHash32, capability32, role, cancellationToken);

        public ValueTask<ContactResolverDcrResolveResult> ResolveDcrAsync(
            OpaqueDcrResolveRequest request,
            CancellationToken cancellationToken) => inner.ResolveDcrAsync(request, cancellationToken);

        public ValueTask<ContactResolverDcrResolveResult> ReadDcrClaimAsync(
            OpaqueDcrResolveRequest request,
            CancellationToken cancellationToken) => inner.ReadDcrClaimAsync(request, cancellationToken);

        public ValueTask<ContactResolverMutationResult> WriteXurSuccessorAsync(
            OpaqueXurWriteRequest request,
            CancellationToken cancellationToken) => inner.WriteXurSuccessorAsync(request, cancellationToken);

        public ValueTask<ContactResolverXurReadResult> ResolveXurSuccessorsAsync(
            ReadOnlyMemory<byte> serviceCapability32,
            ReadOnlyMemory<byte> exactXur1Hash32,
            ulong afterGeneration,
            int maximumEvents,
            CancellationToken cancellationToken) => inner.ResolveXurSuccessorsAsync(
                serviceCapability32, exactXur1Hash32, afterGeneration, maximumEvents, cancellationToken);
    }

    private sealed class IdentityResolverReplica(ReadOnlyMemory<byte> replicaId)
        : IContactResolverReplica
    {
        public ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();

        public ValueTask<ContactResolverMutationResult> PublishDcrAsync(
            OpaqueDcrPublishRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<ContactResolverDcrReadResult> ResolveCurrentDcrAsync(
            ReadOnlyMemory<byte> locatorHash32,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<ContactMailboxGrantRouteResult> ResolveMailboxGrantRouteAsync(
            ReadOnlyMemory<byte> locatorHash32,
            ReadOnlyMemory<byte> capability32,
            ContactMailboxGrantRole role,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<ContactResolverDcrResolveResult> ResolveDcrAsync(
            OpaqueDcrResolveRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<ContactResolverDcrResolveResult> ReadDcrClaimAsync(
            OpaqueDcrResolveRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<ContactResolverMutationResult> WriteXurSuccessorAsync(
            OpaqueXurWriteRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<ContactResolverXurReadResult> ResolveXurSuccessorsAsync(
            ReadOnlyMemory<byte> serviceCapability32,
            ReadOnlyMemory<byte> exactXur1Hash32,
            ulong afterGeneration,
            int maximumEvents,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class IdentityPreKeyReplica(ReadOnlyMemory<byte> replicaId)
        : IContactPreKeyReplica
    {
        public ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();

        public ValueTask<ContactPreKeyClaimResult> ClaimAsync(
            OpaquePreKeyClaimRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask LatchForkAsync(
            ReadOnlyMemory<byte> serviceCapability32,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = Path.Combine(
            Path.GetTempPath(), "xnode-contact-facade-" + Guid.NewGuid().ToString("N"));

        internal Fixture(CurrentContactPublicationFixture publicationAuthorizations)
        {
            Context = new StaticFixtureContextVerifier(publicationAuthorizations);
            Clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1100));
            var security = new TestStorageSecurity();
            Facade = new ContactServiceOpaqueFacade(
                Path.Combine(directory, "resolver-a.state"),
                Path.Combine(directory, "resolver-b.state"),
                Path.Combine(directory, "prekey-a.state"),
                Path.Combine(directory, "prekey-b.state"),
                publicationAuthorizations.CreateReceiptAuthorities(),
                Context,
                publicationAuthorizations.Verifier,
                Clock,
                security,
                new MailboxDurabilityBarrier());
        }

        internal ContactServiceOpaqueFacade Facade { get; }
        internal StaticFixtureContextVerifier Context { get; }
        internal FixedClock Clock { get; }

        public void Dispose()
        {
            Facade.Dispose();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    // Only the explicit stale-view fault is injected. Normal acceptance checks
    // exact tuples from signed current PublishInvite/ClaimPreKey placements.
    private sealed class StaticFixtureContextVerifier(CurrentContactPublicationFixture inputs)
        : IContactRequestContextVerifier
    {
        private readonly ExactContactRequestContextVerifier publication = new(inputs.Placement);
        private readonly ExactContactRequestContextVerifier claim = new(inputs.ClaimPlacement);
        internal ContactRequestContextStatus Status { get; set; } = ContactRequestContextStatus.Accepted;

        public ValueTask<ContactRequestContextResult> VerifyAsync(
            ReadOnlyMemory<byte> networkId, ReadOnlyMemory<byte> viewHash,
            ReadOnlyMemory<byte> placementHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Status != ContactRequestContextStatus.Accepted)
                return ValueTask.FromResult(new ContactRequestContextResult(Status, inputs.Placement.ViewHash));
            var verifier = placementHash.Span.SequenceEqual(inputs.ClaimPlacement.PlacementHash.Span)
                ? claim : publication;
            return verifier.VerifyAsync(networkId, viewHash, placementHash, cancellationToken);
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = now;
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }
}
