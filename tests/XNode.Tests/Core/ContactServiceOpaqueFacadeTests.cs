using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Rebex.Security.Cryptography;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class ContactServiceOpaqueFacadeTests
{
    private static readonly Xpa1AuthorizationTestFixture PublicationAuthorizations = new();

    // Frozen canonical minimum XRR1/XRA1/XRC1/XSS1/PMT2/PMS2 closure from the
    // protocol codec vectors. Keeping bytes here avoids any production authoring
    // or InternalsVisibleTo test seam.
    private const string CanonicalRouteClosureBase64 =
        "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" +
        "AAAAAAAAAAAAAAAAAAAAAAAA";

    [Fact]
    public async Task ContextMismatchDoesNotMutateAndAcceptedPublishDurablyExactReplays()
    {
        using var fixture = new Fixture();
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

        var replayBytes = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var replay = Xpo1Codec.Decode(replayBytes.Span, request);
        Assert.Equal(Xpo1Status.ExactReplay, replay.Status);
        Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, replay.MutationOutcome);
    }

    [Fact]
    public async Task ResolveWithoutVerifiedRouteClosureIsCanonicalUnavailableNotStoredCiphertext()
    {
        using var fixture = new Fixture();
        var publish = Xpu();
        var publication = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, publish);
        Assert.Equal(Xpo1Status.Committed, Xpo1Codec.Decode(publication.Span, publish).Status);
        var resolve = Xiq();

        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ResolveDcr, resolve);
        var decoded = Xis1Codec.Decode(response.Span, resolve);

        Assert.Equal(Xis1Status.TemporarilyUnavailable, decoded.Status);
        Assert.Equal(ContactServiceMutationOutcome.None, decoded.MutationOutcome);
    }

    [Fact]
    public async Task MissingClosureDoesNotConsumeOneTimeInviteAndSuccessExactReplays()
    {
        using var fixture = new Fixture();
        var publish = Xpu(usageLimit: 1);
        var publication = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, publish);
        Assert.Equal(Xpo1Status.Committed, Xpo1Codec.Decode(publication.Span, publish).Status);
        var resolve = Xiq(operationByte: 31);

        var unavailable = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ResolveDcr, resolve);
        Assert.Equal(Xis1Status.TemporarilyUnavailable,
            Xis1Codec.Decode(unavailable.Span, resolve).Status);

        fixture.Closures.Value = Convert.FromBase64String(
            CanonicalRouteClosureBase64);
        var first = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ResolveDcr, resolve);
        var decoded = Xis1Codec.Decode(first.Span, resolve);
        Assert.Equal(Xis1Status.Success, decoded.Status);
        Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted,
            decoded.MutationOutcome);
        AssertResolveClaimReceipts(decoded, Xiq1Codec.Decode(resolve));

        fixture.Clock.UtcNow = fixture.Clock.UtcNow.AddSeconds(1);
        fixture.Closures.Value = null;
        var replay = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ResolveDcr, resolve);
        Assert.Equal(first.ToArray(), replay.ToArray());
        Assert.Equal(Xis1Status.Success,
            Xis1Codec.Decode(replay.Span, resolve).Status);

        var competing = Xiq(operationByte: 32);
        var competingResponse = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ResolveDcr, competing);
        Assert.Equal(
            Xis1Status.AlreadyClaimed,
            Xis1Codec.Decode(competingResponse.Span, competing).Status);
    }

    [Fact]
    public async Task MissingPreKeyInventoryReturnsClosedCanonicalStatus()
    {
        using var fixture = new Fixture();
        var request = Xpk();
        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ClaimPreKey, request);
        var decoded = Xpc1Codec.Decode(response.Span, request);
        Assert.Equal(Xpc1Status.PreKeysUnavailable, decoded.Status);
    }

    [Fact]
    public async Task RemoteShapedAuthoritiesAreDelegatedAndReceiptsStayCanonicallySorted()
    {
        using var fixture = new InjectedFixture();
        var request = Xpu();

        var response = await fixture.Facade.DispatchAsync(
            ContactServiceFacadeOperation.PublishDcr, request);
        var decoded = Xpo1Codec.Decode(response.Span, request);

        Assert.Equal(Xpo1Status.Committed, decoded.Status);
        Assert.Equal(1, fixture.FirstAuthority.IssueCount);
        Assert.Equal(1, fixture.SecondAuthority.IssueCount);
        var receipts = decoded.Field(19).Span;
        Assert.Equal(193, receipts.Length);
        Assert.True(receipts.Slice(1, 32).SequenceCompareTo(receipts.Slice(97, 32)) < 0);
    }

    [Fact]
    public async Task CrossReplicaReceiptSubstitutionFailsClosedWithoutReceiptEmission()
    {
        using var fixture = new InjectedFixture(
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
        using var fixture = new InjectedFixture(
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
        using var fixture = new InjectedFixture(
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
        using var fixture = new InjectedFixture(
            secondBehavior: ReceiptAuthorityBehavior.WaitForCancellation);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await fixture.Facade.DispatchAsync(
                ContactServiceFacadeOperation.PublishDcr,
                Xpu(),
                cancellation.Token));
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
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task SameAuthorizationChangedExactBodyPermanentlyLatchesConflict()
    {
        using var fixture = new Fixture();
        var original = Xpu();
        var changed = PublicationAuthorizations.CreateEncodedRequest(
            operationMarker: 44,
            authorizationMarker: 8,
            ciphertextMarker: 45);

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
        using var fixture = new Fixture();
        var request = Xpu();

        var responses = await Task.WhenAll(Enumerable.Range(0, 16).Select(async _ =>
            Xpo1Codec.Decode((await fixture.Facade.DispatchAsync(
                ContactServiceFacadeOperation.PublishDcr, request)).Span, request)));

        Assert.Single(responses, static item => item.Status == Xpo1Status.Committed);
        Assert.Equal(15, responses.Count(static item => item.Status == Xpo1Status.ExactReplay));
        Assert.All(responses, static item =>
            Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, item.MutationOutcome));
    }

    [Fact]
    public async Task PartialReplicaCommitStaysReservedWithoutReceiptsThenReconciles()
    {
        using var fixture = new PartialReplicaFixture();
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
    }

    private static byte[] Xpu(uint usageLimit = 0) =>
        PublicationAuthorizations.CreateEncodedRequest(usageLimit);

    private static byte[] Xiq(byte operationByte = 13) => Xiq1Codec.Encode(
        Network(), B(32, operationByte), B(32, 3), B(32, 4), 195, 240,
        B(32, 5), 0, Xiq1AntiSpamTokenType.None, [],
        ContactServicePaddingClass.Bytes256);

    private static byte[] Xpk() => Xpk1Codec.Encode(
        B(16, 1), B(32, 14), B(32, 3), B(32, 4), 195, 240,
        B(32, 15), B(32, 16), B(32, 17), B(32, 18), B(32, 19));

    private static byte[] Record(string magic, IReadOnlyList<(ushort Tag, byte[] Value)> fields)
    {
        var result = new byte[12 + fields.Sum(static item => 8 + item.Value.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        foreach (var field in fields)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), field.Tag);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 4), checked((uint)field.Value.Length));
            offset += 8;
            field.Value.CopyTo(result, offset);
            offset += field.Value.Length;
        }
        return result;
    }

    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] Network() => Enumerable.Range(1, 16)
        .Select(static value => checked((byte)value)).ToArray();
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
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

    private static ContactServiceOpaqueFacade CreatePathFacade(
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
            [new(B(32, 21)), new(B(32, 22))],
            new MutableRouteClosureSource(),
            new StaticFixtureContextVerifier(),
            PublicationAuthorizations,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(200)),
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

    private static ContactServiceOpaqueFacade CreateIdentityFacade(
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
                new MutableRouteClosureSource(),
                new StaticFixtureContextVerifier(),
                PublicationAuthorizations,
                saga,
                new FixedClock(DateTimeOffset.FromUnixTimeSeconds(200)));
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
        internal int IssueCount { get; private set; }
        public ReadOnlyMemory<byte> ReplicaId => identity.ReplicaId;

        public async ValueTask<ContactServiceReplicaReceipt> IssueAsync(
            ContactServiceReplicaReceiptRequest request,
            CancellationToken cancellationToken)
        {
            IssueCount++;
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
            ReceiptAuthorityBehavior secondBehavior = ReceiptAuthorityBehavior.Valid)
        {
            var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(200));
            var security = new TestStorageSecurity();
            var durability = new MailboxDurabilityBarrier();
            firstLocal = new LocalContactServiceReplicaReceiptAuthority(B(32, 31));
            secondLocal = new LocalContactServiceReplicaReceiptAuthority(B(32, 32));
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
            new MutableRouteClosureSource(),
            new StaticFixtureContextVerifier(),
            PublicationAuthorizations,
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

        internal PartialReplicaFixture()
        {
            var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(200));
            var security = new TestStorageSecurity();
            var durability = new MailboxDurabilityBarrier();
            firstLocal = new LocalContactServiceReplicaReceiptAuthority(B(32, 51));
            secondLocal = new LocalContactServiceReplicaReceiptAuthority(B(32, 52));
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
            new MutableRouteClosureSource(),
            new StaticFixtureContextVerifier(),
            PublicationAuthorizations,
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

        internal Fixture()
        {
            Context = new StaticFixtureContextVerifier();
            Closures = new MutableRouteClosureSource();
            Clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(200));
            var security = new TestStorageSecurity();
            Facade = new ContactServiceOpaqueFacade(
                Path.Combine(directory, "resolver-a.state"),
                Path.Combine(directory, "resolver-b.state"),
                Path.Combine(directory, "prekey-a.state"),
                Path.Combine(directory, "prekey-b.state"),
                [new(B(32, 21)), new(B(32, 22))],
                Closures,
                Context,
                PublicationAuthorizations,
                Clock,
                security,
                new MailboxDurabilityBarrier());
        }

        internal ContactServiceOpaqueFacade Facade { get; }
        internal StaticFixtureContextVerifier Context { get; }
        internal MutableRouteClosureSource Closures { get; }
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

    // Static view/placement acceptance is deliberately test-only. Production
    // activation requires verified XNV continuity and PMT2 derivation.
    private sealed class StaticFixtureContextVerifier : IContactRequestContextVerifier
    {
        internal ContactRequestContextStatus Status { get; set; } = ContactRequestContextStatus.Accepted;
        public ValueTask<ContactRequestContextResult> VerifyAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> viewHash,
            ReadOnlyMemory<byte> placementHash,
            CancellationToken cancellationToken) => ValueTask.FromResult(
                new ContactRequestContextResult(Status, B(32, 3)));
    }

    private sealed class MutableRouteClosureSource : IContactRouteClosureSource
    {
        internal byte[]? Value { get; set; }

        public ValueTask<ReadOnlyMemory<byte>?> ReadAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken) => ValueTask.FromResult<ReadOnlyMemory<byte>?>(
                Value is null ? null : Value.ToArray());
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }
}
