using System.Security.Cryptography;
using System.Text;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class ContactResolverApplicationServiceTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 7, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task DispatcherPublishesResolvesAndExactReplaysOnlyAfterTwoReplicaAgreement()
    {
        using var fixture = new ReplicaPairFixture();
        using var coordinator = fixture.CreateCoordinator();
        var dispatcher = new ContactResolverRequestDispatcher(new ContactResolverApplicationService(coordinator));
        var locator = Hash("application/locator");
        var ciphertext = Ciphertext("application/dcr", 80);
        var publish = new ContactResolverPublishRequest(DcrRequest(
            locator,
            "application/publish",
            0,
            Zero32(),
            ciphertext,
            fixture.Clock));

        var committed = await dispatcher.DispatchAsync(publish);
        Assert.Equal(ContactResolverApplicationStatus.Committed, committed.Status);
        Assert.Equal(ContactResolverApplicationMutationOutcome.DurablyCommitted, committed.MutationOutcome);
        Assert.Equal(2, committed.DurableReplicaCount);
        Assert.Equal(SHA256.HashData(ciphertext), committed.ObjectHash.ToArray());

        var replay = await dispatcher.DispatchAsync(publish);
        Assert.Equal(ContactResolverApplicationStatus.ExactReplay, replay.Status);
        Assert.Equal(ContactResolverApplicationMutationOutcome.DurablyCommitted, replay.MutationOutcome);
        Assert.Equal(2, replay.DurableReplicaCount);

        var resolve = new ContactResolverResolveRequest(
            Hash("application/resolve-operation"),
            Hash("application/resolve-request"),
            locator);
        var resolved = await dispatcher.DispatchAsync(resolve);
        Assert.Equal(ContactResolverApplicationStatus.Success, resolved.Status);
        Assert.Equal(ciphertext, resolved.Publication!.Ciphertext);
        resolved.Publication.Ciphertext[0] ^= 0xff;
        Assert.Equal(ciphertext, (await dispatcher.DispatchAsync(resolve)).Publication!.Ciphertext);
    }

    [Fact]
    public async Task ConcurrentChangedSuccessorsProduceOneQuorumCommitThenForkConflict()
    {
        using var fixture = new ReplicaPairFixture();
        using var coordinator = fixture.CreateCoordinator();
        var dispatcher = new ContactResolverRequestDispatcher(new ContactResolverApplicationService(coordinator));
        var locator = Hash("application/cas");
        var genesisStoreRequest = DcrRequest(locator, "cas/0", 0, Zero32(), Ciphertext("cas/0", 40), fixture.Clock);
        Assert.Equal(
            ContactResolverApplicationStatus.Committed,
            (await dispatcher.DispatchAsync(new ContactResolverPublishRequest(genesisStoreRequest))).Status);

        var left = new ContactResolverPublishRequest(DcrRequest(
            locator,
            "cas/left",
            1,
            genesisStoreRequest.ObjectCiphertextHash,
            Ciphertext("cas/left", 40),
            fixture.Clock));
        var right = new ContactResolverPublishRequest(DcrRequest(
            locator,
            "cas/right",
            1,
            genesisStoreRequest.ObjectCiphertextHash,
            Ciphertext("cas/right", 40),
            fixture.Clock));

        var results = await Task.WhenAll(
            dispatcher.DispatchAsync(left),
            dispatcher.DispatchAsync(right));
        Assert.Contains(results, item => item.Status == ContactResolverApplicationStatus.Committed);
        Assert.Contains(results, item => item.Status == ContactResolverApplicationStatus.Conflict);

        var resolve = await dispatcher.DispatchAsync(new ContactResolverResolveRequest(
            Hash("cas/resolve-operation"),
            Hash("cas/resolve-request"),
            locator));
        Assert.Equal(ContactResolverApplicationStatus.Conflict, resolve.Status);
    }

    [Fact]
    public async Task PartialReplicaFailureIsOutcomeUnknownAndSameRequestReconciles()
    {
        using var fixture = new ReplicaPairFixture();
        var second = new SwitchableReplica(fixture.SecondReplica) { FailPublishBeforeMutation = true };
        using var coordinator = fixture.CreateCoordinator(fixture.FirstReplica, second);
        var service = new ContactResolverApplicationService(coordinator);
        var dispatcher = new ContactResolverRequestDispatcher(service);
        var locator = Hash("application/partial");
        var request = new ContactResolverPublishRequest(DcrRequest(
            locator,
            "partial/publish",
            0,
            Zero32(),
            Ciphertext("partial", 40),
            fixture.Clock));

        var partial = await dispatcher.DispatchAsync(request);
        Assert.Equal(ContactResolverApplicationStatus.OutcomeUnknown, partial.Status);
        Assert.Equal(ContactResolverApplicationMutationOutcome.OutcomeUnknown, partial.MutationOutcome);
        Assert.Equal(1, partial.DurableReplicaCount);

        var unresolved = await dispatcher.DispatchAsync(new ContactResolverResolveRequest(
            Hash("partial/resolve-operation"),
            Hash("partial/resolve-request"),
            locator));
        Assert.Equal(ContactResolverApplicationStatus.TemporarilyUnavailable, unresolved.Status);

        second.FailPublishBeforeMutation = false;
        var reconciled = await service.ReconcileAsync(request);
        Assert.Equal(ContactResolverApplicationStatus.Committed, reconciled.Status);
        Assert.Equal(2, reconciled.DurableReplicaCount);
        Assert.Equal(ContactResolverApplicationMutationOutcome.DurablyCommitted, reconciled.MutationOutcome);

        var replay = await dispatcher.DispatchAsync(request);
        Assert.Equal(ContactResolverApplicationStatus.ExactReplay, replay.Status);
        Assert.Equal(2, replay.DurableReplicaCount);
    }

    [Fact]
    public async Task OneTimeResolveIsTwoReplicaDurableAndPartialCommitCannotBeStolen()
    {
        using var fixture = new ReplicaPairFixture();
        var second = new SwitchableReplica(fixture.SecondReplica)
        {
            FailResolveBeforeMutation = true
        };
        using var coordinator = fixture.CreateCoordinator(fixture.FirstReplica, second);
        var service = new ContactResolverApplicationService(coordinator);
        var locator = Hash("application/one-time");
        var publish = new ContactResolverPublishRequest(DcrRequest(
            locator,
            "one-time/publish",
            0,
            Zero32(),
            Ciphertext("one-time", 64),
            fixture.Clock,
            usageLimit: 1));
        Assert.Equal(
            ContactResolverApplicationStatus.Committed,
            (await service.PublishDcrAsync(publish)).Status);

        var redeem = new ContactResolverResolveRequest(
            Hash("one-time/redeem-operation"),
            Hash("one-time/redeem-request"),
            locator,
            Enumerable.Repeat((byte)0x42,
                OpaqueDcrResolveRequest.MinimumRouteClosureBytes).ToArray(),
            checked((ulong)fixture.Clock.UtcNow.ToUnixTimeSeconds()));
        var partial = await service.ResolveCurrentDcrAsync(redeem);
        Assert.Equal(ContactResolverApplicationStatus.OutcomeUnknown, partial.Status);
        Assert.Equal(ContactResolverApplicationMutationOutcome.OutcomeUnknown,
            partial.MutationOutcome);
        Assert.Equal(1, partial.DurableReplicaCount);

        var competing = await service.ResolveCurrentDcrAsync(
            new ContactResolverResolveRequest(
                Hash("one-time/competing-operation"),
                Hash("one-time/competing-request"),
                locator));
        Assert.Equal(ContactResolverApplicationStatus.TemporarilyUnavailable,
            competing.Status);
        Assert.Null(competing.Publication);

        second.FailResolveBeforeMutation = false;
        var reconciled = await service.ResolveCurrentDcrAsync(redeem);
        Assert.Equal(ContactResolverApplicationStatus.Committed, reconciled.Status);
        Assert.Equal(ContactResolverApplicationMutationOutcome.DurablyCommitted,
            reconciled.MutationOutcome);
        Assert.Equal(2, reconciled.DurableReplicaCount);
        Assert.Equal<ulong>(1, reconciled.ClaimCommitGeneration);
        Assert.Equal<uint>(1, reconciled.Publication!.UsageLimit);

        var replay = await service.ResolveCurrentDcrAsync(redeem);
        Assert.Equal(ContactResolverApplicationStatus.ExactReplay, replay.Status);
        Assert.Equal(ContactResolverApplicationMutationOutcome.DurablyCommitted,
            replay.MutationOutcome);
        Assert.Equal(reconciled.Publication.Ciphertext, replay.Publication!.Ciphertext);

        var claimed = await service.ResolveCurrentDcrAsync(
            new ContactResolverResolveRequest(
                Hash("one-time/claimed-operation"),
                Hash("one-time/claimed-request"),
                locator));
        Assert.Equal(ContactResolverApplicationStatus.AlreadyClaimed, claimed.Status);
    }

    [Fact]
    public async Task PreflightNotFoundCurrentMismatchIsNonDefinitiveAndDoesNotClaim()
    {
        using var fixture = new ReplicaPairFixture();
        var locator = Hash("application/preflight-mismatch");
        var publication = DcrRequest(
            locator,
            "preflight-mismatch/publish",
            0,
            Zero32(),
            Ciphertext("preflight-mismatch", 64),
            fixture.Clock,
            usageLimit: 1);
        Assert.Equal(ContactResolverMutationDisposition.Committed,
            fixture.SecondStore.PublishDcr(publication).Disposition);

        using var coordinator = fixture.CreateCoordinator();
        var service = new ContactResolverApplicationService(coordinator);
        var unavailable = await service.ResolveCurrentDcrAsync(
            new ContactResolverResolveRequest(
                Hash("preflight-mismatch/operation"),
                Hash("preflight-mismatch/request"),
                locator,
                Enumerable.Repeat((byte)0x43,
                    OpaqueDcrResolveRequest.MinimumRouteClosureBytes).ToArray(),
                checked((ulong)fixture.Clock.UtcNow.ToUnixTimeSeconds())));

        Assert.Equal(ContactResolverApplicationStatus.TemporarilyUnavailable,
            unavailable.Status);
        Assert.Equal(ContactResolverApplicationMutationOutcome.None,
            unavailable.MutationOutcome);

        Assert.Equal(ContactResolverMutationDisposition.Committed,
            fixture.FirstStore.PublishDcr(publication).Disposition);
        var fresh = await service.ResolveCurrentDcrAsync(
            new ContactResolverResolveRequest(
                Hash("preflight-mismatch/fresh-operation"),
                Hash("preflight-mismatch/fresh-request"),
                locator,
                Enumerable.Repeat((byte)0x44,
                    OpaqueDcrResolveRequest.MinimumRouteClosureBytes).ToArray(),
                checked((ulong)fixture.Clock.UtcNow.ToUnixTimeSeconds())));
        Assert.Equal(ContactResolverApplicationStatus.Committed, fresh.Status);
        Assert.Equal(2, fresh.DurableReplicaCount);
    }

    [Fact]
    public async Task XurWriteFetchReplayAndPartialReconciliationRemainOpaque()
    {
        using var fixture = new ReplicaPairFixture();
        var second = new SwitchableReplica(fixture.SecondReplica) { FailXurAfterMutation = true };
        using var coordinator = fixture.CreateCoordinator(fixture.FirstReplica, second);
        var service = new ContactResolverApplicationService(coordinator);
        var dispatcher = new ContactResolverRequestDispatcher(service);
        var capability = Hash("application/xur-capability");
        var exactXur1Hash = Hash("application/exact-xur1");
        var writeStoreRequest = XurRequest(
            capability,
            exactXur1Hash,
            "xur/write/1",
            1,
            Zero32(),
            fixture.Clock);
        var write = new ContactResolverXurWriteRequest(writeStoreRequest);

        var unknown = await dispatcher.DispatchAsync(write);
        Assert.Equal(ContactResolverApplicationStatus.OutcomeUnknown, unknown.Status);
        Assert.Equal(1, unknown.DurableReplicaCount);

        second.FailXurAfterMutation = false;
        var reconciled = await service.ReconcileAsync(write);
        Assert.Equal(ContactResolverApplicationStatus.ExactReplay, reconciled.Status);
        Assert.Equal(2, reconciled.DurableReplicaCount);

        var fetch = new ContactResolverXurFetchRequest(
            Hash("xur/fetch-operation"),
            Hash("xur/fetch-request"),
            capability,
            exactXur1Hash,
            afterGeneration: 0,
            maximumEvents: 64);
        var events = await dispatcher.DispatchAsync(fetch);
        Assert.Equal(ContactResolverApplicationStatus.Events, events.Status);
        Assert.Single(events.Events);
        Assert.Equal(writeStoreRequest.EventHash.ToArray(), events.Events[0].EventHash);

        var noChange = await dispatcher.DispatchAsync(new ContactResolverXurFetchRequest(
            Hash("xur/no-change-operation"),
            Hash("xur/no-change-request"),
            capability,
            exactXur1Hash,
            afterGeneration: 1,
            maximumEvents: 64));
        Assert.Equal(ContactResolverApplicationStatus.NoChange, noChange.Status);

        var wrongDescriptor = await dispatcher.DispatchAsync(new ContactResolverXurFetchRequest(
            Hash("xur/wrong-descriptor-operation"),
            Hash("xur/wrong-descriptor-request"),
            capability,
            Hash("xur/wrong-exact-xur1"),
            afterGeneration: 0,
            maximumEvents: 64));
        Assert.Equal(ContactResolverApplicationStatus.NotFound, wrongDescriptor.Status);

        var conflictingStoreRequest = XurRequest(
            capability,
            Hash("xur/forked-exact-xur1"),
            "xur/write/fork",
            2,
            writeStoreRequest.EventHash,
            fixture.Clock);
        var conflicting = await dispatcher.DispatchAsync(
            new ContactResolverXurWriteRequest(conflictingStoreRequest));
        Assert.Equal(ContactResolverApplicationStatus.Conflict, conflicting.Status);

        var forkLatched = await dispatcher.DispatchAsync(fetch);
        Assert.Equal(ContactResolverApplicationStatus.Conflict, forkLatched.Status);
    }

    [Fact]
    public async Task ReplicaDivergenceAndCorruptRequestsFailClosed()
    {
        using var fixture = new ReplicaPairFixture();
        var locator = Hash("application/divergence");
        var left = DcrRequest(locator, "divergence/left", 0, Zero32(), Ciphertext("left", 40), fixture.Clock);
        var right = DcrRequest(locator, "divergence/right", 0, Zero32(), Ciphertext("right", 40), fixture.Clock);
        Assert.Equal(ContactResolverMutationDisposition.Committed, fixture.FirstStore.PublishDcr(left).Disposition);
        Assert.Equal(ContactResolverMutationDisposition.Committed, fixture.SecondStore.PublishDcr(right).Disposition);

        using var coordinator = fixture.CreateCoordinator();
        var dispatcher = new ContactResolverRequestDispatcher(new ContactResolverApplicationService(coordinator));
        var divergent = await dispatcher.DispatchAsync(new ContactResolverResolveRequest(
            Hash("divergence/resolve-operation"),
            Hash("divergence/resolve-request"),
            locator));
        Assert.Equal(ContactResolverApplicationStatus.Conflict, divergent.Status);
        Assert.Null(divergent.Publication);

        var invalid = await dispatcher.DispatchAsync(null);
        Assert.Equal(ContactResolverApplicationStatus.InvalidRequest, invalid.Status);
        var unknown = await dispatcher.DispatchAsync(new UnknownRequest());
        Assert.Equal(ContactResolverApplicationStatus.InvalidRequest, unknown.Status);

        Assert.Throws<ArgumentException>(() => new ContactResolverResolveRequest(
            Zero32(),
            Hash("valid-request"),
            locator));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ContactResolverXurFetchRequest(
            Hash("operation"),
            Hash("request"),
            Hash("capability"),
            Hash("xur"),
            0,
            65));
        Assert.Throws<ArgumentException>(() => new ContactResolverTwoReplicaCoordinator(
            fixture.FirstReplica,
            new ContactResolverStoreReplica(Hash("replica/first"), fixture.SecondStore)));
    }

    private static OpaqueDcrPublishRequest DcrRequest(
        byte[] locator,
        string operation,
        ulong generation,
        ReadOnlySpan<byte> predecessor,
        byte[] ciphertext,
        FixedClock clock,
        uint usageLimit = 0) =>
        new(
            locator,
            Hash("operation/" + operation),
            Hash("request/" + operation),
            generation,
            predecessor,
            SHA256.HashData(ciphertext),
            ciphertext,
            usageLimit,
            checked((ulong)clock.UtcNow.AddDays(1).ToUnixTimeSeconds()));

    private static OpaqueXurWriteRequest XurRequest(
        byte[] capability,
        byte[] exactXur1Hash,
        string operation,
        ulong generation,
        ReadOnlySpan<byte> predecessor,
        FixedClock clock)
    {
        var ciphertext = Ciphertext("ciphertext/" + operation, 32);
        return new(
            capability,
            Hash("operation/" + operation),
            Hash("request/" + operation),
            exactXur1Hash,
            generation,
            predecessor,
            Hash("event/" + operation),
            SHA256.HashData(ciphertext),
            ciphertext,
            checked((ulong)clock.UtcNow.AddDays(400).ToUnixTimeSeconds()));
    }

    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

    private static byte[] Ciphertext(string value, int length)
    {
        var seed = Hash(value);
        var result = new byte[length];
        for (var index = 0; index < result.Length; index++)
        {
            result[index] = seed[index % seed.Length];
        }
        return result;
    }

    private static byte[] Zero32() => new byte[32];

    private sealed class UnknownRequest : ContactResolverApplicationRequest
    {
        internal UnknownRequest()
            : base((ContactResolverApplicationOperation)255, Hash("unknown-operation"), Hash("unknown-request"))
        {
        }
    }

    private sealed class SwitchableReplica(IContactResolverReplica inner) : IContactResolverReplica
    {
        internal bool FailPublishBeforeMutation { get; set; }
        internal bool FailXurAfterMutation { get; set; }
        internal bool FailResolveBeforeMutation { get; set; }
        public ReadOnlyMemory<byte> ReplicaId => inner.ReplicaId;

        public ValueTask<ContactResolverMutationResult> PublishDcrAsync(
            OpaqueDcrPublishRequest request,
            CancellationToken cancellationToken)
        {
            if (FailPublishBeforeMutation)
            {
                throw new IOException("Injected replica outage.");
            }
            return inner.PublishDcrAsync(request, cancellationToken);
        }

        public ValueTask<ContactResolverDcrReadResult> ResolveCurrentDcrAsync(
            ReadOnlyMemory<byte> locatorHash32,
            CancellationToken cancellationToken) =>
            inner.ResolveCurrentDcrAsync(locatorHash32, cancellationToken);

        public ValueTask<ContactResolverDcrResolveResult> ResolveDcrAsync(
            OpaqueDcrResolveRequest request,
            CancellationToken cancellationToken)
        {
            if (FailResolveBeforeMutation)
            {
                throw new IOException("Injected resolve replica outage.");
            }
            return inner.ResolveDcrAsync(request, cancellationToken);
        }

        public ValueTask<ContactResolverDcrResolveResult> ReadDcrClaimAsync(
            OpaqueDcrResolveRequest request,
            CancellationToken cancellationToken) =>
            inner.ReadDcrClaimAsync(request, cancellationToken);

        public async ValueTask<ContactResolverMutationResult> WriteXurSuccessorAsync(
            OpaqueXurWriteRequest request,
            CancellationToken cancellationToken)
        {
            var result = await inner.WriteXurSuccessorAsync(request, cancellationToken);
            if (FailXurAfterMutation)
            {
                throw new IOException("Injected lost replica acknowledgement.");
            }
            return result;
        }

        public ValueTask<ContactResolverXurReadResult> ResolveXurSuccessorsAsync(
            ReadOnlyMemory<byte> serviceCapability32,
            ReadOnlyMemory<byte> exactXur1Hash32,
            ulong afterGeneration,
            int maximumEvents,
            CancellationToken cancellationToken) =>
            inner.ResolveXurSuccessorsAsync(
                serviceCapability32,
                exactXur1Hash32,
                afterGeneration,
                maximumEvents,
                cancellationToken);
    }

    private sealed class ReplicaPairFixture : IDisposable
    {
        private readonly string directory;

        internal ReplicaPairFixture()
        {
            directory = Path.Combine(
                Path.GetTempPath(),
                "xnode-contact-application-tests-" + Guid.NewGuid().ToString("N"));
            Clock = new FixedClock(Start);
            var security = new TestStorageSecurity();
            FirstStore = new ContactResolverOpaqueStore(
                Path.Combine(directory, "first.state"),
                clock: Clock,
                storageSecurity: security,
                durability: new MailboxDurabilityBarrier());
            SecondStore = new ContactResolverOpaqueStore(
                Path.Combine(directory, "second.state"),
                clock: Clock,
                storageSecurity: security,
                durability: new MailboxDurabilityBarrier());
            FirstReplica = new ContactResolverStoreReplica(Hash("replica/first"), FirstStore);
            SecondReplica = new ContactResolverStoreReplica(Hash("replica/second"), SecondStore);
        }

        internal FixedClock Clock { get; }
        internal ContactResolverOpaqueStore FirstStore { get; }
        internal ContactResolverOpaqueStore SecondStore { get; }
        internal IContactResolverReplica FirstReplica { get; }
        internal IContactResolverReplica SecondReplica { get; }

        internal ContactResolverTwoReplicaCoordinator CreateCoordinator(
            IContactResolverReplica? first = null,
            IContactResolverReplica? second = null) =>
            new(first ?? FirstReplica, second ?? SecondReplica);

        public void Dispose()
        {
            FirstStore.Dispose();
            SecondStore.Dispose();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }
}
