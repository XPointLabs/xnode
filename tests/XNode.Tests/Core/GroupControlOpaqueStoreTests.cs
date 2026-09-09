using System.Security.Cryptography;
using System.Text;
using XNode.Core.GroupControl;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class GroupControlOpaqueStoreTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 7, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void WriteFetchExactReplayAndDefensiveCopiesSurviveRestart()
    {
        using var fixture = new StoreFixture();
        var capability = Hash("restart/capability");
        var gsr = Hash("restart/gsr");
        var request = WriteRequest(capability, gsr, "restart/1", 1, Zero32(), fixture.Clock);

        using (var store = fixture.Open())
        {
            Assert.Equal(GroupControlMutationDisposition.Committed, store.Write(request).Disposition);
        }
        using (var store = fixture.Open())
        {
            Assert.Equal(GroupControlMutationDisposition.ExactReplay, store.Write(request).Disposition);
            var fetched = store.Fetch(FetchRequest(capability, gsr, "restart/fetch", 0));
            Assert.Equal(GroupControlReadDisposition.Events, fetched.Disposition);
            Assert.Single(fetched.Records);
            Assert.Equal(request.SealedGcf1.ToArray(), fetched.Records[0].SealedGcf1);

            fetched.Records[0].SealedGcf1[0] ^= 0xff;
            fetched.Records[0].SealedGcf1Hash[0] ^= 0xff;
            var again = store.Fetch(FetchRequest(capability, gsr, "restart/fetch/again", 0));
            Assert.Equal(request.SealedGcf1.ToArray(), again.Records[0].SealedGcf1);
            Assert.Equal(request.SealedGcf1Hash.ToArray(), again.Records[0].SealedGcf1Hash);
        }
    }

    [Fact]
    public void StaleSequenceDoesNotMutateButChangedSameSequenceForkLatchesAcrossRestart()
    {
        using var fixture = new StoreFixture();
        var capability = Hash("fork/capability");
        var gsr = Hash("fork/gsr");
        var first = WriteRequest(capability, gsr, "fork/1", 1, Zero32(), fixture.Clock);

        using (var store = fixture.Open())
        {
            Assert.Equal(GroupControlMutationDisposition.Committed, store.Write(first).Disposition);
            var stale = WriteRequest(capability, gsr, "fork/stale", 3, first.SealedGcf1Hash, fixture.Clock);
            Assert.Equal(GroupControlMutationDisposition.StaleSequence, store.Write(stale).Disposition);

            var changedCiphertext = Ciphertext("fork/changed-body", 32);
            var changed = new OpaqueGroupControlWriteRequest(
                capability,
                gsr,
                first.OperationId,
                Hash("request/fork/changed-body"),
                1,
                Zero32(),
                SHA256.HashData(changedCiphertext),
                changedCiphertext,
                first.EffectiveExpiresAtUnixSeconds);
            Assert.Equal(GroupControlMutationDisposition.Conflict, store.Write(changed).Disposition);
            Assert.Equal(
                GroupControlReadDisposition.Conflict,
                store.Fetch(FetchRequest(capability, gsr, "fork/fetch", 0)).Disposition);
        }
        using (var store = fixture.Open())
        {
            var successor = WriteRequest(capability, gsr, "fork/2", 2, first.SealedGcf1Hash, fixture.Clock);
            Assert.Equal(GroupControlMutationDisposition.ForkLatched, store.Write(successor).Disposition);
            Assert.Equal(
                GroupControlReadDisposition.Conflict,
                store.Fetch(FetchRequest(capability, gsr, "fork/fetch/restart", 0)).Disposition);
        }
    }

    [Fact]
    public void WrongPredecessorForkLatchesAndGsrSubstitutionIsRejected()
    {
        using var fixture = new StoreFixture();
        var capability = Hash("predecessor/capability");
        var gsr = Hash("predecessor/gsr");
        var first = WriteRequest(capability, gsr, "predecessor/1", 1, Zero32(), fixture.Clock);
        using var store = fixture.Open();
        Assert.Equal(GroupControlMutationDisposition.Committed, store.Write(first).Disposition);

        var wrong = WriteRequest(capability, gsr, "predecessor/2", 2, Hash("wrong predecessor"), fixture.Clock);
        Assert.Equal(GroupControlMutationDisposition.Conflict, store.Write(wrong).Disposition);
        Assert.Equal(
            GroupControlReadDisposition.Conflict,
            store.Fetch(FetchRequest(capability, Hash("substituted gsr"), "predecessor/fetch", 0)).Disposition);
    }

    [Fact]
    public void ExpiryReturnsExplicitGapAndCannotBeExtendedPastFourHundredDays()
    {
        using var fixture = new StoreFixture();
        var capability = Hash("expiry/capability");
        var gsr = Hash("expiry/gsr");
        using var store = fixture.Open();
        var first = WriteRequest(
            capability,
            gsr,
            "expiry/1",
            1,
            Zero32(),
            fixture.Clock,
            fixture.Clock.UtcNow.AddSeconds(1));
        Assert.Equal(GroupControlMutationDisposition.Committed, store.Write(first).Disposition);
        var second = WriteRequest(capability, gsr, "expiry/2", 2, first.SealedGcf1Hash, fixture.Clock);
        Assert.Equal(GroupControlMutationDisposition.Committed, store.Write(second).Disposition);

        fixture.Clock.UtcNow = fixture.Clock.UtcNow.AddSeconds(2);
        Assert.Equal(
            GroupControlReadDisposition.Gap,
            store.Fetch(FetchRequest(capability, gsr, "expiry/fetch", 0)).Disposition);
        Assert.Equal(
            GroupControlReadDisposition.NoChange,
            store.Fetch(FetchRequest(capability, gsr, "expiry/no-change", 2)).Disposition);

        Assert.Throws<ArgumentOutOfRangeException>(() => store.Write(WriteRequest(
            Hash("too-long/capability"),
            Hash("too-long/gsr"),
            "too-long/1",
            1,
            Zero32(),
            fixture.Clock,
            fixture.Clock.UtcNow.AddDays(400).AddSeconds(1))));
    }

    [Fact]
    public void CompactionRequiresExpiryAndRetainsAtLeastOneThousandTwentyFourCommits()
    {
        using var fixture = new StoreFixture(new GroupControlOpaqueStoreOptions
        {
            MaximumStreams = 1,
            MaximumRecordsPerStream = 1_025,
            MaximumCiphertextBytes = 1_000_000,
            MaximumPersistedBytes = 4_000_000
        });
        var capability = Hash("retention/capability");
        var gsr = Hash("retention/gsr");
        using var store = fixture.Open();
        byte[] predecessor = Zero32();
        OpaqueGroupControlWriteRequest? first = null;
        OpaqueGroupControlWriteRequest? last = null;
        for (ulong sequence = 1; sequence <= 1_025; sequence++)
        {
            var expiry = sequence == 1
                ? fixture.Clock.UtcNow.AddSeconds(1)
                : fixture.Clock.UtcNow.AddDays(400);
            var request = WriteRequest(
                capability,
                gsr,
                "retention/" + sequence,
                sequence,
                predecessor,
                fixture.Clock,
                expiry,
                ciphertextLength: 4);
            Assert.Equal(GroupControlMutationDisposition.Committed, store.Write(request).Disposition);
            first ??= request;
            last = request;
            predecessor = request.SealedGcf1Hash.ToArray();
        }

        fixture.Clock.UtcNow = fixture.Clock.UtcNow.AddSeconds(2);
        var checkpoint = VerifiedGroupControlCompactionCheckpoint.FromVerifiedClosure(
            capability,
            1,
            first!.SealedGcf1Hash);
        Assert.Equal(1, store.Compact(checkpoint));
        Assert.Equal(0, store.Compact(checkpoint));
        Assert.Equal(
            GroupControlReadDisposition.Gap,
            store.Fetch(FetchRequest(capability, gsr, "retention/gap", 0)).Disposition);
        var tail = store.Fetch(FetchRequest(capability, gsr, "retention/tail", 1, 64));
        Assert.Equal(GroupControlReadDisposition.Events, tail.Disposition);
        Assert.Equal((ulong)2, tail.Records[0].ControlSequence);
        Assert.True(tail.HasMore);
        Assert.Equal((ulong)1_025, tail.CurrentControlSequence);
        Assert.Equal(last!.SealedGcf1Hash.ToArray(), tail.CurrentControlHash);
    }

    [Fact]
    public void StreamAndByteQuotasRejectBeforeMutation()
    {
        using var fixture = new StoreFixture(new GroupControlOpaqueStoreOptions
        {
            MaximumStreams = 1,
            MaximumRecordsPerStream = GroupControlOpaqueStoreOptions.MinimumRetainedCommits,
            MaximumCiphertextBytes = GroupControlOpaqueStoreOptions.MaximumSealedGcf1Bytes,
            MaximumPersistedBytes = 1_000_000
        });
        using var store = fixture.Open();
        var full = WriteRequest(
            Hash("quota/capability/1"),
            Hash("quota/gsr/1"),
            "quota/1",
            1,
            Zero32(),
            fixture.Clock,
            ciphertextLength: GroupControlOpaqueStoreOptions.MaximumSealedGcf1Bytes);
        Assert.Equal(GroupControlMutationDisposition.Committed, store.Write(full).Disposition);
        var rejected = WriteRequest(
            Hash("quota/capability/2"),
            Hash("quota/gsr/2"),
            "quota/2",
            1,
            Zero32(),
            fixture.Clock);
        Assert.Equal(GroupControlMutationDisposition.QuotaExceeded, store.Write(rejected).Disposition);
        Assert.Equal(
            GroupControlReadDisposition.NotFound,
            store.Fetch(FetchRequest(rejected.ServiceCapability, rejected.ExactGsr1Hash, "quota/fetch", 0)).Disposition);
    }

    [Fact]
    public void CorruptStateIsQuarantinedAndNeverSilentlyReset()
    {
        using var fixture = new StoreFixture();
        var request = WriteRequest(
            Hash("corrupt/capability"),
            Hash("corrupt/gsr"),
            "corrupt/1",
            1,
            Zero32(),
            fixture.Clock);
        using (var store = fixture.Open())
        {
            Assert.Equal(GroupControlMutationDisposition.Committed, store.Write(request).Disposition);
        }

        var bytes = File.ReadAllBytes(fixture.StatePath);
        bytes[^1] ^= 0xff;
        File.WriteAllBytes(fixture.StatePath, bytes);
        Assert.Throws<GroupControlStoreCorruptException>(() => fixture.Open());
        Assert.False(File.Exists(fixture.StatePath));
        Assert.Single(Directory.GetFiles(fixture.DirectoryPath, "*.quarantine.*"));
    }

    [Fact]
    public async Task ApplicationRequiresTwoReplicaDurabilityAndReconcilesLostAcknowledgement()
    {
        using var fixture = new ReplicaFixture();
        var second = new SwitchableReplica(fixture.SecondReplica) { FailAfterMutation = true };
        using var coordinator = fixture.Coordinator(fixture.FirstReplica, second);
        var service = new GroupControlApplicationService(coordinator);
        var request = WriteRequest(
            Hash("application/capability"),
            Hash("application/gsr"),
            "application/1",
            1,
            Zero32(),
            fixture.Clock);

        var unknown = await service.WriteAsync(request);
        Assert.Equal(GroupControlApplicationStatus.OutcomeUnknown, unknown.Status);
        Assert.Equal(GroupControlMutationOutcome.OutcomeUnknown, unknown.MutationOutcome);
        Assert.Equal(1, unknown.DurableReplicaCount);

        second.FailAfterMutation = false;
        var replay = await service.ReconcileAsync(request);
        Assert.Equal(GroupControlApplicationStatus.ExactReplay, replay.Status);
        Assert.Equal(GroupControlMutationOutcome.DurablyCommitted, replay.MutationOutcome);
        Assert.Equal(2, replay.DurableReplicaCount);

        var fetched = await service.FetchAsync(FetchRequest(
            request.ServiceCapability,
            request.ExactGsr1Hash,
            "application/fetch",
            0));
        Assert.Equal(GroupControlApplicationStatus.Events, fetched.Status);
        Assert.Single(fetched.Records);
        fetched.Records[0].SealedGcf1[0] ^= 0xff;
        Assert.Equal(request.SealedGcf1.ToArray(), (await service.FetchAsync(FetchRequest(
            request.ServiceCapability,
            request.ExactGsr1Hash,
            "application/fetch/again",
            0))).Records[0].SealedGcf1);
    }

    private static OpaqueGroupControlWriteRequest WriteRequest(
        ReadOnlySpan<byte> capability,
        ReadOnlySpan<byte> gsr,
        string operation,
        ulong sequence,
        ReadOnlySpan<byte> predecessor,
        FixedClock clock,
        DateTimeOffset? expiry = null,
        int ciphertextLength = 32)
    {
        var ciphertext = Ciphertext(operation, ciphertextLength);
        return new(
            capability,
            gsr,
            Hash("operation/" + operation),
            Hash("request/" + operation),
            sequence,
            predecessor,
            SHA256.HashData(ciphertext),
            ciphertext,
            checked((ulong)(expiry ?? clock.UtcNow.AddDays(1)).ToUnixTimeSeconds()));
    }

    private static OpaqueGroupControlFetchRequest FetchRequest(
        ReadOnlySpan<byte> capability,
        ReadOnlySpan<byte> gsr,
        string operation,
        ulong after,
        int maximum = 64) =>
        new(
            capability,
            gsr,
            Hash("operation/" + operation),
            Hash("request/" + operation),
            after,
            maximum);

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

    private sealed class StoreFixture : IDisposable
    {
        private readonly GroupControlOpaqueStoreOptions? options;

        internal StoreFixture(GroupControlOpaqueStoreOptions? options = null)
        {
            this.options = options;
            DirectoryPath = Path.Combine(Path.GetTempPath(), "xnode-group-control-tests-" + Guid.NewGuid().ToString("N"));
            StatePath = Path.Combine(DirectoryPath, "group-control.state");
            Clock = new FixedClock(Start);
        }

        internal string DirectoryPath { get; }
        internal string StatePath { get; }
        internal FixedClock Clock { get; }

        internal GroupControlOpaqueStore Open() =>
            new(StatePath, options, Clock, new TestStorageSecurity(), new MailboxDurabilityBarrier());

        public void Dispose()
        {
            if (Directory.Exists(DirectoryPath))
            {
                Directory.Delete(DirectoryPath, recursive: true);
            }
        }
    }

    private sealed class ReplicaFixture : IDisposable
    {
        private readonly string directory;

        internal ReplicaFixture()
        {
            directory = Path.Combine(Path.GetTempPath(), "xnode-group-control-replicas-" + Guid.NewGuid().ToString("N"));
            Clock = new FixedClock(Start);
            FirstStore = Open("first.state");
            SecondStore = Open("second.state");
            FirstReplica = new GroupControlStoreReplica(Hash("replica/first"), FirstStore);
            SecondReplica = new GroupControlStoreReplica(Hash("replica/second"), SecondStore);
        }

        internal FixedClock Clock { get; }
        internal GroupControlOpaqueStore FirstStore { get; }
        internal GroupControlOpaqueStore SecondStore { get; }
        internal IGroupControlReplica FirstReplica { get; }
        internal IGroupControlReplica SecondReplica { get; }

        internal GroupControlTwoReplicaCoordinator Coordinator(
            IGroupControlReplica? first = null,
            IGroupControlReplica? second = null) =>
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

        private GroupControlOpaqueStore Open(string name) =>
            new(
                Path.Combine(directory, name),
                clock: Clock,
                storageSecurity: new TestStorageSecurity(),
                durability: new MailboxDurabilityBarrier());
    }

    private sealed class SwitchableReplica(IGroupControlReplica inner) : IGroupControlReplica
    {
        internal bool FailAfterMutation { get; set; }
        public ReadOnlyMemory<byte> ReplicaId => inner.ReplicaId;

        public async ValueTask<GroupControlMutationResult> WriteAsync(
            OpaqueGroupControlWriteRequest request,
            CancellationToken cancellationToken)
        {
            var result = await inner.WriteAsync(request, cancellationToken);
            if (FailAfterMutation)
            {
                throw new IOException("Injected lost acknowledgement.");
            }
            return result;
        }

        public ValueTask<GroupControlReadResult> FetchAsync(
            OpaqueGroupControlFetchRequest request,
            CancellationToken cancellationToken) =>
            inner.FetchAsync(request, cancellationToken);
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }
}
