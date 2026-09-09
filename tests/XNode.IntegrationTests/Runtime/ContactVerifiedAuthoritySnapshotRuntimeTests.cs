using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Extensions.DependencyInjection;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactVerifiedAuthoritySnapshotRuntimeTests
{
    private static readonly byte[] NetworkId = Bytes(16, 0x11);
    private static readonly byte[] GenesisHash = Bytes(32, 0x22);
    private static readonly byte[] DirectoryLeaf = Bytes(32, 0x33);

    [Fact]
    public async Task GenesisIsDurablyCommittedBeforeSnapshotIsExposed()
    {
        var candidate = State();
        var store = new RecordingStore { HoldCommit = true };
        using var source = Source(store, new FakeVerifier(candidate));

        var read = source.ReadCurrentAsync(default).AsTask();
        await store.CommitEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.False(read.IsCompleted);
        store.ReleaseCommit.TrySetResult();
        var snapshot = await read;

        Assert.NotNull(snapshot);
        Assert.Equal(1, store.CommitCount);
    }

    [Fact]
    public async Task ExactSuccessorAppendsEveryProtectedLineageAndCommitsOnce()
    {
        var previous = State();
        var successor = State(
            adhGeneration: 1,
            viewGeneration: 1,
            chain: [Bytes(4, 0x41), Bytes(4, 0x42)]);
        var store = new RecordingStore(previous);
        using var source = Source(
            store,
            new FakeVerifier(successor),
            Package(successor));

        _ = await source.ReadCurrentAsync(default);

        Assert.Equal(1, store.CommitCount);
        Assert.Same(successor, store.Current);
    }

    [Fact]
    public async Task RestartReusesProtectedLkgAndExactReplayDoesNotRewriteIt()
    {
        var previous = State();
        var store = new RecordingStore(previous);
        var verifier = new FakeVerifier(previous);
        using var source = Source(store, verifier, Package(previous));

        _ = await source.ReadCurrentAsync(default);

        Assert.Same(previous, verifier.ObservedPrevious);
        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task StaleVerifiedCandidateCannotRollProtectedLkgBack()
    {
        var previous = State(adhGeneration: 2, viewGeneration: 2);
        var stale = State(adhGeneration: 1, viewGeneration: 1);
        var store = new RecordingStore(previous);
        using var source = Source(store, new FakeVerifier(stale), Package(previous));

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await source.ReadCurrentAsync(default));

        Assert.Contains("backward", failure.Message, StringComparison.Ordinal);
        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task SameGenerationDifferentVerifiedTupleIsRejectedAsFork()
    {
        var previous = State();
        var fork = State(headMarker: 0x7a);
        var store = new RecordingStore(previous);
        using var source = Source(store, new FakeVerifier(fork), Package(previous));

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await source.ReadCurrentAsync(default));

        Assert.Contains("forks", failure.Message, StringComparison.Ordinal);
        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task CrossNetworkCandidateIsRejectedAgainstImmutableGenesisPin()
    {
        var crossNetwork = State(networkId: Bytes(16, 0x51));
        var store = new RecordingStore();
        using var source = Source(store, new FakeVerifier(crossNetwork));

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await source.ReadCurrentAsync(default));

        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task IncompleteClosureReachesProtocolVerifierAndFailsClosed()
    {
        var store = new RecordingStore();
        var clock = new SequenceClock();
        var packageSource = new RecordingPackageSource(EmptyPackage());
        using var source = new ProductionContactVerifiedAuthoritySnapshotSource(
            packageSource,
            clock,
            new ProtocolContactAuthorityPackageVerifier(clock),
            store,
            supportedDirectoryReader: 1);

        await Assert.ThrowsAsync<XPointNetworkAuthorityVerificationException>(async () =>
            await source.ReadCurrentAsync(default));

        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task UnavailableRawPackageDoesNotFallBackToCachedOrPremintedAuthority()
    {
        var store = new RecordingStore(State());
        var packageSource = new RecordingPackageSource(null);
        using var source = Source(
            store,
            new FakeVerifier(State()),
            packageSource: packageSource);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await source.ReadCurrentAsync(default));

        Assert.Contains("unavailable", failure.Message, StringComparison.Ordinal);
        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task ProtectedStateTamperFailsBeforeNetworkSourceIsCalled()
    {
        var store = new RecordingStore
        {
            ReadFailure = new CryptographicException("protected state authentication failed")
        };
        var packageSource = new RecordingPackageSource(Package(State()));
        using var source = Source(
            store,
            new FakeVerifier(State()),
            packageSource: packageSource);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.ReadCurrentAsync(default));

        Assert.Equal(0, packageSource.Calls);
    }

    [Fact]
    public async Task ConcurrentReadsAreSerializedAcrossFetchVerifyAndCommit()
    {
        var state = State();
        var packageSource = new RecordingPackageSource(Package(state)) { HoldFirstFetch = true };
        var store = new RecordingStore();
        using var source = Source(
            store,
            new FakeVerifier(state, state),
            packageSource: packageSource);

        var first = source.ReadCurrentAsync(default).AsTask();
        await packageSource.FirstFetchEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var second = source.ReadCurrentAsync(default).AsTask();
        await Task.Delay(50);

        Assert.Equal(1, packageSource.Calls);
        packageSource.ReleaseFirstFetch.TrySetResult();
        await Task.WhenAll(first, second);
        Assert.Equal(2, packageSource.Calls);
        Assert.Equal(1, packageSource.MaximumConcurrentFetches);
    }

    [Fact]
    public void ProductionContactRuntimeCannotActivateFromOptionsWithoutRealSources()
    {
        var services = new ServiceCollection();
        var options = new ContactServicePersistenceOptions
        {
            RuntimeActivation = true,
            MapReplicaEndpoint = true
        };

        var failure = Assert.Throws<InvalidOperationException>(() =>
            services.AddProductionContactServiceBoundary(
                options,
                new ContactAuthoritySnapshotPersistenceOptions
                {
                    StatePath = Path.Combine(Path.GetTempPath(), "contact-authority.state")
                }));

        Assert.Contains(nameof(IContactAuthorityArtifactPackageSource), failure.Message,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            services,
            static descriptor => descriptor.ServiceType == typeof(IContactServiceOpaqueDispatcher));
    }

    [Fact]
    public void ForwardCheckpointAdvanceRollbackAndForkAreDistinguished()
    {
        var previous = State(checkpointGeneration: 4, checkpointMarker: 0x74);
        var advanced = State(checkpointGeneration: 5, checkpointMarker: 0x75);
        var rollback = State(checkpointGeneration: 3, checkpointMarker: 0x73);
        var fork = State(checkpointGeneration: 4, checkpointMarker: 0x76);

        Assert.Equal(ContactAuthorityProgress.Advanced,
            ContactAuthorityDurableState.Compare(previous, advanced));
        Assert.Equal(ContactAuthorityProgress.Stale,
            ContactAuthorityDurableState.Compare(previous, rollback));
        Assert.Equal(ContactAuthorityProgress.Fork,
            ContactAuthorityDurableState.Compare(previous, fork));
    }

    private static ProductionContactVerifiedAuthoritySnapshotSource Source(
        RecordingStore store,
        FakeVerifier verifier,
        ContactAuthorityArtifactPackage? package = null,
        RecordingPackageSource? packageSource = null)
    {
        var clock = new SequenceClock();
        packageSource ??= new RecordingPackageSource(package ?? Package(verifier.FirstState));
        return new ProductionContactVerifiedAuthoritySnapshotSource(
            packageSource,
            clock,
            verifier,
            store,
            supportedDirectoryReader: 1);
    }

    private static ContactAuthorityArtifactPackage EmptyPackage() => new(
        [],
        [],
        ReadOnlyMemory<byte>.Empty,
        ReadOnlyMemory<byte>.Empty,
        ReadOnlyMemory<byte>.Empty,
        [],
        [],
        [],
        [],
        []);

    private static ContactAuthorityArtifactPackage Package(ContactAuthorityDurableState state) => new(
        Memories(state.Xna1Chain),
        Memories(state.Dts1Chain),
        Bytes(8, 0x61),
        Bytes(8, 0x62),
        Bytes(8, 0x63),
        Memories(state.Xvp1Chain),
        Memories(state.Xnv1Chain),
        Memories(state.Xnh1Chain),
        [Bytes(4, 0x64)],
        Memories(state.Pmt2Chain));

    private static ContactAuthorityDurableState State(
        ulong adhGeneration = 0,
        ulong viewGeneration = 0,
        byte headMarker = 0x71,
        byte[]? networkId = null,
        byte[][]? chain = null,
        ulong? checkpointGeneration = null,
        byte checkpointMarker = 0x74)
    {
        chain ??= [Bytes(4, 0x41)];
        return new ContactAuthorityDurableState
        {
            NetworkId = networkId ?? NetworkId.ToArray(),
            GenesisAuthorityCoreHash = GenesisHash.ToArray(),
            ExactAdh1 = Bytes(16, checked((byte)(0x50 + adhGeneration))),
            Adh1CoreHash = Bytes(32, checked((byte)(0x60 + adhGeneration))),
            AdhGeneration = adhGeneration,
            AdhTreeSize = adhGeneration + 1,
            HeadCoreReference = Reference("XNH1", headMarker),
            HeadTreeSize = viewGeneration + 1,
            HeadRoot = Bytes(32, headMarker),
            ViewCoreReference = Reference("XNV1", checked((byte)(0x72 + viewGeneration))),
            ViewGeneration = viewGeneration,
            AuthorityCoreReference = Reference("XNA1", 0x73),
            LastForwardCheckpointCoreReference = checkpointGeneration.HasValue
                ? Reference("XNF1", checkpointMarker)
                : [],
            LastForwardCheckpointGeneration = checkpointGeneration,
            Xna1Chain = Clone(chain),
            Dts1Chain = Clone(chain),
            Xvp1Chain = Clone(chain),
            Xnv1Chain = Clone(chain),
            Xnh1Chain = Clone(chain),
            Pmt2Chain = Clone(chain)
        };
    }

    private static ReadOnlyMemory<byte>[] Memories(byte[][] values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();

    private static byte[][] Clone(byte[][] values) =>
        values.Select(static value => value.ToArray()).ToArray();

    private static byte[] Reference(string magic, byte marker)
    {
        var output = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic, output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4, 2), 1);
        output.AsSpan(6).Fill(marker);
        return output;
    }

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();

    private sealed class SequenceClock : IOnionMonotonicClock
    {
        private ulong sample = 100;
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(Bytes(16, 0x7f), sample++));
        }
    }

    private sealed class RecordingPackageSource(ContactAuthorityArtifactPackage? package)
        : IContactAuthorityArtifactPackageSource
    {
        private int concurrentFetches;
        public int Calls { get; private set; }
        public int MaximumConcurrentFetches { get; private set; }
        public bool HoldFirstFetch { get; init; }
        public TaskCompletionSource FirstFetchEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirstFetch { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public XPointNetworkGenesisPin GenesisPin { get; } = new(NetworkId, GenesisHash);
        public ReadOnlyMemory<byte> DirectoryLeafKey => DirectoryLeaf.ToArray();

        public async ValueTask<ContactAuthorityArtifactPackage?> FetchAsync(
            ContactAuthorityArtifactRequest request,
            CancellationToken cancellationToken)
        {
            _ = request;
            Calls++;
            var current = Interlocked.Increment(ref concurrentFetches);
            MaximumConcurrentFetches = Math.Max(MaximumConcurrentFetches, current);
            try
            {
                if (HoldFirstFetch && Calls == 1)
                {
                    FirstFetchEntered.TrySetResult();
                    await ReleaseFirstFetch.Task.WaitAsync(cancellationToken);
                }
                return package;
            }
            finally
            {
                Interlocked.Decrement(ref concurrentFetches);
            }
        }
    }

    private sealed class FakeVerifier(params ContactAuthorityDurableState[] inputStates)
        : IContactAuthorityPackageVerifier
    {
        private readonly Queue<ContactAuthorityDurableState> states = new(inputStates);
        public ContactAuthorityDurableState FirstState { get; } = inputStates[0];
        public ContactAuthorityDurableState? ObservedPrevious { get; private set; }

        public ValueTask<ContactAuthorityVerificationResult> VerifyAsync(
            XPointNetworkGenesisPin genesisPin,
            ContactAuthorityArtifactRequest request,
            ContactAuthorityArtifactPackage package,
            Deep.Protocol.AccountDirectoryV1.AccountDirectoryMonotonicRequestWindow monotonic,
            ContactAuthorityDurableState? previous,
            ushort supportedDirectoryReader,
            CancellationToken cancellationToken)
        {
            _ = genesisPin;
            _ = request;
            _ = package;
            _ = monotonic;
            _ = supportedDirectoryReader;
            cancellationToken.ThrowIfCancellationRequested();
            ObservedPrevious = previous;
            var state = states.Count > 1 ? states.Dequeue() : states.Peek();
            var snapshot = (ContactVerifiedAuthoritySnapshot)RuntimeHelpers
                .GetUninitializedObject(typeof(ContactVerifiedAuthoritySnapshot));
            return ValueTask.FromResult(new ContactAuthorityVerificationResult(snapshot, state));
        }
    }

    private sealed class RecordingStore(ContactAuthorityDurableState? initial = null)
        : IContactAuthorityDurableStateStore
    {
        public ContactAuthorityDurableState? Current { get; private set; } = initial;
        public Exception? ReadFailure { get; init; }
        public bool HoldCommit { get; init; }
        public int CommitCount { get; private set; }
        public TaskCompletionSource CommitEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseCommit { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask<ContactAuthorityDurableState?> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ReadFailure is not null)
            {
                return ValueTask.FromException<ContactAuthorityDurableState?>(ReadFailure);
            }
            return ValueTask.FromResult(Current);
        }

        public async ValueTask CommitAsync(
            ContactAuthorityDurableState state,
            CancellationToken cancellationToken)
        {
            CommitEntered.TrySetResult();
            if (HoldCommit)
            {
                await ReleaseCommit.Task.WaitAsync(cancellationToken);
            }
            Current = state;
            CommitCount++;
        }
    }
}
