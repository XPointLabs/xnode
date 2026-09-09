using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactAuthoritySourceTests
{
    private static readonly byte[] NetworkId = Bytes(16, 1);
    private static readonly byte[] LocatorHash = Bytes(32, 2);

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public async Task PlacementRejectsUnboundedShardBeforeAuthorityRead(int length)
    {
        var source = new RecordingSnapshotSource();
        var adapter = new VerifiedContactServicePlacementAuthoritySource(
            source,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(100)));

        await Assert.ThrowsAnyAsync<ArgumentException>(async () =>
            await adapter.MintAsync(
                ContactServiceRequestKind.ResolveInvite,
                Bytes(length, 3),
                default));

        Assert.Equal(0, source.Calls);
    }

    [Fact]
    public async Task PlacementRejectsZeroShardBeforeAuthorityRead()
    {
        var source = new RecordingSnapshotSource();
        var adapter = new VerifiedContactServicePlacementAuthoritySource(
            source,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(100)));

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await adapter.MintAsync(
                ContactServiceRequestKind.ResolveInvite,
                new byte[32],
                default));

        Assert.Equal(0, source.Calls);
    }

    [Fact]
    public async Task PlacementHasNoFallbackWhenVerifiedSnapshotIsUnavailable()
    {
        var source = new RecordingSnapshotSource(
            new IOException("verified directory unavailable"));
        var adapter = new VerifiedContactServicePlacementAuthoritySource(
            source,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(100)));

        await Assert.ThrowsAsync<IOException>(async () =>
            await adapter.MintAsync(
                ContactServiceRequestKind.ResolveInvite,
                Bytes(32, 3),
                default));

        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public async Task PublicationVerifierRejectsNullBeforeAuthorityRead()
    {
        var source = new RecordingSnapshotSource();
        var adapter = new VerifiedContactPublicationAuthorizationVerifier(source);

        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await adapter.VerifyAsync(null!, default));

        Assert.Equal(0, source.Calls);
    }

    [Fact]
    public async Task PublicationVerifierDoesNotSwallowCancellationOrReadAuthority()
    {
        var source = new RecordingSnapshotSource();
        var adapter = new VerifiedContactPublicationAuthorizationVerifier(source);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var request = (Xpu1Request)RuntimeHelpers
            .GetUninitializedObject(typeof(Xpu1Request));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await adapter.VerifyAsync(request, cancellation.Token));

        Assert.Equal(0, source.Calls);
    }

    [Theory]
    [InlineData(15, 32)]
    [InlineData(16, 31)]
    [InlineData(17, 32)]
    [InlineData(16, 33)]
    public async Task RouteRejectsUnboundedSelectorBeforeCapabilityRead(
        int networkLength,
        int locatorLength)
    {
        var source = new RecordingRouteSource();
        var adapter = new VerifiedContactRouteClosureSource(
            source,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(100)));

        await Assert.ThrowsAnyAsync<ArgumentException>(async () =>
            await adapter.ReadAsync(
                Bytes(networkLength, 1),
                Bytes(locatorLength, 2),
                default));

        Assert.Equal(0, source.Calls);
    }

    [Fact]
    public async Task MissingVerifiedRouteReturnsMissingWithoutRawOrHttpFallback()
    {
        var source = new RecordingRouteSource();
        var adapter = new VerifiedContactRouteClosureSource(
            source,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(100)));

        var result = await adapter.ReadAsync(NetworkId, LocatorHash, default);

        Assert.Null(result);
        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public async Task RouteProviderFailureIsFailClosed()
    {
        var source = new RecordingRouteSource(
            new IOException("verified route unavailable"));
        var adapter = new VerifiedContactRouteClosureSource(
            source,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(100)));

        await Assert.ThrowsAsync<IOException>(async () =>
            await adapter.ReadAsync(NetworkId, LocatorHash, default));

        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public async Task ForgedRouteCapabilityIsRejectedAsAuthorityFailure()
    {
        var source = new RecordingRouteSource(RouteClosure(
            ("XRR1", 643),
            ("XRA1", 550),
            ("XRC1", 940),
            ("XSS1", 643),
            ("PMT2", 842),
            ("PMS2", 500)));
        var adapter = new VerifiedContactRouteClosureSource(
            source,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds(100)));

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await adapter.ReadAsync(NetworkId, LocatorHash, default));

        Assert.IsType<ContactFormatException>(failure.InnerException);
        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public void CanonicalizerWritesFrozenSixRecordOrderAndExactBound()
    {
        var closure = RouteClosure(
            ("XRR1", 643),
            ("XRA1", 550),
            ("XRC1", 940),
            ("XSS1", 643),
            ("PMT2", 842),
            ("PMS2", 500));

        var encoded = ContactRouteClosureCanonicalizer.EncodeVerified(closure);

        Assert.Equal(4_143, encoded.Length);
        Assert.Equal(6, encoded[0]);
        var offset = 1;
        foreach (var expected in new[] { 643, 550, 940, 643, 842, 500 })
        {
            Assert.Equal((uint)expected,
                BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(offset, 4)));
            offset += 4 + expected;
        }
        Assert.Equal(encoded.Length, offset);
    }

    [Fact]
    public void CanonicalizerRejectsClosureOverXis1Bound()
    {
        var closure = RouteClosure(
            ("XRR1", 643),
            ("XRA1", 550),
            ("XRC1", 940),
            ("XSS1", 643),
            ("PMT2", 842),
            ("PMS2", ContactRouteClosureCanonicalizer.MaximumEncodedBytes));

        Assert.Throws<InvalidOperationException>(() =>
            ContactRouteClosureCanonicalizer.EncodeVerified(closure));
    }

    [Fact]
    public void CanonicalizerRejectsClosureBelowXis1Bound()
    {
        var closure = RouteClosure(
            ("XRR1", 1),
            ("XRA1", 1),
            ("XRC1", 1),
            ("XSS1", 1),
            ("PMT2", 1),
            ("PMS2", 1));

        Assert.Throws<InvalidOperationException>(() =>
            ContactRouteClosureCanonicalizer.EncodeVerified(closure));
    }

    [Fact]
    public void ProductionAdaptersDependOnlyOnVerifiedCapabilitySources()
    {
        var placementDependencies = typeof(VerifiedContactServicePlacementAuthoritySource)
            .GetConstructors()
            .Single()
            .GetParameters()
            .Select(static parameter => parameter.ParameterType)
            .ToArray();
        var authorizationDependencies = typeof(VerifiedContactPublicationAuthorizationVerifier)
            .GetConstructors()
            .Single()
            .GetParameters()
            .Select(static parameter => parameter.ParameterType)
            .ToArray();
        var routeDependencies = typeof(VerifiedContactRouteClosureSource)
            .GetConstructors()
            .Single()
            .GetParameters()
            .Select(static parameter => parameter.ParameterType)
            .ToArray();

        Assert.Equal(
            [typeof(IContactVerifiedAuthoritySnapshotSource), typeof(IClock)],
            placementDependencies);
        Assert.Equal(
            [typeof(IContactVerifiedAuthoritySnapshotSource)],
            authorizationDependencies);
        Assert.Equal(
            [typeof(IVerifiedContactRouteClosureSource), typeof(IClock)],
            routeDependencies);
        Assert.DoesNotContain(
            placementDependencies.Concat(authorizationDependencies).Concat(routeDependencies),
            static dependency => dependency == typeof(HttpClient)
                || dependency == typeof(ProductionMailboxAuthorityProvider));
    }

    private static VerifiedContactRouteClosure RouteClosure(
        params (string Magic, int CanonicalLength)[] records)
    {
        Assert.Equal(6, records.Length);
        var closure = (VerifiedContactRouteClosure)RuntimeHelpers
            .GetUninitializedObject(typeof(VerifiedContactRouteClosure));
        Invite(closure) = Record(("NOT1", 611));
        Authority(closure) = (VerifiedContactNetworkAuthority)RuntimeHelpers
            .GetUninitializedObject(typeof(VerifiedContactNetworkAuthority));
        Reachability(closure) = Record(records[0]);
        Authorization(closure) = Record(records[1]);
        Route(closure) = Record(records[2]);
        Successor(closure) = Record(records[3]);
        Projection(closure) = Record(records[4]);
        Selection(closure) = Record(records[5]);
        return closure;
    }

    private static ContactRecord Record((string Magic, int CanonicalLength) value)
    {
        var record = (ContactRecord)RuntimeHelpers.GetUninitializedObject(typeof(ContactRecord));
        Magic(record) = value.Magic;
        Canonical(record) = Bytes(value.CanonicalLength, 0x5a);
        return record;
    }

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed class RecordingSnapshotSource(Exception? failure = null)
        : IContactVerifiedAuthoritySnapshotSource
    {
        public int Calls { get; private set; }

        public ValueTask<ContactVerifiedAuthoritySnapshot> ReadCurrentAsync(
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromException<ContactVerifiedAuthoritySnapshot>(
                failure ?? new InvalidOperationException("No synthetic verified capability."));
        }
    }

    private sealed class RecordingRouteSource : IVerifiedContactRouteClosureSource
    {
        private readonly Exception? failure;
        private readonly VerifiedContactRouteClosure? closure;

        internal RecordingRouteSource(Exception? failure = null) =>
            this.failure = failure;

        internal RecordingRouteSource(VerifiedContactRouteClosure closure) =>
            this.closure = closure;

        public int Calls { get; private set; }

        public ValueTask<VerifiedContactRouteClosure?> ReadCurrentAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken)
        {
            Calls++;
            if (failure is not null)
            {
                return ValueTask.FromException<VerifiedContactRouteClosure?>(failure);
            }
            return ValueTask.FromResult(closure);
        }
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Invite>k__BackingField")]
    private static extern ref ContactRecord Invite(VerifiedContactRouteClosure value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Authority>k__BackingField")]
    private static extern ref VerifiedContactNetworkAuthority Authority(
        VerifiedContactRouteClosure value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Reachability>k__BackingField")]
    private static extern ref ContactRecord Reachability(VerifiedContactRouteClosure value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Authorization>k__BackingField")]
    private static extern ref ContactRecord Authorization(VerifiedContactRouteClosure value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Route>k__BackingField")]
    private static extern ref ContactRecord Route(VerifiedContactRouteClosure value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Successor>k__BackingField")]
    private static extern ref ContactRecord Successor(VerifiedContactRouteClosure value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Projection>k__BackingField")]
    private static extern ref ContactRecord Projection(VerifiedContactRouteClosure value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Selection>k__BackingField")]
    private static extern ref ContactRecord Selection(VerifiedContactRouteClosure value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Magic>k__BackingField")]
    private static extern ref string Magic(ContactRecord value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "canonical")]
    private static extern ref byte[] Canonical(ContactRecord value);
}
