using System.Buffers;

namespace XNode.ProfileGenerator.Tests;

public sealed class CallerMemoryPrivacyTests
{
    private const string ExpectedInvalidInput = "The dormant profile input is invalid.";
    private const string ExpectedBounds = "A dormant profile bound was exceeded.";
    private const string Sentinel = "caller-owned-memory-sensitive-sentinel";

    [Theory]
    [InlineData(MemoryLocation.Genesis, FailureKind.Custom)]
    [InlineData(MemoryLocation.Genesis, FailureKind.ProfileContract)]
    [InlineData(MemoryLocation.Delegation, FailureKind.Custom)]
    [InlineData(MemoryLocation.Delegation, FailureKind.ProfileContract)]
    [InlineData(MemoryLocation.Bridge, FailureKind.Custom)]
    [InlineData(MemoryLocation.Bridge, FailureKind.ProfileContract)]
    public void NonOomCallerMemoryFailuresAreSanitized(
        MemoryLocation location,
        FailureKind kind)
    {
        var fixture = TestOnlyProfileFixture.Input();
        Exception failure = kind == FailureKind.ProfileContract
            ? new ProfileContractException(Sentinel)
            : new CallerOwnedMemorySentinelException(Sentinel);
        using var manager = new ThrowingMemoryManager(failure);
        var hostile = manager.CreateReadOnlyMemory(1);

        var exception = Assert.Throws<ProfileContractException>(() => Create(
            fixture,
            location,
            hostile));

        Assert.Equal(ExpectedInvalidInput, exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(Sentinel, exception.ToString(), StringComparison.Ordinal);
        if (kind == FailureKind.Custom)
        {
            Assert.DoesNotContain(
                nameof(CallerOwnedMemorySentinelException),
                exception.ToString(),
                StringComparison.Ordinal);
        }
        Assert.Equal(1, manager.GetSpanCallCount);
    }

    [Theory]
    [InlineData(MemoryLocation.Genesis)]
    [InlineData(MemoryLocation.Delegation)]
    [InlineData(MemoryLocation.Bridge)]
    public void CallerMemoryOutOfMemoryFailuresPropagateUnchanged(MemoryLocation location)
    {
        var fixture = TestOnlyProfileFixture.Input();
        var failure = new OutOfMemoryException(Sentinel);
        using var manager = new ThrowingMemoryManager(failure);
        var hostile = manager.CreateReadOnlyMemory(1);

        var exception = Assert.Throws<OutOfMemoryException>(() => Create(
            fixture,
            location,
            hostile));

        Assert.Same(failure, exception);
        Assert.Equal(1, manager.GetSpanCallCount);
    }

    [Theory]
    [InlineData(MemoryLocation.Genesis)]
    [InlineData(MemoryLocation.Delegation)]
    [InlineData(MemoryLocation.Bridge)]
    public void ComponentBoundsAreCheckedBeforeCallerMemoryIsAccessed(MemoryLocation location)
    {
        var fixture = TestOnlyProfileFixture.Input();
        using var manager = new ThrowingMemoryManager(
            new CallerOwnedMemorySentinelException(Sentinel));
        var oversized = manager.CreateReadOnlyMemory(
            ProfileComposerLimits.MaximumComponentBytes + 1);

        var exception = Assert.Throws<ProfileContractException>(() => Create(
            fixture,
            location,
            oversized));

        Assert.Equal(ExpectedBounds, exception.Message);
        Assert.Null(exception.InnerException);
        Assert.Equal(0, manager.GetSpanCallCount);
    }

    [Fact]
    public void ArrayBackedComponentsAreDefensivelyCopied()
    {
        var fixture = TestOnlyProfileFixture.Input();
        var genesis = fixture.CanonicalGenesis.ToArray();
        var delegation = fixture.CanonicalSignedDelegation.ToArray();
        var bridges = fixture.CanonicalSignedBridges
            .Select(static value => value.ToArray())
            .ToArray();
        var expectedGenesis = genesis.ToArray();
        var expectedDelegation = delegation.ToArray();
        var expectedBridges = bridges.Select(static value => value.ToArray()).ToArray();

        var input = new ProfileAssemblyInput(
            genesis,
            fixture.GenesisSignatures,
            delegation,
            bridges.Select(static value => (ReadOnlyMemory<byte>)value));

        genesis[0] ^= 0xff;
        delegation[0] ^= 0xff;
        foreach (var bridge in bridges)
            bridge[0] ^= 0xff;

        Assert.Equal(expectedGenesis, input.CanonicalGenesis.ToArray());
        Assert.Equal(expectedDelegation, input.CanonicalSignedDelegation.ToArray());
        Assert.Equal(
            expectedBridges,
            input.CanonicalSignedBridges.Select(static value => value.ToArray()));
    }

    public enum MemoryLocation
    {
        Genesis,
        Delegation,
        Bridge
    }

    public enum FailureKind
    {
        Custom,
        ProfileContract
    }

    private static ProfileAssemblyInput Create(
        ProfileAssemblyInput fixture,
        MemoryLocation location,
        ReadOnlyMemory<byte> hostile) =>
        new(
            location == MemoryLocation.Genesis ? hostile : fixture.CanonicalGenesis,
            fixture.GenesisSignatures,
            location == MemoryLocation.Delegation ? hostile : fixture.CanonicalSignedDelegation,
            location == MemoryLocation.Bridge ? [hostile] : fixture.CanonicalSignedBridges);

    private sealed class CallerOwnedMemorySentinelException(string message) :
        Exception(message);

    private sealed class ThrowingMemoryManager(Exception failure) : MemoryManager<byte>
    {
        public int GetSpanCallCount { get; private set; }

        public ReadOnlyMemory<byte> CreateReadOnlyMemory(int length) => CreateMemory(length);

        public override Span<byte> GetSpan()
        {
            GetSpanCallCount++;
            throw failure;
        }

        public override MemoryHandle Pin(int elementIndex = 0) =>
            throw new NotSupportedException();

        public override void Unpin()
        {
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
