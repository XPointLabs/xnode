using System.Collections;

namespace XNode.ProfileGenerator.Tests;

public sealed class CallerEnumerablePrivacyTests
{
    private const string ExpectedInvalidInput = "The dormant profile input is invalid.";
    private const string Sentinel = "caller-owned-enumerable-sensitive-sentinel";

    [Theory]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.GetEnumerator, FailureKind.Custom)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.GetEnumerator, FailureKind.ProfileContract)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.MoveNext, FailureKind.Custom)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.MoveNext, FailureKind.ProfileContract)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.Current, FailureKind.Custom)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.Current, FailureKind.ProfileContract)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.Dispose, FailureKind.Custom)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.Dispose, FailureKind.ProfileContract)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.GetEnumerator, FailureKind.Custom)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.GetEnumerator, FailureKind.ProfileContract)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.MoveNext, FailureKind.Custom)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.MoveNext, FailureKind.ProfileContract)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.Current, FailureKind.Custom)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.Current, FailureKind.ProfileContract)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.Dispose, FailureKind.Custom)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.Dispose, FailureKind.ProfileContract)]
    public void NonOomCallerEnumerableFailuresAreSanitized(
        CallerCollection collection,
        FailureStage stage,
        FailureKind kind)
    {
        var fixture = TestOnlyProfileFixture.Input();
        Exception failure = kind == FailureKind.ProfileContract
            ? new ProfileContractException(Sentinel)
            : new CallerOwnedEnumerableSentinelException(Sentinel);

        var exception = Assert.Throws<ProfileContractException>(() => new ProfileAssemblyInput(
            fixture.CanonicalGenesis,
            collection == CallerCollection.GenesisSignatures
                ? new ThrowingEnumerable<ProfilePublicSignature>(stage, failure)
                : fixture.GenesisSignatures,
            fixture.CanonicalSignedDelegation,
            collection == CallerCollection.SignedBridges
                ? new ThrowingEnumerable<ReadOnlyMemory<byte>>(stage, failure)
                : fixture.CanonicalSignedBridges));

        Assert.Equal(ExpectedInvalidInput, exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(Sentinel, exception.ToString(), StringComparison.Ordinal);
        if (kind == FailureKind.Custom)
        {
            Assert.DoesNotContain(
                nameof(CallerOwnedEnumerableSentinelException),
                exception.ToString(),
                StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.GetEnumerator)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.MoveNext)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.Current)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.Dispose)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.GetEnumerator)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.MoveNext)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.Current)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.Dispose)]
    public void CallerEnumerableOutOfMemoryFailuresPropagateUnchanged(
        CallerCollection collection,
        FailureStage stage)
    {
        var fixture = TestOnlyProfileFixture.Input();
        var failure = new OutOfMemoryException(Sentinel);

        var exception = Assert.Throws<OutOfMemoryException>(() => new ProfileAssemblyInput(
            fixture.CanonicalGenesis,
            collection == CallerCollection.GenesisSignatures
                ? new ThrowingEnumerable<ProfilePublicSignature>(stage, failure)
                : fixture.GenesisSignatures,
            fixture.CanonicalSignedDelegation,
            collection == CallerCollection.SignedBridges
                ? new ThrowingEnumerable<ReadOnlyMemory<byte>>(stage, failure)
                : fixture.CanonicalSignedBridges));

        Assert.Same(failure, exception);
    }

    [Theory]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.MoveNext)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.Current)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.MoveNext)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.Current)]
    public void PrimaryOutOfMemoryIsNotMaskedByDisposeOutOfMemory(
        CallerCollection collection,
        FailureStage primaryStage)
    {
        var fixture = TestOnlyProfileFixture.Input();
        var primaryFailure = new OutOfMemoryException("primary-oom-sentinel");
        var disposeFailure = new OutOfMemoryException("dispose-oom-sentinel");

        var exception = Assert.Throws<OutOfMemoryException>(() => new ProfileAssemblyInput(
            fixture.CanonicalGenesis,
            collection == CallerCollection.GenesisSignatures
                ? new DualFailureEnumerable<ProfilePublicSignature>(
                    primaryStage,
                    primaryFailure,
                    disposeFailure)
                : fixture.GenesisSignatures,
            fixture.CanonicalSignedDelegation,
            collection == CallerCollection.SignedBridges
                ? new DualFailureEnumerable<ReadOnlyMemory<byte>>(
                    primaryStage,
                    primaryFailure,
                    disposeFailure)
                : fixture.CanonicalSignedBridges));

        Assert.Same(primaryFailure, exception);
        Assert.NotSame(disposeFailure, exception);
    }

    public enum CallerCollection
    {
        GenesisSignatures,
        SignedBridges
    }

    public enum FailureStage
    {
        GetEnumerator,
        MoveNext,
        Current,
        Dispose
    }

    public enum FailureKind
    {
        Custom,
        ProfileContract
    }

    private sealed class CallerOwnedEnumerableSentinelException(string message) :
        Exception(message);

    private sealed class ThrowingEnumerable<T>(FailureStage stage, Exception failure) :
        IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator()
        {
            if (stage == FailureStage.GetEnumerator)
                throw failure;
            return new ThrowingEnumerator<T>(stage, failure);
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class ThrowingEnumerator<T>(FailureStage stage, Exception failure) :
        IEnumerator<T>
    {
        private bool _moved;

        public T Current =>
            stage == FailureStage.Current ? throw failure : default!;

        object? IEnumerator.Current => Current;

        public bool MoveNext()
        {
            if (stage == FailureStage.MoveNext)
                throw failure;
            if (stage == FailureStage.Current && !_moved)
            {
                _moved = true;
                return true;
            }
            return false;
        }

        public void Reset() => throw new NotSupportedException();

        public void Dispose()
        {
            if (stage == FailureStage.Dispose)
                throw failure;
        }
    }

    private sealed class DualFailureEnumerable<T>(
        FailureStage primaryStage,
        Exception primaryFailure,
        Exception disposeFailure) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() =>
            new DualFailureEnumerator<T>(primaryStage, primaryFailure, disposeFailure);

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class DualFailureEnumerator<T>(
        FailureStage primaryStage,
        Exception primaryFailure,
        Exception disposeFailure) : IEnumerator<T>
    {
        private bool _moved;

        public T Current =>
            primaryStage == FailureStage.Current ? throw primaryFailure : default!;

        object? IEnumerator.Current => Current;

        public bool MoveNext()
        {
            if (primaryStage == FailureStage.MoveNext)
                throw primaryFailure;
            if (!_moved)
            {
                _moved = true;
                return true;
            }
            return false;
        }

        public void Reset() => throw new NotSupportedException();

        public void Dispose() => throw disposeFailure;
    }
}
