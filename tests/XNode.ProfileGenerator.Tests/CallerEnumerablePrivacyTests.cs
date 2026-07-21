using System.Collections;

namespace XNode.ProfileGenerator.Tests;

public sealed class CallerEnumerablePrivacyTests
{
    private const string ExpectedInvalidInput = "The dormant profile input is invalid.";
    private const string Sentinel = "caller-owned-enumerable-sensitive-sentinel";

    [Theory]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.GetEnumerator)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.MoveNext)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.GetEnumerator)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.MoveNext)]
    public void NonOomCallerEnumerableFailuresAreSanitized(
        CallerCollection collection,
        FailureStage stage)
    {
        var fixture = TestOnlyProfileFixture.Input();
        var failure = new CallerOwnedEnumerableSentinelException(Sentinel);

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
        Assert.DoesNotContain(
            nameof(CallerOwnedEnumerableSentinelException),
            exception.ToString(),
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.GetEnumerator)]
    [InlineData(CallerCollection.GenesisSignatures, FailureStage.MoveNext)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.GetEnumerator)]
    [InlineData(CallerCollection.SignedBridges, FailureStage.MoveNext)]
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

    public enum CallerCollection
    {
        GenesisSignatures,
        SignedBridges
    }

    public enum FailureStage
    {
        GetEnumerator,
        MoveNext
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
            return new ThrowingEnumerator<T>(failure);
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class ThrowingEnumerator<T>(Exception failure) : IEnumerator<T>
    {
        public T Current => default!;

        object? IEnumerator.Current => Current;

        public bool MoveNext() => throw failure;

        public void Reset() => throw new NotSupportedException();

        public void Dispose()
        {
        }
    }
}
