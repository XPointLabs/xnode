using System.Runtime.CompilerServices;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactRouteRecipientAuthoritySourceTests
{
    private static readonly byte[] NetworkId = Bytes(16, 0x31);
    private static readonly byte[] LocatorHash = Bytes(32, 0x32);

    [Fact]
    public void EvidenceCanOnlyBeDerivedFromProtocolVerifiedResolveOrClaimClosures()
    {
        Assert.Empty(typeof(ContactRouteRecipientResolveEvidence)
            .GetConstructors(System.Reflection.BindingFlags.Public
                | System.Reflection.BindingFlags.Instance));
        var factories = typeof(ContactRouteRecipientResolveEvidence)
            .GetMethods(System.Reflection.BindingFlags.Static
                | System.Reflection.BindingFlags.NonPublic)
            .Where(method => method.ReturnType
                == typeof(ContactRouteRecipientResolveEvidence))
            .Select(method => method.GetParameters().Single().ParameterType)
            .OrderBy(type => type.FullName, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [typeof(VerifiedContactClaimClosure),
             typeof(VerifiedPermanentContactResolveClosure)],
            factories);
    }

    [Fact]
    public async Task MissingVerifiedResolveClosureFailsClosedBeforeProjection()
    {
        var evidence = new RecordingResolveSource(null);
        var projector = new RecordingProjector(Material());
        var source = new ProtocolContactRouteRecipientAuthoritySource(
            evidence, projector);

        var result = await source.ReadCurrentAsync(
            NetworkId, LocatorHash, default);

        Assert.Null(result);
        Assert.Equal(1, evidence.Calls);
        Assert.Equal(0, projector.Calls);
    }

    [Fact]
    public async Task VerifiedClosureIsReadOnceAndProjectedForExactSelector()
    {
        var closure = Closure();
        var material = Material();
        var evidence = new RecordingResolveSource(closure);
        var projector = new RecordingProjector(material);
        var source = new ProtocolContactRouteRecipientAuthoritySource(
            evidence, projector);

        var result = await source.ReadCurrentAsync(
            NetworkId, LocatorHash, default);

        Assert.Same(material, result);
        Assert.Equal(1, evidence.Calls);
        Assert.Equal(1, projector.Calls);
        Assert.Same(closure, projector.ObservedClosure);
        Assert.Equal(NetworkId, evidence.ObservedNetwork);
        Assert.Equal(LocatorHash, evidence.ObservedLocator);
        Assert.Equal(NetworkId, projector.ObservedNetwork);
        Assert.Equal(LocatorHash, projector.ObservedLocator);
    }

    [Fact]
    public async Task RejectedStaleOrMismatchedEvidenceFailsClosed()
    {
        var projector = new RecordingProjector(null);
        var source = new ProtocolContactRouteRecipientAuthoritySource(
            new RecordingResolveSource(Closure()), projector);

        Assert.Null(await source.ReadCurrentAsync(
            NetworkId, LocatorHash, default));
        Assert.Equal(1, projector.Calls);
    }

    [Fact]
    public async Task ExactReplayDoesNotCreateAHiddenSingleUseAuthority()
    {
        var closure = Closure();
        var material = Material();
        var evidence = new RecordingResolveSource(closure);
        var projector = new RecordingProjector(material);
        var source = new ProtocolContactRouteRecipientAuthoritySource(
            evidence, projector);

        var first = await source.ReadCurrentAsync(NetworkId, LocatorHash, default);
        var replay = await source.ReadCurrentAsync(NetworkId, LocatorHash, default);

        Assert.Same(material, first);
        Assert.Same(material, replay);
        Assert.Equal(2, evidence.Calls);
        Assert.Equal(2, projector.Calls);
    }

    [Fact]
    public async Task OneReadCannotMixEvidenceAcrossConcurrentLocatorChanges()
    {
        var firstClosure = Closure();
        var secondClosure = Closure();
        var firstMaterial = Material(0x41);
        var secondMaterial = Material(0x51);
        var evidence = new AlternatingResolveSource(firstClosure, secondClosure);
        var projector = new ClosureBoundProjector(
            firstClosure, firstMaterial, secondClosure, secondMaterial);
        var source = new ProtocolContactRouteRecipientAuthoritySource(
            evidence, projector);

        var first = await source.ReadCurrentAsync(NetworkId, LocatorHash, default);
        var second = await source.ReadCurrentAsync(NetworkId, LocatorHash, default);

        Assert.Same(firstMaterial, first);
        Assert.Same(secondMaterial, second);
        Assert.Equal(2, evidence.Calls);
        Assert.Equal(2, projector.Calls);
    }

    [Theory]
    [InlineData(15, 32)]
    [InlineData(16, 31)]
    public async Task InvalidSelectorRejectsBeforeEvidenceLookup(
        int networkLength,
        int locatorLength)
    {
        var evidence = new RecordingResolveSource(Closure());
        var source = new ProtocolContactRouteRecipientAuthoritySource(
            evidence, new RecordingProjector(Material()));

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.ReadCurrentAsync(
                Bytes(networkLength, 0x31),
                Bytes(locatorLength, 0x32),
                default));
        Assert.Equal(0, evidence.Calls);
    }

    [Fact]
    public async Task CallerCancellationPropagatesBeforeEvidenceLookup()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var evidence = new RecordingResolveSource(Closure());
        var source = new ProtocolContactRouteRecipientAuthoritySource(
            evidence, new RecordingProjector(Material()));

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await source.ReadCurrentAsync(
                NetworkId, LocatorHash, cancellation.Token));
        Assert.Equal(0, evidence.Calls);
    }

    private static ContactRouteRecipientResolveEvidence Closure() =>
        (ContactRouteRecipientResolveEvidence)RuntimeHelpers.GetUninitializedObject(
            typeof(ContactRouteRecipientResolveEvidence));

    private static ContactRouteRecipientAuthorityMaterial Material(byte fill = 0x41) => new(
        Raw("XIR1", 611, fill),
        (VerifiedDevice)RuntimeHelpers.GetUninitializedObject(typeof(VerifiedDevice)),
        (CurrentlyAuthoritativeDca1)RuntimeHelpers.GetUninitializedObject(
            typeof(CurrentlyAuthoritativeDca1)),
        Raw("PMS2", 500, checked((byte)(fill + 1))));

    private static byte[] Raw(string magic, int length, byte fill)
    {
        var result = Bytes(length, fill);
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        return result;
    }

    private static byte[] Bytes(int length, byte fill) =>
        Enumerable.Repeat(fill, length).ToArray();

    private sealed class RecordingResolveSource(
        ContactRouteRecipientResolveEvidence? result)
        : IContactRouteRecipientResolveClosureSource
    {
        public int Calls { get; private set; }
        public byte[]? ObservedNetwork { get; private set; }
        public byte[]? ObservedLocator { get; private set; }

        public ValueTask<ContactRouteRecipientResolveEvidence?> ReadCurrentAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            ObservedNetwork = networkId.ToArray();
            ObservedLocator = locatorHash.ToArray();
            return ValueTask.FromResult(result);
        }
    }

    private sealed class AlternatingResolveSource(
        ContactRouteRecipientResolveEvidence first,
        ContactRouteRecipientResolveEvidence second)
        : IContactRouteRecipientResolveClosureSource
    {
        public int Calls { get; private set; }

        public ValueTask<ContactRouteRecipientResolveEvidence?> ReadCurrentAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult<ContactRouteRecipientResolveEvidence?>(
                Calls == 1 ? first : second);
        }
    }

    private sealed class RecordingProjector(
        ContactRouteRecipientAuthorityMaterial? result)
        : IContactRouteRecipientEvidenceProjector
    {
        public int Calls { get; private set; }
        public ContactRouteRecipientResolveEvidence? ObservedClosure { get; private set; }
        public byte[]? ObservedNetwork { get; private set; }
        public byte[]? ObservedLocator { get; private set; }

        public ValueTask<ContactRouteRecipientAuthorityMaterial?> VerifyCurrentAsync(
            ContactRouteRecipientResolveEvidence resolved,
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            ObservedClosure = resolved;
            ObservedNetwork = networkId.ToArray();
            ObservedLocator = locatorHash.ToArray();
            return ValueTask.FromResult(result);
        }
    }

    private sealed class ClosureBoundProjector(
        ContactRouteRecipientResolveEvidence firstClosure,
        ContactRouteRecipientAuthorityMaterial firstMaterial,
        ContactRouteRecipientResolveEvidence secondClosure,
        ContactRouteRecipientAuthorityMaterial secondMaterial)
        : IContactRouteRecipientEvidenceProjector
    {
        public int Calls { get; private set; }

        public ValueTask<ContactRouteRecipientAuthorityMaterial?> VerifyCurrentAsync(
            ContactRouteRecipientResolveEvidence resolved,
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            if (ReferenceEquals(resolved, firstClosure))
            {
                return ValueTask.FromResult<ContactRouteRecipientAuthorityMaterial?>(
                    firstMaterial);
            }
            if (ReferenceEquals(resolved, secondClosure))
            {
                return ValueTask.FromResult<ContactRouteRecipientAuthorityMaterial?>(
                    secondMaterial);
            }
            throw new InvalidOperationException("Unexpected resolve closure.");
        }
    }
}
