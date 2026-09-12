using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactRecipientResolveEvidenceCacheTests
{
    private static readonly byte[] NetworkId = Bytes(16, 0x21);
    private static readonly byte[] Locator = Bytes(32, 0x41);

    [Fact]
    public async Task VerifiedEvidenceIsIdempotentAndReverifiedAfterRestart()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        var firstVerifier = new GenerationVerifier();
        using (var first = Cache(temporary.Path, protection, firstVerifier))
        {
            var submission = Permanent(generation: 7, responseMarker: 0x71);
            await first.ObserveAsync(submission, default);
            await first.ObserveAsync(submission, default);
            Assert.Equal(2, firstVerifier.Calls);
        }

        var restartedVerifier = new GenerationVerifier();
        using var restarted = Cache(temporary.Path, protection, restartedVerifier);
        await restarted.InitializeAsync(default);
        var resolved = await restarted.ReadCurrentAsync(NetworkId, Locator, default);

        Assert.NotNull(resolved);
        Assert.Equal(1, restartedVerifier.Calls);
    }

    [Fact]
    public async Task SameGenerationForkLatchesAcrossRestart()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        using (var first = Cache(temporary.Path, protection, new GenerationVerifier()))
        {
            await first.ObserveAsync(Permanent(7, 0x71), default);
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await first.ObserveAsync(Permanent(7, 0x72), default));
        }

        using var restarted = Cache(temporary.Path, protection, new GenerationVerifier());
        await restarted.InitializeAsync(default);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ReadCurrentAsync(NetworkId, Locator, default));
    }

    [Fact]
    public async Task FreshPermanentReceiptForSameClosureReplacesWithoutFalseFork()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        using (var first = Cache(temporary.Path, protection, new GenerationVerifier()))
        {
            await first.ObserveAsync(Permanent(7, 0x71, requestMarker: 0x11), default);
            await first.ObserveAsync(Permanent(7, 0x71, requestMarker: 0x12), default);
        }

        using var restarted = Cache(temporary.Path, protection, new GenerationVerifier());
        Assert.NotNull(await restarted.ReadCurrentAsync(NetworkId, Locator, default));
    }

    [Fact]
    public async Task RollbackIsRejectedWithoutReplacingCurrentEvidence()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        using (var first = Cache(temporary.Path, protection, new GenerationVerifier()))
        {
            await first.ObserveAsync(Permanent(8, 0x81), default);
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await first.ObserveAsync(Permanent(7, 0x71), default));
        }

        using var restarted = Cache(temporary.Path, protection, new GenerationVerifier());
        Assert.NotNull(await restarted.ReadCurrentAsync(NetworkId, Locator, default));
    }

    [Fact]
    public async Task StaleCurrentReverificationNeverServesRetainedEvidence()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        using (var first = Cache(temporary.Path, protection, new GenerationVerifier()))
        {
            await first.ObserveAsync(Permanent(7, 0x71), default);
        }

        var staleVerifier = new UnavailableVerifier();
        using var restarted = Cache(temporary.Path, protection, staleVerifier);
        Assert.Null(await restarted.ReadCurrentAsync(NetworkId, Locator, default));
        Assert.Equal(1, staleVerifier.Calls);
    }

    [Fact]
    public async Task OneTimeReplacementForksEvenWhenGenerationAdvances()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        using var cache = Cache(temporary.Path, protection, new GenerationVerifier());
        await cache.ObserveAsync(OneTime(7, 0x71), default);

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await cache.ObserveAsync(OneTime(8, 0x81), default));
    }

    [Fact]
    public async Task WrongOpaqueSelectorMissesWithoutVerificationAndStateHasNoPlaintext()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        var verifier = new GenerationVerifier();
        string statePath;
        using (var cache = Cache(temporary.Path, protection, verifier))
        {
            var submission = Permanent(7, 0x71);
            await cache.ObserveAsync(submission, default);
            statePath = cache.StatePath;
            var callsBeforeMiss = verifier.Calls;

            Assert.Null(await cache.ReadCurrentAsync(
                NetworkId, Bytes(32, 0x61), default));
            Assert.Equal(callsBeforeMiss, verifier.Calls);
            Assert.DoesNotContain(
                submission.ExactAddress.ToArray(),
                File.ReadAllBytes(statePath).AsSpan());
        }
    }

    [Fact]
    public async Task PreKeyCandidateScanIsNetworkBoundedAndReverifiesEveryReturnedEntry()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        var verifier = new GenerationVerifier();
        using var cache = Cache(temporary.Path, protection, verifier);
        await cache.ObserveAsync(Permanent(7, 0x71), default);
        var callsBeforeScan = verifier.Calls;

        var candidates = await cache.ReadCurrentCandidatesAsync(NetworkId, default);

        var candidate = Assert.Single(candidates);
        Assert.Equal(Locator, candidate.LocatorHash.ToArray());
        Assert.Equal(callsBeforeScan + 1, verifier.Calls);
        Assert.Empty(await cache.ReadCurrentCandidatesAsync(Bytes(16, 0x22), default));
        Assert.Equal(callsBeforeScan + 1, verifier.Calls);
    }

    [Fact]
    public async Task ProtectedStateCorruptionFailsClosedOnStartup()
    {
        using var temporary = new TemporaryDirectory();
        var protection = Protection(temporary.Path);
        string statePath;
        using (var first = Cache(temporary.Path, protection, new GenerationVerifier()))
        {
            await first.ObserveAsync(Permanent(7, 0x71), default);
            statePath = first.StatePath;
        }
        var bytes = File.ReadAllBytes(statePath);
        bytes[^1] ^= 1;
        File.WriteAllBytes(statePath, bytes);

        using var restarted = Cache(temporary.Path, protection, new GenerationVerifier());
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await restarted.InitializeAsync(default));
    }

    [Fact]
    public async Task ProtocolVerifierRejectsRequestSelectorMismatchBeforeAuthorityLookup()
    {
        var network = Bytes(16, 0x31);
        var locator = Bytes(32, 0x51);
        var wrongNetwork = Bytes(16, 0x32);
        var requestBytes = Xiq1Codec.Encode(
            wrongNetwork,
            Bytes(32, 0x61),
            Bytes(32, 0x71),
            Bytes(32, 0x81),
            10,
            20,
            locator,
            0,
            Xiq1AntiSpamTokenType.None,
            ReadOnlySpan<byte>.Empty,
            ContactServicePaddingClass.Bytes256);
        var resultBytes = Xis1Codec.Encode(
            requestBytes,
            Xis1Status.NotFound,
            ContactServiceMutationOutcome.None,
            11,
            0,
            ContactServicePaddingClass.Bytes256,
            []);
        var snapshots = new RejectIfCalledSnapshotSource();
        var verifier = new ProtocolContactRecipientResolveEvidenceVerifier(
            snapshots, new RejectIfCalledMonotonicClock());
        var submission = new ContactRecipientResolveEvidenceSubmission(
            ContactRecipientResolveEvidenceKind.Permanent,
            network,
            locator,
            [0x01],
            requestBytes,
            resultBytes);

        Assert.Null(await verifier.VerifyCurrentAsync(submission, default));
        Assert.Equal(0, snapshots.Calls);
    }

    [Fact]
    public void ProductionCompositionRegistersDurableOwnerInsteadOfClosedSource()
    {
        using var temporary = new TemporaryDirectory();
        var services = new ServiceCollection();
        services.AddDataProtection().PersistKeysToFileSystem(
            new DirectoryInfo(Path.Combine(temporary.Path, "keys")));
        services.AddSingleton<IContactRecipientResolveEvidenceVerifier>(
            new UnavailableVerifier());
        services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        services.AddProductionContactRouteClosure(new(
            new ContactRouteClosureHttpSourceOptions(
                "https://registry.example", TimeSpan.FromSeconds(5)),
            Path.Combine(temporary.Path, "route", "lkg.bin"),
            4 * 1024 * 1024));

        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteRecipientResolveClosureSource)
            && descriptor.ImplementationFactory is not null);
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteRecipientResolveEvidenceOwner));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType
                == typeof(IPrivacyRoutedContactRecipientResolveEvidenceIngestion)
            && descriptor.ImplementationType
                == typeof(PrivacyRoutedContactRecipientResolveEvidenceIngestion));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(FileContactRecipientResolveEvidenceCache)
            && descriptor.ImplementationFactory is not null);
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactPreKeyRecipientResolveEvidenceSource));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IContactPreKeyRecipientAuthoritySource)
            && descriptor.ImplementationType
                == typeof(ProtocolContactPreKeyRecipientAuthoritySource));
        Assert.DoesNotContain(services, descriptor =>
            descriptor.ServiceType == typeof(IContactRouteRecipientResolveClosureSource)
            && descriptor.ImplementationType
                == typeof(ClosedContactRouteRecipientResolveClosureSource));

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<FileContactRecipientResolveEvidenceCache>());
    }

    private static FileContactRecipientResolveEvidenceCache Cache(
        string root,
        IDataProtectionProvider protection,
        IContactRecipientResolveEvidenceVerifier verifier) => new(
            new(
                Path.Combine(root, "state", "recipient-evidence.bin"),
                4 * 1024 * 1024,
                64),
            verifier,
            protection,
            new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());

    private static IDataProtectionProvider Protection(string root) =>
        DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(root, "keys")));

    private static ContactRecipientResolveEvidenceSubmission Permanent(
        byte generation,
        byte responseMarker,
        byte requestMarker = 0x11) => new(
            ContactRecipientResolveEvidenceKind.Permanent,
            NetworkId,
            Locator,
            Encoding.ASCII.GetBytes(
                "deep-sensitive-account-and-device-identity-must-not-appear-in-state"),
            [generation, requestMarker],
            [responseMarker, 0x21]);

    private static ContactRecipientResolveEvidenceSubmission OneTime(
        byte generation,
        byte responseMarker) => new(
            ContactRecipientResolveEvidenceKind.OneTime,
            NetworkId,
            Locator,
            Encoding.ASCII.GetBytes(
                "deep-sensitive-one-time-invite-key-must-not-appear-in-state"),
            [generation, 0x12],
            [responseMarker, 0x22]);

    private static ContactRouteRecipientResolveEvidence EmptyEvidence() =>
        (ContactRouteRecipientResolveEvidence)RuntimeHelpers.GetUninitializedObject(
            typeof(ContactRouteRecipientResolveEvidence));

    private static byte[] Bytes(int length, byte fill) =>
        Enumerable.Repeat(fill, length).ToArray();

    private sealed class GenerationVerifier : IContactRecipientResolveEvidenceVerifier
    {
        public int Calls { get; private set; }

        public ValueTask<VerifiedContactRecipientResolveObservation?> VerifyCurrentAsync(
            ContactRecipientResolveEvidenceSubmission submission,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            var generation = submission.ExactXiq1.Span[0];
            return ValueTask.FromResult<VerifiedContactRecipientResolveObservation?>(new(
                EmptyEvidence(),
                (ulong)generation,
                submission.Kind == ContactRecipientResolveEvidenceKind.OneTime
                    ? (ulong)generation
                    : 0UL,
                Bytes(32, submission.ExactXis1.Span[0])));
        }
    }

    private sealed class UnavailableVerifier : IContactRecipientResolveEvidenceVerifier
    {
        public int Calls { get; private set; }

        public ValueTask<VerifiedContactRecipientResolveObservation?> VerifyCurrentAsync(
            ContactRecipientResolveEvidenceSubmission submission,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult<VerifiedContactRecipientResolveObservation?>(null);
        }
    }

    private sealed class RejectIfCalledSnapshotSource : IContactVerifiedAuthoritySnapshotSource
    {
        public int Calls { get; private set; }

        public ValueTask<ContactVerifiedAuthoritySnapshot> ReadCurrentAsync(
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromException<ContactVerifiedAuthoritySnapshot>(
                new InvalidOperationException("Snapshot lookup must not occur."));
        }
    }

    private sealed class RejectIfCalledMonotonicClock : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(
            CancellationToken cancellationToken) =>
            ValueTask.FromException<OnionMonotonicReading>(
                new InvalidOperationException("Clock lookup must not occur."));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        internal TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"xnode-recipient-evidence-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        internal string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
