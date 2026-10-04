using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using Sodium;
using XNode.Core.Mailbox;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Actual signed DID2/network/PMA2 and native protected files/barriers.
/// Clock/proof production is test-owned; this is not node ingress, peer or device evidence.</summary>
public sealed partial class MailboxGrantRevocationStoreTests
{
    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task LateNewScopePinsCurrentTailAndKeepsInitialFloorAcrossColdAdvance(MailboxCapabilityDomain role)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(signed, role); var host = await Host(signed);
        var expired = Snapshot(signed, role, expires: 1_080);
        var tail = Snapshot(signed, role, 2, expired, [Bytes(16, 0x51)]);
        byte[] enrollment;
        await using (var store = files.Open())
        {
            await Assert.ThrowsAsync<CryptographicException>(() => store.EnrollAsync(host, expired).AsTask());
            Assert.False(File.Exists(files.Enrollment));
            await store.EnrollAsync(host, tail);
            enrollment = File.ReadAllBytes(files.Enrollment);
            Assert.Equal(tail, (await store.ReadProtectedAsync()).ToArray());
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.EnrollAsync(host, tail).AsTask());
        }
        var successor = Snapshot(signed, role, 3, tail, [Bytes(16, 0x51), Bytes(16, 0x52)]);
        await using (var store = files.Open())
        {
            await store.AdvanceAsync(host, successor);
            Assert.Equal(enrollment, File.ReadAllBytes(files.Enrollment));
            await Assert.ThrowsAsync<MailboxGrantRevocationFloorException>(() =>
                store.AdvanceAsync(host, Snapshot(signed, role)).AsTask());
            Assert.Equal(successor, (await store.ReadProtectedAsync()).ToArray());
            await store.WithCurrentAsync(host, async (lease, token) =>
            {
                await Assert.ThrowsAsync<CryptographicException>(() =>
                    lease.EnsureGrantNotRevokedAsync(Grant(signed, host, role, 0x51), token).AsTask());
                await lease.EnsureGrantNotRevokedAsync(Grant(signed, host, role, 0x53), token);
                return 1;
            });
        }
        await using var reopened = files.Open();
        Assert.Equal(successor, (await reopened.ReadProtectedAsync()).ToArray());
        Assert.Equal(enrollment, File.ReadAllBytes(files.Enrollment));
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit, false)]
    [InlineData(MailboxCapabilityDomain.Retrieve, false)]
    [InlineData(MailboxCapabilityDomain.Deposit, true)]
    [InlineData(MailboxCapabilityDomain.Retrieve, true)]
    public async Task LateEnrollmentRejectsProtectedFloorBelowOrDifferentAtInitialPinAcrossRestart(
        MailboxCapabilityDomain role, bool sameGeneration)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(signed, role); var host = await Host(signed);
        var genesis = Snapshot(signed, role);
        var initial = Snapshot(signed, role, 2, genesis, [Bytes(16, 0x51)]);
        await using (var store = files.Open()) await store.EnrollAsync(host, initial);
        // Independently authenticated native records simulate a stale/split restore,
        // not a writer-authorized transition. The immutable enrollment must fence it.
        var bad = sameGeneration ? Snapshot(signed, role, 2, genesis, [Bytes(16, 0x52)]) : genesis;
        files.ReplaceProtectedFloorAndAnchor(bad);
        await using var reopened = files.Open();
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadProtectedAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.EnrollAsync(host, initial).AsTask());
        var callbacks = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.WithCurrentAsync(host, (_, _) =>
            { callbacks++; return ValueTask.FromResult(1); }).AsTask());
        Assert.Equal(0, callbacks);
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task ExplicitEnrollmentRestartSuccessorAndRevokedGrantUseNativeProtectedReadBack(MailboxCapabilityDomain role)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed, role);
        var host = await Host(signed); var first = Snapshot(signed, role);
        await using (var store = files.Open())
        {
            var calls = 0;
            await Assert.ThrowsAsync<InvalidDataException>(() => store.WithCurrentAsync(host, (_, _) =>
                { calls++; return ValueTask.FromResult(1); }).AsTask());
            Assert.Equal(0, calls);
            await store.EnrollAsync(host, first);
            Assert.Equal(first, (await store.ReadProtectedAsync()).ToArray());
            await store.WithCurrentAsync(host, async (lease, token) =>
                { await lease.EnsureGrantNotRevokedAsync(Grant(signed, host, role, 0x51), token); return 1; });
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.EnrollAsync(host, first).AsTask());
            Assert.False(File.ReadAllBytes(files.Floor).AsSpan().SequenceEqual(first));
        }
        Assert.NotEmpty(Directory.GetFiles(files.Keys, "key-*.xml"));
        await using var reopened = files.Open();
        var next = Snapshot(signed, role, 2, first, [Bytes(16, 0x51)]);
        await reopened.AdvanceAsync(host, next); await reopened.AdvanceAsync(host, next);
        Assert.Equal(next, (await reopened.ReadProtectedAsync()).ToArray());
        await reopened.WithCurrentAsync(host, async (lease, token) =>
        {
            await Assert.ThrowsAsync<CryptographicException>(() => lease.EnsureGrantNotRevokedAsync(Grant(signed, host, role, 0x51), token).AsTask());
            await lease.EnsureGrantNotRevokedAsync(Grant(signed, host, role, 0x52), token);
            return 1;
        });
    }

    [Theory]
    [InlineData("floor")]
    [InlineData("anchor")]
    [InlineData("enrollment")]
    [InlineData("both-floor-anchor")]
    [InlineData("corrupt-floor")]
    [InlineData("corrupt-anchor")]
    [InlineData("corrupt-enrollment")]
    [InlineData("partial")]
    [InlineData("purpose")]
    [InlineData("keys")]
    public async Task ReopenRejectsLostCorruptPartialOrWrongPurposeStateWithoutAutoGenesis(string fault)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var first = Snapshot(signed);
        await using (var store = files.Open()) await store.EnrollAsync(host, first);
        if (fault == "both-floor-anchor") { File.Delete(files.Floor); File.Delete(files.Anchor); }
        else if (fault is "floor" or "anchor" or "enrollment") File.Delete(files.PathFor(fault));
        else if (fault.StartsWith("corrupt-", StringComparison.Ordinal))
        { var path = files.PathFor(fault[8..]); var bytes = File.ReadAllBytes(path); bytes[^1] ^= 1; File.WriteAllBytes(path, bytes); }
        else if (fault == "partial") File.WriteAllBytes(files.Floor + ".interrupted.tmp", [1]);
        else if (fault == "purpose") File.Copy(files.Floor, files.Anchor, overwrite: true);
        else foreach (var key in Directory.GetFiles(files.Keys)) File.Delete(key);
        await using var reopened = files.Open();
        await Assert.ThrowsAnyAsync<Exception>(() => reopened.ReadProtectedAsync().AsTask());
        await Assert.ThrowsAnyAsync<Exception>(() => reopened.EnrollAsync(host, first).AsTask());
        var callbacks = 0;
        await Assert.ThrowsAnyAsync<Exception>(() => reopened.WithCurrentAsync(host, (_, _) =>
            { callbacks++; return ValueTask.FromResult(1); }).AsTask());
        Assert.Equal(0, callbacks);
    }

    [Fact]
    public async Task StaleAuthenticFloorCannotOverrideIndependentAnchor()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var first = Snapshot(signed); byte[] prior;
        await using (var store = files.Open())
        {
            await store.EnrollAsync(host, first); prior = File.ReadAllBytes(files.Floor);
            await store.AdvanceAsync(host, Snapshot(signed, generation: 2, prior: first));
        }
        File.WriteAllBytes(files.Floor, prior);
        await using var reopened = files.Open();
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadProtectedAsync().AsTask());
    }

    [Fact]
    public async Task LosingAllRecordsInInitializedOwnerCannotReenroll()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var first = Snapshot(signed);
        await using var store = files.Open(); await store.EnrollAsync(host, first);
        File.Delete(files.Enrollment); File.Delete(files.Anchor); File.Delete(files.Floor);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadProtectedAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(() => store.EnrollAsync(host, first).AsTask());
    }

    [Theory]
    [InlineData("fork")]
    [InlineData("removed")]
    public async Task AuthenticatedIssuerConflictLatchesAcrossRestartAndPreservesPrior(string kind)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var first = Snapshot(signed, serials: [Bytes(16, 0x51)]); byte[] prior;
        await using (var store = files.Open())
        {
            await store.EnrollAsync(host, first); prior = File.ReadAllBytes(files.Floor);
            var hostile = kind == "fork" ? Snapshot(signed, serials: [Bytes(16, 0x52)]) : Snapshot(signed, generation: 2, prior: first);
            var error = await Assert.ThrowsAsync<MailboxGrantRevocationFloorException>(() => store.AdvanceAsync(host, hostile).AsTask());
            Assert.Equal(kind == "fork" ? MailboxGrantRevocationFloorError.SignedFork : MailboxGrantRevocationFloorError.RemovedSerial, error.Error);
            Assert.True(File.Exists(files.Fault)); Assert.Equal(prior, File.ReadAllBytes(files.Floor));
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.ReadProtectedAsync().AsTask());
        }
        await using var reopened = files.Open();
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadProtectedAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.EnrollAsync(host, first).AsTask());
    }

    [Theory]
    [InlineData("unsigned-fork")]
    [InlineData("gap")]
    [InlineData("rollback")]
    public async Task InvalidSignatureOrNormalRejectedHistoryDoesNotLatchOrLoseFloor(string kind)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var first = Snapshot(signed); var second = Snapshot(signed, generation: 2, prior: first);
        await using var store = files.Open(); await store.EnrollAsync(host, first); await store.AdvanceAsync(host, second);
        var bad = kind == "rollback" ? first : kind == "gap" ? Snapshot(signed, generation: 4, prior: second) :
            Snapshot(signed, generation: 2, prior: first, serials: [Bytes(16, 0x51)]);
        if (kind == "unsigned-fork") bad[^1] ^= 1;
        await Assert.ThrowsAnyAsync<CryptographicException>(() => store.AdvanceAsync(host, bad).AsTask());
        Assert.False(File.Exists(files.Fault)); Assert.Equal(second, (await store.ReadProtectedAsync()).ToArray());
        await store.WithCurrentAsync(host, async (lease, token) => { await lease.EnsureCurrentAsync(token); return 1; });
    }

    [Theory]
    [InlineData("enrollment.bin")]
    [InlineData("anchor.bin")]
    [InlineData("floor.bin")]
    public async Task CrashAfterNativeReplacementNeverReleasesAuthorityAndKeepsUncertainty(string target)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var first = Snapshot(signed); var crash = new Barrier(target);
        await using (var store = files.Open(crash))
        {
            await Assert.ThrowsAsync<IOException>(() => store.EnrollAsync(host, first).AsTask());
            Assert.True(crash.ReachedTarget);
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.ReadProtectedAsync().AsTask());
        }
        await using var reopened = files.Open();
        if (target == "floor.bin") // read-back proves the complete exact write; no previous success was returned
            Assert.Equal(first, (await reopened.ReadProtectedAsync()).ToArray());
        else
            await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadProtectedAsync().AsTask());
    }

    [Fact]
    public async Task SerializedOperationBlocksSuccessorAndDisposeAndEscapedLeaseRejects()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var first = Snapshot(signed);
        var store = files.Open(); await store.EnrollAsync(host, first);
        var entered = Signal(); var release = Signal(); FileMailboxGrantRevocationStore.CurrentLease? escaped = null;
        var operation = store.WithCurrentAsync(host, async (lease, token) =>
        { escaped = lease; entered.SetResult(); await release.Task.WaitAsync(token); return 1; }).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var advance = store.AdvanceAsync(host, Snapshot(signed, generation: 2, prior: first)).AsTask();
        Assert.False(advance.IsCompleted);
        Assert.Throws<IOException>(() => files.Open());
        release.SetResult(); Assert.Equal(1, await operation); await advance;
        await Assert.ThrowsAsync<InvalidOperationException>(() => escaped!.EnsureCurrentAsync().AsTask());
        await store.DisposeAsync();
        await using var reopened = files.Open(); Assert.Equal(2UL, MailboxGrantRevocationV1Codec.Decode((await reopened.ReadProtectedAsync()).Span).Generation);
    }

    [Fact]
    public async Task AsyncVerificationOutlivingLeaseRejectsAfterProtectedClockCallback()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var clock = new Clock(); var host = await Host(signed, clock); var first = Snapshot(signed);
        await using var store = files.Open(); await store.EnrollAsync(host, first);
        Task? escapedTask = null;
        await store.WithCurrentAsync(host, async (lease, _) =>
        {
            clock.BlockAt = clock.Reads + 2; // after the native floor read, during the second host-time callback
            escapedTask = lease.EnsureCurrentAsync().AsTask();
            await clock.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(10)); return 1;
        });
        clock.Release.SetResult();
        await Assert.ThrowsAsync<InvalidOperationException>(() => escapedTask!);
    }

    [Fact]
    public async Task PostOperationExpirySuppressesResultWithoutDeletingCommittedFloor()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var first = Snapshot(signed, expires: 1_110);
        await using var store = files.Open(); await store.EnrollAsync(host, first); var effects = 0;
        await Assert.ThrowsAsync<CryptographicException>(() => store.WithCurrentAsync(host, (_, _) =>
        { effects++; signed.Sample = 105; return ValueTask.FromResult(1); }).AsTask());
        Assert.Equal(1, effects); Assert.Equal(first, (await store.ReadProtectedAsync()).ToArray());
        await store.AdvanceAsync(host, Snapshot(signed, generation: 2, prior: first));
        await store.WithCurrentAsync(host, async (lease, token) => { await lease.EnsureCurrentAsync(token); return 1; });
    }

    [Fact]
    public async Task CancellationBeforeEnrollmentDoesNotWriteStateAndDisposeWaitsForOperation()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var host = await Host(signed); var store = files.Open(); var first = Snapshot(signed);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.EnrollAsync(host, first, canceled.Token).AsTask());
        Assert.False(File.Exists(files.Enrollment)); await store.EnrollAsync(host, first);
        var entered = Signal(); var release = Signal();
        var operation = store.WithCurrentAsync(host, async (_, _) =>
        { entered.SetResult(); await release.Task; return 1; }).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var dispose = store.DisposeAsync().AsTask(); Assert.False(dispose.IsCompleted);
        Assert.Throws<IOException>(() => files.Open()); release.SetResult(); await operation; await dispose;
        await Assert.ThrowsAsync<ObjectDisposedException>(() => store.ReadProtectedAsync().AsTask());
    }

    [Theory]
    [InlineData("same")]
    [InlineData("nested")]
    [InlineData("parent")]
    public async Task CustodyCannotLiveInReplaceableDataOrEncloseIt(string layout)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(); using var files = new Custody(signed);
        var bad = layout == "same" ? files.Data : layout == "nested" ? Path.Combine(files.Data, "custody") : files.Root;
        Assert.Throws<ArgumentException>(() => files.Open(custody: bad));
    }

    internal static ValueTask<VerifiedMailboxHostAuthorityV2> Host(DeepIdV2PublicationAuthorityFixture signed, IOnionMonotonicClock? clock = null) =>
        MailboxHostAuthorityV2Verifier.VerifyAsync(signed.NetworkContext, signed.Authority, signed.MailboxAuthority, new(clock ?? signed));
    internal static byte[] Snapshot(DeepIdV2PublicationAuthorityFixture signed, MailboxCapabilityDomain role = MailboxCapabilityDomain.Deposit,
        ulong generation = 1, byte[]? prior = null, byte[][]? serials = null, ulong expires = 1_120, ulong? issued = null)
    {
        var key = PublicKeyAuth.GenerateKeyPair(Bytes(32, role == MailboxCapabilityDomain.Deposit ? (byte)0x31 : (byte)0x32));
        try
        {
            ReadOnlyMemory<byte>[] fields = [DeepIdV2PublicationAuthorityFixture.Network, Reference(signed), new byte[] { (byte)role }, key.PublicKey,
                U64(generation), prior is null ? new byte[32] : MailboxGrantRevocationV1Codec.Decode(prior).CoreHash,
                U64(issued ?? (generation == 1 ? 1_000UL : 1_090UL)), U64(issued ?? (generation == 1 ? 1_000UL : 1_090UL)), U64(expires),
                U32((uint)(serials?.Length ?? 0)), (serials ?? []).SelectMany(x => x).ToArray()];
            return MailboxGrantRevocationV1Codec.Encode(fields,
                PublicKeyAuth.SignDetached(MailboxGrantRevocationV1Codec.CreateSignatureInput(fields), key.PrivateKey));
        }
        finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }
    internal static byte[] Grant(DeepIdV2PublicationAuthorityFixture signed, VerifiedMailboxHostAuthorityV2 host,
        MailboxCapabilityDomain role, byte serial, ulong expires = 1_110)
    {
        var crypto = new SodiumMailboxCapabilityCrypto(); var seed = Bytes(32, role == MailboxCapabilityDomain.Deposit ? (byte)0x31 : (byte)0x32);
        var policy = MailboxAuthorityV2Verifier.Verify(signed.Authority, signed.MailboxAuthority.Span,
            signed.Freshness.TrustedLowerUnixSeconds, signed.Freshness.TrustedUpperUnixSeconds);
        return MailboxAuthenticatedCapabilityCodec.EncodeGrant(crypto.SignGrant(new()
        {
            Domain = role, Lifecycle = MailboxCapabilityLifecycle.Active, NetworkId = signed.NetworkContext.NetworkId,
            Epoch = host.SelectionEpoch, Generation = policy.MinimumGrantGeneration,
            Serial = Bytes(16, serial), NotBeforeUnixSeconds = 1_090, ExpiresAtUnixSeconds = expires,
            PlacementCommitment = MailboxPlacementCommitment.Compute(new(Bytes(32, 0x55))),
            MembershipCommitment = host.MembershipCommitment, SelectionInput = Bytes(32, 0x56), OverlapUntilUnixSeconds = 0,
            IssuerPublicKey = crypto.GetPublicKey(seed), HolderPublicKey = crypto.GetPublicKey(Bytes(32, 0x57)),
            IssuerSignature = ReadOnlyMemory<byte>.Empty,
        }, seed));
    }
    private static byte[] Reference(DeepIdV2PublicationAuthorityFixture signed) =>
        [.. "PMA2"u8, 0, 1, .. ContactCodec.Decode(ProtocolMagic.PMA2, signed.MailboxAuthority.Span).CoreHash.Span];
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static byte[] Bytes(int count, byte marker) => Enumerable.Repeat(marker, count).ToArray();
    private static byte[] U64(ulong value) { var x = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(x, value); return x; }
    private static byte[] U32(uint value) { var x = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(x, value); return x; }
    private sealed class Clock : IOnionMonotonicClock
    {
        internal int Reads, BlockAt = -1; internal TaskCompletionSource Blocked = Signal(), Release = Signal();
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); var read = Interlocked.Increment(ref Reads);
            if (read == BlockAt) { Blocked.SetResult(); await Release.Task.WaitAsync(token); }
            return new(DeepIdV2PublicationAuthorityFixture.Boot, 100);
        }
    }
    internal sealed class Custody(DeepIdV2PublicationAuthorityFixture signed, MailboxCapabilityDomain role = MailboxCapabilityDomain.Deposit,
        byte[]? nodeId = null) : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "native-mgr1-" + Guid.NewGuid().ToString("N"));
        internal string Data => Path.Combine(Root, "node-data"); internal string Keys => Path.Combine(Root, "protection");
        private string Scope => Directory.GetDirectories(Path.Combine(Root, "custody")).Single();
        internal string Floor => Path.Combine(Scope, "floor.bin"); internal string Anchor => Path.Combine(Scope, "anchor.bin");
        internal string Enrollment => Path.Combine(Scope, "enrollment.bin"); internal string Fault => Path.Combine(Scope, "fault.bin");
        internal string PathFor(string part) => part == "floor" ? Floor : part == "anchor" ? Anchor : Enrollment;
        internal void ReplaceProtectedFloorAndAnchor(byte[] exact)
        {
            var provider = DataProtectionProvider.Create(new DirectoryInfo(Keys), builder => builder.SetApplicationName("XPoint.XNode.MGR1.NativeTests.v1"));
            var scope = Path.GetFileName(Scope);
            File.WriteAllBytes(Floor, provider.CreateProtector("Deep.XNode.MGR1.Floor.v1", scope).Protect(exact));
            File.WriteAllBytes(Anchor, provider.CreateProtector("Deep.XNode.MGR1.Anchor.v1", scope).Protect(exact));
        }
        internal FileMailboxGrantRevocationStore Open(IMailboxDurabilityBarrier? barrier = null, string? custody = null)
        {
            var security = new MailboxStorageSecurity(); security.SecureDirectory(Keys); security.SecureDirectory(Data);
            var provider = DataProtectionProvider.Create(new DirectoryInfo(Keys), builder => builder.SetApplicationName("XPoint.XNode.MGR1.NativeTests.v1"));
            return new(Data, custody ?? Path.Combine(Root, "custody"), nodeId ?? Bytes(32, 0x70), signed.NetworkContext.NetworkId.Span,
                Reference(signed), role, provider, security, barrier ?? new MailboxDurabilityBarrier());
        }
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
    }
    private sealed class Barrier(string target) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier inner = new(); internal bool ReachedTarget;
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            inner.ReplaceFile(temporaryPath, finalPath);
            if (Path.GetFileName(finalPath) == target) { ReachedTarget = true; throw new IOException("Injected native replacement interruption."); }
        }
        public void FlushFileAndParentDirectory(string path) => inner.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => inner.FlushParentDirectory(path);
    }
}
