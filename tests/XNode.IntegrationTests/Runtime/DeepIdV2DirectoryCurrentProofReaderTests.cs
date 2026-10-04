using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2DirectoryCurrentProofReaderTests
{
    [Theory]
    [InlineData("current")]
    [InlineData("expiry")]
    [InlineData("boot")]
    [InlineData("rollback")]
    [InlineData("index")]
    public async Task GenuineProofObservationRechecksActualProtectedHeadAndClockWithoutFetching(string state)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = Path.Combine(Path.GetTempPath(), "did2-observed-head-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var genesis = signed.Freshness.VerifiedProtectedLkgExactAdh1;
            Assert.Equal(1UL, signed.Freshness.NextProtectedLkg.LogGeneration);
            var genesisHash = signed.Freshness.NextProtectedLkg.Head.PredecessorAdh1CoreHash;
            using var store = new FileDeepIdV2DirectoryProtectedHeadStore(Path.Combine(root, "journal"), root,
                genesis.Span, genesisHash.Span, new EphemeralDataProtectionProvider(), new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
            var prior = await store.RestoreAsync(signed.Authority, default);
            await store.CommitVerifiedAsync(prior, signed.Freshness, default);
            var source = new RejectIfCalledArtifacts();
            var reader = new DeepIdV2DirectoryCurrentProofReader(source, store, signed, new RejectIfCalledPq());
            var latest = Path.Combine(root, "journal", "latest.floor");
            var exactIndex = File.ReadAllBytes(latest);
            switch (state)
            {
                case "expiry": signed.Sample = signed.Freshness.FreshnessDeadlineMonotonicSeconds; break;
                case "boot": signed.ClockReadings.Enqueue(new OnionMonotonicReading(Bytes(16, 0x42), 100)); break;
                case "rollback": signed.Sample = 99; break;
                case "index": File.Delete(latest); break;
            }
            if (state == "current") await reader.ValidateObservedAsync(signed.Freshness, signed.Authority, default);
            else if (state == "index")
                await Assert.ThrowsAsync<InvalidDataException>(async () => await reader.ValidateObservedAsync(signed.Freshness, signed.Authority, default));
            else await Assert.ThrowsAsync<CryptographicException>(async () => await reader.ValidateObservedAsync(signed.Freshness, signed.Authority, default));
            Assert.False(source.Called);
            if (state == "index") Assert.False(File.Exists(latest));
            else Assert.Equal(exactIndex, File.ReadAllBytes(latest));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task MissingProtectedFloorRejectsBeforeClockOrNetworkRequest()
    {
        var source = new RejectIfCalledArtifacts();
        var clock = new RejectIfCalledClock();
        var reader = new DeepIdV2DirectoryCurrentProofReader(source,
            new MissingFloor(), clock, new RejectIfCalledPq());
        var did2 = DeepIdV2Codec.AuthorDid2(Bytes(32, 0x21),
            Bytes(1952, 0x31), Bytes(16, 0x41));
        var authority = (VerifiedXPointNetworkAuthority)
            RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedXPointNetworkAuthority));

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reader.ReadCurrentAsync(did2, authority, 1, 2, default));
        Assert.False(source.Called);
        Assert.False(clock.Called);
    }

    [Fact]
    public async Task RetiredReaderVersionRejectsBeforeProtectedStateAccess()
    {
        var floor = new MissingFloor();
        var reader = new DeepIdV2DirectoryCurrentProofReader(
            new RejectIfCalledArtifacts(), floor,
            new RejectIfCalledClock(), new RejectIfCalledPq());
        var did2 = DeepIdV2Codec.AuthorDid2(Bytes(32, 0x21),
            Bytes(1952, 0x31), Bytes(16, 0x41));
        var authority = (VerifiedXPointNetworkAuthority)
            RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedXPointNetworkAuthority));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await reader.ReadCurrentAsync(did2, authority, 1, 1, default));
        Assert.False(floor.Called);
    }

    [Fact]
    public async Task MissingDeploymentProfileRejectsBeforeProtectedStateAccess()
    {
        var floor = new MissingFloor();
        var reader = new DeepIdV2DirectoryCurrentProofReader(
            new RejectIfCalledArtifacts(), floor,
            new RejectIfCalledClock(), new RejectIfCalledPq());
        var did2 = DeepIdV2Codec.AuthorDid2(Bytes(32, 0x21),
            Bytes(1952, 0x31), Bytes(16, 0x41));
        var authority = (VerifiedXPointNetworkAuthority)
            RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedXPointNetworkAuthority));

        var error = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            async () => await reader.ReadCurrentAsync(did2, authority,
                0, 2, default));
        Assert.Equal("deploymentProfileId", error.ParamName);
        Assert.False(floor.Called);
    }

    private static byte[] Bytes(int length, byte value)
    {
        var bytes = new byte[length];
        bytes.AsSpan().Fill(value);
        return bytes;
    }

    private sealed class MissingFloor : IDeepIdV2DirectoryProtectedHeadStore
    {
        public ValueTask<AccountDirectoryProtectedLkg> ReadRetainedAsync(
            VerifiedXPointNetworkAuthority authority, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No retained observation is available.");
        public ValueTask CommitCatchupAsync(VerifiedDeepIdV2DirectoryCatchup verified,
            CancellationToken cancellationToken) => throw new InvalidOperationException("No history may be committed.");
        internal bool Called { get; private set; }

        public ValueTask<AccountDirectoryProtectedLkg> RestoreAsync(
            VerifiedXPointNetworkAuthority authority,
            CancellationToken cancellationToken)
        {
            Called = true;
            return ValueTask.FromResult<AccountDirectoryProtectedLkg>(null!);
        }

        public ValueTask CommitVerifiedAsync(AccountDirectoryProtectedLkg expected,
            VerifiedDeepIdV2DirectoryFreshness verified,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No proof may be committed.");
    }

    private sealed class RejectIfCalledArtifacts :
        IDeepIdV2DirectoryProofArtifactSource
    {
        public ValueTask<DeepIdV2DirectoryHistoryPage> FetchHistoryAsync(AccountDirectoryProtectedLkg source,
            CancellationToken cancellationToken) => throw new InvalidOperationException("No history may be fetched.");
        internal bool Called { get; private set; }

        public ValueTask<DeepIdV2DirectoryProofWireResponse> FetchAsync(
            ParsedAdl1V2 lookup, ParsedDid2 did2, ReadOnlyMemory<byte> nonce,
            ReadOnlyMemory<byte> bootId, ulong monotonicSendSample,
            CancellationToken cancellationToken)
        {
            Called = true;
            throw new InvalidOperationException("No proof may be fetched.");
        }
    }

    private sealed class RejectIfCalledClock : IOnionMonotonicClock
    {
        internal bool Called { get; private set; }

        public ValueTask<OnionMonotonicReading> ReadAsync(
            CancellationToken cancellationToken)
        {
            Called = true;
            throw new InvalidOperationException("No clock read is expected.");
        }
    }

    private sealed class RejectIfCalledPq : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952,
            ReadOnlySpan<byte> message, ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> signature3309) =>
            throw new InvalidOperationException("No signature check is expected.");
    }
}
