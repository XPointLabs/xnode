using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2DirectoryCurrentProofReaderTests
{
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
