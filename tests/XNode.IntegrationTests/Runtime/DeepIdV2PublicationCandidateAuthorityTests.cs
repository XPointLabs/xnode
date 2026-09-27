using System.Runtime.CompilerServices;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.ContactPreKey;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2PublicationCandidateAuthorityTests
{
    [Fact]
    public async Task IncompleteJournal_DoesNotAskDirectoryOrClockForAuthority()
    {
        var directory = Path.Combine(Path.GetTempPath(),
            "xnode-did2-candidate-" + Guid.NewGuid().ToString("N"));
        var proofs = new RejectIfCalledProofs();
        var clock = new RejectIfCalledClock();
        try
        {
            using var journal = new DeepIdV2PublicationJournal(directory,
                Bytes(16, 0x11), Bytes(32, 0x12), Bytes(32, 0x13),
                Bytes(32, 0x14), Bytes(32, 0x15));
            var gate = new DeepIdV2PublicationCandidateAuthority(proofs, clock);
            var closure = (ParsedDcr1V2)RuntimeHelpers.GetUninitializedObject(
                typeof(ParsedDcr1V2));
            var authorization = (VerifiedDca1V2)
                RuntimeHelpers.GetUninitializedObject(typeof(VerifiedDca1V2));

            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await gate.VerifyCommittedCandidateAsync(journal, closure,
                    authorization, default));
            Assert.False(proofs.Called);
            Assert.False(clock.Called);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class RejectIfCalledProofs :
        IDeepIdV2CurrentDirectoryProofSource
    {
        internal bool Called { get; private set; }

        public ValueTask<VerifiedDeepIdV2DirectoryFreshness> ReadCurrentAsync(
            ParsedDid2 did2, CancellationToken cancellationToken)
        {
            Called = true;
            throw new InvalidOperationException("No incomplete candidate lookup.");
        }
    }

    private sealed class RejectIfCalledClock : IOnionMonotonicClock
    {
        internal bool Called { get; private set; }

        public ValueTask<OnionMonotonicReading> ReadAsync(
            CancellationToken cancellationToken)
        {
            Called = true;
            throw new InvalidOperationException("No incomplete candidate clock.");
        }
    }

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();
}
