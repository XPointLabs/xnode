using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task CompleteOperationScratchPrecedesProtectedPlanAndInterruptedReplaceKeepsExactIntent(int interruption)
    {
        await using var f = await Fixture.CreateAsync();
        var barrier = new OperationScratchOrder(f.LedgerFile, interruption);
        f.OpenLedger(durability: barrier, custodyDurability: barrier);
        var client = MailboxAuthenticatedClientRequestCodec.Decode(f.ClientStoreFrame());
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(client.Binding.CanonicalRequest.Span);
        async Task Reserve()
        {
            _ = await f.Sender.Node.Admission.WithGrantAsync(
                MailboxAuthenticatedCapabilityCodec.EncodeGrant(client.Presentation.Grant), MailboxCapabilityDomain.Deposit,
                async (scope, token) =>
                {
                    await f.Ledger!.ReserveCurrentStoreAsync(envelope, scope.Grant.MembershipCommitment,
                        scope.Replicas.Select(replica => replica.NodeId).ToArray(), scope.Lease,
                        (cursor, upper) => f.Sender.Receiver.AuthorStoreRequest(scope,
                            client.Binding.CanonicalRequest, cursor, upper), scope.Host, token);
                    return 0;
                });
        }
        if (interruption == 0) await Reserve();
        else
        {
            await Assert.ThrowsAsync<IOException>(Reserve);
            Assert.True(barrier.Interrupted);
            Assert.True(barrier.PendingFlushed);
            Assert.False(barrier.CommittedFlushed);
            Assert.Equal(interruption == 2, barrier.OperationReplaced);
            barrier.Interruption = 0;
            await f.InitializeLedgerAsync();
        }
        Assert.True(barrier.OperationReplaced);
        Assert.True(barrier.CommittedFlushed);
        Assert.True(barrier.OperationFlushes > 0);
        Assert.Equal(barrier.PreparedBytes, File.ReadAllBytes(f.LedgerFile));
        Assert.Single(f.ExactIntents);
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests);
    }

    // Observe real durability calls and perform the actual native barriers. The
    // test does not emulate disk persistence or inject a successful authority.
    private sealed class OperationScratchOrder(string operationFile, int interruption) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new();
        private int checkpoints;
        internal int Interruption = interruption;
        internal bool Interrupted, PendingFlushed, OperationReplaced, CommittedFlushed;
        internal int OperationFlushes;
        internal byte[]? PreparedBytes;

        public void ReplaceFile(string temporary, string final)
        {
            if (final == operationFile)
            {
                if (Interrupted && Interruption != 0) throw new IOException("Test-owned interrupted scratch replacement.");
                Assert.True(PendingFlushed);
                Assert.NotNull(PreparedBytes);
                Assert.Equal(PreparedBytes, File.ReadAllBytes(temporary));
                if (Interruption == 1)
                { Interrupted = true; throw new IOException("Test-owned pre-replacement interruption."); }
                native.ReplaceFile(temporary, final); OperationReplaced = true;
                if (Interruption == 2)
                { Interrupted = true; throw new IOException("Test-owned post-replacement interruption."); }
                return;
            }
            if (Path.GetFileName(final) == "checkpoint.bin")
            {
                Assert.NotNull(PreparedBytes);
                if (checkpoints != 0)
                { Assert.True(OperationReplaced); Assert.True(OperationFlushes > 0); }
                checkpoints++;
            }
            native.ReplaceFile(temporary, final);
        }

        public void FlushFileAndParentDirectory(string path)
        {
            native.FlushFileAndParentDirectory(path);
            if (path.StartsWith(operationFile + ".", StringComparison.Ordinal) && path.EndsWith(".tmp", StringComparison.Ordinal))
            {
                PreparedBytes = File.ReadAllBytes(path);
                using var document = JsonDocument.Parse(PreparedBytes);
                var operation = document.RootElement.GetProperty("operations").EnumerateObject().Single().Value;
                var exact = Convert.FromBase64String(operation.GetProperty("peerRequest").GetString()!);
                Assert.Equal(exact, MailboxPeerWireV2Codec.Encode(MailboxPeerWireV2Codec.Decode(exact)));
            }
            else if (path == operationFile)
            {
                Assert.True(OperationReplaced); Assert.True(PendingFlushed);
                Assert.Equal(PreparedBytes, File.ReadAllBytes(path));
                OperationFlushes++;
            }
            else if (Path.GetFileName(path) == "checkpoint.bin")
            {
                if (checkpoints == 1) PendingFlushed = true;
                else CommittedFlushed = true;
            }
        }

        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
    }
}
