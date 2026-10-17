using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PeerClientClosedFailureDiagnosticPreservesExactRefusalAndRateBound(bool throwingSink)
    {
        await using var f = await Fixture.CreateAsync();
        f.Bind(true);
        var request = f.Sender.Frame(MailboxPeerReplicationOperation.Store);
        var before = request.ToArray();
        var target = f.Sender.Node.Replicas.Single(replica => replica.NodeId.Span.SequenceEqual(f.Sender.Node.Node)).Transport;
        var log = new PeerDiagnosticLog<CurrentMailboxReplicaPeerClient>(throwingSink);
        var ingressLog = new PeerDiagnosticLog<CurrentMailboxPeerHttpEndpoint>(throwingSink);
        f.RemoteHost.Endpoint = new CurrentMailboxPeerHttpEndpoint(f.Sender.Receiver, f.RemoteHost.Port, ingressLog);
        var client = new CurrentMailboxReplicaPeerClient(log);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            Assert.Null(await client.SendAsync(target, MailboxPeerReplicationOperation.Store, request, default));
            Assert.Equal((int)HttpStatusCode.Forbidden, f.RemoteHost.LastStatus);
        }
        Assert.Equal(before, request);
        Assert.Equal(1, log.Calls);
        Assert.False(log.ExceptionPassed);
        Assert.Equal(LogLevel.Warning, log.Level);
        Assert.Equal(new[] { "Phase", "Reason", "Status", "{OriginalFormat}" },
            log.Fields.Keys.OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal("headers", log.Fields["Phase"]);
        Assert.Equal("status", log.Fields["Reason"]);
        Assert.Equal(403, log.Fields["Status"]);
        Assert.Equal(1, ingressLog.Calls);
        Assert.False(ingressLog.ExceptionPassed);
        Assert.Equal(LogLevel.Warning, ingressLog.Level);
        Assert.Equal(new[] { "AuthorityCheck", "Failure", "Il", "Method", "Reason", "{OriginalFormat}" },
            ingressLog.Fields.Keys.OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal("AuthorizationFailed", ingressLog.Fields["Failure"]);
        Assert.Equal("cryptographic-rejection", ingressLog.Fields["Reason"]);
        Assert.Equal("Unclassified", ingressLog.Fields["AuthorityCheck"]);
        var method = Assert.IsType<string>(ingressLog.Fields["Method"]);
        Assert.StartsWith("CurrentMailboxReplicaReceiver+", method);
        Assert.InRange(method.Length, 1, 240);
        Assert.Matches("^[A-Za-z0-9_.+<>`]+$", method);
        Assert.InRange(Assert.IsType<int>(ingressLog.Fields["Il"]), -1, 1048575);
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Recipient.ReplayFiles);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
    }

    private sealed class PeerDiagnosticLog<T>(bool throwing) : ILogger<T>
    {
        internal int Calls;
        internal bool ExceptionPassed;
        internal LogLevel Level;
        internal Dictionary<string, object?> Fields = new(StringComparer.Ordinal);
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Calls++; Level = level; ExceptionPassed |= exception is not null;
            Fields = ((IEnumerable<KeyValuePair<string, object?>>)state!).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            if (throwing) throw new InvalidOperationException("Test diagnostic sink failure.");
        }
    }

    [Fact]
    public async Task NonWriterClientAndSignedHttpPeerCannotReserveOrAllocateCursor()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); f.OpenRecipientLedger();
        var recipientPrior = File.ReadAllBytes(f.AckLedgerFile.Replace(f.Sender.Node.DataRoot, f.Recipient.Node.DataRoot, StringComparison.Ordinal));
        var client = f.ClientStoreFrame();
        var reversed = f.Sender.Frame(MailboxPeerReplicationOperation.Store);
        var target = f.Sender.Node.Replicas.Single(replica => replica.NodeId.Span.SequenceEqual(f.Sender.Node.Node)).Transport;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            f.Bind(true);
            await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.StoreClientAsync(client, f.RecipientLedger!).AsTask());
            Assert.Equal(0, f.Recipient.Node.Replay.Diagnostics.ScopeCount);
            Assert.Equal(0UL, f.Recipient.Node.Replay.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);
            Assert.Equal(0, f.Recipient.Node.OutcomeCount);
            Assert.Equal(recipientPrior, File.ReadAllBytes(f.AckLedgerFile));
            Assert.Null(await new CurrentMailboxReplicaPeerClient().SendAsync(
                target, MailboxPeerReplicationOperation.Store, reversed, default));
            Assert.Equal((int)HttpStatusCode.Forbidden, f.RemoteHost.LastStatus);
            Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Recipient.ReplayFiles);
            Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
            Assert.Empty(f.ExactIntents);
            f.Reopen();
        }
        f.Bind(false);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, f.Ledger!)).Status);
        var peer = MailboxPeerWireV2Codec.Decode(Assert.Single(f.ExactIntents));
        Assert.Equal(1UL, peer.Cursor); Assert.Equal(f.Sender.Node.Replicas[0].NodeId.ToArray(), peer.SenderRouterId.ToArray());
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        Assert.Equal(1UL, Assert.Single(page.Items).Cursor);
    }
}
