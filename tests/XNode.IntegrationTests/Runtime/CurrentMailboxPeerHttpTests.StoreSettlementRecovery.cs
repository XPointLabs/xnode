using System.Text.Json.Nodes;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task OriginalStoreRecoverySettlesNativePendingWithoutClientAndAdoptsSameQuorum(bool lostReply, bool reopen)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = f.ClientStoreFrame();
        if (lostReply)
        {
            f.RemoteHost.DropNext = true;
            Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, (await f.Coordinator.StoreClientAsync(client)).Status);
        }
        else
        {
            f.Sender.Fault.Action = point =>
            { if (point == MailboxPeerMutationFaultPoint.StoreReserved) throw new IOException("Test-owned original Store interruption."); };
            await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(client).AsTask());
            f.Sender.Fault.Action = null;
        }
        var original = Assert.Single(f.ExactIntents);
        if (reopen) { f.Reopen(); f.Signed.Sample = 101; }
        var clientOutcomes = f.Sender.Node.OutcomeCount;
        using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, NullLogger<CurrentMailboxStoreRecoveryWorker>.Instance);
        Assert.Equal("settled", await worker.RunOnceAsync(default));
        Assert.Equal(original, Assert.Single(f.ExactIntents));
        Assert.Equal(clientOutcomes, f.Sender.Node.OutcomeCount); // Native settlement is not a fabricated client outcome.
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.All(f.PeerClient.ExactRequests, request => Assert.Equal(original, request));
        var document = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!;
        var operation = document["operations"]!.AsObject().Single().Value!;
        Assert.Equal("durable", operation["state"]!.GetValue<string>());
        var quorum = Convert.FromBase64String(operation["receipt"]!.GetValue<string>());
        var http = f.AllHttpRequests;
        Assert.Equal("idle", await worker.RunOnceAsync(default));
        Assert.Equal(http, f.AllHttpRequests);
        f.Reopen(); f.Signed.Sample = 102;
        var recovered = await f.Coordinator.StoreClientAsync(client);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, recovered.Status);
        Assert.Equal(quorum, recovered.CanonicalMqr3.ToArray());
        Assert.Equal(http, f.AllHttpRequests); // Adopt, never create another receipt/peer mutation.
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        Assert.Single(page.Items); Assert.Equal(1UL, page.NextCursor);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OriginalStoreRecoveryCannotDispatchExpiredOrUnavailableAuthority(bool unavailable)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.RemoteHost.DropNext = true;
        _ = await f.Coordinator.StoreClientAsync(f.ClientStoreFrame());
        var original = Assert.Single(f.ExactIntents); var protectedDocument = File.ReadAllBytes(f.LedgerFile);
        var http = f.AllHttpRequests;
        f.Reopen();
        if (unavailable) f.Signed.RejectProof = true; else f.Signed.Sample = 105;
        using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, NullLogger<CurrentMailboxStoreRecoveryWorker>.Instance);
        Assert.Equal("unavailable", await worker.RunOnceAsync(default));
        Assert.Equal(original, Assert.Single(f.ExactIntents)); Assert.Equal(protectedDocument, File.ReadAllBytes(f.LedgerFile));
        Assert.Equal(http, f.AllHttpRequests);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => worker.RunOnceAsync(cancelled.Token));
        Assert.Equal(http, f.AllHttpRequests);
    }

    [Fact]
    public async Task OriginalStoreRecoveryCannotBypassProtectedRevocation()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = f.ClientStoreFrame(); f.RemoteHost.DropNext = true;
        _ = await f.Coordinator.StoreClientAsync(client);
        var grant = MailboxAuthenticatedClientRequestCodec.Decode(client).Presentation.Grant;
        var prior = MailboxGrantRevocationStoreTests.Snapshot(f.Signed);
        await f.Sender.Node.Deposit.AdvanceAsync(f.Sender.Node.Host,
            MailboxGrantRevocationStoreTests.Snapshot(f.Signed, generation: 2, prior: prior, serials: [grant.Serial.ToArray()]));
        var document = File.ReadAllBytes(f.LedgerFile); var http = f.AllHttpRequests;
        using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, NullLogger<CurrentMailboxStoreRecoveryWorker>.Instance);
        Assert.Equal("unavailable", await worker.RunOnceAsync(default));
        Assert.Equal(document, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(http, f.AllHttpRequests);
    }

    [Theory]
    [InlineData("foreign-key")]
    [InlineData("terminal")]
    [InlineData("settled")]
    public async Task OriginalStoreRecoveryRechecksActualIntentBeforePeerReplayOrMutation(string changed)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.RemoteHost.DropNext = true; _ = await f.Coordinator.StoreClientAsync(f.ClientStoreFrame());
        var intent = await f.Sender.Receiver.ReadPendingStoreAsync(uint.MaxValue, default);
        Assert.NotNull(intent);
        if (changed == "foreign-key") intent = intent! with { OperationKey = "not-an-owned-intent" };
        else if (changed == "terminal")
        {
            var terminal = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!;
            var row = terminal["operations"]!.AsObject().Single().Value!;
            row["state"] = "terminal"; row["error"] = "test-owned closed state";
            await f.InstallTestOwnedDocumentAsync(System.Text.Encoding.UTF8.GetBytes(terminal.ToJsonString()));
        }
        else
        {
            using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, NullLogger<CurrentMailboxStoreRecoveryWorker>.Instance);
            Assert.Equal("settled", await worker.RunOnceAsync(default));
        }
        var document = File.ReadAllBytes(f.LedgerFile); var http = f.AllHttpRequests;
        var before = AdmissionOwnerDigest(f.Sender.Node.DataRoot);
        var called = false;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.WithOriginalStoreIntentAsync(
            intent!, (_, _) =>
            { called = true; return ValueTask.FromResult(0); }, default).AsTask());
        Assert.False(called); Assert.Equal(before, AdmissionOwnerDigest(f.Sender.Node.DataRoot));
        Assert.Equal(document, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(http, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OriginalStoreRecoveryQuorumPersistenceFailureResumesSealedWinnerWithoutPeerHttp(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(new SettlementWriteFault(beforeReplace));
        var client = f.ClientStoreFrame(); f.RemoteHost.DropNext = true;
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, (await f.Coordinator.StoreClientAsync(client)).Status);
        var original = Assert.Single(f.ExactIntents);
        using (var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, NullLogger<CurrentMailboxStoreRecoveryWorker>.Instance))
            Assert.Equal("unavailable", await worker.RunOnceAsync(default));
        Assert.Equal(0, f.Sender.Node.OutcomeCount);
        var http = f.AllHttpRequests;
        f.Reopen(); f.Signed.Sample = 101;
        using (var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, NullLogger<CurrentMailboxStoreRecoveryWorker>.Instance))
            Assert.Equal("idle", await worker.RunOnceAsync(default));
        var document = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!;
        var saved = Convert.FromBase64String(document["operations"]!.AsObject().Single().Value!["receipt"]!.GetValue<string>());
        Assert.NotEmpty(saved); Assert.Equal(original, Assert.Single(f.ExactIntents));
        var result = await f.Coordinator.StoreClientAsync(client);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, result.Status);
        Assert.Equal(saved, result.CanonicalMqr3.ToArray()); Assert.Equal(http, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OriginalStoreRecoveryCannotRepairMissingCustody(bool checkpoint)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.RemoteHost.DropNext = true; _ = await f.Coordinator.StoreClientAsync(f.ClientStoreFrame());
        var path = checkpoint ? Assert.Single(Directory.GetFiles(f.Sender.Node.OperationCustodyRoot,
            "checkpoint.bin", SearchOption.AllDirectories)) : f.LedgerFile;
        File.Delete(path); var http = f.AllHttpRequests;
        using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, NullLogger<CurrentMailboxStoreRecoveryWorker>.Instance);
        Assert.Equal("unavailable", await worker.RunOnceAsync(default));
        Assert.False(File.Exists(path)); Assert.Equal(http, f.AllHttpRequests);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
    }

    [Fact]
    public async Task OriginalStoreRecoveryWrongTlsCannotInventQuorumOrAdvancePrefix()
    {
        await using var f = await Fixture.CreateAsync(wrongPin: true); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        var original = Assert.Single(f.ExactIntents); var document = File.ReadAllBytes(f.LedgerFile);
        using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, NullLogger<CurrentMailboxStoreRecoveryWorker>.Instance);
        Assert.Equal("incomplete", await worker.RunOnceAsync(default));
        Assert.Equal(original, Assert.Single(f.ExactIntents)); Assert.Equal(document, File.ReadAllBytes(f.LedgerFile));
        Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(2, f.PeerClient.ExactRequests.Count);
        Assert.All(f.PeerClient.ExactRequests, request => Assert.Equal(original, request));
    }

    [Fact]
    public async Task OriginalStoreRecoveryHostedLifetimeIsCancellableAndIdleDoesNotWrite()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var document = File.ReadAllBytes(f.LedgerFile); var logger = new StoreRecoverySignal();
        using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, logger);
        await worker.StartAsync(default);
        Assert.Equal("Current mailbox Store recovery: state=idle; original custody retained.",
            await logger.Seen.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.False(worker.ExecuteTask!.IsCompleted);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StopAsync(stop.Token);
        Assert.True(worker.ExecuteTask.IsCompleted);
        Assert.Equal(document, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(0, f.AllHttpRequests);
    }

    private sealed class StoreRecoverySignal : ILogger<CurrentMailboxStoreRecoveryWorker>
    {
        internal bool Throw;
        internal int Calls;
        internal TaskCompletionSource<string> Seen { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Calls++; Assert.Null(exception);
            if (Throw) throw new IOException("Test-owned logger failure.");
            Seen.TrySetResult(formatter(state, exception));
        }
    }

    [Fact]
    public async Task OriginalStoreRecoveryOnionAuthorityFailureRetainsCustodyWithoutStoppingHost()
    {
        // Obtain the genuine sealed Protocol exception through its verifier,
        // not a new public constructor, reflection or fake runtime authority.
        using var expired = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var history = Deep.Protocol.DeepExtension.PrivacyRouting.OnionNetworkProtectedHistoryCodec.Encode(expired.NetworkContext);
        expired.Sample = expired.Freshness.FreshnessDeadlineMonotonicSeconds;
        var boundary = await Assert.ThrowsAsync<Deep.Protocol.DeepExtension.PrivacyRouting.OnionBoundaryException>(() => expired.VerifyHistoryAsync(history).AsTask());
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.RemoteHost.DropNext = true; _ = await f.Coordinator.StoreClientAsync(f.ClientStoreFrame());
        var document = File.ReadAllBytes(f.LedgerFile); var http = f.AllHttpRequests;
        f.OpenLedger(afterVerifiedRead: () => throw boundary);
        var logger = new StoreRecoverySignal();
        using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, logger);
        Assert.Equal("unavailable", await worker.RunOnceAsync(default));
        Assert.Equal("unavailable", await worker.RunOnceAsync(default));
        Assert.DoesNotContain(boundary.Message, await logger.Seen.Task);
        Assert.Equal(SHA256.HashData(document), SHA256.HashData(File.ReadAllBytes(f.LedgerFile)));
        Assert.Equal(http, f.AllHttpRequests);
        await worker.StartAsync(default);
        Assert.False(worker.ExecuteTask!.IsCompleted);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StopAsync(stop.Token);
        Assert.True(worker.ExecuteTask.IsCompleted);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OriginalStoreRecoveryClosedFailureCannotReadPrivateExceptionOrChangeOutcome(bool loggerThrows)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.RemoteHost.DropNext = true; _ = await f.Coordinator.StoreClientAsync(f.ClientStoreFrame());
        var document = File.ReadAllBytes(f.LedgerFile); var http = f.AllHttpRequests;
        f.OpenLedger(afterVerifiedRead: () => throw new UnreadableNativeFailure());
        var logger = new StoreRecoverySignal { Throw = loggerThrows };
        using var worker = new CurrentMailboxStoreRecoveryWorker(f.Coordinator, logger);
        Assert.Equal("unavailable", await worker.RunOnceAsync(default));
        Assert.Equal("unavailable", await worker.RunOnceAsync(default));
        Assert.Equal(1, logger.Calls);
        if (!loggerThrows)
        {
            Assert.True(logger.Seen.Task.IsCompletedSuccessfully);
            var message = await logger.Seen.Task;
            Assert.StartsWith("Current mailbox Store recovery: state=unavailable; method=MailboxClientOperationLedger+", message);
            Assert.Contains("; il=", message);
            Assert.DoesNotContain(nameof(UnreadableNativeFailure), message);
        }
        Assert.Equal(document, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(http, f.AllHttpRequests);
    }

    [Fact]
    public void OriginalStoreRecoveryAuthorityReasonUsesOnlyExistingAllowlistedBuiltinMetadata()
    {
        foreach (var label in new[] { "Lifecycle", "Network", "Generation", "IssuerKey", "IssuerNotBefore", "GrantNotBefore",
            "GrantExpiry", "PolicyExpiry", "NetworkExpiry", "Lifetime", "Signature" })
        {
            var error = new System.Security.Cryptography.CryptographicException();
            error.Data["Deep.MailboxAuthority.Check"] = label;
            Assert.Equal(label, CurrentMailboxDiagnostics.AuthorityFailureCheck(error));
        }
        var unknown = new System.Security.Cryptography.CryptographicException();
        Assert.Equal("Unclassified", CurrentMailboxDiagnostics.AuthorityFailureCheck(unknown));
        unknown.Data["Deep.MailboxAuthority.Check"] = "private-unrecognized-provider-value";
        Assert.Equal("Unclassified", CurrentMailboxDiagnostics.AuthorityFailureCheck(unknown));
        unknown.Data["Deep.MailboxAuthority.Check"] = new UnreadableNativeFailure();
        Assert.Equal("Unclassified", CurrentMailboxDiagnostics.AuthorityFailureCheck(unknown));
        Assert.Equal("Unclassified", CurrentMailboxDiagnostics.AuthorityFailureCheck(new UnreadableAuthorityFailure()));
        Assert.Equal("Unclassified", CurrentMailboxDiagnostics.AuthorityFailureCheck(null));
    }

    private sealed class UnreadableAuthorityFailure : System.Security.Cryptography.CryptographicException
    {
        public override System.Collections.IDictionary Data => throw new InvalidOperationException("Private diagnostic getter must not run.");
        public override string Message => throw new InvalidOperationException("Private message must not be read.");
        public override string ToString() => throw new InvalidOperationException("Private value must not be rendered.");
    }
}
