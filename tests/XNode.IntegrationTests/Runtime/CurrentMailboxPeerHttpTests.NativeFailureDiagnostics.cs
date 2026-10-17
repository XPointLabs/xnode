using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.Logging;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData("mailbox-peer-store-context-conflict", "StoreContext")]
    [InlineData("mailbox-peer-tombstone-context-conflict", "TombstoneContext")]
    [InlineData("mailbox-peer-expiry-overflow", "ExpiryOverflow")]
    [InlineData("invalid-mailbox-blob", "InvalidBlob")]
    [InlineData("mailbox-blob-size-rejected", "BlobSize")]
    [InlineData("mailbox-ciphertext-not-canonical", "CiphertextCanonical")]
    [InlineData("mailbox-blob-ttl-rejected", "BlobTtl")]
    [InlineData("mailbox-blob-digest-mismatch", "BlobDigest")]
    [InlineData("mailbox-storage-corrupt", "StorageCorrupt")]
    [InlineData("mailbox-blob-id-conflict", "BlobConflict")]
    [InlineData("mailbox-capacity-exhausted", "Capacity")]
    [InlineData("private mailbox-blob-ttl-rejected", "Unclassified")]
    [InlineData(null, "Unclassified")]
    public void NativeMutationObserverMapsOnlyWholeClosedCodes(string? input, string expected)
    {
        var error = CurrentMailboxDiagnostics.MutationRejection(input);
        Assert.Equal("Current peer durable mutation was rejected.", error.Message);
        Assert.Equal(expected, CurrentMailboxDiagnostics.MutationFailureCheck(error));
        Assert.Equal("Unclassified", CurrentMailboxDiagnostics.MutationFailureCheck(new UnreadableNativeFailure()));
        error.Data["Deep.MailboxMutation.Check"] = "private payload";
        Assert.Equal("Unclassified", CurrentMailboxDiagnostics.MutationFailureCheck(error));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task NativeMutationObserverCannotPromoteRejectionOrExposeOriginalText(bool loggerThrows)
    {
        await using var f = await Fixture.CreateAsync();
        var logger = new NativeFailureLogger { Throw = loggerThrows };
        using var services = NativeServices(f, () => throw CurrentMailboxDiagnostics.MutationRejection("mailbox-blob-ttl-rejected"), logger);
        var dispatcher = NativeDispatcher(services);
        AssertUnknown(await dispatcher.DispatchAsync(OnionOperation.Retrieve,
            NativeFrame(f, MailboxAuthenticatedOperation.Retrieve), default));
        Assert.Equal(1, logger.Calls); Assert.Null(logger.SuppliedException);
        if (!loggerThrows)
        {
            var message = Assert.Single(logger.Messages);
            Assert.Contains("; mutationCheck=BlobTtl;", message);
            Assert.DoesNotContain("mailbox-blob-ttl-rejected", message);
            Assert.EndsWith("; completion remains unknown.", message);
        }
        Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativeIngressClosedFailureObserverCannotReadPrivateExceptionOrChangeUnknown(bool loggerThrows)
    {
        await using var f = await Fixture.CreateAsync();
        var logger = new NativeFailureLogger { Throw = loggerThrows };
        var failure = new UnreadableNativeFailure();
        using var services = NativeServices(f, () => throw failure, logger);
        var dispatcher = NativeDispatcher(services);
        var exact = NativeFrame(f, MailboxAuthenticatedOperation.Retrieve);
        var reads = f.Signed.PublicationReads;
        var ledger = File.ReadAllBytes(f.LedgerFile);
        AssertUnknown(await dispatcher.DispatchAsync(OnionOperation.Retrieve, exact, default));
        AssertUnknown(await dispatcher.DispatchAsync(OnionOperation.Retrieve, exact, default));
        Assert.Equal(1, logger.Calls); // Bounded even when the logger itself fails.
        Assert.Null(logger.SuppliedException);
        if (!loggerThrows)
        {
            var message = Assert.Single(logger.Messages);
            Assert.StartsWith("Current mailbox terminal incomplete: stage=native-failure; kind=custody-or-io;", message);
            Assert.Contains("; depth=0; method=NativeMailboxExitDispatcher+", message);
            Assert.Contains("; il=", message);
            Assert.EndsWith("; completion remains unknown.", message);
            Assert.DoesNotContain(nameof(UnreadableNativeFailure), message);
        }
        Assert.Equal(reads, f.Signed.PublicationReads);
        Assert.Equal(ledger, File.ReadAllBytes(f.LedgerFile));
        Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
    }

    [Fact]
    public async Task NativeIngressClosedFailureObserverCannotSwallowCallerCancellation()
    {
        await using var f = await Fixture.CreateAsync();
        var logger = new NativeFailureLogger();
        using var cancelled = new CancellationTokenSource();
        using var services = NativeServices(f, cancelled.Cancel, logger);
        var dispatcher = NativeDispatcher(services);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => dispatcher.DispatchAsync(
            OnionOperation.Retrieve, NativeFrame(f, MailboxAuthenticatedOperation.Retrieve), cancelled.Token));
        Assert.True(cancelled.IsCancellationRequested);
        Assert.Null(logger.SuppliedException);
        Assert.Contains("stage=caller-cancelled; kind=cancelled;", Assert.Single(logger.Messages));
        Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
    }

    private sealed class UnreadableNativeFailure : IOException
    {
        public override string Message => throw new InvalidOperationException("Private Message must not be read.");
        public override System.Collections.IDictionary Data => throw new InvalidOperationException("Private Data must not be read.");
        public override string ToString() => throw new InvalidOperationException("Private ToString must not be read.");
    }

    private sealed class NativeFailureLogger : ILogger<NativeMailboxExitDispatcher>
    {
        internal bool Throw;
        internal int Calls;
        internal Exception? SuppliedException;
        internal List<string> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Calls++; SuppliedException = exception;
            if (Throw) throw new IOException("Logger failure cannot replace dispatch outcome.");
            Messages.Add(formatter(state, exception));
        }
    }
}
