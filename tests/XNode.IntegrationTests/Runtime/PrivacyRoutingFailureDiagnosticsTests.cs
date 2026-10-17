using Microsoft.Extensions.Logging;

namespace XNode.IntegrationTests.Runtime;

public sealed class PrivacyRoutingFailureDiagnosticsTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ObservationIsClosedBoundedAndDoesNotReplaceFailure(bool throwing)
    {
        var logger = new Capture(throwing);
        var observer = new PrivacyRoutingFailureDiagnostics(logger);
        var error = new IOException("DO-NOT-EXPORT", new InvalidOperationException("DO-NOT-EXPORT"));
        observer.Report("untrusted", error);
        var count = logger.Rows.Count;
        observer.Report("Dispatch", error);
        Assert.Equal(count, logger.Rows.Count);
        Assert.Equal(throwing ? 1 : 2, count);
        foreach (var row in logger.Rows)
        {
            Assert.Null(row.Error);
            Assert.Equal("Unclassified", row.Values["Phase"]);
            Assert.Equal(new[] { "Category", "Depth", "Il", "Method", "Phase", "{OriginalFormat}" },
                row.Values.Keys.Order(StringComparer.Ordinal));
            Assert.DoesNotContain("DO-NOT-EXPORT", string.Join(" ", row.Values.Values));
        }
    }
    private sealed class Capture(bool throwing) : ILogger
    {
        internal readonly List<(Dictionary<string, object?> Values, Exception? Error)> Rows = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error,
            Func<TState, Exception?, string> formatter)
        {
            Rows.Add((((IEnumerable<KeyValuePair<string, object?>>)state!).ToDictionary(), error));
            if (throwing) throw new IOException("Test sink interruption.");
        }
    }
}
