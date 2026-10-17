using Microsoft.Extensions.Logging;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2PreKeyClaimDiagnosticsTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedFailureObservationPreservesPrivacyRateBoundAndThrowingSinkIsolation(bool throwing)
    {
        var logger = new Capture(throwing);
        var diagnostics = new DeepIdV2PreKeyClaimDiagnostics(logger);
        var error = new IOException("DO-NOT-EXPORT", new InvalidOperationException("DO-NOT-EXPORT"));
        diagnostics.Report("untrusted-phase", error);
        var count = logger.Rows.Count;
        diagnostics.Report("Terminal", error);
        Assert.Equal(count, logger.Rows.Count);
        Assert.Equal(throwing ? 1 : 2, count);
        foreach (var row in logger.Rows)
        {
            Assert.Null(row.Error);
            Assert.Equal("Unclassified", row.Values["Phase"]);
            Assert.Contains((string)row.Values["Category"]!, new[] { "Io", "InvalidOperation" });
            Assert.Equal(new[] { "Category", "Depth", "Il", "Method", "Phase", "{OriginalFormat}" },
                row.Values.Keys.Order(StringComparer.Ordinal));
            Assert.DoesNotContain("DO-NOT-EXPORT", string.Join(" ", row.Values.Values));
            Assert.InRange((int)row.Values["Il"]!, -1, 1048575);
        }
    }

    private sealed class Capture(bool throwing) : ILogger
    {
        internal readonly List<(Dictionary<string, object?> Values, Exception? Error)> Rows = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Rows.Add((((IEnumerable<KeyValuePair<string, object?>>)state!).ToDictionary(), exception));
            if (throwing) throw new IOException("Test sink interruption.");
        }
    }
}
