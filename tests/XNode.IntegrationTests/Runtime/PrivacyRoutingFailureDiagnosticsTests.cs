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
            Assert.Equal(GroupControlAuthorityRejection.Unclassified, row.Values["AuthorityCheck"]);
            Assert.Equal(new[] { "AuthorityCheck", "Category", "Depth", "Il", "Method", "Phase", "{OriginalFormat}" },
                row.Values.Keys.Order(StringComparer.Ordinal));
            Assert.DoesNotContain("DO-NOT-EXPORT", string.Join(" ", row.Values.Values));
        }
    }
    [Fact]
    public void GroupAuthorityReasonIsTypedAndNeverExportsExceptionData()
    {
        var error = new GroupControlAuthorityUnavailableException(GroupControlAuthorityRejection.Expired);
        error.Data["untrusted"] = "DO-NOT-EXPORT";
        var logger = new Capture(false);
        new PrivacyRoutingFailureDiagnostics(logger).Report("Dispatch", error);
        var row = Assert.Single(logger.Rows);
        Assert.Null(row.Error);
        Assert.Equal(GroupControlAuthorityRejection.Expired, row.Values["AuthorityCheck"]);
        Assert.DoesNotContain("DO-NOT-EXPORT", string.Join(" ", row.Values.Values));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new GroupControlAuthorityUnavailableException((GroupControlAuthorityRejection)255));
    }
    [Fact]
    public void ContactAdmissionPreservesOnlyItsClosedPhase()
    {
        var logger = new Capture(false);
        new PrivacyRoutingFailureDiagnostics(logger).Report("ContactAdmission", new IOException("DO-NOT-EXPORT"));
        var row = Assert.Single(logger.Rows);
        Assert.Null(row.Error);
        Assert.Equal("ContactAdmission", row.Values["Phase"]);
        Assert.DoesNotContain("DO-NOT-EXPORT", string.Join(" ", row.Values.Values));
    }
    [Fact]
    public void ContactAuthorityReasonIsTypedAndNeverExportsExceptionData()
    {
        var error = new ContactAdmissionIntervalException(ContactAdmissionRejection.IssuedFuture);
        error.Data["untrusted"] = "DO-NOT-EXPORT";
        var logger = new Capture(false);
        new PrivacyRoutingFailureDiagnostics(logger).Report("ContactAdmission", error);
        var row = Assert.Single(logger.Rows);
        Assert.Null(row.Error);
        Assert.Equal(ContactAdmissionRejection.IssuedFuture, row.Values["AuthorityCheck"]);
        Assert.DoesNotContain("DO-NOT-EXPORT", string.Join(" ", row.Values.Values));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ContactAdmissionIntervalException((ContactAdmissionRejection)255));
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
