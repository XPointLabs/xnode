namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxWorkTimingTests
{
    [Fact]
    public async Task WorkUsesClosedNumericBucketsAndRestoresNestedScopeAcrossAwait()
    {
        CurrentMailboxDiagnostics.WorkSummary? outer = null, inner = null;
        using (CurrentMailboxDiagnostics.BeginWork(row => outer = row))
        {
            using (CurrentMailboxDiagnostics.Measure("lease-check")) await Task.Yield();
            using (CurrentMailboxDiagnostics.BeginWork(row => inner = row))
            using (CurrentMailboxDiagnostics.Measure("lease-check")) await Task.Yield();
            using (CurrentMailboxDiagnostics.Measure("lease-check")) await Task.Yield();
            using (CurrentMailboxDiagnostics.Measure("DO-NOT-EXPORT")) await Task.Yield();
        }
        Assert.Equal(2, outer!.LeaseChecks);
        Assert.Equal(1, inner!.LeaseChecks);
        Assert.All(typeof(CurrentMailboxDiagnostics.WorkSummary).GetProperties(), property =>
            Assert.Equal(typeof(long), property.PropertyType));
        using (CurrentMailboxDiagnostics.BeginWork(_ => throw new IOException("Test sink interruption.")))
        using (CurrentMailboxDiagnostics.Measure("lease-check")) await Task.Yield();
    }

    [Fact]
    public void OriginWaitObservationsStayNumericAndBelongToTheirActualWorkScope()
    {
        CurrentMailboxDiagnostics.WorkSummary? outer = null, inner = null;
        using (CurrentMailboxDiagnostics.BeginWork(row => outer = row))
        {
            CurrentMailboxDiagnostics.RecordOriginWait(12.75);
            using (CurrentMailboxDiagnostics.BeginWork(row => inner = row))
                CurrentMailboxDiagnostics.RecordOriginWait(34.5);
            CurrentMailboxDiagnostics.RecordOriginWait(1.25);
        }
        Assert.Equal(2, outer!.OriginWaits);
        Assert.Equal(13, outer.OriginWaitMs);
        Assert.Equal(1, inner!.OriginWaits);
        Assert.Equal(34, inner.OriginWaitMs);
    }
}
