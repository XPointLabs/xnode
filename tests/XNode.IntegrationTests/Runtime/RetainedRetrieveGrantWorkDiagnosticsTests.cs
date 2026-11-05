using System.Diagnostics.Metrics;
using System.Collections.Concurrent;
using Deep.Protocol.ContactV2;
using Microsoft.Extensions.DependencyInjection;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class Did2ContactServiceCompositionTests
{
    [Fact]
    public async Task PublicRetainedRetrieveMeasuresClosedPhasesWithoutChangingTheIssuerWinner()
    {
        await using var scope = await RetainedPeerScope.CreateAsync(); await scope.PublishAsync();
        using var holder = new GrantSigner(0x52);
        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        var phases = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);
        var durations = new ConcurrentBag<double>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, observer) =>
        {
            if (instrument.Meter.Name == CurrentMailboxDiagnostics.MeterName && instrument.Name == "phase.duration")
                observer.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<double>((_, duration, tags, _) =>
        {
            foreach (var tag in tags)
                if (tag.Key == "phase" && tag.Value is string phase && phase.StartsWith("retained-", StringComparison.Ordinal))
                {
                    durations.Add(duration);
                    phases.AddOrUpdate(phase, 1, (_, count) => count + 1);
                }
        });
        listener.Start();
        var exact = await scope.Providers[0].GetRequiredService<IContactServiceOpaqueDispatcher>()
            .DispatchAsync(ContactServiceOperation.AcquireMailboxGrant, request.ExactXmg2, default);
        Assert.Equal(510, exact.Length);
        Assert.Equal(1, scope.State.GrantCalls); Assert.Equal(1, scope.State.GrantSignatures);
        Assert.Equal(scope.State.GrantWinners.Values.Single(), exact.ToArray());
        Assert.All(durations, duration => Assert.InRange(duration, 0, 3_600_000));
        Assert.Equal(new[] {
            "retained-gate", "retained-host", "retained-issuer", "retained-local-receipt", "retained-local-scope",
            "retained-placement", "retained-remote-read", "retained-remote-receipt", "retained-request",
            "retained-response", "retained-source"
        }, phases.Keys.Order(StringComparer.Ordinal));
    }
}

public sealed class RetainedRetrieveGrantWorkDiagnosticsTests
{
    [Fact]
    public void ThrowingMetricSinkCannotReplaceCancellationOrCountDisposalTwice()
    {
        using var listener = new MeterListener();
        var throwForThisFlow = new AsyncLocal<bool>(); var sinkCalls = 0;
        listener.InstrumentPublished = (instrument, observer) =>
        {
            if (instrument.Meter.Name == CurrentMailboxDiagnostics.MeterName && instrument.Name == "phase.duration")
                observer.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<double>((_, _, _, _) =>
        {
            if (!throwForThisFlow.Value) return;
            Interlocked.Increment(ref sinkCalls);
            throw new IOException("Test-owned metric sink failure.");
        });
        listener.Start();
        CurrentMailboxDiagnostics.WorkSummary? summary = null;
        var original = new OperationCanceledException();
        using (CurrentMailboxDiagnostics.BeginWork(value => summary = value))
        {
            throwForThisFlow.Value = true;
            var measurement = Assert.IsAssignableFrom<IDisposable>(CurrentMailboxDiagnostics.Measure("retained-source"));
            var actual = Assert.Throws<OperationCanceledException>((Action)(() =>
            {
                using (measurement) throw original;
            }));
            Assert.Same(original, actual);
            measurement.Dispose();
            throwForThisFlow.Value = false;
        }
        Assert.NotNull(summary); Assert.Equal(1, summary.RetainedSourceCalls); Assert.Equal(1, sinkCalls);
    }

    [Fact]
    public async Task ConcurrentWorkKeepsItsOwnSourceReadCounts()
    {
        static async Task<CurrentMailboxDiagnostics.WorkSummary> CaptureAsync(int count)
        {
            CurrentMailboxDiagnostics.WorkSummary? summary = null;
            using (CurrentMailboxDiagnostics.BeginWork(value => summary = value))
                await Task.WhenAll(Enumerable.Range(0, count).Select(_ => Task.Run(() =>
                {
                    using var measured = CurrentMailboxDiagnostics.Measure("retained-source");
                })));
            return Assert.IsType<CurrentMailboxDiagnostics.WorkSummary>(summary);
        }
        var results = await Task.WhenAll(CaptureAsync(1), CaptureAsync(3));
        Assert.Equal(1, results[0].RetainedSourceCalls); Assert.Equal(3, results[1].RetainedSourceCalls);
    }
}
