using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Extensions.Logging;
using Sodium;
using XNode.Core.Mailbox.Client;
using static XNode.IntegrationTests.Runtime.MailboxGrantRevocationStoreTests;

namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxRevocationRefreshTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualHttpConsumerAndNativeRefreshResumeBeyondBudgetWithoutEnrollmentOrExpiredAdmission(bool observed)
    {
        await using var f = await CurrentMailboxAdmissionTests.Fixture.CreateAsync(MailboxAuthenticatedOperation.Retrieve);
        var old = (await f.Deposit.ReadProtectedAsync()).ToArray();
        var snapshots = new Dictionary<(MailboxCapabilityDomain, ulong), byte[]> { [(MailboxCapabilityDomain.Deposit, 1)] = old };
        for (ulong generation = 2; generation <= 71; generation++)
        { var next = Snapshot(f.Signed, generation: generation, prior: old, expires: generation == 71 ? 1_140UL : 1_120UL); snapshots[(MailboxCapabilityDomain.Deposit, generation)] = next; old = next; }
        snapshots[(MailboxCapabilityDomain.Retrieve, 2)] = Snapshot(f.Signed, MailboxCapabilityDomain.Retrieve, 2,
            (await f.Retrieve.ReadProtectedAsync()).ToArray(), expires: 1_140);
        f.Signed.Sample = 115; // Both initial floors expired; complete host remains current.
        using var files = observed ? new DeepIdV2NetworkPlacementRuntimeTests.Assets(f.Signed) : null;
        using var networkFloor = files?.OpenFloor();
        var source = files?.Source(networkFloor!);
        if (source is not null)
        {
            var local = OnionPathCandidateSnapshotFactory.Create(f.Signed.NetworkContext).Candidates.Single(candidate =>
                candidate.NodeId.Span.SequenceEqual(f.Node));
            await source.ReadCurrentAsync(local.RouterOwnerId,
                ScalarMult.Base(f.Signed.TestOnionScalar(local.NodeId.Span)), default, default);
        }
        CurrentMailboxAdmission CurrentAdmission() => source is null ? f.Admission :
            new(source, f.Signed, f.Node, f.Deposit, f.Retrieve, f.Runtime);
        var admission = CurrentAdmission();
        using var handler = new Records(snapshots); using var client = new HttpClient(handler);
        var artifacts = new HttpsMailboxGrantRevocationArtifactSource(client, "https://registry.example/");
        await Assert.ThrowsAsync<IOException>(() => admission.RefreshRevocationsAsync(artifacts, default).AsTask());
        Assert.Equal(65UL, MailboxGrantRevocationV1Codec.Decode((await f.Deposit.ReadProtectedAsync()).Span).Generation);
        var callbacks = 0;
        await Assert.ThrowsAsync<CryptographicException>(() => admission.WithHostAsync((_, _) =>
        { callbacks++; return ValueTask.FromResult(true); }).AsTask());
        Assert.Equal(0, callbacks);
        f.ReopenRuntime(); // No transient cursor authorizes the next batch.
        admission = CurrentAdmission();
        await admission.RefreshRevocationsAsync(artifacts, default);
        Assert.Equal(71UL, MailboxGrantRevocationV1Codec.Decode((await f.Deposit.ReadProtectedAsync()).Span).Generation);
        Assert.Equal(snapshots[(MailboxCapabilityDomain.Retrieve, 2)], (await f.Retrieve.ReadProtectedAsync()).ToArray());
        await admission.WithHostAsync(async (scope, token) => { _ = await scope.Lease.CheckAsync(token); return true; });
        var calls = handler.Calls;
        await admission.RefreshRevocationsAsync(artifacts, default);
        Assert.Equal(calls + 2, handler.Calls); // Exact replay reads only one target per role.
        if (observed)
        {
            Assert.Equal(1, f.Signed.ProofReads);
            Assert.True(f.Signed.ObservationChecks > 260);
        }
    }

    [Fact]
    public async Task MissingProtectedRoleRejectsBeforeTransportAndNeverAutoEnrolls()
    {
        await using var f = await CurrentMailboxAdmissionTests.Fixture.CreateAsync(MailboxAuthenticatedOperation.Retrieve,
            missing: MailboxCapabilityDomain.Deposit);
        using var handler = new Records([]); using var client = new HttpClient(handler);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Admission.RefreshRevocationsAsync(
            new HttpsMailboxGrantRevocationArtifactSource(client, "https://registry.example/"), default).AsTask());
        Assert.Equal(0, handler.Calls);
        Assert.False(File.Exists(f.DepositFloorFile));
    }

    [Fact]
    public async Task InvalidTargetSignatureCannotChangeNativeFloor()
    {
        await using var f = await CurrentMailboxAdmissionTests.Fixture.CreateAsync(MailboxAuthenticatedOperation.Retrieve);
        var saved = (await f.Deposit.ReadProtectedAsync()).ToArray();
        var bad = Snapshot(f.Signed, generation: 2, prior: saved); bad[^1] ^= 1;
        using var handler = new Records(new() { [(MailboxCapabilityDomain.Deposit, 2)] = bad }); using var client = new HttpClient(handler);
        await Assert.ThrowsAsync<CryptographicException>(() => f.Admission.RefreshRevocationsAsync(
            new HttpsMailboxGrantRevocationArtifactSource(client, "https://registry.example/"), default).AsTask());
        Assert.Equal(1, handler.Calls); Assert.Equal(saved, (await f.Deposit.ReadProtectedAsync()).ToArray());
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(1_048_577UL)]
    [InlineData(ulong.MaxValue)]
    public async Task GenerationOutsideControlBoundsRejectsBeforeHttp(ulong generation)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var exact = Snapshot(signed);
        using var handler = new Records([]); using var client = new HttpClient(handler);
        var source = new HttpsMailboxGrantRevocationArtifactSource(client, "https://registry.example/");
        await Assert.ThrowsAsync<ArgumentException>(() => source.FetchAsync(DeepIdV2PublicationAuthorityFixture.Network,
            MailboxGrantRevocationV1Codec.Decode(exact).Field(2), MailboxCapabilityDomain.Deposit, generation, default).AsTask());
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task NetworkFailureKeepsWorkerAliveWithoutChangingEitherFloor()
    {
        await using var f = await CurrentMailboxAdmissionTests.Fixture.CreateAsync(MailboxAuthenticatedOperation.Retrieve);
        var deposit = (await f.Deposit.ReadProtectedAsync()).ToArray();
        var retrieve = (await f.Retrieve.ReadProtectedAsync()).ToArray();
        using var handler = new Records([]) { Fault = "network" }; using var client = new HttpClient(handler);
        var logger = new ErrorSignal();
        using var worker = new CurrentMailboxRevocationRefreshWorker(f.Admission,
            new HttpsMailboxGrantRevocationArtifactSource(client, "https://registry.example/"), logger);
        await worker.StartAsync(default);
        Assert.Equal("Mailbox control refresh unavailable (HttpRequestException).",
            await logger.Seen.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.False(worker.ExecuteTask!.IsCompleted);
        Assert.Equal(1, handler.Calls);
        Assert.Equal(deposit, (await f.Deposit.ReadProtectedAsync()).ToArray());
        Assert.Equal(retrieve, (await f.Retrieve.ReadProtectedAsync()).ToArray());
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StopAsync(stop.Token);
    }

    private sealed class ErrorSignal : ILogger<CurrentMailboxRevocationRefreshWorker>
    {
        internal TaskCompletionSource<string> Seen { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        { Assert.Null(exception); Seen.TrySetResult(formatter(state, exception)); }
    }

    [Theory]
    [InlineData("redirect")]
    [InlineData("wrong-media")]
    [InlineData("parameters")]
    [InlineData("encoding")]
    [InlineData("cache")]
    [InlineData("nosniff")]
    [InlineData("oversize")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public async Task HttpFramingRejectsBeforeAnyNativeUse(string fault)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var exact = Snapshot(signed);
        using var handler = new Records(new() { [(MailboxCapabilityDomain.Deposit, 1)] = exact }) { Fault = fault };
        using var client = new HttpClient(handler);
        var source = new HttpsMailboxGrantRevocationArtifactSource(client, "https://registry.example/");
        Task Fetch() => source.FetchAsync(DeepIdV2PublicationAuthorityFixture.Network,
            MailboxGrantRevocationV1Codec.Decode(exact).Field(2), MailboxCapabilityDomain.Deposit, 1, default).AsTask();
        if (fault == "truncated") await Assert.ThrowsAsync<EndOfStreamException>(Fetch);
        else await Assert.ThrowsAsync<InvalidDataException>(Fetch);
        Assert.Equal(1, handler.Calls);
    }

    private sealed class Records(Dictionary<(MailboxCapabilityDomain Role, ulong Generation), byte[]> records) : HttpMessageHandler
    {
        internal int Calls;
        internal string? Fault;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++;
            if (Fault == "network") throw new HttpRequestException();
            Assert.Equal(HttpMethod.Get, request.Method); Assert.Null(request.Content);
            Assert.Equal(HttpsMailboxGrantRevocationArtifactSource.MediaType, Assert.Single(request.Headers.Accept).MediaType);
            var parts = request.RequestUri!.AbsolutePath.Split('/');
            var role = (MailboxCapabilityDomain)byte.Parse(parts[^2], System.Globalization.CultureInfo.InvariantCulture);
            var generation = parts[^1] == "latest" ? records.Keys.Where(key => key.Role == role).Max(key => key.Generation) :
                ulong.Parse(parts[^1], System.Globalization.CultureInfo.InvariantCulture);
            var exact = records[(role, generation)];
            var body = Fault == "trailing" ? exact.Concat(new byte[] { 1 }).ToArray() :
                Fault == "truncated" ? exact[..^1] : exact;
            var response = new HttpResponseMessage(HttpStatusCode.OK) { RequestMessage = request, Content = new ByteArrayContent(body) };
            response.Content.Headers.ContentType = new(Fault == "wrong-media" ? "application/json" : HttpsMailboxGrantRevocationArtifactSource.MediaType);
            response.Content.Headers.ContentLength = Fault == "oversize" ? 65_864 : exact.Length;
            response.Headers.CacheControl = new() { NoStore = Fault != "cache" };
            if (Fault != "nosniff") response.Headers.Add("X-Content-Type-Options", "nosniff");
            if (Fault == "parameters") response.Content.Headers.ContentType.Parameters.Add(new("charset", "utf-8"));
            if (Fault == "encoding") response.Content.Headers.ContentEncoding.Add("gzip");
            if (Fault == "redirect") response.RequestMessage = new(HttpMethod.Get, "https://other.example/");
            return Task.FromResult(response);
        }
    }
}
