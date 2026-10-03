using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.Mailbox.Client;
using static XNode.IntegrationTests.Runtime.MailboxGrantRevocationStoreTests;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Signed producer -> both native MGR owners -> native replay/outcome.
/// Not activated ingress, peer quorum, receipt signing, or device evidence.</summary>
public sealed class CurrentMailboxAdmissionTests
{
    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store)]
    [InlineData(MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(MailboxAuthenticatedOperation.Ack)]
    public async Task SignedAdmissionAndExactTerminalReplaySurviveNativeReopen(MailboxAuthenticatedOperation operation)
    {
        await using var fixture = await Fixture.CreateAsync(operation);
        // This ceremony is generation zero: its author requires ID == identity
        // key. A genuinely rotated descriptor must separately qualify S02/S03.
        Assert.Equal(fixture.Node, fixture.Replicas[0].SigningPublicKey.ToArray());
        var first = await fixture.Admission.WithRequestAsync(fixture.Frame, operation, async (request, token) =>
        {
            Assert.Equal(MailboxAuthenticatedReplayDisposition.NewReserved, request.ReplayDisposition);
            Assert.True(await request.TryAcquireExecutionAsync(token));
            await request.ReserveOutcomeCapacityAsync(64, token);
            return await request.PersistTerminalAsync(MailboxClientTerminalOutcome.OperationConflict, token);
        });
        Assert.Equal(1, fixture.Replay.Diagnostics.CompletedCount);
        fixture.ReopenRuntime();
        var replay = await fixture.Admission.WithRequestAsync(fixture.Frame, operation, async (request, token) =>
        {
            Assert.Equal(MailboxAuthenticatedReplayDisposition.IdempotentCompleted, request.ReplayDisposition);
            Assert.False(await request.TryAcquireExecutionAsync(token));
            return request.RecoveredOutcome!;
        });
        Assert.Equal(first.CanonicalBytes.ToArray(), replay.CanonicalBytes.ToArray());
        Assert.Equal(1, fixture.Replay.Diagnostics.ScopeCount);
    }

    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store)]
    [InlineData(MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(MailboxAuthenticatedOperation.Ack)]
    public async Task WrongHolderCannotAdvanceTimeFloorOrReserveReplay(MailboxAuthenticatedOperation operation)
    {
        await using var fixture = await Fixture.CreateAsync(operation);
        var bad = fixture.Frame.ToArray();
        // Actual canonical presentation remains well formed; only its holder signature changes.
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(bad);
        var signature = decoded.Presentation.HolderSignature.ToArray(); signature[0] ^= 1;
        bad = MailboxAuthenticatedClientRequestCodec.Encode(decoded with
        { Presentation = decoded.Presentation with { HolderSignature = signature } });
        var calls = 0;
        await Assert.ThrowsAsync<MailboxAuthenticatedCapabilityException>(() => fixture.Admission.WithRequestAsync(bad,
            operation, (_, _) => { calls++; return ValueTask.FromResult(1); }).AsTask());
        Assert.Equal(0, calls);
        Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
        Assert.Equal(0UL, fixture.Replay.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);
        await fixture.Admission.WithRequestAsync(fixture.Frame, operation, (request, _) =>
        { Assert.Equal(MailboxAuthenticatedReplayDisposition.NewReserved, request.ReplayDisposition); return ValueTask.FromResult(1); });
        Assert.Equal(1, fixture.Replay.Diagnostics.PendingCount);
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task EitherMissingRoleFloorRejectsBeforeNativeReplay(MailboxCapabilityDomain missing)
    {
        await using var fixture = await Fixture.CreateAsync(MailboxAuthenticatedOperation.Store, missing);
        var calls = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Admission.WithRequestAsync(fixture.Frame,
            MailboxAuthenticatedOperation.Store, (_, _) => { calls++; return ValueTask.FromResult(1); }).AsTask());
        Assert.Equal(0, calls); Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
        Assert.Equal(0UL, fixture.Replay.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);
    }

    [Theory]
    [InlineData("expiry")]
    [InlineData("cancel")]
    [InlineData("source")]
    public async Task CallbackFailureSuppressesResultAndPreservesExactPendingOnReopen(string failure)
    {
        await using var fixture = await Fixture.CreateAsync(MailboxAuthenticatedOperation.Store);
        using var cancelled = new CancellationTokenSource();
        var requestTask = fixture.Admission.WithRequestAsync(fixture.Frame, MailboxAuthenticatedOperation.Store, (request, _) =>
        {
            Assert.Equal(MailboxAuthenticatedReplayDisposition.NewReserved, request.ReplayDisposition);
            if (failure == "expiry") fixture.Signed.Sample = 105;
            if (failure == "cancel") cancelled.Cancel();
            if (failure == "source") fixture.Signed.RejectProof = true;
            return ValueTask.FromResult(1);
        }, cancelled.Token).AsTask();
        Assert.NotNull(await Record.ExceptionAsync(() => requestTask));
        Assert.Equal(1, fixture.Replay.Diagnostics.PendingCount);
        fixture.Signed.Sample = 100; fixture.Signed.RejectProof = false;
        fixture.ReopenRuntime();
        await fixture.Admission.WithRequestAsync(fixture.Frame, MailboxAuthenticatedOperation.Store, (request, _) =>
        { Assert.Equal(MailboxAuthenticatedReplayDisposition.InFlight, request.ReplayDisposition); return ValueTask.FromResult(1); });
        Assert.Equal(1, fixture.Replay.Diagnostics.PendingCount);
    }

    [Fact]
    public async Task RevokedCompletedGrantCannotReleaseCachedOutcome()
    {
        await using var fixture = await Fixture.CreateAsync(MailboxAuthenticatedOperation.Store);
        await fixture.Admission.WithRequestAsync(fixture.Frame, MailboxAuthenticatedOperation.Store, async (request, token) =>
        {
            Assert.True(await request.TryAcquireExecutionAsync(token));
            await request.ReserveOutcomeCapacityAsync(64, token);
            return await request.PersistTerminalAsync(MailboxClientTerminalOutcome.OperationConflict, token);
        });
        var prior = Snapshot(fixture.Signed);
        await fixture.Deposit.AdvanceAsync(fixture.Host, Snapshot(fixture.Signed, generation: 2, prior: prior,
            serials: [MailboxAuthenticatedCapabilityCodec.DecodeGrant(fixture.ExactGrant).Serial.ToArray()]));
        var calls = 0;
        Assert.NotNull(await Record.ExceptionAsync(() => fixture.Admission.WithRequestAsync(fixture.Frame,
            MailboxAuthenticatedOperation.Store, (_, _) => { calls++; return ValueTask.FromResult(1); }).AsTask()));
        Assert.Equal(0, calls); Assert.Equal(1, fixture.Replay.Diagnostics.CompletedCount);
    }

    [Fact]
    public async Task EscapedRequestCannotUseAuthorityOrNativeOutcomes()
    {
        await using var fixture = await Fixture.CreateAsync(MailboxAuthenticatedOperation.Store);
        CurrentMailboxAdmission.Request? escaped = null;
        await fixture.Admission.WithRequestAsync(fixture.Frame, MailboxAuthenticatedOperation.Store, (request, _) =>
        { escaped = request; return ValueTask.FromResult(1); });
        await Assert.ThrowsAsync<InvalidOperationException>(() => escaped!.EnsureCurrentAsync().AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(() => escaped!.ReserveOutcomeCapacityAsync(64).AsTask());
        Assert.Throws<InvalidOperationException>(() => escaped!.RecoveredOutcome);
        Assert.Equal(1, fixture.Replay.Diagnostics.PendingCount);
    }

    [Fact]
    public async Task ForeignSigningKeyCannotStandInForSelectedNodeId()
    {
        await using var fixture = await Fixture.CreateAsync(MailboxAuthenticatedOperation.Store);
        var foreignKey = MailboxAuthenticatedCapabilityCodec.DecodeGrant(fixture.ExactGrant).IssuerPublicKey;
        Assert.DoesNotContain(fixture.Replicas, replica => replica.NodeId.Span.SequenceEqual(foreignKey.Span));
        var wrong = new CurrentMailboxAdmission(fixture.Signed, fixture.Signed,
            foreignKey, fixture.Deposit, fixture.Retrieve, fixture.Runtime);
        await Assert.ThrowsAsync<CryptographicException>(() => wrong.WithRequestAsync(fixture.Frame,
            MailboxAuthenticatedOperation.Store, (_, _) => ValueTask.FromResult(1)).AsTask());
        Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("placement")]
    [InlineData("epoch")]
    public async Task CrossFedBodyCannotReserveNativeReplay(string mismatch)
    {
        await using var fixture = await Fixture.CreateAsync(MailboxAuthenticatedOperation.Store);
        var frame = mismatch == "operation" ? fixture.Frame :
            Request(fixture.Host.SelectionEpoch + (mismatch == "epoch" ? 1UL : 0UL),
                MailboxAuthenticatedOperation.Store, fixture.ExactGrant, mismatch == "placement" ? (byte)0x61 : (byte)0x55);
        var operation = mismatch == "operation" ? MailboxAuthenticatedOperation.Ack : MailboxAuthenticatedOperation.Store;
        var calls = 0;
        Assert.NotNull(await Record.ExceptionAsync(() => fixture.Admission.WithRequestAsync(frame, operation,
            (_, _) => { calls++; return ValueTask.FromResult(1); }).AsTask()));
        Assert.Equal(0, calls); Assert.Equal(0, fixture.Replay.Diagnostics.ScopeCount);
        Assert.Equal(0UL, fixture.Replay.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);
    }

    [Fact]
    public async Task FloorSuccessorCannotCommitInsideBoundedOperation()
    {
        await using var fixture = await Fixture.CreateAsync(MailboxAuthenticatedOperation.Store);
        var next = Snapshot(fixture.Signed, generation: 2, prior: Snapshot(fixture.Signed), serials: [Bytes(16, 0x51)]);
        Task? advance = null;
        await fixture.Admission.WithRequestAsync(fixture.Frame, MailboxAuthenticatedOperation.Store, async (request, token) =>
        {
            advance = fixture.Deposit.AdvanceAsync(fixture.Host, next).AsTask();
            Assert.False(advance.IsCompleted);
            await request.EnsureCurrentAsync(token);
            Assert.False(advance.IsCompleted);
            return 1;
        });
        await advance!.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(next, (await fixture.Deposit.ReadProtectedAsync()).ToArray());
        Assert.Equal(1, fixture.Replay.Diagnostics.PendingCount);
    }

    [Fact]
    public async Task CallerBufferMutationDuringAuthorityReadDoesNotChangeCapturedRequest()
    {
        await using var fixture = await Fixture.CreateAsync(MailboxAuthenticatedOperation.Store);
        var caller = fixture.Frame.ToArray();
        var source = new CallbackSource(fixture.Signed, () => Array.Fill(caller, (byte)0));
        var admission = new CurrentMailboxAdmission(source, fixture.Signed, fixture.Node,
            fixture.Deposit, fixture.Retrieve, fixture.Runtime);
        await admission.WithRequestAsync(caller, MailboxAuthenticatedOperation.Store, (request, _) =>
        { Assert.Equal(MailboxAuthenticatedReplayDisposition.NewReserved, request.ReplayDisposition); return ValueTask.FromResult(1); });
        Assert.Equal(1, fixture.Replay.Diagnostics.PendingCount);
        await fixture.Admission.WithRequestAsync(fixture.Frame, MailboxAuthenticatedOperation.Store, (request, _) =>
        { Assert.Equal(MailboxAuthenticatedReplayDisposition.InFlight, request.ReplayDisposition); return ValueTask.FromResult(1); });
    }

    private sealed class CallbackSource(IDeepIdV2ContactStoreAuthoritySource inner, Action callback)
        : IDeepIdV2ContactStoreAuthoritySource
    {
        public ValueTask<DeepIdV2ContactStoreAuthority> ReadPublicationAuthorityAsync(CancellationToken token)
        { callback(); return inner.ReadPublicationAuthorityAsync(token); }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        internal DeepIdV2PublicationAuthorityFixture Signed = null!;
        private Custody depositFiles = null!, retrieveFiles = null!;
        internal FileMailboxGrantRevocationStore Deposit = null!, Retrieve = null!;
        internal VerifiedMailboxHostAuthorityV2 Host = null!;
        internal IReadOnlyList<VerifiedMailboxReplicaV2> Replicas = null!;
        internal byte[] Node = [], ExactGrant = [], Frame = [];
        internal DurableMailboxCapabilityReplayJournal Replay = null!;
        private MailboxClientCanonicalOutcomeStore outcomes = null!;
        internal MailboxAuthenticatedCapabilityRuntime Runtime = null!;
        internal CurrentMailboxAdmission Admission = null!;

        internal static async Task<Fixture> CreateAsync(MailboxAuthenticatedOperation operation,
            MailboxCapabilityDomain? missing = null)
        {
            var f = new Fixture { Signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync() };
            f.Host = await MailboxGrantRevocationStoreTests.Host(f.Signed);
            var role = operation == MailboxAuthenticatedOperation.Store ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve;
            f.ExactGrant = Grant(f.Signed, f.Host, role, 0x51);
            f.Replicas = await f.Host.ResolveGrantReplicasAsync(f.ExactGrant);
            f.Node = f.Replicas[0].NodeId.ToArray();
            f.depositFiles = new(f.Signed, MailboxCapabilityDomain.Deposit, f.Node);
            f.retrieveFiles = new(f.Signed, MailboxCapabilityDomain.Retrieve, f.Node);
            f.Deposit = f.depositFiles.Open(); f.Retrieve = f.retrieveFiles.Open();
            if (missing != MailboxCapabilityDomain.Deposit) await f.Deposit.EnrollAsync(f.Host, Snapshot(f.Signed));
            if (missing != MailboxCapabilityDomain.Retrieve) await f.Retrieve.EnrollAsync(f.Host, Snapshot(f.Signed, MailboxCapabilityDomain.Retrieve));
            f.Frame = Request(f.Host.SelectionEpoch, operation, f.ExactGrant);
            f.ReopenRuntime(); return f;
        }
        internal void ReopenRuntime()
        {
            outcomes?.Dispose(); Replay?.Dispose();
            Replay = new(depositFiles.Data); outcomes = new(depositFiles.Data);
            Runtime = new(new RejectAllMailboxCapabilityAuthoritySource(), new RejectAllMailboxCapabilityRevocationPolicy(),
                Replay, outcomes, new NoUtcClock());
            Admission = new(Signed, Signed, Node, Deposit, Retrieve, Runtime);
        }
        public async ValueTask DisposeAsync()
        {
            outcomes.Dispose(); Replay.Dispose();
            await Retrieve.DisposeAsync(); await Deposit.DisposeAsync();
            retrieveFiles.Dispose(); depositFiles.Dispose(); Signed.Dispose();
        }
    }
    private sealed class NoUtcClock : IClock
    { public DateTimeOffset UtcNow => throw new InvalidOperationException("Current admission must not read host UTC."); }

    private static byte[] Request(ulong epoch, MailboxAuthenticatedOperation operation, byte[] exactGrant, byte placementMarker = 0x55)
    {
        var mailbox = new BlindedMailboxId(Bytes(32, 0x54)); var placement = new BlindedPlacementId(Bytes(32, placementMarker));
        var id = Bytes(16, 0x58);
        var binding = operation switch
        {
            MailboxAuthenticatedOperation.Store => MailboxAuthenticatedRequestTranscript.ForStore(new()
            {
                Epoch = epoch, MailboxId = mailbox, PlacementId = placement, OperationId = id,
                DeduplicationDigest = Bytes(32, 0x59), CreatedAtUnixSeconds = 1_090,
                ExpiresAtUnixSeconds = 1_150, Ciphertext = Bytes(64, 0x60)
            }),
            MailboxAuthenticatedOperation.Retrieve => MailboxAuthenticatedRequestTranscript.ForRetrieve(epoch, id, mailbox, placement, 0, 10, []),
            MailboxAuthenticatedOperation.Ack => MailboxAuthenticatedRequestTranscript.ForAck(epoch, id, mailbox, placement, true, [],
                [new() { Cursor = 1, EnvelopeDigest = Bytes(32, 0x59) }]),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
        var crypto = new SodiumMailboxCapabilityCrypto();
        return MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding, Presentation = crypto.SignPresentation(MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactGrant), binding, 1, Bytes(32, 0x57))
        });
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
}
