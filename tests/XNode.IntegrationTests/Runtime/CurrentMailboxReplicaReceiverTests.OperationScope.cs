using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxReplicaReceiverTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualPeerAndClientEnsureCurrentUseTheOwnedReadSegment(bool client)
    {
        await using var f = await Fixture.CreateAsync(localReplicaIndex: client ? 0 : 1);
        CurrentMailboxDiagnostics.WorkSummary? current = null;
        if (client)
            await f.Receiver.WithClientRequestAsync(f.Node.Frame, MailboxAuthenticatedOperation.Store,
                async (request, token) =>
                {
                    using (CurrentMailboxDiagnostics.BeginWork(result => current = result))
                        await request.EnsureCurrentAsync(token);
                    return true;
                }, default, f.Operations);
        else
            await f.Receiver.WithPeerAsync(f.Frame(MailboxPeerReplicationOperation.Store),
                MailboxPeerReplicationOperation.Store, MailboxPeerWireResponseReplicaV2.Recipient,
                async (operation, token) =>
                {
                    using (CurrentMailboxDiagnostics.BeginWork(result => current = result))
                        await operation.EnsureCurrentAsync(token);
                    return true;
                });
        Assert.Equal(2, current!.LeaseChecks);
        Assert.Empty(f.MutationFiles);
    }

    [Fact]
    public async Task CurrentOperationReadSegmentUsesTwoActualChecksAndClosesBeforeRequestWork()
    {
        await using var f = await Fixture.CreateAsync();
        await f.Receiver.ReceiveAsync(f.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store);
        MailboxCurrentCustodyReadScope? escaped = null;
        await f.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            CurrentMailboxDiagnostics.WorkSummary? recovery = null, regular = null;
            using (CurrentMailboxDiagnostics.BeginWork(result => recovery = result))
                await f.Operations.InitializeCurrentAsync(f.Node.Node, scope.Host, scope.Lease, token,
                    f.Node.Runtime.ValidateCurrentNativeRecovery, async (floors, ct) =>
                    {
                        f.PeerReplay.ValidateCurrentFloors(floors, ct);
                        await f.Mutations.ValidateCurrentRecoveryAsync(scope.Lease, ct, floors);
                    });
            using (CurrentMailboxDiagnostics.BeginWork(result => regular = result))
                await f.Operations.CheckCurrentOperationAsync(f.Node.Node, scope.Host, scope.Lease, token,
                    f.Node.Runtime.ValidateCurrentNativeRecovery, async (floors, read, ct) =>
                    {
                        escaped = read;
                        f.PeerReplay.ValidateCurrentFloors(floors, ct);
                        await f.Mutations.ValidateCurrentOperationAsync(read, ct, floors);
                    });
            Assert.Equal(4, recovery!.LeaseChecks);
            Assert.Equal(2, regular!.LeaseChecks);
            Assert.Throws<ObjectDisposedException>(() => escaped!.RequireActive());
            // A second actual read also proves the transferred native gate was
            // released before returning to request work.
            await f.Operations.CheckCurrentOperationAsync(f.Node.Node, scope.Host, scope.Lease, token,
                f.Node.Runtime.ValidateCurrentNativeRecovery,
                (floors, read, ct) => f.Mutations.ValidateCurrentOperationAsync(read, ct, floors));
            return true;
        });
    }

    [Theory]
    [InlineData("mutation-missing")]
    [InlineData("mutation-same-length")]
    [InlineData("blob-missing")]
    [InlineData("blob-same-length")]
    [InlineData("replay-missing")]
    [InlineData("ledger-same-length")]
    public async Task CurrentOperationReadSegmentRechecksAllActualRetainedCustody(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        await f.Receiver.ReceiveAsync(f.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store);
        var path = defect.StartsWith("mutation", StringComparison.Ordinal) ? Assert.Single(f.MutationFiles) :
            defect.StartsWith("blob", StringComparison.Ordinal) ? Assert.Single(Directory.GetFiles(
                Path.Combine(f.Node.DataRoot, "mailbox-v1"), "*.json", SearchOption.AllDirectories)) :
            defect.StartsWith("replay", StringComparison.Ordinal) ? Assert.Single(f.ReplayFiles) :
            Path.Combine(f.Node.DataRoot, "mailbox-client-intent", "operations.json");
        var original = File.ReadAllBytes(path);
        await f.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            Task<ulong> Read() => f.Operations.CheckCurrentOperationAsync(f.Node.Node, scope.Host, scope.Lease, token,
                f.Node.Runtime.ValidateCurrentNativeRecovery, async (floors, read, ct) =>
                {
                    f.PeerReplay.ValidateCurrentFloors(floors, ct);
                    await f.Mutations.ValidateCurrentOperationAsync(read, ct, floors);
                });
            await Read();
            if (defect.EndsWith("missing", StringComparison.Ordinal)) File.Delete(path);
            else
            {
                var changed = original.ToArray(); changed[0] ^= 1;
                File.WriteAllBytes(path, changed);
            }
            await Assert.ThrowsAsync<InvalidDataException>(Read);
            // Failed reads never repair or replace retained bytes.
            if (File.Exists(path)) Assert.Equal(original.Length, new FileInfo(path).Length);
            else Assert.False(File.Exists(path));
            File.WriteAllBytes(path, original);
            new MailboxStorageSecurity().SecureFile(path);
            await Read();
            return true;
        });
    }

    [Theory]
    [InlineData("source")]
    [InlineData("expiry")]
    [InlineData("floor")]
    [InlineData("cancel")]
    public async Task CurrentOperationReadSegmentFinalCallbackRejectsChangesAndReleasesOwners(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        using var cancel = new CancellationTokenSource();
        var floor = File.ReadAllBytes(f.Node.DepositFloorFile);
        await f.Node.Admission.WithGrantAsync(f.Node.ExactGrant, MailboxCapabilityDomain.Deposit, async (scope, token) =>
        {
            Task<ulong> Read(bool damage) => f.Operations.CheckCurrentOperationAsync(f.Node.Node, scope.Host,
                scope.Lease, cancel.Token, f.Node.Runtime.ValidateCurrentNativeRecovery, async (floors, read, ct) =>
                {
                    await f.Mutations.ValidateCurrentOperationAsync(read, ct, floors);
                    if (!damage) return;
                    if (defect == "source") f.Node.Signed.RejectProof = true;
                    else if (defect == "expiry") f.Node.Signed.Sample = 105;
                    else if (defect == "floor") File.Delete(f.Node.DepositFloorFile);
                    else cancel.Cancel();
                });
            Assert.NotNull(await Record.ExceptionAsync(() => Read(true)));
            f.Node.Signed.RejectProof = false; f.Node.Signed.Sample = 100;
            if (defect == "floor")
            {
                File.WriteAllBytes(f.Node.DepositFloorFile, floor);
                new MailboxStorageSecurity().SecureFile(f.Node.DepositFloorFile);
            }
            if (defect != "cancel") await Read(false);
            return true;
        });
        Assert.Empty(f.MutationFiles); Assert.Empty(f.ReplayFiles);
    }
}
