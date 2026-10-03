using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

/// <summary>
/// Actual DID2 proof/publication/journals plus production HTTP peer client,
/// endpoint authentication/replay and exact wire codec in an in-process handler.
/// The handler is not a real socket/TLS/SPKI or physical ONION/device test.
/// </summary>
public sealed class DeepIdV2PreKeyClaimRuntimeTests
{
    [Fact]
    public async Task ConcurrentExhaustionHonorsSignedLastResortLimitAndExactReplayAfterRestart()
    {
        using var harness = await Harness.CreateAsync(lastResortReuseLimit: 2);
        var requests = Enumerable.Range(0, harness.Signed.Publication.OneTimeMembers.Count)
            .Select(index => harness.Request(checked((byte)(0x10 + index)))).ToArray();
        var wires = await Task.WhenAll(requests.Select((request, index) =>
            harness.Claims[index % 2].ReceiveTerminalAsync(request.CanonicalBytes, default).AsTask()));
        var claims = requests.Select((request, index) => harness.Verify(request, wires[index])).ToArray();
        Assert.Equal(requests.Length, claims.Select(result => Convert.ToHexString(result.Field(17).Span)).Distinct().Count());
        Assert.All(claims, result =>
        {
            Assert.NotEqual(new byte[32], result.Field(17).ToArray());
            Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(result.Field(23).Span));
            Assert.Equal(160, result.Field(28).Length);
        });
        Assert.Equal(Enumerable.Range(1, requests.Length).Select(value => (ulong)value),
            claims.Select(result => U64(result.Field(24).Span)).Order());

        var fallbackRequests = new[] { harness.Request(0xd0), harness.Request(0xd1) };
        var fallbackWires = new ReadOnlyMemory<byte>[2];
        for (var index = 0; index < 2; index++)
        {
            fallbackWires[index] = await harness.Claims[index].ReceiveTerminalAsync(fallbackRequests[index].CanonicalBytes, default);
            var fallback = harness.Verify(fallbackRequests[index], fallbackWires[index]);
            Assert.Equal(harness.Signed.Publication.LastResortMember.CanonicalBytes.ToArray(), fallback.Field(16).ToArray());
            Assert.Equal(harness.Signed.Publication.Manifest.CanonicalBytes.ToArray(), fallback.Field(26).ToArray());
            Assert.Equal(new byte[32], fallback.Field(17).ToArray());
            Assert.Equal(checked((ushort)(index + 1)), BinaryPrimitives.ReadUInt16BigEndian(fallback.Field(23).Span));
            Assert.Equal((ulong)(requests.Length + index + 1), U64(fallback.Field(24).Span));
            Assert.Equal(ushort.MaxValue, BinaryPrimitives.ReadUInt16BigEndian(fallback.Field(27).Span));
            Assert.Empty(fallback.Field(28).ToArray());
        }
        var exhaustedRequest = harness.Request(0xd2);
        var before = ClaimSnapshotHashes(harness.Root);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var refused = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[attempt].ReceiveTerminalAsync(
                exhaustedRequest.CanonicalBytes, default)).Span, exhaustedRequest.CanonicalBytes.Span);
            Assert.Equal(Xpc1V2Status.PreKeysUnavailable, refused.Status);
            Assert.Equal(Xpc1V2MutationOutcome.None, refused.MutationOutcome);
            Assert.Empty(refused.Field(16).ToArray());
            Assert.Equal(before, ClaimSnapshotHashes(harness.Root));
            harness.Reopen();
        }
        for (var index = 0; index < 2; index++)
            Assert.Equal(fallbackWires[index].ToArray(), (await harness.Claims[1 - index].ReceiveTerminalAsync(
                fallbackRequests[index].CanonicalBytes, default)).ToArray());
        Assert.Equal(wires[0].ToArray(), (await harness.Claims[1].ReceiveTerminalAsync(
            requests[0].CanonicalBytes, default)).ToArray());
        Assert.Equal(before, ClaimSnapshotHashes(harness.Root));
    }

    private static string[] ClaimSnapshotHashes(string root) =>
        Directory.GetFiles(root, "claims.state", SearchOption.AllDirectories).Order()
            .Select(path => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)))).ToArray();

    [Theory]
    [InlineData((byte)ContactReplicaRpcOperation.PrepareDid2PreKeyClaim)]
    [InlineData((byte)ContactReplicaRpcOperation.CompleteDid2PreKeyClaim)]
    public async Task LostLastResortResponseBlocksNewOperationUntilExactReconciliation(byte lostOperation)
    {
        using var harness = await Harness.CreateAsync();
        for (var index = 0; index < harness.Signed.Publication.OneTimeMembers.Count; index++)
        {
            var request = harness.Request(checked((byte)(0x10 + index)));
            _ = harness.Verify(request, await harness.Claims[index % 2].ReceiveTerminalAsync(request.CanonicalBytes, default));
        }
        var pending = harness.Request(0xd0);
        harness.LoseNextResponse = (ContactReplicaRpcOperation)lostOperation;
        var lost = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[0].ReceiveTerminalAsync(
            pending.CanonicalBytes, default)).Span, pending.CanonicalBytes.Span);
        Assert.Equal(Xpc1V2Status.OutcomeUnknown, lost.Status);
        Assert.Equal(Xpc1V2MutationOutcome.OutcomeUnknown, lost.MutationOutcome);
        harness.Reopen();
        var next = harness.Request(0xd1);
        var before = ClaimSnapshotHashes(harness.Root);
        var blocked = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[1].ReceiveTerminalAsync(
            next.CanonicalBytes, default)).Span, next.CanonicalBytes.Span);
        Assert.Equal(Xpc1V2Status.OutcomeUnknown, blocked.Status);
        Assert.Equal(Xpc1V2MutationOutcome.OutcomeUnknown, blocked.MutationOutcome);
        Assert.Equal(before, ClaimSnapshotHashes(harness.Root));

        var resumedWire = await harness.Claims[1].ReceiveTerminalAsync(pending.CanonicalBytes, default);
        var resumed = harness.Verify(pending, resumedWire);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(resumed.Field(23).Span));
        Assert.Equal(33UL, U64(resumed.Field(24).Span));
        Assert.Equal(harness.Signed.Publication.LastResortMember.CanonicalBytes.ToArray(), resumed.Field(16).ToArray());
        harness.Reopen();
        Assert.Equal(resumedWire.ToArray(), (await harness.Claims[0].ReceiveTerminalAsync(pending.CanonicalBytes, default)).ToArray());
        var completed = ClaimSnapshotHashes(harness.Root);
        var refused = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[0].ReceiveTerminalAsync(
            next.CanonicalBytes, default)).Span, next.CanonicalBytes.Span);
        Assert.Equal(Xpc1V2Status.PreKeysUnavailable, refused.Status);
        Assert.Equal(Xpc1V2MutationOutcome.None, refused.MutationOutcome);
        Assert.Equal(completed, ClaimSnapshotHashes(harness.Root));
    }

    [Fact]
    public async Task BothAnonymousExits_UseOneCoordinatorAndDistinctDurableKeys_ThenRestartReplay()
    {
        using var harness = await Harness.CreateAsync();
        var first = harness.Request(0xb0); var second = harness.Request(0xb1);
        var results = await Task.WhenAll(
            harness.Claims[0].ReceiveTerminalAsync(first.CanonicalBytes, default).AsTask(),
            harness.Claims[1].ReceiveTerminalAsync(second.CanonicalBytes, default).AsTask());
        var a = harness.Verify(first, results[0]); var b = harness.Verify(second, results[1]);
        AssertOneTimeSelection(harness, a);
        AssertOneTimeSelection(harness, b);
        Assert.NotEqual(a.Field(17).ToArray(), b.Field(17).ToArray());
        Assert.Equal(new ulong[] { 1, 2 }, new[] { U64(a.Field(24).Span), U64(b.Field(24).Span) }.Order());
        Assert.True(harness.HttpCalls >= 7);
        harness.Reopen();
        Assert.Equal(results[0].ToArray(), (await harness.Claims[1].ReceiveTerminalAsync(first.CanonicalBytes, default)).ToArray());
        Assert.Equal(results[1].ToArray(), (await harness.Claims[0].ReceiveTerminalAsync(second.CanonicalBytes, default)).ToArray());
    }

    [Theory]
    [InlineData((byte)ContactReplicaRpcOperation.PrepareDid2PreKeyClaim)]
    [InlineData((byte)ContactReplicaRpcOperation.CompleteDid2PreKeyClaim)]
    public async Task LostAuthenticatedResponse_ExactRetryAfterRestartDoesNotSelectAnotherKey(byte lostOperation)
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        harness.LoseNextResponse = (ContactReplicaRpcOperation)lostOperation;
        var unknown = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[0].ReceiveTerminalAsync(
            request.CanonicalBytes, default)).Span, request.CanonicalBytes.Span);
        Assert.Equal(Xpc1V2Status.OutcomeUnknown, unknown.Status);
        Assert.Equal(Xpc1V2MutationOutcome.OutcomeUnknown, unknown.MutationOutcome);
        var originalKey = harness.Signed.Publication.OneTimeMembers[0].OneTimePrekeyId.ToArray();
        harness.Reopen();
        var resumed = await harness.Claims[1].ReceiveTerminalAsync(request.CanonicalBytes, default);
        var verified = harness.Verify(request, resumed);
        Assert.Equal(originalKey, verified.Field(17).ToArray());
        Assert.Equal(1UL, U64(verified.Field(24).Span));
        Assert.Equal(resumed.ToArray(), (await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default)).ToArray());
        var next = harness.Request(0xb1);
        var nextResult = harness.Verify(next, await harness.Claims[0].ReceiveTerminalAsync(next.CanonicalBytes, default));
        Assert.Equal(2UL, U64(nextResult.Field(24).Span));
        Assert.Equal(harness.Signed.Publication.OneTimeMembers[1].OneTimePrekeyId.ToArray(), nextResult.Field(17).ToArray());
    }

    [Theory]
    [InlineData("ephemeral")]
    [InlineData("bundle")]
    [InlineData("issued")]
    [InlineData("expiry")]
    public async Task ChangedRequestForSameOperation_ReturnsConflictWithoutAnotherReservation(string mutation)
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        var original = await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default);
        var accepted = harness.Verify(request, original);
        AssertOneTimeSelection(harness, accepted);
        Assert.Equal(1UL, U64(accepted.Field(24).Span));
        var changed = ChangeRequest(request, mutation);
        Assert.Equal(request.Field(2).ToArray(), changed.Field(2).ToArray());
        Assert.NotEqual(request.RequestHash.ToArray(), changed.RequestHash.ToArray());
        var before = ClaimSnapshotHashes(harness.Root);
        byte[]? conflictWire = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var wire = await harness.Claims[1 - attempt].ReceiveTerminalAsync(changed.CanonicalBytes, default);
            var conflict = DeepIdV2PreKeyClaimResultCodec.Decode(wire.Span, changed.CanonicalBytes.Span);
            Assert.Equal(Xpc1V2Status.Conflict, conflict.Status);
            Assert.Equal(Xpc1V2MutationOutcome.None, conflict.MutationOutcome);
            Assert.Equal(32, conflict.Field(16).Length);
            Assert.NotEqual(new byte[32], conflict.Field(16).ToArray());
            if (conflictWire is not null) Assert.Equal(conflictWire, wire.ToArray());
            conflictWire = wire.ToArray();
            Assert.Equal(before, ClaimSnapshotHashes(harness.Root));
            harness.Reopen();
        }
        Assert.Equal(original.ToArray(), (await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default)).ToArray());
        Assert.Equal(before, ClaimSnapshotHashes(harness.Root));
        var next = harness.Request(0xb1);
        var second = harness.Verify(next, await harness.Claims[1].ReceiveTerminalAsync(next.CanonicalBytes, default));
        AssertOneTimeSelection(harness, second);
        Assert.Equal(2UL, U64(second.Field(24).Span));
        Assert.NotEqual(accepted.Field(17).ToArray(), second.Field(17).ToArray());
        Assert.Equal(harness.Signed.Publication.OneTimeMembers[1].OneTimePrekeyId.ToArray(), second.Field(17).ToArray());
    }

    [Theory]
    [InlineData("network")]
    [InlineData("device")]
    [InlineData("service")]
    [InlineData("suite")]
    [InlineData("requested-suite")]
    public async Task SignedInventoryCannotAuthorizeAnotherRequestScope_ValidRequestStillClaimsFirstKey(string mutation)
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        var before = InventorySnapshotHashes(harness.Root);
        var hostile = mutation is "suite" or "requested-suite" ? request.CanonicalBytes.ToArray() : ChangeRequest(request, mutation).CanonicalBytes.ToArray();
        if (mutation is "suite" or "requested-suite")
        {
            if (mutation == "suite")
                BinaryPrimitives.WriteUInt16BigEndian(hostile.AsSpan(6), 0x0201);
            else
            {
                // Exact fixed XPK1 field20, independently asserted before mutation.
                Assert.Equal(20, BinaryPrimitives.ReadUInt16BigEndian(hostile.AsSpan(348)));
                Assert.Equal(2U, BinaryPrimitives.ReadUInt32BigEndian(hostile.AsSpan(352)));
                BinaryPrimitives.WriteUInt16BigEndian(hostile.AsSpan(356), 0x0302);
            }
            await Assert.ThrowsAnyAsync<FormatException>(async () =>
                await harness.Claims[0].ReceiveTerminalAsync(hostile, default));
        }
        else
            await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
                await harness.Claims[0].ReceiveTerminalAsync(hostile, default));
        Assert.Equal(0, harness.HttpCalls);
        Assert.Empty(ClaimSnapshotHashes(harness.Root));
        Assert.Equal(before, InventorySnapshotHashes(harness.Root));
        Assert.Empty(Directory.GetFiles(harness.Root, "fork.marker", SearchOption.AllDirectories));
        Assert.Empty(Directory.GetFiles(harness.Root, "fault.marker", SearchOption.AllDirectories));
        harness.Reopen();
        var claimed = harness.Verify(request, await harness.Claims[1].ReceiveTerminalAsync(request.CanonicalBytes, default));
        AssertOneTimeSelection(harness, claimed);
        Assert.Equal(1UL, U64(claimed.Field(24).Span));
        Assert.Equal(harness.Signed.Publication.OneTimeMembers[0].OneTimePrekeyId.ToArray(), claimed.Field(17).ToArray());
    }

    private static string[] InventorySnapshotHashes(string root) =>
        Directory.GetFiles(root, "active.state", SearchOption.AllDirectories).Order()
            .Select(path => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)))).ToArray();

    private static ParsedXpk1V2 ChangeRequest(ParsedXpk1V2 request, string mutation)
    {
        static byte[] Changed() => Enumerable.Repeat((byte)0xfb, 32).ToArray();
        if (mutation is not ("network" or "device" or "service" or "ephemeral" or "bundle" or "issued" or "expiry"))
            throw new ArgumentOutOfRangeException(nameof(mutation));
        return DeepIdV2PreKeyClaimRequestCodec.Decode(DeepIdV2PreKeyClaimRequestCodec.Encode(
            mutation == "network" ? Changed().AsSpan(0, 16) : request.Field(1).Span,
            request.Field(2).Span, request.Field(3).Span, request.Field(4).Span,
            mutation == "issued" ? U64(request.Field(5).Span) + 1 : U64(request.Field(5).Span),
            mutation == "expiry" ? U64(request.Field(6).Span) - 1 : U64(request.Field(6).Span),
            request.Field(16).Span, mutation == "bundle" ? Changed() : request.Field(17).Span,
            mutation == "service" ? Changed() : request.Field(18).Span,
            mutation == "device" ? Changed() : request.Field(19).Span,
            mutation == "ephemeral" ? Changed() : request.Field(21).Span));
    }

    private static void AssertOneTimeSelection(Harness harness, ParsedXpc1V2 result)
    {
        Assert.Equal(Xpc1V2MutationOutcome.DurablyCommitted, result.MutationOutcome);
        var index = BinaryPrimitives.ReadUInt16BigEndian(result.Field(27).Span);
        Assert.InRange((int)index, 0, harness.Signed.Publication.OneTimeMembers.Count - 1);
        var member = harness.Signed.Publication.OneTimeMembers[index];
        Assert.Equal(member.CanonicalBytes.ToArray(), result.Field(16).ToArray());
        Assert.Equal(member.OneTimePrekeyId.ToArray(), result.Field(17).ToArray());
        Assert.Equal(harness.Signed.Publication.Manifest.CanonicalBytes.ToArray(), result.Field(26).ToArray());
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(result.Field(23).Span));
        Assert.Equal(160, result.Field(28).Length);
        // Harness.Verify already verifies both actual selected replica signatures;
        // the result codec executes Merkle membership and exact request binding.
    }

    [Theory]
    [InlineData(5, false, false)]
    [InlineData(5, false, true)]
    [InlineData(5, true, false)]
    [InlineData(5, true, true)]
    [InlineData(32, false, false)]
    [InlineData(32, false, true)]
    [InlineData(32, true, false)]
    [InlineData(32, true, true)]
    public async Task NativeCompletionWriteFailure_ReturnsUnknown_ExactReconciliationKeepsFirstKey(
        int error, bool peer, bool afterReplace)
    {
        using var harness = await Harness.CreateAsync();
        var barrier = new NativeCompletionFailure(harness.Nodes[peer ? 1 : 0].DataDirectory, error, afterReplace);
        harness.Durability = barrier;
        harness.Reopen();
        var request = harness.Request();
        var unknown = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[0].ReceiveTerminalAsync(
            request.CanonicalBytes, default)).Span, request.CanonicalBytes.Span);
        Assert.Equal(1, barrier.Failures);
        Assert.Equal(peer ? 1 : 0, harness.UnavailableResponses);
        Assert.Equal(Xpc1V2Status.OutcomeUnknown, unknown.Status);
        Assert.Equal(Xpc1V2MutationOutcome.OutcomeUnknown, unknown.MutationOutcome);
        Assert.Empty(unknown.Field(16).ToArray());
        Assert.Equal(2, ClaimSnapshotHashes(harness.Root).Length);
        harness.Reopen();
        var completed = await harness.Claims[1].ReceiveTerminalAsync(request.CanonicalBytes, default);
        var recovered = harness.Verify(request, completed);
        AssertOneTimeSelection(harness, recovered);
        Assert.Equal(1UL, U64(recovered.Field(24).Span));
        Assert.Equal(harness.Signed.Publication.OneTimeMembers[0].OneTimePrekeyId.ToArray(), recovered.Field(17).ToArray());
        harness.Reopen();
        Assert.Equal(completed.ToArray(), (await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default)).ToArray());
        var next = harness.Request(0xb1);
        var second = harness.Verify(next, await harness.Claims[1].ReceiveTerminalAsync(next.CanonicalBytes, default));
        Assert.Equal(2UL, U64(second.Field(24).Span));
        Assert.Equal(harness.Signed.Publication.OneTimeMembers[1].OneTimePrekeyId.ToArray(), second.Field(17).ToArray());
        Assert.Equal(1, barrier.Failures);
    }

    [Fact]
    public async Task UnavailableCurrentRecipientProof_CannotCreateClaimState()
    {
        using var harness = await Harness.CreateAsync();
        harness.Signed.RejectProof = true;
        await Assert.ThrowsAnyAsync<System.Security.Cryptography.CryptographicException>(async () =>
            await harness.Claims[0].ReceiveTerminalAsync(harness.Request().CanonicalBytes, default));
        Assert.Empty(Directory.GetFiles(harness.Root, "claims.state", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task AuthorityExpiryAfterPeerPrepare_ReturnsUnknownAndLeavesKeyReserved()
    {
        using var harness = await Harness.CreateAsync();
        harness.ExpireAfterPrepare = true;
        var request = harness.Request();
        var response = DeepIdV2PreKeyClaimResultCodec.Decode((await harness.Claims[0].ReceiveTerminalAsync(
            request.CanonicalBytes, default)).Span, request.CanonicalBytes.Span);
        Assert.Equal(Xpc1V2Status.OutcomeUnknown, response.Status);
        Assert.Equal(2, Directory.GetFiles(harness.Root, "claims.state", SearchOption.AllDirectories).Length);
        using var store = new DeepIdV2InventoryCommitStore(harness.Nodes[0].DataDirectory,
            DeepIdV2PublicationAuthorityFixture.Network, DeepIdV2PublicationAuthorityFixture.Service,
            harness.Nodes[0].GetRouterId().ToBytes());
        var proposal = store.PrepareNextClaim(request, 1_095, 1_105,
            _ => throw new InvalidOperationException("Existing pending reservation must not change."));
        Assert.Empty(proposal.CompletedResult.ToArray());
        Assert.Equal(harness.Signed.Publication.OneTimeMembers[0].OneTimePrekeyId.ToArray(), proposal.Offering.OneTimePrekeyId.ToArray());
    }

    [Fact]
    public async Task LegacyOrWrongPlacementCannotReachV2ClaimMutation()
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request().CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4), 1);
        await Assert.ThrowsAnyAsync<FormatException>(async () => await harness.Claims[0].ReceiveTerminalAsync(request, default));
        var valid = harness.Request();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await harness.Receivers[0].ReceiveAsync(
            new(harness.Placement, ContactReplicaRpcOperation.ClaimPreKey, new byte[32], valid.CanonicalBytes),
            harness.Nodes[1].GetRouterId(), default));
        var projection = ContactServicePlacementCapability.FromUntrustedProjection(ContactServiceRequestKind.ClaimPreKey,
            harness.Placement.NetworkId.Span, harness.Placement.ViewHash.Span, Enumerable.Repeat((byte)0xfb, 32).ToArray(),
            harness.Placement.ShardKey.Span, harness.Placement.SelectionEpoch, harness.Placement.ValidUntilUnixSeconds,
            harness.Placement.ReplicaIds);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await harness.Claims[0].ReceiveAsync(
            new(projection, ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim, new byte[32], valid.CanonicalBytes),
            harness.Nodes[1].GetRouterId(), default));
        Assert.Empty(Directory.GetFiles(harness.Root, "claims.state", SearchOption.AllDirectories));
    }

    [Fact]
    public void ClaimFlag_RequiresObserverAndDID2OnlyPublicationBoundary()
    {
        var options = new DeepIdV2PreKeyClaimOptions { Enabled = true };
        Assert.True(options.Validate(true, true, true));
        Assert.Throws<InvalidOperationException>(() => options.Validate(false, true, true));
        Assert.Throws<InvalidOperationException>(() => options.Validate(true, false, true));
        Assert.Throws<InvalidOperationException>(() => options.Validate(true, true, false));
    }

    [Fact]
    public async Task UnknownCapabilityLookup_DoesNotCreateCustodyDirectory()
    {
        using var harness = await Harness.CreateAsync();
        var directories = Directory.GetDirectories(harness.Root, "*", SearchOption.AllDirectories).Order().ToArray();
        Assert.Throws<InvalidOperationException>(() => DeepIdV2InventoryCommitStore.OpenExisting(
            harness.Nodes[0].DataDirectory, DeepIdV2PublicationAuthorityFixture.Network,
            Enumerable.Repeat((byte)0xfc, 32).ToArray(), harness.Nodes[0].GetRouterId().ToBytes(),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));
        Assert.Equal(directories, Directory.GetDirectories(harness.Root, "*", SearchOption.AllDirectories).Order().ToArray());
    }

    [Fact]
    public async Task PeerProposal_IsClosedAndCannotBePreparedByTheSecondRankedReplica()
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        var proposal = new DeepIdV2ClaimProposal(request, harness.Signed.Publication.OneTimeMembers[0],
            harness.Signed.Publication.Manifest, 1, 0);
        ParsedXic1V2 Receipt(int index)
        {
            using var store = DeepIdV2InventoryCommitStore.OpenExisting(harness.Nodes[index].DataDirectory,
                DeepIdV2PublicationAuthorityFixture.Network, DeepIdV2PublicationAuthorityFixture.Service,
                harness.Nodes[index].GetRouterId().ToBytes(), new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
            return store.ReadCurrentCommitReceipt()!;
        }
        var exact = DeepIdV2ClaimPeerPayloadCodec.EncodePrepare(proposal, Receipt(0), Receipt(1), new byte[64]);
        Assert.Equal(request.CanonicalBytes.ToArray(),
            DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(exact).Proposal.Request.CanonicalBytes.ToArray());
        Assert.Throws<InvalidDataException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(exact[..^1]));
        Assert.Throws<InvalidDataException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare([.. exact, 0]));
        var hostileLength = exact.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(hostileLength.AsSpan(438 + 560 + 8 + 2), uint.MaxValue);
        Assert.Throws<InvalidDataException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(hostileLength));
        var old = exact.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(old.AsSpan(4), 1);
        Assert.ThrowsAny<FormatException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(old));
        var wrongSuite = exact.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(wrongSuite.AsSpan(6), 0x0201);
        Assert.ThrowsAny<FormatException>(() => DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(wrongSuite));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await harness.Claims[0].ReceiveAsync(
            new(harness.Placement, ContactReplicaRpcOperation.PrepareDid2PreKeyClaim, new byte[32], exact),
            harness.Nodes[1].GetRouterId(), default));
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
            await harness.Claims[1].ReceiveAsync(new(harness.Placement,
                ContactReplicaRpcOperation.PrepareDid2PreKeyClaim, new byte[32], exact),
                harness.Nodes[0].GetRouterId(), default));
        Assert.Empty(Directory.GetFiles(harness.Root, "claims.state", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task CompletionForkLatch_SurvivesReopenAndPreservesInventory()
    {
        using var harness = await Harness.CreateAsync();
        var request = harness.Request();
        _ = harness.Verify(request, await harness.Claims[0].ReceiveTerminalAsync(request.CanonicalBytes, default));
        using (var store = DeepIdV2InventoryCommitStore.OpenExisting(harness.Nodes[0].DataDirectory,
            DeepIdV2PublicationAuthorityFixture.Network, DeepIdV2PublicationAuthorityFixture.Service,
            harness.Nodes[0].GetRouterId().ToBytes(), new MailboxStorageSecurity(), new MailboxDurabilityBarrier()))
        {
            Assert.Throws<InvalidDataException>(() => store.LatchClaimCompletionFork());
            Assert.Throws<InvalidDataException>(() => store.ReadCurrentPublication());
        }
        Assert.Single(Directory.GetFiles(harness.Nodes[0].DataDirectory, "claims.state", SearchOption.AllDirectories));
        Assert.Single(Directory.GetFiles(harness.Nodes[0].DataDirectory, "active.state", SearchOption.AllDirectories));
        Assert.Throws<InvalidDataException>(() => DeepIdV2InventoryCommitStore.OpenExisting(
            harness.Nodes[0].DataDirectory, DeepIdV2PublicationAuthorityFixture.Network,
            DeepIdV2PublicationAuthorityFixture.Service, harness.Nodes[0].GetRouterId().ToBytes(),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));
    }

    private static ulong U64(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);

    private sealed class Harness : IDisposable
    {
        internal string Root { get; } = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(),
            "did2-claim-runtime-" + Guid.NewGuid().ToString("N"))).FullName;
        internal DeepIdV2PublicationAuthorityFixture Signed { get; private set; } = null!;
        internal ContactServicePlacementCapability Placement { get; private set; } = null!;
        internal RouterNodeOptions[] Nodes { get; private set; } = [];
        internal DeepIdV2PreKeyClaimRuntime[] Claims { get; private set; } = [];
        internal DeepIdV2ReplicaStageReceiver[] Receivers { get; private set; } = [];
        private PrivacyRoutingConfiguration[] privacy = [];
        private readonly ServiceProvider services = new ServiceCollection().AddLogging().AddRouting().BuildServiceProvider();
        private readonly IClock clock = new FixedClock();
        private readonly ContactServicePersistenceOptions options = new() { ReplicaTimeoutSeconds = 20 };
        private ContactReplicaReplayGuard[] replays = [];
        internal ContactReplicaRpcOperation? LoseNextResponse { get; set; }
        internal bool ExpireAfterPrepare { get; set; }
        internal int HttpCalls { get; private set; }
        internal int UnavailableResponses { get; private set; }
        internal IMailboxDurabilityBarrier Durability { get; set; } = new MailboxDurabilityBarrier();

        internal static async Task<Harness> CreateAsync(ushort lastResortReuseLimit = 1)
        {
            var harness = new Harness();
            try
            {
                harness.Signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(lastResortReuseLimit: lastResortReuseLimit);
                harness.Placement = await harness.Signed.MintPreKeyClaimAsync(DeepIdV2PublicationAuthorityFixture.Service, default);
                harness.Nodes = harness.Placement.ReplicaIds.Select((id, i) => new RouterNodeOptions
                {
                    RouterId = Convert.ToHexString(id.Span), Ed25519PrivateKey = Convert.ToHexString(harness.Signed.Node(id.Span).Seed),
                    DataDirectory = Path.Combine(harness.Root, i.ToString())
                }).ToArray();
                harness.privacy = Enumerable.Range(0, 2).Select(i => Privacy(harness.Nodes[i].GetRouterId(),
                    harness.Nodes[1 - i].GetRouterId())).ToArray();
                harness.Reopen();
                var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(harness.Signed.Publication.CanonicalBytes.Span,
                    harness.Signed.Placement.ViewHash.Span, harness.Signed.Publisher.CanonicalBytes.Span,
                    harness.Signed.Dca, harness.Signed.Xps);
                var receipts = new ParsedXic1V2[2];
                for (var i = 0; i < 2; i++)
                    foreach (var fragment in fragments)
                    {
                        var result = await harness.Receivers[i].ReceiveTerminalAsync(fragment, default);
                        if (fragment == fragments[^1]) receipts[i] = DeepIdV2PreKeyCommitReceiptCodec.Decode(result.Span);
                    }
                DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(harness.Signed.Publication,
                    harness.Signed.Placement.VerifiedPlacement, receipts[0], receipts[1]);
                return harness;
            }
            catch { harness.Dispose(); throw; }
        }

        internal void Reopen()
        {
            replays = [new(options), new(options)]; Claims = new DeepIdV2PreKeyClaimRuntime[2];
            Receivers = new DeepIdV2ReplicaStageReceiver[2];
            for (var i = 0; i < 2; i++)
            {
                var nodeIndex = i;
                var peer = new HttpContactReplicaPeerClient(Nodes[i], privacy[i], options, clock,
                    _ => new Handler((request, token) => HttpAsync(1 - nodeIndex, request, token)));
                var candidates = new DeepIdV2PublicationCandidateAuthority(Signed, Signed);
                var security = new MailboxStorageSecurity(); var durability = Durability;
                Claims[i] = new(Nodes[i], Signed, candidates, peer, Signed, clock, security, durability);
                Receivers[i] = new(Nodes[i], Signed, security, durability,
                    new(Nodes[i], candidates, Signed, Signed, security, durability), Claims[i]);
            }
        }

        internal ParsedXpk1V2 Request(byte operation = 0xb0, byte ephemeral = 0xb2) =>
            DeepIdV2PreKeyClaimRequestCodec.Decode(DeepIdV2PreKeyClaimRequestCodec.Encode(Placement.NetworkId.Span,
                Enumerable.Repeat(operation, 32).ToArray(), Placement.ViewHash.Span, Placement.PlacementHash.Span,
                1_000, 1_400, Placement.ShardKey.Span, Enumerable.Repeat((byte)0xb3, 32).ToArray(),
                Signed.Publication.Manifest.Field(6).Span[6..], Signed.Publication.Manifest.Field(3).Span,
                Enumerable.Repeat(ephemeral, 32).ToArray()));

        internal ParsedXpc1V2 Verify(ParsedXpk1V2 request, ReadOnlyMemory<byte> response)
        {
            var parsed = DeepIdV2PreKeyClaimResultCodec.Decode(response.Span, request.CanonicalBytes.Span);
            _ = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request, parsed, Placement.VerifiedPlacement);
            Assert.Equal(Xpc1V2Status.Claimed, parsed.Status); return parsed;
        }

        private async Task<HttpResponseMessage> HttpAsync(int nodeIndex, HttpRequestMessage request, CancellationToken token)
        {
            HttpCalls++;
            Assert.Equal(HttpVersion.Version20, request.Version);
            Assert.Equal(HttpVersionPolicy.RequestVersionExact, request.VersionPolicy);
            Assert.Equal(ContactReplicaHttpContract.Route, request.RequestUri!.AbsolutePath);
            var body = await request.Content!.ReadAsByteArrayAsync(token);
            var command = ContactReplicaWireCodec.DecodeRequest(body);
            var context = new DefaultHttpContext { RequestServices = services };
            context.Connection.LocalPort = 7443; context.Request.Scheme = "https";
            context.Request.Method = "POST"; context.Request.Protocol = "HTTP/2";
            context.Request.ContentType = ContactReplicaHttpContract.MediaType;
            context.Request.ContentLength = body.Length; context.Request.Body = new MemoryStream(body);
            foreach (var header in request.Headers) context.Request.Headers[header.Key] = header.Value.ToArray();
            context.Response.Body = new MemoryStream();
            var result = await ContactReplicaHttpEndpoint.HandleCoreAsync(context, true, options,
                replays[nodeIndex], Receivers[nodeIndex], Nodes[nodeIndex], clock, 7443, token);
            await result.ExecuteAsync(context);
            if (context.Response.StatusCode == StatusCodes.Status503ServiceUnavailable)
            {
                UnavailableResponses++;
                Assert.Equal(0, context.Response.Body.Length);
                Assert.False(context.Response.Headers.ContainsKey(ContactReplicaPeerAuthenticator.SignatureHeader));
            }
            if (command.Operation == ContactReplicaRpcOperation.PrepareDid2PreKeyClaim && ExpireAfterPrepare)
            { ExpireAfterPrepare = false; Signed.Sample = Signed.Freshness.FreshnessDeadlineMonotonicSeconds; }
            if (LoseNextResponse == command.Operation)
            { LoseNextResponse = null; throw new HttpRequestException("Synthetic authenticated-response loss after receiver processing."); }
            var response = new HttpResponseMessage((HttpStatusCode)context.Response.StatusCode)
            { Version = HttpVersion.Version20, Content = new ByteArrayContent(((MemoryStream)context.Response.Body).ToArray()) };
            if (context.Response.ContentType is { } contentType)
                response.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
            foreach (var header in context.Response.Headers)
                if (!header.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                    response.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            return response;
        }

        private static PrivacyRoutingConfiguration Privacy(RouterId local, RouterId peer) => new(true,
            Enumerable.Repeat((byte)0x81, 32).ToArray(), Sodium.ScalarMult.Base(Enumerable.Repeat((byte)0x81, 32).ToArray()), new Uri("https://local.invalid/api/peer/privacy/v1/frame"),
            new Dictionary<RouterId, PrivacyPeer> { [peer] = new(peer,
                new Uri("https://peer.invalid/api/peer/privacy/v1/frame"), Enumerable.Repeat((byte)0x83, 32).ToArray(),
                Sodium.ScalarMult.Base(Enumerable.Repeat((byte)0x84, 32).ToArray()), false) },
            64, 600, TimeSpan.FromSeconds(30), 1024, 1_000, TimeSpan.FromMinutes(5));

        public void Dispose()
        { foreach (var item in privacy) item.Dispose(); Signed?.Dispose(); services.Dispose(); if (Directory.Exists(Root)) Directory.Delete(Root, true); }
    }

    private sealed class FixedClock : IClock { public DateTimeOffset UtcNow => DateTimeOffset.FromUnixTimeSeconds(1_100); }
    // Deterministic native error classification, not a diagnosis of the observed
    // intermittent Windows lock. No retry, ACL change or write suppression.
    private sealed class NativeCompletionFailure(string replicaDirectory, int error, bool afterReplace) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier inner = new();
        private int writes;
        internal int Failures { get; private set; }
        public void FlushFileAndParentDirectory(string path) => inner.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => inner.FlushParentDirectory(path);
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            var prefix = Path.GetFullPath(replicaDirectory) + Path.DirectorySeparatorChar;
            if (Path.GetFileName(finalPath) == "claims.state" &&
                Path.GetFullPath(finalPath).StartsWith(prefix, StringComparison.Ordinal) && ++writes == 2)
            {
                if (afterReplace) inner.ReplaceFile(temporaryPath, finalPath);
                Failures++;
                throw new System.ComponentModel.Win32Exception(error);
            }
            inner.ReplaceFile(temporaryPath, finalPath);
        }
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => handler(request, token);
    }
}
