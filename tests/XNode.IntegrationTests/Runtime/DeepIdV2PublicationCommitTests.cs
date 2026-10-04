using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using XNode.Core.ContactResolver;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Current signed ceremony and exact cryptographic commit inputs.
/// Receipt synthesis here is not a node persistence/transport/device claim;
/// actual two-store one-time publication is checked by the opaque facade test.</summary>
public sealed class DeepIdV2PublicationCommitTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CommitRequiresActualDistinctDescriptorKeysNotNodeIdAliases(bool oneTime)
    {
        using var f = await Create(oneTime);
        var result = await SignedResult(f);
        var placement = Placement(f);
        foreach (var id in placement.RankedReplicaNodeIds)
            Assert.False(id.Span.SequenceEqual(f.NetworkContext.ResolveNodeIdentityPublicKey(id).Span));
        var verified = await Verify(f, result, oneTime);
        Assert.Equal(result, verified.ExactXpo1.ToArray()); Assert.Equal(0ul, verified.Generation);
        Assert.Equal(f.ContactPublication.ObjectCiphertextHash.ToArray(), verified.ObjectCiphertextHash.ToArray());
    }

    [Theory]
    [InlineData("id-as-key")]
    [InlineData("changed-signature")]
    [InlineData("unselected-replica")]
    [InlineData("changed-request")]
    [InlineData("clock-rollback")]
    [InlineData("clock-rollback-after-read")]
    [InlineData("clock-rollback-at-release")]
    [InlineData("clock-rollback-at-final")]
    [InlineData("clock-reboot")]
    [InlineData("expired-release")]
    [InlineData("expired-final")]
    [InlineData("expired-current")]
    [InlineData("oversized-result")]
    public async Task OneTimeCommitRejectsUnboundOrUnavailableEvidence(string fault)
    {
        using var f = await Create(true);
        var result = await SignedResult(f, fault);
        var request = f.ContactOwnedRequest;
        if (fault == "changed-request")
        {
            var bytes = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
            bytes[24] ^= 1;
            request = ContactPublicationAuthorityWireCodec.DecodeRequest(bytes);
        }
        if (fault == "clock-rollback") f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 99));
        if (fault == "clock-rollback-after-read")
        {
            f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 102));
            f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 101));
        }
        if (fault is "clock-rollback-at-release" or "clock-rollback-at-final")
        {
            f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 100));
            f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 102));
            if (fault == "clock-rollback-at-final")
                f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 102));
            f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 101));
        }
        if (fault == "clock-reboot") f.ClockReadings.Enqueue(new(Enumerable.Repeat((byte)0x42, 16).ToArray(), f.Sample));
        if (fault is "expired-release" or "expired-final")
        {
            f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, f.Sample));
            if (fault == "expired-final")
                f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, f.Sample));
            f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, f.Sample));
            f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, f.Freshness.FreshnessDeadlineMonotonicSeconds));
        }
        if (fault == "expired-current") f.Sample = f.Freshness.FreshnessDeadlineMonotonicSeconds;
        if (fault == "oversized-result") result = new byte[DeepIdV2PublicationCommitVerifier.MaximumResultBytes + 1];
        async Task VerifyCandidate() =>
            await DeepIdV2PublicationCommitVerifier.VerifyOneTimeCommittedAsync(f.ContactRoute,
                f.OneTimeContactObject!, request, f.ContactPublication.CanonicalBytes, result);
        if (fault is "clock-rollback" or "clock-reboot" or "expired-current" or "expired-release" or "expired-final")
        {
            var failure = await Assert.ThrowsAsync<AccountDirectoryFreshnessVerificationException>(VerifyCandidate);
            Assert.Equal("DirectoryFreshnessExpired", failure.Code);
        }
        else await Assert.ThrowsAsync<CryptographicException>(VerifyCandidate);
    }

    [Fact]
    public async Task ReusableCommitAlsoChecksItsFirstProtectedReading()
    {
        using var f = await Create(false); var result = await SignedResult(f);
        f.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, 99));
        var failure = await Assert.ThrowsAsync<AccountDirectoryFreshnessVerificationException>(async () =>
            await Verify(f, result, false));
        Assert.Equal("DirectoryFreshnessExpired", failure.Code);
    }

    [Fact]
    public async Task OneTimePastCommitDoesNotRenewExpiredDispatchAuthorization()
    {
        using var f = await Create(true);
        var result = await SignedResult(f);
        var after = checked(f.ContactOwnedRequest.ExpiresAtUnixSeconds + 10);
        var route = await f.RefreshContactProofAsync(100 + after - 1_100, after);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(route,
                f.ContactOwnedRequest, f.ContactPublication.CanonicalBytes));
        var committed = await DeepIdV2PublicationCommitVerifier.VerifyOneTimeCommittedAsync(route,
            f.OneTimeContactObject!, f.ContactOwnedRequest, f.ContactPublication.CanonicalBytes, result);
        Assert.Equal(result, committed.ExactXpo1.ToArray());
    }

    [Fact]
    public async Task OneTimeCommitRequiresLiveTypedCandidateAndPreservesCancellation()
    {
        using var f = await Create(true);
        var result = await SignedResult(f);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await DeepIdV2PublicationCommitVerifier.VerifyOneTimeCommittedAsync(f.ContactRoute,
                f.OneTimeContactObject!, f.ContactOwnedRequest, f.ContactPublication.CanonicalBytes, result, cancellation.Token));
        f.OneTimeContactObject!.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            DeepIdV2PublicationCommitVerifier.VerifyOneTimeCommittedAsync(f.ContactRoute,
                f.OneTimeContactObject, f.ContactOwnedRequest, f.ContactPublication.CanonicalBytes, result));
    }

    [Fact]
    public async Task OneTimeCommitCannotAdoptAnotherReusableRoute()
    {
        using var oneTime = await Create(true); using var reusable = await Create(false);
        var result = await SignedResult(oneTime);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2PublicationCommitVerifier.VerifyOneTimeCommittedAsync(reusable.ContactRoute,
                oneTime.OneTimeContactObject!, oneTime.ContactOwnedRequest, oneTime.ContactPublication.CanonicalBytes, result));
    }

    private static Task<DeepIdV2PublicationAuthorityFixture> Create(bool oneTime) =>
        DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true,
            authorOneTimeObject: oneTime, distinctNodeIdentities: true);
    private static VerifiedContactServicePlacement Placement(DeepIdV2PublicationAuthorityFixture f) =>
        ContactServicePlacementFactory.Create(f.NetworkContext, ContactServiceRequestKind.PublishInvite,
            f.ContactPublication.LocatorHash);
    private static ValueTask<VerifiedDeepIdV2PublicationCommit> Verify(DeepIdV2PublicationAuthorityFixture f,
        byte[] result, bool oneTime) => oneTime
        ? DeepIdV2PublicationCommitVerifier.VerifyOneTimeCommittedAsync(f.ContactRoute, f.OneTimeContactObject!,
            f.ContactOwnedRequest, f.ContactPublication.CanonicalBytes, result)
        : DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(f.ContactRoute, f.ContactObject,
            f.ContactOwnedRequest, f.ContactPublication.CanonicalBytes, result);

    private static async Task<byte[]> SignedResult(DeepIdV2PublicationAuthorityFixture f, string? fault = null)
    {
        var request = f.ContactPublication; var placement = Placement(f);
        var ids = placement.RankedReplicaNodeIds.Select(id => id.ToArray()).ToArray();
        if (fault == "unselected-replica")
        {
            var third = Deep.Protocol.DeepExtension.PrivacyRouting.OnionPathCandidateSnapshotFactory
                .Create(f.NetworkContext).Candidates.Single(node => !ids.Any(id => id.AsSpan().SequenceEqual(node.NodeId.Span)));
            ids[1] = third.NodeId.ToArray();
        }
        ids = ids.OrderBy(id => Convert.ToHexString(id), StringComparer.Ordinal).ToArray();
        var generation = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(generation, 1);
        var tuple = request.RequestHash.ToArray().Concat(request.ObjectCiphertextHash.ToArray()).Concat(generation).ToArray();
        var input = ContactServiceReceiptTranscript.SigningInput(
            new ContactServiceReplicaReceiptRequest(ContactServiceReceiptKind.PublishCommit, tuple));
        var receipts = new byte[193]; receipts[0] = 2;
        try
        {
            for (var index = 0; index < 2; index++)
            {
                ids[index].CopyTo(receipts, 1 + index * 96);
                var signature = fault == "id-as-key"
                    ? SignWithId(ids[index], input)
                    : (await f.Node(ids[index]).SignXpa1Async(input, default)).ToArray();
                signature.CopyTo(receipts, 33 + index * 96);
            }
            if (fault == "changed-signature") receipts[^1] ^= 1;
            var ownGeneration = new byte[8];
            return Xpo1Codec.Encode(request.CanonicalBytes.Span, Xpo1Status.Committed,
                ContactServiceMutationOutcome.DurablyCommitted, 1_100, 0, ContactServicePaddingClass.Bytes1024,
                [ownGeneration, request.ObjectCiphertextHash, generation, receipts]);
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }
    private static byte[] SignWithId(byte[] id, byte[] input)
    {
        var pair = PublicKeyAuth.GenerateKeyPair(id);
        try { return PublicKeyAuth.SignDetached(input, pair.PrivateKey); }
        finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
    }
}
