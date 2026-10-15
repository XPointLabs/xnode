using Deep.Protocol.ContactV1;
using System.Buffers.Binary;
using Deep.Protocol.ContactV2;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactAuthorizedPublicationReplicaTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "xnode-contact-authorized-replica-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task StandaloneReusableRequestRejectsBeforeAuthorityCallbackOrMutation()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new NeverCalledVerifier();
        using var runtime = Open(verifier);
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
            await runtime.Service.PublishAsync(ceremony.ContactPublication.CanonicalBytes, default));
        Assert.Equal(0, verifier.Calls);
        var absent = await runtime.Replica.ResolveCurrentDcrAsync(ceremony.ContactPublication.LocatorHash, default);
        Assert.Equal(ContactResolverReadDisposition.NotFound, absent.Disposition);
    }

    private sealed class NeverCalledVerifier : IContactPublicationAuthorizationVerifier
    {
        internal int Calls;
        public ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(Xpu1Request request, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("Retired reusable dispatch reached authority."); }
        public ValueTask<VerifiedXpa1PublicationAuthorization> VerifyLeaseAsync(
            Deep.Protocol.ContactV2.ParsedDeepIdV2PublicationLease request, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("Unexpected lease dispatch."); }
    }

    [Fact]
    public async Task OneTimeInviteCannotEnterReusableLeaseOrRecovery()
    {
        using var reusable = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        using var oneTime = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true, authorOneTimeObject: true);
        var original = oneTime.ContactPublication;
        Assert.Equal(1u, original.UsageLimit);
        var template = reusable.ContactDispatch.ToArray();
        using var output = new MemoryStream(); output.Write(template.AsSpan(0, 12));
        for (var offset = 12; offset < template.Length;)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(template.AsSpan(offset));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(template.AsSpan(offset + 4)));
            var value = tag == 2 ? original.RequestHash.ToArray() : tag == 9 ? original.CanonicalBytes.ToArray()
                : template.AsSpan(offset + 8, length).ToArray();
            var header = template.AsSpan(offset, 8).ToArray();
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), checked((uint)value.Length));
            output.Write(header); output.Write(value); offset += 8 + length;
        }
        var forged = output.ToArray();
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
        {
            var verifier = new NeverCalledVerifier();
            using var runtime = Open(verifier);
            try { await runtime.Service.PublishAsync(forged, default); }
            finally { Assert.Equal(0, verifier.Calls); }
        });
    }

    [Fact]
    public async Task ExactXpaReservationAndCommitSurviveReplicaRestart()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var request = ceremony.ContactPublication;

        using (var first = Open(verifier))
        {
            var committed = await first.Service.PublishAsync(ceremony.Dispatch(request), default);
            Assert.Equal(ContactResolverMutationDisposition.Committed, committed.Disposition);
        }

        using var restarted = Open(verifier);
        var replay = await restarted.Service.PublishAsync(ceremony.Dispatch(request), default);
        Assert.Equal(ContactResolverMutationDisposition.ExactReplay, replay.Disposition);
    }

    [Fact]
    public async Task SameAuthorizationWithDifferentValidWitnessSetLatchesExactRequestConflict()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var firstRequest = ceremony.ContactPublication;
        var changedRequest = ceremony.AlternateContactPublication;
        var originalAuthorization = await verifier.VerifyAsync(firstRequest, default);
        var alternateAuthorization = await verifier.VerifyAsync(changedRequest, default);
        Assert.Equal(originalAuthorization.AuthorizationId.ToArray(), alternateAuthorization.AuthorizationId.ToArray());
        Assert.Equal(firstRequest.AuthorizedBodyHash.ToArray(), changedRequest.AuthorizedBodyHash.ToArray());
        Assert.NotEqual(firstRequest.RequestHash.ToArray(), changedRequest.RequestHash.ToArray());
        using var runtime = Open(verifier);

        _ = await runtime.Service.PublishAsync(ceremony.Dispatch(firstRequest), default);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await runtime.Service.PublishAsync(ceremony.Dispatch(changedRequest), default));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await runtime.Service.PublishAsync(ceremony.Dispatch(firstRequest), default));

        var stored = await runtime.Replica.ResolveCurrentDcrAsync(
            firstRequest.LocatorHash,
            default);
        Assert.Equal(ContactResolverReadDisposition.Current, stored.Disposition);
        Assert.Equal(
            firstRequest.ObjectCiphertextHash.ToArray(),
            stored.Publication!.ObjectCiphertextHash);
    }

    [Fact]
    public async Task ForgedWitnessCannotReserveAuthorizationOrPreventValidPublication()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var request = ceremony.ContactPublication;
        var forgedXpa = request.ExactXpa1.ToArray();
        forgedXpa[^1] ^= 1;
        var forged = Xpu1Codec.Decode(Xpu1Codec.Encode(request.NetworkId.Span,
            request.OperationId.Span, request.ViewHash.Span, request.PlacementHash.Span,
            request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds, request.LocatorHash.Span,
            request.Xir1Hash.Span, request.Generation, request.PredecessorObjectHash.Span,
            request.ObjectCiphertext.Span, request.UsageLimit, request.EffectiveExpiresAtUnixSeconds,
            request.ExactRouteClosure.Span, forgedXpa, request.OwnerRetrieveCapability.Span));
        using var runtime = Open(verifier);
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
            await runtime.Service.PublishAsync(forged.CanonicalBytes, default));
        var forgedLease = ceremony.ContactDispatch.ToArray(); forgedLease[^1] ^= 1;
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
            await runtime.Service.PublishAsync(forgedLease, default));
        var absent = await runtime.Replica.ResolveCurrentDcrAsync(request.LocatorHash, default);
        Assert.Equal(ContactResolverReadDisposition.NotFound, absent.Disposition);
        var accepted = await runtime.Service.PublishAsync(ceremony.Dispatch(request), default);
        Assert.Equal(ContactResolverMutationDisposition.Committed, accepted.Disposition);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private Runtime Open(IContactPublicationAuthorizationVerifier verifier)
    {
        Directory.CreateDirectory(root);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1100));
        var store = new ContactResolverOpaqueStore(
            Path.Combine(root, "resolver.state"),
            clock: clock);
        var replica = new ContactResolverStoreReplica(
            Enumerable.Repeat((byte)0x51, 32).ToArray(),
            store);
        var saga = new ContactPublicationAuthorizationSaga(
            Path.Combine(root, "xpa1-saga.state"),
            Path.Combine(root, "xpa1-saga.key"));
        return new Runtime(
            store,
            saga,
            replica,
            new ContactAuthorizedPublicationReplica(replica, verifier, saga, clock));
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed record Runtime(
        ContactResolverOpaqueStore Store,
        ContactPublicationAuthorizationSaga Saga,
        ContactResolverStoreReplica Replica,
        ContactAuthorizedPublicationReplica Service) : IDisposable
    {
        public void Dispose()
        {
            Saga.Dispose();
            Store.Dispose();
        }
    }
}
