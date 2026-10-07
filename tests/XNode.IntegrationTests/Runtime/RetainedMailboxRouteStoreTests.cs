using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Real signed DID2 publication/host/request with actual durable files.
/// No renewed grant, peer dispatch, elapsed-history or device E2E claim.</summary>
public sealed class RetainedMailboxRouteStoreTests(CurrentContactPublicationFixture signed)
    : IClassFixture<CurrentContactPublicationFixture>
{
    [Fact]
    public async Task AuthorizedCustodySurvivesReopenWithoutUsingHostUtcAndReturnsCopies()
    {
        using var files = new Files();
        var publication = await Publication();
        var request = await Request();
        using (var store = files.Open())
            Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(publication).Disposition);
        files.Clock.Throw = true;
        using var reopened = files.Open();
        var found = await reopened.ResolveRetainedMailboxRouteAsync(request);
        Assert.Equal(RetainedMailboxRouteDisposition.Found, found.Disposition);
        Assert.Equal(publication.CanonicalRouteClosure.ToArray(), found.ExactRouteClosure.ToArray());
        var route = ContactRouteClosureCodec.Decode(publication.CanonicalRouteClosure);
        Assert.Equal(Math.Min(publication.EffectiveExpiresAtUnixSeconds,
            ContactResolverOpaqueStore.LastPossibleRouteAdmission(route))
            + ContactResolverOpaqueStore.MailboxObjectHorizonSeconds, found.ReadUntilUnixSeconds);
        var copy = found.ExactRouteClosure.ToArray(); copy[0] ^= 1;
        Assert.Equal(publication.CanonicalRouteClosure.ToArray(), found.ExactRouteClosure.ToArray());
        Assert.Equal(-1, File.ReadAllBytes(files.Path).AsSpan().IndexOf(signed.Request.OwnerRetrieveCapability.Span));
    }

    [Fact]
    public async Task LookupRequiresHolderSignedExactRouteIntentAndDefensivelyExportsIt()
    {
        using var files = new Files(); using var store = files.Open();
        var publication = await Publication();
        _ = store.PublishDcr(publication);
        var exact = await Request();
        Assert.Equal(signed.Route.Route.ExactHash.ToArray(), exact.ExactRouteHash.ToArray());
        Assert.True(MemoryMarshal.TryGetArray(exact.ExactRouteHash, out var exported)); exported.AsSpan()[0] ^= 1;
        Assert.Equal(signed.Route.Route.ExactHash.ToArray(), exact.ExactRouteHash.ToArray());
        var before = File.ReadAllBytes(files.Path);
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound,
            (await store.ResolveRetainedMailboxRouteAsync(await Request(routeHash: Bytes(32, 0xfb)))).Disposition);
        Assert.Equal(RetainedMailboxRouteDisposition.Found,
            (await store.ResolveRetainedMailboxRouteAsync(exact)).Disposition);
        Assert.Equal(before, File.ReadAllBytes(files.Path));
    }

    [Fact]
    public async Task RawOpaquePublicationCannotMintRetainedCustody()
    {
        using var files = new Files(); using var store = files.Open();
        var raw = Raw(await Publication());
        Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(raw).Disposition);
        Assert.Equal(ContactResolverReadDisposition.Current, store.ResolveMailboxGrantRoute(raw.LocatorHash,
            signed.Request.OwnerRetrieveCapability.Span, ContactMailboxGrantRole.Retrieve).Disposition);
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound,
            (await store.ResolveRetainedMailboxRouteAsync(await Request())).Disposition);
    }

    [Fact]
    public async Task FactoryRejectsDifferentExactRequestAgainstClosedAuthorization()
    {
        var authorization = await signed.Verifier.VerifyAsync(signed.Request, default);
        await Assert.ThrowsAsync<ContactPublicationAuthorizationBindingException>(async () =>
            await OpaqueDcrPublishRequest.FromAuthorizedPublicationAsync(authorization, signed.AlternateRequest, default));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task LookupRequiresExactLocatorAndOwnerCapability(bool wrongLocator)
    {
        using var files = new Files(); using var store = files.Open();
        _ = store.PublishDcr(await Publication());
        var request = await Request(locator: wrongLocator ? Bytes(32, 0xfc) : null,
            capability: wrongLocator ? null : Bytes(32, 0xfd));
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound,
            (await store.ResolveRetainedMailboxRouteAsync(request)).Disposition);
    }

    [Fact]
    public async Task CapacityBackpressureDoesNotEvictOrLatchExistingCustodyAndExactReplayStillWorks()
    {
        using var files = new Files();
        using var store = files.Open(new() { MaximumRetainedMailboxRoutes = 1 });
        var first = await Publication();
        Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(first).Disposition);
        var before = File.ReadAllBytes(files.Path);
        using var other = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true,
            contactDepositMarker: 0xd9, contactPublicationMarker: 0xc7);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(other);
        var next = await OpaqueDcrPublishRequest.FromAuthorizedPublicationAsync(
            await verifier.VerifyAsync(other.ContactPublication, default), other.ContactPublication, default);
        Assert.Equal(ContactResolverMutationDisposition.QuotaExceeded, store.PublishDcr(next).Disposition);
        Assert.Equal(before, File.ReadAllBytes(files.Path));
        Assert.Equal(ContactResolverMutationDisposition.ExactReplay, store.PublishDcr(first).Disposition);
        Assert.Equal(RetainedMailboxRouteDisposition.Found,
            (await store.ResolveRetainedMailboxRouteAsync(await Request())).Disposition);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AtomicPublicationAndReadCustodyAreBothAbsentOrBothPresentAfterDurabilityFailure(bool afterReplace)
    {
        using var files = new Files(); var publication = await Publication(); var request = await Request();
        using (var store = files.Open(durability: new ReplaceFault(afterReplace)))
        {
            Assert.Throws<IOException>(() => store.PublishDcr(publication));
            Assert.Throws<InvalidOperationException>(() => store.ResolveCurrentDcr(publication.LocatorHash));
        }
        using var reopened = files.Open();
        Assert.Equal(afterReplace ? ContactResolverReadDisposition.Current : ContactResolverReadDisposition.NotFound,
            reopened.ResolveCurrentDcr(publication.LocatorHash).Disposition);
        Assert.Equal(afterReplace ? RetainedMailboxRouteDisposition.Found : RetainedMailboxRouteDisposition.NotFound,
            (await reopened.ResolveRetainedMailboxRouteAsync(request)).Disposition);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("missing")]
    [InlineData("horizon")]
    [InlineData("route")]
    public async Task ColdStateRejectsOldGenerationMissingCustodyAndMalformedHorizonOrRoute(string defect)
    {
        using var files = new Files();
        using (var store = files.Open()) _ = store.PublishDcr(await Publication());
        RewriteEnvelope(files.Path, json =>
        {
            if (defect == "version") json["version"] = 4;
            else if (defect == "missing") json.Remove("retainedMailboxRoutes");
            else if (defect == "horizon") json["retainedMailboxRoutes"]![0]!["readUntilUnixSeconds"] = 1UL;
            else json["retainedMailboxRoutes"]![0]!["routeClosure"] = Convert.ToBase64String(Bytes(4143, 0x41));
        });
        Assert.Throws<ContactResolverStoreCorruptException>(() => files.Open());
        Assert.False(File.Exists(files.Path));
        Assert.Single(Directory.GetFiles(files.Root, "resolver.state.quarantine.*"));
    }

    [Fact]
    public async Task DcrPredecessorGcDoesNotEraseIndependentReadCustodyAcrossReopen()
    {
        using var files = new Files(); var first = await Publication(); var read = await Request();
        // This deliberately isolates the actual storage GC clock. The current
        // signed host is unchanged; it is not a 48h network-history E2E proof.
        using (var store = files.Open())
        {
            _ = store.PublishDcr(first);
            var successor = Raw(first, successor: true, expiry: 300_000);
            Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(successor).Disposition);
            var update = Update(); _ = store.WriteXurSuccessor(update);
            files.Clock.Seconds += 48 * 60 * 60;
            _ = store.CollectGarbage(VerifiedXurCompactionCheckpoint.FromVerifiedClosure(
                update.ServiceCapability, 1, update.EventHash));
            Assert.Equal(ContactResolverMutationDisposition.Expired, store.PublishDcr(first).Disposition);
            var persisted = File.ReadAllBytes(files.Path);
            var length = (int)BinaryPrimitives.ReadUInt32BigEndian(persisted.AsSpan(8));
            var json = JsonNode.Parse(persisted.AsSpan(12, length))!;
            Assert.Single(json["publications"]![0]!["records"]!.AsArray());
            Assert.Single(json["retainedMailboxRoutes"]!.AsArray());
            Assert.Equal(RetainedMailboxRouteDisposition.Found,
                (await store.ResolveRetainedMailboxRouteAsync(read)).Disposition);
        }
        using var reopened = files.Open();
        Assert.Equal(RetainedMailboxRouteDisposition.Found,
            (await reopened.ResolveRetainedMailboxRouteAsync(read)).Disposition);
    }

    [Theory]
    [InlineData("boot")]
    [InlineData("rollback")]
    [InlineData("expiry")]
    [InlineData("cancel")]
    public async Task AuthorityLossDuringFinalRecheckReturnsNoRouteAndDoesNotMutate(string defect)
    {
        using var files = new Files(); using var store = files.Open(); _ = store.PublishDcr(await Publication());
        var clock = new CallbackClock(); var request = await Request(clock: clock);
        using var cancel = new CancellationTokenSource();
        clock.Reset(() =>
        {
            if (defect == "cancel") cancel.Cancel();
            if (defect == "boot") clock.Boot = Bytes(16, 0xfc);
            if (defect == "rollback") clock.Sample = 99;
            if (defect == "expiry") clock.Sample = 300;
        });
        var before = File.ReadAllBytes(files.Path);
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await store.ResolveRetainedMailboxRouteAsync(request, cancel.Token));
        else await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await store.ResolveRetainedMailboxRouteAsync(request));
        Assert.Equal(before, File.ReadAllBytes(files.Path));
    }

    [Fact]
    public async Task DurableMutationDuringClockCallbackInvalidatesCapturedLookupSnapshot()
    {
        using var files = new Files(); using var store = files.Open(); _ = store.PublishDcr(await Publication());
        var clock = new CallbackClock(); var request = await Request(clock: clock);
        clock.Reset(() => Assert.Equal(ContactResolverMutationDisposition.Committed,
            store.WriteXurSuccessor(Update()).Disposition));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await store.ResolveRetainedMailboxRouteAsync(request));
        clock.Reset(null);
        Assert.Equal(RetainedMailboxRouteDisposition.Found,
            (await store.ResolveRetainedMailboxRouteAsync(request)).Disposition);
    }

    private async Task<OpaqueDcrPublishRequest> Publication() =>
        await OpaqueDcrPublishRequest.FromAuthorizedPublicationAsync(
            await signed.Verifier.VerifyAsync(signed.Request, default), signed.Request, default);

    private async Task<VerifiedMailboxRetainedReadRequestV2> Request(byte[]? locator = null,
        byte[]? capability = null, CallbackClock? clock = null, byte[]? routeHash = null)
    {
        using var signer = new Holder();
        var authored = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(signed.Route,
            locator is null ? signed.Request.LocatorHash : locator,
            capability is null ? signed.Request.OwnerRetrieveCapability : capability, signer);
        var host = await signed.VerifyMailboxHostAsync(clock);
        if (routeHash is not null)
        {
            // A real valid holder proof of wrong intent is not matching custody.
            var changedBytes = authored.ExactXmg2.ToArray();
            // Fixed current request: tag11 value starts 331, tag12 at371.
            Assert.Equal(435, changedBytes.Length);
            routeHash.CopyTo(changedBytes, 331);
            var changed = ContactCodec.Decode("XMG2", changedBytes);
            var proof = new byte[64];
            await signer.SignMailboxGrantRequestAsync(changed.SignatureInput, proof, default);
            proof.CopyTo(changedBytes, 371);
            return await host.VerifyRetainedReadRequestAsync(changedBytes);
        }
        return await host.VerifyRetainedReadRequestAsync(authored.ExactXmg2);
    }

    private static OpaqueDcrPublishRequest Raw(OpaqueDcrPublishRequest source, bool successor = false, ulong? expiry = null)
    {
        var cipher = successor ? Bytes(64, 0xee) : source.Ciphertext.ToArray();
        return new(source.LocatorHash, successor ? Bytes(32, 0xea) : source.OperationId,
            successor ? Bytes(32, 0xeb) : source.RequestHash, successor ? 1UL : source.Generation,
            successor ? source.ObjectCiphertextHash : source.PredecessorObjectHash,
            SHA256.HashData(cipher), cipher, source.CanonicalRouteClosure, source.UsageLimit,
            expiry ?? source.EffectiveExpiresAtUnixSeconds, source.DepositCapabilityDigest, source.RetrieveCapabilityDigest);
    }

    private static OpaqueXurWriteRequest Update()
    {
        var cipher = Bytes(32, 0xe1);
        return new(Bytes(32, 0xe2), Bytes(32, 0xe3), Bytes(32, 0xe4), Bytes(32, 0xe5),
            1, new byte[32], Bytes(32, 0xe6), SHA256.HashData(cipher), cipher, 30_000_000);
    }
    private static byte[] Bytes(int count, byte marker) => Enumerable.Repeat(marker, count).ToArray();
    private static void RewriteEnvelope(string path, Action<JsonObject> change)
    {
        var old = File.ReadAllBytes(path); var length = (int)BinaryPrimitives.ReadUInt32BigEndian(old.AsSpan(8));
        var json = JsonNode.Parse(old.AsSpan(12, length))!.AsObject(); change(json);
        var payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(json);
        var next = new byte[12 + payload.Length + 32]; old.AsSpan(0, 8).CopyTo(next);
        BinaryPrimitives.WriteUInt32BigEndian(next.AsSpan(8), (uint)payload.Length);
        payload.CopyTo(next, 12); SHA256.HashData(payload).CopyTo(next, 12 + payload.Length); File.WriteAllBytes(path, next);
    }
    private sealed class Holder : IReachabilityMailboxHolderSigner, IDisposable
    {
        private readonly KeyPair key = PublicKeyAuth.GenerateKeyPair();
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ValueTask<int> SignMailboxGrantRequestAsync(ReadOnlyMemory<byte> input, Memory<byte> output, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey).CopyTo(output); return ValueTask.FromResult(64); }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private sealed class CallbackClock : IOnionMonotonicClock
    {
        internal byte[] Boot = DeepIdV2PublicationAuthorityFixture.Boot.ToArray();
        internal ulong Sample = 100; private int calls; private Action? action;
        internal void Reset(Action? callback) { calls = 0; action = callback; }
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { if (++calls == 3) action?.Invoke(); ct.ThrowIfCancellationRequested(); return ValueTask.FromResult(new OnionMonotonicReading(Boot, Sample)); }
    }
    private sealed class StorageClock : IClock
    {
        internal long Seconds = 1100; internal bool Throw;
        public DateTimeOffset UtcNow => Throw ? throw new InvalidOperationException("Lookup must not read UTC.") : DateTimeOffset.FromUnixTimeSeconds(Seconds);
    }
    private sealed class Files : IDisposable
    {
        internal string Root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "xnode-retained-route-" + Guid.NewGuid().ToString("N"));
        internal string Path => System.IO.Path.Combine(Root, "resolver.state");
        internal StorageClock Clock = new();
        internal ContactResolverOpaqueStore Open(ContactResolverOpaqueStoreOptions? options = null, IMailboxDurabilityBarrier? durability = null) =>
            new(Path, options, Clock, durability: durability);
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
    }
    private sealed class ReplaceFault(bool after) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier actual = new();
        public void FlushFileAndParentDirectory(string path) => actual.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => actual.FlushParentDirectory(path);
        public void ReplaceFile(string temporary, string final)
        { if (after) actual.ReplaceFile(temporary, final); throw new IOException("Injected replacement boundary failure."); }
    }
}
