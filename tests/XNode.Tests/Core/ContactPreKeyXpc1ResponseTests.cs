using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using Sodium;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class ContactPreKeyXpc1ResponseTests
{
    private static readonly DateTimeOffset Start = DateTimeOffset.FromUnixTimeSeconds(200);

    [Fact]
    public async Task TwoReplicaClaimProducesNormativeXpc1AndExactReplayAcrossRestart()
    {
        using var fixture = new Fixture();
        var requestBytes = fixture.RequestBytes;

        byte[] firstBytes;
        using (var running = fixture.Open())
        {
            firstBytes = (await running.Facade.DispatchAsync(
                ContactServiceFacadeOperation.ClaimPreKey,
                requestBytes)).ToArray();
            var first = Xpc1Codec.Decode(firstBytes, requestBytes);
            AssertClaim(fixture, first);

            fixture.Clock.UtcNow = Start.AddSeconds(1);
            var replay = (await running.Facade.DispatchAsync(
                ContactServiceFacadeOperation.ClaimPreKey,
                requestBytes)).ToArray();
            Assert.Equal(firstBytes, replay);
        }

        fixture.Clock.UtcNow = Start.AddSeconds(2);
        using var restarted = fixture.Open();
        var afterRestart = (await restarted.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ClaimPreKey,
            requestBytes)).ToArray();
        Assert.Equal(firstBytes, afterRestart);
        AssertClaim(fixture, Xpc1Codec.Decode(afterRestart, requestBytes));
    }

    [Theory]
    [InlineData("network")]
    [InlineData("device")]
    [InlineData("xps")]
    public async Task RequestBindingSubstitutionCannotReleaseDpk2(string field)
    {
        using var fixture = new Fixture();
        var request = fixture.BuildRequest(
            network: field == "network" ? Bytes(16, 0xa1) : null,
            device: field == "device" ? Bytes(32, 0xa2) : null,
            xps: field == "xps" ? Bytes(32, 0xa4) : null);

        using var running = fixture.Open();
        var response = await running.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ClaimPreKey,
            request);
        var decoded = Xpc1Codec.Decode(response.Span, request);

        Assert.DoesNotContain(decoded.Status, new[] { Xpc1Status.Claimed, Xpc1Status.Replay });
        Assert.False(response.Span.IndexOf(fixture.FirstExactDpk2) >= 0);
    }

    [Fact]
    public async Task ReceiptAuthoritySubstitutionFailsClosedAfterDurableClaim()
    {
        using var fixture = new Fixture(substituteSecondReceiptIdentity: true);
        using var running = fixture.Open();

        var response = await running.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ClaimPreKey,
            fixture.RequestBytes);
        var decoded = Xpc1Codec.Decode(response.Span, fixture.RequestBytes);

        Assert.Equal(Xpc1Status.OutcomeUnknown, decoded.Status);
        Assert.Equal(ContactServiceMutationOutcome.OutcomeUnknown, decoded.MutationOutcome);
        Assert.False(response.Span.IndexOf(fixture.FirstExactDpk2) >= 0);
    }

    [Fact]
    public async Task Xic1ReplicaSetSubstitutionFailsClosedAfterDurableClaim()
    {
        using var fixture = new Fixture(inventoryReplicaMismatch: true);
        using var running = fixture.Open();

        var response = await running.Facade.DispatchAsync(
            ContactServiceFacadeOperation.ClaimPreKey,
            fixture.RequestBytes);
        var decoded = Xpc1Codec.Decode(response.Span, fixture.RequestBytes);

        Assert.Equal(Xpc1Status.OutcomeUnknown, decoded.Status);
        Assert.Equal(ContactServiceMutationOutcome.OutcomeUnknown, decoded.MutationOutcome);
        Assert.False(response.Span.IndexOf(fixture.FirstExactDpk2) >= 0);
    }

    [Fact]
    public void MalformedDpk2CannotEnterVerifiedInventoryProjection()
    {
        Assert.ThrowsAny<Exception>(() => new Fixture(corruptFirstDpk2: true));
    }

    [Fact]
    public void PublicVerifierContractIsPresentWithoutServerRawKeyInputs()
    {
        var verify = Assert.Single(
            typeof(Xpc1PreKeyClaimReceiptVerifier).GetMethods(),
            static method => method.Name == "VerifyAsync");
        Assert.DoesNotContain(verify.GetParameters(), static parameter =>
            parameter.ParameterType == typeof(byte[])
            || parameter.ParameterType == typeof(ReadOnlyMemory<byte>)
            || parameter.ParameterType == typeof(bool));

        var inventoryCapability = typeof(VerifiedOpaquePreKeyInventory);
        Assert.False(inventoryCapability.IsPublic);
        Assert.Empty(inventoryCapability.GetConstructors());
        var projection = Assert.Single(inventoryCapability.GetMethods(
            BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly),
            static method => method.Name == "FromVerifiedPublication");
        Assert.Equal(
            [typeof(VerifiedPreKeyInventoryPublication)],
            projection.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        var install = Assert.Single(typeof(ContactPreKeyOpaqueStore).GetMethods(
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly),
            static method => method.Name == "InstallVerifiedInventory");
        Assert.Equal(
            [typeof(VerifiedOpaquePreKeyInventory)],
            install.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
    }

    private static void AssertClaim(Fixture fixture, Xpc1Result result)
    {
        Assert.Equal(Xpc1Status.Claimed, result.Status);
        Assert.Equal(ContactServiceMutationOutcome.DurablyCommitted, result.MutationOutcome);
        Assert.Equal((ulong)Start.ToUnixTimeSeconds(), result.ServerTimeUnixSeconds);
        Assert.Equal(fixture.FirstExactDpk2, result.Field(16).ToArray());
        Assert.Equal(fixture.FirstPreKeyId, result.Field(17).ToArray());
        Assert.Equal(fixture.Dmd1Hash, result.Field(19).ToArray());
        Assert.Equal(fixture.Drs1Reference, result.Field(20).ToArray());
        Assert.Equal(U64(Fixture.ServiceGeneration), result.Field(21).ToArray());
        Assert.Equal(U64(Fixture.PreKeyExpiry), result.Field(22).ToArray());
        Assert.Equal(U16(0), result.Field(23).ToArray());
        Assert.Equal(U64(1), result.Field(24).ToArray());

        var request = Xpk1Codec.Decode(fixture.RequestBytes);
        Assert.Equal(
            Xpc1Codec.ComputeClaimReceiptHash(
                request.RequestHash.Span,
                fixture.FirstExactDpk2,
                result.Field(26).Span,
                fixture.FirstPreKeyId,
                1,
                0),
            result.Field(18).ToArray());

        var exactDpk2Hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(
            Dpk2Codec.Decode(fixture.FirstExactDpk2));
        var tuple = Join(
            request.RequestHash.ToArray(),
            exactDpk2Hash,
            Xpi1Codec.ComputeHash(result.Field(26).Span),
            fixture.FirstPreKeyId,
            U64(1),
            U16(0));
        var signatureInput = SignatureInput(
            "Deep/ContactResolver/V1/prekey-claim-commit",
            tuple);
        var receipts = result.Field(25).Span;
        Assert.Equal(fixture.ExactXpi1, result.Field(26).ToArray());
        Assert.Equal(U16(0), result.Field(27).ToArray());
        Assert.Equal(160, result.Field(28).Length);
        Assert.Equal(193, receipts.Length);
        Assert.Equal(2, receipts[0]);
        Assert.True(receipts.Slice(1, 32).SequenceCompareTo(receipts.Slice(97, 32)) < 0);
        for (var offset = 1; offset < receipts.Length; offset += 96)
        {
            Assert.True(PublicKeyAuth.VerifyDetached(
                receipts.Slice(offset + 32, 64).ToArray(),
                signatureInput,
                receipts.Slice(offset, 32).ToArray()));
        }
    }

    private sealed class Fixture : IDisposable
    {
        internal const ulong ServiceGeneration = 7;
        internal const ulong PreKeyExpiry = 230;
        private readonly string directory = Path.Combine(
            Path.GetTempPath(),
            "xnode-xpc1-response-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] firstReceiptSeed = Bytes(32, 0x31);
        private readonly byte[] secondReceiptSeed = Bytes(32, 0x32);
        private readonly VerifiedOpaquePreKeyInventory inventory;
        private readonly bool substituteSecondReceiptIdentity;
        private readonly bool corruptFirstDpk2;

        internal Fixture(
            bool substituteSecondReceiptIdentity = false,
            bool corruptFirstDpk2 = false,
            bool inventoryReplicaMismatch = false)
        {
            this.substituteSecondReceiptIdentity = substituteSecondReceiptIdentity;
            this.corruptFirstDpk2 = corruptFirstDpk2;
            Clock = new MutableClock(Start);
            NetworkId = Bytes(16, 0x11);
            ServiceCapability = Bytes(32, 0x12);
            DeviceId = Bytes(32, 0x13);
            Xps1Hash = Bytes(32, 0x15);
            Dmd1Hash = Bytes(32, 0x16);
            Drs1Reference = Reference("DRS1", 0x17);

            var oneTime = Enumerable.Range(0, ContactPreKeyStoreOptions.MinimumOneTimeOfferings)
                .Select(index => (ReadOnlyMemory<byte>)Offering(index, lastResort: false))
                .ToArray();
            var lastResort = Offering(0xff, lastResort: true);
            FirstExactDpk2 = oneTime[0].ToArray();
            FirstPreKeyId = Dpk2Codec.Decode(FirstExactDpk2).OneTimeX25519PrekeyId.ToArray();
            using var firstReplica = new LocalContactServiceReplicaReceiptAuthority(firstReceiptSeed);
            using var secondReplica = new LocalContactServiceReplicaReceiptAuthority(secondReceiptSeed);
            inventory = PreKeyInventoryTestCapability.Create(
                NetworkId, ServiceCapability, DeviceId, Reference("DPD1", 0x43),
                ServiceGeneration, Xps1Hash, Dmd1Hash, Drs1Reference,
                190, PreKeyExpiry, oneTime, lastResort,
                [firstReplica.ReplicaId,
                    inventoryReplicaMismatch ? Bytes(32, 0xee) : secondReplica.ReplicaId]);
            Dcb1Hash = Bytes(32, 0x14);
            ExactXpi1 = inventory.ExactXpi1.ToArray();
            RequestBytes = BuildRequest();
        }

        internal MutableClock Clock { get; }
        internal byte[] NetworkId { get; }
        internal byte[] ServiceCapability { get; }
        internal byte[] DeviceId { get; }
        internal byte[] Dcb1Hash { get; }
        internal byte[] Xps1Hash { get; }
        internal byte[] Dmd1Hash { get; }
        internal byte[] Drs1Reference { get; }
        internal byte[] FirstExactDpk2 { get; }
        internal byte[] FirstPreKeyId { get; }
        internal byte[] ExactXpi1 { get; }
        internal byte[] RequestBytes { get; }

        internal byte[] BuildRequest(
            byte[]? network = null,
            byte[]? device = null,
            byte[]? dcb = null,
            byte[]? xps = null) => Xpk1Codec.Encode(
                network ?? NetworkId,
                Bytes(32, 0x21),
                Bytes(32, 0x22),
                Bytes(32, 0x23),
                195,
                240,
                ServiceCapability,
                dcb ?? Dcb1Hash,
                xps ?? Xps1Hash,
                device ?? DeviceId,
                Bytes(32, 0x24));

        internal RunningFacade Open() => new(this);

        public void Dispose()
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        private byte[] Offering(int index, bool lastResort)
        {
            var dpk2 = BuildDpk2(index, lastResort);
            var exact = Dpk2Codec.Encode(dpk2);
            if (corruptFirstDpk2 && !lastResort && index == 0)
            {
                exact[0] ^= 0xff;
            }
            return exact;
        }

        private Dpk2Record BuildDpk2(int index, bool lastResort)
        {
            var device = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x41));
            var discriminator = checked((byte)(index & 0x1f));
            var oneTimeId = lastResort ? [] : Bytes(32, checked((byte)(0x50 + discriminator)));
            var oneTimePublic = lastResort ? [] : Bytes(32, checked((byte)(0x70 + discriminator)));
            Dpk2Record Create(byte[] signedX, byte[] mlKem, byte[] bundle) => new(
                NetworkId,
                Bytes(32, 0x42),
                DeviceId,
                3,
                Reference("DPD1", 0x43),
                5,
                Dmd1Hash,
                ServiceGeneration,
                1,
                Bytes(32, checked((byte)(0x90 + discriminator))),
                1,
                190,
                190,
                PreKeyExpiry,
                Bytes(32, 0x44),
                Bytes(32, 0x45),
                Bytes(32, 0x46),
                signedX,
                oneTimeId,
                oneTimePublic,
                Bytes(32, checked((byte)(0xb0 + discriminator))),
                Bytes(1184, checked((byte)(0xd0 + discriminator))),
                lastResort ? Dpk2PrekeyKind.LastResort : Dpk2PrekeyKind.OneTime,
                lastResort ? (ushort)4 : (ushort)0,
                mlKem,
                bundle);

            var unsigned = Create(new byte[64], new byte[64], new byte[64]);
            var signedX = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(unsigned),
                device.PrivateKey);
            var mlKem = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(unsigned),
                device.PrivateKey);
            var partial = Create(signedX, mlKem, new byte[64]);
            var bundle = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(partial),
                device.PrivateKey);
            return Create(signedX, mlKem, bundle);
        }

        internal sealed class RunningFacade : IDisposable
        {
            private readonly ContactPreKeyOpaqueStore firstStore;
            private readonly ContactPreKeyOpaqueStore secondStore;
            private readonly ContactResolverOpaqueStore firstResolver;
            private readonly ContactResolverOpaqueStore secondResolver;
            private readonly ContactPublicationAuthorizationSaga saga;
            private readonly LocalContactServiceReplicaReceiptAuthority firstAuthority;
            private readonly LocalContactServiceReplicaReceiptAuthority secondAuthority;

            internal RunningFacade(Fixture fixture)
            {
                var security = new TestStorageSecurity();
                var durability = new MailboxDurabilityBarrier();
                Directory.CreateDirectory(fixture.directory);
                firstStore = new ContactPreKeyOpaqueStore(
                    Path.Combine(fixture.directory, "prekey-a.state"),
                    clock: fixture.Clock,
                    storageSecurity: security,
                    durability: durability);
                secondStore = new ContactPreKeyOpaqueStore(
                    Path.Combine(fixture.directory, "prekey-b.state"),
                    clock: fixture.Clock,
                    storageSecurity: security,
                    durability: durability);
                Assert.Contains(firstStore.InstallVerifiedInventory(fixture.inventory).Disposition,
                    new[] { ContactPreKeyInventoryDisposition.Installed, ContactPreKeyInventoryDisposition.ExactReplay });
                Assert.Contains(secondStore.InstallVerifiedInventory(fixture.inventory).Disposition,
                    new[] { ContactPreKeyInventoryDisposition.Installed, ContactPreKeyInventoryDisposition.ExactReplay });

                firstResolver = new ContactResolverOpaqueStore(
                    Path.Combine(fixture.directory, "resolver-a.state"),
                    clock: fixture.Clock,
                    storageSecurity: security,
                    durability: durability);
                secondResolver = new ContactResolverOpaqueStore(
                    Path.Combine(fixture.directory, "resolver-b.state"),
                    clock: fixture.Clock,
                    storageSecurity: security,
                    durability: durability);
                saga = new ContactPublicationAuthorizationSaga(
                    Path.Combine(fixture.directory, "xpa-saga.state"),
                    Path.Combine(fixture.directory, "xpa-saga.key"),
                    security: security,
                    durability: durability);
                firstAuthority = new LocalContactServiceReplicaReceiptAuthority(fixture.firstReceiptSeed);
                secondAuthority = new LocalContactServiceReplicaReceiptAuthority(fixture.secondReceiptSeed);
                IContactServiceReplicaReceiptAuthority secondReceipt = fixture.substituteSecondReceiptIdentity
                    ? new SubstitutingReceiptAuthority(secondAuthority, firstAuthority)
                    : secondAuthority;
                Facade = new ContactServiceOpaqueFacade(
                    [
                        new ContactServiceReplicaBinding(
                            new ContactResolverStoreReplica(firstAuthority.ReplicaId.Span, firstResolver),
                            new ContactPreKeyStoreReplica(firstAuthority.ReplicaId.Span, firstStore),
                            firstAuthority),
                        new ContactServiceReplicaBinding(
                            new ContactResolverStoreReplica(secondAuthority.ReplicaId.Span, secondResolver),
                            new ContactPreKeyStoreReplica(secondAuthority.ReplicaId.Span, secondStore),
                            secondReceipt)
                    ],
                    new EmptyRouteSource(),
                    new AcceptedContext(),
                    new RejectAllContactPublicationAuthorizationVerifier(),
                    saga,
                    fixture.Clock);
            }

            internal ContactServiceOpaqueFacade Facade { get; }

            public void Dispose()
            {
                Facade.Dispose();
                saga.Dispose();
                firstResolver.Dispose();
                secondResolver.Dispose();
                firstStore.Dispose();
                secondStore.Dispose();
                firstAuthority.Dispose();
                secondAuthority.Dispose();
            }
        }
    }

    private sealed class SubstitutingReceiptAuthority(
        IContactServiceReplicaReceiptAuthority identity,
        IContactServiceReplicaReceiptAuthority signer) : IContactServiceReplicaReceiptAuthority
    {
        public ReadOnlyMemory<byte> ReplicaId => identity.ReplicaId;

        public async ValueTask<ContactServiceReplicaReceipt> IssueAsync(
            ContactServiceReplicaReceiptRequest request,
            CancellationToken cancellationToken)
        {
            var signed = await signer.IssueAsync(request, cancellationToken);
            return new ContactServiceReplicaReceipt(signed.ReplicaId, signed.Signature);
        }
    }

    private sealed class AcceptedContext : IContactRequestContextVerifier
    {
        public ValueTask<ContactRequestContextResult> VerifyAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> viewHash,
            ReadOnlyMemory<byte> placementHash,
            CancellationToken cancellationToken) => ValueTask.FromResult(
                new ContactRequestContextResult(
                    ContactRequestContextStatus.Accepted,
                    ReadOnlyMemory<byte>.Empty));
    }

    private sealed class EmptyRouteSource : IContactRouteClosureSource
    {
        public ValueTask<ReadOnlyMemory<byte>?> ReadAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken) => ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);
    }

    internal sealed class MutableClock(DateTimeOffset now) : IClock
    {
        internal DateTimeOffset UtcNow { get; set; } = now;
        DateTimeOffset IClock.UtcNow => UtcNow;
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }

    private static byte[] Reference(string magic, byte fill)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        value.AsSpan(6).Fill(fill);
        return value;
    }

    private static byte[] Bytes(int length, byte fill)
    {
        var value = new byte[length];
        value.AsSpan().Fill(fill);
        return value;
    }

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static byte[] SignatureInput(string domain, ReadOnlySpan<byte> value)
    {
        var label = System.Text.Encoding.ASCII.GetBytes(domain);
        var output = new byte[label.Length + 7 + value.Length];
        label.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(label.Length + 1), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(label.Length + 3),
            checked((uint)value.Length));
        value.CopyTo(output.AsSpan(label.Length + 7));
        return output;
    }
}
