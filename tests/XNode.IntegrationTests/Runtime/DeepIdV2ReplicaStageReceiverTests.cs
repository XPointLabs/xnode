using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Http;
using Rebex.Security.Cryptography;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2ReplicaStageReceiverTests
{
    private static readonly byte[] Network = Bytes(16, 0x11);
    private static readonly byte[] Operation = Bytes(32, 0x12);
    private static readonly byte[] View = Bytes(32, 0x13);
    private static readonly byte[] PlacementHash = Bytes(32, 0x14);
    private static readonly byte[] Capability = Bytes(32, 0x35);
    private static readonly byte[] Local = Bytes(32, 0x15);
    private static readonly byte[] Remote = Bytes(32, 0x16);

    [Fact]
    public async Task AuthenticatedSelectedPeer_StagesExactV2SequenceAcrossReopen()
    {
        var root = Path.Combine(Path.GetTempPath(),
            "xnode-did2-replica-" + Guid.NewGuid().ToString("N"));
        var placement = Placement();
        var source = new FixedPlacement(placement);
        var node = new RouterNodeOptions
        {
            DataDirectory = root,
            RouterId = Convert.ToHexString(Local)
        };
        try
        {
            var receiver = new DeepIdV2ReplicaStageReceiver(node, source,
                new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
            var aggregate = Aggregate();
            var publisher = DeepIdV2Codec.DecodeDid2(Did2());
            var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
                aggregate, View, publisher.CanonicalBytes.Span,
                Bytes(DeepIdV2ContactAuthorizationCodec.CanonicalLength, 0xd1),
                Xps1());
            var first = Command(placement, publisher, fragments[0]);
            await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
                await receiver.ReceiveAsync(first,
                    RouterId.FromHex(Convert.ToHexString(Bytes(32, 0x17))),
                    default));
            var operationPath = Path.Combine(root, "did2-prekey-stage",
                Convert.ToHexString(Network), Convert.ToHexString(Operation));
            Assert.False(Directory.Exists(operationPath));

            foreach (var fragment in fragments)
            {
                var command = Command(placement, publisher, fragment);
                var wire = ContactReplicaWireCodec.Encode(command);
                var decoded = ContactReplicaWireCodec.DecodeRequest(wire);
                var response = await receiver.ReceiveAsync(decoded,
                    RouterId.FromHex(Convert.ToHexString(Remote)), default);
                Assert.Equal(command.CorrelationId.ToArray(),
                    response.CorrelationId.ToArray());
                Assert.Equal(Local, response.ReplicaId.ToArray());
                Assert.Single(response.Payload.ToArray());
            }

            using (var journal = new DeepIdV2PublicationJournal(operationPath,
                       Network, Operation, View, PlacementHash, Capability))
            {
                var committed = journal.ReadCommitted();
                Assert.NotNull(committed);
                Assert.Equal(aggregate, committed.Candidate!.CanonicalBytes.ToArray());
                Assert.Equal(publisher.CanonicalBytes.ToArray(),
                    committed.PublisherDid2!.CanonicalBytes.ToArray());
            }
            var replay = await receiver.ReceiveAsync(
                Command(placement, publisher, fragments[^1]),
                RouterId.FromHex(Convert.ToHexString(Remote)), default);
            Assert.Equal(new byte[] { 3 }, replay.Payload.ToArray());
            var finalCommand = Command(placement, publisher, fragments[^1])
                with { Operation = ContactReplicaRpcOperation.CommitDid2PreKeyPublication };
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await receiver.ReceiveAsync(finalCommand,
                    RouterId.FromHex(Convert.ToHexString(Remote)), default));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await receiver.ReceiveAsync(finalCommand with
                {
                    Payload = DeepIdV2ReplicaStagePayloadCodec.Encode(
                        publisher, fragments[0])
                }, RouterId.FromHex(Convert.ToHexString(Remote)), default));
            Assert.False(Directory.Exists(Path.Combine(root,
                "did2-prekey-commits")));
            Assert.Equal(fragments.Count + 2, source.Calls);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void StagingSwitch_RequiresPlacementAndUat()
    {
        var options = new DeepIdV2ReplicaStageOptions { Enabled = true };
        Assert.Throws<InvalidOperationException>(() => options.Validate(
            placementEnabled: false,
            developmentOrUat: true));
        Assert.Throws<InvalidOperationException>(() => options.Validate(
            placementEnabled: true,
            developmentOrUat: false));
        Assert.True(options.Validate(placementEnabled: true,
            developmentOrUat: true));
    }

    [Fact]
    public void OnionStageStatus_MapsDurableCandidateToStagedAck()
    {
        Assert.Equal([1], DeepIdV2ReplicaStagePayloadCodec
            .EncodeTerminalStageStatus(PublicationStageDisposition.Staged));
        Assert.Equal([1], DeepIdV2ReplicaStagePayloadCodec
            .EncodeTerminalStageStatus(PublicationStageDisposition.CandidateReady));
        Assert.Equal([3], DeepIdV2ReplicaStagePayloadCodec
            .EncodeTerminalStageStatus(PublicationStageDisposition.ExactReplay));
        Assert.Throws<InvalidDataException>(() =>
            DeepIdV2ReplicaStagePayloadCodec.EncodeTerminalStageStatus(
                PublicationStageDisposition.Incomplete));
    }

    [Fact]
    public async Task OnionTerminal_RequiresLocallyVerifiedPlacementBeforeStaging()
    {
        var root = Path.Combine(Path.GetTempPath(),
            "xnode-did2-terminal-" + Guid.NewGuid().ToString("N"));
        var source = new FixedPlacement(Placement());
        try
        {
            var receiver = new DeepIdV2ReplicaStageReceiver(new()
            {
                DataDirectory = root,
                RouterId = Convert.ToHexString(Local)
            }, source, new MailboxStorageSecurity(),
                new MailboxDurabilityBarrier());
            var dispatcher = new DeepIdV2ContactOnionDispatcher(receiver);
            var publisher = DeepIdV2Codec.DecodeDid2(Did2());
            var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
                Aggregate(), View, publisher.CanonicalBytes.Span,
                Bytes(DeepIdV2ContactAuthorizationCodec.CanonicalLength,
                    0xd1),
                Xps1());
            await Assert.ThrowsAsync<ContactServiceUnavailableException>(
                async () => await dispatcher.DispatchAsync(
                    ContactServiceOperation.ResolveDcr, fragments[0],
                    default));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await dispatcher.DispatchAsync(
                    ContactServiceOperation.PublishPreKeyInventory,
                    fragments[1], default));
            Assert.Equal(0, source.Calls);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await dispatcher.DispatchAsync(
                    ContactServiceOperation.PublishPreKeyInventory,
                    fragments[0], default));
            Assert.Equal(1, source.Calls);
            Assert.False(Directory.Exists(Path.Combine(root,
                "did2-prekey-stage", Convert.ToHexString(Network),
                Convert.ToHexString(Operation))));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StaleProjectionAndV1Operation_CannotStageOrCreateOperation()
    {
        var root = Path.Combine(Path.GetTempPath(),
            "xnode-did2-reject-" + Guid.NewGuid().ToString("N"));
        var current = Placement();
        var source = new FixedPlacement(current);
        try
        {
            var receiver = new DeepIdV2ReplicaStageReceiver(new()
            {
                DataDirectory = root,
                RouterId = Convert.ToHexString(Local)
            }, source, new MailboxStorageSecurity(),
                new MailboxDurabilityBarrier());
            var publisher = DeepIdV2Codec.DecodeDid2(Did2());
            var manifest = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
                Aggregate(), View, publisher.CanonicalBytes.Span,
                Bytes(DeepIdV2ContactAuthorizationCodec.CanonicalLength, 0xd1),
                Xps1())[0];
            var stale = ContactServicePlacementCapability.FromUntrustedProjection(
                ContactServiceRequestKind.PublishPreKeyInventory,
                Network, View, Bytes(32, 0x88), Capability, 7, 100_000,
                [Local, Remote]);
            var command = Command(stale, publisher, manifest);
            await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
                await receiver.ReceiveAsync(command,
                    RouterId.FromHex(Convert.ToHexString(Remote)), default));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await receiver.ReceiveAsync(command with
                {
                    Placement = current,
                    Operation = ContactReplicaRpcOperation.ApplyPreKeyPublication
                }, RouterId.FromHex(Convert.ToHexString(Remote)), default));
            Assert.Equal(1, source.Calls);
            Assert.False(Directory.Exists(Path.Combine(root,
                "did2-prekey-stage", Convert.ToHexString(Network),
                Convert.ToHexString(Operation))));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PeerHttpEnvelope_AuthenticatesBeforeV2DispatchAndRejectsReplay()
    {
        var now = DateTimeOffset.Parse("2026-09-27T10:00:00Z");
        var senderSeed = Bytes(32, 0x91);
        var recipientSeed = Bytes(32, 0x92);
        var senderSigner = new Ed25519();
        senderSigner.FromSeed(senderSeed);
        var recipientSigner = new Ed25519();
        recipientSigner.FromSeed(recipientSeed);
        var sender = RouterId.FromBytes(senderSigner.GetPublicKey());
        var recipient = RouterId.FromBytes(recipientSigner.GetPublicKey());
        var node = new RouterNodeOptions
        {
            RouterId = recipient.Value,
            Ed25519PrivateKey = Convert.ToHexStringLower(recipientSeed)
        };
        var command = new ContactReplicaRpcCommand(Placement(),
            ContactReplicaRpcOperation.StageDid2PreKeyPublication,
            Bytes(32, 0x75), Bytes(64, 0x76));
        var body = ContactReplicaWireCodec.Encode(command);
        var headers = ContactReplicaPeerAuthenticator.SignRequest(sender,
            recipient, Convert.ToHexStringLower(senderSeed),
            command.CorrelationId.Span, body, now);
        var receiver = new RecordingReceiver();
        var guard = new ContactReplicaReplayGuard(new()
        {
            ReplicaTimeoutSeconds = 5,
            ReplayCapacity = 100,
            ReplayTtlSeconds = 300
        });
        var options = new ContactServicePersistenceOptions
        {
            ReplicaTimeoutSeconds = 5,
            ReplayCapacity = 100,
            ReplayTtlSeconds = 300
        };

        var first = Context(body, headers);
        var accepted = await ContactReplicaHttpEndpoint.HandleCoreAsync(
            first, true, options, guard, receiver, node,
            new FixedClock(now), 8083, default);
        Assert.NotNull(accepted);
        Assert.Equal(1, receiver.Calls);
        Assert.Equal(sender, receiver.LastSender);

        var replay = await ContactReplicaHttpEndpoint.HandleCoreAsync(
            Context(body, headers), true, options, guard, receiver, node,
            new FixedClock(now), 8083, default);
        Assert.IsType<Microsoft.AspNetCore.Http.HttpResults.NotFound>(replay);
        Assert.Equal(1, receiver.Calls);
    }

    private static DefaultHttpContext Context(byte[] body,
        ContactReplicaAuthenticationHeaders headers)
    {
        var context = new DefaultHttpContext();
        context.Connection.LocalPort = 8083;
        context.Request.Scheme = "https";
        context.Request.Protocol = "HTTP/2";
        context.Request.Method = "POST";
        context.Request.ContentType = ContactReplicaHttpContract.MediaType;
        context.Request.ContentLength = body.Length;
        context.Request.Body = new MemoryStream(body);
        context.Request.Headers[ContactReplicaPeerAuthenticator.SenderHeader] =
            headers.SenderReplicaId;
        context.Request.Headers[ContactReplicaPeerAuthenticator.RecipientHeader] =
            headers.RecipientReplicaId;
        context.Request.Headers[ContactReplicaPeerAuthenticator.TimestampHeader] =
            headers.TimestampUnixMilliseconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
        context.Request.Headers[ContactReplicaPeerAuthenticator.NonceHeader] =
            headers.Nonce;
        context.Request.Headers[ContactReplicaPeerAuthenticator.CorrelationHeader] =
            headers.Correlation;
        context.Request.Headers[ContactReplicaPeerAuthenticator.SignatureHeader] =
            headers.Signature;
        return context;
    }

    private sealed class RecordingReceiver : IContactReplicaCommandReceiver
    {
        internal int Calls { get; private set; }
        internal RouterId LastSender { get; private set; }

        public ValueTask<ContactReplicaRpcResponse> ReceiveAsync(
            ContactReplicaRpcCommand command, RouterId authenticatedSender,
            CancellationToken cancellationToken)
        {
            Calls++;
            LastSender = authenticatedSender;
            return ValueTask.FromResult(new ContactReplicaRpcResponse(
                command.Operation, command.CorrelationId.ToArray(),
                Bytes(32, 0x92), new byte[] { 1 }));
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private static ContactReplicaRpcCommand Command(
        ContactServicePlacementCapability placement, ParsedDid2 publisher,
        byte[] fragment) => new(placement,
        ContactReplicaRpcOperation.StageDid2PreKeyPublication,
        Bytes(32, 0x75),
        DeepIdV2ReplicaStagePayloadCodec.Encode(publisher, fragment));

    private static ContactServicePlacementCapability Placement() =>
        ContactServicePlacementCapability.FromUntrustedProjection(
            ContactServiceRequestKind.PublishPreKeyInventory,
            Network, View, PlacementHash, Capability, 7, 100_000,
            [Local, Remote]);

    private sealed class FixedPlacement(ContactServicePlacementCapability value) :
        IDeepIdV2PreKeyPlacementSource
    {
        internal int Calls { get; private set; }

        public ValueTask<ContactServicePlacementCapability>
            MintPreKeyPublicationAsync(ParsedDid2 publisher,
                ReadOnlyMemory<byte> serviceCapability,
                CancellationToken cancellationToken)
        {
            Calls++;
            Assert.Equal(Capability, serviceCapability.ToArray());
            Assert.Equal(Did2(), publisher.CanonicalBytes.ToArray());
            return ValueTask.FromResult(value);
        }
    }

    private static byte[] Did2() => DeepIdV2Codec.AuthorDid2(
        Bytes(32, 0xa1), Bytes(1952, 0xa2), Bytes(16, 0xa3))
        .CanonicalBytes.ToArray();

    private static byte[] Xps1()
    {
        ReadOnlyMemory<byte>[] fields =
        [
            Network, Capability, Bytes(32, 0x21),
            Reference("DPD1", Bytes(32, 0x25)), Be64(1), new byte[32],
            Be16(DeepIdV2Codec.Suite), Be16(32), Be16(1), Be64(100),
            Be64(100_000)
        ];
        return DeepIdV2PreKeyServiceCodec.Encode(fields, Bytes(64, 0xe1));
    }

    private static byte[] Aggregate()
    {
        var oneTime = DeepIdV2Dpk2Codec.Decode(DeepIdV2Dpk2Codec.Encode(
            Record(Dpk2PrekeyKind.OneTime)));
        var lastResort = DeepIdV2Dpk2Codec.Decode(DeepIdV2Dpk2Codec.Encode(
            Record(Dpk2PrekeyKind.LastResort)));
        ReadOnlyMemory<byte>[] fields =
        [
            Network, Capability, Bytes(32, 0x21),
            Reference("DPD1", Bytes(32, 0x25)), Be64(1),
            Reference("XPS1", Bytes(32, 0x45)), Be64(1),
            new byte[32], Be16(32), Bytes(32, 0x65),
            lastResort.ExactHash, Bytes(32, 0x20),
            Reference("DRS1", Bytes(32, 0x85)), Be64(100), Be64(100_000)
        ];
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(
            DeepIdV2PreKeyManifestCodec.Encode(fields, Bytes(64, 0x95)));
        return DeepIdV2PreKeyPublicationCodec.Encode(Network, Operation,
            PlacementHash, manifest, Enumerable.Repeat(oneTime, 32).ToArray(),
            lastResort);
    }

    private static Dpk2Record Record(Dpk2PrekeyKind kind) => new(
        Network, Bytes(32, 0x22), Bytes(32, 0x21), 1,
        Reference("DPD1", Bytes(32, 0x25)), 1, Bytes(32, 0x20),
        1, 1, Bytes(32, 0x26), 1, 100, 100, 100_000,
        Bytes(32, 0x27), Bytes(32, 0x28), Bytes(32, 0x29),
        Bytes(64, 0x30),
        kind == Dpk2PrekeyKind.OneTime ? Bytes(32, 0x31) : [],
        kind == Dpk2PrekeyKind.OneTime ? Bytes(32, 0x32) : [],
        Bytes(32, 0x33), Bytes(1184, 0x34), kind,
        kind == Dpk2PrekeyKind.LastResort ? (ushort)1 : (ushort)0,
        Bytes(64, 0x36), Bytes(64, 0x37));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static byte[] Be16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] Be64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Reference(string magic, byte[] hash)
    {
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4),
            magic == "XPS1" ? (ushort)2 : (ushort)1);
        hash.CopyTo(output, 6);
        return output;
    }
}
