using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using Sodium;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed partial class DeepIdV2PublicationJournalTests
{
    [Fact]
    public void ClaimReservation_ExactReplaySurvivesRestartAndExpiryWithoutResigning()
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        var request = ClaimRequest(publication);
        byte[] tuple;
        using (var store = fixture.OpenInventoryStore(signer.PublicKey))
        {
            _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
            var reservation = Reserve(store, request, publication, input => Sign(input, signer));
            Assert.False(reservation.ExactReplay);
            tuple = reservation.Tuple.ToArray();
            Assert.Equal(DeepIdV2PreKeyClaimCommitment.CreateTuple(request.CanonicalBytes.Span,
                publication.OneTimeMembers[0].CanonicalBytes.Span,
                publication.Manifest.CanonicalBytes.Span, 1, 0), tuple);
        }
        using var reopened = fixture.OpenInventoryStore(signer.PublicKey);
        var replay = reopened.ReserveClaimProposal(request, publication.OneTimeMembers[0],
            publication.Manifest, 1, 0, 100_001, 100_002,
            _ => throw new InvalidOperationException("Replay must not sign or free expired keys."));
        Assert.True(replay.ExactReplay);
        Assert.Equal(tuple, replay.Tuple.ToArray());
        var returned = replay.Tuple.ToArray();
        returned[0] ^= 1;
        Assert.Equal(tuple, replay.Tuple.ToArray());
        Assert.Throws<InvalidOperationException>(() => Reserve(reopened,
            ClaimRequest(publication, 0x89), publication, input => Sign(input, signer), generation: 2));
    }

    [Fact]
    public void ClaimReservation_ChangedRequestOrProposalCannotReplaceExistingOperation()
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        using var store = fixture.OpenInventoryStore(signer.PublicKey);
        _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
        var request = ClaimRequest(publication);
        var first = Reserve(store, request, publication, input => Sign(input, signer));
        Assert.Throws<InvalidOperationException>(() => Reserve(store,
            ClaimRequest(publication, ephemeral: 0x88), publication, input => Sign(input, signer)));
        Assert.Throws<InvalidOperationException>(() => Reserve(store,
            request, publication, input => Sign(input, signer), generation: 2));
        Assert.Equal(first.Tuple.ToArray(), Reserve(store, request, publication,
            _ => throw new InvalidOperationException("Replay must not sign.")).Tuple.ToArray());
    }

    [Theory]
    [InlineData(99UL, 200UL)]
    [InlineData(200UL, 199UL)]
    [InlineData(200UL, 100_000UL)]
    public void ClaimReservation_InvalidTimeCannotActivateCustody(ulong lower, ulong upper)
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        using var store = fixture.OpenInventoryStore(signer.PublicKey);
        _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
        Assert.Throws<InvalidOperationException>(() => store.ReserveClaimProposal(
            ClaimRequest(publication), publication.OneTimeMembers[0], publication.Manifest,
            1, 0, lower, upper, input => Sign(input, signer)));
        Assert.False(File.Exists(Path.Combine(fixture.InventoryServicePath(), "claims.state")));
        Assert.False(File.Exists(Path.Combine(fixture.InventoryServicePath(), "claims-activated.marker")));
    }

    [Fact]
    public void ClaimReservation_UnpublishedInventoryAndWrongSignerDoNotReserve()
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var other = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa9));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        using var store = fixture.OpenInventoryStore(signer.PublicKey);
        Assert.Throws<UnauthorizedAccessException>(() => Reserve(store,
            ClaimRequest(publication), publication, input => Sign(input, signer)));
        _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
        Assert.Throws<CryptographicException>(() => Reserve(store,
            ClaimRequest(publication), publication, input => Sign(input, other)));
        Assert.False(File.Exists(Path.Combine(fixture.InventoryServicePath(), "claims-activated.marker")));
        Assert.False(Reserve(store, ClaimRequest(publication), publication,
            input => Sign(input, signer)).ExactReplay);
    }

    [Fact]
    public void ClaimReservation_LastResortCounterIsPersistentAndBounded()
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        using (var store = fixture.OpenInventoryStore(signer.PublicKey))
        {
            _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
            Assert.Throws<InvalidOperationException>(() => store.ReserveClaimProposal(
                ClaimRequest(publication), publication.LastResortMember, publication.Manifest,
                1, 1, 200, 201, input => Sign(input, signer)));
            _ = Reserve(store, ClaimRequest(publication, 0x89), publication, input => Sign(input, signer));
            var result = store.ReserveClaimProposal(ClaimRequest(publication),
                publication.LastResortMember, publication.Manifest, 2, 1, 200, 201,
                input => Sign(input, signer));
            Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(result.Tuple.Span[136..]));
        }
        using var reopened = fixture.OpenInventoryStore(signer.PublicKey);
        Assert.Throws<InvalidOperationException>(() => reopened.ReserveClaimProposal(
            ClaimRequest(publication, 0x88), publication.LastResortMember,
            publication.Manifest, 3, 1, 200, 201, input => Sign(input, signer)));
        Assert.Throws<CryptographicException>(() => reopened.ReserveClaimProposal(
            ClaimRequest(publication, 0x88), publication.LastResortMember,
            publication.Manifest, 3, 2, 200, 201, input => Sign(input, signer)));
    }

    [Fact]
    public void ClaimReservation_ConcurrentProposalsCannotReserveOneKeyTwice()
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        using var store = fixture.OpenInventoryStore(signer.PublicKey);
        _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
        var successes = 0;
        Parallel.For(0, 12, i =>
        {
            try
            {
                _ = Reserve(store, ClaimRequest(publication, checked((byte)(0x80 + i))),
                    publication, input => Sign(input, signer));
                Interlocked.Increment(ref successes);
            }
            catch (InvalidOperationException) { }
        });
        Assert.Equal(1, successes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClaimReservation_CrashAtReplaceRequiresReopenAndNeverReleasesKey(bool afterReplace)
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        var request = ClaimRequest(publication);
        using (var store = fixture.OpenInventoryStore(signer.PublicKey,
                   new CrashOnClaimReplace(afterReplace)))
        {
            _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
            Assert.Throws<IOException>(() => Reserve(store, request, publication, input => Sign(input, signer)));
            Assert.Throws<IOException>(() => Reserve(store, request, publication, input => Sign(input, signer)));
        }
        if (!afterReplace)
        {
            Assert.Throws<InvalidDataException>(() => fixture.OpenInventoryStore(signer.PublicKey));
            return;
        }
        using var reopened = fixture.OpenInventoryStore(signer.PublicKey);
        Assert.True(Reserve(reopened, request, publication,
            _ => throw new InvalidOperationException("Durable replay must not sign.")).ExactReplay);
        Assert.Throws<InvalidOperationException>(() => Reserve(reopened,
            ClaimRequest(publication, 0x88), publication, input => Sign(input, signer), generation: 2));
    }

    [Theory]
    [InlineData("deleted")]
    [InlineData("tampered")]
    [InlineData("trailing")]
    public void ClaimReservation_LostOrCorruptStateCannotBecomeFreshCustody(string mutation)
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        using (var store = fixture.OpenInventoryStore(signer.PublicKey))
        {
            _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
            _ = Reserve(store, ClaimRequest(publication), publication, input => Sign(input, signer));
        }
        var path = Path.Combine(fixture.InventoryServicePath(), "claims.state");
        if (mutation == "deleted") File.Delete(path);
        else
        {
            var bytes = File.ReadAllBytes(path);
            if (mutation == "tampered") bytes[100] ^= 1;
            else Array.Resize(ref bytes, bytes.Length + 1);
            File.WriteAllBytes(path, bytes);
        }
        Assert.Throws<InvalidDataException>(() => fixture.OpenInventoryStore(signer.PublicKey));
        Assert.True(File.Exists(Path.Combine(fixture.InventoryServicePath(), "fault.marker")));
        Assert.Throws<InvalidDataException>(() => fixture.OpenInventoryStore(signer.PublicKey));
    }

    private static DeepIdV2LocalClaimReservation Reserve(DeepIdV2InventoryCommitStore store,
        ParsedXpk1V2 request, ParsedXpp1V2 publication, Func<byte[], byte[]> sign,
        ulong generation = 1) => store.ReserveClaimProposal(request, publication.OneTimeMembers[0],
        publication.Manifest, generation, 0, 200, 201, sign);

    [Fact]
    public void ClaimReservation_SuccessorEpochDoesNotFreeReservedOneTimeIdOrResetLastResortCounter()
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var first = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        var successor = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate(operation: Bytes(32, 0x76),
            epoch: 2, predecessor: first.Manifest.ExactHash.ToArray()));
        using var store = fixture.OpenInventoryStore(signer.PublicKey);
        _ = store.CommitAuthorized(first, 200, input => Sign(input, signer));
        _ = Reserve(store, ClaimRequest(first, 0x89), first, input => Sign(input, signer));
        _ = store.ReserveClaimProposal(ClaimRequest(first), first.LastResortMember,
            first.Manifest, 2, 1, 200, 201, input => Sign(input, signer));
        _ = store.CommitAuthorized(successor, 201, input => Sign(input, signer));
        Assert.Throws<InvalidOperationException>(() => Reserve(store, ClaimRequest(successor, 0x88),
            successor, input => Sign(input, signer), generation: 3));
        Assert.Throws<InvalidOperationException>(() => store.ReserveClaimProposal(
            ClaimRequest(successor, 0x88), successor.LastResortMember, successor.Manifest,
            3, 1, 200, 201, input => Sign(input, signer)));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("offering-length")]
    [InlineData("retired-request")]
    [InlineData("count")]
    public void ClaimReservation_EvenLocallySignedMalformedStateIsQuarantined(string mutation)
    {
        using var fixture = new Fixture();
        var signer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xa8));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(Aggregate());
        using (var store = fixture.OpenInventoryStore(signer.PublicKey))
        {
            _ = store.CommitAuthorized(publication, 200, input => Sign(input, signer));
            _ = Reserve(store, ClaimRequest(publication), publication, input => Sign(input, signer));
        }
        var path = Path.Combine(fixture.InventoryServicePath(), "claims.state");
        var bytes = File.ReadAllBytes(path);
        switch (mutation)
        {
            case "generation": BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(90 + 438 + 560), 2); break;
            case "offering-length": BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(90 + 438 + 560 + 10), uint.MaxValue); break;
            case "retired-request": BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(90 + 4), 1); break;
            case "count": BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(86), uint.MaxValue); break;
        }
        var domain = Encoding.ASCII.GetBytes("Deep/XNode/V2/prekey-claim-reservations");
        var body = bytes[..^64];
        var digestInput = new byte[domain.Length + 5 + body.Length];
        domain.CopyTo(digestInput, 0);
        BinaryPrimitives.WriteUInt32BigEndian(digestInput.AsSpan(domain.Length + 1), (uint)body.Length);
        body.CopyTo(digestInput, domain.Length + 5);
        Sign(SHA256.HashData(digestInput), signer).CopyTo(bytes, bytes.Length - 64);
        File.WriteAllBytes(path, bytes);
        Assert.Throws<InvalidDataException>(() => fixture.OpenInventoryStore(signer.PublicKey));
        Assert.True(File.Exists(Path.Combine(fixture.InventoryServicePath(), "fault.marker")));
        Assert.Throws<InvalidDataException>(() => fixture.OpenInventoryStore(signer.PublicKey));
    }

    private static ParsedXpk1V2 ClaimRequest(ParsedXpp1V2 publication,
        byte operation = 0x87, byte ephemeral = 0x86) =>
        DeepIdV2PreKeyClaimRequestCodec.Decode(DeepIdV2PreKeyClaimRequestCodec.Encode(
            Network, Bytes(32, operation), View, publication.PlacementHash.Span,
            100, 100_000, publication.Manifest.Field(2).Span, Bytes(32, 0x85),
            publication.Manifest.Field(6).Span[6..], publication.Manifest.Field(3).Span,
            Bytes(32, ephemeral)));

    private static byte[] Sign(byte[] input, KeyPair signer) =>
        PublicKeyAuth.SignDetached(input, signer.PrivateKey);

    private sealed class CrashOnClaimReplace(bool afterReplace) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier inner = new();
        public void FlushFileAndParentDirectory(string path) => inner.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => inner.FlushParentDirectory(path);
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (Path.GetFileName(finalPath) != "claims.state")
            {
                inner.ReplaceFile(temporaryPath, finalPath);
                return;
            }
            if (afterReplace) inner.ReplaceFile(temporaryPath, finalPath);
            throw new IOException("Synthetic crash at the claim reservation replacement.");
        }
    }
}
