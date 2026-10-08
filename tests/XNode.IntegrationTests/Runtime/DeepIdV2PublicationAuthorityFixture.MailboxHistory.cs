using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace XNode.IntegrationTests.Runtime;

internal sealed partial class DeepIdV2PublicationAuthorityFixture
{
    // Native key/floor enrollment can consume the short initial PMT lease in
    // a loaded full suite. Reverify the same signed closure under the fixture's
    // current monotonic reading immediately before the first native operation.
    // This changes neither signed intervals nor the verifier's lease lifetime.
    internal async Task RefreshInitialMailboxLeaseAsync()
    {
        var original = ContactCodec.Decode("PMT2", Projection.Span);
        if (BinaryPrimitives.ReadUInt64BigEndian(original.Field(2).Span) != 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(original.Field(12).Span) != ShortMailboxProjectionExpiry)
            throw new InvalidOperationException("This refresh requires the initial short projection fixture.");
        var history = OnionNetworkProtectedHistoryCodec.Encode(NetworkContext);
        NetworkContext = await VerifyHistoryAsync(history);
    }

    // Test-owned threshold ceremony. All resulting capabilities still come
    // from the public signed-lineage verifier, never a raw authority factory.
    internal async Task AdvanceMailboxProjectionAsync()
    {
        var original = ContactCodec.Decode("PMT2", Projection.Span);
        if (BinaryPrimitives.ReadUInt64BigEndian(original.Field(12).Span) != ShortMailboxProjectionExpiry)
            throw new InvalidOperationException("This ceremony requires the short original projection fixture.");
        var history = OnionNetworkProtectedHistoryCodec.Encode(NetworkContext);
        var exact = Projection.ToArray();
        ReplaceProjectionField(exact, 2, U64(checked(BinaryPrimitives.ReadUInt64BigEndian(original.Field(2).Span) + 1)));
        ReplaceProjectionField(exact, 3, original.CoreHash.Span);
        ReplaceProjectionField(exact, 6, U64(checked(BinaryPrimitives.ReadUInt64BigEndian(original.Field(6).Span) + 1)));
        ReplaceProjectionField(exact, 10, U64(ShortMailboxProjectionExpiry));
        ReplaceProjectionField(exact, 11, U64(ShortMailboxProjectionExpiry));
        ReplaceProjectionField(exact, 12, U64(1_500));
        using var w1 = new TestSigner(0x30); using var w2 = new TestSigner(0x31); using var w3 = new TestSigner(0x32);
        var candidate = SignProjection(exact, [w1, w2, w3]);
        // New independently signed directory evidence, not an unsigned clock
        // override or continued use of a proof from the initial operation.
        await RefreshDirectoryProofAsync(206, ShortMailboxProjectionExpiry + 6);
        var network = await VerifyHistoryProjectionAsync(candidate, history);
        Projection = candidate; NetworkContext = network;
    }

    private ValueTask<VerifiedOnionNetworkContext> VerifyHistoryProjectionAsync(
        ReadOnlyMemory<byte> projection, ReadOnlyMemory<byte> history) =>
        OnionNetworkContextVerifier.VerifyFromProtectedHistoryAsync(Authority, Freshness,
            [Policy], [View], [Head], Descriptors, [Projection, projection], history, new(this), default);
}
