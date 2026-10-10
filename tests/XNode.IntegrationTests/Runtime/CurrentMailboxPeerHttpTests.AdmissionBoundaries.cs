using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData("retired-magic", 400, false)]
    [InlineData("body", 400, false)]
    [InlineData("role", 400, false)]
    [InlineData("selector", 504, true)]
    [InlineData("nonmember", 504, true)]
    [InlineData("profile-one", 504, true)]
    public async Task NativeIngressAdmissionBoundaryPreservesBothOwnersAndOriginalRequest(
        string fault, int status, bool readsAuthority)
    {
        await using var f = await Fixture.CreateAsync();
        using var services = NativeServices(f);
        var dispatcher = NativeDispatcher(services);
        var original = f.ClientStoreFrame();
        var hostile = original.ToArray();
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(original);
        var crypto = new SodiumMailboxCapabilityCrypto();
        var grant = decoded.Presentation.Grant;
        switch (fault)
        {
            case "retired-magic":
                // Negative input derived from the current producer, not an old
                // positive corpus or a compatibility reader.
                "MAU2"u8.CopyTo(hostile);
                break;
            case "body":
                hostile[^1] ^= 1;
                break;
            case "role":
                grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                    MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host,
                        MailboxCapabilityDomain.Retrieve, 0x52));
                hostile = Present(grant);
                break;
            case "selector":
                // Holder legitimately signs the changed presentation, but the
                // issuer signature does not authorize the altered selector.
                var selector = grant.SelectionInput.ToArray(); selector[0] ^= 1;
                hostile = Present(grant with { SelectionInput = selector });
                break;
            case "nonmember":
                // A genuinely issuer-signed grant may select another pair.
                // This local node must not admit it merely because it is a
                // member of the overall signed network projection.
                byte[]? otherSelector = null;
                for (var index = 1; index <= 256; index++)
                {
                    var candidate = SHA256.HashData(BitConverter.GetBytes(index));
                    var ranked = await f.Sender.Node.Host.RankReplicasAsync(candidate);
                    if (ranked.Take(2).Any(node => node.Span.SequenceEqual(f.Sender.Node.Node))) continue;
                    otherSelector = candidate; break;
                }
                Assert.NotNull(otherSelector);
                grant = crypto.SignGrant(grant with { SelectionInput = otherSelector },
                    Enumerable.Repeat((byte)0x31, 32).ToArray());
                await f.Sender.Node.Host.EnsureGrantCurrentAsync(MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant));
                hostile = Present(grant);
                break;
            case "profile-one":
                var policy = ContactCodec.Decode(f.Signed.MailboxAuthority.Span);
                var oldProfile = f.Signed.MailboxAuthority.ToArray();
                var profileOffset = 12 + Enumerable.Range(1, 8).Sum(tag => 8 + policy.Field(tag).Length) + 8;
                BinaryPrimitives.WriteUInt16BigEndian(oldProfile.AsSpan(profileOffset, 2), 1);
                Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(ContactCodec.Decode(oldProfile).Field(9).Span));
                // Profile rejection precedes root-signature validation; do not
                // mistake a bad signature for proof of a retired-profile fence.
                var rejection = Assert.Throws<CryptographicException>(() =>
                    MailboxAuthorityV2Verifier.Verify(f.Signed.Authority, oldProfile,
                        f.Signed.Freshness.TrustedLowerUnixSeconds, f.Signed.Freshness.TrustedUpperUnixSeconds));
                Assert.Equal("PMA2 does not authorize the current selection-bound mailbox algorithm.", rejection.Message);
                f.Signed.PublicationMailboxAuthorityOverride = oldProfile;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(fault));
        }

        var reads = f.Signed.PublicationReads;
        var senderReplay = f.Sender.Node.Replay.Diagnostics;
        var recipientReplay = f.Recipient.Node.Replay.Diagnostics;
        var senderState = AdmissionOwnerDigest(f.Sender.Node.DataRoot);
        var recipientState = AdmissionOwnerDigest(f.Recipient.Node.DataRoot);
        var result = await dispatcher.DispatchAsync(OnionOperation.Store, hostile, default);
        Assert.False(result.Success); Assert.Equal(status, result.StatusCode);
        Assert.Empty(result.CanonicalBody.ToArray());
        Assert.Equal(reads + (readsAuthority ? 1 : 0), f.Signed.PublicationReads);
        Assert.Equal(senderReplay, f.Sender.Node.Replay.Diagnostics);
        Assert.Equal(recipientReplay, f.Recipient.Node.Replay.Diagnostics);
        Assert.Equal(senderState, AdmissionOwnerDigest(f.Sender.Node.DataRoot));
        Assert.Equal(recipientState, AdmissionOwnerDigest(f.Recipient.Node.DataRoot));
        Assert.Empty(f.ExactIntents); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(0, f.Sender.Node.OutcomeCount); Assert.Equal(0, f.Recipient.Node.OutcomeCount);
        f.Signed.PublicationMailboxAuthorityOverride = null;
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());

        // Same exact current counter/body must remain usable after the refusal.
        // This distinguishes pre-reservation rejection from a consumed claim.
        var accepted = await dispatcher.DispatchAsync(OnionOperation.Store, original, default);
        Assert.True(accepted.Success); Assert.NotEmpty(accepted.CanonicalBody.ToArray());
        Assert.Equal(1, f.AllHttpRequests); Assert.Single(f.ExactIntents);
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());

        byte[] Present(MailboxAuthenticatedGrant value) => MailboxAuthenticatedClientRequestCodec.Encode(decoded with
        {
            Presentation = crypto.SignPresentation(value, decoded.Binding, decoded.Presentation.ReplayCounter,
                Enumerable.Repeat((byte)0x57, 32).ToArray())
        });
    }

    [Theory]
    [InlineData("expiry-boundary")]
    [InlineData("clock-rollback")]
    [InlineData("revoked")]
    public async Task NativeIngressAuthorityFenceRejectsBeforeEitherReplayOrMutation(string fault)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.ClientStoreFrame();
        var grant = MailboxAuthenticatedClientRequestCodec.Decode(exact).Presentation.Grant;
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
        if (fault == "revoked")
        {
            var prior = MailboxGrantRevocationStoreTests.Snapshot(f.Signed);
            await f.Sender.Node.Deposit.AdvanceAsync(f.Sender.Node.Host,
                MailboxGrantRevocationStoreTests.Snapshot(f.Signed, generation: 2, prior: prior,
                    serials: [grant.Serial.ToArray()]));
        }
        else if (fault == "expiry-boundary")
        {
            f.Signed.Sample = checked(f.Signed.Freshness.MonotonicSample +
                grant.ExpiresAtUnixSeconds - f.Signed.Freshness.TrustedUpperUnixSeconds);
            Assert.Equal(grant.ExpiresAtUnixSeconds, f.Signed.Freshness.TrustedUpperUnixSeconds +
                f.Signed.Sample - f.Signed.Freshness.MonotonicSample);
        }
        else if (fault == "clock-rollback") f.Signed.Sample = f.Signed.Freshness.MonotonicSample - 1;
        else throw new ArgumentOutOfRangeException(nameof(fault));

        var reads = f.Signed.PublicationReads;
        var sender = AdmissionOwnerDigest(f.Sender.Node.DataRoot);
        var recipient = AdmissionOwnerDigest(f.Recipient.Node.DataRoot);
        using var services = NativeServices(f);
        AssertUnknown(await NativeDispatcher(services).DispatchAsync(OnionOperation.Store, exact, default));
        Assert.True(f.Signed.PublicationReads > reads);
        Assert.Equal(sender, AdmissionOwnerDigest(f.Sender.Node.DataRoot));
        Assert.Equal(recipient, AdmissionOwnerDigest(f.Recipient.Node.DataRoot));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount);
        Assert.Equal(0, f.Recipient.Node.Replay.Diagnostics.ScopeCount);
        Assert.Equal(0, f.Sender.Node.OutcomeCount); Assert.Equal(0, f.Recipient.Node.OutcomeCount);
        Assert.Empty(f.ExactIntents); Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        // The complete native file inventory/content is unchanged from the
        // empty stores checked above. A revoked/expired authority must not be
        // restored or bypassed merely to inspect those stores afterwards.
        Assert.Equal(0, f.AllHttpRequests);
    }

    private static byte[] AdmissionOwnerDigest(string root)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .OrderBy(file => Path.GetRelativePath(root, file), StringComparer.Ordinal))
        {
            // Only an aggregate digest can enter failure evidence, never paths,
            // capabilities, protected records or application payloads.
            digest.AppendData(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetRelativePath(root, file))));
            if (Path.GetFileName(file) is ".replay.lock" or ".outcomes.lock" or ".adapter.lock" or ".lease")
            {
                // Exclusive owner locks are intentionally unreadable. Include
                // their inventory and require zero length; do not bypass locks
                // or exclude any durable replay/outcome/operation record.
                Assert.Equal(0, new FileInfo(file).Length);
                digest.AppendData(SHA256.HashData(Array.Empty<byte>()));
            }
            else digest.AppendData(SHA256.HashData(File.ReadAllBytes(file)));
        }
        return digest.GetHashAndReset();
    }
}
