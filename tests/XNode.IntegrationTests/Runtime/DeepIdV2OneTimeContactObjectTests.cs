using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Actual owned DID2/route/device authors; local object evidence, not publication/device E2E.</summary>
public sealed class DeepIdV2OneTimeContactObjectTests
{
    [Fact]
    public async Task OwnedSignedOneTimeObjectMatchesIndependentAeadAndExactRestore()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true);
        var contact = Assert.IsType<AuthoredDeepIdV2OneTimeContactObject>(fixture.OneTimeContactObject);
        var invitation = contact.ExactInvitation.ToArray();
        var protectedObject = contact.ProtectedDcr1.ToArray();
        try
        {
            var dia = ContactCodec.Decode("DIA1", invitation);
            Assert.Equal(225, invitation.Length);
            Assert.Equal((byte)2, fixture.ContactRoute.Invite.Field(9).Span[0]);
            Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(fixture.ContactRoute.Invite.Field(10).Span));
            Assert.Equal(10u, BinaryPrimitives.ReadUInt32BigEndian(contact.Closure.Bundle.Field(16).Span));
            Assert.Equal(SHA256.HashData(contact.Closure.Bundle.CanonicalBytes.Span), dia.Field(7).ToArray());
            Assert.Equal(contact.Closure.Bundle.Field(18).ToArray(), dia.Field(8).ToArray());
            Assert.Equal(contact.Closure.CanonicalBytes.Length + 40, protectedObject.Length);
            Assert.Equal(IndependentDomainHash("Deep/ContactResolver/V1/one-time-locator", dia.Field(5).ToArray()),
                contact.LocatorHash.ToArray());
            var key = dia.Field(6).ToArray(); var aad = Aad(invitation);
            byte[]? plaintext = null;
            try
            {
                plaintext = SecretAeadXChaCha20Poly1305.Decrypt(protectedObject[24..], protectedObject[..24], key, aad);
                Assert.Equal(contact.Closure.CanonicalBytes.ToArray(), plaintext);
            }
            finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(aad); if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext); }
            using var restored = await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(fixture.ContactRoute,
                contact.Closure.CanonicalBytes, invitation, protectedObject);
            Assert.Equal(invitation, restored.ExactInvitation.ToArray());
            Assert.Equal(protectedObject, restored.ProtectedDcr1.ToArray());
            Assert.Equal(contact.LocatorHash.ToArray(), restored.LocatorHash.ToArray());
            var exported = contact.ExactInvitation.ToArray(); exported[^1] ^= 1;
            Assert.Equal(invitation, contact.ExactInvitation.ToArray());
            CryptographicOperations.ZeroMemory(exported);
            Assert.Empty(typeof(AuthoredDeepIdV2OneTimeContactObject).GetConstructors());
            Assert.DoesNotContain(typeof(AuthoredDeepIdV2OneTimeContactObject).GetMethods(),
                method => method.Name is "Sign" or "Dispatch" or "Publish" or "Acknowledge" or "Redeem");
            contact.Dispose(); contact.Dispose();
            Assert.Throws<ObjectDisposedException>(() => contact.ExactInvitation);
            Assert.Throws<ObjectDisposedException>(() => contact.ProtectedDcr1);
            Assert.Throws<ObjectDisposedException>(() => contact.LocatorHash);
            Assert.Equal(invitation, restored.ExactInvitation.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(invitation); CryptographicOperations.ZeroMemory(protectedObject); }
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(5)] [InlineData(6)] [InlineData(7)] [InlineData(8)]
    public async Task ChangedInvitationCannotOpenOriginalCiphertext(int tag)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true);
        var contact = fixture.OneTimeContactObject!;
        var invitation = contact.ExactInvitation.ToArray();
        try
        {
            invitation[ValueOffset(invitation, tag)] ^= 1;
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(
                fixture.ContactRoute, contact.Closure.CanonicalBytes, invitation, contact.ProtectedDcr1));
            using var original = await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(fixture.ContactRoute,
                contact.Closure.CanonicalBytes, contact.ExactInvitation, contact.ProtectedDcr1);
            Assert.Equal(contact.ProtectedDcr1.ToArray(), original.ProtectedDcr1.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(invitation); }
    }

    [Theory]
    [InlineData(1)] [InlineData(7)] [InlineData(8)]
    public async Task ValidAeadWithWrongNetworkBundleOrExpiryStillRejectsBinding(int tag)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true);
        var contact = fixture.OneTimeContactObject!; var invitation = contact.ExactInvitation.ToArray();
        byte[]? ciphertext = null;
        try
        {
            invitation[ValueOffset(invitation, tag)] ^= 1;
            ciphertext = IndependentSeal(contact.Closure.CanonicalBytes.ToArray(), invitation);
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(
                fixture.ContactRoute, contact.Closure.CanonicalBytes, invitation, ciphertext));
        }
        finally { CryptographicOperations.ZeroMemory(invitation); if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext); }
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public async Task RetainedOneTimeObjectRejectsCiphertextFramingOrCorruption(int fault)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true);
        var contact = fixture.OneTimeContactObject!; var ciphertext = contact.ProtectedDcr1.ToArray();
        try
        {
            if (fault == 0) ciphertext[0] ^= 1;
            if (fault == 1) ciphertext[^1] ^= 1;
            if (fault == 2) ciphertext = ciphertext[..^1];
            if (fault == 3) ciphertext = ciphertext.Append((byte)0).ToArray();
            if (fault == 4) ciphertext = new byte[65_576];
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(
                fixture.ContactRoute, contact.Closure.CanonicalBytes, contact.ExactInvitation, ciphertext));
        }
        finally { CryptographicOperations.ZeroMemory(ciphertext); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task RestoreRechecksActualCurrentAuthorityAndPostAwaitClock(bool discontinuity)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true);
        var contact = fixture.OneTimeContactObject!;
        if (discontinuity)
        {
            fixture.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, fixture.Sample + 2));
            fixture.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, fixture.Sample + 1));
        }
        else fixture.Sample = fixture.Freshness.FreshnessDeadlineMonotonicSeconds;
        if (discontinuity)
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(
                fixture.ContactRoute, contact.Closure.CanonicalBytes, contact.ExactInvitation, contact.ProtectedDcr1));
        else
        {
            var error = await Assert.ThrowsAsync<AccountDirectoryFreshnessVerificationException>(async () =>
                await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(fixture.ContactRoute,
                    contact.Closure.CanonicalBytes, contact.ExactInvitation, contact.ProtectedDcr1));
            Assert.Equal("DirectoryFreshnessExpired", error.Code);
        }
    }

    [Fact]
    public async Task PermanentPublicationEnvelopeCannotAdoptOneTimeObjectAsReusable()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true);
        var contact = fixture.OneTimeContactObject!;
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(
            fixture.ContactRoute, contact.Closure.CanonicalBytes, contact.ExactInvitation, contact.ProtectedDcr1, cancelled.Token));
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
            fixture.ContactRoute, contact.Closure.CanonicalBytes, contact.ProtectedDcr1, fixture.ContactAddress.ResolverReadCapability));
    }

    [Fact]
    public async Task RestoreCannotSubstituteAnotherGenuineDid2Route()
    {
        using var original = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true);
        using var other = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true, rootMarker: 0x21);
        var contact = original.OneTimeContactObject!;
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(
            other.ContactRoute, contact.Closure.CanonicalBytes, contact.ExactInvitation, contact.ProtectedDcr1));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public async Task MalformedInvitationRejectsBeforeClockCallbacks(int fault)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorOneTimeObject: true);
        var contact = fixture.OneTimeContactObject!; var invitation = contact.ExactInvitation.ToArray();
        try
        {
            if (fault == 0) invitation[5] = 2;
            if (fault == 1) invitation[7] ^= 1;
            if (fault == 2) invitation = invitation[..^1];
            if (fault == 3) invitation = invitation.Append((byte)0).ToArray();
            if (fault == 4) BinaryPrimitives.WriteUInt32BigEndian(invitation.AsSpan(16, 4), uint.MaxValue);
            fixture.ClockReadings.Enqueue(new(DeepIdV2PublicationAuthorityFixture.Boot, fixture.Sample));
            if (fault is 0 or 1 or 4)
                await Assert.ThrowsAsync<ContactFormatException>(async () => await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(
                    fixture.ContactRoute, contact.Closure.CanonicalBytes, invitation, contact.ProtectedDcr1));
            else
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreOneTimeAsync(
                    fixture.ContactRoute, contact.Closure.CanonicalBytes, invitation, contact.ProtectedDcr1));
            Assert.Single(fixture.ClockReadings);
        }
        finally { CryptographicOperations.ZeroMemory(invitation); }
    }

    private static int ValueOffset(byte[] bytes, int wanted)
    {
        var offset = 12;
        for (var tag = 1; tag <= 9; tag++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset + 4, 4)));
            offset += 8; if (tag == wanted) return offset; offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(wanted));
    }
    private static byte[] Aad(byte[] invitation)
    { var aad = invitation.ToArray(); aad.AsSpan(ValueOffset(aad, 6), 32).Clear(); return aad; }
    private static byte[] IndependentSeal(byte[] plaintext, byte[] invitation)
    {
        var key = invitation.AsSpan(ValueOffset(invitation, 6), 32).ToArray();
        var aad = Aad(invitation); var nonce = RandomNumberGenerator.GetBytes(24);
        try { return nonce.Concat(SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, key, aad)).ToArray(); }
        finally { foreach (var value in new[] { key, aad, nonce, plaintext }) CryptographicOperations.ZeroMemory(value); }
    }
    private static byte[] IndependentDomainHash(string label, byte[] value)
    {
        var length = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        return SHA256.HashData(Encoding.ASCII.GetBytes(label).Concat(new byte[] { 0 }).Concat(length).Concat(value).ToArray());
    }
}
