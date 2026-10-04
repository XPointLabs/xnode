using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Sodium;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2OneTimePublicationTests
{
    [Fact]
    public async Task OwnedV4RequestBindsPublicLocatorWithoutExportingInvitationKey()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true, authorOneTimeObject: true);
        var request = fixture.ContactOwnedRequest;
        var exact = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
        var invitation = fixture.OneTimeContactObject!.ExactInvitation.ToArray();
        try
        {
            var dia = ContactCodec.Decode("DIA1", invitation);
            Assert.Equal(4, BinaryPrimitives.ReadUInt16BigEndian(exact));
            Assert.Equal((byte)2, request.PublicationKind);
            Assert.Equal(dia.Field(5).ToArray(), request.OneTimeLocator.ToArray());
            Assert.Equal(request.OneTimeLocator.ToArray(), exact.AsSpan(exact.Length - 84, 16).ToArray());
            Assert.Equal(fixture.OneTimeContactObject.LocatorHash.ToArray(), request.LocatorHash.ToArray());
            Assert.Equal(-1, exact.AsSpan().IndexOf(dia.Field(6).Span));
            Assert.Equal(-1, exact.AsSpan().IndexOf(invitation));
            Assert.Equal(exact, ContactPublicationAuthorityWireCodec.EncodeRequest(ContactPublicationAuthorityWireCodec.DecodeRequest(exact)));
            var unsigned = exact[..^64];
            BinaryPrimitives.WriteUInt32BigEndian(unsigned.AsSpan(4), checked((uint)unsigned.Length));
            var input = IndependentSigningInput(unsigned);
            var device = fixture.Freshness.CurrentCheckpoint!.Binding.Identity.ActiveDevices.Single().Certificate;
            Assert.True(PublicKeyAuth.VerifyDetached(request.PublisherSignature.ToArray(), input, device.DeviceEd25519PublicKey.ToArray()));
            Assert.Equal(input, ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(request));
            await DeepIdV2PublicationAuthorityAuthor.VerifyRequestAsync(fixture.ContactRoute, request);
            _ = await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(fixture.ContactRoute, request,
                fixture.ContactPublication.CanonicalBytes);
            var authorization = fixture.ContactPublication.Field(26).ToArray();
            Assert.Equal((byte)2, Field(authorization, 5)[0]);
            Assert.Equal(1u, fixture.ContactPublication.UsageLimit);
            Assert.Equal(SHA256.HashData(fixture.OneTimeContactObject.Closure.Bundle.CanonicalBytes.Span), Field(authorization, 7));
            using var manifest = JsonDocument.Parse(File.ReadAllText(FindManifest()));
            var machine = manifest.RootElement;
            Assert.Equal(ContactPublicationAuthorityWireCodec.Version, machine.GetProperty("envelopeVersion").GetInt32());
            Assert.Equal(ContactPublicationAuthorityWireCodec.MinimumRequestBytes, machine.GetProperty("minimumRequestBytes").GetInt32());
            Assert.Equal(ContactPublicationAuthorityWireCodec.MaximumRequestBytes, machine.GetProperty("maximumRequestBytes").GetInt32());
            Assert.Equal(ContactPublicationAuthorityWireCodec.RequestMediaType, machine.GetProperty("requestMediaType").GetString());
            Assert.Equal(16, machine.GetProperty("publicLocatorBytes").GetInt32());
            Assert.False(machine.GetProperty("runtimeActivation").GetBoolean());
            // This schema deliberately permits only const fields: check every
            // required property and reject extra metadata, without a second
            // generic schema grammar or an external test dependency.
            RequireClosedMetadata(machine, FindManifest());
            var vectorsPath = FindManifest().Replace(".registry.json", ".vectors.json", StringComparison.Ordinal);
            using var vectors = JsonDocument.Parse(File.ReadAllText(vectorsPath));
            RequireClosedMetadata(vectors.RootElement, vectorsPath);
            Assert.Equal(nameof(OwnedV4RequestBindsPublicLocatorWithoutExportingInvitationKey), vectors.RootElement.GetProperty("positive").GetString());
            Assert.Equal(nameof(ChangedPublicLocatorCannotReachWitnessCallbacks), vectors.RootElement.GetProperty("signatureTamper").GetString());
            Assert.Equal(nameof(ReusableEnvelopeRequiresZeroPublicOneTimeLocator), vectors.RootElement.GetProperty("kindMix").GetString());
            Assert.Equal(nameof(HostileV4FramingAndKindLocatorMixRejectBeforeAuthority), vectors.RootElement.GetProperty("hostileOwner").GetString());
        }
        finally { CryptographicOperations.ZeroMemory(invitation); }
    }

    private static void RequireClosedMetadata(JsonElement machine, string path)
    {
        using var schema = JsonDocument.Parse(File.ReadAllText(Path.ChangeExtension(path, ".schema.json")));
        var properties = schema.RootElement.GetProperty("properties");
        Assert.False(schema.RootElement.GetProperty("additionalProperties").GetBoolean());
        var required = schema.RootElement.GetProperty("required").EnumerateArray().Select(value => value.GetString()).ToArray();
        Assert.Equal(required.Length, machine.EnumerateObject().Count());
        Assert.Equal(required.Length, properties.EnumerateObject().Count());
        foreach (var name in required)
            Assert.True(JsonElement.DeepEquals(properties.GetProperty(name!).GetProperty("const"), machine.GetProperty(name!)));
    }

    [Fact]
    public async Task ChangedPublicLocatorCannotReachWitnessCallbacks()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true, authorOneTimeObject: true);
        var exact = ContactPublicationAuthorityWireCodec.EncodeRequest(fixture.ContactOwnedRequest);
        exact[exact.Length - 84] ^= 1;
        var forged = ContactPublicationAuthorityWireCodec.DecodeRequest(exact);
        var witnesses = fixture.Authority.WitnessKeys.Select(key => new NeverSignWitness(key.Id.ToArray())).ToArray();
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(
            fixture.ContactRoute, forged, witnesses));
        Assert.All(witnesses, witness => Assert.Equal(0, witness.Calls));
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(
            fixture.ContactRoute, forged, fixture.ContactPublication.CanonicalBytes));
    }

    [Theory]
    [InlineData("retired-v3")]
    [InlineData("retired-v2")]
    [InlineData("unknown-v5")]
    [InlineData("reserved")]
    [InlineData("truncated")]
    [InlineData("zero-one-time-locator")]
    [InlineData("trailing")]
    [InlineData("oversized")]
    public async Task HostileV4FramingAndKindLocatorMixRejectBeforeAuthority(string fault)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true, authorOneTimeObject: true);
        var exact = ContactPublicationAuthorityWireCodec.EncodeRequest(fixture.ContactOwnedRequest);
        using var vectors = JsonDocument.Parse(File.ReadAllText(FindManifest().Replace(".registry.json", ".vectors.json", StringComparison.Ordinal)));
        Assert.Contains(fault, vectors.RootElement.GetProperty("hostile").EnumerateArray().Select(value => value.GetString()));
        switch (fault)
        {
            case "retired-v3": BinaryPrimitives.WriteUInt16BigEndian(exact, 3); break;
            case "retired-v2": BinaryPrimitives.WriteUInt16BigEndian(exact, 2); break;
            case "unknown-v5": BinaryPrimitives.WriteUInt16BigEndian(exact, 5); break;
            case "reserved": exact[3] = 1; break;
            case "truncated": exact = exact[..^16]; break;
            case "zero-one-time-locator": exact.AsSpan(exact.Length - 84, 16).Clear(); break;
            case "trailing": exact = exact.Append((byte)0).ToArray(); break;
            case "oversized": exact = new byte[ContactPublicationAuthorityWireCodec.MaximumRequestBytes + 1]; break;
            default: throw new ArgumentOutOfRangeException(nameof(fault));
        }
        if (fault == "zero-one-time-locator") Assert.Throws<CryptographicException>(() => ContactPublicationAuthorityWireCodec.DecodeRequest(exact));
        else Assert.Throws<FormatException>(() => ContactPublicationAuthorityWireCodec.DecodeRequest(exact));
    }

    [Fact]
    public async Task ReusableEnvelopeRequiresZeroPublicOneTimeLocator()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var exact = ContactPublicationAuthorityWireCodec.EncodeRequest(fixture.ContactOwnedRequest);
        Assert.Equal(new byte[16], fixture.ContactOwnedRequest.OneTimeLocator.ToArray());
        exact[exact.Length - 84] = 1;
        Assert.Throws<CryptographicException>(() => ContactPublicationAuthorityWireCodec.DecodeRequest(exact));
    }

    private sealed class NeverSignWitness(byte[] id) : IXpa1PublicationAuthorizationWitnessSigner
    {
        internal int Calls;
        public ReadOnlyMemory<byte> WitnessId => id.ToArray();
        public ValueTask<ReadOnlyMemory<byte>> SignXpa1Async(ReadOnlyMemory<byte> input, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("Invalid publisher bytes must reject before signing."); }
    }
    private static string FindManifest()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var file = Path.Combine(directory.FullName, "docs", "survival-program", "releases", "v3.0.0", "specs", "contact-publication-v4.registry.json");
            if (File.Exists(file)) return file;
        }
        throw new FileNotFoundException("Frozen one-time publication manifest is absent.");
    }
    private static byte[] Field(byte[] record, int wanted)
    {
        var offset = 12;
        while (offset < record.Length)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(offset));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(record.AsSpan(offset + 4)));
            offset += 8;
            if (tag == wanted) return record.AsSpan(offset, length).ToArray();
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(wanted));
    }
    private static byte[] IndependentSigningInput(byte[] unsigned)
    {
        var domain = Encoding.ASCII.GetBytes("Deep/ContactResolver/V2/publication-publisher");
        var result = new byte[domain.Length + 7 + unsigned.Length];
        domain.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(domain.Length + 1), DeepIdV2Codec.Suite);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(domain.Length + 3), checked((uint)unsigned.Length));
        unsigned.CopyTo(result, domain.Length + 7);
        return result;
    }
}
