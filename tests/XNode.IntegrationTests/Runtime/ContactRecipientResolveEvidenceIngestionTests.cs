using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.DependencyInjection;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactRecipientResolveEvidenceIngestionTests
{
    private static readonly byte[] NetworkId = Bytes(16, 0x11);
    private static readonly byte[] Locator = Bytes(32, 0x51);

    [Fact]
    public void IngestionContractRequiresAuthenticatedOpenedOnionResponse()
    {
        var method = typeof(IPrivacyRoutedContactRecipientResolveEvidenceIngestion)
            .GetMethod(nameof(IPrivacyRoutedContactRecipientResolveEvidenceIngestion.ObserveAsync));

        Assert.NotNull(method);
        Assert.Equal(typeof(ReadOnlyMemory<byte>),
            method.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(PrivacyRoutingOpenedResponse),
            method.GetParameters()[1].ParameterType);
        Assert.DoesNotContain(
            typeof(IPrivacyRoutedContactRecipientResolveEvidenceIngestion).GetMethods(),
            candidate => candidate.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(VerifiedCanonicalOnionRequest)));
        Assert.DoesNotContain(
            typeof(IPrivacyRoutedContactRecipientResolveEvidenceIngestion).GetMethods(),
            candidate => candidate.GetParameters().Count(parameter =>
                parameter.ParameterType == typeof(ReadOnlyMemory<byte>)) > 1);
    }

    [Fact]
    public async Task NonSuccessAuthenticatedXis1DoesNotReachDurableOwner()
    {
        var exactXiq1 = Request();
        var authenticated = Authenticated(exactXiq1);
        var exactXis1 = Xis1Codec.Encode(
            exactXiq1,
            Xis1Status.NotFound,
            ContactServiceMutationOutcome.None,
            11,
            0,
            ContactServicePaddingClass.Bytes256,
            []);
        var owner = new RecordingOwner();
        var ingestion = new PrivacyRoutedContactRecipientResolveEvidenceIngestion(owner);

        await ingestion.ObserveAsync(
            "DID1"u8.ToArray(), Opened(authenticated, exactXis1), default);

        Assert.Equal(0, owner.Calls);
    }

    [Fact]
    public async Task NetworkMutationAfterCapabilityMintCannotReachDurableOwner()
    {
        var exactXiq1 = Request();
        var authenticated = Authenticated(exactXiq1);
        SetField(authenticated.Network, "_networkId", Bytes(16, 0x12));
        var exactXis1 = Xis1Codec.Encode(
            exactXiq1,
            Xis1Status.NotFound,
            ContactServiceMutationOutcome.None,
            11,
            0,
            ContactServicePaddingClass.Bytes256,
            []);
        var owner = new RecordingOwner();
        var ingestion = new PrivacyRoutedContactRecipientResolveEvidenceIngestion(owner);

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await ingestion.ObserveAsync(
                "DID1"u8.ToArray(), Opened(authenticated, exactXis1), default));

        Assert.Equal(0, owner.Calls);
    }

    [Fact]
    public void OneTimeEvidenceRequiresCommittedClaimShape()
    {
        var uncommitted = Result(
            ContactServiceMutationOutcome.None,
            field22Bytes: 8,
            field23Bytes: 193);
        Assert.Throws<InvalidDataException>(() =>
            PrivacyRoutedContactRecipientResolveEvidenceIngestion.EnsureResultCanFeed(
                ContactRecipientResolveEvidenceKind.OneTime, uncommitted));

        var committed = Result(
            ContactServiceMutationOutcome.DurablyCommitted,
            field22Bytes: 8,
            field23Bytes: 193);
        PrivacyRoutedContactRecipientResolveEvidenceIngestion.EnsureResultCanFeed(
            ContactRecipientResolveEvidenceKind.OneTime, committed);
    }

    [Fact]
    public void PermanentEvidenceRejectsConsumingClaimShape()
    {
        var permanent = Result(
            ContactServiceMutationOutcome.None,
            field22Bytes: 193,
            field23Bytes: 0);
        PrivacyRoutedContactRecipientResolveEvidenceIngestion.EnsureResultCanFeed(
            ContactRecipientResolveEvidenceKind.Permanent, permanent);

        var consuming = Result(
            ContactServiceMutationOutcome.DurablyCommitted,
            field22Bytes: 8,
            field23Bytes: 193);
        Assert.Throws<InvalidDataException>(() =>
            PrivacyRoutedContactRecipientResolveEvidenceIngestion.EnsureResultCanFeed(
                ContactRecipientResolveEvidenceKind.Permanent, consuming));
    }

    [Fact]
    public void ExactAddressKindAcceptsOnlyCanonicalDid1OrDia1()
    {
        var did1 = ApplicationCoreCodec.AuthorDid1(
            Bytes(32, 0x61), Bytes(16, 0x62)).CanonicalBytes.ToArray();
        var dia1 = Dia1();

        Assert.Equal(
            ContactRecipientResolveEvidenceKind.Permanent,
            PrivacyRoutedContactRecipientResolveEvidenceIngestion.ExactAddressKind(did1));
        Assert.Equal(
            ContactRecipientResolveEvidenceKind.OneTime,
            PrivacyRoutedContactRecipientResolveEvidenceIngestion.ExactAddressKind(dia1));

        Assert.Throws<ApplicationCoreFormatException>(() =>
            PrivacyRoutedContactRecipientResolveEvidenceIngestion.ExactAddressKind(
                [.. did1, 0]));
        dia1[^1] = 0;
        Assert.Throws<ContactFormatException>(() =>
            PrivacyRoutedContactRecipientResolveEvidenceIngestion.ExactAddressKind(dia1));
    }

    private static byte[] Request() => Xiq1Codec.Encode(
        NetworkId,
        Bytes(32, 0x21),
        Bytes(32, 0x31),
        Bytes(32, 0x41),
        10,
        20,
        Locator,
        0,
        Xiq1AntiSpamTokenType.None,
        ReadOnlySpan<byte>.Empty,
        ContactServicePaddingClass.Bytes256);

    private static VerifiedCanonicalOnionRequest Authenticated(byte[] exactXiq1)
    {
        var network = (VerifiedOnionNetworkContext)RuntimeHelpers.GetUninitializedObject(
            typeof(VerifiedOnionNetworkContext));
        SetField(network, "_networkId", NetworkId.ToArray());
        return OnionTerminalPayloadVerifierV1.VerifyRequest(
            network, OnionOperation.ContactResolve, exactXiq1);
    }

    private static PrivacyRoutingOpenedResponse Opened(
        VerifiedCanonicalOnionRequest request,
        byte[] exactXis1)
    {
        var authenticated = OnionTerminalPayloadVerifierV1.VerifySuccess(
            request, exactXis1);
        var opened = (PrivacyRoutingOpenedResponse)RuntimeHelpers.GetUninitializedObject(
            typeof(PrivacyRoutingOpenedResponse));
        SetField(opened, "<Result>k__BackingField", authenticated);
        return opened;
    }

    private static Xis1Result Result(
        ContactServiceMutationOutcome outcome,
        int field22Bytes,
        int field23Bytes)
    {
        var result = (Xis1Result)RuntimeHelpers.GetUninitializedObject(typeof(Xis1Result));
        SetField(result, "<Status>k__BackingField", Xis1Status.Success);
        SetField(result, "<MutationOutcome>k__BackingField", outcome);
        SetField(result, "fields", new Dictionary<ushort, byte[]>
        {
            [22] = new byte[field22Bytes],
            [23] = new byte[field23Bytes]
        });
        return result;
    }

    private static byte[] Dia1() => Record(
        ProtocolMagic.DIA1,
        [
            Bytes(16, 0x11),
            Bytes(32, 0x21),
            [2],
            UInt16(1),
            Bytes(16, 0x31),
            Bytes(32, 0x41),
            Bytes(32, 0x51),
            UInt64(500),
            UInt16(1)
        ]);

    private static byte[] Record(string magic, IReadOnlyList<byte[]> fields)
    {
        var encoded = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic, encoded);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                encoded.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(
                encoded.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(encoded, offset);
            offset += fields[index].Length;
        }
        return encoded;
    }

    private static byte[] UInt16(ushort value)
    {
        var encoded = new byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        return encoded;
    }

    private static byte[] UInt64(ulong value)
    {
        var encoded = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

    private static void SetField(object target, string name, object value)
    {
        for (var type = target.GetType(); type is not null; type = type.BaseType)
        {
            var field = type.GetField(
                name,
                BindingFlags.Instance | BindingFlags.NonPublic);
            if (field is not null)
            {
                field.SetValue(target, value);
                return;
            }
        }
        throw new InvalidOperationException($"Field {name} was not found.");
    }

    private static byte[] Bytes(int length, byte fill) =>
        Enumerable.Repeat(fill, length).ToArray();

    private sealed class RecordingOwner : IContactRouteRecipientResolveEvidenceOwner
    {
        public int Calls { get; private set; }

        public ValueTask ObserveAsync(
            ContactRecipientResolveEvidenceSubmission submission,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.CompletedTask;
        }
    }
}
