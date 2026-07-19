namespace XNode.ProfileGenerator.Tests;

public sealed class CorrectiveBoundaryAndFuzzTests
{
    [Fact]
    public void ExactMaximumFileAndComponentCountAreCanonicalAndInspectable()
    {
        var input = FindExactPayload(
            ProfileComposerLimits.MaximumFilePayloadBytes,
            bridgeCount: ProfileComposerLimits.MaximumComponents -
                ProfileComposerLimits.RequiredNonBridgeComponents,
            contactsPerBridge: 8);
        var document = Compose(input);
        Assert.Equal(ProfileComposerLimits.MaximumFilePayloadBytes, document.FilePayload.Length);
        Assert.Equal(ProfileComposerLimits.MaximumComponents, document.ComponentCount);
        Assert.Null(document.QrText);

        var inspected = DormantProfileInspector.Inspect(
            document.FilePayload.Span,
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());
        Assert.Equal(document.FilePayload.ToArray(), inspected.FilePayload.ToArray());
        Assert.Equal(ProfileComposerLimits.MaximumComponents, inspected.ComponentCount);
    }

    [Theory]
    [InlineData(1_524, 2_048, true)]
    [InlineData(1_525, 0, false)]
    public void QrBoundaryUsesActualCanonicalProfileBytes(
        int exactFileBytes,
        int expectedQrCharacters,
        bool qrAvailable)
    {
        var document = Compose(FindExactPayload(exactFileBytes, bridgeCount: 1, contactsPerBridge: 1));
        Assert.Equal(exactFileBytes, document.FilePayload.Length);
        Assert.Equal(qrAvailable, document.QrText is not null);
        if (!qrAvailable)
            return;

        Assert.Equal(expectedQrCharacters, document.QrText!.Length);
        Assert.True(DormantProfileQr.TryDecode(document.QrText, out var decoded));
        Assert.Equal(document.FilePayload.ToArray(), decoded);
    }

    [Fact]
    public void StructuredMutationsOfEveryFramingAndTrustComponentFailClosed()
    {
        var canonical = Compose(TestOnlyProfileFixture.Input()).FilePayload.ToArray();
        var components = ComponentOffsets(canonical);
        Assert.Equal(4, components.Count);
        var offsets = new[]
        {
            0,
            4,
            5,
            6,
            components[0].TypeOffset,
            components[0].LengthOffset,
            components[0].PayloadOffset,
            components[0].PayloadOffset + 4,
            components[0].PayloadOffset + 12,
            components[1].TypeOffset,
            components[1].LengthOffset,
            components[1].PayloadOffset,
            components[1].PayloadOffset + 1,
            components[1].PayloadOffset + components[1].Length - 1,
            components[2].TypeOffset,
            components[2].LengthOffset,
            components[2].PayloadOffset,
            components[2].PayloadOffset + 12,
            components[2].PayloadOffset + components[2].Length - 1,
            components[3].TypeOffset,
            components[3].LengthOffset,
            components[3].PayloadOffset,
            components[3].PayloadOffset + 12,
            components[3].PayloadOffset + components[3].Length - 1
        };

        foreach (var offset in offsets.Distinct())
        {
            foreach (var mask in new byte[] { 0x01, 0x40, 0x80 })
            {
                var mutated = canonical.ToArray();
                mutated[offset] ^= mask;
                AssertMalformed(mutated);
            }
        }
    }

    private static ProfileAssemblyInput FindExactPayload(
        int target,
        int bridgeCount,
        int contactsPerBridge)
    {
        const int minimumContactLength = 32;
        const int maximumContactLength = 500;
        var lengths = Enumerable.Repeat(
            minimumContactLength,
            bridgeCount * contactsPerBridge).ToArray();
        for (var attempt = 0; attempt < 256; attempt++)
        {
            var input = TestOnlyProfileFixture.Input(
                bridgeCount: bridgeCount,
                contactsPerBridge: contactsPerBridge,
                exactContactLengths: lengths);
            var current = Compose(input).FilePayload.Length;
            if (current == target)
                return input;

            var delta = target - current;
            if (delta > 0)
            {
                var index = Array.FindIndex(lengths, value => value < maximumContactLength);
                Assert.True(index >= 0, $"Target {target} is above the reachable canonical maximum.");
                lengths[index] += Math.Min(delta, maximumContactLength - lengths[index]);
            }
            else
            {
                var index = Array.FindLastIndex(lengths, value => value > minimumContactLength);
                Assert.True(index >= 0, $"Target {target} is below the reachable canonical minimum.");
                lengths[index] -= Math.Min(-delta, lengths[index] - minimumContactLength);
            }
        }
        throw new Xunit.Sdk.XunitException($"Exact canonical payload {target} was not reached.");
    }

    private static DormantProfileDocument Compose(ProfileAssemblyInput input) =>
        DormantProfileComposer.Compose(
            input,
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());

    private static void AssertMalformed(byte[] value) =>
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileInspector.Inspect(
                value,
                TestOnlyProfileFixture.Options(),
                TestOnlyProfileFixture.SignatureScheme()));

    private static IReadOnlyList<ComponentOffset> ComponentOffsets(byte[] value)
    {
        var offset = 6;
        _ = ReadVarUInt(value, ref offset);
        var result = new List<ComponentOffset>(value[5]);
        for (var index = 0; index < value[5]; index++)
        {
            var typeOffset = offset++;
            var lengthOffset = offset;
            var length = ReadVarUInt(value, ref offset);
            result.Add(new ComponentOffset(typeOffset, lengthOffset, offset, length));
            offset += length;
        }
        Assert.Equal(value.Length, offset);
        return result;
    }

    private static int ReadVarUInt(byte[] value, ref int offset)
    {
        var result = 0;
        var shift = 0;
        byte current;
        do
        {
            current = value[offset++];
            result |= (current & 0x7f) << shift;
            shift += 7;
        } while ((current & 0x80) != 0);
        return result;
    }

    private sealed record ComponentOffset(
        int TypeOffset,
        int LengthOffset,
        int PayloadOffset,
        int Length);
}
