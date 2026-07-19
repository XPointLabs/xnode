namespace XNode.ProfileGenerator.Tests;

public sealed class BoundsAndMalformedTests
{
    [Fact]
    public void IndividualComponentAndComponentCountBounds_AreExact()
    {
        var exact = new byte[ProfileComposerLimits.MaximumComponentBytes];
        _ = new ProfileAssemblyInput(exact, [], exact, []);
        Assert.Throws<ProfileContractException>(() =>
            new ProfileAssemblyInput(
                new byte[ProfileComposerLimits.MaximumComponentBytes + 1],
                [],
                exact,
                []));

        var maximumBridges = Enumerable.Range(
                0,
                ProfileComposerLimits.MaximumComponents - ProfileComposerLimits.RequiredNonBridgeComponents)
            .Select(static _ => (ReadOnlyMemory<byte>)new byte[1])
            .ToArray();
        _ = new ProfileAssemblyInput(
            (ReadOnlyMemory<byte>)new byte[] { 1 },
            [],
            (ReadOnlyMemory<byte>)new byte[] { 1 },
            maximumBridges);
        Assert.Throws<ProfileContractException>(() =>
            new ProfileAssemblyInput(
                (ReadOnlyMemory<byte>)new byte[] { 1 },
                [],
                (ReadOnlyMemory<byte>)new byte[] { 1 },
                maximumBridges.Append((ReadOnlyMemory<byte>)new byte[1])));
    }

    [Fact]
    public void FileAndQrBounds_AreExact()
    {
        Assert.True(ProfileComposerLimits.IsFilePayloadLengthAllowed(
            ProfileComposerLimits.MaximumFilePayloadBytes));
        Assert.False(ProfileComposerLimits.IsFilePayloadLengthAllowed(
            ProfileComposerLimits.MaximumFilePayloadBytes + 1));
        Assert.True(ProfileComposerLimits.IsQrTextLengthAllowed(
            ProfileComposerLimits.MaximumQrTextCharacters));
        Assert.False(ProfileComposerLimits.IsQrTextLengthAllowed(
            ProfileComposerLimits.MaximumQrTextCharacters + 1));
        Assert.True(ProfileComposerLimits.IsDerivedLabelLengthAllowed(
            new string('x', ProfileComposerLimits.MaximumDerivedLabelUtf8Bytes)));
        Assert.False(ProfileComposerLimits.IsDerivedLabelLengthAllowed(
            new string('x', ProfileComposerLimits.MaximumDerivedLabelUtf8Bytes + 1)));
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileInspector.Inspect(
                new byte[ProfileComposerLimits.MaximumFilePayloadBytes + 1],
                TestOnlyProfileFixture.Options(),
                TestOnlyProfileFixture.SignatureScheme()));
    }

    [Fact]
    public void InspectorRejectsUnknownVersionTrailingReorderingDuplicatesAndNonMinimalLengths()
    {
        var document = DormantProfileComposer.Compose(
            TestOnlyProfileFixture.Input(),
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());
        var canonical = document.FilePayload.ToArray();

        AssertMalformed(Mutate(canonical, 4, 2));
        AssertMalformed([.. canonical, (byte)0]);
        var bodyOffset = BodyOffset(canonical);
        AssertMalformed(Mutate(canonical, bodyOffset, 2));

        var secondTypeOffset = NextComponentOffset(canonical, bodyOffset);
        AssertMalformed(Mutate(canonical, secondTypeOffset, 1));

        var nonMinimal = canonical.ToList();
        var lastLengthByte = 6;
        while ((nonMinimal[lastLengthByte] & 0x80) != 0)
            lastLengthByte++;
        nonMinimal[lastLengthByte] |= 0x80;
        nonMinimal.Insert(lastLengthByte + 1, 0);
        AssertMalformed(nonMinimal.ToArray());
    }

    [Fact]
    public void TruncationAndDeterministicFuzzCorpusFailClosed()
    {
        var canonical = DormantProfileComposer.Compose(
            TestOnlyProfileFixture.Input(),
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme()).FilePayload.ToArray();
        for (var length = 0; length < canonical.Length; length++)
            AssertMalformed(canonical.AsSpan(0, length).ToArray());

        var random = new Random(0x14c1);
        for (var iteration = 0; iteration < 300; iteration++)
        {
            var malformed = new byte[random.Next(0, 1024)];
            random.NextBytes(malformed);
            AssertMalformed(malformed);
        }
    }

    private static void AssertMalformed(byte[] value) =>
        Assert.Throws<ProfileContractException>(() =>
            DormantProfileInspector.Inspect(
                value,
                TestOnlyProfileFixture.Options(),
                TestOnlyProfileFixture.SignatureScheme()));

    private static int BodyOffset(byte[] value)
    {
        var offset = 6;
        while ((value[offset++] & 0x80) != 0)
        {
        }
        return offset;
    }

    private static int NextComponentOffset(byte[] value, int componentOffset)
    {
        var offset = componentOffset + 1;
        var length = 0;
        var shift = 0;
        byte current;
        do
        {
            current = value[offset++];
            length |= (current & 0x7f) << shift;
            shift += 7;
        } while ((current & 0x80) != 0);
        return offset + length;
    }

    private static byte[] Mutate(byte[] source, int offset, byte value)
    {
        var result = source.ToArray();
        result[offset] = value;
        return result;
    }
}
