using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using static XNode.IntegrationTests.Runtime.MailboxGrantRevocationStoreTests;

namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxPolicySuccessorTests
{
    [Fact]
    public async Task SignedExactPredecessorAndIndependentIssuerRotationAreRequired()
    {
        using var f = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var old = f.MailboxAuthority.ToArray();
        await f.AdvancePublicNetworkAsync(rotateMailboxIssuers: true);
        CurrentMailboxPolicySuccessorCommand.ValidatePolicy(f.Authority, old, f.MailboxAuthority.Span);
        Assert.Throws<CryptographicException>(() => CurrentMailboxPolicySuccessorCommand.ValidatePolicy(f.Authority, old, old));
        var corrupt = old.ToArray(); corrupt[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => CurrentMailboxPolicySuccessorCommand.ValidatePolicy(f.Authority, corrupt, f.MailboxAuthority.Span));
        using var unchangedKeys = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var before = unchangedKeys.MailboxAuthority.ToArray(); await unchangedKeys.AdvancePublicNetworkAsync();
        Assert.Throws<CryptographicException>(() => CurrentMailboxPolicySuccessorCommand.ValidatePolicy(unchangedKeys.Authority, before, unchangedKeys.MailboxAuthority.Span));
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task PriorProtectedSnapshotKeepsItsOriginalRoleAndSignature(MailboxCapabilityDomain role)
    {
        using var f = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var floor = Snapshot(f, role);
        CurrentMailboxPolicySuccessorCommand.ValidatePriorFloor(f.MailboxAuthority.Span, floor, role);
        Assert.Throws<CryptographicException>(() => CurrentMailboxPolicySuccessorCommand.ValidatePriorFloor(f.MailboxAuthority.Span, floor,
            role == MailboxCapabilityDomain.Deposit ? MailboxCapabilityDomain.Retrieve : MailboxCapabilityDomain.Deposit));
        floor[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => CurrentMailboxPolicySuccessorCommand.ValidatePriorFloor(f.MailboxAuthority.Span, floor, role));
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task CompletedSuccessorReplayIsReadOnlyAndCannotReplaceOrRepairFloor(MailboxCapabilityDomain role)
    {
        using var f = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(f, role); var host = await Host(f); var initial = Snapshot(f, role);
        byte[] protectedFloor;
        await using (var store = files.Open())
        {
            await store.EnrollPolicySuccessorAsync(host, initial, default);
            protectedFloor = File.ReadAllBytes(files.Floor);
            await store.EnrollPolicySuccessorAsync(host, initial, default);
            Assert.Equal(protectedFloor, File.ReadAllBytes(files.Floor));
            await Assert.ThrowsAsync<CryptographicException>(() => store.EnrollPolicySuccessorAsync(host,
                Snapshot(f, role, generation: 2, prior: initial), default).AsTask());
        }
        await using (var reopened = files.Open())
        {
            await reopened.EnrollPolicySuccessorAsync(host, initial, default);
            Assert.Equal(protectedFloor, File.ReadAllBytes(files.Floor));
        }
        File.Delete(files.Floor);
        await using var partial = files.Open();
        await Assert.ThrowsAsync<InvalidDataException>(() => partial.EnrollPolicySuccessorAsync(host, initial, default).AsTask());
        Assert.False(File.Exists(files.Floor));
    }
}
