using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using static XNode.IntegrationTests.Runtime.MailboxGrantRevocationStoreTests;

namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxEnrollmentCommandTests
{
    [Theory]
    [InlineData("missing")]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("extra")]
    [InlineData("relative")]
    public void InvalidArgumentsRejectBeforeConfigurationOrCustody(string fault)
    {
        string[] args = fault switch
        {
            "missing" => ["current-mailbox-enroll"],
            "unknown" => ["current-mailbox-enroll", "--unknown", "missing", "--retrieve-mgr1-file", "missing"],
            "duplicate" => ["current-mailbox-enroll", "--deposit-mgr1-file", "missing", "--deposit-mgr1-file", "missing"],
            "extra" => ["current-mailbox-enroll", "--deposit-mgr1-file", "missing", "--retrieve-mgr1-file", "missing", "--reset"],
            _ => ["current-mailbox-enroll", "--deposit-mgr1-file", "relative.mgr1", "--retrieve-mgr1-file", "relative.mgr1"]
        };
        Assert.Throws<ArgumentException>(() => CurrentMailboxEnrollmentCommand.ReadInputs(args));
    }

    [Fact]
    public async Task ExactBoundedInputsAreOwnedBeforeAnyNetworkCallbacks()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true);
        var root = Path.Combine(Path.GetTempPath(), "deep-enrollment-inputs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var depositPath = Path.Combine(root, "deposit.mgr1");
        var retrievePath = Path.Combine(root, "retrieve.mgr1");
        var deposit = Snapshot(signed);
        var retrieve = Snapshot(signed, MailboxCapabilityDomain.Retrieve);
        try
        {
            Write(depositPath, deposit); Write(retrievePath, retrieve);
            string[] args = ["current-mailbox-enroll", "--deposit-mgr1-file", depositPath, "--retrieve-mgr1-file", retrievePath];
            var owned = CurrentMailboxEnrollmentCommand.ReadInputs(args);
            Write(depositPath, new byte[327]); Write(retrievePath, new byte[327]);
            Assert.Equal(deposit, owned.Deposit); Assert.Equal(retrieve, owned.Retrieve);
            Assert.ThrowsAny<Exception>(() => CurrentMailboxEnrollmentCommand.ReadInputs(args));
            Write(depositPath, new byte[MailboxGrantRevocationV1Codec.MaximumBytes + 1]);
            Assert.Throws<InvalidDataException>(() => CurrentMailboxEnrollmentCommand.ReadInputs(args));
            Write(depositPath, deposit); Write(retrievePath, retrieve.Concat(new byte[] { 1 }).ToArray());
            Assert.ThrowsAny<Exception>(() => CurrentMailboxEnrollmentCommand.ReadInputs(args));
        }
        finally { Directory.Delete(root, true); }
    }

    private static void Write(string path, byte[] bytes)
    {
        using var file = new FileStream(path, FileMode.Create, FileAccess.Write);
        file.Write(bytes);
    }
}
