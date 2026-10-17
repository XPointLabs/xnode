namespace XNode.IntegrationTests.Runtime;

public sealed class ContactReplicaResourceBudgetTests
{
    [Fact]
    public void DefaultsGiveAuthenticatedLeafWorkHeadroomInsideOneBoundedComposite()
    {
        var options = new ContactServicePersistenceOptions();
        options.Validate();
        Assert.Equal(TimeSpan.FromSeconds(10), options.ReplicaTimeout);
        foreach (var operation in Enum.GetValues<ContactReplicaRpcOperation>())
            Assert.Equal(TimeSpan.FromSeconds(operation == ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim ? 25 : 10),
                options.ReplicaRequestBudget(operation));
        options.ReplicaTimeoutSeconds = 1;
        Assert.Equal(TimeSpan.FromSeconds(1), options.ReplicaRequestBudget(ContactReplicaRpcOperation.ReadCurrentDcr));
        Assert.Equal(TimeSpan.FromSeconds(4), options.ReplicaRequestBudget(ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim));
    }
}
