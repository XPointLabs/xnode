namespace XNode.IntegrationTests.Runtime;

// Real TLS/native custody uses the unchanged five-second peer budget. Unrelated
// fixture creation must not exhaust it before a functional ACK assertion. This
// isolates one collection, not the assembly or concurrent requests inside tests.
[CollectionDefinition(nameof(CurrentMailboxTlsCustodyCollection), DisableParallelization = true)]
public sealed class CurrentMailboxTlsCustodyCollection { }
