namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientOperationLedger
{
    // The memo owns its detached dictionaries and arrays. Strings and scalar-only
    // records are immutable; a caller may mutate its returned document without
    // modifying any later grammar reuse. No authority or replay decision lives here.
    internal static MailboxClientLedgerDocument CopyGrammarDocument(MailboxClientLedgerDocument source) => new(
        source.SchemaVersion, source.NextCoordinatorSequence, source.RetiredCursorFloor,
        new(source.NextCursorByMailbox, StringComparer.Ordinal),
        source.Operations.ToDictionary(pair => pair.Key,
            pair => pair.Value with { ExpectedReplicaIds = pair.Value.ExpectedReplicaIds.ToArray() }, StringComparer.Ordinal),
        source.AckOperations.ToDictionary(pair => pair.Key,
            pair => pair.Value with
            {
                ExpectedReplicaIds = pair.Value.ExpectedReplicaIds.ToArray(),
                Items = pair.Value.Items.ToArray()
            }, StringComparer.Ordinal),
        new(source.ClientReplayFloors, StringComparer.Ordinal),
        new(source.PeerReplayFloors, StringComparer.Ordinal));
}
