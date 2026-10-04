namespace XNode.Core.Mailbox.Client;

// Internal native seam; never client evidence or a replacement operation journal.
// The ledger gate and directory lease serialize all calls. The native owner binds
// the exact local path/node/network and rejects missing enrollment on reads.
internal interface IMailboxOperationCustody
{
    void RequireScope(ReadOnlySpan<byte> localNode, ReadOnlySpan<byte> network);
    void RequireNewScope(string operationFile);
    void RequireDocumentSnapshot(string operationFile, ReadOnlySpan<byte> sha256, long length);
    ValueTask EnrollAsync(string operationFile, MailboxCurrentOperationLease lease, CancellationToken token);
    ValueTask VerifyAsync(string operationFile, MailboxCurrentOperationLease lease,
        Func<string, CancellationToken, Task> validate, CancellationToken token);
    ValueTask PrepareAsync(string operationFile, string temporaryFile, MailboxCurrentOperationLease lease,
        CancellationToken token);
    ValueTask CommitAsync(string operationFile, MailboxCurrentOperationLease lease, CancellationToken token);
}
