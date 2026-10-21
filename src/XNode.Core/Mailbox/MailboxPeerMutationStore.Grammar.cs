namespace XNode.Core.Mailbox;

public sealed partial class MailboxPeerMutationStore
{
    private const int MaximumMutationDocumentBytes = 16 * 1024;
    internal const int MaximumMutationGrammarEntries = 1024;
    internal const int MaximumMutationGrammarSourceBytes = 4 * 1024 * 1024;
    private readonly object _mutationGrammarGate = new();
    private readonly Dictionary<(string Hash, int Length), PersistedMutation> _mutationGrammar = new();
    private readonly Queue<(string Hash, int Length)> _mutationGrammarOrder = new();
    private int _mutationGrammarBytes;
    private long _mutationGrammarDecodeCount;

    internal long MutationGrammarDecodeCount => Interlocked.Read(ref _mutationGrammarDecodeCount);
    internal (int Entries, int SourceBytes) MutationGrammarSize
    {
        get { lock (_mutationGrammarGate) return (_mutationGrammar.Count, _mutationGrammarBytes); }
    }

    private bool TryGetMutationGrammar((string Hash, int Length) key, out PersistedMutation record)
    {
        lock (_mutationGrammarGate)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _mutationGrammar.TryGetValue(key, out record!);
        }
    }

    private void RememberMutationGrammar((string Hash, int Length) key, PersistedMutation record)
    {
        // PersistedMutation has only immutable strings/scalars. No raw encoded
        // bytes, path, file metadata, floor result or effect authority is kept.
        lock (_mutationGrammarGate)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (_mutationGrammar.ContainsKey(key)) return;
            while (_mutationGrammar.Count >= MaximumMutationGrammarEntries ||
                   _mutationGrammarBytes > MaximumMutationGrammarSourceBytes - key.Length)
            {
                var oldest = _mutationGrammarOrder.Dequeue();
                _mutationGrammar.Remove(oldest);
                _mutationGrammarBytes -= oldest.Length;
            }
            _mutationGrammar.Add(key, record);
            _mutationGrammarOrder.Enqueue(key);
            _mutationGrammarBytes += key.Length;
        }
    }

    private void ClearMutationGrammar()
    {
        lock (_mutationGrammarGate)
        {
            _mutationGrammar.Clear();
            _mutationGrammarOrder.Clear();
            _mutationGrammarBytes = 0;
        }
    }
}
