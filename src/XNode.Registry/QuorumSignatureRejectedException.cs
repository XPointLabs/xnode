namespace XNode.Registry;

public sealed class QuorumSignatureRejectedException : InvalidOperationException
{
    public QuorumSignatureRejectedException(string message)
        : base(message)
    {
    }
}
