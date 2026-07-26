using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.NodeDb;

namespace XNode;

public sealed class NodeDbMailboxPeerAuthorizer : IMailboxPeerAuthorizer
{
    private readonly NodeDb _nodeDb;

    public NodeDbMailboxPeerAuthorizer(NodeDb nodeDb)
    {
        _nodeDb = nodeDb;
    }

    public bool IsAuthorized(RouterId routerId, DateTimeOffset now)
    {
        var contact = _nodeDb.GetContact(routerId);
        return _nodeDb.IsRegistered(routerId)
            && contact is not null
            && RelayContactSigner.VerifyFresh(contact, now);
    }
}
