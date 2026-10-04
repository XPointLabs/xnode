namespace XNode;

internal sealed class CurrentMailboxHolderRateLimitException()
    : Exception("Current mailbox verified-holder budget is exhausted.");
