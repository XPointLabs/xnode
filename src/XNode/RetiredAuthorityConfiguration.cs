namespace XNode;

internal static class RetiredAuthorityConfiguration
{
    internal static void RequireAbsent(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        foreach (var section in new[] { "ContactAuthority", "GroupControlAuthority", "MailboxPeerAuthority", "MailboxClient",
            "MailboxClientAdapter", "MailboxClientProductionAuthority", "MailboxAuthorityForwarding" })
            // JSON empty objects become null-valued configuration keys. Exists()
            // misses those declarations, but they are still retired input.
            if (configuration.GetChildren().Any(child => string.Equals(child.Key, section, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException(
                    "Retired authority configuration is not accepted by the DID2 host.");
    }
}
