namespace XNode;

internal static class RetiredAuthorityConfiguration
{
    internal static void RequireAbsent(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        foreach (var section in new[] { "ContactAuthority", "GroupControlAuthority" })
            if (configuration.GetSection(section).Exists())
                throw new InvalidOperationException(
                    "Retired identity authority configuration is not accepted by the DID2 host.");
    }
}
