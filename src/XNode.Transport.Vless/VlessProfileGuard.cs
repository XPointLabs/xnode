namespace XNode.Transport.Vless;

public static class VlessProfileGuard
{
    public static void Validate(VlessTransportOptions options, bool isDevelopment)
    {
        if (isDevelopment)
        {
            return;
        }

        if (options.MockProcess || string.Equals(options.XrayExecutablePath, "mock", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Non-production VLESS mock process is not allowed outside Development profile.");
        }
    }
}
