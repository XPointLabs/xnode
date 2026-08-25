namespace XNode;

internal static class XNodeReadinessPolicy
{
    internal static bool IsPrivacyReady(bool privacyEnabled, bool isDevelopment) =>
        privacyEnabled || isDevelopment;
}
