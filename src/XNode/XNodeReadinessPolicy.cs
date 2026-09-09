namespace XNode;

public sealed class RequiredTerminalServicesOptions
{
    public bool Contact { get; set; }
    public bool GroupControl { get; set; }
}

internal sealed record RequiredTerminalServicesStatus(
    bool Ready,
    string Contact,
    string GroupControl);

internal static class XNodeReadinessPolicy
{
    internal static bool IsPrivacyReady(bool privacyEnabled, bool isDevelopment) =>
        privacyEnabled || isDevelopment;

    internal static RequiredTerminalServicesStatus RequiredTerminals(
        RequiredTerminalServicesOptions options,
        bool contactRuntimeActive,
        bool groupControlRuntimeActive)
    {
        ArgumentNullException.ThrowIfNull(options);
        var contactReady = !options.Contact || contactRuntimeActive;
        var groupControlReady = !options.GroupControl || groupControlRuntimeActive;
        return new RequiredTerminalServicesStatus(
            contactReady && groupControlReady,
            Status(options.Contact, contactRuntimeActive),
            Status(options.GroupControl, groupControlRuntimeActive));
    }

    private static string Status(bool required, bool active) => active
        ? "ready"
        : required
            ? "required-unavailable"
            : "disabled";
}
