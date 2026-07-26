namespace XNode;

public sealed class MailboxClientActivationOptions
{
    public bool Enabled { get; set; }
}

public sealed record MailboxClientActivationStatus(
    bool Enabled,
    bool ClientRoutesMapped,
    bool LegacyV1TranslationEnabled,
    string CapabilityVerifier,
    string StoreFanout,
    string TombstoneFanout,
    string Store,
    string Retrieve,
    string Acknowledge,
    string Reason)
{
    public bool StrictMau2DecoderRegistered { get; init; }
    public bool Ed25519CapabilityVerifierRegistered { get; init; }
    public bool DurableReplayJournalRegistered { get; init; }
    public string IssuerAuthority { get; init; } = "unconfigured";
    public string RevocationPolicy { get; init; } = "unconfigured";
}

public static class MailboxClientActivationGuard
{
    public const string BlockedReason = "mailbox-client-protocol-contracts-unavailable";

    public static MailboxClientActivationStatus EnsureDormant(
        MailboxClientActivationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Enabled)
        {
            throw new InvalidOperationException(
                "MailboxClient activation is blocked until the remaining B-E runtime " +
                "contracts in ADR 0006 are pinned and implemented.");
        }

        return new(
            Enabled: false,
            ClientRoutesMapped: false,
            LegacyV1TranslationEnabled: false,
            CapabilityVerifier: "p03b2-internal-not-ready",
            StoreFanout: "disabled",
            TombstoneFanout: "disabled",
            Store: "not-ready",
            Retrieve: "not-ready",
            Acknowledge: "not-ready",
            Reason: BlockedReason)
        {
            StrictMau2DecoderRegistered = true,
            Ed25519CapabilityVerifierRegistered = true,
            DurableReplayJournalRegistered = true,
            IssuerAuthority = "unconfigured",
            RevocationPolicy = "reject-all"
        };
    }
}
