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
    public bool PeerRuntimeReady { get; init; }
    public string PeerWire { get; init; } = "unconfigured";
    public string PlacementAuthority { get; init; } = "dormant";
    public string ClientIngress { get; init; } = "dormant";
}

public static class MailboxClientActivationGuard
{
    public const string BlockedReason =
        "peer-runtime-ready-client-authorities-and-ingress-dormant";

    public static MailboxClientActivationStatus EnsureDormant(
        MailboxClientActivationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Enabled)
        {
            throw new InvalidOperationException(
                "MailboxClient activation requires reviewed issuer, placement and revocation " +
                "authorities plus the public client ingress contract; all remain reject-all.");
        }

        return new(
            Enabled: false,
            ClientRoutesMapped: false,
            LegacyV1TranslationEnabled: false,
            CapabilityVerifier: "p10b3-internal-reject-all",
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
            IssuerAuthority = "dormant-reject-all",
            RevocationPolicy = "dormant-reject-all",
            PeerRuntimeReady = true,
            PeerWire = "prq2-mrr2-mqr3",
            PlacementAuthority = "client-dormant-reject-all",
            ClientIngress = "dormant-unmapped"
        };
    }
}
