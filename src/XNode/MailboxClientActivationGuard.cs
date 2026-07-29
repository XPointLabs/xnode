namespace XNode;

public sealed class MailboxClientActivationOptions
{
    public bool Enabled { get; set; }
    public MailboxClientDevelopmentFixtureOptions DevelopmentFixture { get; set; } = new();
}

public sealed record MailboxClientActivationStatus(
    bool Enabled,
    bool ClientRoutesMapped,
    bool NativeMau2Ingress,
    string AuthenticatedRuntime,
    string StoreFanout,
    string TombstoneFanout,
    string Store,
    string Retrieve,
    string Acknowledge,
    string Reason)
{
    public bool StrictMau2DecoderRegistered { get; init; }
    public bool Ed25519Mau2VerifierRegistered { get; init; }
    public bool DurableReplayJournalRegistered { get; init; }
    public bool DurableCanonicalOutcomeStoreRegistered { get; init; }
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
            NativeMau2Ingress: false,
            AuthenticatedRuntime: "native-mau2-reject-all",
            StoreFanout: "disabled",
            TombstoneFanout: "disabled",
            Store: "not-ready",
            Retrieve: "not-ready",
            Acknowledge: "not-ready",
            Reason: BlockedReason)
        {
            StrictMau2DecoderRegistered = true,
            Ed25519Mau2VerifierRegistered = true,
            DurableReplayJournalRegistered = true,
            DurableCanonicalOutcomeStoreRegistered = true,
            IssuerAuthority = "dormant-reject-all",
            RevocationPolicy = "dormant-reject-all",
            PeerRuntimeReady = true,
            PeerWire = "prq2-mrr2-mqr3",
            PlacementAuthority = "client-dormant-reject-all",
            ClientIngress = "dormant-unmapped"
        };
    }

    public static MailboxClientActivationStatus Starting() => Active(
        "starting",
        "initializing");

    public static MailboxClientActivationStatus Ready() => Active(
        "ready",
        "ready");

    public static MailboxClientActivationStatus Failed(string reason) => Active(
        "not-ready",
        reason);

    private static MailboxClientActivationStatus Active(
        string operationStatus,
        string reason) => new(
        Enabled: true,
        ClientRoutesMapped: true,
        NativeMau2Ingress: true,
        AuthenticatedRuntime: "mau2-ed25519-durable-replay-outcomes",
        StoreFanout: "development-fixture-mrr2",
        TombstoneFanout: "development-fixture-mrr2",
        Store: operationStatus,
        Retrieve: operationStatus,
        Acknowledge: operationStatus,
        Reason: reason)
    {
        StrictMau2DecoderRegistered = true,
        Ed25519Mau2VerifierRegistered = true,
        DurableReplayJournalRegistered = true,
        DurableCanonicalOutcomeStoreRegistered = true,
        IssuerAuthority = "development-config-pinned",
        RevocationPolicy = "development-config-pinned",
        PeerRuntimeReady = true,
        PeerWire = "prq2-mrr2-mqr3",
        PlacementAuthority = "development-config-pinned",
        ClientIngress = "native-mau2-meo1-mbr2-mba2"
    };
}
