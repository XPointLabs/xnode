using System.Text.Json;
using System.Text.RegularExpressions;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Extensions.Configuration;
using XNode;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed class MailboxClientActivationGuardTests
{
    [Fact]
    public void DefaultStatus_IsExplicitlyDormantAndNotReadyPerOperation()
    {
        var status = MailboxClientActivationGuard.EnsureDormant(
            new MailboxClientActivationOptions());

        Assert.False(status.Enabled);
        Assert.False(status.ClientRoutesMapped);
        Assert.False(status.LegacyV1TranslationEnabled);
        Assert.Equal("p03b2-internal-not-ready", status.CapabilityVerifier);
        Assert.Equal("disabled", status.StoreFanout);
        Assert.Equal("disabled", status.TombstoneFanout);
        Assert.Equal("not-ready", status.Store);
        Assert.Equal("not-ready", status.Retrieve);
        Assert.Equal("not-ready", status.Acknowledge);
        Assert.Equal(MailboxClientActivationGuard.BlockedReason, status.Reason);
        Assert.True(status.StrictMau2DecoderRegistered);
        Assert.True(status.Ed25519CapabilityVerifierRegistered);
        Assert.True(status.DurableReplayJournalRegistered);
        Assert.Equal("unconfigured", status.IssuerAuthority);
        Assert.Equal("reject-all", status.RevocationPolicy);

        var verifier = new RejectAllMailboxClientCapabilityVerifier();
        Assert.False(verifier.IsConfigured);
        Assert.False(verifier.ProvidesDurableAtomicReplay);
        Assert.False(new RejectAllMailboxClientReplicaAuthorizer().IsConfigured);
        Assert.False(new DisabledMailboxClientReplicaFanout().IsConfigured);
        Assert.False(new DisabledMailboxClientTombstoneFanout().IsConfigured);
    }

    [Fact]
    public void ConfigurationOrEnvironmentCannotActivateBlockedRuntime()
    {
        const string prefix = "XNODE_ACTIVATION_GUARD_TEST_";
        var variable = $"{prefix}MailboxClient__Enabled";
        Environment.SetEnvironmentVariable(variable, "true");
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddEnvironmentVariables(prefix)
                .Build();
            var options = configuration.GetSection("MailboxClient")
                .Get<MailboxClientActivationOptions>();

            Assert.NotNull(options);
            Assert.True(options.Enabled);
            Assert.Throws<InvalidOperationException>(() =>
                MailboxClientActivationGuard.EnsureDormant(options));
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [Fact]
    public void ProgramMapsOnlyLegacyPeerMailboxRouteAndCannotComposeClientAdapter()
    {
        var root = FindRepositoryRoot();
        var hostDirectory = Path.Combine(root, "src", "XNode");
        var hostSource = string.Join(
            "\n",
            Directory.GetFiles(hostDirectory, "*.cs", SearchOption.AllDirectories)
                .Order(StringComparer.Ordinal)
                .Select(File.ReadAllText));
        var mailboxRoutes = Regex.Matches(
                hostSource,
                "Map(?:Get|Post|Put|Delete)\\(\"([^\"]*mailbox[^\"]*)\"",
                RegexOptions.CultureInvariant)
            .Select(static match => match.Groups[1].Value)
            .ToArray();

        Assert.Equal(["/api/peer/mailbox/replica"], mailboxRoutes);
        Assert.DoesNotContain(
            nameof(MailboxClientStoreAdapter),
            hostSource,
            StringComparison.Ordinal);

        using var appSettings = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(hostDirectory, "appsettings.json")));
        Assert.False(appSettings.RootElement
            .GetProperty("MailboxClient")
            .GetProperty("enabled")
            .GetBoolean());
        Assert.Contains(
            nameof(MailboxClientActivationGuard.EnsureDormant),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(MailboxAuthenticatedCapabilityRuntime),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(DurableMailboxCapabilityReplayJournal),
            hostSource,
            StringComparison.Ordinal);
    }

    [Fact]
    public void LegacyJsonPeerClientIsNotACanonicalV2FanoutOrTombstoneTransport()
    {
        var hostTypes = typeof(Program).Assembly.GetTypes()
            .Where(static type => type is { IsAbstract: false, IsInterface: false })
            .ToArray();
        Assert.DoesNotContain(hostTypes, type =>
            typeof(IMailboxClientReplicaFanout).IsAssignableFrom(type));
        Assert.DoesNotContain(hostTypes, type =>
            typeof(IMailboxClientTombstoneFanout).IsAssignableFrom(type));
        Assert.False(typeof(IMailboxClientReplicaFanout).IsAssignableFrom(
            typeof(HttpMailboxReplicaPeerClient)));
        Assert.False(typeof(IMailboxClientTombstoneFanout).IsAssignableFrom(
            typeof(HttpMailboxReplicaPeerClient)));
        Assert.DoesNotContain(
            typeof(HttpMailboxReplicaPeerClient).GetMethods(),
            method => method.ReturnType == typeof(MailboxReplicaReceiptV2));
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("XNode repository root was not found.");
    }
}
