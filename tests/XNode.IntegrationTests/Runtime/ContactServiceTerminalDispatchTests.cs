using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactServiceTerminalDispatchTests
{
    private const OnionOperation ContactResolve = OnionOperation.ContactResolve;

    [Theory]
    [InlineData("XPU1")]
    [InlineData("XPK1")]
    [InlineData("XUW1")]
    [InlineData("XIQ1")]
    [InlineData("XUQ1")]
    [InlineData("XPP1")]
    public void ExactContactMagicIsRecognizedOnlyForContactResolve(
        string magic)
    {
        var body = System.Text.Encoding.ASCII.GetBytes(magic).Concat(new byte[300]).ToArray();

        Assert.True(PrivacyTerminalExitDispatcher.TryContactOperation(
            body, out var operation));
        Assert.True(PrivacyTerminalExitDispatcher.OuterOperationMatches(
            ContactResolve, operation));
    }

    [Theory]
    [InlineData(OnionOperation.Store)]
    [InlineData(OnionOperation.Retrieve)]
    [InlineData(OnionOperation.Acknowledge)]
    public void MailboxOperationsCannotDispatchContactPayload(
        OnionOperation outer)
    {
        Assert.True(PrivacyTerminalExitDispatcher.TryContactOperation(
            "XIQ1"u8, out var operation));
        Assert.False(PrivacyTerminalExitDispatcher.OuterOperationMatches(
            outer, operation));
    }

    [Fact]
    public void NonContactPayloadIsNotClassifiedAsContact()
    {
        Assert.False(PrivacyTerminalExitDispatcher.TryContactOperation(
            "MAU2"u8, out _));
    }

    [Theory]
    [InlineData("GSW1")]
    [InlineData("GSQ1")]
    public void GroupControlPayloadHasAClosedProductionMultiplexerBranch(string magic)
    {
        Assert.True(PrivacyTerminalExitDispatcher.TryGroupControlOperation(
            System.Text.Encoding.ASCII.GetBytes(magic)));
        Assert.False(PrivacyTerminalExitDispatcher.TryContactOperation(
            System.Text.Encoding.ASCII.GetBytes(magic), out _));
    }

    [Fact]
    public void GroupControlNeverAliasesAnyCurrentOrUndefinedOuterOperation()
    {
        Assert.All(Enum.GetValues<OnionOperation>(), operation =>
            Assert.Equal(
                Enum.GetName(operation) == "GroupControl",
                PrivacyTerminalExitDispatcher.OuterOperationMatchesGroupControl(operation)));
        Assert.Equal(
            Enum.GetName((OnionOperation)5) == "GroupControl",
            PrivacyTerminalExitDispatcher.OuterOperationMatchesGroupControl(
                (OnionOperation)5));
    }

    [Fact]
    public void UnknownContactMagicCannotMatchContactResolve()
    {
        Assert.False(PrivacyTerminalExitDispatcher.TryContactOperation(
            "MAU2"u8, out var operation));
        Assert.False(PrivacyTerminalExitDispatcher.OuterOperationMatches(
            ContactResolve, operation));
    }

    [Fact]
    public async Task UnavailableProductionContactDispatcherFailsClosed()
    {
        var dispatcher = new UnavailableContactServiceOpaqueDispatcher();
        await Assert.ThrowsAsync<ContactServiceUnavailableException>(async () =>
            await dispatcher.DispatchAsync(
                ContactServiceOperation.ResolveDcr,
                "XIQ1"u8.ToArray(),
                default));
    }

    [Fact]
    public void TerminalBoundaryRequiresVerifiedOnionRequestCapability()
    {
        var mailbox = new RecordingMailbox();
        INativeMailboxExitDispatcher dispatcher = Create(
            mailbox, new RecordingContact());
        Func<VerifiedCanonicalOnionRequest, CancellationToken,
            Task<NativeMailboxDispatchResult>> dispatch = dispatcher.DispatchAsync;

        Assert.NotNull(dispatch);
        Assert.Equal(0, mailbox.Calls);
    }

    [Fact]
    public void ProductionCompositionKeepsContactRuntimeAndReplicaEndpointDormant()
    {
        var root = FindRepositoryRoot();
        var program = File.ReadAllText(Path.Combine(root, "src", "XNode", "Program.cs"));

        Assert.DoesNotContain("ContactServiceOpaqueFacade", program,
            StringComparison.Ordinal);
        Assert.Contains(nameof(ContactServiceHostComposition.AddContactServiceBoundary), program,
            StringComparison.Ordinal);

        using var settings = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(root, "src", "XNode", "appsettings.json")));
        var contact = settings.RootElement.GetProperty("ContactService");
        Assert.False(contact.GetProperty("runtimeActivation").GetBoolean());
        Assert.False(contact.GetProperty("mapReplicaEndpoint").GetBoolean());
    }

    private static PrivacyTerminalExitDispatcher Create(
        RecordingMailbox mailbox,
        IContactServiceOpaqueDispatcher contact)
    {
        var routed = new RoutedNativeMailboxExitDispatcher(
            new MailboxAuthorityForwardingConfiguration(
                authority: null,
                allowedExitRouterIds: new HashSet<XNode.Core.RouterId>()),
            mailbox,
            new UnusedForwarding());
        return new PrivacyTerminalExitDispatcher(routed, contact);
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

    private sealed class RecordingContact : IContactServiceOpaqueDispatcher
    {
        public int Calls { get; private set; }
        public ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
            ContactServiceOperation operation,
            ReadOnlyMemory<byte> canonicalRequest,
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(new byte[] { 7, 8, 9 });
        }
    }

    private sealed class ThrowingContact(string failure)
        : IContactServiceOpaqueDispatcher
    {
        public int Calls { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
            ContactServiceOperation operation,
            ReadOnlyMemory<byte> canonicalRequest,
            CancellationToken cancellationToken)
        {
            Calls++;
            throw failure switch
            {
                "io" => new IOException("test dependency failure"),
                "invalid-operation" => new InvalidOperationException(
                    "test dependency failure"),
                "unauthorized-access" => new UnauthorizedAccessException(
                    "test dependency failure"),
                _ => new ArgumentOutOfRangeException(nameof(failure))
            };
        }
    }

    private sealed class RecordingMailbox : ILocalNativeMailboxExitDispatcher
    {
        public int Calls { get; private set; }
        public NativeMailboxDispatchResult Result { get; init; } =
            NativeMailboxDispatchResult.RejectedBeforeForward();

        public Task<NativeMailboxDispatchResult> DispatchAsync(
            OnionOperation privacyOperation,
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(Result);
        }
    }

    private sealed class UnusedForwarding : IMailboxAuthorityForwardingClient
    {
        public Task<NativeMailboxDispatchResult> ForwardAsync(
            OnionOperation operation,
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken) => throw new InvalidOperationException();
    }
}
