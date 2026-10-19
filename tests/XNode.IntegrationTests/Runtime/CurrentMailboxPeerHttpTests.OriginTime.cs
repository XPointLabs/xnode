using Deep.Protocol.DeepExtension.MailboxCapabilities;
using System.Security.Cryptography;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task FutureEnvelopeCannotCommitAnImpossibleImmutablePeerIntent()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var upper = await f.Sender.Node.Admission.WithHostAsync((scope, ct) => scope.Lease.CheckAsync(ct));
        var original = MailboxAuthenticatedClientRequestCodec.Decode(f.ClientStoreFrame());
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(original.Binding.CanonicalRequest.Span) with
        { CreatedAtUnixSeconds = upper + 1, ExpiresAtUnixSeconds = upper + 1 + MailboxClientLimits.MaximumTtlSeconds };
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var frame = MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding,
            Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(original.Presentation.Grant, binding,
                original.Presentation.ReplayCounter, Enumerable.Repeat((byte)0x57, 32).ToArray())
        });
        await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.StoreClientAsync(frame, f.Ledger!).AsTask());
        Assert.Empty(f.ExactIntents);
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Recipient.ReplayFiles);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests);
    }
}
