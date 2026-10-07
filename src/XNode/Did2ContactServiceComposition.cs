using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Net;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace XNode;

public sealed class DeepIdV2ContactResolverOptions
{
    public bool Enabled { get; set; }
    public bool MailboxGrantEnabled { get; set; }
    public string MailboxGrantAuthorityOrigin { get; set; } = string.Empty;
    internal bool Validate(bool independentObserver, bool privacy, bool stage)
    {
        if (Enabled && (!independentObserver || !privacy || !stage))
            throw new InvalidOperationException("DID2 contact service requires its independent observer, privacy carrier and V2 staging.");
        if (MailboxGrantEnabled && (!Enabled || !Uri.TryCreate(MailboxGrantAuthorityOrigin, UriKind.Absolute, out var origin) ||
            origin.Scheme != Uri.UriSchemeHttps || origin.UserInfo.Length != 0 || origin.Query.Length != 0 ||
            origin.Fragment.Length != 0 || origin.AbsolutePath != "/"))
            throw new InvalidOperationException("DID2 mailbox grant issuance requires the enabled resolver and an explicit HTTPS authority origin.");
        return Enabled;
    }
}

// Service time only. It is never registered as the host clock used for peer
// admission signatures, heartbeats or scheduling. No caller time/trust inputs.
internal sealed class Did2AuthenticatedContactClock(
    IDeepIdV2ContactStoreAuthoritySource snapshots, IOnionMonotonicClock monotonic) : IClock
{
    private readonly object gate = new();
    private ulong? lastUpper;
    public DateTimeOffset UtcNow
    {
        get
        {
            using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var read = ReadAsync(budget.Token).AsTask();
            try { return DateTimeOffset.FromUnixTimeSeconds(checked((long)read.WaitAsync(budget.Token).GetAwaiter().GetResult().Upper)); }
            catch { if (!read.IsCompleted) _ = ObserveAsync(read); throw; }
        }
    }

    internal async ValueTask<(ulong Lower, ulong Upper)> ReadAsync(CancellationToken ct)
    {
        var current = await snapshots.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
        current.Network.EnsureCurrent();
        var now = await monotonic.ReadAsync(ct).ConfigureAwait(false) ??
            throw new CryptographicException("DID2 service monotonic time is absent.");
        if (!current.Freshness.IsCurrentAtMonotonic(now.BootId.Span, now.SampleSeconds))
            throw new CryptographicException("DID2 service proof is expired or belongs to another boot.");
        var elapsed = checked(now.SampleSeconds - current.Freshness.MonotonicSample);
        var lower = checked(current.Freshness.TrustedLowerUnixSeconds + elapsed);
        var upper = checked(current.Freshness.TrustedUpperUnixSeconds + elapsed);
        current.Network.EnsureCurrent(); ct.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (lastUpper is { } prior && upper < prior)
                throw new CryptographicException("DID2 authenticated service time moved backwards.");
            lastUpper = upper;
        }
        return (lower, upper);
    }

    private static async Task ObserveAsync(Task task)
    { try { await task.ConfigureAwait(false); } catch { /* Late proof retrieval cannot release service time. */ } }
}

internal sealed class Did2ContactResolverDispatcher(
    ProductionContactServiceOpaqueDispatcher opaque,
    IContactServicePlacementAuthoritySource placements,
    Did2AuthenticatedContactClock time, bool grantsEnabled = false) : IContactServiceOpaqueDispatcher
{
    public async ValueTask<ReadOnlyMemory<byte>> DispatchAsync(ContactServiceOperation operation,
        ReadOnlyMemory<byte> canonicalRequest, CancellationToken ct)
    {
        if (operation is not (ContactServiceOperation.PublishDcr or ContactServiceOperation.ResolveDcr) &&
            !(grantsEnabled && operation == ContactServiceOperation.AcquireMailboxGrant))
            throw new ContactServiceUnavailableException("Only DID2 contact publication/resolve is enabled here.");
        ContactServiceRequestRecord? request = operation switch
        {
            ContactServiceOperation.PublishDcr => Xpu1Codec.Decode(canonicalRequest.Span),
            ContactServiceOperation.ResolveDcr => Xiq1Codec.Decode(canonicalRequest.Span), _ => null,
        };
        var grant = request is null ? ContactCodec.Decode("XMG2", canonicalRequest.Span) : null;
        if (grant is not null) ContactCodec.VerifyMailboxGrantHolderSignature(grant);
        var kind = grant is null ? ContactReplicaRequestBinding.RequestKind(operation) : ContactServiceRequestKind.ResolveInvite;
        var shard = grant is null ? ContactReplicaRequestBinding.ShardKey(request!) : grant.Field(3);
        var forwarded = false;
        try
        {
            var placement = await placements.MintAsync(kind, shard, ct).ConfigureAwait(false);
            await RequireIntervalAsync(request, grant, ct).ConfigureAwait(false);
            forwarded = true;
            var result = await opaque.DispatchAsync(operation, canonicalRequest, ct).ConfigureAwait(false);
            var after = await placements.MintAsync(kind, shard, ct).ConfigureAwait(false);
            ContactReplicaRequestReceiver.EnsureExactPlacement(placement, after);
            await RequireIntervalAsync(request, grant, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is OnionBoundaryException or CryptographicException or
            InvalidOperationException or UnauthorizedAccessException or IOException or OverflowException or
            ContactServiceReceiptAuthorityException)
        {
            if (forwarded) throw new IOException("DID2 contact dispatch has no current authenticated completion; outcome is unknown.", error);
            throw new ContactServiceUnavailableException("DID2 contact dispatch has no current admission authority.");
        }
    }

    private async ValueTask RequireIntervalAsync(ContactServiceRequestRecord? request, ContactRecord? grant, CancellationToken ct)
    {
        var window = await time.ReadAsync(ct).ConfigureAwait(false);
        var issued = BinaryPrimitives.ReadUInt64BigEndian(grant is null ? request!.Field(5).Span : grant.Field(9).Span);
        var expires = BinaryPrimitives.ReadUInt64BigEndian(grant is null ? request!.Field(6).Span : grant.Field(10).Span);
        if (window.Lower < issued || window.Upper >= expires || grant is not null && (expires <= issued || expires - issued > 120))
            throw new CryptographicException("The contact request does not cover the complete authenticated interval.");
    }
}

internal sealed class Did2ContactReplicaCommandDispatcher(
    DeepIdV2ReplicaStageReceiver prekeys, ContactReplicaRequestReceiver contacts) : IContactReplicaCommandReceiver
{
    public ValueTask<ContactReplicaRpcResponse> ReceiveAsync(ContactReplicaRpcCommand command,
        RouterId authenticatedSender, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(command); ct.ThrowIfCancellationRequested();
        if (command.Operation is ContactReplicaRpcOperation.StageDid2PreKeyPublication or
            ContactReplicaRpcOperation.CommitDid2PreKeyPublication or ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim or
            ContactReplicaRpcOperation.PrepareDid2PreKeyClaim or ContactReplicaRpcOperation.CompleteDid2PreKeyClaim or
            ContactReplicaRpcOperation.ReadDid2PreKeyInventoryCommit)
            return prekeys.ReceiveAsync(command, authenticatedSender, ct);
        if (command.Placement.RequestKind is not (ContactServiceRequestKind.PublishInvite or ContactServiceRequestKind.ResolveInvite) ||
            command.Operation is not (ContactReplicaRpcOperation.PublishDcr or ContactReplicaRpcOperation.ReadCurrentDcr or
                ContactReplicaRpcOperation.ResolveDcr or ContactReplicaRpcOperation.ReadDcrClaim or ContactReplicaRpcOperation.IssueReceipt or
                ContactReplicaRpcOperation.ReadMailboxGrantRoute or ContactReplicaRpcOperation.ReadRetainedMailboxGrantRoute))
            throw new InvalidDataException("The DID2 contact endpoint rejects non-current contact operations.");
        return contacts.ReceiveAsync(command, authenticatedSender, ct);
    }
}

internal static class Did2ContactServiceComposition
{
    internal static void AddDid2ContactResolver(this IServiceCollection services, DeepIdV2ContactResolverOptions? options = null)
    {
        if (options?.MailboxGrantEnabled == true)
        {
            var origin = new Uri(options.MailboxGrantAuthorityOrigin);
            services.RemoveAll<IMailboxGrantAuthorityClient>();
            services.AddHttpClient("did2-mailbox-grant-authority", client =>
            { client.Timeout = TimeSpan.FromSeconds(30); client.DefaultRequestHeaders.ExpectContinue = false; })
                .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
                { AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.None })
                .AddTypedClient<IMailboxGrantAuthorityClient>((client, provider) =>
                    new HttpsMailboxGrantAuthorityClient(client, provider.GetRequiredService<RouterNodeOptions>(), origin,
                        provider.GetRequiredService<IClock>()));
        }
        services.AddSingleton<Did2AuthenticatedContactClock>();
        services.TryAddSingleton<IContactServicePlacementAuthoritySource, VerifiedContactServicePlacementAuthoritySource>();
        services.AddSingleton<IContactPublicationAuthorizationVerifier, VerifiedContactPublicationAuthorizationVerifier>();
        services.AddSingleton(provider => new ContactServiceAuthoritySources(
            provider.GetRequiredService<IContactServicePlacementAuthoritySource>(),
            provider.GetRequiredService<IContactPublicationAuthorizationVerifier>()));
        services.AddSingleton(provider => new ContactServiceLocalReplicaRuntime(
            provider.GetRequiredService<RouterNodeOptions>(), provider.GetRequiredService<Did2AuthenticatedContactClock>(),
            provider.GetRequiredService<IMailboxStorageSecurity>(), provider.GetRequiredService<IMailboxDurabilityBarrier>(),
            provider.GetRequiredService<FileContactResolverStateCustody>()));
        services.AddSingleton(provider => new ProductionContactServiceOpaqueDispatcher(
            provider.GetRequiredService<RouterNodeOptions>(), provider.GetRequiredService<ContactServiceAuthoritySources>(),
            provider.GetRequiredService<ContactServiceLocalReplicaRuntime>(), provider.GetRequiredService<IContactReplicaPeerClient>(),
            provider.GetRequiredService<IMailboxGrantAuthorityClient>(), provider.GetRequiredService<Did2AuthenticatedContactClock>()));
        services.AddSingleton<ProtectedRetainedMailboxReadAuthority>();
        services.AddSingleton(provider => new ContactReplicaRequestReceiver(
            provider.GetRequiredService<RouterNodeOptions>(), provider.GetRequiredService<ContactServiceAuthoritySources>(),
            provider.GetRequiredService<ContactServiceLocalReplicaRuntime>(), provider.GetRequiredService<Did2AuthenticatedContactClock>(),
            provider.GetRequiredService<ProtectedRetainedMailboxReadAuthority>()));
        services.AddSingleton(provider => new Did2ContactResolverDispatcher(
            provider.GetRequiredService<ProductionContactServiceOpaqueDispatcher>(),
            provider.GetRequiredService<IContactServicePlacementAuthoritySource>(),
            provider.GetRequiredService<Did2AuthenticatedContactClock>(), options?.MailboxGrantEnabled == true));
        services.AddSingleton<Did2ContactReplicaCommandDispatcher>();
        services.RemoveAll<IContactReplicaCommandReceiver>();
        services.AddSingleton<IContactReplicaCommandReceiver>(provider => provider.GetRequiredService<Did2ContactReplicaCommandDispatcher>());
    }
}
