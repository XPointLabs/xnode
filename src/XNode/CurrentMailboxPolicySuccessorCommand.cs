using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;
using Sodium;

namespace XNode;

// Listener-free explicit policy succession, never initial enrollment or startup
// repair. Old policy scopes and the complete network-owned native ledger remain.
internal static class CurrentMailboxPolicySuccessorCommand
{
    internal static async Task RunAsync(string[] args)
    {
        if (args is not ["current-mailbox-policy-successor", "--prior-policy-file", var prior,
            "--deposit-mgr1-file", var deposit, "--retrieve-mgr1-file", var retrieve]) throw new ArgumentException("Invalid policy successor inputs.");
        var oldPolicy = Read(prior, 65_535);
        var snapshots = new[] { Read(deposit, MailboxGrantRevocationV1Codec.MaximumBytes), Read(retrieve, MailboxGrantRevocationV1Codec.MaximumBytes) };
        // Reject grammar before configuration/native/network callbacks.
        _ = ContactCodec.Decode("PMA2", oldPolicy);
        foreach (var bytes in snapshots) _ = MailboxGrantRevocationV1Codec.Decode(bytes);
        await using var services = CurrentMailboxEnrollmentCommand.CreateConfiguredServices();
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var ct = budget.Token;
        var configuration = services.GetRequiredService<CurrentMailboxCustodyConfiguration>();
        var source = services.GetRequiredService<IDeepIdV2ContactStoreAuthoritySource>();
        _ = await services.GetRequiredService<DeepIdV2DirectoryProofRuntime>().RestoreHeadAsync(ct).ConfigureAwait(false);
        await services.GetRequiredService<DeepIdV2NetworkPlacementRuntime>().AcquireObservationAsync(ct).ConfigureAwait(false);
        var authority = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
        var host = await MailboxHostAuthorityV2Verifier.VerifyPolicyAsync(authority.Network, authority.Authority,
            authority.MailboxAuthority, authority.TrustedTime, ct).ConfigureAwait(false);
        ValidatePolicy(authority.Authority, oldPolicy, authority.MailboxAuthority.ExactPma2.Span);
        var receiver = services.GetRequiredService<CurrentMailboxReplicaReceiver>();
        await receiver.ValidateEnrollmentSigningCustodyAsync(services.GetRequiredService<CurrentMailboxAdmission>(), host, ct).ConfigureAwait(false);
        var protection = services.GetRequiredKeyedService<IDataProtectionProvider>(typeof(CurrentMailboxHostComposition));
        var node = services.GetRequiredService<XNode.Core.RouterNodeOptions>();
        var priorRecord = ContactCodec.Decode("PMA2", oldPolicy);
        byte[] priorReference = [.. "PMA2"u8, 0, 1, .. priorRecord.CoreHash.Span];
        var oldStores = new List<FileMailboxGrantRevocationStore>();
        try
        {
            // Hold both predecessor writer leases through the complete operation.
            foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
            {
                var store = new FileMailboxGrantRevocationStore(node.DataDirectory, configuration.IndependentCustodyDirectory,
                    receiver.LocalNodeId.Span, configuration.NetworkId, priorReference, role, protection,
                    services.GetRequiredService<IMailboxStorageSecurity>(), services.GetRequiredService<IMailboxDurabilityBarrier>());
                oldStores.Add(store);
            }
            for (var i = 0; i < 2; i++)
            {
                var oldFloor = await oldStores[i].ReadProtectedAsync(ct).ConfigureAwait(false);
                ValidatePriorFloor(oldPolicy, oldFloor.Span, i == 0 ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve);
                _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, snapshots[i], ct).ConfigureAwait(false);
            }
            // No prior floor, journal, key ring, enrollment or replay row is overwritten.
            // Interrupted partial new-scope writes fail closed for operator recovery.
            for (var i = 0; i < 2; i++)
            {
                var role = i == 0 ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve;
                var current = services.GetRequiredKeyedService<FileMailboxGrantRevocationStore>(role);
                await current.EnrollPolicySuccessorAsync(host, snapshots[i], ct).ConfigureAwait(false);
            }
            await receiver.InitializeHostAsync(ct).ConfigureAwait(false); // actual old native journal + every independent floor
            foreach (var old in oldStores) _ = await old.ReadProtectedAsync(ct).ConfigureAwait(false);
        }
        finally { foreach (var store in oldStores) await store.DisposeAsync().ConfigureAwait(false); }
        Console.WriteLine("Signed policy successor enrolled; predecessor floors and actual native journal retained and reverified.");
    }

    internal static void ValidatePolicy(VerifiedXPointNetworkAuthority authority, ReadOnlySpan<byte> prior, ReadOnlySpan<byte> next)
    {
        var old = ContactCodec.Decode("PMA2", prior); var current = ContactCodec.Decode("PMA2", next);
        var floor = XPointNetworkOperationalSuccessorAuthor.ComputeNextMailboxGrantFloor(authority, prior);
        if (!Fixed(old.Field(1).Span, current.Field(1).Span) || !Fixed(old.CoreHash.Span, current.Field(3).Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(current.Field(2).Span) != checked(BinaryPrimitives.ReadUInt64BigEndian(old.Field(2).Span) + 1) ||
            BinaryPrimitives.ReadUInt64BigEndian(current.Field(7).Span) < floor ||
            new[] { old.Field(5), old.Field(6) }.Any(key => Fixed(key.Span, current.Field(5).Span) || Fixed(key.Span, current.Field(6).Span)))
            throw new CryptographicException("Policy succession needs exact signed predecessor, advanced floor and fresh independent issuers.");
    }

    internal static void ValidatePriorFloor(ReadOnlySpan<byte> policy, ReadOnlySpan<byte> bytes, MailboxCapabilityDomain role)
    {
        var pma = ContactCodec.Decode("PMA2", policy); var floor = MailboxGrantRevocationV1Codec.Decode(bytes);
        byte[] reference = [.. "PMA2"u8, 0, 1, .. pma.CoreHash.Span];
        var key = pma.Field(role == MailboxCapabilityDomain.Deposit ? 5 : 6);
        if (floor.Domain != role || !Fixed(floor.Field(1).Span, pma.Field(1).Span) || !Fixed(floor.Field(2).Span, reference) ||
            !Fixed(floor.Field(4).Span, key.Span) || !PublicKeyAuth.VerifyDetached(floor.Field(12).ToArray(), floor.SignatureInput.ToArray(), key.ToArray()))
            throw new CryptographicException("Protected predecessor floor signature/scope differs.");
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static byte[] Read(string path, int bound)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Explicit public input path required.");
        for (var p = Path.GetFullPath(path); p is not null; p = Path.GetDirectoryName(p)) if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Linked input rejected.");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 || file.Length > bound) throw new InvalidDataException("Unbounded policy successor input.");
        var bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes); if (file.ReadByte() != -1) throw new IOException("Input changed."); return bytes;
    }
}
