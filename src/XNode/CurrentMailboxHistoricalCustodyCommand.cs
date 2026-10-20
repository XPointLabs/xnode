using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode;

internal static class CurrentMailboxHistoricalCustodyCommand
{
    internal static async Task RunAsync(string[] args)
    {
        var export = args.Length == 5 && args[0] == "current-mailbox-export-store-recovery" &&
            args[1] == "--request-file" && args[3] == "--output-file";
        var reconcile = args.Length == 3 && args[0] == "current-mailbox-reconcile-store" && args[1] == "--forwarding-file";
        if (!export && !reconcile) throw new ArgumentException("Invalid historical custody command.");
        var input = ReadInput(args[2], export);
        // Same exclusive native owners/configuration as the ordinary process.
        // No listeners, enrollment, reset, hosted workers or new key material.
        await using var services = CurrentMailboxEnrollmentCommand.CreateConfiguredServices();
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        _ = await services.GetRequiredService<DeepIdV2DirectoryProofRuntime>().RestoreHeadAsync(budget.Token).ConfigureAwait(false);
        await services.GetRequiredService<DeepIdV2NetworkPlacementRuntime>().AcquireObservationAsync(budget.Token).ConfigureAwait(false);
        var receiver = services.GetRequiredService<CurrentMailboxReplicaReceiver>();
        if (export)
        {
            var proof = await receiver.ExportHistoricalStoreRecoveryAsync(input, budget.Token).ConfigureAwait(false);
            WriteNewProof(args[4], proof.Span, services.GetRequiredService<IMailboxStorageSecurity>(),
                services.GetRequiredService<IMailboxDurabilityBarrier>());
            Console.WriteLine("Historical Store custody proof exported. No new Store or quorum was produced.");
        }
        else
        {
            await receiver.ReconcileHistoricalStoreCustodyAsync(input, budget.Token).ConfigureAwait(false);
            Console.WriteLine("Historical Pending metadata reconciled. Store/ACK/client effects and emitted receipts: zero.");
        }
    }

    private static byte[] ReadInput(string path, bool original)
    {
        RequirePath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var overhead = original ? 0 : MailboxPeerWireV2Codec.StoreForwardingOverhead;
        if (stream.Length < MailboxPeerWireV2Limits.MinimumStoreRequestLength + overhead ||
            stream.Length > MailboxPeerWireV2Limits.MaximumRequestLength + overhead)
            throw new InvalidDataException("Historical custody input exceeds its closed bound.");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Historical custody input changed during capture.");
        if (original) _ = MailboxPeerWireV2Codec.Decode(bytes);
        else _ = MailboxPeerWireV2Codec.DecodeForwardedStoreRequest(bytes);
        return bytes;
    }

    private static void WriteNewProof(string path, ReadOnlySpan<byte> proof,
        IMailboxStorageSecurity security, IMailboxDurabilityBarrier durability)
    {
        RequirePath(path);
        if (File.Exists(path)) throw new IOException("Historical proof output must be a new private file.");
        security.SecureDirectory(Path.GetDirectoryName(path)!);
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            security.SecureFile(path); stream.Write(proof); stream.Flush(true);
        }
        durability.FlushFileAndParentDirectory(path);
    }

    private static void RequirePath(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Absolute historical custody path required.");
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Historical custody paths cannot traverse links.");
    }
}
