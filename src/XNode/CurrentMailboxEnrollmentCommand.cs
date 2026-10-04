using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode;

internal static class CurrentMailboxEnrollmentCommand
{
    internal static async Task RunAsync(string[] args)
    {
        var (deposit, retrieve) = ReadInputs(args);
        // Same configuration and actual owners as Program, but no listeners,
        // hosted services, generated node identity or synthetic trust source.
        var builder = WebApplication.CreateBuilder(Array.Empty<string>());
        builder.Logging.ClearProviders();
        RetiredAuthorityConfiguration.RequireAbsent(builder.Configuration);
        var node = builder.Configuration.GetSection("Node").Get<RouterNodeOptions>() ?? new();
        var mailbox = builder.Configuration.GetSection("Mailbox").Get<ReplicatedMailboxOptions>() ?? new();
        mailbox.Validate();
        var custody = (builder.Configuration.GetSection("CurrentMailboxCustody")
            .Get<CurrentMailboxCustodyOptions>(o => o.ErrorOnUnknownConfiguration = true) ?? new())
            .Validate(node, mailbox) ?? throw new InvalidOperationException("Current mailbox bindings are required.");
        var reviewedEnvironment = builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("UAT");
        var proof = (builder.Configuration.GetSection("DeepIdV2DirectoryProof").Get<DeepIdV2DirectoryProofOptions>() ?? new())
            .ValidateAndLoad(node, reviewedEnvironment) ?? throw new InvalidOperationException("Current proof source is required.");
        var placement = (builder.Configuration.GetSection("DeepIdV2NetworkPlacement").Get<DeepIdV2NetworkPlacementOptions>() ?? new())
            .ValidateAndLoad(true, reviewedEnvironment) ?? throw new InvalidOperationException("Current network source is required.");
        if (placement.Observer is null) throw new InvalidOperationException("Independent current observation is required.");
        builder.Services.AddSingleton(node);
        builder.Services.AddSingleton(mailbox);
        builder.Services.AddSingleton<IOnionMonotonicClock>(static _ => new LinuxBootOnionMonotonicClock());
        builder.Services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        builder.Services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        builder.Services.AddDeepIdV2DirectoryProof(proof);
        builder.Services.AddDeepIdV2NetworkPlacement(placement);
        builder.Services.AddCurrentMailboxHost(custody, node, mailbox);
        await using var services = builder.Services.BuildServiceProvider();
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await services.GetRequiredService<CurrentMailboxReplicaReceiver>()
            .EnrollNewHostAsync(deposit, retrieve, budget.Token).ConfigureAwait(false);
        Console.WriteLine("Current mailbox enrollment verified. Current authority and signed renewal remain required for readiness.");
    }

    internal static (byte[] Deposit, byte[] Retrieve) ReadInputs(string[] args)
    {
        if (args.Length != 5 || args[0] != "current-mailbox-enroll" ||
            args[1] != "--deposit-mgr1-file" || args[3] != "--retrieve-mgr1-file")
            throw new ArgumentException("Invalid current mailbox enrollment arguments.");
        return (ReadSnapshot(args[2]), ReadSnapshot(args[4]));
    }

    private static byte[] ReadSnapshot(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("An absolute MGR1 input is required.");
        path = Path.GetFullPath(path);
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("MGR1 input cannot traverse links.");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 327 or > MailboxGrantRevocationV1Codec.MaximumBytes)
            throw new InvalidDataException("MGR1 input exceeds its closed bound.");
        var exact = new byte[checked((int)file.Length)];
        file.ReadExactly(exact);
        if (file.ReadByte() != -1) throw new InvalidDataException("MGR1 input changed during capture.");
        return MailboxGrantRevocationV1Codec.Decode(exact).CanonicalBytes.ToArray();
    }
}
