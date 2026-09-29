using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2NetworkFloorAuditTests
{
    private const string Genesis = "1111111111111111111111111111111111111111111111111111111111111111";
    private const string Node = "2222222222222222222222222222222222222222222222222222222222222222";

    [Theory]
    [InlineData("valid")]
    [InlineData("wrong-node")]
    [InlineData("wrong-genesis")]
    [InlineData("corrupt-floor")]
    [InlineData("missing-anchor")]
    [InlineData("missing-keys")]
    [InlineData("extra-file")]
    [InlineData("bad-arguments")]
    [InlineData("inside-snapshot")]
    [InlineData("existing-output")]
    public async Task OfflineAuditExportsOnlyMatchingProtectedHistoryAndNeverChangesSnapshot(string fault)
    {
        var root = Path.Combine(Path.GetTempPath(), "did2-offline-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
            var live = Path.Combine(root, "live");
            var keys = Path.Combine(live, "keys");
            Directory.CreateDirectory(keys);
            var provider = DataProtectionProvider.Create(new DirectoryInfo(keys), builder =>
                builder.SetApplicationName(DeepIdV2NetworkFloorAudit.ApplicationName));
            DeepIdV2NetworkFloor retained;
            try
            {
                using var store = new FileDeepIdV2NetworkFloorStore(live,
                    DeepIdV2NetworkFloorAudit.Protector(provider, Genesis, Node),
                    new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
                retained = await store.CommitVerifiedAsync(null, signed.NetworkContext, default);
            }
            finally { (provider as IDisposable)?.Dispose(); }
            var snapshot = Path.Combine(root, "snapshot");
            var snapshotKeys = Path.Combine(snapshot, "keys");
            Directory.CreateDirectory(snapshotKeys);
            foreach (var key in Directory.GetFiles(keys)) File.Copy(key, Path.Combine(snapshotKeys, Path.GetFileName(key)));
            File.Copy(Path.Combine(live, "did2-network-state", "floor.bin"), Path.Combine(snapshot, "floor.bin"));
            File.Copy(Path.Combine(live, "did2-network-anchor", "anchor.bin"), Path.Combine(snapshot, "anchor.bin"));
            var output = Path.Combine(root, "history.dnh2");
            string[] args = ["did2-network-floor-audit", "--snapshot-root", snapshot,
                "--directory-genesis-core-hash", Genesis, "--node-id", Node, "--output", output];
            switch (fault)
            {
                case "wrong-node": args[6] = Genesis; break;
                case "wrong-genesis": args[4] = Node; break;
                case "corrupt-floor": File.WriteAllBytes(Path.Combine(snapshot, "floor.bin"), [1]); break;
                case "missing-anchor": File.Delete(Path.Combine(snapshot, "anchor.bin")); break;
                case "missing-keys": foreach (var key in Directory.GetFiles(snapshotKeys)) File.Delete(key); break;
                case "extra-file": File.WriteAllBytes(Path.Combine(snapshot, "partial"), [1]); break;
                case "bad-arguments": args[3] = "--unknown"; break;
                case "inside-snapshot": args[8] = Path.Combine(snapshot, "history.dnh2"); break;
                case "existing-output": File.WriteAllBytes(output, [0x42]); break;
            }
            var before = DigestTree(root);
            if (fault == "valid")
            {
                DeepIdV2NetworkFloorAudit.Run(args);
                Assert.Equal(retained.History, File.ReadAllBytes(output));
                Assert.Equal(before, DigestTree(root, output));
                Assert.False(File.Exists(Path.Combine(snapshot, "floor.lock")));
            }
            else
            {
                Assert.ThrowsAny<Exception>(() => DeepIdV2NetworkFloorAudit.Run(args));
                Assert.Equal(before, DigestTree(root));
                if (fault == "existing-output") Assert.Equal(new byte[] { 0x42 }, File.ReadAllBytes(output));
                else Assert.False(File.Exists(output));
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static string[] DigestTree(string root, string? ignored = null) =>
        Directory.GetFiles(root, "*", SearchOption.AllDirectories).Where(path => path != ignored)
            .Order(StringComparer.Ordinal).Select(path => Path.GetRelativePath(root, path) + ":" +
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))) + ":" +
                File.GetLastWriteTimeUtc(path).Ticks).ToArray();
}
