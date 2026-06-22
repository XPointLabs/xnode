using XNode.Core;
using XNode.Core.Configuration;
using XNode.Core.Paths;
using XNode.Registry;

namespace XNode.Tests.Core;

public sealed class ConfigFileTests
{
    [Fact]
    public async Task ConfigFile_RendersAndLoadsRouterOptions()
    {
        var file = Path.Combine(Path.GetTempPath(), $"deep-config-{Guid.NewGuid():N}.json");
        try
        {
            var document = new RouterConfigDocument
            {
                Node =
                {
                    RouterId = TestData.Id(1).Value,
                    DataDirectory = "/var/lib/xnode",
                    PublicHost = "node.example.org",
                    PublicPort = 443
                },
                Paths = new PathSelectionOptions
                {
                    ClientHops = 3,
                    UniqueHopNetmask = 24
                }
            };

            await RouterConfigFile.SaveAsync(file, document);
            var loaded = await RouterConfigFile.LoadAsync(file);

            Assert.Equal(TestData.Id(1).Value, loaded.Node.RouterId);
            Assert.Equal(24, loaded.Paths.UniqueHopNetmask);
            Assert.Contains("node.example.org", RouterConfigFile.Render(loaded));
        }
        finally
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }
    }

    [Fact]
    public void NodeIdentityOptions_ReadPrivateKeysFromFiles()
    {
        var ed25519File = Path.Combine(Path.GetTempPath(), $"deep-ed25519-{Guid.NewGuid():N}.key");
        var blsFile = Path.Combine(Path.GetTempPath(), $"deep-bls-{Guid.NewGuid():N}.key");
        var ed25519PrivateKey = new string('1', 64);
        var blsPrivateKey = new string('a', 64);
        try
        {
            File.WriteAllText(ed25519File, $"{ed25519PrivateKey}\n");
            File.WriteAllText(blsFile, $"{blsPrivateKey}\n");

            var node = new RouterNodeOptions { Ed25519PrivateKeyPath = ed25519File };
            var registration = new RegistryRegistrationOptions { BlsPrivateKeyPath = blsFile };

            Assert.Equal(ed25519PrivateKey, node.GetEd25519PrivateKey());
            Assert.Equal(blsPrivateKey, registration.GetBlsPrivateKey());
        }
        finally
        {
            if (File.Exists(ed25519File))
            {
                File.Delete(ed25519File);
            }

            if (File.Exists(blsFile))
            {
                File.Delete(blsFile);
            }
        }
    }
}
