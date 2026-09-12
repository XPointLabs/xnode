using XNode.Core;

namespace XNode.Tests.Core;

public sealed class RouterNodeOptionsTests
{
    private const string Seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    [Fact]
    public void GetEd25519PrivateKey_NormalizesInstallerFileEnvelope()
    {
        var directory = Directory.CreateTempSubdirectory("xnode-key-");
        try
        {
            var path = Path.Combine(directory.FullName, "key_ed25519");
            File.WriteAllText(path, $"0x{Seed}\n");
            var options = new RouterNodeOptions { Ed25519PrivateKeyPath = path };

            Assert.Equal(Seed, options.GetEd25519PrivateKey());
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void GetEd25519PrivateKey_NormalizesInlineHexToCanonicalLowercase()
    {
        var options = new RouterNodeOptions { Ed25519PrivateKey = $"  {Seed.ToUpperInvariant()}  " };

        Assert.Equal(Seed, options.GetEd25519PrivateKey());
    }

    [Theory]
    [InlineData("0X0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")]
    [InlineData("0x01")]
    [InlineData("gg02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")]
    public void GetEd25519PrivateKey_RejectsNonCanonicalEnvelope(string value)
    {
        var options = new RouterNodeOptions { Ed25519PrivateKey = value };

        var error = Assert.Throws<InvalidOperationException>(options.GetEd25519PrivateKey);

        Assert.Contains("32-byte hexadecimal value", error.Message, StringComparison.Ordinal);
    }
}
