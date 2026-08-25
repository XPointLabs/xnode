using System.Text.Json;
using Rebex.Security.Cryptography;
using XNode.Core;

namespace XNode.Tests.Core;

public sealed class RegistryCatalogRequestSignerTests
{
    [Fact]
    public void Sign_ProducesVerifiableCatalogRequestHeaders()
    {
        var seed = Convert.ToHexString(Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray()).ToLowerInvariant();
        var signer = new Ed25519();
        signer.FromSeed(Convert.FromHexString(seed));
        var nodeId = Convert.ToHexString(signer.GetPublicKey()).ToLowerInvariant();
        var options = new RouterNodeOptions { RouterId = nodeId, Ed25519PrivateKey = seed };
        var now = DateTimeOffset.Parse("2026-06-30T10:00:00Z");
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/privacy-contacts?network=mainnet");

        RegistryCatalogRequestSigner.Sign(request, options, now);

        var nonce = request.Headers.GetValues(RegistryCatalogRequestSigner.NonceHeader).Single();
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = "xpoint-registry-catalog-v1",
            method = "GET",
            path = "/api/privacy-contacts",
            nodeId,
            timestampUnixMs = now.ToUnixTimeMilliseconds(),
            nonce
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var signature = Convert.FromHexString(request.Headers.GetValues(RegistryCatalogRequestSigner.SignatureHeader).Single());
        var verifier = new Ed25519();
        verifier.FromPublicKey(Convert.FromHexString(nodeId));
        Assert.True(verifier.VerifyMessage(payload, signature));
    }
}
