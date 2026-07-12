using System.Text;
using System.Text.Json;
using XNode.Core;
using XNode.Core.Session;

namespace XNode.Tests.Core;

public sealed class SessionRpcResponseAuthenticatorTests
{
    private const string Seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    private const string Nonce = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    [Fact]
    public void CanonicalJson_ProducesStableSortedBytesAndDigest()
    {
        using var document = JsonDocument.Parse("""
            { "z": 2, "a": [3, { "b": "x", "a": true }], "n": 1.25 }
            """);

        var canonical = RpcCanonicalJson.Serialize(document.RootElement);

        Assert.Equal("{\"a\":[3,{\"a\":true,\"b\":\"x\"}],\"n\":1.25,\"z\":2}", Encoding.UTF8.GetString(canonical));
        Assert.Equal("c886182f98d2dc8f244c7e6176fcb5ed7532c789220b2ccdb0540406b43e6147", RpcCanonicalJson.Sha256Hex(document.RootElement));
    }

    [Fact]
    public void SignAndVerify_BindsRequestAndOutcomeAndRemainsLegacyReadable()
    {
        var request = Request();
        var response = SessionRpcResponse.Ok(request.Id, new { targetKey = "05target", route = new[] { 0, 1, 2 } });
        var signed = SessionRpcResponseAuthenticator.Sign(
            request,
            response,
            RelayContactSigner.DeriveRouterId(Seed),
            Seed,
            TestData.Now);

        Assert.True(SessionRpcResponseAuthenticator.Verify(request, signed, TestData.Now));
        Assert.False(SessionRpcResponseAuthenticator.Verify(request with { Id = "wrong-id" }, signed, TestData.Now));
        Assert.False(SessionRpcResponseAuthenticator.Verify(request with { Method = "wrong-method" }, signed, TestData.Now));
        Assert.False(SessionRpcResponseAuthenticator.Verify(request with { Nonce = new string('a', 64) }, signed, TestData.Now));
        Assert.False(SessionRpcResponseAuthenticator.Verify(
            request with { Payload = JsonSerializer.SerializeToElement(new { targetKey = "tampered" }) },
            signed,
            TestData.Now));
        Assert.False(SessionRpcResponseAuthenticator.Verify(
            request,
            signed with { Result = new { targetKey = "tampered" } },
            TestData.Now));

        var legacy = JsonSerializer.Deserialize<LegacyResponse>(
            JsonSerializer.Serialize(signed, SessionRpc.JsonOptions),
            SessionRpc.JsonOptions);
        Assert.NotNull(legacy);
        Assert.Equal(request.Id, legacy.Id);
        Assert.True(legacy.Success);
    }

    [Fact]
    public void Verify_RejectsAuthenticButStaleResponse()
    {
        var request = Request();
        var signed = SessionRpcResponseAuthenticator.Sign(
            request,
            SessionRpcResponse.Ok(request.Id, new { ok = true }),
            RelayContactSigner.DeriveRouterId(Seed),
            Seed,
            TestData.Now.Subtract(TimeSpan.FromMinutes(3)));

        Assert.False(SessionRpcResponseAuthenticator.Verify(request, signed, TestData.Now));
    }

    private static SessionRpcRequest Request() => new(
        "request-1",
        "storage_route",
        JsonSerializer.SerializeToElement(new { targetKey = "05target", nested = new { b = 2, a = 1 } }),
        Nonce);

    private sealed record LegacyResponse(string Id, bool Success, JsonElement? Result, string? Error);
}
