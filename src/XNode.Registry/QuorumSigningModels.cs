using System.Text.Json.Serialization;

namespace XNode.Registry;

public sealed record QuorumSignatureResponse
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "";

    [JsonPropertyName("nodeId")]
    public string NodeId { get; init; } = "";

    [JsonPropertyName("blsPublicKey")]
    public string BlsPublicKey { get; init; } = "";

    [JsonPropertyName("amount")]
    public long Amount { get; init; }

    [JsonPropertyName("timestamp")]
    public long Timestamp { get; init; }

    [JsonPropertyName("msgToSign")]
    public string MessageToSign { get; init; } = "";

    [JsonPropertyName("signature")]
    public string Signature { get; init; } = "";
}

public sealed record QuorumSignatureRequest
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "";

    [JsonPropertyName("recipientAddress")]
    public string RecipientAddress { get; init; } = "";

    [JsonPropertyName("amount")]
    public long Amount { get; init; }

    [JsonPropertyName("policyQuote")]
    public string PolicyQuote { get; init; } = "";

    [JsonPropertyName("blsPublicKey")]
    public string BlsPublicKey { get; init; } = "";

    [JsonPropertyName("timestamp")]
    public long Timestamp { get; init; }
}
