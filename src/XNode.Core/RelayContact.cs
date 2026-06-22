using System.Net;

namespace XNode.Core;

public sealed record RelayContact
{
    public static readonly TimeSpan OutdatedAge = TimeSpan.FromHours(12);
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(30);
    public static readonly TimeSpan MinGossipAge = TimeSpan.FromMinutes(1);

    public required RouterId RouterId { get; init; }

    public required string PublicHost { get; init; }

    public string? PublicIp { get; init; }

    public required int PublicPort { get; init; }

    public string X25519PublicKey { get; init; } = "";

    public string RpcEndpoint { get; init; } = "";

    public DateTimeOffset SignedAt { get; init; } = DateTimeOffset.UtcNow;

    public DateTimeOffset ExpiresAt { get; init; } = DateTimeOffset.UtcNow.Add(Lifetime);

    public string RouterVersion { get; init; } = "0.0.0";

    public bool IsReachable { get; init; } = true;

    public string[] Capabilities { get; init; } = Array.Empty<string>();

    public string? Serialized { get; init; }

    public string SignatureAlgorithm { get; init; } = "ed25519";

    public string Signature { get; init; } = "";

    public bool IsExpired(DateTimeOffset now) => ExpiresAt <= now;

    public bool IsOutdated(DateTimeOffset now) => now - SignedAt >= OutdatedAge;

    public bool NewerThan(RelayContact other, TimeSpan atLeast) => SignedAt - other.SignedAt >= atLeast;

    public bool AddressChanged(RelayContact other)
    {
        return PublicPort != other.PublicPort
            || !StringComparer.OrdinalIgnoreCase.Equals(PublicHost, other.PublicHost)
            || !StringComparer.OrdinalIgnoreCase.Equals(PublicIp, other.PublicIp);
    }

    public IPAddress? GetIpv4Address()
    {
        var candidate = PublicIp ?? PublicHost;
        return IPAddress.TryParse(candidate, out var parsed) && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? parsed
            : null;
    }
}
