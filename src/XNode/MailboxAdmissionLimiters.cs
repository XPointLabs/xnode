using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode;

public sealed class MailboxClientIngressLimiter
{
    private readonly object _gate = new();
    private readonly Dictionary<MailboxAuthenticatedOperation, Endpoint> _endpoints = [];

    public bool TryEnter(
        MailboxHttpEndpointContract contract,
        ulong nowUnixSeconds,
        out IDisposable lease)
    {
        var operation = contract.AuthenticatedOperation
            ?? throw new ArgumentException(
                "Client ingress contracts require an authenticated operation.",
                nameof(contract));
        lock (_gate)
        {
            if (!_endpoints.TryGetValue(operation, out var endpoint))
            {
                endpoint = new(contract.MaximumConcurrentRequests);
                _endpoints.Add(operation, endpoint);
            }

            Reset(endpoint, nowUnixSeconds);
            if (endpoint.WindowCount >= contract.RequestsPerMinute
                || !endpoint.Concurrency.Wait(0))
            {
                lease = EmptyLease.Instance;
                return false;
            }

            endpoint.WindowCount++;
            lease = new Releaser(endpoint.Concurrency);
            return true;
        }
    }

    private static void Reset(Endpoint endpoint, ulong now)
    {
        if (endpoint.WindowStartedAt == 0
            || now >= endpoint.WindowStartedAt + MailboxWireHttpContract.RateWindowSeconds)
        {
            endpoint.WindowStartedAt = now;
            endpoint.WindowCount = 0;
        }
    }

    private sealed class Endpoint(int concurrency)
    {
        public ulong WindowStartedAt { get; set; }
        public int WindowCount { get; set; }
        public SemaphoreSlim Concurrency { get; } = new(concurrency, concurrency);
    }

    private sealed class Releaser(SemaphoreSlim endpoint) : IDisposable
    {
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                endpoint.Release();
            }
        }
    }

    private sealed class EmptyLease : IDisposable
    {
        public static EmptyLease Instance { get; } = new();
        public void Dispose()
        {
        }
    }
}

public sealed class MailboxClientVerifiedHolderLimiter
{
    private const int MaximumPartitions = 4096;
    private const int RequestsPerMinute = 120;
    private static ReadOnlySpan<byte> Domain =>
        "XNODE-MAILBOX-VERIFIED-HOLDER-LIMITER-V1\0"u8;

    private readonly object _gate = new();
    private readonly Dictionary<string, Window> _windows =
        new(StringComparer.Ordinal);

    public bool TryAccept(
        ReadOnlySpan<byte> holderPublicKey,
        MailboxAuthenticatedOperation operation,
        ulong nowUnixSeconds)
    {
        if (holderPublicKey.Length != 32
            || holderPublicKey.IndexOfAnyExcept((byte)0) < 0
            || operation is not (
                MailboxAuthenticatedOperation.Store
                or MailboxAuthenticatedOperation.Retrieve
                or MailboxAuthenticatedOperation.Ack))
        {
            return false;
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        hash.AppendData([(byte)operation]);
        hash.AppendData(holderPublicKey);
        var key = Convert.ToHexString(hash.GetHashAndReset());

        lock (_gate)
        {
            if (!_windows.TryGetValue(key, out var window))
            {
                if (_windows.Count >= MaximumPartitions)
                {
                    var expired = _windows
                        .Where(item =>
                            nowUnixSeconds >= item.Value.StartedAtUnixSeconds
                                + MailboxWireHttpContract.RateWindowSeconds)
                        .OrderBy(static item => item.Value.StartedAtUnixSeconds)
                        .ThenBy(static item => item.Key, StringComparer.Ordinal)
                        .FirstOrDefault();
                    if (expired.Key is null)
                    {
                        return false;
                    }

                    _windows.Remove(expired.Key);
                }

                window = new()
                {
                    StartedAtUnixSeconds = nowUnixSeconds
                };
                _windows.Add(key, window);
            }

            if (nowUnixSeconds >= window.StartedAtUnixSeconds
                    + MailboxWireHttpContract.RateWindowSeconds
                || nowUnixSeconds < window.StartedAtUnixSeconds)
            {
                window.StartedAtUnixSeconds = nowUnixSeconds;
                window.Count = 0;
            }

            if (window.Count >= RequestsPerMinute)
            {
                return false;
            }

            window.Count++;
            return true;
        }
    }

    private sealed class Window
    {
        public ulong StartedAtUnixSeconds { get; set; }
        public int Count { get; set; }
    }
}
