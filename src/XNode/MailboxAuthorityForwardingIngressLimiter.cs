namespace XNode;

public sealed class MailboxAuthorityForwardingIngressLimiter
{
    private readonly PrivacyRoutingConfiguration _configuration;
    private readonly SemaphoreSlim _concurrency;
    private readonly object _gate = new();
    private long _windowStartedAtUnixSeconds;
    private int _windowCount;

    public MailboxAuthorityForwardingIngressLimiter(
        PrivacyRoutingConfiguration configuration)
    {
        _configuration = configuration;
        _concurrency = new SemaphoreSlim(
            configuration.MaximumConcurrentRequests,
            configuration.MaximumConcurrentRequests);
    }

    public bool TryEnter(DateTimeOffset now, out IDisposable lease)
    {
        if (!_concurrency.Wait(0))
        {
            lease = EmptyLease.Instance;
            return false;
        }

        lock (_gate)
        {
            var unixSeconds = now.ToUnixTimeSeconds();
            if (_windowStartedAtUnixSeconds == 0
                || unixSeconds >= _windowStartedAtUnixSeconds + 60)
            {
                _windowStartedAtUnixSeconds = unixSeconds;
                _windowCount = 0;
            }

            if (_windowCount >= _configuration.RequestsPerMinute)
            {
                _concurrency.Release();
                lease = EmptyLease.Instance;
                return false;
            }

            _windowCount++;
        }

        lease = new Releaser(_concurrency);
        return true;
    }

    private sealed class Releaser(SemaphoreSlim semaphore) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                semaphore.Release();
            }
        }
    }

    private sealed class EmptyLease : IDisposable
    {
        public static EmptyLease Instance { get; } = new();
        public void Dispose() { }
    }
}
