namespace XNode;

// Socket ownership only, never a network/route/receipt authority. The caller
// supplies an already verified immutable network object and exact public hop
// binding. New network objects (including new epochs) cannot share connections.
internal sealed class PrivacyPeerHttpPool(TimeProvider? timeProvider = null, int capacity = 16) : IDisposable
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly Dictionary<(object Network, string Binding), Connection> entries = [];
    private readonly object sync = new();
    private bool disposed;
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(2);

    internal Lease Borrow(object network, string binding, Func<Action<DateTime, DateTime>, HttpClient> factory)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            foreach (var pair in entries.ToArray())
                if (!pair.Value.Reusable(clock)) { entries.Remove(pair.Key); Retire(pair.Value); }
            var key = (network, binding);
            if (!entries.TryGetValue(key, out var connection))
            {
                connection = new Connection(clock.GetTimestamp(), factory);
                if (entries.Count < capacity) entries.Add(key, connection);
                else connection.Retired = true; // bounded one-shot; no eviction of an active dispatch
            }
            connection.Users++;
            return new Lease(this, connection);
        }
    }

    private static void Retire(Connection connection)
    {
        connection.Retired = true;
        if (connection.Users == 0) connection.Client.Dispose();
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            foreach (var connection in entries.Values) Retire(connection);
            entries.Clear();
        }
    }

    internal sealed class Connection
    {
        internal readonly HttpClient Client;
        internal readonly long Started;
        internal int Users;
        internal bool Retired;
        private readonly object certificateGate = new();
        private long certificateNotBefore, certificateNotAfter;
        internal Connection(long started, Func<Action<DateTime, DateTime>, HttpClient> factory)
        {
            Started = started;
            Client = factory((from, until) =>
            {
                // Multiple H2 connections must never extend the oldest
                // authenticated certificate deadline still in this pool.
                lock (certificateGate)
                {
                    certificateNotBefore = Math.Max(certificateNotBefore, from.ToUniversalTime().Ticks);
                    var ticks = until.ToUniversalTime().Ticks;
                    certificateNotAfter = certificateNotAfter == 0 ? ticks : Math.Min(certificateNotAfter, ticks);
                }
            });
        }
        internal bool CertificateCurrent(TimeProvider clock)
        {
            lock (certificateGate)
            {
                var now = clock.GetUtcNow().UtcTicks;
                return certificateNotAfter != 0 && now >= certificateNotBefore && now < certificateNotAfter;
            }
        }
        internal bool Reusable(TimeProvider clock)
        {
            var elapsed = clock.GetElapsedTime(Started);
            lock (certificateGate)
                return elapsed >= TimeSpan.Zero && elapsed < Lifetime &&
                    (certificateNotAfter == 0 || CertificateCurrent(clock));
        }
    }

    internal sealed class Lease(PrivacyPeerHttpPool pool, Connection connection) : IDisposable
    {
        private int disposed;
        internal HttpClient Client => connection.Client;
        internal bool CertificateCurrent => connection.CertificateCurrent(pool.clock);
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            lock (pool.sync)
                if (--connection.Users == 0 && connection.Retired) connection.Client.Dispose();
        }
    }
}
