using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace XNode;

/// <summary>
/// Linux/Docker boot-scoped monotonic time. The sample is kernel uptime rather
/// than process uptime, so protected directory freshness survives an XNode
/// process/container restart on the same boot and detects a host reboot.
/// </summary>
internal sealed class LinuxBootOnionMonotonicClock : IOnionMonotonicClock
{
    internal const string DefaultBootIdPath = "/proc/sys/kernel/random/boot_id";
    internal const string DefaultUptimePath = "/proc/uptime";

    private readonly Func<CancellationToken, ValueTask<string>> readBootId;
    private readonly Func<CancellationToken, ValueTask<string>> readUptime;
    private readonly object gate = new();
    private byte[]? observedBootId;
    private ulong observedSample;

    internal LinuxBootOnionMonotonicClock()
        : this(
            cancellationToken => ReadTextAsync(DefaultBootIdPath, cancellationToken),
            cancellationToken => ReadTextAsync(DefaultUptimePath, cancellationToken))
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "The XNode production monotonic authority requires Linux procfs.");
        }
    }

    internal LinuxBootOnionMonotonicClock(
        Func<CancellationToken, ValueTask<string>> readBootId,
        Func<CancellationToken, ValueTask<string>> readUptime)
    {
        this.readBootId = readBootId ?? throw new ArgumentNullException(nameof(readBootId));
        this.readUptime = readUptime ?? throw new ArgumentNullException(nameof(readUptime));
    }

    public async ValueTask<OnionMonotonicReading> ReadAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bootText = await readBootId(cancellationToken).ConfigureAwait(false);
        var uptimeText = await readUptime(cancellationToken).ConfigureAwait(false);
        var bootId = ParseBootId(bootText);
        try
        {
            var sample = ParseUptimeSeconds(uptimeText);
            lock (gate)
            {
                if (observedBootId is not null
                    && !CryptographicOperations.FixedTimeEquals(observedBootId, bootId))
                {
                    throw new IOException(
                        "The kernel boot identity changed during the authority operation.");
                }
                if (observedBootId is not null && sample < observedSample)
                {
                    throw new IOException(
                        "The kernel monotonic uptime moved backwards.");
                }

                observedBootId ??= bootId.ToArray();
                observedSample = sample;
                return new OnionMonotonicReading(bootId, sample);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bootId);
        }
    }

    internal static ValueTask<string> ReadTextAsync(
        string path,
        CancellationToken cancellationToken)
    {
        // procfs values are tiny kernel-memory reads, not asynchronous disk
        // I/O. Scheduling two ThreadPool file operations on every authority
        // check needlessly stalls the bounded native critical section.
        // Read BOTH actual sources on every sample; no clock value is cached.
        cancellationToken.ThrowIfCancellationRequested();
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 512, FileOptions.None);
        Span<byte> bytes = stackalloc byte[512];
        var count = 0;
        while (count < bytes.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = stream.Read(bytes[count..]);
            if (read == 0) break;
            count += read;
        }
        if (stream.ReadByte() != -1) throw new InvalidDataException("Linux procfs value exceeds its bound.");
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(new UTF8Encoding(false, true).GetString(bytes[..count]));
    }

    private static byte[] ParseBootId(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var canonical = value.Trim();
        if (!Guid.TryParseExact(canonical, "D", out _))
        {
            throw new InvalidDataException("The Linux boot identity is not a canonical UUID.");
        }

        var utf8 = Encoding.ASCII.GetBytes(canonical.ToLowerInvariant());
        var digest = SHA256.HashData(utf8);
        CryptographicOperations.ZeroMemory(utf8);
        try
        {
            var bootId = digest.AsSpan(0, 16).ToArray();
            if (bootId.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                CryptographicOperations.ZeroMemory(bootId);
                throw new InvalidDataException("The derived Linux boot identity is zero.");
            }
            return bootId;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static ulong ParseUptimeSeconds(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var separator = value.AsSpan().IndexOfAny(" \t\r\n");
        var first = separator < 0 ? value.AsSpan() : value.AsSpan(0, separator);
        if (!decimal.TryParse(
                first,
                NumberStyles.AllowDecimalPoint,
                CultureInfo.InvariantCulture,
                out var seconds)
            || seconds < 0
            || seconds > ulong.MaxValue)
        {
            throw new InvalidDataException("The Linux monotonic uptime is invalid.");
        }
        return decimal.ToUInt64(decimal.Truncate(seconds));
    }
}
