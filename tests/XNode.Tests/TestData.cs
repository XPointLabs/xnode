using XNode.Core;

namespace XNode.Tests;

internal static class TestData
{
    public static readonly DateTimeOffset Now = new(2026, 5, 28, 12, 0, 0, TimeSpan.Zero);

    public static RouterId Id(byte value)
    {
        var bytes = new byte[RouterId.ByteLength];
        bytes[^1] = value;
        return RouterId.FromBytes(bytes);
    }

}

internal sealed class FixedClock : IClock
{
    public FixedClock(DateTimeOffset utcNow)
    {
        UtcNow = utcNow;
    }

    public DateTimeOffset UtcNow { get; set; }
}
