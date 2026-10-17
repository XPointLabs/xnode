namespace XNode;

// Bounded durations only, never absolute signed times, account IDs or authority.
// These observations do not decide admission, time validity or retry permission.
internal readonly record struct CoordinationTimeObservation(int Lead, int Width, int Age)
{
    internal static CoordinationTimeObservation Measure(ulong lower, ulong upper, ulong issued, ulong age) =>
        new(Bound(issued > lower ? issued - lower : 0),
            Bound(upper >= lower ? upper - lower : 0), Bound(age));
    private static int Bound(ulong value) => checked((int)Math.Min(value, 3_600UL));
}
