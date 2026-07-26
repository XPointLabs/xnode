namespace XNode.Core.Runtime;

public sealed class MembershipRouteArtifactOptions
{
    public const int MaximumAllowedBytes = 2 * 1024 * 1024;

    public string ArtifactPath { get; set; } = "";

    public int MaximumBytes { get; set; } = MaximumAllowedBytes;
}

public sealed class MembershipRouteArtifactPublisher(MembershipRouteArtifactOptions options)
{
    public bool IsConfigured => !string.IsNullOrWhiteSpace(options.ArtifactPath);

    public async Task<byte[]?> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConfigured)
            return null;
        if (options.MaximumBytes is <= 0 or > MembershipRouteArtifactOptions.MaximumAllowedBytes)
            throw new InvalidOperationException("Membership artifact byte limit is invalid.");

        var path = Path.GetFullPath(options.ArtifactPath);
        var info = new FileInfo(path);
        if (!info.Exists)
            return null;
        if (info.Length is <= 0 || info.Length > options.MaximumBytes)
            throw new InvalidDataException("Membership artifact is outside its configured byte limit.");

        await using var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var output = new MemoryStream(checked((int)info.Length));
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return output.ToArray();
            if (output.Length + read > options.MaximumBytes)
                throw new InvalidDataException("Membership artifact changed beyond its configured byte limit.");
            output.Write(buffer, 0, read);
        }
    }
}
