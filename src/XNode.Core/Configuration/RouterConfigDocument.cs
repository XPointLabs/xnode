using System.Text.Json;
using XNode.Core.Paths;

namespace XNode.Core.Configuration;

public sealed class RouterConfigDocument
{
    public RouterNodeOptions Node { get; set; } = new();

    public PathSelectionOptions Paths { get; set; } = new();
}

public static class RouterConfigFile
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static async Task<RouterConfigDocument> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<RouterConfigDocument>(stream, JsonOptions, cancellationToken)
            ?? throw new InvalidOperationException($"Router config '{path}' was empty.");
    }

    public static string Render(RouterConfigDocument document) => JsonSerializer.Serialize(document, JsonOptions);

    public static async Task SaveAsync(
        string path,
        RouterConfigDocument document,
        CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(path, Render(document), cancellationToken);
    }
}
