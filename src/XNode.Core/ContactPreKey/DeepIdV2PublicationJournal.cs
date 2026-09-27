using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using XNode.Core.Mailbox;

namespace XNode.Core.ContactPreKey;

/// <summary>
/// Durable, operation-scoped staging of bounded DID2 XPP1 records. A complete
/// aggregate is only a candidate for independent authorization and two-replica
/// commit; staging never grants publication or claim authority.
/// </summary>
internal sealed class DeepIdV2PublicationJournal : IDisposable
{
    private readonly string directory;
    private readonly byte[] networkId;
    private readonly byte[] operationId;
    private readonly byte[] viewHash;
    private readonly byte[] placementHash;
    private readonly byte[] serviceCapability;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream lease;
    private bool disposed;
    private bool faulted;

    internal DeepIdV2PublicationJournal(string directory, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> operationId, ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash, ReadOnlySpan<byte> serviceCapability,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (networkId.Length != 16 || operationId.Length != 32 ||
            viewHash.Length != 32 || placementHash.Length != 32 ||
            serviceCapability.Length != 32 || IsZero(networkId) ||
            IsZero(operationId) || IsZero(viewHash) || IsZero(placementHash) ||
            IsZero(serviceCapability))
            throw new ArgumentException("The DID2 publication scope is invalid.");
        this.directory = System.IO.Path.GetFullPath(directory);
        this.networkId = networkId.ToArray();
        this.operationId = operationId.ToArray();
        this.viewHash = viewHash.ToArray();
        this.placementHash = placementHash.ToArray();
        this.serviceCapability = serviceCapability.ToArray();
        this.security = security ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();
        this.security.SecureDirectory(this.directory);
        var lockPath = System.IO.Path.Combine(this.directory, "operation.lock");
        lease = new FileStream(lockPath, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 1,
            Options = FileOptions.WriteThrough
        });
        try
        {
            this.security.SecureFile(lockPath);
            ValidatePersistedState();
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    internal PublicationStageResult Stage(ReadOnlySpan<byte> canonical)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted || File.Exists(Path("fault.marker")))
            throw new InvalidDataException("The DID2 publication journal is faulted.");
        var incoming = DeepIdV2BoundedPreKeyPublicationCodec.Decode(canonical);
        if (!Fixed(incoming.NetworkId.Span, networkId) ||
            !Fixed(incoming.PublicationOperationId.Span, operationId))
            return new(PublicationStageDisposition.WrongScope);
        if (!Fixed(incoming.ViewHash.Span, viewHash) ||
            !Fixed(incoming.PlacementHash.Span, placementHash))
            return File.Exists(Path("manifest.xpp1"))
                ? LatchFork()
                : new(PublicationStageDisposition.WrongScope);
        if (File.Exists(Path("fork.marker")))
            return new(PublicationStageDisposition.ForkLatched);

        try
        {
            return incoming.Phase switch
            {
                Xpp1V2FragmentPhase.Manifest => StageManifest(incoming),
                Xpp1V2FragmentPhase.Chunk => StageChunk(incoming),
                Xpp1V2FragmentPhase.Commit => StageCommit(incoming),
                _ => throw new InvalidOperationException("The codec admitted an unknown phase.")
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            faulted = true;
            throw;
        }
    }

    internal PublicationStageResult? ReadCommitted()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted || File.Exists(Path("fault.marker")) ||
            File.Exists(Path("fork.marker")))
            throw new InvalidDataException("The DID2 publication journal is unavailable.");
        try
        {
            var manifest = Read("manifest.xpp1", Xpp1V2FragmentPhase.Manifest);
            var commit = Read("commit.xpp1", Xpp1V2FragmentPhase.Commit);
            if (manifest is null && commit is not null)
                throw new InvalidDataException("A DID2 commit has no staged manifest.");
            if (manifest is null || commit is null)
                return null;
            MatchHeader(manifest, commit);
            return new PublicationStageResult(
                PublicationStageDisposition.CandidateReady,
                Reassemble(manifest),
                DeepIdV2Codec.DecodeDid2(manifest.PublisherDid2.Span));
        }
        catch (Exception exception) when (exception is InvalidDataException or FormatException)
        {
            faulted = true;
            FaultAndQuarantine();
            throw new InvalidDataException("The committed DID2 publication is corrupt.",
                exception);
        }
    }

    private PublicationStageResult StageManifest(ParsedXpp1V2Fragment incoming)
    {
        var stored = Read("manifest.xpp1", Xpp1V2FragmentPhase.Manifest);
        if (stored is not null)
            return Fixed(stored.CanonicalBytes.Span, incoming.CanonicalBytes.Span)
                ? new(PublicationStageDisposition.ExactReplay)
                : LatchFork();
        if (!ManifestBindsServiceCapability(incoming))
            return new(PublicationStageDisposition.WrongScope);
        Write("manifest.xpp1", incoming.CanonicalBytes.Span);
        return new(PublicationStageDisposition.Staged);
    }

    private PublicationStageResult StageChunk(ParsedXpp1V2Fragment incoming)
    {
        var manifest = Read("manifest.xpp1", Xpp1V2FragmentPhase.Manifest);
        if (manifest is null)
            return new(PublicationStageDisposition.Incomplete);
        if (!HeadersMatch(manifest, incoming) ||
            !DescriptorMatches(manifest, incoming))
            return LatchFork();
        var name = ChunkName(incoming.ChunkIndex);
        var stored = Read(name, Xpp1V2FragmentPhase.Chunk);
        if (stored is not null)
            return Fixed(stored.CanonicalBytes.Span, incoming.CanonicalBytes.Span)
                ? new(PublicationStageDisposition.ExactReplay)
                : LatchFork();
        if (File.Exists(Path("commit.xpp1")))
            return LatchFork();
        Write(name, incoming.CanonicalBytes.Span);
        return new(PublicationStageDisposition.Staged);
    }

    private PublicationStageResult StageCommit(ParsedXpp1V2Fragment incoming)
    {
        var manifest = Read("manifest.xpp1", Xpp1V2FragmentPhase.Manifest);
        if (manifest is null)
            return new(PublicationStageDisposition.Incomplete);
        if (!HeadersMatch(manifest, incoming))
            return LatchFork();
        var stored = Read("commit.xpp1", Xpp1V2FragmentPhase.Commit);
        if (stored is not null)
            return Fixed(stored.CanonicalBytes.Span, incoming.CanonicalBytes.Span)
                ? new(PublicationStageDisposition.ExactReplay,
                    Reassemble(manifest),
                    DeepIdV2Codec.DecodeDid2(manifest.PublisherDid2.Span))
                : LatchFork();
        if (!HaveAllChunks(manifest))
            return new(PublicationStageDisposition.Incomplete);
        ParsedXpp1V2 candidate;
        try { candidate = Reassemble(manifest); }
        catch (Exception exception) when (exception is InvalidDataException or FormatException)
        {
            if (faulted) throw;
            return LatchFork();
        }
        Write("commit.xpp1", incoming.CanonicalBytes.Span);
        return new(PublicationStageDisposition.CandidateReady, candidate,
            DeepIdV2Codec.DecodeDid2(manifest.PublisherDid2.Span));
    }

    private bool HaveAllChunks(ParsedXpp1V2Fragment manifest)
    {
        for (ushort index = 0; index < manifest.ChunkCount; index++)
            if (!File.Exists(Path(ChunkName(index))))
                return false;
        return true;
    }

    private ParsedXpp1V2 Reassemble(ParsedXpp1V2Fragment manifest)
    {
        var aggregate = new byte[checked((int)manifest.AggregateLength)];
        var offset = 0;
        for (ushort index = 0; index < manifest.ChunkCount; index++)
        {
            var chunk = Read(ChunkName(index), Xpp1V2FragmentPhase.Chunk)
                ?? throw new InvalidDataException("A committed DID2 publication has a missing chunk.");
            MatchHeader(manifest, chunk);
            MatchDescriptor(manifest, chunk);
            chunk.Body.Span.CopyTo(aggregate.AsSpan(offset));
            offset += chunk.Body.Length;
        }
        if (offset != aggregate.Length ||
            !Fixed(DeepIdV2BoundedPreKeyPublicationCodec.ComputeAggregateHash(
                aggregate), manifest.ExactAggregateHash.Span))
            throw new InvalidDataException("DID2 publication aggregate commitment differs.");
        var candidate = DeepIdV2PreKeyPublicationCodec.Decode(aggregate);
        if (!Fixed(candidate.NetworkId.Span, networkId) ||
            !Fixed(candidate.PublicationOperationId.Span, operationId) ||
            !Fixed(candidate.PlacementHash.Span, manifest.PlacementHash.Span) ||
            !Fixed(candidate.Manifest.Field(2).Span, serviceCapability) ||
            !Fixed(candidate.Manifest.CanonicalBytes.Span,
                manifest.Body.Span.Slice(DeepIdV2Codec.Did2Length,
                    DeepIdV2PreKeyManifestCodec.CanonicalLength)))
            throw new InvalidDataException("DID2 publication aggregate scope differs.");
        return candidate;
    }

    private void ValidatePersistedState()
    {
        if (File.Exists(Path("fault.marker")))
            throw new InvalidDataException("The DID2 publication journal was quarantined.");
        try
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*.xpp1"))
            {
                var name = System.IO.Path.GetFileName(file);
                if (name != "manifest.xpp1" && name != "commit.xpp1" &&
                    !(name.Length == "chunk-000.xpp1".Length &&
                      name.StartsWith("chunk-", StringComparison.Ordinal)))
                    throw new InvalidDataException("DID2 journal has an unknown record name.");
            }
            var manifest = Read("manifest.xpp1", Xpp1V2FragmentPhase.Manifest);
            var commit = Read("commit.xpp1", Xpp1V2FragmentPhase.Commit);
            if (manifest is null)
            {
                if (commit is not null || Directory.EnumerateFiles(directory,
                        "chunk-*.xpp1").Any())
                    throw new InvalidDataException("DID2 journal contains orphan records.");
                return;
            }
            if (!ManifestBindsServiceCapability(manifest))
                throw new InvalidDataException("DID2 journal manifest has a wrong shard capability.");
            foreach (var file in Directory.EnumerateFiles(directory, "chunk-*.xpp1"))
            {
                var name = System.IO.Path.GetFileName(file);
                if (name.Length != "chunk-000.xpp1".Length ||
                    !ushort.TryParse(name.AsSpan(6, 3), out var index) ||
                    index >= manifest.ChunkCount || name != ChunkName(index))
                    throw new InvalidDataException("DID2 journal contains an invalid chunk name.");
                var chunk = Read(name, Xpp1V2FragmentPhase.Chunk)!;
                if (chunk.ChunkIndex != index)
                    throw new InvalidDataException("DID2 journal chunk index differs from its file name.");
                MatchHeader(manifest, chunk);
                MatchDescriptor(manifest, chunk);
            }
            if (commit is not null)
            {
                MatchHeader(manifest, commit);
                _ = Reassemble(manifest);
            }
        }
        catch (Exception exception) when (exception is InvalidDataException or FormatException
            or IOException or UnauthorizedAccessException)
        {
            FaultAndQuarantine();
            throw new InvalidDataException("The DID2 publication journal is corrupt and quarantined.",
                exception);
        }
    }

    private ParsedXpp1V2Fragment? Read(string name, Xpp1V2FragmentPhase phase)
    {
        var path = Path(name);
        if (!File.Exists(path)) return null;
        try
        {
            security.ValidateSecureFile(path);
            var info = new FileInfo(path);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 ||
                info.Length is < 325 or > DeepIdV2BoundedPreKeyPublicationCodec.MaximumCanonicalBytes)
                throw new InvalidDataException("DID2 journal record exceeds its bound or is a link.");
            var result = DeepIdV2BoundedPreKeyPublicationCodec.Decode(File.ReadAllBytes(path));
            if (result.Phase != phase || !Fixed(result.NetworkId.Span, networkId) ||
                !Fixed(result.PublicationOperationId.Span, operationId) ||
                !Fixed(result.ViewHash.Span, viewHash) ||
                !Fixed(result.PlacementHash.Span, placementHash) ||
                (phase == Xpp1V2FragmentPhase.Manifest &&
                 !ManifestBindsServiceCapability(result)))
                throw new InvalidDataException("DID2 journal record scope or phase differs.");
            return result;
        }
        catch (Exception exception) when (exception is InvalidDataException or FormatException
            or IOException or UnauthorizedAccessException)
        {
            faulted = true;
            FaultAndQuarantine();
            throw new InvalidDataException("The DID2 publication journal record is corrupt.", exception);
        }
    }

    private static void MatchHeader(ParsedXpp1V2Fragment manifest,
        ParsedXpp1V2Fragment fragment)
    {
        if (!HeadersMatch(manifest, fragment))
            throw new InvalidDataException("DID2 publication fragment header differs.");
    }

    private bool ManifestBindsServiceCapability(ParsedXpp1V2Fragment manifest) =>
        Fixed(DeepIdV2PreKeyManifestCodec.Decode(
            manifest.Body.Span.Slice(DeepIdV2Codec.Did2Length,
                DeepIdV2PreKeyManifestCodec.CanonicalLength))
            .Field(2).Span, serviceCapability);

    private static bool HeadersMatch(ParsedXpp1V2Fragment manifest,
        ParsedXpp1V2Fragment fragment)
    {
        foreach (var tag in new[] { 2, 3, 4, 5, 6, 7, 8, 11 })
            if (!Fixed(manifest.Field(tag).Span, fragment.Field(tag).Span))
                return false;
        return true;
    }

    private static void MatchDescriptor(ParsedXpp1V2Fragment manifest,
        ParsedXpp1V2Fragment chunk)
    {
        if (!DescriptorMatches(manifest, chunk))
            throw new InvalidDataException("DID2 publication chunk descriptor differs.");
    }

    private static bool DescriptorMatches(ParsedXpp1V2Fragment manifest,
        ParsedXpp1V2Fragment chunk)
    {
        var row = manifest.Body.Span.Slice(
            DeepIdV2Codec.Did2Length +
            DeepIdV2PreKeyManifestCodec.CanonicalLength +
            chunk.ChunkIndex * 36, 36);
        return BinaryPrimitives.ReadUInt32BigEndian(row) == chunk.Body.Length &&
            Fixed(row[4..], chunk.ChunkHash.Span);
    }

    private PublicationStageResult LatchFork()
    {
        Write("fork.marker", [1]);
        return new(PublicationStageDisposition.ForkLatched);
    }

    private void FaultAndQuarantine()
    {
        var marker = Path("fault.marker");
        if (!File.Exists(marker)) Write("fault.marker", [1]);
        foreach (var path in Directory.EnumerateFiles(directory, "*.xpp1"))
        {
            var quarantine = path + ".quarantine." + Guid.NewGuid().ToString("N");
            durability.ReplaceFile(path, quarantine);
            durability.FlushFileAndParentDirectory(quarantine);
        }
    }

    private void Write(string name, ReadOnlySpan<byte> bytes)
    {
        var destination = Path(name);
        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew,
                       FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            security.SecureFile(temporary);
            durability.FlushFileAndParentDirectory(temporary);
            durability.ReplaceFile(temporary, destination);
            durability.FlushFileAndParentDirectory(destination);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private string Path(string name) => System.IO.Path.Combine(directory, name);
    private static string ChunkName(ushort index) => $"chunk-{index:D3}.xpp1";
    private static bool IsZero(ReadOnlySpan<byte> value) =>
        !value.ContainsAnyExcept((byte)0);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        lease.Dispose();
    }
}

internal enum PublicationStageDisposition
{
    Staged,
    Incomplete,
    ExactReplay,
    CandidateReady,
    ForkLatched,
    WrongScope
}

internal sealed record PublicationStageResult(PublicationStageDisposition Disposition,
    ParsedXpp1V2? Candidate = null, ParsedDid2? PublisherDid2 = null);
