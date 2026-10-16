using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using XNode.Core.Mailbox;

namespace XNode;

// Historical public bytes only. The node-signed durable inventory anchors the
// exact descriptor hash; the caller still verifies its signature/transition
// against independently current device authority before admitting a successor.
internal static class DeepIdV2PublicationSupportReader
{
    internal static ParsedXps1V2 ReadPredecessorService(string dataDirectory,
        ParsedXpp1V2 predecessor, ParsedDid2 publisher, IMailboxStorageSecurity security)
    {
        var boundary = Path.GetFullPath(dataDirectory);
        var path = Path.Combine(boundary, "did2-prekey-stage",
            Convert.ToHexString(predecessor.NetworkId.Span),
            Convert.ToHexString(predecessor.PublicationOperationId.Span), "manifest.xpp1");
        for (var current = path; ; current = Path.GetDirectoryName(current)!)
        {
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("DID2 historical public support is linked.");
            if (string.Equals(current, boundary, OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) break;
            if (Path.GetDirectoryName(current) is null)
                throw new InvalidDataException("DID2 public support escaped its owned data root.");
        }
        if (!File.Exists(path)) throw new InvalidDataException("DID2 historical publication support is absent.");
        security.ValidateSecureFile(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 325 or > DeepIdV2BoundedPreKeyPublicationCodec.MaximumCanonicalBytes)
            throw new InvalidDataException("DID2 historical public support exceeds its bound.");
        var bytes = new byte[checked((int)file.Length)];
        file.ReadExactly(bytes);
        if (file.ReadByte() != -1) throw new InvalidDataException("DID2 historical public support changed while reading.");
        var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(bytes);
        if (fragment.Phase != Xpp1V2FragmentPhase.Manifest ||
            !Fixed(fragment.NetworkId.Span, predecessor.NetworkId.Span) ||
            !Fixed(fragment.PublicationOperationId.Span, predecessor.PublicationOperationId.Span) ||
            !Fixed(fragment.PlacementHash.Span, predecessor.PlacementHash.Span) ||
            !Fixed(fragment.PublisherDid2.Span, publisher.CanonicalBytes.Span))
            throw new InvalidDataException("DID2 historical public support differs from retained scope.");
        var service = DeepIdV2PreKeyServiceCodec.Decode(fragment.PublisherXps1.Span);
        var manifest = predecessor.Manifest;
        foreach (var tag in new[] { 1, 2, 3, 4 })
            if (!Fixed(service.Field(tag).Span, manifest.Field(tag).Span))
                throw new InvalidDataException("DID2 historical descriptor differs from retained inventory scope.");
        if (BinaryPrimitives.ReadUInt64BigEndian(service.Field(5).Span) !=
                BinaryPrimitives.ReadUInt64BigEndian(manifest.Field(5).Span) ||
            !Fixed(SHA256.HashData(service.CanonicalBytes.Span), manifest.Field(6).Span[6..]))
            throw new InvalidDataException("DID2 historical descriptor differs from its node-signed inventory reference.");
        return service;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
