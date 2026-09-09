using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.ContactV1;
using XNode.Core.Mailbox;
using XNode.Core.PrivacyRouting;

namespace XNode.Core.ContactResolver;

internal enum ContactPublicationAuthorizationSagaDisposition
{
    NewReserved = 1,
    ExistingReserved = 2,
    ExistingCommitted = 3,
    ConflictLatched = 4
}

internal enum ContactPublicationAuthorizationSagaFailpoint
{
    BeforeReservePersist = 1,
    AfterReservePersist = 2,
    BeforeCommitPersist = 3,
    AfterCommitPersist = 4
}

internal interface IContactPublicationAuthorizationSagaFaults
{
    void Hit(ContactPublicationAuthorizationSagaFailpoint failpoint);
}

internal sealed class ContactPublicationAuthorizationSagaOptions
{
    internal const int DefaultMaximumRecords = 65_536;
    internal static readonly TimeSpan DefaultRetentionAfterAuthorization = TimeSpan.FromDays(30);

    internal int MaximumRecords { get; init; } = DefaultMaximumRecords;
    internal TimeSpan RetentionAfterAuthorization { get; init; } = DefaultRetentionAfterAuthorization;

    internal void Validate()
    {
        if (MaximumRecords < 1 || MaximumRecords > 1_000_000
            || RetentionAfterAuthorization < TimeSpan.Zero
            || RetentionAfterAuthorization > TimeSpan.FromDays(400))
        {
            throw new ArgumentOutOfRangeException(nameof(ContactPublicationAuthorizationSagaOptions));
        }
    }
}

/// <summary>
/// Protected, crash-safe one-way journal for consuming an XPA1 authorization.
/// A conflict latch is intentionally never pruned. Reserved and committed exact
/// requests are retained past the authorization lifetime for bounded recovery.
/// </summary>
internal sealed class ContactPublicationAuthorizationSaga : IDisposable
{
    private const int SchemaVersion = 1;
    private const int MaximumPlaintextBytes = 32 * 1024 * 1024;
    private static readonly byte[] FormatMagic = "XPA1SAG1"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly object gate = new();
    private readonly OnionDurableFile file;
    private readonly int maximumRecords;
    private readonly ulong retentionSeconds;
    private readonly IContactPublicationAuthorizationSagaFaults? faults;
    private SagaDocument document;
    private bool faulted;
    private bool disposed;

    internal ContactPublicationAuthorizationSaga(
        string statePath,
        string protectionKeyPath,
        ContactPublicationAuthorizationSagaOptions? options = null,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null,
        IContactPublicationAuthorizationSagaFaults? faults = null)
    {
        options ??= new ContactPublicationAuthorizationSagaOptions();
        options.Validate();
        security ??= new MailboxStorageSecurity();
        durability ??= new MailboxDurabilityBarrier();
        EnsureProtectionKey(statePath, protectionKeyPath, security, durability);
        file = new OnionDurableFile(
            statePath,
            protectionKeyPath,
            FormatMagic,
            MaximumPlaintextBytes,
            security,
            durability);
        maximumRecords = options.MaximumRecords;
        retentionSeconds = checked((ulong)options.RetentionAfterAuthorization.TotalSeconds);
        this.faults = faults;
        document = Load();
    }

    internal ContactPublicationAuthorizationSagaDisposition Reserve(
        VerifiedXpa1PublicationAuthorization authorization,
        Xpu1Request request,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(request);
        var candidate = SagaRecord.From(authorization, request, nowUnixSeconds, retentionSeconds);
        lock (gate)
        {
            ThrowIfUnavailable();
            Prune(nowUnixSeconds);
            var key = Convert.ToHexString(candidate.AuthorizationId);
            if (document.Records.TryGetValue(key, out var existing))
            {
                if (existing.Status == SagaStatus.ConflictLatched || !existing.ExactEquals(candidate))
                {
                    if (existing.Status != SagaStatus.ConflictLatched)
                    {
                        existing.Status = SagaStatus.ConflictLatched;
                        existing.CommittedAtUnixSeconds = null;
                        existing.ConflictDetectedAtUnixSeconds = nowUnixSeconds;
                        Save();
                    }
                    return ContactPublicationAuthorizationSagaDisposition.ConflictLatched;
                }

                return existing.Status switch
                {
                    SagaStatus.Reserved => ContactPublicationAuthorizationSagaDisposition.ExistingReserved,
                    SagaStatus.Committed => ContactPublicationAuthorizationSagaDisposition.ExistingCommitted,
                    _ => ContactPublicationAuthorizationSagaDisposition.ConflictLatched
                };
            }

            if (document.Records.Count >= maximumRecords)
            {
                throw new InvalidOperationException("The XPA1 authorization saga has reached its durable capacity.");
            }

            faults?.Hit(ContactPublicationAuthorizationSagaFailpoint.BeforeReservePersist);
            document.Records.Add(key, candidate);
            try
            {
                Save();
            }
            catch
            {
                document.Records.Remove(key);
                throw;
            }
            faults?.Hit(ContactPublicationAuthorizationSagaFailpoint.AfterReservePersist);
            return ContactPublicationAuthorizationSagaDisposition.NewReserved;
        }
    }

    internal void Commit(
        VerifiedXpa1PublicationAuthorization authorization,
        Xpu1Request request,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(request);
        var candidate = SagaRecord.From(authorization, request, nowUnixSeconds, retentionSeconds);
        lock (gate)
        {
            ThrowIfUnavailable();
            var key = Convert.ToHexString(candidate.AuthorizationId);
            if (!document.Records.TryGetValue(key, out var existing)
                || existing.Status == SagaStatus.ConflictLatched
                || !existing.ExactEquals(candidate))
            {
                if (existing is not null && existing.Status != SagaStatus.ConflictLatched)
                {
                    existing.Status = SagaStatus.ConflictLatched;
                    existing.CommittedAtUnixSeconds = null;
                    existing.ConflictDetectedAtUnixSeconds = nowUnixSeconds;
                    Save();
                }
                throw new InvalidOperationException("The XPA1 authorization cannot commit without its exact durable reservation.");
            }
            if (existing.Status == SagaStatus.Committed)
            {
                return;
            }

            faults?.Hit(ContactPublicationAuthorizationSagaFailpoint.BeforeCommitPersist);
            existing.Status = SagaStatus.Committed;
            existing.CommittedAtUnixSeconds = nowUnixSeconds;
            try
            {
                Save();
            }
            catch
            {
                existing.Status = SagaStatus.Reserved;
                existing.CommittedAtUnixSeconds = null;
                throw;
            }
            faults?.Hit(ContactPublicationAuthorizationSagaFailpoint.AfterCommitPersist);
        }
    }

    internal ContactPublicationAuthorizationSagaDisposition Read(
        ReadOnlySpan<byte> authorizationId32)
    {
        if (authorizationId32.Length != 32)
        {
            throw new ArgumentException("An XPA1 authorization id must contain 32 bytes.", nameof(authorizationId32));
        }
        lock (gate)
        {
            ThrowIfUnavailable();
            if (!document.Records.TryGetValue(Convert.ToHexString(authorizationId32), out var record))
            {
                throw new KeyNotFoundException();
            }
            return record.Status switch
            {
                SagaStatus.Reserved => ContactPublicationAuthorizationSagaDisposition.ExistingReserved,
                SagaStatus.Committed => ContactPublicationAuthorizationSagaDisposition.ExistingCommitted,
                _ => ContactPublicationAuthorizationSagaDisposition.ConflictLatched
            };
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            file.Dispose();
        }
    }

    private SagaDocument Load()
    {
        if (!file.Exists)
        {
            return new SagaDocument();
        }

        var plaintext = file.Read();
        try
        {
            var loaded = JsonSerializer.Deserialize<SagaDocument>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("The XPA1 saga document is empty.");
            Validate(loaded);
            return loaded;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or OverflowException)
        {
            throw new InvalidDataException("The XPA1 saga document is invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void Save()
    {
        try
        {
            Validate(document);
            var plaintext = JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions);
            try
            {
                file.Write(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch
        {
            faulted = true;
            throw;
        }
    }

    private void Prune(ulong nowUnixSeconds)
    {
        var expired = document.Records
            .Where(static pair => pair.Value.Status != SagaStatus.ConflictLatched)
            .Where(pair => pair.Value.RetainUntilUnixSeconds <= nowUnixSeconds)
            .Select(static pair => pair.Key)
            .ToArray();
        if (expired.Length == 0)
        {
            return;
        }
        foreach (var key in expired)
        {
            document.Records.Remove(key);
        }
        Save();
    }

    private void Validate(SagaDocument candidate)
    {
        if (candidate.Version != SchemaVersion || candidate.Records is null
            || candidate.Records.Count > maximumRecords)
        {
            throw new InvalidDataException("The XPA1 saga version or bounds are invalid.");
        }
        foreach (var pair in candidate.Records)
        {
            var record = pair.Value ?? throw new InvalidDataException("An XPA1 saga record is missing.");
            if (pair.Key.Length != 64 || !pair.Key.Equals(Convert.ToHexString(record.AuthorizationId), StringComparison.Ordinal)
                || record.Status is < SagaStatus.Reserved or > SagaStatus.ConflictLatched
                || record.AuthorizationId.Length != 32 || record.ExactRequestHash.Length != 32
                || record.CanonicalRequestDigest.Length != 32 || record.AuthorizedBodyHash.Length != 32
                || record.NetworkId.Length != 16 || record.OperationId.Length != 32
                || record.LocatorHash.Length != 32 || record.ObjectCiphertextHash.Length != 32
                || record.Status == SagaStatus.Committed && record.CommittedAtUnixSeconds is null
                || record.Status != SagaStatus.Committed && record.CommittedAtUnixSeconds is not null
                || record.Status == SagaStatus.ConflictLatched && record.ConflictDetectedAtUnixSeconds is null
                || record.Status != SagaStatus.ConflictLatched && record.ConflictDetectedAtUnixSeconds is not null)
            {
                throw new InvalidDataException("An XPA1 saga record is invalid.");
            }
        }
    }

    private static void EnsureProtectionKey(
        string statePath,
        string keyPath,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);
        var fullStatePath = Path.GetFullPath(statePath);
        var fullKeyPath = Path.GetFullPath(keyPath);
        if (File.Exists(fullStatePath) && !File.Exists(fullKeyPath))
        {
            throw new InvalidDataException("The XPA1 saga protection key is missing for existing state.");
        }
        if (File.Exists(fullKeyPath))
        {
            return;
        }

        var directory = Path.GetDirectoryName(fullKeyPath)
            ?? throw new ArgumentException("The XPA1 saga protection key has no parent directory.", nameof(keyPath));
        security.SecureDirectory(directory);
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using (var stream = new FileStream(
                       fullKeyPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       32,
                       FileOptions.WriteThrough))
            {
                stream.Write(key);
                stream.Flush(flushToDisk: true);
            }
            security.SecureFile(fullKeyPath);
            durability.FlushFileAndParentDirectory(fullKeyPath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted)
        {
            throw new InvalidOperationException("The XPA1 authorization saga is faulted after a durability failure.");
        }
    }

    private enum SagaStatus
    {
        Reserved = 1,
        Committed = 2,
        ConflictLatched = 3
    }

    private sealed class SagaDocument
    {
        public int Version { get; set; } = SchemaVersion;
        public Dictionary<string, SagaRecord> Records { get; set; } = new(StringComparer.Ordinal);
    }

    private sealed class SagaRecord
    {
        public byte[] AuthorizationId { get; set; } = [];
        public byte[] ExactRequestHash { get; set; } = [];
        public byte[] CanonicalRequestDigest { get; set; } = [];
        public byte[] AuthorizedBodyHash { get; set; } = [];
        public byte[] NetworkId { get; set; } = [];
        public byte[] OperationId { get; set; } = [];
        public byte[] LocatorHash { get; set; } = [];
        public ulong Generation { get; set; }
        public byte[] ObjectCiphertextHash { get; set; } = [];
        public ulong AuthorizationExpiresAtUnixSeconds { get; set; }
        public ulong RetainUntilUnixSeconds { get; set; }
        public ulong ReservedAtUnixSeconds { get; set; }
        public ulong? CommittedAtUnixSeconds { get; set; }
        public ulong? ConflictDetectedAtUnixSeconds { get; set; }
        public SagaStatus Status { get; set; }

        internal static SagaRecord From(
            VerifiedXpa1PublicationAuthorization authorization,
            Xpu1Request request,
            ulong nowUnixSeconds,
            ulong retentionSeconds) => new()
        {
            AuthorizationId = authorization.AuthorizationId.ToArray(),
            ExactRequestHash = request.RequestHash.ToArray(),
            CanonicalRequestDigest = SHA256.HashData(request.CanonicalBytes.Span),
            AuthorizedBodyHash = request.AuthorizedBodyHash.ToArray(),
            NetworkId = request.NetworkId.ToArray(),
            OperationId = request.OperationId.ToArray(),
            LocatorHash = request.LocatorHash.ToArray(),
            Generation = request.Generation,
            ObjectCiphertextHash = request.ObjectCiphertextHash.ToArray(),
            AuthorizationExpiresAtUnixSeconds = authorization.AuthorizationExpiresAtUnixSeconds,
            RetainUntilUnixSeconds = authorization.AuthorizationExpiresAtUnixSeconds > ulong.MaxValue - retentionSeconds
                ? ulong.MaxValue
                : authorization.AuthorizationExpiresAtUnixSeconds + retentionSeconds,
            ReservedAtUnixSeconds = nowUnixSeconds,
            Status = SagaStatus.Reserved
        };

        internal bool ExactEquals(SagaRecord other) =>
            Fixed(AuthorizationId, other.AuthorizationId)
            && Fixed(ExactRequestHash, other.ExactRequestHash)
            && Fixed(CanonicalRequestDigest, other.CanonicalRequestDigest)
            && Fixed(AuthorizedBodyHash, other.AuthorizedBodyHash)
            && Fixed(NetworkId, other.NetworkId)
            && Fixed(OperationId, other.OperationId)
            && Fixed(LocatorHash, other.LocatorHash)
            && Generation == other.Generation
            && Fixed(ObjectCiphertextHash, other.ObjectCiphertextHash)
            && AuthorizationExpiresAtUnixSeconds == other.AuthorizationExpiresAtUnixSeconds;

        private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
            left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    }
}
