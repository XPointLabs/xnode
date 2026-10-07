using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class RetainedMailboxRouteStoreTests
{
    [Fact]
    public async Task ProtectedRetainedReadUsesRealPublicationAndPersistedNativeRootAfterColdReopen()
    {
        using var f = ProtectedFiles(); var publication = await Publication();
        Assert.Equal(ContactResolverMutationDisposition.Committed, f.Enroll().PublishDcr(publication).Disposition);
        var exact = File.ReadAllBytes(f.Document); var root = File.ReadAllBytes(f.Checkpoint);
        var result = await f.Open().ResolveProtectedRetainedMailboxRouteAsync(await Request());
        Assert.Equal(RetainedMailboxRouteDisposition.Found, result.Disposition);
        Assert.Equal(publication.CanonicalRouteClosure.ToArray(), result.ExactRouteClosure.ToArray());
        Assert.Equal(exact, File.ReadAllBytes(f.Document)); Assert.Equal(root, File.ReadAllBytes(f.Checkpoint));
        Assert.Equal(-1, exact.AsSpan().IndexOf(signed.Request.OwnerRetrieveCapability.Span));
        Assert.True(new FileInfo(f.Checkpoint).Length <= 4_096);
    }

    [Fact]
    public async Task UnprotectedRowsCannotBeBlessedAndNeutralLookupCannotServeProtectedEvidence()
    {
        using var f = ProtectedFiles();
        using (var unprotected = new ContactResolverOpaqueStore(f.Document, clock: f.Clock))
        {
            _ = unprotected.PublishDcr(await Publication());
            var request = await Request();
            Assert.Equal(RetainedMailboxRouteDisposition.Found, (await unprotected.ResolveRetainedMailboxRouteAsync(request)).Disposition);
            await Assert.ThrowsAsync<InvalidOperationException>(() => unprotected.ResolveProtectedRetainedMailboxRouteAsync(request).AsTask());
        }
        var before = File.ReadAllBytes(f.Document);
        Assert.Throws<InvalidDataException>(() => f.Enroll());
        Assert.Throws<InvalidDataException>(() => f.Open());
        Assert.Equal(before, File.ReadAllBytes(f.Document)); Assert.False(File.Exists(f.Enrollment));
    }

    [Theory]
    [InlineData("data-rollback")]
    [InlineData("missing-data")]
    [InlineData("missing-enrollment")]
    [InlineData("missing-checkpoint")]
    [InlineData("checkpoint-tamper")]
    [InlineData("root-rollback")]
    public async Task ProtectedColdReopenRejectsLostSplitTamperedOrRolledBackNativeState(string defect)
    {
        using var f = ProtectedFiles(); var store = f.Enroll();
        var initial = File.ReadAllBytes(f.Document); var initialRoot = File.ReadAllBytes(f.Checkpoint);
        _ = store.PublishDcr(await Publication()); f.Close();
        if (defect == "data-rollback") File.WriteAllBytes(f.Document, initial);
        if (defect == "missing-data") File.Delete(f.Document);
        if (defect == "missing-enrollment") File.Delete(f.Enrollment);
        if (defect == "missing-checkpoint") File.Delete(f.Checkpoint);
        if (defect == "checkpoint-tamper") { var root = File.ReadAllBytes(f.Checkpoint); root[^1] ^= 1; File.WriteAllBytes(f.Checkpoint, root); }
        if (defect == "root-rollback") File.WriteAllBytes(f.Checkpoint, initialRoot);
        Assert.Throws<InvalidDataException>(() => f.Open());
        // No reenrollment or automatic replacement of the independently owned root.
        Assert.Throws<InvalidDataException>(() => f.Enroll());
    }

    [Theory]
    [InlineData("prepare", false)]
    [InlineData("prepare", true)]
    [InlineData("document", false)]
    [InlineData("document", true)]
    [InlineData("commit", false)]
    [InlineData("commit", true)]
    public async Task ProtectedPendingCrashRecoversOnlyExactAnchoredCandidate(string step, bool afterReplace)
    {
        var fault = new ProtectedReplaceFault(step, afterReplace);
        using var f = ProtectedFiles(fault); var store = f.Enroll(); fault.Arm();
        var publication = await Publication();
        Assert.Throws<IOException>(() => store.PublishDcr(publication));
        Assert.True(fault.Reached);
        Assert.Throws<InvalidOperationException>(() => store.ResolveCurrentDcr(signed.Request.LocatorHash.Span));
        var expected = step == "prepare" && !afterReplace ? RetainedMailboxRouteDisposition.NotFound : RetainedMailboxRouteDisposition.Found;
        var reopened = f.Open();
        Assert.Equal(expected, (await reopened.ResolveProtectedRetainedMailboxRouteAsync(await Request())).Disposition);
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.Document)!, "resolver.state.*.tmp"));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.Checkpoint)!, "*.tmp"));
    }

    [Theory]
    [InlineData("checkpoint.bin")]
    [InlineData("enrollment.bin")]
    public async Task MetadataTemporaryNeverReplacesMissingAuthenticatedRecord(string record)
    {
        using var f = ProtectedFiles(); _ = f.Enroll().PublishDcr(await Publication()); f.Close();
        var path = Path.Combine(Path.GetDirectoryName(f.Checkpoint)!, record);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.Move(path, temporary);
        Assert.Throws<InvalidDataException>(() => f.Open());
        Assert.False(File.Exists(path)); Assert.True(File.Exists(temporary));
    }

    [Fact]
    public async Task CommittedRecoveryRemovesOnlyExactUnanchoredMetadataTemporaries()
    {
        using var f = ProtectedFiles(); _ = f.Enroll().PublishDcr(await Publication()); f.Close();
        var root = File.ReadAllBytes(f.Checkpoint); var document = File.ReadAllBytes(f.Document);
        var temporary = f.Checkpoint + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(temporary, "not protected authority");
        Assert.Equal(RetainedMailboxRouteDisposition.Found,
            (await f.Open().ResolveProtectedRetainedMailboxRouteAsync(await Request())).Disposition);
        Assert.False(File.Exists(temporary));
        Assert.Equal(root, File.ReadAllBytes(f.Checkpoint)); Assert.Equal(document, File.ReadAllBytes(f.Document));
        f.Close(); var unknown = f.Checkpoint + ".unknown.tmp"; File.WriteAllText(unknown, "unknown");
        Assert.Throws<InvalidDataException>(() => f.Open());
        Assert.True(File.Exists(unknown)); Assert.Equal(root, File.ReadAllBytes(f.Checkpoint));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProtectedPendingMissingOrChangedExactTemporaryCannotInventRecovery(bool delete)
    {
        var fault = new ProtectedReplaceFault("document", false);
        using var f = ProtectedFiles(fault); var store = f.Enroll(); fault.Arm();
        var publication = await Publication();
        Assert.Throws<IOException>(() => store.PublishDcr(publication)); f.Close();
        var temporary = Assert.Single(Directory.GetFiles(Path.GetDirectoryName(f.Document)!, "resolver.state.*.tmp"));
        var root = File.ReadAllBytes(f.Checkpoint); var document = File.ReadAllBytes(f.Document);
        if (delete) File.Delete(temporary); else File.AppendAllText(temporary, " ");
        Assert.Throws<InvalidDataException>(() => f.Open());
        Assert.Equal(root, File.ReadAllBytes(f.Checkpoint)); Assert.Equal(document, File.ReadAllBytes(f.Document));
    }

    [Fact]
    public async Task ProtectedLookupRejectsExternalDataReplacementDuringCurrentAuthorityCallback()
    {
        using var f = ProtectedFiles(); var store = f.Enroll(); _ = store.PublishDcr(await Publication());
        var clock = new CallbackClock(); var request = await Request(clock: clock);
        var document = File.ReadAllBytes(f.Document); var root = File.ReadAllBytes(f.Checkpoint);
        clock.Reset(() => File.AppendAllText(f.Document, " "));
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ResolveProtectedRetainedMailboxRouteAsync(request).AsTask());
        Assert.Equal(root, File.ReadAllBytes(f.Checkpoint));
        File.WriteAllBytes(f.Document, document); clock.Reset(null);
        Assert.Equal(RetainedMailboxRouteDisposition.Found, (await store.ResolveProtectedRetainedMailboxRouteAsync(request)).Disposition);
    }

    [Fact]
    public async Task CapturedCandidateCannotChangeBetweenSerializationAndNativePrepare()
    {
        var fault = new PreparedBytesSubstitution(); using var f = ProtectedFiles(fault);
        var store = f.Enroll(); var root = File.ReadAllBytes(f.Checkpoint); var document = File.ReadAllBytes(f.Document);
        fault.Armed = true;
        var publication = await Publication();
        Assert.Throws<InvalidDataException>(() => store.PublishDcr(publication));
        Assert.True(fault.Reached); Assert.Equal(root, File.ReadAllBytes(f.Checkpoint));
        Assert.Equal(document, File.ReadAllBytes(f.Document));
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound,
            (await f.Open().ResolveProtectedRetainedMailboxRouteAsync(await Request())).Disposition);
    }

    [Fact]
    public async Task CapturedReadBytesMustMatchRootEvenWhenPathAgainContainsAuthenticatedDocument()
    {
        using var f = ProtectedFiles(); _ = f.Enroll().PublishDcr(await Publication());
        var document = File.ReadAllBytes(f.Document); var substituted = document.ToArray(); substituted[^1] ^= 1;
        Assert.Throws<InvalidDataException>(() => f.Custody!.RequireDocumentSnapshot(f.Document,
            SHA256.HashData(substituted), substituted.LongLength));
        f.Custody!.RequireSnapshot(f.Document);
        Assert.Equal(RetainedMailboxRouteDisposition.Found,
            (await f.Current!.ResolveProtectedRetainedMailboxRouteAsync(await Request())).Disposition);
    }

    [Fact]
    public async Task JointMatchingRootAndDocumentRollbackIsExplicitlyOutsideLocalGuarantee()
    {
        using var f = ProtectedFiles(); var store = f.Enroll();
        var original = File.ReadAllBytes(f.Document); var root = File.ReadAllBytes(f.Checkpoint);
        _ = store.PublishDcr(await Publication()); f.Close();
        File.WriteAllBytes(f.Document, original); File.WriteAllBytes(f.Checkpoint, root);
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound,
            (await f.Open().ResolveProtectedRetainedMailboxRouteAsync(await Request())).Disposition);
    }

    [Theory]
    [InlineData("purpose")]
    [InlineData("oversize")]
    [InlineData("keys")]
    public async Task ProtectedColdReopenRejectsWrongPurposeOversizedRecordOrMissingKeyRing(string defect)
    {
        using var f = ProtectedFiles(); _ = f.Enroll().PublishDcr(await Publication()); f.Close();
        if (defect == "purpose") File.Copy(f.Enrollment, f.Checkpoint, overwrite: true);
        if (defect == "oversize") File.AppendAllText(f.Checkpoint, new string('x', 4_096));
        if (defect == "keys") foreach (var key in Directory.GetFiles(f.Keys)) File.Delete(key); // Exact test-created ring only.
        var before = File.ReadAllBytes(f.Document);
        Assert.Throws<InvalidDataException>(() => f.Open());
        Assert.Equal(before, File.ReadAllBytes(f.Document));
        Assert.Throws<InvalidDataException>(() => f.Enroll());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CopiedNativeRootCannotBeReboundToAnotherNodeOrNetwork(bool foreignNetwork)
    {
        using var f = ProtectedFiles(); _ = f.Enroll().PublishDcr(await Publication()); f.Close();
        var foreignNode = foreignNetwork ? f.Node : Bytes(32, 0xe7);
        var foreignNet = foreignNetwork ? Bytes(16, 0xe8) : f.Network;
        var target = Path.Combine(f.Native, "contact-resolver", Convert.ToHexString(SHA256.HashData([.. foreignNode, .. foreignNet])));
        var security = new MailboxStorageSecurity(); security.SecureDirectory(target);
        foreach (var name in new[] { "enrollment.bin", "checkpoint.bin" })
        {
            var copy = Path.Combine(target, name);
            File.Copy(name == "enrollment.bin" ? f.Enrollment : f.Checkpoint, copy);
            security.SecureFile(copy);
        }
        using var custody = new FileContactResolverStateCustody(f.Data, f.Native, foreignNode, foreignNet,
            f.Protection(), new ContactResolverOpaqueStoreOptions().MaximumPersistedBytes);
        var before = File.ReadAllBytes(f.Document);
        Assert.Throws<InvalidDataException>(() => new ContactResolverOpaqueStore(f.Document, custody: custody));
        Assert.Equal(before, File.ReadAllBytes(f.Document));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InterruptedInitialEnrollmentCannotBlessExistingEmptyDocument(bool afterReplace)
    {
        var fault = new ProtectedReplaceFault("enrollment", afterReplace); fault.Arm();
        using var f = ProtectedFiles(fault);
        Assert.Throws<IOException>(() => f.Enroll()); Assert.True(fault.Reached);
        Assert.True(File.Exists(f.Document)); var before = File.ReadAllBytes(f.Document);
        Assert.Throws<InvalidDataException>(() => f.Open());
        Assert.Throws<InvalidDataException>(() => f.Enroll());
        Assert.Equal(before, File.ReadAllBytes(f.Document));
    }

    [Fact]
    public void NativeCustodyRequiresDisjointNonRootPathsAndOneLifetimeWriter()
    {
        using var f = ProtectedFiles(); _ = f.Enroll();
        Assert.Throws<ArgumentException>(() => new FileContactResolverStateCustody(f.Data, f.Data, f.Node, f.Network,
            f.Protection(), 4_096));
        Assert.Throws<ArgumentException>(() => new FileContactResolverStateCustody(f.Data, Path.GetPathRoot(f.Native)!,
            f.Node, f.Network, f.Protection(), 4_096));
        Assert.Throws<IOException>(() => new FileContactResolverStateCustody(f.Data, f.Native, f.Node, f.Network,
            f.Protection(), new ContactResolverOpaqueStoreOptions().MaximumPersistedBytes));
        f.Custody!.RequireSnapshot(f.Document);
    }

    private ProtectedResolverFiles ProtectedFiles(IMailboxDurabilityBarrier? durability = null) =>
        new(signed.Placement.ReplicaIds[0].ToArray(), signed.Network.NetworkId.ToArray(), durability);

    private sealed class ProtectedResolverFiles : IDisposable
    {
        internal readonly string Root = Path.Combine(Path.GetTempPath(), "xnode-protected-retained-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] node, network; private readonly IMailboxDurabilityBarrier? durability;
        internal byte[] Node => node.ToArray(); internal byte[] Network => network.ToArray();
        private readonly MailboxStorageSecurity security = new();
        internal readonly StorageClock Clock = new();
        internal ContactResolverOpaqueStore? Current; internal FileContactResolverStateCustody? Custody;
        internal string Data => Path.Combine(Root, "data");
        internal string Native => Path.Combine(Root, "custody");
        internal string Keys => Path.Combine(Root, "keys");
        internal string Document => Path.Combine(Data, "contact-service-v1", "resolver.state");
        private string Scope => Path.Combine(Native, "contact-resolver", Convert.ToHexString(SHA256.HashData([.. node, .. network])));
        internal string Enrollment => Path.Combine(Scope, "enrollment.bin");
        internal string Checkpoint => Path.Combine(Scope, "checkpoint.bin");
        internal ProtectedResolverFiles(byte[] node, byte[] network, IMailboxDurabilityBarrier? durability)
        {
            this.node = node; this.network = network; this.durability = durability;
            security.SecureDirectory(Keys);
            var services = new ServiceCollection();
            services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Keys))
                .SetApplicationName(CurrentMailboxHostComposition.ProtectionApplication).DisableAutomaticKeyGeneration();
            using (var provider = services.BuildServiceProvider())
                provider.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(90));
            foreach (var key in Directory.GetFiles(Keys)) security.SecureFile(key);
        }
        internal ContactResolverOpaqueStore Open() => Open(enroll: false);
        internal ContactResolverOpaqueStore Enroll() => Open(enroll: true);
        internal IDataProtectionProvider Protection() => DataProtectionProvider.Create(new DirectoryInfo(Keys),
            builder => builder.SetApplicationName(CurrentMailboxHostComposition.ProtectionApplication).DisableAutomaticKeyGeneration());
        private ContactResolverOpaqueStore Open(bool enroll)
        {
            Close();
            Custody = new(Data, Native, node, network, Protection(), new ContactResolverOpaqueStoreOptions().MaximumPersistedBytes,
                security, durability);
            try
            {
                Current = enroll ? ContactResolverOpaqueStore.EnrollNewProtected(Document, Custody, clock: Clock, durability: durability) :
                    new ContactResolverOpaqueStore(Document, clock: Clock, durability: durability, custody: Custody);
                return Current;
            }
            catch { Close(); throw; }
        }
        internal void Close() { Current?.Dispose(); Current = null; Custody?.Dispose(); Custody = null; }
        public void Dispose() { Close(); if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
    }

    private sealed class ProtectedReplaceFault(string step, bool after) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier actual = new(); private bool armed; private int checkpoints;
        internal bool Reached; internal void Arm() { armed = true; checkpoints = 0; }
        public void FlushFileAndParentDirectory(string path) => actual.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => actual.FlushParentDirectory(path);
        public void ReplaceFile(string temporary, string final)
        {
            var isCheckpoint = Path.GetFileName(final) == "checkpoint.bin";
            var checkpoint = isCheckpoint && armed ? ++checkpoints : 0;
            var fault = armed && (step == "document" && Path.GetFileName(final) == "resolver.state" ||
                step == "enrollment" && Path.GetFileName(final) == "enrollment.bin" ||
                step == "prepare" && checkpoint == 1 || step == "commit" && checkpoint == 2);
            if (!fault) { actual.ReplaceFile(temporary, final); return; }
            Reached = true; armed = false;
            if (after) actual.ReplaceFile(temporary, final);
            throw new IOException("Injected protected resolver replacement boundary.");
        }
    }
    private sealed class PreparedBytesSubstitution : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier actual = new(); internal bool Armed, Reached;
        public void ReplaceFile(string temporary, string final) => actual.ReplaceFile(temporary, final);
        public void FlushParentDirectory(string path) => actual.FlushParentDirectory(path);
        public void FlushFileAndParentDirectory(string path)
        {
            actual.FlushFileAndParentDirectory(path);
            if (Armed && Path.GetFileName(path).StartsWith("resolver.state.", StringComparison.Ordinal))
            { Armed = false; Reached = true; File.AppendAllText(path, " "); }
        }
    }
}
