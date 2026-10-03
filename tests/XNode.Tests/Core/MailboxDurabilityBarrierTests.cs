using System.ComponentModel;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class MailboxDurabilityBarrierTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WindowsTransientNativeLock_ReplacesOnlyTheOriginalTemporaryFile(bool lockTemporary)
    {
        if (!OperatingSystem.IsWindows()) return;
        WithFiles((temporary, final) =>
        {
            using var held = new FileStream(lockTemporary ? temporary : final,
                FileMode.Open, FileAccess.Read, FileShare.Read);
            var delays = new List<int>();
            var barrier = new MailboxDurabilityBarrier(delay =>
            {
                delays.Add(delay);
                Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(final));
                Assert.Equal(new byte[] { 4, 5, 6 }, File.ReadAllBytes(temporary));
                held.Dispose();
                Thread.Sleep(delay);
            });
            barrier.ReplaceFile(temporary, final);
            Assert.NotEmpty(delays);
            Assert.InRange(delays.Count, 1, 3);
            Assert.Equal(new byte[] { 4, 5, 6 }, File.ReadAllBytes(final));
            Assert.False(File.Exists(temporary));
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WindowsPermanentNativeLock_ExhaustsBoundWithoutChangingEitherFile(bool lockTemporary)
    {
        if (!OperatingSystem.IsWindows()) return;
        WithFiles((temporary, final) =>
        {
            using var held = new FileStream(lockTemporary ? temporary : final,
                FileMode.Open, FileAccess.Read, FileShare.Read);
            var delays = new List<int>();
            var barrier = new MailboxDurabilityBarrier(delays.Add);
            var error = Assert.Throws<Win32Exception>(() => barrier.ReplaceFile(temporary, final));
            Assert.Contains(error.NativeErrorCode, new[] { 5, 32, 33 });
            Assert.Equal(new[] { 10, 20, 40 }, delays);
            Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(final));
            Assert.Equal(new byte[] { 4, 5, 6 }, File.ReadAllBytes(temporary));
        });
    }

    [Fact]
    public void WindowsReadOnlyDestination_FailsWithoutClearingItsProtection()
    {
        if (!OperatingSystem.IsWindows()) return;
        WithFiles((temporary, final) =>
        {
            var original = File.GetAttributes(final);
            File.SetAttributes(final, original | FileAttributes.ReadOnly);
            try
            {
                var delays = new List<int>();
                var barrier = new MailboxDurabilityBarrier(delays.Add);
                var error = Assert.Throws<Win32Exception>(() => barrier.ReplaceFile(temporary, final));
                Assert.Equal(5, error.NativeErrorCode);
                Assert.Equal(new[] { 10, 20, 40 }, delays);
                Assert.True(File.GetAttributes(final).HasFlag(FileAttributes.ReadOnly));
                Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(final));
                Assert.Equal(new byte[] { 4, 5, 6 }, File.ReadAllBytes(temporary));
            }
            finally { File.SetAttributes(final, original); }
        });
    }

    [Fact]
    public void WindowsMissingTemporaryFile_DoesNotRetryOrReportSuccess()
    {
        if (!OperatingSystem.IsWindows()) return;
        WithFiles((temporary, final) =>
        {
            File.Delete(temporary);
            var barrier = new MailboxDurabilityBarrier(_ => throw new InvalidOperationException("No retry without source custody."));
            var error = Assert.Throws<Win32Exception>(() => barrier.ReplaceFile(temporary, final));
            Assert.Equal(2, error.NativeErrorCode);
            Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(final));
            Assert.False(File.Exists(temporary));
        });
    }

    private static void WithFiles(Action<string, string> test)
    {
        var root = Path.Combine(Path.GetTempPath(), "xnode-native-replace-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var temporary = Path.Combine(root, "new.tmp");
            var final = Path.Combine(root, "current.state");
            File.WriteAllBytes(temporary, [4, 5, 6]);
            File.WriteAllBytes(final, [1, 2, 3]);
            test(temporary, final);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
