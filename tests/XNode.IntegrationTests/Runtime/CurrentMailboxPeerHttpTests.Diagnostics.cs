namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task RequestBodyObservationPreservesBytesEofAndInnerOwnership()
    {
        var host = new Host();
        using var inner = new MemoryStream([0x41, 0x42, 0x43]);
        using (var observed = new ObservedRequestBody(inner, host))
        {
            var bytes = new byte[3];
            await observed.ReadExactlyAsync(bytes);
            Assert.Equal(new byte[] { 0x41, 0x42, 0x43 }, bytes);
            Assert.Equal(0, await observed.ReadAsync(new byte[1]));
            Assert.Equal(3, host.BodyBytes); Assert.Equal(1, host.EndReads);
            Assert.Equal("native-receiver", host.Phase);
        }
        inner.Position = 0; Assert.Equal(0x41, inner.ReadByte());
    }

    [Fact]
    public async Task RequestBodyObservationDoesNotSwallowCancellation()
    {
        var host = new Host();
        using var inner = new MemoryStream([0x41]);
        using var observed = new ObservedRequestBody(inner, host);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            observed.ReadAsync(new byte[1], cancellation.Token).AsTask());
        Assert.Equal(0, inner.Position); Assert.Equal(0, host.BodyBytes); Assert.Equal(0, host.EndReads);
        Assert.Equal("body-read", host.Phase);
    }

    [Fact]
    public async Task RequestBodyObservationDoesNotTranslateIoFailure()
    {
        var host = new Host(); var error = new IOException("Test-owned read failure.");
        using var inner = new FailingRequestBody(error);
        using var observed = new ObservedRequestBody(inner, host);
        Assert.Same(error, await Assert.ThrowsAsync<IOException>(() => observed.ReadAsync(new byte[1]).AsTask()));
        Assert.Equal(0, host.BodyBytes); Assert.Equal(0, host.EndReads);
        Assert.Equal("body-read", host.Phase);
    }

    private sealed class FailingRequestBody(IOException error) : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) =>
            ValueTask.FromException<int>(error);
    }

    private sealed partial class Host
    {
        internal string Phase = "not-started";
        internal string? HandlerFailure;
        internal int BodyBytes, EndReads;
        internal bool RequestCancelled;
        internal long HandlerMilliseconds;
        internal TaskCompletionSource? RequestCompleted;
        // Test-only resource diagnostics, never an authority clock or payload log.
        internal string Diagnostics => $"phase={Volatile.Read(ref Phase)}; body-bytes={Volatile.Read(ref BodyBytes)}; " +
            $"end-reads={Volatile.Read(ref EndReads)}; request-cancelled={Volatile.Read(ref RequestCancelled)}; " +
            $"handler-error={HandlerFailure}; handler-elapsed-ms={Interlocked.Read(ref HandlerMilliseconds)}";
    }

    // Transparent non-owning observer: the same bytes, cancellation and exceptions
    // reach the product endpoint. An EOF observation separates body wait from
    // native receiver work without introducing a production callback or bypass.
    private sealed class ObservedRequestBody(Stream inner, Host host) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            host.Phase = "body-read";
            var read = inner.Read(buffer, offset, count);
            Record(read, count); return read;
        }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            host.Phase = "body-read";
            var read = await inner.ReadAsync(buffer, token).ConfigureAwait(false);
            Record(read, buffer.Length); return read;
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) =>
            ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
        private void Record(int read, int requested)
        {
            Interlocked.Add(ref host.BodyBytes, read);
            if (requested > 0 && read == 0)
            { Interlocked.Increment(ref host.EndReads); host.Phase = "native-receiver"; }
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
