# Encrypted BLOB chunk storage component

This is an internal filesystem component, not an active Blob service, endpoint,
upload permission or remote receipt. The normative attachment semantics belong
to [CONTACT-AND-GROUP §16](../../docs/architecture/CONTACT-AND-GROUP-PROTOCOL-V1.md),
the route/circuit requirements to [XPoint §12.2](../../docs/architecture/XPOINT-NETWORK-V1.md),
and lifecycle deadlines to [retention policy](../../docs/architecture/RETENTION-AND-RECOVERY-V1.md).
`IAttachmentBlobTransport` remains unfrozen. Do not expose a direct `/file` URL.

`DurableBlobChunkStore` stores exact opaque ciphertext by its SHA256 commitment
under one exclusively leased, service-restricted directory. Both byte and file
quotas are bounded and reconstructed from actual durable files at reopen.
Filename generation accepts only an exact commitment; no user filename, manifest,
key, device, conversation or identity enters this store. It does not receive raw
capabilities. The eventual service must authenticate and authorize access first.

Publication stages a bounded regular file, flushes content and its parent, promotes
it atomically and flushes the committed file/parent before returning. Exact retries
verify bytes and do not rewrite a committed chunk or consume quota twice. Failed
durability has outcome-unknown semantics and closes the instance until reopen.
Cancellation after promotion may also leave a committed chunk; retry uses its
exact commitment. Reopen discards only closed, randomly named unpublished staging
files, never unknown entries or corrupt committed ciphertext. Reparse points,
hostile sizes, integrity failures and an incompatible smaller quota reject.

Verification (focused; production image/full gate unchanged):

```powershell
dotnet test tests/XNode.Tests/XNode.Tests.csproj -c Release -m:1 `
  -p:DeepProtocolSourceCutover=true -p:UseSharedCompilation=false `
  --filter FullyQualifiedName~DurableBlobChunkStoreTests
docker build --file eng/Dockerfile.blob-storage-tests `
  --build-context deep_protocol=../deep-protocol `
  --tag xnode-blob-storage-tests:local .
```

The Docker lane uses the existing digest-pinned SDK, no service ports/state mounts,
and no production keys. It verifies actual Linux file barriers and cold reopen,
not a real power cut. The component's absence of a delivery/authority caller is
intentional until a frozen masked-circuit/service contract exists. Per-object
immutable index/fork custody, capability/placement admission, padded objects,
reference-aware retention, replication, signed receipts, client resume and real
Windows/Android transfer remain required. Do not advertise this component test as
Blob role readiness or release acceptance.
