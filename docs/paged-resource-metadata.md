# Paged metadata in the native-shadow alpha

Fresh allocation-bounded conversion now selects count-admission schema 2 after
complete frozen-source allocation, namespace and security reconciliation. The
descriptor pins actual counts, the inspection digest, expected-object and recovery
map page budgets, semantic byte limits and projected owning handles. The complete
raw identity domain remains limited to 2,048; this is not arbitrary-volume or
unlimited-file-count support.

The object allowance is derived from the actual raw count and remaining room in
the existing 34,056 owning-handle budget, rather than a fixed 1,280-object split.
Native construction and observation require an actual authenticated page owner
for schema 2. Supplying descriptor JSON or passing a legacy input slice cannot
satisfy that requirement. Existing schema-1 descriptors are preserved exactly;
whole-image construction and independent source baselines keep their legacy
admission path.

`expectation.pages` carries bounded chunks of object JSON. Individual large
objects may span pages, preserving the previous 16 MiB semantic JSON budget
without imposing a new 4 MiB object limit. Encoded file overhead has a separate
derived budget. Page framing, an on-disk ordinal index, complete counts, ordered
keys and SHA-256 pins are checked before any reader is returned. The reader
retains an ordinary-file handle excluding write/delete sharing and caches at
most one encoded page. Callers still exclude raw aliases and writable mappings.

Construction, protected target observation, converted verification and recovery
decode one object at a time. Every existing native owning handle remains held;
this change does not introduce handle batching. Compact path and child indexes
avoid decoding the whole object domain for every directory entry. Complete
retrieval queries remain in place.

Fresh fast conversion writes `recovery-payload-manifest.pages`. The recovery map
reader validates the complete expected stream/directory key set, map contents,
source identity, selected plan and ticket before opening a journal or target.
It then retrieves individual records through its retained reader. Old JSON map
manifests remain readable. Schema-2 bundles additionally require a pinned
`expectation_pages` input; the original `expectation.json` and its semantic SHA
remain pinned for certificates and compatibility. All new metadata files remain
subject to the existing data-volume exclusions and revalidation boundaries.

The read-only `lab-inspect-paged-metadata` binary checks these pinned artifacts
without opening a journal or source device. It does not grant conversion or
recovery authority. The clean candidate builder includes this observer binary.

Four focused binary compilation checks pass. No unit tests were added or run.
Native qualification of this new path is pending; the earlier 1,084-object
conversion evidence does not qualify these changes. Source inspection and native
reports still have bounded in-memory collections, and the existing 16 MiB
semantic, 64 MiB inspection/report/map and stream/range budgets remain. Further
scaling requires paging those domains and a separate owning-handle design.
