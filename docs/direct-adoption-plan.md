# Direct extent adoption candidates

`lab-ntfs-adoption-plan` reads a frozen NTFS inspection and a separately
measured ReFS occupied-range map. It plans each supported ordinary stream in
**bytes**, then classifies logical ranges as `adopt`, `relocate`, `materialize`,
or `hole`. It accepts 4 KiB or 64 KiB target clusters. Resident content and
uninitialized streams need materialization; unaligned or occupied source
clusters need relocation; sparse holes remain holes when they can be expressed
at the target cluster boundary. The result is diagnostic and never authorizes
a volume write. For saved inspections, it uses the actual partition length;
NTFS's boot-sector total can exclude its final backup sector.

Future native shadow reports include a compressed, complete
metadata-inclusive allocation bitmap with its SHA-256 and cluster count. The
planner accepts that map directly and checks its interval totals and volume
geometry. It still treats the map as evidence, not as authority to adopt a
cluster: fixed bootstrap sectors, metadata references and refcount ownership
need an independent graph check before a writer may claim space.

On the protected four-file NTFS tree, the full 512 KiB would be an adoption
candidate if the target had no occupied ranges at those locations. The native
ReFS metadata-inclusive bitmap reported all four source ranges occupied.
Using those measured ranges, the Rust planner classified all 512 KiB for
relocation, matching the separately observed native shadow placement. The
reports are under `.lab/development/ordinary-adoption-plan*.json`.

The target occupancy input must ultimately come from an independent complete
ReFS allocator and metadata-ownership graph. A Medium-allocator free bit alone
is insufficient: the isolated REFSNT experiment found an early `MSB+` page
that its Medium-only `RfsClusterFree` query considered free. The current
planner also does not serialize ReFS metadata, reserve physical ranges through
the writer, handle named streams, or issue a source-admission certificate.
