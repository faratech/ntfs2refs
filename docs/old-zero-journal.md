# Canonical old-zero journal encoding

The allocation capture can mark a complete changed range as old-zero only after
examining every actual original byte. Existing range boundaries are unchanged;
coalescing ANDs the evidence, so a range containing any nonzero byte is stored
normally. Allocation, sparse state, valid-data length and diagnostic counters
cannot establish this evidence. Preparation independently rereads every claimed
old-zero source byte and refuses a mismatch before source activation.

`SelectedPlan.old_zero_ranges` is a sorted, unique, exact subset of complete
selected ranges. When it is empty, the three previous encodings and serialized
plan fields are unchanged. A nonempty subset selects format 4, `N2ROLD01`:

| Record offset | Size | Value |
|---|---:|---|
| 0 | 8 | Target byte offset |
| 8 | 8 | Logical range length |
| 16 | 8 | New kind: literal 0, canonical zero 1, saved-old reference 2 |
| 24 | 8 | Original source offset for a new saved-old reference, otherwise 0 |
| 32 | 8 | Old kind: stored payload 0, canonical zero 1 |
| 40 | 32 | SHA-256 of the complete logical old bytes |
| 72 | 32 | SHA-256 of the complete logical new bytes |

The existing 8,192-byte marker area, 80-byte header and 80-byte footer remain;
the new footer magic is `N2ROEND1`. The descriptor and pinned plan must agree
exactly. Stored old payload precedes stored new payload for each record; canonical
zeros and copy references have no payload allocation.

For selected bytes `D`, new zeros `Z`, new copy references `C`, old zeros `O`
and record count `N`, exact journal length is:

```text
8192 + 80 + 104*N + 2*D - Z - C - O + 80
```

The fresh planner chooses this encoding only when omitted old payload exceeds
the cost of widening every record: 8 bytes per record versus copy format 3,
16 versus new-zero format 2, or 24 versus literal format 1. Otherwise it keeps
the previous journal encoding at equal or lower size. Actual capture observations remain in
the capture report; the pinned selected plan identifies the encoding used.

Old/new selected digests retain their complete logical bytes and original range
framing. The immutable-body digest covers every byte actually serialized.
Independent loading checks all descriptors, literal payloads, generated zeros,
resolved copies, selected digests and footer before returning authenticated
records. A central old-byte resolver supplies stored payload or canonical zeros
for mixed-state checks, rollback and copies crossing either representation.
Recovery remains self-contained and never resolves copies from an activated
source device. All selected writes, required ReFS zeros, exact target checks,
flushes, ordering and HND/ABT boundaries remain.

Because `J` may be smaller than `D`, the native old-zero write gate checks
`D <= J + O` with checked arithmetic, the complete allowed ranges and the
unchanged encoded selected-byte profile ceiling. Counts alone grant no source
or journal authority. Legacy native gates are unchanged.

Capture still uses the conservative `D + literal + reserve` capacity allowance
and existing resource ceilings. This first change reduces actual stored payload;
it does not widen admission to arbitrarily large changed sets. Metadata sizing
uses 104-byte records within the existing 16 MiB reserve. Sealed `e4ffb3a`
passed one normal grown V3 native case with format 4, 5,587,607,552 actual
old-zero bytes, native exit 0/HND and all 811 independent stream hashes. Its
same-plan serialized journal reduction is 5,587,579,280 bytes after record
widening. [Normal native scope](old-zero-native.md). Native old-zero fault and
recovery qualification remain pending. The focused release build passed.
The earlier `0474927` owned-file experiment passed all three previous encodings
and both old-zero modes, including persisted short-write Resume/Rollback,
cross-record copies, actual false-old-zero refusal and unchanged framed old/new
digests. Old-zero alone omitted 12,288 bytes and saved 12,216 journal bytes;
the copy case omitted 16,384 and saved 16,328. Their different legacy record
widths account for the metadata overhead. These are tiny ordinary-file results,
not native conversion qualification. Reports remain under
`.lab/hyperv/streaming-v2-20261027/old-zero-functional-8f3c08f0efa6409db9a3511f19e8e406`;
the summary SHA-256 is
`44827ea6397d5ead7b5ecd05c9f4a496753a6a871fddafa138f26b9bb36e2ac4`.
No unit tests were added or run.
