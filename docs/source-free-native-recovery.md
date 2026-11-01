# Source-free native recovery

The prepared-source format5 case now has a real flushed-first-write interruption
and native Resume/Rollback. All ran inside the owning Windows11 VM; no raw replay
occurred after HND. Rollback started separately from ORIGINAL interrupted
checkpoint7721d92e, never the resumed branch.

The interrupted c2c1ef3 producer4456/birth1793571035196 exited86 after one actual
flushed payload write. Its132,774,832-byte journal includes402,669,568 hash-only
free bytes. The restore-required allocated scope is143,527,936 bytes. Actual
source offline1/shadow offline+readonly3, no Apply/HND and complete metadata pins
were verified before normal shutdown and saving the original state.

Public Resume4688/birth1793571990732 completed in18.7571244 seconds with
ApplyIntent, an exclusive loaded journal owner, N2RFRE01 and HND. It restored
native ReFS service and passed all811 independent stream hashes. The successful
branch is preserved atd9e580fa;57 archived metadata files88,487,120 bytes were
source/copy SHA-verified. Timing excludes lab metadata prechecks and observers.

Public Rollback6052/birth1793572869378 completed in9.8437227 seconds with
ApplyIntent, an exclusive journal owner and ABT. The143,527,936-byte restoration
scope matched checksumc395ac7284dcc32ba73e148957e544d837fc1c7423291f09c1ec32aefac36ceb.
NTFS service and all811 independent hashes passed.55 metadata files61,767,592 bytes
were source/copy SHA-verified; restored state67eda3e4 is preserved separately.

This qualifies the recorded controlled interruption and both recovery directions. It does not
establish physical-power-loss safety or prove that the first interrupted write
modified a free range. Rollback compared `old_restored_selected_sha256` over
D-F; journal markers/footer retain their original full-old checksum identity.

The next Rust candidate reuses closing metadata read buffers. Its focused and
optimized builds and source review passed; none of this c2 native recovery
evidence qualifies that new runtime. No unit tests were added or run.

[Exact observations and artifact pins](../evidence/source-free-recovery-native-20261101.json).
