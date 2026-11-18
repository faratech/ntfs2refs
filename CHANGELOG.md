# Changelog

What changed for someone who runs the converter. The measurements behind each
entry are in the pull request named beside it and in `docs/performance.md`.

## 0.4.0 (not yet released)

This section is a draft: it lists what is merged or on the release's branches
and is corrected against the final lab runs before the release is built.

### Memory

- A run's memory follows the volume instead of fixed reservations. A volume of
  500,000 files converts on a machine with 13 GB of RAM free, where it was
  refused with 15.6 GiB free (#157).
- `--memory-limit <MiB>` holds a run to a limit. With less memory a run keeps
  less in memory and takes longer; it no longer falls off a cliff. A limit
  below what the volume needs is refused before anything is built (#159).
- When memory is short the rows of the volume's walks go to working storage,
  and caches a run keeps only to go faster are given back (#157, #160, #162).
- `--check` says how much memory a volume needs, and the figure is tested
  against runs held to it (#131, #159, #164).
- A directory with very many entries no longer needs thirty-two times its
  listing in memory (#164).

### Speed

- A full Windows volume converts faster than with 0.3.0-beta.1 (the figures
  are filled in from the final runs): parallel metadata passes where memory
  is spare, digests computed off the writing thread, records parsed as text,
  stream tails read in parallel (#141, #142, #143, #145, #152).

### What it converts

- `--list` says of an optical drive or a mounted disc image what it is,
  instead of printing "Incorrect function (os error 1)" for it. A volume whose
  query fails for another reason is named by its drive letter (#147).
- The working directory may be on an MBR disk. The volume to convert must
  still be on a GPT disk (#108).

### Removed

- The routes and commands of earlier designs that `--help` did not list:
  `--whole-image-verification`, `--experimental-thin-shadow`,
  `--experimental-thin-backing-bytes`, `--experimental-allocation-bounded`,
  and the subcommands `inspect`, `plan`, `verify`, `diff`, `compare-retained`,
  `convert`, `resume`, `rollback`, `finalize`, `complete-label`,
  `operation-state` and `cancel`. `capabilities` is the one subcommand left.
  The executable is about a fifth smaller. The tag `archive/hidden-routes`
  keeps the removed code. `--recover` and `--recover --rollback` are
  unchanged.

### For those who build it

- The checks and gates are two local commands, `lab\Invoke-Checks.ps1` and
  `lab\Invoke-GateRound.ps1`; the unit tests run in seconds (#153).
- The gate round has a case with middling memory: 100,000 files held to
  1,240 MiB, with a time bound (#164).

## 0.3.0-beta.1 (2026-11-15)

- `--check`: reads a volume while it stays online and says every refusal a
  conversion would give, and what a conversion takes in working storage,
  memory and time. A conversion runs the same check before it changes
  anything (#119, #121).
- A data volume on a disk it shares with other partitions converts (#126).
- `--short-names drop` converts a data volume that has 8.3 short names (#133).
- `--compare-listing`: a run lists the volume before and after and compares
  the two (#122).
- Windows Server 2025 and standard ReFS as a target (#119).
- A directory's case-sensitive mark no longer refuses a volume when no two
  names in it differ only by case; the mark is not carried over (#121).
- Backup software's shadow-copy provider refuses a volume only if it holds
  something (#134).
- A disk that goes offline is given time to lose its volumes before it comes
  online again; a cancelled run says what it left behind (#128, #130).

## 0.2.0-beta.1 (2026-11-13)

- A used data volume converts; refusals say what to do; feature and recovery
  matrices (#93).
- A run that is cut off while it prepares can be cancelled with
  `--recover ... --rollback` (#97).

## 0.0.1-alpha (2026-11-11)

- A Windows boot volume converted in place from another Windows installation
  and started from ReFS in the lab (#27).
