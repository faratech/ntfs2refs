# Checks

**The checks run locally.** `lab\Invoke-Checks.ps1 -Commit <commit>` checks
one exact commit in a worktree of its own with the pinned toolchain: the
formatting, Clippy, all tests, and every executable built in release mode,
the converter started once. It prints a
table, writes it as Markdown with `-Report`, and exits 1 if a check failed.
A change is integrated only when that table, for the commit being merged, is
in its pull request with every check passed. GitHub Actions is not used for
this (the owner's decision of 15 November 2026, when the account's Actions
jobs stopped starting): nothing runs on a push or a pull request.

The workflow below is the same checks on a hosted runner. It is kept for
whoever wants them there and starts only by manual dispatch.

## The workflow

`workflows/windows.yml` runs on manual dispatch only. The hosted `windows-2022` runner installs Rust 1.98.1 with rustfmt
and Clippy, verifies the x86-64 MSVC host and targets
`x86_64-pc-windows-msvc`. This compiles the `cfg(windows)` modules and uses the
repository's static CRT configuration.

The lane is three jobs that run side by side, each with its own checkout and
toolchain and a limit of 60 minutes:

- `checks`: formatting and Clippy.
- `tests`: the workspace's ordinary tests, which builds and links every
  target.
- `release`: every executable of the workspace built and linked in release
  mode, the two a release ships among them, and the converter started once.

As one job in sequence the lane took 42 minutes, 29 of them building 113
executables in release mode, nearly all of them for lab stages that were
retired. Those executables have left the tree (`lab/RETIRED.md` names the tag
that has them); the workspace now builds the converter, the listing tool and
the executable of the restart route. Cargo dependency-consuming commands
use `--locked`; the toolchain check refuses silent drift from
`rust-toolchain.toml`.

Clippy uses the repository's current lint severities. Existing and new warnings
are printed and remain advisory; compiler errors and denied lint failures fail
the job. There is no `continue-on-error`, warning suppression or claim that
`-D warnings` passes. A warning-free gate requires a separate reviewed cleanup
or explicit baseline policy.

CI does not create or run Hyper-V VMs, attach disks, run converters against live
devices, fetch native disk images, use laboratory credentials or enable the
ignored native-corpus tests. Ordinary-file recovery tests can still launch
their private ignored child-test helper. Passing CI is compilation and test
evidence, not native ReFS acceptance, conversion qualification or crash safety.
Those results remain separately recorded under the laboratory evidence docs.

The workflow has read-only repository permissions and leaves no checkout
credentials in Git configuration. No caches or build-artifact uploads are
configured; images, `.lab`, recovery journals and secrets stay outside CI.

The checkout action is pinned to full commit
`fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09`, resolved from the official
`actions/checkout` v5 tag and verified through its GitHub API commit and action
source on October 25, 2026. See the
[pinned checkout commit](https://github.com/actions/checkout/commit/fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09)
and the official
[Windows 2022 runner image inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md).

The CI host is a build/test environment, not the native conversion qualification
target. The frozen Windows 11 release and its native evidence remain unchanged.

A passing result must be observed for the revision being integrated; a
table for an earlier revision is not sufficient.
Formatting and documentation closeout does not replace the independently
qualified release executable or transfer its native evidence to another binary.
