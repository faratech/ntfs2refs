# Windows CI

`workflows/windows.yml` runs on pushes to `main`, pull requests and manual
dispatch. The hosted `windows-2025` runner installs Rust 1.98.1 with rustfmt
and Clippy, verifies the x86-64 MSVC host and targets
`x86_64-pc-windows-msvc`. This compiles the `cfg(windows)` modules and uses the
repository's static CRT configuration.

The checks job checks formatting, runs Clippy and executes the workspace's
ordinary tests. A separate parallel job builds all workspace release executables
from the same revision. Both jobs must pass. Cold release compilation has its
own 60-minute budget rather than sharing the checks job's 45-minute deadline;
the original combined job left the build only about 29 minutes before cancellation.
Cargo dependency-consuming
commands use `--locked`; the toolchain check refuses silent drift from
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
[Windows 2025 runner image inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md).

A passing result must be observed for the revision being integrated; the
workflow file or a green run for an earlier revision is not sufficient.
Formatting and documentation closeout does not replace the independently
qualified release executable or transfer its native evidence to another binary.
