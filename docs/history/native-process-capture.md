# Native lab process lifetime and output capture

The failed probe case `win11-20261024T034413955Z` retains its original
`completionKnown=true, exitCode=null` launcher evidence. Its successful Rust
report does not retroactively make that process record successful. The next run
uses a new pinned wrapper revision.

`Invoke-GuestNativeProbe.ps1` and `Invoke-GuestNativeReconstruct.ps1` embed the
same small managed runner. It owns `System.Diagnostics.Process` from `Start`
through exit-code retrieval, then disposes it only after process exit and both
capture tasks have completed. This explicitly retains the native process handle
used to retrieve exit information. Microsoft documents that the handle retains
the exited process's administrative information until the component releases it,
and that `ExitCode` requires a valid handle and an exited process.
[Process.WaitForExit](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.waitforexit?view=netframework-4.8.1),
[Process.ExitCode](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.exitcode?view=netframework-4.8.1).

Each stream has a separate asynchronous byte pump. Capture files are create-new,
flushed, and limited to 65,536 bytes each. Excess bytes are drained without being
saved, and an explicit overflow flag refuses successful validation even if the
child exits zero. These files are incomplete prefixes when overflow occurs.
The runner closes empty stdin and does not invoke a shell. Its callers supply
only the already constrained guest paths and validated CLI arguments.

The finite deadline covers process exit and both capture tasks. A timeout or
capture failure leaves completion unknown, retains the process and pumps in a
static collection, and does not kill or dispose the process. The host must
preserve its guest session and branch. This does not make process lifetime
survive a terminated guest PowerShell process or a VM power loss. No new guest
dependency is staged; a fresh PowerShell process is required so a preloaded
managed type cannot substitute for the pinned implementation.

`lab/Test-NativeProcessCapture.ps1` runs harmless local children to test rapid
zero/nonzero exits, exact stdout/stderr, EOF on stdin, timeout followed by garbage
collection and natural completion, capture overflow, and create-new/start
failures. It also checks both embedded implementations are identical. These
tests exercise actual OS process lifetime, complementing the wrappers' mocked
process/result guards; they do not run VM or storage operations.
