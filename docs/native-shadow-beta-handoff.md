# Native-shadow beta bundle

This bundle contains the exact Rust executables used for the successful
240 GiB NTFS-to-ReFS conversion. The original partition, label, admitted file
contents and supported metadata survived native verification, mutation and
clean reboot. The converter runs on the machine owning the disks; Hyper-V
was only the laboratory environment.

The recorded case used Windows 11 26300.9457, NTFS 3.1 with 64 KiB clusters,
ReFS 3.14 with 4 KiB clusters, and fourteen admitted objects. Six user files
and three Windows ancillary files totaled 134,500,457 bytes. This placement
relocated all nonresident payload and materialized 105 resident bytes. The
337,903,616-byte target write set had 94 patches and a 675,831,546-byte journal.
Expanded-geometry interruption and storage power-loss tests remain open.

The producer is `4befb3b92aa764a5dfe1eaf935380d75c9962909` plus the recorded
capabilities-only patch; executable hashes are authoritative for this bundle.
Later source improvements are not substituted into it. In particular, it
does not contain the newer streaming-payload/Unicode profile or removal of the
roughly 16 TiB native observation limit. Its larger-tree routing budget does
not override that known limit. Native qualification is limited to the recorded
case, not every compiled limit or Windows release.

## Prepare the volumes

Use an elevated Windows process. Select a nonboot basic GPT NTFS data volume,
an independent empty ReFS shadow volume with matching partition length/offset
and sector geometry, and independent NTFS journal storage. The shadow must
use 4 KiB clusters and label `n2r-retained-shadow`. Prepare only scratch storage;
the source NTFS partition is never a formatter target.

The larger-tree profile has a 4 GiB logical-data budget, 1,024 files and 256
directories including root. It uses ASCII components of at most 100 bytes and
16 path components. Unsupported encodings/features, aliases, names, security
state or layouts refuse admission. These are implementation ceilings, not
tested maxima. The shadow initializes payload contents and full-image scans
remain expensive: the recorded run took about 3 h 40 min. Back up valuable data
independently before using experimental conversion software.

## Run on a disposable copy

Extract the ZIP and open an elevated PowerShell in its directory. Replace the
example volume letters with the independently prepared roles. The run output
belongs on the current Windows OS volume and must be fresh.

```powershell
$operationId = [guid]::NewGuid().ToString('N')
$requestsDirectory = Join-Path $env:SystemDrive 'ntfs2refs\requests'
New-Item -ItemType Directory -Path $requestsDirectory -Force | Out-Null
$requestPath = Join-Path $requestsDirectory ($operationId + '.json')
$runRoot = Join-Path $env:SystemDrive ('ntfs2refs\runs\' + $operationId)

.\bin\ntfs2refs-bind.exe --source 'F:\' --shadow 'R:\' --journal 'J:\' `
  --experiment-id $operationId --experimental-large-tree `
  --experimental-large-journal --max-journal-bytes 1073741824 `
  --output $requestPath
if ($LASTEXITCODE -ne 0) { throw 'Binding refused; inspect its output.' }

$requestPin = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
.\bin\ntfs2refs.exe convert --request $requestPath --request-sha256 $requestPin --output $runRoot
if ($LASTEXITCODE -ne 0) { throw ('Conversion stopped; preserve recovery material in ' + $runRoot) }
```

The experimental-profile notices are written to stderr. Use PowerShell's
normal native-command error handling; do not treat a notice alone as a failed
exit code. A binding request or JSON success flag is not write authorization:
the running converter must still obtain live source and target admission.

## Interrupted work and recovery

Keep the run's `request.json`, `ticket.json`, expectation and journal location,
and use these same executables for recovery. Preserve the original disks,
shadow and journal. A stopped process can leave the target intentionally
offline. Use the public lifecycle/recovery commands after inspecting its actual
state; do not rerun `convert` over an activated operation. The core's durable
handoff permanently closes NTFS rollback before writable ReFS service.

The complete frozen-alpha recovery cases belong to a different executable and
geometry. They are not evidence of interruption recovery for this beta. See
the project's CLI workflow and beta result report for the current boundaries.

The package contains binaries, hashes and documentation only. It contains no
VM images, credentials, prebound device requests, automatic formatting or
automatic conversion script.
