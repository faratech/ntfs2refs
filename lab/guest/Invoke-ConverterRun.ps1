<# Guest worker for one converter run. Reads run.json beside itself, starts
   ntfs2refs.exe with the listed arguments, answers its confirmation prompt
   (and, with "answers": 2, its question about plain conversions before it)
   (unless run.json says "answer": false, for a run that has to consent
   by its own --yes), streams stdout/stderr to files and writes
   native-terminal.json when the process exits. It pins nothing: the host
   harness decides what to run. #>
param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$utf8 = [Text.UTF8Encoding]::new($false)
$process = $null; $output = $null; $errors = $null
try {
    $run = Get-Content -LiteralPath (Join-Path $Root 'run.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $exe = Join-Path $Root 'ntfs2refs.exe'
    $arguments = @($run.arguments)
    foreach ($argument in $arguments) { if ($argument -match '[\s"]') { throw "Argument needs quoting, which this worker does not do: $argument" } }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo.FileName = $exe
    $process.StartInfo.Arguments = $arguments -join ' '
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    # Unbuffered, shared-read files so the host can tail progress while it runs.
    $output = [IO.FileStream]::new((Join-Path $Root 'stdout.log'), [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read, 1)
    $errors = [IO.FileStream]::new((Join-Path $Root 'stderr.log'), [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read, 1)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) { throw 'Converter did not start' }
    $outTask = $process.StandardOutput.BaseStream.CopyToAsync($output, 65536)
    $errTask = $process.StandardError.BaseStream.CopyToAsync($errors, 65536)
    [IO.File]::WriteAllText((Join-Path $Root 'native-process.json'),
        (@{ pid = $process.Id; arguments = $arguments; started_utc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json), $utf8)
    # An unattended run gets no answer from here: its standard input is closed empty.
    $answers = -not ($run.PSObject.Properties['answer'] -and $run.answer -eq $false)
    # A run asked about its plain conversions as well asks twice (run.json "answers").
    $count = if ($run.PSObject.Properties['answers']) { [int]$run.answers } else { 1 }
    if ($answers) { foreach ($i in 1..([Math]::Max(1, $count))) { $process.StandardInput.WriteLine('y') }; $process.StandardInput.Flush() }
    $process.StandardInput.Close()
    $peak = 0L
    while (-not $process.WaitForExit(1000)) { $process.Refresh(); $peak = [Math]::Max($peak, $process.PeakWorkingSet64) }
    $watch.Stop()
    $null = $outTask.GetAwaiter().GetResult(); $null = $errTask.GetAwaiter().GetResult()
    $output.Flush($true); $errors.Flush($true)
    [IO.File]::WriteAllText((Join-Path $Root 'native-terminal.json'),
        (@{ native_exit = $process.ExitCode; wall_seconds = $watch.Elapsed.TotalSeconds; peak_working_set_bytes = $peak
            finished_utc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json), $utf8)
    exit $process.ExitCode
} catch {
    [IO.File]::WriteAllText((Join-Path $Root 'worker-error.txt'), ($_ | Out-String), $utf8); throw
} finally {
    if ($null -ne $output) { $output.Dispose() }; if ($null -ne $errors) { $errors.Dispose() }; if ($null -ne $process) { $process.Dispose() }
}
