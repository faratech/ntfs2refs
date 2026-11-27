function Get-ReleaseArchiveSourceDocuments([string]$Source) {
    'README.md'
    'DISCLAIMER.md'
    'docs/cli-workflow.md'
    'docs/feature-matrix.md'
    'docs/recovery-matrix.md'
    if (Test-Path -LiteralPath (Join-Path $Source 'LICENSE') -PathType Leaf) { 'LICENSE' }
}
