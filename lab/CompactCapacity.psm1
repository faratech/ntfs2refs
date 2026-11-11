# Forecast for the enrolled 52-GiB compact lab case. This is separate from the
# converter's packed-image/journal requirements and is not a storage reservation.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Get-CompactExperimentForecast {
    param(
        [Parameter(Mandatory)][ValidateRange(1,68719476736)][long]$ObservedOsChildBytes,
        [Parameter(Mandatory)][ValidateRange(1,17179869184)][long]$MaximumJournalBytes,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ObservationReference
    )
    $osForecast=[long]([Math]::Ceiling(([decimal]$ObservedOsChildBytes * 1.25) / 1MB) * 1MB)
    $components=[ordered]@{
        osChildHighWaterWithMargin=$osForecast
        shadowMetadata=256MB
        packedChangedBytes=[long][Math]::Ceiling($MaximumJournalBytes / 2)
        journal=$MaximumJournalBytes
        sourceAndNativeMountGrowth=512MB
        recoveryHeadroom=512MB
        reportsAndTools=64MB
    }
    $sum=[long]0
    foreach($value in $components.Values){$sum+=[long]$value}
    $rounded=[long]([Math]::Ceiling([decimal]$sum / 1GB) * 1GB)
    [pscustomobject]@{
        schemaVersion=1
        kind='measured-compact-lab-forecast'
        observationReference=$ObservationReference
        observedOsChildBytes=$ObservedOsChildBytes
        components=$components
        additionalBytes=$rounded
        hardReservation=$false
        continuousEnforcement=$false
        sourceReconstructionStillRequiresLiveAdmission=$true
    }
}
Export-ModuleMember -Function Get-CompactExperimentForecast
