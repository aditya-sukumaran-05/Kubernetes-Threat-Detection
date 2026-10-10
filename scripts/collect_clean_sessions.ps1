#requires -Version 5.1
<#!
.SYNOPSIS
Collect replacement sessions after verifying the webapp is at a clean CPU baseline.

Existing captures are never altered.  The explicit counts intentionally do not
reuse sessions collected while an orphaned CPU loop was present.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Plan = [ordered]@{
    network_normal = 2
    network_attack = 3
    workload_normal = 4
    workload_attack = 4
    fusion_normal = 4
    fusion_attack = 4
}

function Assert-CleanCpuBaseline {
    $maxAttempts = 18
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $line = (& kubectl top pod -n default -l app=webapp --no-headers)
        if ($LASTEXITCODE -eq 0 -and $line) {
            $columns = $line -split '\s+'
            if ($columns.Count -ge 2 -and $columns[1] -match '^(\d+)m$') {
                $cpuMillicores = [int]$Matches[1]
                if ($cpuMillicores -le 100) {
                    Write-Host "Clean CPU baseline: ${cpuMillicores}m"
                    return
                }
                Write-Host "Waiting for CPU to return to clean baseline (currently ${cpuMillicores}m, attempt $attempt of $maxAttempts)..."
            }
        }
        Start-Sleep -Seconds 5
    }
    throw "Refusing collection: webapp CPU baseline did not settle below 100m (last read: $line)."
}

Push-Location $ProjectRoot
try {
    foreach ($scenario in $Plan.Keys) {
        for ($index = 1; $index -le $Plan[$scenario]; $index++) {
            Write-Host "Collecting clean $scenario session $index of $($Plan[$scenario])..."
            Assert-CleanCpuBaseline
            & .\run-experiment.ps1 $scenario
            if ($LASTEXITCODE -ne 0) {
                throw "Experiment failed: $scenario session $index"
            }
        }
    }
}
finally {
    Pop-Location
}
