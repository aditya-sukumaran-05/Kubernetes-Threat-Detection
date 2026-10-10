#requires -Version 5.1
<# Collect only the sessions missing from the approved four-per-scenario target. #>
[CmdletBinding()]
param(
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$RunsRoot = Join-Path $ProjectRoot 'experiments\runs'
$TargetPerScenario = 4
$CleanCampaignCutoff = [DateTimeOffset]::Parse('2026-09-20T09:39:50Z')
$Scenarios = @('network_normal', 'network_attack', 'workload_normal', 'workload_attack', 'fusion_normal', 'fusion_attack')

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

function Get-EligibleRuns([string]$Scenario) {
    @(Get-ChildItem -LiteralPath $RunsRoot -Directory | ForEach-Object {
        $metadataPath = Join-Path $_.FullName 'metadata.json'
        if (-not (Test-Path -LiteralPath $metadataPath)) { return }
        $metadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
        if ($metadata.scenario -eq $Scenario -and
            $metadata.status -eq 'validated' -and
            $metadata.validation.valid -eq $true -and
            $metadata.experiment_start_time_utc -and
            ([DateTimeOffset]::Parse($metadata.experiment_start_time_utc) -ge $CleanCampaignCutoff)) {
            $metadata
        }
    })
}

Push-Location $ProjectRoot
try {
    $planSummary = [ordered]@{}
    foreach ($scenario in $Scenarios) {
        $eligibleCount = @(Get-EligibleRuns $scenario).Count
        $needed = [Math]::Max(0, $TargetPerScenario - $eligibleCount)
        $planSummary[$scenario] = [PSCustomObject]@{
            Eligible = $eligibleCount
            Target   = $TargetPerScenario
            Missing  = $needed
        }
    }

    Write-Host "=== Missing Session Campaign Plan ==="
    $totalMissing = 0
    foreach ($scenario in $planSummary.Keys) {
        $item = $planSummary[$scenario]
        $totalMissing += $item.Missing
        Write-Host ("{0,-16} : {1} eligible, {2} missing (target {3})" -f $scenario, $item.Eligible, $item.Missing, $item.Target)
    }
    Write-Host "Total missing sessions planned: $totalMissing"

    if ($DryRun) {
        Write-Host "Dry-run requested; no experiments will be executed."
        return
    }

    foreach ($scenario in $Scenarios) {
        $needed = $planSummary[$scenario].Missing
        for ($index = 1; $index -le $needed; $index++) {
            Write-Host "Collecting $scenario ($index of $needed missing sessions)..."
            Assert-CleanCpuBaseline
            & .\run-experiment.ps1 $scenario
            if ($LASTEXITCODE -ne 0) { throw "Experiment wrapper failed for $scenario." }
            $latest = @(Get-EligibleRuns $scenario | Sort-Object experiment_start_time_utc -Descending | Select-Object -First 1)
            if ($latest.Count -ne 1) { throw "No validated $scenario metadata was found after collection." }
            Write-Host "Validated session: $($latest[0].experiment_id)"
        }
    }
}
finally {
    Pop-Location
}
