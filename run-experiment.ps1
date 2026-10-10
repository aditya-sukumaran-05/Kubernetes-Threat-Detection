#requires -Version 5.1
<#!
.SYNOPSIS
Thin local wrapper for one Phase 3 Kubernetes experiment.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('network_normal', 'network_attack', 'workload_normal', 'workload_attack', 'fusion_normal', 'fusion_attack')]
    [string]$Scenario
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$SetupScript = Join-Path $ProjectRoot 'setup-lab.ps1'

if (-not (Test-Path -LiteralPath $SetupScript)) {
    Write-Error "Lab setup script not found: $SetupScript"
    exit 1
}

Write-Host "Preparing local lab for scenario: $Scenario"
& $SetupScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "Lab setup failed; experiment '$Scenario' was not started."
    exit $LASTEXITCODE
}

Push-Location $ProjectRoot
try {
    Write-Host "Starting Phase 3 experiment: $Scenario"
    & python -m experiments.run_experiment --scenario $Scenario --execute
    $runnerExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

if ($runnerExitCode -ne 0) {
    Write-Error "Experiment '$Scenario' failed (exit code $runnerExitCode)."
    exit $runnerExitCode
}

Write-Host "Experiment '$Scenario' completed successfully. See the runner result above for its run directory and validation status."
exit 0
