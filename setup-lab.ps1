#requires -Version 5.1
<#!
.SYNOPSIS
Initializes and verifies the local Minikube environment used by this project.

The script never deletes a Minikube cluster, webapp deployment, experiment
data, or run directory. It only recreates the explicitly named
traffic-generator Pod when it has completed or failed.
#>

$ErrorActionPreference = 'Stop'

$Namespace = 'default'
$WebappDeployment = 'webapp'
$WebappService = 'webapp'
$TrafficGenerator = 'traffic-generator'
$GadgetBin = 'C:\Users\adity\bin'

function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Fail "Required command '$Name' was not found on PATH."
    }
}

function Invoke-Checked([string]$Description, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        Fail "$Description failed (exit code $LASTEXITCODE)."
    }
}

function Wait-ForPodPhase([string]$PodName, [string]$ExpectedPhase, [int]$TimeoutSeconds = 120) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $phase = (& kubectl get pod $PodName -n $Namespace -o jsonpath='{.status.phase}' 2>$null).Trim()
        if ($phase -eq $ExpectedPhase) { return }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    Fail "Pod '$PodName' did not reach phase '$ExpectedPhase' within $TimeoutSeconds seconds."
}

function Test-KubeResource([string[]]$Arguments) {
    & kubectl @Arguments *> $null
    return $LASTEXITCODE -eq 0
}

Require-Command 'kubectl'
Require-Command 'minikube'

if (Test-Path -LiteralPath $GadgetBin) {
    $env:PATH = "$GadgetBin;$env:PATH"
}

$minikubeHost = (& minikube status -p minikube -o json 2>$null | ConvertFrom-Json).Host
if ($minikubeHost -ne 'Running') {
    Invoke-Checked 'Starting the existing Minikube profile' { minikube start -p minikube }
}

$context = (& kubectl config current-context).Trim()
if ($context -ne 'minikube') {
    Fail "Active Kubernetes context is '$context', expected 'minikube'. Refusing to continue."
}

Invoke-Checked 'Waiting for the Minikube node to be Ready' { kubectl wait --for=condition=Ready node/minikube --timeout=120s }

if (-not (Test-KubeResource @('get', 'deployment', $WebappDeployment, '-n', $Namespace))) {
    Invoke-Checked 'Creating missing webapp deployment' { kubectl create deployment $WebappDeployment -n $Namespace --image=nginx }
    Invoke-Checked 'Creating missing webapp NodePort service' { kubectl expose deployment $WebappDeployment -n $Namespace --port=80 --target-port=80 --type=NodePort --name=$WebappService }
}
elseif (-not (Test-KubeResource @('get', 'service', $WebappService, '-n', $Namespace))) {
    Invoke-Checked 'Creating missing webapp NodePort service' { kubectl expose deployment $WebappDeployment -n $Namespace --port=80 --target-port=80 --type=NodePort --name=$WebappService }
}
Invoke-Checked 'Waiting for webapp deployment readiness' { kubectl rollout status deployment/$WebappDeployment -n $Namespace --timeout=120s }

$metricsDeploymentExists = Test-KubeResource @('get', 'deployment', 'metrics-server', '-n', 'kube-system')
if (-not $metricsDeploymentExists) {
    Invoke-Checked 'Enabling Minikube metrics-server addon' { minikube addons enable metrics-server -p minikube }
}
Invoke-Checked 'Waiting for metrics-server readiness' { kubectl rollout status deployment/metrics-server -n kube-system --timeout=120s }
Invoke-Checked 'Verifying workload metrics API' { kubectl top pod -n $Namespace -l app=webapp --no-headers }

Require-Command 'kubectl'
Invoke-Checked 'Verifying Inspektor Gadget client and server' { kubectl gadget version }

$trafficPhase = (& kubectl get pod $TrafficGenerator -n $Namespace -o jsonpath='{.status.phase}' 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or -not $trafficPhase) {
    Invoke-Checked 'Creating missing traffic-generator pod' {
        kubectl run $TrafficGenerator -n $Namespace --image=busybox --restart=Never --labels=run=traffic-generator --command -- sh -c 'sleep 3600000'
    }
}
elseif ($trafficPhase -in @('Succeeded', 'Failed')) {
    Invoke-Checked 'Deleting completed traffic-generator pod' { kubectl delete pod $TrafficGenerator -n $Namespace --wait=true }
    Invoke-Checked 'Recreating traffic-generator pod' {
        kubectl run $TrafficGenerator -n $Namespace --image=busybox --restart=Never --labels=run=traffic-generator --command -- sh -c 'sleep 3600000'
    }
}
Wait-ForPodPhase -PodName $TrafficGenerator -ExpectedPhase 'Running'
Invoke-Checked 'Waiting for traffic-generator readiness' { kubectl wait --for=condition=Ready pod/$TrafficGenerator -n $Namespace --timeout=120s }

Write-Host ''
Write-Host '## Kubernetes Threat Detection Lab'
Write-Host 'Minikube:       OK'
Write-Host 'Context:        OK'
Write-Host 'Node:           Ready'
Write-Host 'Webapp:         Ready'
Write-Host 'Metrics Server: Ready'
Write-Host 'Gadget:         OK'
Write-Host 'Traffic Gen:    Running'
Write-Host 'Lab status:     READY'
