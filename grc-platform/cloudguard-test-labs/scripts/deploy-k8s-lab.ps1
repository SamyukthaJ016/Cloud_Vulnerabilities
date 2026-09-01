$ErrorActionPreference = "Stop"
$LabRoot = Split-Path -Parent $PSScriptRoot
$Manifest = Join-Path $LabRoot "kubernetes\vulnerable-k8s.yaml"

Write-Host "Applying Kubernetes CloudGuard test lab to the current kubectl context..."
kubectl apply -f $Manifest
