$ErrorActionPreference = "Stop"
$LabRoot = Split-Path -Parent $PSScriptRoot
$Manifest = Join-Path $LabRoot "kubernetes\vulnerable-k8s.yaml"

Write-Host "Deleting Kubernetes CloudGuard test lab from the current kubectl context..."
kubectl delete -f $Manifest --ignore-not-found=true
