param(
  [Parameter(Mandatory = $true)]
  [string]$ProjectId,
  [string]$Region = "us-central1",
  [string]$Zone = "us-central1-a",
  [string]$TestPrincipal = ""
)

$ErrorActionPreference = "Stop"
$LabRoot = Split-Path -Parent $PSScriptRoot
$GcpDir = Join-Path $LabRoot "gcp"

Write-Host "Destroying GCP CloudGuard test lab from project '$ProjectId'..."
Push-Location $GcpDir
try {
  terraform destroy -auto-approve `
    -var="gcp_project_id=$ProjectId" `
    -var="gcp_region=$Region" `
    -var="gcp_zone=$Zone" `
    -var="test_principal=$TestPrincipal"
} finally {
  Pop-Location
}
