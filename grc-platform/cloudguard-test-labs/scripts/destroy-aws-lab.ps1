param(
  [string]$Profile = "cloudgoat-lab",
  [string]$Region = "us-east-1"
)

$ErrorActionPreference = "Stop"
$LabRoot = Split-Path -Parent $PSScriptRoot
$AwsDir = Join-Path $LabRoot "aws"

Write-Host "Destroying AWS CloudGuard test lab from profile '$Profile' region '$Region'..."
Push-Location $AwsDir
try {
  terraform destroy -auto-approve -var="aws_profile=$Profile" -var="aws_region=$Region"
} finally {
  Pop-Location
}
