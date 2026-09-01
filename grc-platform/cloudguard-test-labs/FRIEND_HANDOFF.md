# Friend Handoff: CloudGuard Vulnerable Lab Testing

This guide is for running the vulnerable scanner test labs on another PC.

Do not use production cloud accounts, real customer data, or real secrets.

## What Your Friend Needs

- Docker Desktop
- Git
- Terraform
- AWS CLI
- Google Cloud CLI, only for GCP testing
- kubectl, only for Kubernetes testing
- A disposable AWS account
- A disposable GCP project
- A disposable Kubernetes cluster, such as kind, minikube, EKS, GKE, or AKS

## Safe Option

The safest option is that your friend creates their own disposable AWS account and GCP project. Then they own billing, access, and cleanup.

## If You Give Them Access To Your Test Account

Only do this for a throwaway account. Never share your root user.

For AWS:

- Create a separate IAM user for your friend.
- Give it permissions only in the disposable account.
- Rotate/delete the access key after the demo.
- Add AWS Budget alerts.

For GCP:

- Add your friend only to the disposable project.
- Use a test principal only.
- Remove their access after the demo.
- Add a budget alert.

## Copy This Folder

Give your friend this folder:

```text
cloudguard-test-labs
```

It contains:

- `aws/` Terraform for AWS vulnerable resources
- `gcp/` Terraform for GCP vulnerable resources
- `kubernetes/` vulnerable Kubernetes manifests
- `iac/` IaC-only vulnerable files for static scanning
- `scripts/` PowerShell helper scripts

## AWS Test

Your friend configures AWS CLI:

```powershell
aws configure --profile cloudguard-test
aws sts get-caller-identity --profile cloudguard-test
```

Deploy vulnerable AWS resources:

```powershell
cd cloudguard-test-labs
.\scripts\deploy-aws-lab.ps1 -Profile cloudguard-test -Region us-east-1
```

Then scan the AWS account in CloudGuard using:

- AWS Access Key ID from the `cloudguard-test` profile
- AWS Secret Access Key from the `cloudguard-test` profile
- Region: `us-east-1`
- Role ARN: leave blank unless using a real IAM role ARN
- Session Token: leave blank unless using temporary credentials

Destroy AWS lab:

```powershell
.\scripts\destroy-aws-lab.ps1 -Profile cloudguard-test -Region us-east-1
```

## GCP Test

Your friend creates a disposable GCP project and authenticates:

```powershell
gcloud auth login
gcloud config set project YOUR_TEST_PROJECT_ID
gcloud auth application-default login
```

Deploy vulnerable GCP resources:

```powershell
cd cloudguard-test-labs
.\scripts\deploy-gcp-lab.ps1 -ProjectId YOUR_TEST_PROJECT_ID
```

Then scan the GCP project in CloudGuard using the service account or credential method supported by their CloudGuard setup.

Destroy GCP lab:

```powershell
.\scripts\destroy-gcp-lab.ps1 -ProjectId YOUR_TEST_PROJECT_ID
```

## Kubernetes Test

Your friend switches kubectl to a disposable cluster:

```powershell
kubectl config current-context
```

Deploy vulnerable Kubernetes objects:

```powershell
cd cloudguard-test-labs
.\scripts\deploy-k8s-lab.ps1
```

Then scan the cluster in CloudGuard using kubeconfig.

Destroy Kubernetes lab:

```powershell
.\scripts\destroy-k8s-lab.ps1
```

## IaC Test

Your friend does not need cloud credentials for this test.

Point CloudGuard IaC scanner at:

```text
cloudguard-test-labs\iac
```

This tests Terraform, CloudFormation, and Kubernetes manifest scanning.

## Demo Explanation

Say:

> I created isolated vulnerable targets for AWS, GCP, Kubernetes, and IaC. CloudGuard scans the live cloud accounts and local IaC folder, detects misconfigurations, and then the findings can be reviewed in GRC.

## Cleanup Rule

Always destroy the AWS/GCP/Kubernetes labs after testing.
