# CloudGuard Isolated Vulnerable Test Labs

These labs create isolated, intentionally vulnerable targets for CloudGuard scanner testing:

- AWS live lab
- GCP live lab
- Kubernetes live lab
- IaC-only vulnerable folder

Do not use production accounts, real customer data, or real secrets. Use only throwaway cloud accounts/projects and dummy values.

## Safety Checklist

- Use a disposable AWS account and a disposable GCP project.
- Add budget alerts in AWS and GCP before deploying.
- Keep only dummy data in buckets and secrets.
- Use the `cloudguard-test` tag/label.
- Destroy live labs immediately after testing.

## Required Tools

- Terraform
- AWS CLI configured with a disposable profile
- gcloud configured with a disposable project
- kubectl configured to a disposable cluster

## 1. AWS Live Lab

```powershell
cd grc-platform/cloudguard-test-labs/aws
terraform init
terraform apply -var="aws_profile=cloudgoat-lab" -var="aws_region=us-east-1"
```

Destroy:

```powershell
terraform destroy -var="aws_profile=cloudgoat-lab" -var="aws_region=us-east-1"
```

## 2. GCP Live Lab

Set your disposable GCP project ID:

```powershell
cd grc-platform/cloudguard-test-labs/gcp
terraform init
terraform apply -var="gcp_project_id=YOUR_TEST_PROJECT_ID" -var="gcp_region=us-central1"
```

Destroy:

```powershell
terraform destroy -var="gcp_project_id=YOUR_TEST_PROJECT_ID" -var="gcp_region=us-central1"
```

## 3. Kubernetes Live Lab

Use a disposable kind, minikube, EKS, GKE, or AKS cluster.

```powershell
cd grc-platform/cloudguard-test-labs/kubernetes
kubectl apply -f vulnerable-k8s.yaml
```

Destroy:

```powershell
kubectl delete -f vulnerable-k8s.yaml
```

## 4. IaC Scanner Lab

Do not apply these files. Point the IaC scanner at:

```text
grc-platform/cloudguard-test-labs/iac
```

It contains Terraform, CloudFormation, and Kubernetes manifests with deliberately vulnerable patterns.

## Demo Explanation

Say:

> I built four isolated test targets: AWS, GCP, Kubernetes, and IaC. The live targets create intentionally vulnerable resources for scanner validation, while the IaC folder tests static misconfiguration scanning without deploying resources.
