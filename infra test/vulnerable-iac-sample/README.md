## Vulnerable IaC Sample

This folder is intentionally insecure and exists only to test the IaC scanning flow.

Use this path in the dashboard:

```text
./infra/vulnerable-iac-sample
```

Expected finding types:

- Open security groups
- Public S3 bucket access
- Weak or missing storage protections
- Publicly accessible database configuration

Do not deploy these files to a real environment.
