import boto3
import os

def get_aws_session(region="us-east-1"):
    role_arn = os.getenv("AWS_ASSUME_ROLE_ARN")

    if not role_arn:
        raise RuntimeError(
            "AWS_ASSUME_ROLE_ARN is not set. "
            "Refusing to fall back to default credentials."
        )

    sts = boto3.client("sts", region_name=region)

    assumed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="cloud-vulnerabilities-session"
    )

    creds = assumed["Credentials"]

    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region
    )
