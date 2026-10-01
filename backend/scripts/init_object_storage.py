"""Create the local evidence bucket without a separate MinIO client image."""

import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def ensure_bucket(client, bucket):
    try:
        client.head_bucket(Bucket=bucket)
        return
    except ClientError as exc:
        if str(exc.response.get("Error", {}).get("Code")) not in {"404", "NoSuchBucket", "NotFound"}:
            raise
    try:
        client.create_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "BucketAlreadyOwnedByYou":
            raise
    client.head_bucket(Bucket=bucket)


def main():
    client = boto3.client(
        "s3",
        endpoint_url=os.environ["OBJECT_STORAGE_ENDPOINT_URL"],
        region_name=os.environ.get("OBJECT_STORAGE_REGION", "dokploy"),
        aws_access_key_id=os.environ["OBJECT_STORAGE_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["OBJECT_STORAGE_SECRET_ACCESS_KEY"],
        config=Config(signature_version="s3v4", retries={"mode": "standard", "max_attempts": 5}),
    )
    ensure_bucket(client, os.environ["OBJECT_STORAGE_BUCKET"])
    print("Evidence bucket is ready.")


if __name__ == "__main__":
    main()
