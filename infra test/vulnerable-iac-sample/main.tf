terraform {
  required_version = ">= 1.3.0"
}

provider "aws" {
  region = "us-east-1"
}

# Intentionally insecure test resources for IaC scanner validation only.
resource "aws_security_group" "open_all" {
  name        = "cloudguard-iac-open-all"
  description = "Allows unrestricted inbound access for scanner testing"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "cloudguard-iac-public-bucket-demo"
}

resource "aws_s3_bucket_public_access_block" "public_bucket_controls" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "disabled_example" {
  bucket = aws_s3_bucket.public_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_db_instance" "unencrypted_postgres" {
  identifier              = "cloudguard-iac-db-demo"
  allocated_storage       = 20
  engine                  = "postgres"
  engine_version          = "14.10"
  instance_class          = "db.t3.micro"
  username                = "scanneradmin"
  password                = "Password123456!"
  db_name                 = "scannerdb"
  skip_final_snapshot     = true
  publicly_accessible     = true
  storage_encrypted       = false
  backup_retention_period = 0
}
