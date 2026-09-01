terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name = "cloudguard-test-${random_id.suffix.hex}"
  tags = {
    Project = "cloudguard-test"
    Owner   = "cloudguard-test"
    Purpose = "vulnerable-scanner-lab"
  }
}

resource "aws_s3_bucket" "public_bucket" {
  bucket        = "${local.name}-public"
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "public_bucket" {
  depends_on = [
    aws_s3_bucket_public_access_block.public_bucket,
    aws_s3_bucket_ownership_controls.public_bucket,
  ]
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read"
}

resource "aws_s3_bucket_policy" "public_read" {
  depends_on = [aws_s3_bucket_public_access_block.public_bucket]
  bucket     = aws_s3_bucket.public_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "CloudGuardTestPublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = "${aws_s3_bucket.public_bucket.arn}/*"
    }]
  })
}

resource "aws_s3_object" "dummy_file" {
  bucket       = aws_s3_bucket.public_bucket.id
  key          = "dummy-public-file.txt"
  content      = "dummy test data only - no secrets"
  content_type = "text/plain"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.44.0.0/16"
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = merge(local.tags, { Name = "${local.name}-igw" })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.44.1.0/24"
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Name = "${local.name}-public-subnet" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = merge(local.tags, { Name = "${local.name}-public-rt" })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "bad_ssh" {
  name        = "${local.name}-ssh-open"
  description = "CloudGuard test: SSH open to internet"
  vpc_id      = aws_vpc.lab.id
  ingress {
    description = "bad ssh from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "bad_rdp" {
  name        = "${local.name}-rdp-open"
  description = "CloudGuard test: RDP open to internet"
  vpc_id      = aws_vpc.lab.id
  ingress {
    description = "bad rdp from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "bad_all" {
  name        = "${local.name}-all-open"
  description = "CloudGuard test: all traffic open to internet"
  vpc_id      = aws_vpc.lab.id
  ingress {
    description = "bad all traffic from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_iam_policy" "wildcard_admin" {
  name        = "${local.name}-wildcard-admin"
  description = "CloudGuard test policy with wildcard action and resource"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
  tags = local.tags
}

resource "aws_iam_user" "bad_user" {
  name = "${local.name}-bad-user"
  tags = local.tags
}

resource "aws_iam_user_policy_attachment" "bad_user_admin" {
  user       = aws_iam_user.bad_user.name
  policy_arn = aws_iam_policy.wildcard_admin.arn
}
