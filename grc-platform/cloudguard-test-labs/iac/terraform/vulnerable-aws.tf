terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "public_read" {
  bucket = "cloudguard-test-iac-public-read-example"
  acl    = "public-read"
}

resource "aws_security_group" "ssh_open" {
  name        = "cloudguard-test-iac-ssh-open"
  description = "Unrestricted SSH for IaC scanner test"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "all_open" {
  type              = "ingress"
  security_group_id = aws_security_group.ssh_open.id
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_db_instance" "public_unencrypted" {
  identifier          = "cloudguard-test-iac-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "dummy"
  password            = "dummy-password-not-real"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

resource "aws_launch_template" "public_ip" {
  name_prefix   = "cloudguard-test-iac-"
  image_id      = "ami-12345678"
  instance_type = "t3.micro"
  network_interfaces {
    associate_public_ip_address = true
  }
}

resource "aws_iam_policy" "wildcard" {
  name = "cloudguard-test-iac-wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
