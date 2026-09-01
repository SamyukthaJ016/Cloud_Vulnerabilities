variable "aws_profile" {
  description = "Disposable AWS CLI profile to deploy the lab into."
  type        = string
}

variable "aws_region" {
  description = "AWS region for the test lab."
  type        = string
  default     = "us-east-1"
}
