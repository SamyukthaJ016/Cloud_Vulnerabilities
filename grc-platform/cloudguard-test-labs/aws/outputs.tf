output "aws_lab_bucket" {
  value = aws_s3_bucket.public_bucket.bucket
}

output "aws_lab_iam_user" {
  value = aws_iam_user.bad_user.name
}
