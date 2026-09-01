variable "gcp_project_id" {
  description = "Disposable GCP project ID."
  type        = string
}

variable "gcp_region" {
  description = "GCP region for the lab."
  type        = string
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "GCP zone for the lab VM."
  type        = string
  default     = "us-central1-a"
}

variable "test_principal" {
  description = "Optional test IAM principal to grant roles/editor, such as user:test@example.com. Leave blank to skip."
  type        = string
  default     = ""
}
