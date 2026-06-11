variable "do_token" {
  description = "DigitalOcean API token."
  type        = string
  sensitive   = true
}

variable "spaces_access_id" {
  description = "DigitalOcean Spaces access key."
  type        = string
  sensitive   = true
}

variable "spaces_secret_key" {
  description = "DigitalOcean Spaces secret key."
  type        = string
  sensitive   = true
}

variable "project_name" {
  description = "Base name for DigitalOcean resources."
  type        = string
  default     = "cloudguard"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "prod"
}

variable "region" {
  description = "DigitalOcean region slug."
  type        = string
  default     = "blr1"
}

variable "droplet_size" {
  description = "DigitalOcean Droplet size slug."
  type        = string
  default     = "s-2vcpu-4gb"
}

variable "droplet_image" {
  description = "DigitalOcean image slug."
  type        = string
  default     = "ubuntu-24-04-x64"
}

variable "enable_backups" {
  description = "Enable DigitalOcean Droplet backups."
  type        = bool
  default     = true
}

variable "ssh_public_key_path" {
  description = "Path to the public SSH key Terraform should add to the Droplet."
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "ssh_allowed_cidrs" {
  description = "CIDR ranges allowed to SSH to the Droplet."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}

variable "deploy_user" {
  description = "Linux user created by cloud-init for deployments."
  type        = string
  default     = "cloudguard"
}

variable "spaces_bucket_name" {
  description = "DigitalOcean Spaces bucket name for evidence artifacts."
  type        = string
}
