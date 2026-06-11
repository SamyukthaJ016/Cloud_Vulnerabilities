output "droplet_ip" {
  description = "Public IPv4 address for the CloudGuard Droplet."
  value       = digitalocean_droplet.cloudguard.ipv4_address
}

output "ssh_target" {
  description = "SSH target for deployment."
  value       = "${var.deploy_user}@${digitalocean_droplet.cloudguard.ipv4_address}"
}

output "spaces_bucket" {
  description = "Evidence artifact bucket."
  value       = digitalocean_spaces_bucket.evidence.name
}

output "spaces_endpoint" {
  description = "S3-compatible endpoint for DigitalOcean Spaces."
  value       = "https://${var.region}.digitaloceanspaces.com"
}
