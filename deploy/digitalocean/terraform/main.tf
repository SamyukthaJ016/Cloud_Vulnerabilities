terraform {
  required_version = ">= 1.5.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

provider "digitalocean" {
  token             = var.do_token
  spaces_access_id  = var.spaces_access_id
  spaces_secret_key = var.spaces_secret_key
}

locals {
  tags = ["cloudguard", var.environment]
}

resource "digitalocean_ssh_key" "cloudguard" {
  name       = "${var.project_name}-${var.environment}"
  public_key = file(var.ssh_public_key_path)
}

resource "digitalocean_spaces_bucket" "evidence" {
  name   = var.spaces_bucket_name
  region = var.region
  acl    = "private"
}

resource "digitalocean_droplet" "cloudguard" {
  image      = var.droplet_image
  name       = "${var.project_name}-${var.environment}"
  region     = var.region
  size       = var.droplet_size
  ssh_keys   = [digitalocean_ssh_key.cloudguard.fingerprint]
  monitoring = true
  backups    = var.enable_backups
  tags       = local.tags

  user_data = templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    deploy_user = var.deploy_user
  })
}

resource "digitalocean_firewall" "cloudguard" {
  name        = "${var.project_name}-${var.environment}-firewall"
  droplet_ids = [digitalocean_droplet.cloudguard.id]
  tags        = local.tags

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_cidrs
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_project" "cloudguard" {
  name        = "${var.project_name}-${var.environment}"
  description = "CloudGuard security scanner on DigitalOcean"
  purpose     = "Web Application"
  environment = var.environment == "prod" ? "Production" : "Development"
  resources = [
    digitalocean_droplet.cloudguard.urn,
  ]
}
