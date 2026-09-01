terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
  zone    = var.gcp_zone
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name = "cloudguard-test-${random_id.suffix.hex}"
  labels = {
    project = "cloudguard-test"
    purpose = "vulnerable-scanner-lab"
  }
}

resource "google_storage_bucket" "public_bucket" {
  name                        = "${local.name}-public"
  location                    = var.gcp_region
  uniform_bucket_level_access = true
  force_destroy               = true
  labels                      = local.labels
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_storage_bucket_object" "dummy_file" {
  bucket  = google_storage_bucket.public_bucket.name
  name    = "dummy-public-file.txt"
  content = "dummy test data only - no secrets"
}

resource "google_compute_network" "lab" {
  name                    = "${local.name}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "lab" {
  name          = "${local.name}-subnet"
  ip_cidr_range = "10.55.1.0/24"
  region        = var.gcp_region
  network       = google_compute_network.lab.id
}

resource "google_compute_firewall" "ssh_open" {
  name    = "${local.name}-ssh-open"
  network = google_compute_network.lab.name
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "rdp_open" {
  name    = "${local.name}-rdp-open"
  network = google_compute_network.lab.name
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "all_open" {
  name    = "${local.name}-all-open"
  network = google_compute_network.lab.name
  allow {
    protocol = "all"
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_instance" "bad_vm" {
  name         = "${local.name}-vm"
  machine_type = "e2-micro"
  zone         = var.gcp_zone
  labels       = local.labels

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    access_config {}
  }

  can_ip_forward = true

  shielded_instance_config {
    enable_secure_boot          = false
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    cloudguard-test = "true"
  }
}

resource "google_project_iam_member" "broad_editor" {
  count   = var.test_principal == "" ? 0 : 1
  project = var.gcp_project_id
  role    = "roles/editor"
  member  = var.test_principal
}
