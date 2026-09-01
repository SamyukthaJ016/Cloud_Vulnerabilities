output "gcp_lab_bucket" {
  value = google_storage_bucket.public_bucket.name
}

output "gcp_lab_vm" {
  value = google_compute_instance.bad_vm.name
}
