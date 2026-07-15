terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_regions[0]
}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  # GCP service account account_id is capped at 30 chars; truncate so
  # name_prefix + longest suffix ("-scheduler", 10 chars) still fits.
  sa_prefix = substr(local.name_prefix, 0, 20)
  common_labels = merge(var.labels, {
    project     = var.project_name
    environment = var.environment
    managed_by  = "terraform"
  })
}
