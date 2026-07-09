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
  common_labels = merge(var.labels, {
    project     = var.project_name
    environment = var.environment
    managed_by  = "terraform"
  })
}
