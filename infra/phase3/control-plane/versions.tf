terraform {
  required_version = ">= 1.9.8, < 1.10.0"
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.83.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      project     = "guardrails-phase3"
      environment = "demo"
      managed_by  = "terraform"
    }
  }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags {
    tags = {
      project     = "guardrails-phase3"
      environment = "demo"
      managed_by  = "terraform"
    }
  }
}
