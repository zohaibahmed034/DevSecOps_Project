variable "region" {
  description = "AWS Region jahan resources deploy hongi"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS Cluster ka naam"
  type        = string
  default     = "zuhaib-compliance-cluster"
}

variable "vpc_cidr" {
  description = "VPC ka CIDR range"
  type        = string
  default     = "10.0.0.0/16"
}
