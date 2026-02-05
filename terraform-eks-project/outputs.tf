output "cluster_endpoint" {
  description = "EKS Control Plane ka URL"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "EKS Cluster ka Security Group ID"
  value       = module.eks.cluster_security_group_id
}

output "vpc_id" {
  description = "VPC ka ID jahan resources hain"
  value       = module.vpc.vpc_id
}

output "s3_bucket_arn" {
  description = "Secure S3 Bucket ka ARN"
  value       = aws_s3_bucket.secure_storage.arn
}
