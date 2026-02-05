# 1. VPC Module - NIST/PCI DSS Standard Networking
module "vpc" {
  source = "./vpc.tf" # Agar aapne vpc ka code alag file mein rakha hai
  # Ya agar aap official module use kar rahe hain:
  # source  = "terraform-aws-modules/vpc/aws"
  # version = "5.0.0"

  name = "compliance-vpc"
  cidr = var.vpc_cidr

  azs             = ["${var.region}a", "${var.region}b", "${var.region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true
  
  # Auditing & Logging (SOC2 Requirement)
  enable_flow_log                  = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
}

# 2. EKS Module - Secure Cluster Management
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.15.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.31"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = false # PCI DSS: Private API Endpoint

  # KMS Encryption for Secrets (HIPAA/SOX Requirement)
  create_kms_key = true
  cluster_encryption_config = {
    resources = ["secrets"]
  }

  eks_managed_node_groups = {
    compliance_nodes = {
      min_size     = 3
      max_size     = 5
      desired_size = 3

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND" # Critical workloads ke liye
      
      # IAM Role attach karna jo iam.tf mein banaya
      iam_role_arn = aws_iam_role.node_group_role.arn
    }
  }
}

# 3. Security Groups for EKS (NIST Compliance)
resource "aws_security_group" "eks_security_group" {
  name        = "eks-cluster-sg"
  description = "Allow restricted traffic only"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block] # Sirf VPC ke andar se access
  }
}
