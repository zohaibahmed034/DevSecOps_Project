module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  cluster_name    = "secure-cluster"
  cluster_version = "1.31"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  # API access ko private rakhna (PCI Standard)
  cluster_endpoint_public_access = false 

  eks_managed_node_groups = {
    nodes = {
      min_size     = 3
      max_size     = 5
      desired_size = 3
      instance_types = ["t3.medium"]
    }
  }
}
