resource "aws_s3_bucket" "secure_storage" {
  bucket = "zuhaib-compliance-data-034"
}

resource "aws_s3_bucket_public_access_block" "block_all" {
  bucket = aws_s3_bucket.secure_storage.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypt" {
  bucket = aws_s3_bucket.secure_storage.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
