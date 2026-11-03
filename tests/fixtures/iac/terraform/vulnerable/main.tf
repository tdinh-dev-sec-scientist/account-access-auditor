resource "aws_s3_bucket" "public" {
  bucket = "phase2-vulnerable-assets-example"
  acl    = "public-read"
}
