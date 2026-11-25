# INTENTIONALLY INSECURE TERRAFORM TEST FIXTURE
# Never deploy this configuration.

resource "aws_s3_bucket" "benchmark_bucket" {
  bucket = "security-scanner-benchmark-example"
}

resource "aws_security_group" "benchmark_sg" {
  name = "benchmark-insecure-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
