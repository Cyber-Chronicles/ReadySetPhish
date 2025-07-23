provider "aws" {
  region = var.AWS_REGION
}

resource "aws_vpc" "prod-vpc" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  instance_tenancy     = "default"
  tags                 = { Name = "prod-vpc" }
}

resource "aws_internet_gateway" "prod-igw" {
  vpc_id = aws_vpc.prod-vpc.id
  tags   = { Name = "prod-igw" }
}

# Public Route Table
resource "aws_route_table" "prod-public-crt" {
  vpc_id = aws_vpc.prod-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.prod-igw.id
  }
  tags = { Name = "prod-public-crt" }
}

# Private Route Table (no internet gateway)
resource "aws_route_table" "prod-private-crt" {
  vpc_id = aws_vpc.prod-vpc.id
  tags   = { Name = "prod-private-crt" }
}

# Public Subnet for Phishing Server
resource "aws_subnet" "prod-subnet-public-1" {
  vpc_id                  = aws_vpc.prod-vpc.id
  cidr_block              = "10.10.0.0/24"
  map_public_ip_on_launch = true
  availability_zone       = var.AVAILABILITY_ZONE
  tags                    = { Name = "prod-subnet-public-1" }
}

# Route Table Associations
resource "aws_route_table_association" "prod-crta-public-subnet-1" {
  subnet_id      = aws_subnet.prod-subnet-public-1.id
  route_table_id = aws_route_table.prod-public-crt.id
}

# Security Group for Phishing Server
resource "aws_security_group" "subnet-sg-phish" {
  name        = "ubuntu-subnet-sg-phish"
  description = "Allow Phishing Server traffic"
  vpc_id      = aws_vpc.prod-vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Internet Access"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS Access"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP Access"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH Access"
  }

  ingress {
    from_port   = 3333
    to_port     = 3333
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "GoPhish Admin Panel"
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS TCP"
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS UDP"
  }

  tags = { Name = "subnet-sg-phish" }
}

resource "tls_private_key" "ubuntu-ssh-key" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "kp" {
  key_name   = "ubuntu-SSH-Key-${random_string.resource_code.result}"
  public_key = tls_private_key.ubuntu-ssh-key.public_key_openssh
}

resource "local_file" "ssh_key" {
  filename        = "${aws_key_pair.kp.key_name}.pem"
  content         = tls_private_key.ubuntu-ssh-key.private_key_pem
  file_permission = "0600"
}

resource "local_file" "ssh_key_pub" {
  filename        = "${aws_key_pair.kp.key_name}.pub"
  content         = tls_private_key.ubuntu-ssh-key.public_key_openssh
  file_permission = "0600"
}

data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

# Phishing Server (Public)
# !~Ensure user_data is formatted correctly~!
resource "aws_instance" "phishing-server" {
  ami                         = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type               = "t2.medium"
  subnet_id                   = aws_subnet.prod-subnet-public-1.id
  private_ip                  = "10.10.0.205"
  vpc_security_group_ids      = [aws_security_group.subnet-sg-phish.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.kp.key_name
  tags                        = { Name = "Phishing Server" }

  user_data = <<-EOF
#!/bin/bash
set -e
exec > >(tee /var/log/user-data.log) 2>&1

# Wait for system to stabilize
sleep 30

# Apply SSH hardening configurations
sed -i '/^[[:space:]]*#\?[[:space:]]*PermitRootLogin/s/.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i '/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication/s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i '/^[[:space:]]*#\?[[:space:]]*ChallengeResponseAuthentication/s/.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i '/^[[:space:]]*#\?[[:space:]]*PubkeyAuthentication/s/.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Ensure settings exist if not already present
grep -q '^PubkeyAuthentication' /etc/ssh/sshd_config || echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
grep -q '^ChallengeResponseAuthentication' /etc/ssh/sshd_config || echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config
grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
EOF
}

# Random string resource for SSH key naming
resource "random_string" "resource_code" {
  length  = 6
  upper   = false
  lower   = true
  numeric = true
  special = false
}

resource "local_file" "index_html" {
  filename = "${path.module}/index.html"
  content  = replace(
    file("${path.module}/index.html"),
    "$${phishing_domain}",
    var.phishing_domain
  )
}
