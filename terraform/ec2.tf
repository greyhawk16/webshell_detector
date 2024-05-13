resource "aws_iam_instance_profile" "webshell_detector-EC2_profile" {
  name = "cr-SSTI-profile-EC2_profile"
}



resource "tls_private_key" "this" {
  algorithm     = "RSA"
  rsa_bits      = 4096
}

resource "aws_key_pair" "this" {
  key_name      = "webshell_detector-key_pair"
  public_key    = tls_private_key.this.public_key_openssh

  provisioner "local-exec" {
    command = <<-EOT
      echo "${tls_private_key.this.private_key_pem}" > ${var.ssh-private-key-for-ec2}
    EOT
  }
}


resource "aws_security_group" "alone_web" {
  name        = "webshell_detector-security_group"
  description = "webshell_detector-security_group"
  ingress {
    from_port = 22                                           
    to_port = 22                                             
    protocol = "tcp"                                         
    cidr_blocks = ["0.0.0.0/0"]       
  }
  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_instance" "app_server" {
  ami = "ami-0ddda618e961f2270"  
  instance_type = "t2.micro"
  key_name = "${aws_key_pair.this.key_name}"
  vpc_security_group_ids = ["${aws_security_group.alone_web.id}"] # ["sg-0f1333e985b024d83"]
  iam_instance_profile = "${aws_iam_instance_profile.webshell_detector-EC2_profile.name}"
  
  tags = {
    Name = "webshell_detector-EC2_server"
  }
  root_block_device {
    volume_size         = 30 
  }

  connection {
        type = "ssh"
        user = "ec2-user"
        host = self.public_ip
        private_key = "${file(var.ssh-private-key-for-ec2)}"
  }

  provisioner "file" {
      source = "../code"
      destination = "./"
  }
  
  provisioner "remote-exec" {
    inline = [
      #!/bin/bash
      "cd ./code",
      "chmod +x ./docker_install_script.sh",
      "./docker_install_script.sh"
    ]
  }

    provisioner "remote-exec" {
    inline = [
      #!/bin/bash
      "cd ./code",
      "docker compose up -d"
    ]
  }

    # write public ip-address to location.txt
  provisioner "local-exec" {
    command = <<-EOT
      echo "${self.public_ip}:80" > location.txt
    EOT
  }
}