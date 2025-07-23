output "Ubuntu-Phishing-Server-IP" {
  description = "The public IP address for the Ubuntu Phishing Server, use this to update your DNS records before doing anything else!"
  value       = aws_instance.phishing-server.public_ip
}

output "Evilginx-Tmux-Sesson" {
  description = "Once on the Ec2 server and you have run config,sh, run this tmux command to rejoin the Evilginx session"
  value       = "Once you have run config.sh on the EC2, run this to rejoin the session: tmux attach-session -t EvilginxSession1"
}

output "GoPhish-Tmux-Sesson" {
  description = "Once on the Ec2 server and you have run config,sh, run this tmux command to rejoin the GoPhish session"
  value       = "Once you have run config.sh on the EC2, run this to rejoin the session: tmux attach-session -t GoPhishSession1"
}

output "phishing_ssh_command" {
  description = "SSH command to connect to the Ubuntu Phishing Server."
  value       = "ssh -i ${aws_key_pair.kp.key_name}.pem ubuntu@${aws_instance.phishing-server.public_ip}"
}
