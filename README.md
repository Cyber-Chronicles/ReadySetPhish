# # Ready, Set, Phish!

## Overview

This repository contains the Terraform/AWS infrastructure setup for deploying a phishing server with almost everything setup and ready to start a red team operation/phishing engagement. 
Most of the setup is hands off though there are some manual tasks like running a couple commands and updating DNS records.
I had the idea to automate this while going over [TCM Practical Phishing Course](https://academy.tcm-sec.com/p/practical-phishing-campaigns). A lot of manual work to just setup a couple tools and config was required each time, so I decided to put this repo together to save some blood sweat and tears and help set this process up quicker and more streamlined.
For a proper engagement you should setup a proxy in the evilginx setup to hide and protect your evilginx traffic more thoroughly.
Check out the write up [here for this repo!](https://cyberchronicles.org/posts/6/)

## Architecture
![architecture diagram](/architecture.png)
```
Phishing Email → URL/Domain → Public EC2 (Apache, GoPhish & Evilginx)
```

The setup provides:
- **EC2 Server**: Sets up an EC2 with terraform.
- **Apache Web Server**: Installs Apache with TLS and strong redirect rules to deter bots and crawlers to allow you to host fake content on the root domain to make it appear more legitimate. (Apache is turned off by default to allow evilginx to run. When not using evilginx, enable apache (`sudo systemctl start apache2`) and ensure you have html files in the web server root.
- **GoPhish**: GoPhish is installed and auto-setup in a tmux session(`tmux attach-session -t GoPhishSession1`) with basic hardening done to improve opsec. Advised to tmux in to this session when ready and grab the password as you may not see it again. Then once you obtain this password, exit GoPhish to stop it running, only start up when needed for the campiagn.
- **Evilginx**: Evilginx is installed, configured and ready to use in a tmux session(`tmux attach-session -t EvilginxSession1`) with basic config already set.
  
## Prerequisites

Before deploying this infrastructure ensure you have:

- ✅ **Domain Ownership**: A domain you own (I recommend using Cloudflare as the registrar)
- ✅ **AWS Account**: A valid AWS account with root access
- ✅ **AWS Credentials**: Generated IAM access keys
- ✅ **Linux Environment**: Linux distro for deployment (I prefer Kali)
- ✅ **Terraform+AWS**: Terraform and awscli installed
- ✅ **Redirects**: The script auto sets the apache redirects to google.com, if you want to edit these, ensure it's done before building terraform.
                     - config.sh - lines, 150,204,211,221,339,360,377,395,412,430,469,473,605,613.
---

## What else is included?
- GoPhish has had some slight changes for opsec:
```bash
# Removes GoPhish HTTP Header
find . -type f -exec sed -i 's/X-Gophish-Contact/X-Contact/g' {} +
find . -type f -exec sed -i 's/X-Gophish-Signature/X-Signature/g' {} +
# Changes rid default parameter to id
sed -i 's/const RecipientParameter = "rid"/const RecipientParameter = "id"/g' models/campaign.go
# Updates to config.json for TLS
sed -i '3s/127\.0\.0\.1:3333/0.0.0.0:3333/' /home/ubuntu/gophish/config.json
sed -i '10s/0\.0\.0\.0:80/0.0.0.0:8080/' /home/ubuntu/gophish/config.json
sed -i '11s/false/true/' /home/ubuntu/gophish/config.json
sed -i '12s/example\.crt/fullchain.pem/' /home/ubuntu/gophish/config.json
sed -i '13s/example\.key/privkey.pem/' /home/ubuntu/gophish/config.json
# Updates to config.go to remove the server name
sed -i '46s/const ServerName = "gophish"/const ServerName = "IGNORE"/' /home/ubuntu/gophish/config/config.go
```
- Evilginx has had an easter egg removed to expose itself and some config commands already run to auto-setup your domain, EC2 IP, blacklist etc with Evilginx.
```
sed -i 's/^[[:space:]]*req.Header.Set(p.getHomeDir(), o_host)/\/\/&/' /home/ubuntu/evilginx2/core/http_proxy.go
config domain $MYFQDN
config ipv4 external $EC2IP
blacklist unauth
config unauth_url https://$MYFQDN/
blacklist log off
```

### The Setup

```bash
#!Ensure you already have a domain purchased and have an AWS account
#First, make sure you set up Mailgun or your preferred mail provider you intend to use.
#Now you need to configure your AWS keys that you would have generated from the AWS IAM page earlier (IAM > Quick Links > My Security Credentials > Create Access Key): 
aws configure

#Update redirect if required before building terraform, defaults to office.com - Line 130 - index.html.
#Ensure the following inbound ports are open on the EC2: 22, 53-tcp&udp, 80, 443, 3333
terraform fmt
terraform init
terraform plan
terraform validate
terraform apply
#When prompted, enter your domain name like, example.com
#After setup completes, grab the public IP from the output and update the DNS records for your domain with an A record that points to the new Ec2 IP (DNS only).
#Confirm DNS records have been updated:
dig +short <yourdomain.com>

#Copy over the config.sh script from your host to the EC2, to auto-setup Apache, TLS, GoPhish and Evilginx on the Ec2:
scp -i ubuntu-SSH-Key-######.pem config.sh ubuntu@<YourEC2IP>:/home/ubuntu/
#SSH into the EC2
ssh -i ubuntu-SSH-Key-######.pem ubuntu@<YourEC2IP>
cd /home/ubuntu/ && chmod +x /home/ubuntu/config.sh
sudo /home/ubuntu/config.sh <DOMAIN> <TLD> <EC2IP>
#Example for domain.com with the public IP of 32.11.11.32: sudo ./config.sh domain com 32.11.11.32
#If you are seeing issues about a hostname then run: HOSTNAME=$(hostname) && echo "127.0.1.1 $HOSTNAME" | sudo tee -a /e> /dev/null
#Any other issues try reloading Apache: systemctl reload apache2

#If all went well, you can navigate to GoPhish admin page to setup a profile, but first grab the password:
tmux attach-session -t GoPhishSession1
#Minimize your tmux session or on your kali/windows host, navigate to https://<YourEC2IP>:3333/ (Make sure it's your EC2 IP not your domain name) to change your password for GoPhish (make note of it as you will not be given another chance)
#Once the password has been changed you can update your profile/campaign, if coming back to this later, it is reccomend to close GoPhish to stop having it exposed openly.

#Next, setup the custom Email Template in GoPhish
#Once done, setup the custom Phishlet in Evilginx
tmux attach-session -t EvilginxSession1
#Make sure to create an A record for the subdomains used by the Phishlet
#Now when ready to start, stop Apache so Evilginx can run: sudo systemctl stop apache2
#Confirm the URL works and is logging credentials, then Start the Campaign!
	#Download GoPhish results → Dashboard → Review Campaign → Export CSV
	#Export session data from Evilginx and copy it to a spreadsheet.
	
#To destroy, run terraform destroy and then manually remove the DNS records.
```

## Conclusion
- I plan to do some more studies in making custom email templates for GoPhish, and creating custom phishlets in Evilginx. After that I am looking forward to taking the [Evilginx Mastery Course](https://academy.breakdev.org/evilginx-mastery)
- If you already have an AWS account ready, a domain and your email service already setup, the time to setup the infrastructure completely with this repo is around 10 minutes.
- Average monthly cost to keep this EC2 up and running is $15.
