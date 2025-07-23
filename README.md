# # Ready, Set, Phish!

## Overview

This repository contains the Terraform/AWS infrastructure setup for deploying a phishing server with everything setup ready to start a red team operation/phishing engagement. 
Most of the setup is hands off though there are some manual tasks like running a couple commands and updating DNS records.
I had the idea to automate this while going over [TCM Practical Phishing Course](https://academy.tcm-sec.com/p/practical-phishing-campaigns). Alot of manual work to just setup a couple tools and config was required so I decided to put this repo together to save a bunch of time while in my Terraform/AWS war(study) path.
For a proper engagement you should add a reverse proxy in front of the phishing sever to hide traffic more thoroughly.
[Checkout the write up here for this repo!](https://cyberchronicles.org/posts/6/)

## Architecture
![architecture diagram](/architecture.png)
```
Phishing Email → URL/Domain → Public EC2 (Apache, GoPhish & Evilginx)
```

The setup provides:
- **EC2 Server**: Sets up an EC2 with terraform.
- **Apache hosted**: Uses Apache with TLS and strong redirect rules to deter bots and crawlers
- **GoPhish**: GoPhish is installed and auto setup in a tmux session, GoPhishSession1
- **Evilginx**: Evilginx is installed, configured and reay to use in a tmux session, EvilginxSession1.
  
## Prerequisites

Before deploying this infrastructure ensure you have:

- ✅ **Domain Ownership**: A domain you own (I recommend using Cloudflare as the registrar)
- ✅ **AWS Account**: A valid AWS account with root access
- ✅ **AWS Credentials**: An IAM user with `AdministratorAccess` policy and generated access keys
- ✅ **Linux Environment**: Linux distro for deployment (I prefer Kali)
- ✅ **Terraform+AWS**: Terraform and awscli installed
- ✅ **Redirects**: The script auto sets redirects to office.com or microsoft.com, if you want to edit these, ensure it's done before building terraform.
                     - index.html - line 130
                     - config.sh - lines, 141,194,201,211,329,250,367,385,402,420,459,463,595,599,603
---

### The Setup

```bash
#First, make sure you setup Mailgun or whichever mail provider you intend to use.
#Now you need to configure your AWS keys that you would of generated from your AWS IAM user, (ensure awscli is installed): 
aws configure

#Update redirect if required before building terraform, defaults to office.com - Line 130 - index.html.
#Ensure these Inbound ports must be open on the EC2: 22, 53-tcp&udp, 80, 443, 3333
terraform fmt
terraform init
terraform plan
terraform validate
terraform apply
#When prompted, enter your domain name like, example.com
#After setup completes, grab the public IP from the output and update the DNS records for your domain with an A record that points to the new Ec2 IP (DNS only).

#Copy over the config.sh script from your host to the EC2 to setup to auto setup Apache, TLS, GoPhish and Evilginx on the Ec2:
scp -i ubuntu-SSH-Key-######.pem config.sh ubuntu@<YourEC2IP>:/home/ubuntu/
#SSH into the EC2
ssh -i ubuntu-SSH-Key-######.pem ubuntu@<YourEC2IP>
cd /home/ubuntu/ && chmod +x /home/ubuntu/config.sh
sudo /home/ubuntu/config.sh <DOMAIN> <TLD> <EC2IP>
#Example for domain.com: sudo ./config.sh domain com 32.11.11.32
#If you are seeing issues about a hostname then run: HOSTNAME=$(hostname) && echo "127.0.1.1 $HOSTNAME" | sudo tee -a /e> /dev/null
#Any other issues try reloading Apache: systemctl reload apache2

#If all went well, you can nav to GoPhish admin page to setup a profile, but first grab the password:
tmux attach-session -t GoPhishSession1
#on your kali/windows host, nav to https://<YourEC2IP>:3333/ (Make sure its your EC2 IP not your domain name) to change your password for GoPhish (make note of it as you will not be given another chance)
#Once the password has been changed you can update your profile/campaign.

#Now copy over the webpages from your host to the EC2, and then move them to the web root folder. Ensure you are using your pem file name and your EC2 Public IP.
scp -i ubuntu-SSH-Key-######.pem index.html ubuntu@<YourEC2IP>:/home/ubuntu/
scp -i ubuntu-SSH-Key-######pem captcha.html ubuntu@<YourEC2IP>:/home/ubuntu/
ssh -i ubuntu-SSH-Key-######.pem ubuntu@<YourEC2IP> 'sudo mv /home/ubuntu/index.html /var/www/<yourdomain>/ && sudo mv /home/ubuntu/captcha.html /var/www/<yourdomain>/'

#Next setup the custom Email Template in GoPhish
tmux attach-session -t EvilginxSession1
#Setup the custom Phishlet in Evilginx
#Make sure to create an A record for the subdomains used by the Phishlet
#Confirm URL works and is logging creds, then Start the Campaign!
	#Download GoPhish results → Dashboard → Review Campaign → Export CSV
	#Export sessions from Evilginx with sessions and copy to a spreadsheet.
	
#To destroy run terraform destroy and then manually remove the DNS records.
```

## Conclusion
- I plan to do some more studies in making custom email templates for GoPhish, and creating custom phishlets in Evilginx. After that I am looking forward to taking the [Evilginx Mastery Course](https://academy.breakdev.org/evilginx-mastery)
- If you have not got an AWS account handy or a spare domain to use, it could take about 30 minutes to set this all up.
- If you already have an AWS account ready, a domain and your email service already setup, the time to setup the infrastructure completely with this repo is 10 ~ 15 minutes.
- Average monthly cost to keep this EC2 up and running $15.
