#!/bin/bash
# Download npm, nvm, xo-cli, git python, flask, and pull project

sudo apt install python3 -y
sudo apt install python3-pip -y
sudo apt install python3-flask -y
pip install flask-ldap3-login
pip install flask-saml2

### This portion can be found at https://nodejs.org/en/download
sudo curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
\. "$HOME/.nvm/nvm.sh"
nvm install 22
###

sudo npm install -g xo-cli
sudo chmod +x start.sh
sudo chmod +x web_app.py
sudo chmod +x wsgi.py
sudo chmod +x Broker.py