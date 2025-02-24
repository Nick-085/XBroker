#!/bin/bash
# Download npm, nvm, xo-cli, git python, flask, and pull project

sudo apt install python3 -y
sudo apt install python3-pip -y
sudo pip3 install flask
sudo curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
sudo npm install -g xo-cli
sudo chmod +x start.sh
sudo chmod +x web_app.py
sudo chmod +x Broker.py