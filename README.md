## About the Project
XBroker is a project designed to be an alternative to Citrix VDI and Omnissa Horizon. It uses Xen Orchestra and Apache Guacamole to clone a template VM, start it, and assign it to the requesting user. The ultimate goal is for this project to be ported to as many hypervisor platforms as possible.

### Install Instructions
1. You will need a working Guacamole instance. You can find easy instructions on how to deploy it [here](https://github.com/boschkundendienst/guacamole-docker-compose) or [here](https://www.youtube.com/watch?v=DGw6P5Lkj-U). **All users will need the "add connection" permission in their account settings.**
2. Ensure you are using a non-root account with sudo permissions.
3. Using an Ubuntu/Debian machine (tested and working on Ubuntu 22.04.5 LTS) run the following (please read the scripts in GitHub. You should never blindly run a script from the internet):
```
sudo apt install git -y 
git clone https://github.com/Nick-085/XBroker xbroker
cd xbroker
chmod +x downloadPrereqs.sh
./downloadPrereqs.sh
```
*The `downloadPrereqs.sh` script downloads and installs npm, nvm, Python3, pip3, flask, xo-cli, and applies permissions to esecute necessary files.*

4. Edit `config.json` file for your environment. If you set `slowClone` to True, it will allow for VM cloning while the template VM is on, but takes a long time to complete. Change at your own risk.
5. You can add as many `vdsConfFiles` as you want. These are JSON files that Guacamole uses to provide connection settings. I have provided `winvds.json` as an example. **Do not change username, password, hostname, or connection name as those are passed through from user selection or dynamically pulled from XOA/XCP-ng/XCP-ng tools** 