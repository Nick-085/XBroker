## About the Project
XBroker is a project designed to be an alternative to Citrix VDI and Omnissa Horizon. It uses Xen Orchestra and Apache Guacamole to clone a template VM, start it, and assign it to the requesting user. The ultimate goal is for this project to be ported to as many hypervisor platforms as possible.

## Install Instructions - VM
1. You will need a working Guacamole instance. You can find easy instructions on how to deploy it [here](https://github.com/boschkundendienst/guacamole-docker-compose) or [here](https://www.youtube.com/watch?v=DGw6P5Lkj-U). <ins>**All users will need the "add connection" permission in their account settings.**</ins>
2. Ensure you are using a non-root account with `sudo` permissions.
3. Using an Ubuntu/Debian machine (tested and working on Ubuntu 22.04.5 LTS) run the following (please read the scripts in GitHub. You should never blindly run a script from the internet):
```
sudo apt install git -y 
git clone https://github.com/Nick-085/XBroker xbroker
cd xbroker
chmod +x downloadPrereqs.sh
./downloadPrereqs.sh
```
*The `downloadPrereqs.sh` script downloads and installs npm, nvm, Python3, pip3, flask, xo-cli, and applies permissions to execute necessary files.*

## Install Instructions - Docker (thanks @jgrafton for handholding me in building this)
1. You will need a working Guacamole instance. You can find easy instructions on how to deploy it [here](https://github.com/boschkundendienst/guacamole-docker-compose) or [here](https://www.youtube.com/watch?v=DGw6P5Lkj-U). <ins>**All users will need the "add connection" permission in their account settings.**</ins>
2. Use an account that can use either `sudo` or is in the `docker` group.
3. Run the following:
```
sudo apt install git -y 
git clone https://github.com/Nick-085/XBroker xbroker
cd xbroker
```
4. Edit `config.json` file for your environment. For more information, view the next section.
5. Run `docker build -t xbroker ./`
6. Run `docker run -d -p 8000:8000 xbroker:latest`

To use environment variables to manage configuration, run docker like this:
`docker run -d -p 8000:8000 -e XO_URL="https://xoa.servers.udayton.edu/" -e SVC_BROKER_USER="user1" -e SVC_BROKER_PASS="xxxxxxx" xbroker:latest`

## Setting Up Your Environment
1. Edit `config.json` file for your environment.
2. Enter your Xen Orchestra and Guacamole settings. The XO user MUST be an admin in XO(A).
3. If you set `slowClone` to True, it will allow for VM cloning while the template VM is on, but takes a long time to complete. It will more than likely time out the `getMainIP` process. Change at your own risk.
4. You can add as many `vdsConfFiles` as you want. These are JSON files that Guacamole uses to provide connection settings and define what desktops are available to your users. I have provided `winvds.json` as an example. To make these available, copy the following into 
`config.json` under `vdsConfFiles`:
```
"vds-name.json": {
    "displayName": "Friendly name users see",
    "uuid": "uuid-of-vm-template",
    "expected_cidr_range": "expected-cidr-range-of-deployed-vm"}
```
<ins>**Do not change username, password, hostname, or connection name as those are passed through from user selection or dynamically pulled from XOA and/or XCP-ng (or Citrix) VM Tools!!!**</ins>

5. `displayName` is the name that will be on the dropdown when the user selects what desktop they want to deploy.
6. `uuid` is the UUID of the template VM in XO(A).
7. `expected_cidr_range` is the CIDR range that the VM will have an IP address in. This is done because Windows provides a `169.254.0.0/16` address to XCP-ng/Citrix Tools almost instantly on boot. This tool retries the IP address retrieval until it is within the expected range.
8. Run `start.sh` to start `wsgi.py`. This way, you can exit the terminal without stopping the service.