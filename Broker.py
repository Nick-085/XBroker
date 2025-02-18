#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
import requests
from getpass import getpass
import sys

# Load env vars
with open('config.json') as confFile:
    config = json.load(confFile)

# Used to extract JSON output
def capture_command_output(command):
    stream = os.popen(command)
    output = stream.read().strip()
    return output

if len(sys.argv) != 3:
    print("Usage: python3 Broker.py <username> <password>")
    sys.exit(1)

rUser = sys.argv[1]
rPass = sys.argv[2]

# Get requesting user
# rUser = str(input('Please enter your username: '))
# rPass = getpass('Please enter your password: ')

# XO connection vars
xo = config['xoSettings']['xo']
svcBrokerUser = config['xoSettings']['svcCreds']['svcBrokerUser']
svcBrokerPass = config['xoSettings']['svcCreds']['svcBrokerPass']
vmToClone = config['xoSettings']['vmToClone']
slowClone = config['xoSettings']['slowClone']

# Register service user to XO(A)
subprocess.run('xo-cli register --au --url ' + xo + ' ' + xo + ' ' + svcBrokerUser + ' ' + svcBrokerPass, shell=True)
print(" ")

# Clone VM and change its name to include the username of the requestor
sessionUUID = capture_command_output('xo-cli vm.clone id=' + vmToClone + ' name=vds-' + rUser + ' full_copy=' + slowClone)
subprocess.run('xo-cli vm.start id=' + sessionUUID, shell=True)
sessionVMName = "vds-" + rUser
time.sleep(120)

# Gets the IP Address for the VM
getMainIP = capture_command_output('xo-cli list-objects uuid=' + sessionUUID + ' | grep mainIpAddress')
sessionIP = re.search(r'"mainIpAddress":\s*"([\d.]+)"', getMainIP).group(1)
print(sessionIP)

# User and pass in JSON for payload
auth_payload = {
    "username": rUser,
    "password": rPass 
}

# Login to guac and get token
auth_response = requests.post(config['guacURL'] + "/api/tokens", data=auth_payload, verify=False)
if auth_response.status_code != 200:
    print(f"Failed to authenticate with Guacamole. Status code: {auth_response.status_code}")
    print(f"Response content: {auth_response.content}")
    exit(1)

auth_token = auth_response.json().get("authToken")
if not auth_token:
    print("Failed to retrieve auth token from Guacamole response.")
    exit(1)

# Add the VM to Apache Guacamole
guac_url = config['guacURL'] + f"/api/session/data/postgresql/connections?token={auth_token}"

guac_connection = {
  "parentIdentifier": "ROOT",
  "name": sessionVMName,
  "protocol": config['sessionSettings']['protocol'],
  "parameters": {
    "port": config['sessionSettings']['portNumber'],
    "read-only": "",
    "swap-red-blue": "",
    "cursor": "",
    "color-depth": "",
    "clipboard-encoding": "",
    "disable-copy": "",
    "disable-paste": "",
    "dest-port": "",
    "recording-exclude-output": "",
    "recording-exclude-mouse": "",
    "recording-include-keys": "",
    "create-recording-path": "",
    "enable-sftp": "",
    "sftp-port": "",
    "sftp-server-alive-interval": "",
    "enable-audio": "",
    "security": "",
    "disable-auth": "",
    "ignore-cert": "",
    "gateway-port": "",
    "server-layout": "",
    "timezone": "",
    "console": "",
    "width": "",
    "height": "",
    "dpi": "",
    "resize-method": "",
    "console-audio": "",
    "disable-audio": "",
    "enable-audio-input": "",
    "enable-printing": "",
    "enable-drive": "",
    "create-drive-path": "",
    "enable-wallpaper": "",
    "enable-theming": "",
    "enable-font-smoothing": "",
    "enable-full-window-drag": "",
    "enable-desktop-composition": "",
    "enable-menu-animations": "",
    "disable-bitmap-caching": "",
    "disable-offscreen-caching": "",
    "disable-glyph-caching": "",
    "preconnection-id": "",
    "hostname": sessionIP,
    "username": rUser,
    "password": rPass,
    "domain": "",
    "gateway-hostname": "",
    "gateway-username": "",
    "gateway-password": "",
    "gateway-domain": "",
    "initial-program": "",
    "client-name": "",
    "printer-name": "",
    "drive-name": "",
    "drive-path": "",
    "static-channels": "",
    "remote-app": "",
    "remote-app-dir": "",
    "remote-app-args": "",
    "preconnection-blob": "",
    "load-balance-info": "",
    "recording-path": "",
    "recording-name": "",
    "sftp-hostname": "",
    "sftp-host-key": "",
    "sftp-username": "",
    "sftp-password": "",
    "sftp-private-key": "",
    "sftp-passphrase": "",
    "sftp-root-directory": "",
    "sftp-directory": ""
  },
  "attributes": {
    "max-connections": "",
    "max-connections-per-user": "",
    "weight": "",
    "failover-only": "",
    "guacd-port": "",
    "guacd-encryption": "",
    "guacd-hostname": ""
  }
}

headers = {
    "Content-Type": "application/json"
}

response = requests.post(guac_url, json=guac_connection, headers=headers, verify=False)

if response.status_code == 200:
    print(f"Successfully added {sessionVMName} to Guacamole.")
else:
    print(f"Failed to add {sessionVMName} to Guacamole. Status code: {response.status_code}")