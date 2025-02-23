#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
import requests
import sys

# Load env vars
with open('config.json') as confFile:
    config = json.load(confFile)

# Used to extract JSON output
def capture_command_output(command):
    stream = os.popen(command)
    output = stream.read().strip()
    return output

if len(sys.argv) != 5:
    print("Usage: python3 Broker.py <username> <password> <vdiFile> <vdiUUID>")
    sys.exit(1)

rUser = sys.argv[1]
rPass = sys.argv[2]
vdiFile = sys.argv[3]
vdiUUID = sys.argv[4]

# Load VDI configuration file
with open(vdiFile) as vdiConfFile:
    vdiConfig = json.load(vdiConfFile)

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
sessionName = f"{os.path.splitext(vdiFile)[0]}-{rUser}"
sessionUUID = capture_command_output('xo-cli vm.clone id=' + vdiUUID + ' name=' + sessionName + ' full_copy=' + slowClone)
subprocess.run('xo-cli vm.start id=' + sessionUUID, shell=True)
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

headers = {
    "Content-Type": "application/json"
}

# Update vdiConfig with rUser and rPass
vdiConfig['parameters']['username'] = rUser
vdiConfig['parameters']['password'] = rPass

response = requests.post(guac_url, json=vdiConfig, headers=headers, verify=False)

if response.status_code == 200:
    print(f"Successfully added {sessionName} to Guacamole.")
else:
    print(f"Failed to add {sessionName} to Guacamole. Status code: {response.status_code}")