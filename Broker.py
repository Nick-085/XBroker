#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
import requests

# Load env vars
with open('config.json') as confFile:
    config = json.load(confFile)

# Used to extract JSON output
def capture_command_output(command):
    stream = os.popen(command)
    output = stream.read().strip()
    return output

# Get requesting user
rUser = str(input('What is the username of the person requesting this session?: '))

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
time.sleep(45)

# Gets the IP Address for the VM
getMainIP = capture_command_output('xo-cli list-objects uuid=' + sessionUUID + ' | grep mainIpAddress')
sessionIP = re.search(r'"mainIpAddress":\s*"([\d.]+)"', getMainIP).group(1)
print(sessionIP)

# Add the VM to Apache Guacamole
guac_url = "http://your-guacamole-server/api/session/data/postgresql/connections"
guac_auth = ("guacadmin", "guacadmin_password")  # Replace with your Guacamole admin credentials

guac_connection = {
    "name": sessionVMName,
    "protocol": config['sessionSettings']['protocol'],
    "parameters": {
        "hostname": sessionIP,
        "port": config['sessionSettings']['portNumber'],
        "username": config['sessionSettings']['vmUName'],
        "password": config['sessionSettings']['vmPass']
    }
}

response = requests.post(guac_url, auth=guac_auth, json=guac_connection)
if response.status_code == 200:
    print(f"Successfully added {sessionVMName} to Guacamole.")
else:
    print(f"Failed to add {sessionVMName} to Guacamole. Status code: {response.status_code}")