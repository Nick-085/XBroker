#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
import requests
import sys
import ipaddress

# Load env vars
with open('config.json') as confFile:
    config = json.load(confFile)

# Used to extract JSON output
def capture_command_output(command):
    stream = os.popen(command)
    output = stream.read().strip()
    return output

def get_config_value(key, default=None):
    return os.getenv(key, config.get(key, default))

if len(sys.argv) != 6:
    print("Usage: python3 Broker.py <username> <password> <vdiFile> <vdiUUID> <expectedCIDR>")
    sys.exit(1)

rUser = sys.argv[1]
rPass = sys.argv[2]
vdiFile = sys.argv[3]
vdiUUID = sys.argv[4]
expectedCIDR = sys.argv[5]

# Load VDI configuration file
try:
    with open(os.path.join('vdsProfiles', vdiFile)) as vdiConfFile:
        vdiProfile = json.load(vdiConfFile)
        
        # Check if profile has the required structure
        if 'vdsProperties' not in vdiProfile:
            print(f"Error: Profile missing vdsProperties section")
            sys.exit(1)
        if 'guacPayload' not in vdiProfile:
            print(f"Error: Profile missing guacPayload section")
            sys.exit(1)
            
        # Extract guacPayload for Guacamole configuration
        vdiConfig = vdiProfile['guacPayload']
        
        # Verify UUID and CIDR match what was passed
        if vdiProfile['vdsProperties']['uuid'] != vdiUUID:
            print(f"Error: UUID mismatch in profile file")
            sys.exit(1)
        if vdiProfile['vdsProperties']['expected_cidr_range'] != expectedCIDR:
            print(f"Error: CIDR mismatch in profile file")
            sys.exit(1)
            
        # Ensure required guacPayload structure
        if not isinstance(vdiConfig, dict):
            print(f"Error: guacPayload must be an object")
            sys.exit(1)
        if 'parameters' not in vdiConfig:
            vdiConfig['parameters'] = {}
        if 'attributes' not in vdiConfig:
            vdiConfig['attributes'] = {}
            
except FileNotFoundError:
    print(f"Error: Profile file {vdiFile} not found in vdsProfiles directory")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Error: Invalid JSON in profile file: {str(e)}")
    sys.exit(1)
except Exception as e:
    print(f"Error loading VDS profile: {str(e)}")
    sys.exit(1)

print(f"Successfully loaded profile for {vdiFile}")

# XO connection vars
xo = get_config_value('XO_URL', config['xoSettings']['xo'])
svcBrokerUser = get_config_value('SVC_BROKER_USER', config['xoSettings']['svcCreds']['svcBrokerUser'])
svcBrokerPass = get_config_value('SVC_BROKER_PASS', config['xoSettings']['svcCreds']['svcBrokerPass'])
slowClone = get_config_value('SLOW_CLONE', config['xoSettings']['slowClone'])

# Register service user to XO(A)
subprocess.run('xo-cli register --au --url ' + xo + ' ' + xo + ' ' + svcBrokerUser + ' ' + svcBrokerPass, shell=True)
print(" ")

# Clone VM and change its name to include the username of the requestor
sessionName = f"{os.path.splitext(vdiFile)[0]}-{rUser}"
sessionUUID = capture_command_output('xo-cli vm.clone id=' + vdiUUID + ' name=' + sessionName + ' full_copy=' + slowClone)
subprocess.run('xo-cli vm.start id=' + sessionUUID, shell=True)

# Gets the IP Address for the VM
getMainIP = capture_command_output('xo-cli list-objects uuid=' + sessionUUID + ' | grep mainIpAddress')
sessionIP = re.search(r'"mainIpAddress":\s*"([\d.]+)"', getMainIP)

# Validate the IP address against the expected CIDR range
for i in range(18):
    if sessionIP is None or ipaddress.IPv4Address(sessionIP.group(1)) not in ipaddress.IPv4Network(expectedCIDR):
        time.sleep(5)
        getMainIP = capture_command_output('xo-cli list-objects uuid=' + sessionUUID + ' | grep mainIpAddress')
        sessionIP = re.search(r'"mainIpAddress":\s*"([\d.]+)"', getMainIP)
    else:
        break

if sessionIP is None:
    print("Failed to get a valid IP address for the VM.")
    sys.exit(1)

sessionIP = sessionIP.group(1)
print(sessionIP)

# Use the user's credentials to authenticate with Guacamole
# This way the connection will be created under their account
auth_payload = {
    "username": rUser,
    "password": rPass
}

# Login to guac and get token
guac_url = get_config_value('GUAC_URL', config['guacURL'])
auth_response = requests.post(f"{guac_url}/api/tokens", data=auth_payload, verify=False)
if auth_response.status_code != 200:
    print(f"Failed to authenticate with Guacamole. Status code: {auth_response.status_code}")
    print(f"Response content: {auth_response.content}")
    exit(1)

auth_token = auth_response.json().get("authToken")
if not auth_token:
    print("Failed to retrieve auth token from Guacamole response.")
    exit(1)

# Add the VM to Apache Guacamole
api_url = f"{guac_url}/api/session/data/postgresql/connections?token={auth_token}"

headers = {
    "Content-Type": "application/json"
}

# Update vdiConfig with rUser, rPass, and sessionIP
vdiConfig['parameters']['username'] = rUser
vdiConfig['parameters']['password'] = rPass
vdiConfig['parameters']['hostname'] = sessionIP
vdiConfig['name'] = sessionName

response = requests.post(api_url, json=vdiConfig, headers=headers, verify=False)

if response.status_code == 200:
    connection_data = response.json()
    connection_id = connection_data.get('identifier')
    
    # Connection is automatically added to the user's account since we authenticated as the user
    print(f"Successfully created connection {connection_id} under user {rUser}'s account")
    
    # Include all components needed for URL construction
    print(json.dumps({
        "status": "success",
        "message": f"Successfully added {sessionName} to Guacamole",
        "connection_id": connection_id,
        "connection_type": "c",  # 'c' for connection
        "auth_provider": "postgresql"  # we're using postgresql
    }))
else:
    print(f"Failed to add {sessionName} to Guacamole. Status code: {response.status_code}")
    print(f"Response content: {response.content}")