#!/usr/bin/env python3
import json
import requests
import os
import subprocess
import time

# Load config file
with open('config.json') as confFile:
    config = json.load(confFile)

def get_config_value(key, default=None):
    return os.getenv(key, config.get(key, default))

xoa_url = get_config_value('XO_URL', config['xoSettings']['xo'])
svcBrokerUser = get_config_value('SVC_BROKER_USER', config['xoSettings']['svcCreds']['svcBrokerUser'])
svcBrokerPass = get_config_value('SVC_BROKER_PASS', config['xoSettings']['svcCreds']['svcBrokerPass'])
guac_url = get_config_value('GUAC_URL', config['guacURL'])
guac_admin_user = get_config_value('GUAC_ADMIN_USER', config['guacAdminUser'])
guac_admin_pass = get_config_value('GUAC_ADMIN_PASS', config['guacAdminPass'])
cleanup_interval = get_config_value('CLEANUP_INTERVAL', config['cleanupInterval'])

# Register service user to XO(A)
subprocess.run(f'xo-cli register --au --url {xoa_url} {xoa_url} {svcBrokerUser} {svcBrokerPass}', shell=True)

def delete_vm(vm_uuid):
    result = subprocess.run(f'xo-cli vm.delete id={vm_uuid}', shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"VM {vm_uuid} deleted successfully.")
    else:
        print(f"Failed to delete VM {vm_uuid}. Error: {result.stderr}")

def delete_guac_session(session_name):
    # Authenticate with Guacamole
    auth_payload = {
        "username": guac_admin_user,
        "password": guac_admin_pass
    }
    auth_response = requests.post(f"{guac_url}/api/tokens", data=auth_payload, verify=False)
    if auth_response.status_code != 200:
        print(f"Failed to authenticate with Guacamole. Status code: {auth_response.status_code}")
        return

    try:
        auth_token = auth_response.json().get("authToken")
    except json.JSONDecodeError:
        print("Failed to parse JSON response from Guacamole.")
        print(f"Response content: {auth_response.content}")
        return

    if not auth_token:
        print("Failed to retrieve auth token from Guacamole response.")
        return

    # Get the connection ID for the session
    connections_url = f"{guac_url}/api/session/data/postgresql/connections?token={auth_token}"
    connections_response = requests.get(connections_url, verify=False)
    if connections_response.status_code != 200:
        print(f"Failed to retrieve connections from Guacamole. Status code: {connections_response.status_code}")
        return

    try:
        connections = connections_response.json()
    except json.JSONDecodeError:
        print("Failed to parse JSON response from Guacamole.")
        print(f"Response content: {connections_response.content}")
        return

    connection_id = None
    for connection in connections.values():
        if connection['name'] == session_name:
            connection_id = connection['identifier']
            break

    if not connection_id:
        print(f"Failed to find connection with name {session_name} in Guacamole.")
        return

    # Delete the connection
    delete_url = f"{guac_url}/api/session/data/postgresql/connections/{connection_id}?token={auth_token}"
    delete_response = requests.delete(delete_url, verify=False)
    if delete_response.status_code == 204:
        print(f"Session {session_name} deleted successfully from Guacamole.")
    else:
        print(f"Failed to delete session {session_name} from Guacamole. Status code: {delete_response.status_code}")

def is_stale_session(session_name):
    for template, details in config['vdsConfFiles'].items():
        if session_name.startswith(details['displayName']) and "template" not in session_name.lower():
            return True
        if session_name.startswith(template.split('.')[0]) and "template" not in session_name.lower():
            return True
    return False

while True:
    # Get all VMs
    vm_list = subprocess.run('xo-cli list-objects type=VM', shell=True, capture_output=True, text=True)
    if vm_list.returncode != 0:
        print(f"Failed to list VMs. Error: {vm_list.stderr}")
        exit(1)

    try:
        vms = json.loads(vm_list.stdout)
    except json.JSONDecodeError:
        print("Failed to parse JSON response from xo-cli list-objects.")
        print(f"Response content: {vm_list.stdout}")
        exit(1)

    for vm in vms:
        vm_uuid = vm['id']
        vm_name = vm['name_label']
        vm_power_state = vm['power_state']
        if is_stale_session(vm_name):
            if vm_power_state == 'Halted':
                delete_vm(vm_uuid)
                delete_guac_session(vm_name)

    print(f"Sleeping for {cleanup_interval} minute(s) before next cleanup cycle.")
    time.sleep(cleanup_interval * 60)