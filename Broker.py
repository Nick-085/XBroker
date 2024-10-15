#!/usr/bin/env python3

import json
import os
import psycopg2
import subprocess
from psycopg2 import sql

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
subprocess.run('xo-cli register --au ' + '--url ' + xo + " " + xo + " " + svcBrokerUser + " " + svcBrokerPass, shell=True)
print(" ")

# Clone VM and change its name to include the username of the requestor
sessionUUID = capture_command_output('xo-cli vm.clone id=' + vmToClone + ' name=vds-' + rUser + ' full_copy=' + slowClone, shell=True)
subprocess.run('xo-cli vm.start id=' + sessionUUID, shell=True)
userSession = subprocess.run('xo-cli vm.set id=' + sessionUUID + ' creation=' + rUser)
sessionVMName = "vds-" + rUser

# Gets the IP Address for the VM
sessionIP_c = subprocess.run('xo-cli rest get vms/' + sessionUUID)
sessionIP_j = json.loads(sessionIP_c)
sessionIP = sessionIP_j['mainIpAddress']

print(sessionIP)

vdsRegister = 2 # add VDS to instance to user's Authentik/guac/openrport

# Connect to postgres db and add entry to user's connections
conn = psycopg2.connect(
    database = config['dbSettigs']['dbName'],
    user = config['dbSettigs']['dbUser'],
    password = config['dbSettigs']['dbPass'],
    host = config['dbSettings']['dbHost'],
    port = config['dbSettings']['dbPort']
    )

cur = conn.cursor()

insertQRY = sql.SQL("""
        INSERT INTO guacamole_connection (connection_name, protocol)
        VALUES (%s, %s)
        RETURNING connection_id;
    """)

cur.execute(insertQRY, (sessionVMName, config['sessionSettings']['protocol']))
connection_id = cur.fetchone()[0]