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
rUser = str(input('Who is requesting this session?: '))

# Connect to Xen Orchestra
xo = config['xo']
svcBrokerUser = config['svcCreds']['svcBrokerUser']
svcBrokerPass = config['svcCreds']['svcBrokerPass']
vmToClone = config['vmToClone']
slowClone = config['slowClone']

# Register service user to XO(A)
subprocess.run('xo-cli register --au ' + '--url ' + xo + " " + xo + " " + svcBrokerUser + " " + svcBrokerPass, shell=True)
print(" ")
subprocess.run

# Clone VM and change its name to include the username of the requestor
sessionUUID = capture_command_output('xo-cli vm.clone id=' + vmToClone + ' name=vds-' + rUser + ' full_copy=' + slowClone, shell=True)
subprocess.run('xo-cli vm.start id=' + sessionUUID, shell=True)
userSession = subprocess.run('xo-cli vm.set id=' + sessionUUID + ' creation=' + rUser)
sessionVMName = "vds-" + rUser

vdsRegister = 2 # add VDS to instance to user's Authentik/guac/openrport

# Connect to postgres db and add entry to user's connections