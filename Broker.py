#!/usr/bin/env python3

import io
import json
import os
import subprocess
from getpass import getpass

# Load env vars
with open('config.json') as confFile:
    config = json.load(confFile)

# Connect to Xen Orchestra
xo = config['xo']
svcBrokerUser = config['svcBrokerUser']
svcBrokerPass = config['svcBrokerUser']['svcBrokerPass']
vmToClone = config['vmToClone']

# Register service user to XO(A)
subprocess.run('xo-cli register --au ' + '--url ' + xo + " " + xo + " " + svcBrokerUser + " " + svcBrokerPass)

# Clone VM and change its name to include the username of the requestor
vdsInstance = subprocess.run('xo-cli --json vm.clone uuid=' + vmToClone) # todo return the VM UUID so we can rename it with the username
vdsSearch = subprocess.run('xo-cli list-objects vm uuid=' + vmToClone + ' | grep(user)') # todo get the requesting user somehow. Maybe browser session?
vdsPersonalized = 1 # rename VDS to instance to include username
vdsRegister = 2 # add VDS to instance to user's Authentik/guac/openrport
