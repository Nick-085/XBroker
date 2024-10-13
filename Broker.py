#!/usr/bin/env python3

import subprocess
import os
import load_dotenv

# Load env vars
load_dotenv()

# Connect to Xen Orchestra
xo = os.getenv('xoConnection')
svcBrokerUser = os.getenv('svcBrokerUser')
svcBrokerPass = os.getenv('svcBrokerPass')
vmUUID = os.getenv('vmToClone')

# Register service user to XO(A)
subprocess.run('xo-cli register --au ' + '--url ' + xo + " " + xo + " " + svcBrokerUser + " " + svcBrokerPass)

# Clone VM and change its name to include the username of the requestor
vdsInstance = subprocess.run('xo-cli --json vm.clone uuid=' + vmUUID) # todo return the VM UUID so we can rename it with the username
vdsSearch = subprocess.run('xo-cli list-objects vm uuid=' + vmUUID + ' | grep(user)') # todo get the requesting user somehow. Maybe browser session?
vdsPersonalized = 1 # rename VDS to instance to include username
vdsRegister = 2 # add VDS to instance to user's Authentik/guac/openrport
