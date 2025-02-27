#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
import requests
import sys
import ipaddress

with open('config.json') as confFile:
    config = json.load(confFile)

for template in config['vdsConfFiles']:
    print(f"Checking {template}")