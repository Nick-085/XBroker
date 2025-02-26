#!/usr/bin/env python3
from flask import Flask, request, render_template_string
import subprocess
import json

app = Flask(__name__)

# Load config file
with open('config.json') as confFile:
    config = json.load(confFile)

vdsConfFiles = config['vdsConfFiles']

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        rUser = request.form['username']
        rPass = request.form['password']
        vdiFile = request.form['vdiFile']
        vdiUUID = vdsConfFiles[vdiFile]['uuid']
        expectedCIDR = vdsConfFiles[vdiFile]['expected_cidr_range']
        
        # Execute the Broker script with the provided username, password, VDI file, UUID, and expected CIDR range
        process = subprocess.Popen(['python3', 'Broker.py', rUser, rPass, vdiFile, vdiUUID, expectedCIDR], stdin=subprocess.PIPE, text=True)
        process.communicate()
        
        return 'Broker script executed successfully.'
    
    return render_template_string('''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            Choose a VDI: <select name="vdiFile">
                {% for file, details in vdsConfFiles.items() %}
                    <option value="{{ file }}">{{ details['displayName'] }}</option>
                {% endfor %}
            </select><br>
            <input type="submit" value="Submit">
        </form>
    ''', vdsConfFiles=vdsConfFiles)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)