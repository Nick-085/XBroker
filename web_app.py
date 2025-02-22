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
        
        # Execute the Broker script with the provided username, password, and VDI file
        process = subprocess.Popen(['python3', 'Broker.py', rUser, rPass, vdiFile], stdin=subprocess.PIPE, text=True)
        process.communicate()
        
        return 'Broker script executed successfully.'
    
    return render_template_string('''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            VDI File: <select name="vdiFile">
                {% for file in vdsConfFiles %}
                    <option value="{{ file }}">{{ file }}</option>
                {% endfor %}
            </select><br>
            <input type="submit" value="Submit">
        </form>
    ''', vdsConfFiles=vdsConfFiles)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)