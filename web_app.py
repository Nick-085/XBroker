#!/usr/bin/env python3
from flask import Flask, request, render_template_string, send_from_directory
import subprocess
import json
import os

app = Flask(__name__)

# Load VDS profiles from directory
def load_vds_profiles():
    profiles = {}
    vds_profiles_dir = 'vdsProfiles'
    
    for filename in os.listdir(vds_profiles_dir):
        if filename.endswith('.json'):
            with open(os.path.join(vds_profiles_dir, filename)) as f:
                profile = json.load(f)
                profiles[filename] = profile['vdsProperties']
    
    return profiles

vdsConfFiles = load_vds_profiles()

# Serve the static frontend folder
@app.route('/frontend/<path:filename>')
def frontend_static(filename):
    return send_from_directory('frontend', filename)

@app.route('/frontend/')
def frontend_index():
    return send_from_directory('frontend', 'index.html')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            rUser = request.form['username']
            rPass = request.form['password']
            vdiFile = request.form['vdiFile']
            # Load profile for this VDI
            with open(os.path.join('vdsProfiles', vdiFile)) as f:
                profile = json.load(f)
                vdiUUID = profile['vdsProperties']['uuid']
                expectedCIDR = profile['vdsProperties']['expected_cidr_range']
            
            # Execute the Broker script with the provided username, password, VDI file, UUID, and expected CIDR range
            process = subprocess.run(
                ['python3', 'Broker.py', rUser, rPass, vdiFile, vdiUUID, expectedCIDR],
                text=True,
                capture_output=True,
                check=True
            )
            
            if process.returncode != 0:
                error_msg = process.stderr.strip() or "Unknown error occurred"
                app.logger.error(f"Broker script error: {error_msg}")
                return {'error': f"Broker script error: {error_msg}"}, 500
            
            app.logger.info(f"Broker output: {process.stdout}")
            return {'status': 'success', 'message': process.stdout}, 200
        except Exception as e:
            error_msg = str(e)
            app.logger.error(f"Error: {error_msg}")
            return {'error': error_msg}, 500
    
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