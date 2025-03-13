#!/usr/bin/env python3
from flask import Flask, request, render_template_string, redirect, url_for, session
from flask_ldap3_login import LDAP3LoginManager
import subprocess
import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load config file
with open('config.json') as confFile:
    config = json.load(confFile)

vdsConfFiles = config['vdsConfFiles']

def get_config_value(key, default=None):
    return os.getenv(key, config.get(key, default))

# Conditional import for SAML
if config['samlSettings'].get('SP_ENTITY_ID'):
    from flask_saml2.sp import ServiceProvider

    # SAML Configuration
    class MyServiceProvider(ServiceProvider):
        def get_sp_entity_id(self):
            return get_config_value('SP_ENTITY_ID', config['samlSettings'].get('SP_ENTITY_ID', ''))

        def get_sp_private_key(self):
            return get_config_value('SP_PRIVATE_KEY', config['samlSettings'].get('SP_PRIVATE_KEY', ''))

        def get_sp_certificate(self):
            return get_config_value('SP_CERTIFICATE', config['samlSettings'].get('SP_CERTIFICATE', ''))

        def get_idp_entity_id(self):
            return get_config_value('IDP_ENTITY_ID', config['samlSettings'].get('IDP_ENTITY_ID', ''))

        def get_idp_sso_url(self):
            return get_config_value('IDP_SSO_URL', config['samlSettings'].get('IDP_SSO_URL', ''))

        def get_idp_sso_binding(self):
            return get_config_value('IDP_SSO_BINDING', config['samlSettings'].get('IDP_SSO_BINDING', ''))

        def get_idp_certificate(self):
            return get_config_value('IDP_CERTIFICATE', config['samlSettings'].get('IDP_CERTIFICATE', ''))

    sp = MyServiceProvider()
    app.register_blueprint(sp.create_blueprint(), url_prefix='/saml')

# LDAP Configuration
if config['ldapSettings'].get('LDAP_HOST'):
    app.config['LDAP_HOST'] = get_config_value('LDAP_HOST', config['ldapSettings']['LDAP_HOST'])
    app.config['LDAP_BASE_DN'] = get_config_value('LDAP_BASE_DN', config['ldapSettings']['LDAP_BASE_DN'])
    app.config['LDAP_USER_DN'] = get_config_value('LDAP_USER_DN', config['ldapSettings']['LDAP_USER_DN'])
    app.config['LDAP_GROUP_DN'] = get_config_value('LDAP_GROUP_DN', config['ldapSettings']['LDAP_GROUP_DN'])
    app.config['LDAP_USER_RDN_ATTR'] = get_config_value('LDAP_USER_RDN_ATTR', config['ldapSettings']['LDAP_USER_RDN_ATTR'])
    app.config['LDAP_USER_LOGIN_ATTR'] = get_config_value('LDAP_USER_LOGIN_ATTR', config['ldapSettings']['LDAP_USER_LOGIN_ATTR'])
    app.config['LDAP_BIND_USER_DN'] = get_config_value('LDAP_BIND_USER_DN', config['ldapSettings']['LDAP_BIND_USER_DN'])
    app.config['LDAP_BIND_USER_PASSWORD'] = get_config_value('LDAP_BIND_USER_PASSWORD', config['ldapSettings']['LDAP_BIND_USER_PASSWORD'])

    ldap_manager = LDAP3LoginManager(app)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if config['samlSettings'].get('SP_ENTITY_ID'):
        return redirect(url_for('saml_login'))
    elif config['ldapSettings'].get('LDAP_HOST'):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = ldap_manager.authenticate(username, password)
            if user:
                session['user'] = username
                return redirect(url_for('index'))
            else:
                return 'Invalid credentials', 401
        return render_template_string('''
            <form method="post">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
        ''')
    else:
        if request.method == 'POST':
            session['user'] = request.form['username']
            return redirect(url_for('index'))
        return render_template_string('''
            <form method="post">
                Username: <input type="text" name="username"><br>
                <input type="submit" value="Login">
            </form>
        ''')

@app.route('/saml-login')
def saml_login():
    return redirect(url_for('flask_saml2_sp.login'))

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user' not in session:
        return redirect(url_for('login'))

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