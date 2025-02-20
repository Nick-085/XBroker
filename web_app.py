#!/usr/bin/env python3
from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        rUser = request.form['username']
        rPass = request.form['password']
        
        # Execute the Broker script with the provided username and password
        process = subprocess.Popen(['python3', 'Broker.py', rUser, rPass], stdin=subprocess.PIPE, text=True)
        process.communicate()
        
        return 'Broker script executed successfully.'
    
    return render_template_string('''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Submit">
        </form>
    ''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)