import requests
import flask
from flask import Flask, request, jsonify
import hashlib
import bcrypt
import os
import re
import json  # For saving failed attempts count

class implementPasscode():

    def __init__(self, passcode):
        self.passcode = passcode

    def ValidPasscode(self):
        if len(self.passcode) < 8:
            return False
        if not re.search(r'[a-z]', str(self.passcode)):  # Lowercase check
            return False
        if not re.search(r'[A-Z]', str(self.passcode)):  # Uppercase check
            return False
        if not re.search(r'[0-9]', str(self.passcode)):  # Digit check
            return False
        if not re.search(r'[@#$%^&*!]', str(self.passcode)):  # Special char check
            return False
        return True

    def createTable(self, username, hashedPasscode):
        with open("Passcodes.txt", "a") as hashedCodes:
            hashedCodes.write(f"{username}:{hashedPasscode}\n")

    def compromised(self):
        sha1_password = hashlib.sha1(self.passcode.encode()).hexdigest().upper()  # Fixed encoding
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)

        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return f"Your password has been pwned {count} times!"
            return "Your password is safe (not found in breaches)."
        else:
            return "Error: Unable to reach the API."

    def hash_password(self):
        # Directly hash the password using SHA256 (no salt)
        return hashlib.sha256(self.passcode.encode()).hexdigest()

class Server():
    app = Flask(__name__)  # Define app inside the class

    # Load failed login attempts from a JSON file (or initialize if not exists)
    def load_failed_attempts():
        if os.path.exists('failed_attempts.json'):
            with open('failed_attempts.json', 'r') as f:
                return json.load(f)
        return {}

    # Save failed login attempts to a JSON file
    def save_failed_attempts(attempts):
        with open('failed_attempts.json', 'w') as f:
            json.dump(attempts, f)

    @app.route('/')
    def index():
        return "Welcome To The Secure Login System!"

    @app.route('/signup', methods=['POST'])
    def signup():
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Check if username already exists
        try:
            with open("Passcodes.txt", "r") as file:
                for line in file:
                    stored_user, _ = line.strip().split(":")
                    if stored_user == username:
                        return jsonify({"error": "Username already exists."}), 400
        except FileNotFoundError:
            pass  # File not found is fine, just continue to signup

        pass_instance = implementPasscode(password)

        if not pass_instance.ValidPasscode():
            return jsonify({"error": "Weak password. Must meet security requirements."}), 400

        password_compromise_check = pass_instance.compromised()  # Check if password is compromised
        if "pwned" in password_compromise_check:
            return jsonify({"error": password_compromise_check}), 400

        hashed_pass = pass_instance.hash_password()
        pass_instance.createTable(username, hashed_pass)

        return jsonify({"message": "User registered successfully!"})

    @app.route('/login', methods=['POST'])
    def login():
        data = request.json
        username = data.get('username')
        password = data.get('password')

        failed_attempts = Server.load_failed_attempts()

        # Check if the account is locked due to too many failed attempts
        if username in failed_attempts and failed_attempts[username] >= 5:
            return jsonify({"error": "Account is locked due to too many failed login attempts. Please try again later."}), 403

        hashed_password = hashlib.sha256(password.encode()).hexdigest()  # Hash the login password

        try:
            with open("Passcodes.txt", "r") as file:
                for line in file:
                    stored_user, stored_hash = line.strip().split(":")
                    if stored_user == username and stored_hash == hashed_password:
                        # Reset failed attempts on successful login
                        if username in failed_attempts:
                            del failed_attempts[username]
                            Server.save_failed_attempts(failed_attempts)
                        return jsonify({"message": "Login successful!"})

        except FileNotFoundError:
            return jsonify({"error": "No users found. Please sign up first."}), 400

        # Track failed login attempts
        if username not in failed_attempts:
            failed_attempts[username] = 0

        failed_attempts[username] += 1
        Server.save_failed_attempts(failed_attempts)

        return jsonify({"error": "Invalid username or password."}), 401

if __name__ == "__main__":
    Server.app.run(debug=True)  # Run Flask app from Server class
