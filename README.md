# LockGuard: A Robust Authentication System

LockGuard is an authentication system designed to secure user passwords with strong hashing algorithms and prevent duplicate usernames. The system provides basic sign-up and login functionality using bcrypt to hash passwords and a simple file-based storage solution for usernames and hashed passwords.

## Features:
- **Strong Password Validation:** Ensures passwords meet complexity requirements (uppercase, lowercase, number, special character).
- **Secure Password Storage:** Passwords are hashed using bcrypt before being stored.
- **No Duplicate Usernames:** Prevents users from registering with the same username.
- **Easy-to-Use API:** Simple RESTful API for user registration and login.

## How to Use:

### 1. Start the Application
First, ensure that you have Python 3 installed. To start the server, run the following command in your terminal:
```bash
python app.py
