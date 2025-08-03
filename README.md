# Python Password Manager 🔐
This is a simple command line based password manager for storing your credentials, built using python .

## Security Features 
Passwords are secured strongly using Fernet encryption from cryptography module. 
A master password is required to access the vault and is verified using secured hashing function.
None of the sensitive data is stored in plain text. All of them are either encrypted or hashed.

## Features
- Create new encrypted vaults
- Add service credentials
- View stored passwords
- Master password support


## How to Use
1. Run 'main.py'
2. Follow the on-screen menu to create a vault, add or retrieve passwords.

## Requirements
- Python version 3.10+
- cryptography module