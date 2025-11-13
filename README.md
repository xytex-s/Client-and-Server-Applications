# Client and Server Applications

A Python client-server application for secure log file transmission.

## What it does

- Client application finds log files and encrypts them with AES-256
- Server application receives encrypted files, decrypts them, and stores them securely  
- Uses RSA encryption for key exchange and SHA-256 for integrity verification
- Monitors log files for changes and automatically sends updates

## Setup

- Install requirements: `pip install cryptography`
- Generate RSA keys for the server
- Configure server IP and port in client application
- Run server first, then client

## Files

- `client-application.py` - Finds and encrypts log files, sends to server
- `server-application.py` - Receives encrypted files, decrypts and stores them

Part of SHU Networking Project
