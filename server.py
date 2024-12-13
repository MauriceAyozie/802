import socket
import secrets
from Crypto.Cipher import AES
import hashlib

# Diffie-Hellman parameters (randomized for security)
P = 31  # New prime number
G = 6   # New generator

# Function to generate AES key from the shared secret
def generate_aes_key(secret):
    return hashlib.sha512(str(secret).encode('utf-8')).digest()[:32]  # Truncate to 32 bytes

# Function to encrypt a message using AES
def secure_message(key, msg):
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted_data, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
    return cipher.nonce, encrypted_data, tag

# Initialize the server
def initialize_server():
    IP = '127.0.0.1'  # Loopback address
    port = 12345       # New port number

    # Set up the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, port))
    server_socket.listen()

    print("Server waiting for client connection...")
    conn, address = server_socket.accept()
    print(f"Connection established with: {address}")

    # Start handling the client
    interact_with_client(conn)

    conn.close()

# Handle communication with the client
def interact_with_client(conn):
    # Server generates private and public keys
    private_key = secrets.randbelow(P - 1) + 1
    public_key = pow(G, private_key, P)

    # Send the server's public key to the client
    print(f"Server's public key sent: {public_key}")
    conn.send(str(public_key).encode('utf-8'))

    # Receive client's public key
    client_public_key = int(conn.recv(1024).decode('utf-8'))
    print(f"Received client's public key: {client_public_key}")

    # Derive shared secret key
    shared_secret = pow(client_public_key, private_key, P)
    print(f"Shared secret derived: {shared_secret}")

    # Acknowledge handshake success
    success_message = "Session started successfully!"
    print(f"Sending confirmation: {success_message}")
    conn.send(success_message.encode('utf-8'))

    # Generate AES key using shared secret
    aes_key = generate_aes_key(shared_secret)

    # Encrypt and send data
    nonce, encrypted_msg, tag = secure_message(aes_key, "Here is the encrypted message")
    print(f"Encrypted data sent: {encrypted_msg.hex()} (nonce: {nonce.hex()}, tag: {tag.hex()})")
    conn.send(nonce + encrypted_msg + tag)

if __name__ == "__main__":
    initialize_server()


