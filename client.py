import socket
import secrets
from Crypto.Cipher import AES
import hashlib

# Diffie-Hellman parameters (must match the server)
P = 31  # New prime number
G = 6   # New generator

# Function to generate AES key from the shared secret
def generate_aes_key(secret):
    return hashlib.sha512(str(secret).encode('utf-8')).digest()[:32]  # Truncate to 32 bytes

# Function to decrypt a message using AES
def retrieve_message(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Initialize the client
def initialize_client():
    IP = '127.0.0.1'  # Server's IP address
    port = 12345       # Same port as the server

    # Set up the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP, port))

    # Client generates private and public keys
    client_private_key = secrets.randbelow(P - 1) + 1
    client_public_key = pow(G, client_private_key, P)

    # Receive the server's public key
    server_public_key = int(client_socket.recv(1024).decode('utf-8'))
    print(f"Server's public key received: {server_public_key}")

    # Send client's public key to the server
    print(f"Sending client's public key: {client_public_key}")
    client_socket.send(str(client_public_key).encode('utf-8'))

    # Derive the shared secret key
    shared_secret = pow(server_public_key, client_private_key, P)
    print(f"Shared secret derived: {shared_secret}")

    # Receive the handshake confirmation
    handshake_msg = client_socket.recv(1024).decode('utf-8')
    print(f"Handshake received: {handshake_msg}")

    # Generate the AES key from the shared secret
    aes_key = generate_aes_key(shared_secret)

    # Receive the encrypted data from the server
    encrypted_data = client_socket.recv(1024)
    nonce, ciphertext, tag = encrypted_data[:16], encrypted_data[16:-16], encrypted_data[-16:]
    print(f"Encrypted data received (nonce: {nonce.hex()}, ciphertext: {ciphertext.hex()}, tag: {tag.hex()})")

    # Decrypt the message using the AES key
    decrypted_msg = retrieve_message(aes_key, nonce, ciphertext, tag)
    print(f"Decrypted message: {decrypted_msg}")

    client_socket.close()

if __name__ == "__main__":
    initialize_client()