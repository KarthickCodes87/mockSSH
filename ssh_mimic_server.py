import socket
import os
# make sure to do pip install
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HOST = '127.0.0.1'
PORT = 2222
PASSWORD = 'secret123'

def handle_client(conn):
    # Send protocol greeting, and wait for client's version
    conn.sendall(b"SSH-2.0-MimicSSH\r\n")
    client_version = conn.recv(1024)

    # DH Key Exchange using key size of 2048
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Send the public key to client
    conn.sendall(public_key_bytes)
    # Receive the client public key
    client_pub_key_bytes = b""
    while True:
        chunk = conn.recv(4096)
        client_pub_key_bytes += chunk
        if b"-----END PUBLIC KEY-----" in client_pub_key_bytes:
            break
    client_public_key = serialization.load_pem_public_key(client_pub_key_bytes)
    shared_key        = private_key.exchange(client_public_key)

    # Derive a symmetric key (HKDF)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data"
    ).derive(shared_key)
    # For demo: print the derived secret key
    print("Shared Secret (hex):", derived_key.hex())
    
    
    conn.sendall(b"Password: ")
    password = conn.recv(1024).strip().decode()

    if password != PASSWORD:
        conn.sendall(b"Authentication failed.\r\n")
        conn.close()
        return

    conn.sendall(b"Authenticated! Type 'exit' to quit.\r\n$ ")
    while True:
        cmd = conn.recv(1024).strip().decode()
        if cmd == 'exit':
            conn.sendall(b"Bye!\r\n")
            break
        else:
            try:
                output = os.popen(cmd).read()
                if not output:
                    output = "[No output]\n"
                conn.sendall(output.encode() + b"$ ")
            except Exception as e:
                conn.sendall(f"Error: {e}\n$ ".encode())
    conn.close()

if __name__ == "__main__":
    import os
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening on {HOST}:{PORT} ...")
        while True:
            conn, addr = s.accept()
            print(f"Connection from {addr}")
            handle_client(conn)
