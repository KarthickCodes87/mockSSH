import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HOST = '127.0.0.1'
PORT = 2222

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        banner = s.recv(1024)
        print(banner.decode().strip())
        # Send our "Version"
        s.sendall(b"SSH-2.0-MimicClient\r\n")

        # receive the server public key first
        server_pub_key_bytes = b""
        while True:
            chunk = s.recv(4096)
            server_pub_key_bytes += chunk
            if b"-----END PUBLIC KEY-----" in server_pub_key_bytes:
                break
        server_public_key    = serialization.load_pem_public_key(
            server_pub_key_bytes)
        parameters           = server_public_key.public_numbers().parameter_numbers
        param_numbers        = dh.DHParameterNumbers(
            p=parameters.p,
            g=parameters.g)
        dh_parameters        = param_numbers.parameters()
        private_key          = dh_parameters.generate_private_key()
        client_pub_key_bytes = private_key.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

        # send the public key created 
        s.sendall(client_pub_key_bytes)

        # compute a shared key
        shared_key  = private_key.exchange(server_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data"
        ).derive(shared_key)
        print("Shared Secret (hex):", derived_key.hex())
            
        prompt = s.recv(1024)
        print(prompt.decode(), end='')
        # Enter password
        pw = input()
        s.sendall(pw.encode() + b"\n")
        reply = s.recv(1024)
        print(reply.decode(), end='')
        if b"Authenticated!" not in reply:
            return
        while True:
            cmd = input('$ ')
            s.sendall(cmd.encode()+b'\n')
            res = s.recv(4096)
            print(res.decode(), end='')
            if "Bye!" in res.decode():
                break

if __name__ == "__main__":
    main()
