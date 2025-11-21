import socket

HOST = '127.0.0.1'
PORT = 2222
PASSWORD = 'secret123'

def handle_client(conn):
    # Send protocol greeting, and wait for client's version
    conn.sendall(b"SSH-2.0-MimicSSH\r\n")
    client_version = conn.recv(1024)
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
