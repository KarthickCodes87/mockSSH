import socket

HOST = '127.0.0.1'
PORT = 2222

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        banner = s.recv(1024)
        print(banner.decode().strip())
        # Send our "Version"
        s.sendall(b"SSH-2.0-MimicClient\r\n")
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
