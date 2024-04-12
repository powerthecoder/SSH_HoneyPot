import socket
import paramiko
import threading
import time
import sqlite3

class SSH_Server(paramiko.ServerInterface):
    def __init__(self):
        self.client_ip = None
    
    def get_banner(self):
        return "SSH HONEYPOT", None
    
    def check_auth_passwd(self, username, password):
        connection = sqlite3.connect("honeypot_logs.db")
        cursor = connection.cursor()
        cursor.execute(f"INSERT INTO honeypot (log_time, ip_addy, username, password) VALUES (CURRENT_TIMESTAMP, '{self.client_ip}', '{username}', '{password}')")
        cursor.execute("COMMIT")
        cursor.close()
        connection.close()
        print(f"[{time.now()}]  {username}:{password}")
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        connection = sqlite3.connect("honeypot_logs.db")
        cursor = connection.cursor()
        cursor.execute(f"INSERT INTO honeypot_key (log_time, ip_addy, username, keys) VALUES (CURRENT_TIMESTAMP, '{self.client_ip}', '{username}', '{key}')")
        cursor.execute("COMMIT")
        cursor.close()
        connection.close()
        print(f"[{time.now()}]  {username}:{key}")
        return paramiko.AUTH_FAILED

def handle_connection(client_sock, server_key):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(server_key)
    client_ip = client_sock.getpeername()[0]
    ssh = SSH_Server
    ssh.client_ip = client_ip
    transport.start_server(server=ssh)

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', 22))
    server_sock.listen(100)

    server_key = paramiko.RSAKey.generate(2048)
    while True:
        client_sock, client_addr = server_sock.accept()
        print(f'Connection: {client_addr[0]}:{client_addr[1]}')
        thread = threading.Thread(target=handle_connection, args=(client_sock, server_key))
        thread.start()
    
if __name__ == '__main__':
    main()
