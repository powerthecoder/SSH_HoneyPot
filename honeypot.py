import socket
import paramiko
import threading
import sqlite3

class SSH_Server(paramiko.ServerInterface):
    def __init__(self):
        self.client_ip = None
    
    def set_client_ip(self, ip_addy):
        self.client_ip = ip_addy

    def check_auth_password(self, username, password):
        print(f"{self.client_ip} > {username}:{password}")
        sql = sqlite3.connect("SSH_HoneyPot/honeypot_logs.db")
        c = sql.cursor()
        c.execute(f"INSERT INTO honeypot (log_time, ip_addy, username, password) VALUES (CURRENT_TIMESTAMP, '{self.client_ip}', '{username}', '{password}')")
        c.execute("COMMIT")
        c.close()
        sql.close()

        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        print(f"{self.client_ip} > {username}:{key}")
        sql = sqlite3.connect("SSH_HoneyPot/honeypot_logs.db")
        c = sql.cursor()
        c.execute(f"INSERT INTO honeypot_key (log_time, ip_addy, username, password) VALUES (CURRENT_TIMESTAMP, '{self.client_ip}', '{username}', '{key}')")
        c.execute("COMMIT")
        c.close()
        sql.close()

        return paramiko.AUTH_FAILED
    
def handle_connection(client_sock, server_key, client_ip):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(server_key)
    ssh = SSH_Server()
    ssh.set_client_ip(client_ip)
    transport.start_server(server=ssh)

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host_ip = '0.0.0.0'
    host_port = 22
    server_sock.bind((host_ip, host_port))
    server_sock.listen(100)

    server_key = paramiko.RSAKey.generate(2048)
    print(f"[+] HoneyPot Started on {host_ip}:{host_port}")

    while True:
        client_sock, client_addr = server_sock.accept()
        client_ip = f"{client_addr[0]}:{client_addr[1]}"
        #print(f"Connection: {client_ip}")
        t = threading.Thread(target=handle_connection, args=(client_sock, server_key, client_ip))
        t.start()

if __name__ == '__main__':
    main()