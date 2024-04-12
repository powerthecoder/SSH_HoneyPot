import socket
import paramiko
import threading
import sqlite3

class SSH_Server(paramiko.ServerInterface):
    def __init__(self):
        self.client_ip = None
    
    def set_client_ip(self, ip_addy):
        self.client_ip = ip_addy
        # We finnaly got the client ip sent to the class... could have we done this easier? probably, but I spent way to long on this and im tired

    def check_auth_password(self, username, password):
        # Here we are processing the username and password to see if we are going to allow it to connect to the server
        print(f"{self.client_ip} > {username}:{password}")
        # Connecting to the database file to report the incident
        sql = sqlite3.connect("SSH_HoneyPot/honeypot_logs.db")
        c = sql.cursor()
        # This is where we are inserting all of the information into the database to be able to view later
        c.execute(f"INSERT INTO honeypot (log_time, ip_addy, username, password) VALUES (CURRENT_TIMESTAMP, ?, ?, ?)", (self.client_ip, username, password))
        c.execute("COMMIT")
        c.close()
        sql.close() # CLOSE IT... dont want anything to break (O_O”)

        # Obviously we are not going to let them connect, its not a real SSH Server... we're just a honeypot >:)
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        # Here we are processing the username and password to see if we are going to allow it to connect to the server
        print(f"{self.client_ip} > {username}:{key}")
        # Connecting to the database file to report the incident
        sql = sqlite3.connect("SSH_HoneyPot/honeypot_logs.db")
        c = sql.cursor()
        # This is where we are inserting all of the information into the database to be able to view later
        c.execute(f"INSERT INTO honeypot_key (log_time, ip_addy, username, keys) VALUES (CURRENT_TIMESTAMP, ?, ?, ?)", (self.client_ip, username, key))
        c.execute("COMMIT")
        c.close()
        sql.close() # CLOSE IT... dont want anything to break (O_O”)

        # Obviously we are not going to let them connect, its not a real SSH Server... we're just a honeypot >:)
        return paramiko.AUTH_FAILED
        # does essentially the same thing as "check_auth_password()" but just differnt types of connections
    
# What are we doing here?
def handle_connection(client_sock, server_key, client_ip):
    # In this funciton we are transporting all of the information we gathered 
    #to the SSH_Server class where all of the information will be propperly processed

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(server_key)
    ssh = SSH_Server()
    ssh.set_client_ip(client_ip) # You can see us sending the Client IP to the SSH_Server() class for logging purposes
    transport.start_server(server=ssh)

# Creating the honeypot SSH
def main():
    # Creates network socks for server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Define host IP and Port here
    host_ip = '0.0.0.0'
    host_port = 22
    # Binds the IP and Port to the socks
    server_sock.bind((host_ip, host_port))
    server_sock.listen(100) # Allows up to 100 connections at the same time

    server_key = paramiko.RSAKey.generate(2048)
    print(f"[+] HoneyPot Started on {host_ip}:{host_port}")

    while True:
        # Accepting attempts of connection
        client_sock, client_addr = server_sock.accept()
        client_ip = f"{client_addr[0]}:{client_addr[1]}"
        # Creating a thread to allow multiple instances of this line to run
        # prevents a buffer from happening (or at least tries)
        t = threading.Thread(target=handle_connection, args=(client_sock, server_key, client_ip)) 
        # ^ We are adding "client_ip" to send the IP that is attempting to connect to store in a SQLite3 Database
        t.start()

# its always here ¯\_(ツ)_/¯
if __name__ == '__main__':
    main()