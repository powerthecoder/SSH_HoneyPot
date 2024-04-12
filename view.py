import time
import sqlite3

def view_raw():
    connection = sqlite3.connect("SSH_HoneyPot/honeypot_logs.db")
    cursor = connection.cursor()
    print("SQL Table Connected")
    print("SQL Table Displaying")
    cursor.execute("SELECT * FROM honeypot")
    rows = cursor.fetchall()
    for row in rows:
        print(row)
    cursor.execute("SELECT * FROM honeypot_key")
    rows = cursor.fetchall()
    for row in rows:
        print(row)
    cursor.close()
    connection.close()
    print("SQL Table Closed")

view_raw()