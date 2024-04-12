import time
import sqlite3
def first_time():
    connection = sqlite3.connect("SSH_HoneyPot/honeypot_logs.db")
    cursor = connection.cursor()
    print("SQL Table Connected")
    cursor.execute("CREATE TABLE honeypot (log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ip_addy TEXT, username TEXT, password TEXT)")
    print("SQL Table Created")
    cursor.execute("CREATE TABLE honeypot_key (log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ip_addy TEXT, username TEXT, keys TEXT)")
    print("SQL Table Key Created")
    cursor.execute("INSERT INTO honeypot (log_time, ip_addy, username, password) VALUES (CURRENT_TIMESTAMP, 'IGNORE_0.0.0.0', 'IGNORE_username', 'IGNORE_password')")
    cursor.execute("INSERT INTO honeypot_key (log_time, ip_addy, username, keys) VALUES (CURRENT_TIMESTAMP, 'IGNORE_0.0.0.0', 'IGNORE_username', 'IGNORE_key')")
    cursor.execute("COMMIT")
    print("SQL Table Inserted test")
    time.sleep(2)
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


first_time()
