"""
Author: Andrea Salswach Lopez
ID: 101580260
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""


import socket
import threading
import sqlite3
import os
import platform
import datetime


print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

# Q3: What is the benefit of using @property and @target.setter?
# @property and @target.setter allow us to control how the target value is accessed and modified.
# Instead of directly changing the variable, we can add validation to prevent invalid values like empty strings.
# This helps protect the data and keeps the program more reliable while still allowing the attribute to be used like a normal variable.

    @property
    def target(self):
        return self.__target
    
    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
            return
        self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# The PortScanner class is a child class that inherits from the NetworkTool parent class. 
# This allows it to use the constructor, destructor, and target property methods that were defined in the parent class without needing to rewrite that code.
# The PortScanner constructor calls super().__init__(target) to initialize the target attribute using the parent class.
# This lets the PortScanner class add its own specific functionalities like scanning ports while reusing the code from NetworkTool and avoiding duplicate code.


class PortScanner(NetworkTool): 
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()


    def scan_port(self,port):
        sock = None

# Q4: What would happen without try-except here?
# Without try-except, the program could crash if an error occurs while scanning a port.
# For example, if the connection fails or the target is unreachable, a socket error would stop the program completely.
# This would prevent the rest of the ports from being scanned.
# Using try-except allows the program to handle errors and continue scanning other ports.
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        
        except socket.error as e: 
            print(f"Error scanning port {port}: {e}")
        finally:
            if sock is not None:
                sock.close()
        

    def get_open_ports(self): 
        return [result for result in self.scan_results if result[1] == "Open"]


# Q2: Why do we use threading instead of scanning one port at a time?
# Threading allows the program to scan multiple ports at the same time instead of one by one.
# This makes the scanning process much faster, especially when checking a large range of ports.
# If we scanned ports sequentially, the program would have to wait for each port to finish before moving to the next.
# Using threads improves performance and reduces the total scan time.

    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)
        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()



def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()
        
        if rows:
            for target, port, status, service, scan_date in rows:
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
        else:
            print("No past scans found.")
    except sqlite3.Error as e:
        print(f"No past scans found.")
    finally:
        conn.close()
        

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
  
    try:
        target = input("Enter target IP address (leave blank for default): ")
        if target == "":
            target = "127.0.0.1"

        start_port = int(input("Enter starting port number (1-1024): "))
        if not (1 <= start_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()

        end_port = int(input("Enter ending port number (1-1024): "))
        if not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()

        if end_port < start_port:
            print("End port must be greater than or equal to start port.")
            exit()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    
    scanner.scan_range(start_port, end_port)
    open_ports = scanner.get_open_ports()
    
    print(f"--- Scan Results for {target} ---")
    if open_ports:
        for port, status, service in open_ports:
            print(f"Port {port}: {status} ({service})")
    else:
        print("No open ports found.")
        
    print("------")
    print(f"Total open ports found: {len(open_ports)}")
   
    save_results(target, scanner.scan_results)  
    
    show_history = input("Would you like to see past scan history? (yes/no): ")
    if show_history.lower() == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# One feature I would add is a filter that displays only open ports with known services from the common_ports dictionary.
# This would use a list comprehension to select only the open ports that have a recognized service name.
# This helps make the output cleaner and more useful by focusing on important and commonly used ports.
# Diagram: See diagram_101580260.png in the repository root

