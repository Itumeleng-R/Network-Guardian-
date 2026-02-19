import socket
import threading

target = "192.168.0.1"
start_port = 1
end_port = 500

print(f"Starting scan on {target}...\n")

def scan_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect((target, port))
        print(f"[+] Port {port} is open")
        s.close()
    except:
        pass

threads = []

for port in range(start_port, end_port):
    t = threading.Thread(target=scan_port, args=(port,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print("\nScan complete.")
