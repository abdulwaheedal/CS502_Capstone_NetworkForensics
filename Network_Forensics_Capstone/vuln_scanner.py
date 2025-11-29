import socket
from datetime import datetime

def scan_target(target_ip):
    print(f"\n[*] Starting Forensics Scan on Host: {target_ip}")
    print(f"[*] Time: {datetime.now()}")
    
    open_ports = []
    
    target_ports = [21, 22, 23, 80, 443, 445, 3306, 8080]
    
    try:
        for port in target_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                print(f"[+] Port {port}: OPEN")
                open_ports.append(port)
            else:
                print(f"[-] Port {port}: Closed/Filtered")
            sock.close()
            
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return

    print(f"[*] Scan Complete. Found {len(open_ports)} open ports.")
    
    if 3306 in open_ports:
        print("[!] RISK ALERT: MySQL Port (3306) is open. Vulnerable to SQL Injection (Ref: Case 3).")
    if 445 in open_ports:
        print("[!] RISK ALERT: SMB Port (445) is open. Vulnerable to Ransomware spread (Ref: Case 2).")

if __name__ == "__main__":
    t = input("Enter Target IP (e.g., 127.0.0.1): ")
    scan_target(t)
