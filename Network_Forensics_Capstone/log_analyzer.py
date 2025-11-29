import re

def analyze_logs(file_path):
    print(f"[*] Analyzing Log File: {file_path}...")
    
    patterns = {
        'SQL_Injection': r"UNION SELECT|OR 1=1",
        'Unauthorized_Access': r"Failed password|Unauthorized",
        'File_Deletion': r"rm -rf|DELETE FROM",
        'Ransomware_Ext': r"\.enc|\.lock"
    }
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            
        for i, line in enumerate(lines):
            for threat, pattern in patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    print(f"[ALERT] {threat} detected on Line {i+1}: {line.strip()}")
                    
    except FileNotFoundError:
        print("Error: Log file not found.")

if __name__ == "__main__":
    with open("server_logs.txt", "w") as f:
        f.write("2023-10-01 10:00:00 User admin logged in.\n")
        f.write("2023-10-01 10:05:00 Failed password for invalid user root.\n")
        f.write("2023-10-01 10:10:00 GET /search.php?id=1 UNION SELECT * FROM users;\n")
        f.write("2023-10-01 11:00:00 Executing maintenance script: rm -rf /backups\n")
    
    print("Created dummy 'server_logs.txt' for testing.")
    analyze_logs("server_logs.txt")
