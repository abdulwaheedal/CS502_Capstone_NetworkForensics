# CS502_Capstone_NetworkForensics

## 📘 Overview

This project, **CS502 Capstone: Network Forensics**, is a Python-based toolkit designed to simulate and analyze key components of **digital forensics and cybersecurity investigations**.
It includes modules for **network packet sniffing**, **vulnerability scanning**, and **log file analysis**, providing hands-on exposure to forensic evidence collection and threat detection.

---

## 🧩 Project Structure

```

CS502_Capstone_NetworkForensics/
│
├── Network_Forensics_Capstone/
│   ├── log_analyzer.py         # Detects potential malicious patterns in server logs
│   ├── packet_sniffer.py       # Captures live network packets and identifies suspicious activity
│   ├── vuln_scanner.py         # Scans for open ports and potential vulnerabilities
│
└── README.md                   # Project documentation

````

---

## ⚙️ Requirements

This project is written in **Python 3.x** and relies only on Python’s **standard library**.
No external dependencies are required.

### 🧰 Modules Used

* `socket` – For network connections and packet capture
* `struct` – To unpack network data structures
* `re` – For log pattern matching using regular expressions
* `datetime` – For timestamping scans
* `os`, `textwrap` – For system and text processing tasks

---

## 🚀 Modules Description

### 1. `log_analyzer.py`

**Purpose:**
Analyzes server or system logs to detect suspicious activities such as SQL injections, unauthorized access attempts, ransomware signatures, and file deletions.

**Features:**

* Uses regular expressions to detect common forensic artifacts.
* Highlights suspicious log entries with line numbers.
* Automatically generates a sample `server_logs.txt` file for testing.

**Usage:**

```bash
python3 log_analyzer.py
````

---

### 2. `packet_sniffer.py`

**Purpose:**
Captures and analyzes live network traffic to detect suspicious TCP activity, particularly SYN flood attacks.

**Features:**

* Detects and flags multiple SYN packets from the same source (indicative of DDoS behavior).
* Displays packet source/destination details and TCP flags.
* Supports both Linux and Windows environments (Admin/root privileges required).

**Usage:**

```bash
sudo python3 packet_sniffer.py
```

**Note:**
Running this script on Windows requires administrative privileges and IP binding.
Running on Linux requires `sudo` privileges due to raw socket usage.

---

### 3. `vuln_scanner.py`

**Purpose:**
Performs a basic vulnerability assessment by scanning a host for open ports commonly targeted in cyberattacks.

**Features:**

* Checks common service ports (FTP, SSH, HTTP, HTTPS, SMB, MySQL, etc.).
* Flags potential security risks based on open ports.
* Provides forensic-style alerts for common exploitation scenarios.

**Usage:**

```bash
python3 vuln_scanner.py
```

**Example Output:**

```
[*] Starting Forensics Scan on Host: 127.0.0.1
[*] Time: 2025-11-29 13:45:00
[+] Port 80: OPEN
[+] Port 443: OPEN
[*] Scan Complete. Found 2 open ports.
```

---

## 🔍 Forensic Applications

This toolkit can be used in:

* **Incident Response Simulations** – Detecting malicious activity on compromised hosts.
* **Cybersecurity Education** – Demonstrating forensic evidence collection techniques.
* **Research and Case Studies** – Understanding the behavioral patterns of common attacks.

---

## ⚠️ Legal & Ethical Notice

This software is intended **strictly for educational and authorized research purposes**.
Do **not** use these tools to scan or capture traffic from systems you do not own or have explicit permission to test.
Unauthorized use may violate local, state, or federal laws.

---

## 🧠 Author

**Name:** Abdul Waheed Al Faaiz
**Course:** CS502 – Capstone Project in Network Forensics
**Institution:** K.R. Mangalam University
**Year:** 2025

---

## 📄 License

This project is released under the **MIT License**.
You are free to use, modify, and distribute it for educational or research purposes with appropriate credit.

---
