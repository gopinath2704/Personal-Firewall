🔥 Python Personal Firewall (Scapy + iptables + Tkinter)

A **lightweight personal firewall for Linux** built using **Python, Scapy, iptables, and Tkinter**.  
It allows you to:

✔ Monitor network traffic in real-time  
✔ Block IPs, ports, and protocols  
✔ View logs inside the GUI  
✔ Start / Stop the firewall  
✔ Auto-enforce rules using iptables  
✔ Log suspicious traffic for audits  

This project is designed for **learning, labs, and demonstration purposes**.

---

🛠 Requirements

Operating System
Linux (Ubuntu / Kali / Debian recommended)

Dependencies
Install these first:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk iptables
pip3 install scapy
````

> ⚠️ **You must run the firewall as root**
> Scapy sniffing + iptables require elevated privileges.

---

## 📁 Project Structure

```
personal_firewall/
│
├── firewall_gui.py     # Main Firewall + GUI
├── firewall.log        # Log file (auto-created)
└── README.md
```

---

## 🚀 Running the Firewall

Run the app using:

```bash
sudo python3 firewall_gui.py
```

The GUI will open.

---

## 🖥 GUI Features

### 🔹 Status Indicator

Shows whether the firewall is:

🟢 RUNNING
🔴 STOPPED

---

### 🔹 Rule Editor

You can configure:

* **Blocked IPs**
* **Blocked Ports**
* **Blocked Protocols (e.g., ICMP)**

Values are **space-separated**, for example:

```
Blocked IPs:       192.168.1.10 10.0.0.5
Blocked Ports:     23 445 3389
Blocked Protocols: ICMP
```

Click **Save Rules** to apply.

---

### 🔹 Control Buttons

| Button             | Function                                |
| ------------------ | --------------------------------------- |
| **Start Firewall** | Begins packet sniffing + rule filtering |
| **Stop Firewall**  | Stops firewall + clears iptables rules  |

---

### 🔹 Log Viewer

The firewall logs:

✔ Allowed packets
✔ Blocked packets
✔ Reason for blocking

Logs are also written to:

```
firewall.log
```

Example entry:

```
2025-12-24 | Blocked TCP Port 23 | IP / TCP 10.0.0.2 > 23
```

---

## 🔐 How Blocking Works

The firewall:

1️⃣ Sniffs packets using Scapy
2️⃣ Matches against your rules
3️⃣ Logs the decision
4️⃣ Uses **iptables** to drop malicious traffic

This ensures **kernel-level blocking** — stronger than simple app-level filtering.

---

## 🧪 Testing

### ICMP Test (Ping)

If ICMP is blocked:

```bash
ping 8.8.8.8
```

You will see blocked logs.

---

### Blocked Port Test

Example: Port 23 (Telnet)

```bash
telnet localhost 23
```

---

## 🛑 Reset Firewall Rules (Important)

If anything breaks:

```bash
sudo iptables -F
```

This clears all applied firewall rules.

---

## ⚠️ Disclaimer

This project is intended **for educational use only**.
Do **not** deploy on production systems without professional review.

---

## ⭐ Future Enhancements (Ideas)

* Auto-ban repeat attackers
* Export logs to PDF / CSV
* Email / Telegram alerts
* Dark mode UI
* System service startup
* Stateful packet tracking

---

## 🙌 Contributions

Feel free to fork, improve, and submit PRs!

---
