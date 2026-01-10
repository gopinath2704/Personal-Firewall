---

# 🔥 Python Linux Firewall with GUI

## 📌 Project Overview

The **Python Linux Firewall** is a rule-based firewall application developed using Python and Scapy.
It monitors real-time network traffic, detects malicious activities such as **port scanning**, and dynamically blocks suspicious IPs, ports, and protocols using **iptables**.
A **Tkinter-based GUI** allows easy rule management, real-time logging, and firewall control.

---

## 🎯 Features

* 📡 Real-time packet sniffing
* 🚫 Block IP addresses, ports, and protocols
* 🔍 Port scan detection using SYN packet threshold
* ⚙️ Dynamic blocking using Linux **iptables**
* 🖥️ User-friendly GUI with dark mode
* 📜 Live firewall logs
* 🚨 Critical alert pop-ups with sound
* 🔐 Root privilege enforcement

---

## 🛠️ Technologies Used

* **Python 3**
* **Scapy** – Packet sniffing & analysis
* **Tkinter** – Graphical User Interface
* **IPTables** – Linux packet filtering
* **Socket** – Local IP detection
* **Threading** – Concurrent packet handling
* **Linux OS**

---

## 📂 Project Structure

```
firewall_gui.py
firewall.log
README.md
```

---

## ⚙️ Requirements

* Linux Operating System
* Python 3.x
* Root privileges (sudo access)

### Required Python Packages

```bash
pip install scapy
```

---

## 🚀 How to Run the Project

1. Clone or download the project files
2. Open a terminal in the project directory
3. Run the firewall as **root**:

```bash
sudo python3 firewall_gui.py
```

⚠️ **Important:** The firewall will not start without root privileges.

---

## 🧪 How It Works

1. The firewall captures incoming packets using Scapy
2. Packets are analyzed based on:

   * Source IP
   * Destination port
   * Protocol type
3. Suspicious behavior (e.g., port scanning) is detected using thresholds
4. Malicious traffic is blocked using iptables
5. Alerts and logs are displayed in real time through the GUI

---

## 🖥️ GUI Features

* Start / Stop Firewall
* Add or modify firewall rules
* View active iptables rules
* Real-time packet logs
* Dark mode support

---

## 📜 Logging

All firewall activity is recorded in:

```
firewall.log
```

Log format:

```
Timestamp | Severity | Message | Packet Summary
```

---

## 🔐 Security Note

This firewall manipulates system-level iptables rules.
Always test in a **controlled or virtual environment**.

---

## 🚧 Future Enhancements

* Outbound traffic filtering
* Persistent rule storage
* IDS integration
* Machine learning-based threat detection
* Windows/macOS support

---

## 📄 License

This project is for **educational purposes only**.

---
