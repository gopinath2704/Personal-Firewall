import tkinter as tk
from tkinter import messagebox, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import os

# ---- Default Rules ----
RULES = {
    "blocked_ips": ["192.168.1.100"],
    "blocked_ports": [23, 445],
    "blocked_protocols": ["ICMP"]
}

LOG_FILE = "firewall.log"
firewall_running = False


# ---- Logging Function ----
def log(reason, packet):
    entry = f"{datetime.now()} | {reason} | {packet.summary()}\n"
    with open(LOG_FILE, "a") as f:
        f.write(entry)
    log_box.insert(tk.END, entry)
    log_box.see(tk.END)


# ---- iptables ----
def block_ip(ip):
    os.system(f"iptables -A INPUT -s {ip} -j DROP")

def block_port(port):
    os.system(f"iptables -A INPUT -p tcp --dport {port} -j DROP")


# ---- Packet Handler ----
def packet_handler(packet):
    if IP in packet:
        src = packet[IP].src

        if src in RULES["blocked_ips"]:
            log(f"Blocked IP {src}", packet)
            block_ip(src)
            return

        if ICMP in packet and "ICMP" in RULES["blocked_protocols"]:
            log("Blocked ICMP", packet)
            return

        if TCP in packet and packet[TCP].dport in RULES["blocked_ports"]:
            port = packet[TCP].dport
            log(f"Blocked TCP Port {port}", packet)
            block_port(port)
            return

        if UDP in packet and packet[UDP].dport in RULES["blocked_ports"]:
            port = packet[UDP].dport
            log(f"Blocked UDP Port {port}", packet)
            block_port(port)
            return

        log("Allowed", packet)


# ---- Sniffer Thread ----
def start_sniffing():
    sniff(prn=packet_handler, store=False)


# ---- GUI Callbacks ----
def start_firewall():
    global firewall_running

    if firewall_running:
        messagebox.showinfo("Info", "Firewall already running")
        return

    firewall_running = True
    status_label.config(text="Firewall Status: RUNNING", fg="green")

    t = threading.Thread(target=start_sniffing, daemon=True)
    t.start()


def stop_firewall():
    global firewall_running
    firewall_running = False
    os.system("iptables -F")
    status_label.config(text="Firewall Status: STOPPED", fg="red")
    messagebox.showinfo("Firewall", "Firewall stopped and iptables cleared")


def save_rules():
    try:
        RULES["blocked_ips"] = ip_entry.get().split()
        RULES["blocked_ports"] = list(map(int, port_entry.get().split()))
        RULES["blocked_protocols"] = proto_entry.get().split()

        messagebox.showinfo("Saved", "Rules updated successfully")
    except:
        messagebox.showerror("Error", "Invalid rule format")


# ---- Tkinter Window ----
root = tk.Tk()
root.title("Linux Personal Firewall (Python + Scapy + iptables)")
root.geometry("750x600")

title = tk.Label(root, text="Personal Firewall - GUI", font=("Arial", 16))
title.pack(pady=10)

status_label = tk.Label(root, text="Firewall Status: STOPPED", fg="red", font=("Arial", 12))
status_label.pack(pady=5)


# ---- Rule Editor ----
frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Blocked IPs (space separated):").grid(row=0, column=0, sticky="w")
ip_entry = tk.Entry(frame, width=50)
ip_entry.grid(row=0, column=1)
ip_entry.insert(0, " ".join(RULES["blocked_ips"]))

tk.Label(frame, text="Blocked Ports:").grid(row=1, column=0, sticky="w")
port_entry = tk.Entry(frame, width=50)
port_entry.grid(row=1, column=1)
port_entry.insert(0, " ".join(map(str, RULES["blocked_ports"])))

tk.Label(frame, text="Blocked Protocols:").grid(row=2, column=0, sticky="w")
proto_entry = tk.Entry(frame, width=50)
proto_entry.grid(row=2, column=1)
proto_entry.insert(0, " ".join(RULES["blocked_protocols"]))

tk.Button(root, text="Save Rules", command=save_rules).pack(pady=5)


# ---- Control Buttons ----
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

tk.Button(button_frame, text="Start Firewall", command=start_firewall, width=20).grid(row=0, column=0, padx=5)
tk.Button(button_frame, text="Stop Firewall", command=stop_firewall, width=20).grid(row=0, column=1, padx=5)


# ---- Log Window ----
tk.Label(root, text="Firewall Log Output:").pack()
log_box = scrolledtext.ScrolledText(root, width=80, height=20)
log_box.pack()


root.mainloop()
