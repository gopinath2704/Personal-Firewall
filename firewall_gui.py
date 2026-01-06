import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict
import threading
import socket
import os
import time

RULES = {
    "blocked_ips": ["192.168.1.100"],
    "blocked_ports": [23, 445],
    "blocked_protocols": ["ICMP"]
}

LOG_FILE = "firewall.log"
firewall_running = False
dark_mode = False

blocked_cache_ip = set()
blocked_cache_port = set()
scan_tracker = defaultdict(int)

SCAN_THRESHOLD = 15
local_ips = {"127.0.0.1", socket.gethostbyname(socket.gethostname())}


def alert_sound():
    try:
        os.system("paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga")
    except:
        pass


def log(severity, message, packet):
    entry = f"{datetime.now()} | {severity} | {message} | {packet.summary()}\n"
    with open(LOG_FILE, "a") as f:
        f.write(entry)

    log_box.insert(tk.END, entry)
    log_box.see(tk.END)

    if severity == "CRITICAL":
        show_critical_popup(message)


def show_critical_popup(message):
    popup = Toplevel(root)
    popup.title("CRITICAL SECURITY ALERT")
    popup.geometry("450x200")
    popup.configure(bg="black")

    label = tk.Label(popup, text=message, fg="red", bg="black", font=("Arial", 14, "bold"))
    label.pack(pady=40)

    def flash():
        while True:
            label.config(fg="yellow")
            time.sleep(0.4)
            label.config(fg="red")
            time.sleep(0.4)

    threading.Thread(target=flash, daemon=True).start()
    threading.Thread(target=alert_sound, daemon=True).start()


def block_ip(ip):
    if ip not in blocked_cache_ip:
        os.system(f"iptables -I INPUT -s {ip} -j DROP")
        blocked_cache_ip.add(ip)


def block_port(port):
    if port not in blocked_cache_port:
        os.system(f"iptables -I INPUT -p tcp --dport {port} -j DROP")
        blocked_cache_port.add(port)


def packet_handler(packet):
    if not firewall_running:
        return

    if IP in packet:
        src = packet[IP].src

        if src in local_ips:
            return

        if TCP in packet and packet[TCP].flags == "S":
            scan_tracker[src] += 1
            if scan_tracker[src] >= SCAN_THRESHOLD:
                log("CRITICAL", f"Port Scan Detected from {src}", packet)
                block_ip(src)
                return

        if src in RULES["blocked_ips"]:
            log("HIGH", f"Blocked Blacklisted IP {src}", packet)
            block_ip(src)
            return

        if ICMP in packet and "ICMP" in RULES["blocked_protocols"]:
            log("HIGH", "Blocked ICMP Packet", packet)
            return

        if TCP in packet and packet[TCP].dport in RULES["blocked_ports"]:
            log("HIGH", f"Blocked TCP Port {packet[TCP].dport}", packet)
            block_port(packet[TCP].dport)
            return

        if UDP in packet and packet[UDP].dport in RULES["blocked_ports"]:
            log("HIGH", f"Blocked UDP Port {packet[UDP].dport}", packet)
            block_port(packet[UDP].dport)
            return

        log("LOW", "Allowed Packet", packet)


def start_sniffing():
    sniff(prn=packet_handler, store=False, stop_filter=lambda p: not firewall_running)


def start_firewall():
    global firewall_running
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        messagebox.showerror("ERROR", "Run as ROOT:\n\nsudo python3 firewall.py")
        return

    if firewall_running:
        return

    firewall_running = True
    status_label.config(text="Firewall Status: RUNNING", fg="lightgreen" if dark_mode else "green")
    threading.Thread(target=start_sniffing, daemon=True).start()


def stop_firewall():
    global firewall_running
    firewall_running = False
    os.system("iptables -F")
    blocked_cache_ip.clear()
    blocked_cache_port.clear()
    status_label.config(text="Firewall Status: STOPPED", fg="red")


def save_rules():
    try:
        RULES["blocked_ips"] = ip_entry.get().split()
        RULES["blocked_ports"] = list(map(int, port_entry.get().split()))
        RULES["blocked_protocols"] = proto_entry.get().split()
        messagebox.showinfo("Saved", "Firewall Rules Updated")
    except:
        messagebox.showerror("Error", "Invalid Rule Format")


def view_rules():
    win = Toplevel(root)
    win.title("Current Firewall Rules")
    win.geometry("600x400")

    text = scrolledtext.ScrolledText(win, width=70, height=20)
    text.pack()

    text.insert(tk.END, "=== APPLICATION RULES ===\n")
    text.insert(tk.END, f"Blocked IPs: {RULES['blocked_ips']}\n")
    text.insert(tk.END, f"Blocked Ports: {RULES['blocked_ports']}\n")
    text.insert(tk.END, f"Blocked Protocols: {RULES['blocked_protocols']}\n\n")

    text.insert(tk.END, "=== IPTABLES RULES ===\n")
    text.insert(tk.END, os.popen("iptables -L").read())


# ---------------- DARK MODE ----------------
def apply_theme():
    bg = "#0f0f0f" if dark_mode else "#ffffff"
    fg = "#dddddd" if dark_mode else "#000000"
    boxbg = "#1e1e1e" if dark_mode else "#ffffff"

    root.config(bg=bg)
    for widget in root.winfo_children():
        try:
            widget.config(bg=bg, fg=fg)
        except:
            pass

    for e in [ip_entry, port_entry, proto_entry]:
        e.config(bg=boxbg, fg=fg, insertbackground=fg)

    log_box.config(bg=boxbg, fg=fg)

    status_label.config(fg="lightgreen" if (firewall_running and dark_mode) else ("green" if firewall_running else "red"))


def toggle_dark_mode():
    global dark_mode
    dark_mode = not dark_mode
    apply_theme()


# --------------- GUI -----------------
root = tk.Tk()
root.title("Python Linux Firewall")
root.geometry("800x650")

title = tk.Label(root, text="Python Firewall", font=("Arial", 16))
title.pack(pady=10)

status_label = tk.Label(root, text="Firewall Status: STOPPED", fg="red", font=("Arial", 12))
status_label.pack(pady=5)

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Blocked IPs:").grid(row=0, column=0)
ip_entry = tk.Entry(frame, width=50)
ip_entry.grid(row=0, column=1)

tk.Label(frame, text="Blocked Ports:").grid(row=1, column=0)
port_entry = tk.Entry(frame, width=50)
port_entry.grid(row=1, column=1)

tk.Label(frame, text="Blocked Protocols:").grid(row=2, column=0)
proto_entry = tk.Entry(frame, width=50)
proto_entry.grid(row=2, column=1)

ip_entry.insert(0, " ".join(RULES["blocked_ips"]))
port_entry.insert(0, " ".join(map(str, RULES["blocked_ports"])))
proto_entry.insert(0, " ".join(RULES["blocked_protocols"]))

tk.Button(root, text="Save Rules", command=save_rules).pack(pady=5)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

tk.Button(button_frame, text="Start Firewall", width=20, command=start_firewall).grid(row=0, column=0, padx=5)
tk.Button(button_frame, text="Stop Firewall", width=20, command=stop_firewall).grid(row=0, column=1, padx=5)
tk.Button(button_frame, text="View Rules", width=20, command=view_rules).grid(row=0, column=2, padx=5)
tk.Button(button_frame, text="🌙 Dark Mode", width=20, command=toggle_dark_mode).grid(row=0, column=3, padx=5)

tk.Label(root, text="Firewall Logs:").pack()

log_box = scrolledtext.ScrolledText(root, width=95, height=22)
log_box.pack()

apply_theme()

root.mainloop()
