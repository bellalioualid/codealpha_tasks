import threading
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
from datetime import datetime

sniffing = False
packet_count = 0

def packet_analyzer(packet):
    global packet_count
    if IP in packet:
        packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Update packet counter
        counter_label.config(text=f"Packets Captured: {packet_count}")
        
        msg = f"\n{'='*60}\n"
        msg += f"[{timestamp}] Packet #{packet_count}\n"
        msg += f"{'='*60}\n"
        msg += f" Source IP      : {packet[IP].src}\n"
        msg += f" Destination IP : {packet[IP].dst}\n"

        if packet.haslayer(TCP):
            msg += f" Protocol       : TCP\n"
            msg += f"⬆  Source Port    : {packet[TCP].sport}\n"
            msg += f"⬇  Destination Port: {packet[TCP].dport}\n"
            msg += f" Flags          : {packet[TCP].flags}\n"

        elif packet.haslayer(UDP):
            msg += f" Protocol       : UDP\n"
            msg += f"⬆  Source Port    : {packet[UDP].sport}\n"
            msg += f"⬇  Destination Port: {packet[UDP].dport}\n"

        output_box.insert(tk.END, msg)
        output_box.see(tk.END)
        
        # Update status
        status_label.config(text="Status: Capturing packets...", foreground="#27ae60")

def start_sniffing():
    global sniffing
    sniffing = True
    sniff(prn=packet_analyzer, store=False,
          stop_filter=lambda x: not sniffing)

def start_thread():
    global packet_count
    packet_count = 0
    counter_label.config(text="Packets Captured: 0")
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    clear_btn.config(state="disabled")
    status_label.config(text="Status: Starting sniffer...", foreground="#f39c12")
    
    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")
    clear_btn.config(state="normal")
    output_box.insert(tk.END, f"\n\n{'='*60}\n")
    output_box.insert(tk.END, "⏸  SNIFFING STOPPED\n")
    output_box.insert(tk.END, f"{'='*60}\n\n")
    output_box.see(tk.END)
    status_label.config(text="Status: Stopped", foreground="#e74c3c")

def clear_output():
    global packet_count
    packet_count = 0
    counter_label.config(text="Packets Captured: 0")
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, "Ready to capture packets...\n")
    status_label.config(text="Status: Ready", foreground="#95a5a6")

# ---------- GUI ----------
root = tk.Tk()
root.title("Network Packet Sniffer - Enhanced Edition")
root.geometry("900x650")
root.configure(bg="#2c3e50")

# Style configuration
style = ttk.Style()
style.theme_use('clam')

# Header Frame
header_frame = tk.Frame(root, bg="#34495e", height=80)
header_frame.pack(fill=tk.X, padx=0, pady=0)
header_frame.pack_propagate(False)

title_label = tk.Label(
    header_frame, 
    text=" Network Packet Sniffer",
    font=("Segoe UI", 20, "bold"), 
    bg="#34495e", 
    fg="#ecf0f1"
)
title_label.pack(pady=20)

# Info Frame
info_frame = tk.Frame(root, bg="#2c3e50")
info_frame.pack(fill=tk.X, padx=20, pady=10)

counter_label = tk.Label(
    info_frame,
    text="Packets Captured: 0",
    font=("Segoe UI", 11, "bold"),
    bg="#2c3e50",
    fg="#3498db"
)
counter_label.pack(side=tk.LEFT, padx=10)

status_label = tk.Label(
    info_frame,
    text="Status: Ready",
    font=("Segoe UI", 11),
    bg="#2c3e50",
    fg="#95a5a6"
)
status_label.pack(side=tk.RIGHT, padx=10)

# Control Frame
control_frame = tk.Frame(root, bg="#2c3e50")
control_frame.pack(pady=15)

start_btn = tk.Button(
    control_frame,
    text=" Start Capture",
    command=start_thread,
    bg="#27ae60",
    fg="white",
    font=("Segoe UI", 11, "bold"),
    width=15,
    height=2,
    relief=tk.FLAT,
    cursor="hand2"
)
start_btn.pack(side=tk.LEFT, padx=8)

stop_btn = tk.Button(
    control_frame,
    text=" Stop Capture",
    command=stop_sniffing,
    bg="#e74c3c",
    fg="white",
    font=("Segoe UI", 11, "bold"),
    width=15,
    height=2,
    relief=tk.FLAT,
    cursor="hand2",
    state="disabled"
)
stop_btn.pack(side=tk.LEFT, padx=8)

clear_btn = tk.Button(
    control_frame,
    text="🗑 Clear Output",
    command=clear_output,
    bg="#95a5a6",
    fg="white",
    font=("Segoe UI", 11, "bold"),
    width=15,
    height=2,
    relief=tk.FLAT,
    cursor="hand2"
)
clear_btn.pack(side=tk.LEFT, padx=8)

# Output Frame
output_frame = tk.Frame(root, bg="#2c3e50")
output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

output_label = tk.Label(
    output_frame,
    text="Packet Details:",
    font=("Segoe UI", 10, "bold"),
    bg="#2c3e50",
    fg="#ecf0f1",
    anchor="w"
)
output_label.pack(anchor="w", pady=(0, 5))

output_box = ScrolledText(
    output_frame,
    width=100,
    height=20,
    bg="#1a1a1a",
    fg="#00ff00",
    font=("Consolas", 10),
    insertbackground="white",
    relief=tk.FLAT,
    borderwidth=2
)
output_box.pack(fill=tk.BOTH, expand=True)
output_box.insert(tk.END, "Ready to capture packets...\n")

# Footer
footer_label = tk.Label(
    root,
    text=" Note: Run with administrator/root privileges for full functionality",
    font=("Segoe UI", 9),
    bg="#2c3e50",
    fg="#95a5a6"
)
footer_label.pack(side=tk.BOTTOM, pady=10)

root.mainloop()