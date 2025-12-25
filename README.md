Below is a **clean, professional GitHub README.md** you can copy-paste and use directly.
It’s written for developers, recruiters, and cybersecurity learners.

---

# 🛡️ Network Packet Sniffer (GUI) – Enhanced Edition

A **Python-based network packet sniffer** with a modern **Tkinter GUI**, built using **Scapy** for real-time packet capture and analysis.
This tool allows users to monitor live network traffic, view packet details, and control sniffing through an intuitive interface.

---

## 🚀 Features

* 📡 **Real-time packet capture**
* 🌐 Displays **Source & Destination IPs**
* 🔌 Supports **TCP & UDP protocols**
* 🔢 Shows **source/destination ports & TCP flags**
* 🕒 Timestamped packet logging
* 🧵 **Threaded sniffing** (GUI never freezes)
* 🖥️ Clean, modern **Tkinter GUI**
* 📊 Live **packet counter & status indicator**
* 🧹 Clear output with one click

---

## 🖼️ Interface Overview

* **Start Capture** – Begins packet sniffing
* **Stop Capture** – Safely stops sniffing
* **Clear Output** – Resets packet count and logs
* **Live Status Bar** – Shows current sniffer state
* **Scrollable Packet Log** – Displays packet details in real time

---

## 🧰 Technologies Used

* **Python 3**
* **Scapy** – Packet sniffing & network analysis
* **Tkinter** – GUI framework
* **Threading** – Non-blocking packet capture
* **Datetime** – Packet timestamps

---

## 📦 Installation


###  Install Dependencies

```bash
pip install scapy
```

> ⚠️ **Npcap / libpcap required**

* **Windows**: Install [Npcap](https://npcap.com/) (enable *WinPcap compatibility*)
* **Linux/macOS**: libpcap is usually preinstalled

---

## ▶️ Usage

### Run the Application

```bash
python packet_sniffer_gui.py
```

### Important

🚨 **Must run with Administrator / Root privileges**
Packet sniffing requires elevated permissions.

* **Windows**: Run Command Prompt as *Administrator*
* **Linux/macOS**:

```bash
sudo python3 packet_sniffer_gui.py
```

---

## 📋 Example Output

```
============================================================
[14:32:10] Packet #15
============================================================
 Source IP       : 192.168.1.10
 Destination IP  : 8.8.8.8
 Protocol        : TCP
 ⬆ Source Port   : 50432
 ⬇ Destination Port : 443
 Flags           : S
```

---

## 🛠️ How It Works

* Uses **Scapy’s `sniff()`** function to capture packets
* Runs sniffing in a **background thread** to keep the GUI responsive
* Parses packets for:

  * IP layer
  * TCP / UDP layers
* Updates GUI components in real time

---

## ⚠️ Disclaimer

This project is intended **for educational and ethical use only**.

* Do **NOT** use this tool on networks you do not own or have permission to monitor.
* The author is **not responsible** for misuse.

---

## 📌 Future Improvements

* 🔍 Packet filtering (by IP / protocol / port)
* 💾 Export logs to file (PCAP / TXT)
* 📈 Traffic statistics & graphs
* 🧠 Protocol detection (HTTP, DNS, HTTPS)

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License**.

---

## ⭐ Acknowledgements

* [Scapy Documentation](https://scapy.net/)
* Python & Open Source Community



