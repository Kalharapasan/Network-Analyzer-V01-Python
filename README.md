
# 📡 Network Traffic Analyzer

**Network Traffic Analyzer** is a Python-based GUI application that allows users to view and analyze network information and traffic in real-time.

![image](https://github.com/user-attachments/assets/c6aafb6f-4aba-464c-a04d-581cb3853154)


---

## 🛠️ Technologies Used

- **Python 3**
- **Tkinter** – for GUI
- **psutil** – for accessing system/network stats
- **socket**, **threading**, **datetime**, **subprocess**, **platform** – for network/system operations

---

## 📦 Installation

```bash
git clone https://github.com/Kalharapasan/Network-Analyzer-V01-Python.git
cd Network-Analyzer-V01-Python
pip install psutil
python main.py
```

> **Note:** If `psutil` is not installed: `pip install psutil`

---

## 🧪 Features

### 🔹 Network Info Tab:
- Lists active network interfaces
- Displays IP/MAC addresses
- Shows system CPU/Memory usage and network I/O

### 🔹 Traffic Monitor Tab:
- Real-time bytes in/out
- Live connection count
- Scrollable log view

### 🔹 Active Connections Tab:
- Displays current TCP/UDP connections
- Shows local/remote addresses, protocol, and PID

### 🔹 Statistics Tab:
- Protocol usage statistics
- Top IPs based on traffic volume

---

## ▶️ How to Use

1. Click the **Start Monitoring** button to begin
2. Navigate through tabs to explore network data
3. Use **Clear Logs** to reset logs and stats

---

## 🔐 Requirements

- **Administrator Privileges**: Needed for full functionality (e.g., raw sockets)
- **Cross-platform**: Works on both Windows and Linux

---

## 📸 GUI Preview (Optional)

> You can add a GUI screenshot here: `images/screenshot.png`

---

## 👨‍💻 Author

Developed by P.R.P.S.Kalhara 
GitHub: [https://github.com/Kalharapasan](https://github.com/Kalharapasan)

---

## 📄 License

📄 [License](./LICENSE.md): Proprietary – Permission Required

---

## 📌 Notes

- This is a basic network analyzer for learning and monitoring purposes.
- It does not use advanced packet capturing libraries like `scapy` or `pyshark`.
