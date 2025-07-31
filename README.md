# 🦊 Foxie Network Sniffer

A simple yet powerful network sniffer tool built with Python and Scapy to capture and analyze network traffic in real-time. This project is intended for cybersecurity educational purposes.

## 🚀 Key Features

-   **Real-Time Packet Capture:** Captures network packets on a specified interface.
-   **In-Depth Analysis:** Displays crucial information such as source & destination IP addresses, protocols (TCP/UDP), and port numbers.
-   **Payload Inspection:** Shows the raw data (payload) from packets for further analysis.
-   **Easy to Use:** Simply run from the command line by specifying a network interface.
-   **Lightweight & Efficient:** Built with Scapy for optimal performance without storing packets in memory.

---

## 🛠️ Installation

To run Foxie Network Sniffer, you will need Python 3 and Scapy.

1.  **Clone this repository:**
    ```bash
    git clone https://github.com/Putra1906/Foxie-Sniffer.git
    cd Foxie-Sniffer
    ```

2.  **Install the required dependency (Scapy):**
    ```bash
    pip install scapy
    ```

---

## ⚙️ Usage

This tool must be run with root/administrator privileges to access network interfaces.

1.  **Find your network interface name:**
    -   **On Linux/macOS:** `ifconfig` or `ip a` (e.g., `eth0`, `en0`, `wlan0`)
    -   **On Windows:** `ipconfig` (e.g., `Ethernet`, `Wi-Fi`)

2.  **Run the sniffer with `sudo`:**
    ```bash
    sudo python3 foxie_sniffer.py --interface [your_interface_name]
    ```
    **Example:**
    ```bash
    sudo python3 foxie_sniffer.py --interface eth0
    ```

3.  To stop the program, press **Ctrl + C**.

---

## ⚠️ Disclaimer

**This tool is created for learning and educational purposes in the field of network security.** Using this tool to monitor a network that you do not own without explicit permission is illegal and unethical. The author is not responsible for any misuse or damage caused by this program. Use it wisely and responsibly.

---

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file for more details.