import argparse
from scapy.all import *

def display_banner():
    """Menampilkan banner ASCII art untuk Foxie Network Sniffer."""
    print("======================================================")
    print(r"""
FFFFFFFFFFFFFFFFFFFFFF     OOOOOOOOO      XXXXXXX       XXXXXXX IIIIIIIIII EEEEEEEEEEEEEEEEEEEEEE
F::::::::::::::::::::F   OO:::::::::OO    X:::::X       X:::::X I::::::::I E::::::::::::::::::::E
F::::::::::::::::::::F OO:::::::::::::OO  X:::::X       X:::::X I::::::::I E::::::::::::::::::::E
FF::::::FFFFFFFFF::::F O:::::::OOO::::::O X::::::X     X::::::X II::::::II EE::::::EEEEEEEEE::::E
  F:::::F       FFFFFF O::::::O   O:::::O XXX:::::X   X:::::XXX   I::::I    E:::::E       EEEEEE
  F:::::F              O:::::O     O::::O   X:::::X X:::::X       I::::I    E:::::E             
  F::::::FFFFFFFFFF    O:::::O     O::::O    X:::::X:::::X        I::::I    E::::::EEEEEEEEEE   
  F:::::::::::::::F    O:::::O     O::::O     X:::::::::X         I::::I    E:::::::::::::::E   
  F:::::::::::::::F    O:::::O     O::::O     X:::::::::X         I::::I    E:::::::::::::::E   
  F::::::FFFFFFFFFF    O:::::O     O::::O    X:::::X:::::X        I::::I    E::::::EEEEEEEEEE   
  F:::::F              O:::::O     O::::O   X:::::X X:::::X       I::::I    E:::::E             
  F:::::F              O::::::O   O:::::O XXX:::::X   X:::::XXX   I::::I    E:::::E       EEEEEE
FF:::::::FF            O:::::::OOO::::::O X::::::X     X::::::X II::::::II EE::::::EEEEEEEE:::::E
F::::::::FF             OO::::::::::::OO  X:::::X       X:::::X I::::::::I E::::::::::::::::::::E
F::::::::FF               OO::::::::OO    X:::::X       X:::::X I::::::::I E::::::::::::::::::::E
FFFFFFFFFFF                 OOOOOOOO      XXXXXXX       XXXXXXX IIIIIIIIII EEEEEEEEEEEEEEEEEEEEEE
          
                                    
                                    NETWORK SNIFFER
    """)
    print("======================================================")
    print("Menunggu paket... Tekan Ctrl+C untuk berhenti.\n")

def process_packet(packet):
    """
    Fungsi ini dipanggil untuk setiap paket yang ditangkap.
    Menganalisis dan menampilkan informasi dari paket.
    """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"[IP Packet] Sumber: {ip_src} -> Tujuan: {ip_dst} | Protokol: {protocol}")

        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"  [TCP] Port: {tcp_sport} -> {tcp_dport}")
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    print(f"    [+] Payload:\n{payload[:150]}") 
                    print("-" * 30)
                except:
                    print("    [+] Payload: [Data tidak dapat di-decode]")

        elif packet.haslayer(UDP):
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"  [UDP] Port: {udp_sport} -> {udp_dport}")
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    print(f"    [+] Payload:\n{payload[:150]}")
                    print("-" * 30)
                except:
                    print("    [+] Payload: [Data tidak dapat di-decode]")

def sniff_packets(interface):
    """
    Memulai proses sniffing pada interface yang ditentukan.
    """
    sniff(iface=interface, store=False, prn=process_packet)


def main():
    """Fungsi utama untuk menjalankan program."""
    parser = argparse.ArgumentParser(description="Foxie Network Sniffer - Alat untuk menangkap dan menganalisis paket jaringan.")
    parser.add_argument("-i", "--interface", required=True, help="Interface jaringan untuk di-sniff (contoh: eth0, wlan0)")
    args = parser.parse_args()

    display_banner()

    try:
        sniff_packets(args.interface)
    except Exception as e:
        print(f"[ERROR] Terjadi kesalahan: {e}")
    except KeyboardInterrupt:
        print("\n[INFO] Foxie Network Sniffer berhenti. Sampai jumpa!")

if __name__ == "__main__":
    main()