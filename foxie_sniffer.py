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
    Memproses setiap paket dan menampilkannya dalam format yang terstruktur.
    """
    global packet_count
    packet_count += 1
    
    output_lines = []
    output_lines.append(f"=============== [ Paket #{packet_count} ] ===============")

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        output_lines.append(f"  [->] IP Layer  : {ip_src} -> {ip_dst}")

        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            output_lines.append(f"    [TCP] Port    : {tcp_sport} -> {tcp_dport}")

        elif packet.haslayer(UDP):
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            output_lines.append(f"    [UDP] Port    : {udp_sport} -> {udp_dport}")
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            output_lines.append(f"    [+] Payload   : {len(payload)} bytes")
            output_lines.append(hexdump(payload, dump=True))
            
    if len(output_lines) > 1:
        print("\n".join(output_lines))


def sniff_packets(interface):
    """Memulai proses sniffing."""
    sniff(iface=interface, store=False, prn=process_packet)


def main():
    """Fungsi utama."""
    parser = argparse.ArgumentParser(description="Foxie Network Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Interface jaringan untuk di-sniff")
    args = parser.parse_args()
    display_banner()
    try:
        sniff_packets(args.interface)
    except KeyboardInterrupt:
        print("\n[INFO] Foxie Network Sniffer berhenti.")
    except Exception as e:
        print(f"[ERROR] Terjadi kesalahan: {e}")

if __name__ == "__main__":
    main()