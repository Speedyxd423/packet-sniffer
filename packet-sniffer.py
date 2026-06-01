from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style, init

init()

port_names = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    8080: "HTTP-Alt",
    67: "DHCP",
    68: "DHCP",
    123: "NTP"
}

packet_count = 0
def banner():
    print(Fore.CYAN + """
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "          Packet Sniffer  |  For authorised use only\n" + Style.RESET_ALL)

def process_packet(packet):
    global packet_count
    global log_file
    packet_count += 1
    if IP in packet:
        src = packet[IP].src  # where packet came from
        dst = packet[IP].dst  # where packet is going

        print(Fore.YELLOW + f"[{packet_count}] " + Style.RESET_ALL, end="")

        if TCP in packet:
            port = packet[TCP].dport
            service = port_names.get(port, "Unknown")
            print(Fore.GREEN + "TCP" + Style.RESET_ALL + f" | {src} → {dst} | Port {port} (" + Fore.CYAN + f"{service}" + Style.RESET_ALL + ")")
            log_file.write(f"TCP | {src} → {dst} | Port {port} ({service})\n")
        elif UDP in packet:
            port = packet[UDP].dport
            service = port_names.get(port, "Unknown")
            print(Fore.MAGENTA + "UDP" + Style.RESET_ALL + f" | {src} → {dst} | Port {port} (" + Fore.CYAN + f"{service}" + Style.RESET_ALL + ")")
            log_file.write(f"UDP | {src} → {dst} | Port {port} ({service})\n")
banner()
print(Fore.YELLOW + "[*] " + Style.RESET_ALL + "Filter options: udp, tcp, tcp and port 443, icmp, tcp or udp")
print(Fore.YELLOW + "[*] " + Style.RESET_ALL + "Filter: ", end="")

filename = f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
log_file = open(filename, "w")

filters = input().strip()

print(Fore.YELLOW + f"\n[*] Starting sniffer with filter: '{filters}'\n" + Style.RESET_ALL)

sniff(prn=process_packet, filter=filters if filters else None, store=False)
log_file.close()