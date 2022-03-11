from scapy.all import *

NORMAL_PACKET_COUNT = 6
ATTACK_PACKET_COUNT = 10

IFACE = "eth0"


def create_normal_traffic():
    number_of_packets = NORMAL_PACKET_COUNT
    normal_packets = []

    for i in range(5):
        sIP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        dIP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        p = Ether() / IP(dst=dIP, src=sIP) / TCP(flags='S')
        normal_packets.append(p)

    for i in range(number_of_packets):
        sIP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        dIP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        p = Ether() / IP(dst=dIP, src=sIP) / TCP(flags='A')
        normal_packets.append(p)

    return normal_packets


def create_attack_traffic():
    number_of_packets = ATTACK_PACKET_COUNT
    dIP = '99.7.186.25'
    sIPs = []
    attack_packets = []

    for i in range(number_of_packets):
        sIPs.append(socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))))

    for sIP in sIPs:
        # TCP SYN Packets
        p = Ether() / IP(dst=dIP, src=sIP) / TCP(dport=5555, flags='S')

        attack_packets.append(p)

    return attack_packets


def send_packets():
    all_traffic = []

    all_traffic.extend(create_normal_traffic())
    all_traffic.extend(create_attack_traffic())
    sendp(all_traffic, iface=IFACE, verbose=3)
    return

if __name__ == "__main__":
    send_packets()
