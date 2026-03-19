#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Outil de scan reseau a but éthique et professionnel a utiliser uniquement avec accord du propriétaire du réseau.
# Code par Mr.Dark(moi). Ce script fait environ 217 lignes de code Python.

"""
╔══════════════════════════════════════════════════════════════╗
║  🚀 WiFi Network Scanner PRO v3.0 - Outils pour le recon     ║
║  🔍 Auto-détection + Scan ports + JSON + Couleurs PRO        ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import time
import json
import sys
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# ANSI Colors PRO
class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; PURPLE = '\033[95m'; CYAN = '\033[96m'
    WHITE = '\033[97m'; BOLD = '\033[1m'; END = '\033[0m'

def bannière():
    print(f"""
{Colors.PURPLE}{Colors.BOLD}
   ____     _        ____     _       ____    
U /"___|U  /"\  u U /"___|U  /"\  u U|  _"\ u 
\| | u   \/ _ \/  \| | u   \/ _ \/  \| |_) |/ 
 | |/__  / ___ \   | |/__  / ___ \   |  __/   
  \____|/_/   \_\   \____|/_/   \_\  |_|      
 _// \\  \\    >>  _// \\  \\    >>  ||>>_    
(__)(__)(__)  (__)(__)(__)(__)  (__)(__)__)   
{Colors.CYAN}👤 crée par Mr.Dark | 📅 {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}
    """)

def obtenir_les_réseaux_communs():
    """Réseaux WiFi courants"""
    return [
        '192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24',
        '172.16.0.0/24', '192.168.8.0/24', '192.168.100.0/24'
    ]

class Capcap:
    def __init__(self):
        self.network = None
        self.active_hosts = []
        self.vulnerable_hosts = {}
        self.ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        self.services = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 3306: 'MySQL'}

    def detecteur_reseau(self):
        print(f"{Colors.YELLOW}{Colors.BOLD}[1/4] DÉTECTION RÉSEAU{Colors.END}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            sock.close()
            network = '.'.join(ip.split('.')[:-1]) + '.0/24'
            print(f"{Colors.GREEN}✅ IP locale: {Colors.BOLD}{ip}{Colors.END}")
            print(f"{Colors.GREEN}✅ Réseau: {Colors.BOLD}{network}{Colors.END}")
            return network
        except Exception:
            return None

    def demande_reseau(self):
        print(f"\n{Colors.RED}❌ Détection auto échouée{Colors.END}")
        common_nets = obtenir_les_réseaux_communs()
        print(f"{Colors.CYAN}Réseaux WiFi courants:{Colors.END}")
        for i, net in enumerate(common_nets, 1):
            print(f"  {i}. {Colors.BOLD}{net}{Colors.END}")
        print(f"  0. Saisir manuellement")

        while True:
            try:
                choice = input(f"\n{Colors.YELLOW}Choisissez (0-{len(common_nets)}): {Colors.END}").strip()
                if choice == '0':
                    net = input(f"{Colors.CYAN}Entrez votre réseau (ex: 192.168.1.0/24): {Colors.END}").strip()
                else:
                    net = common_nets[int(choice)-1]
                ipaddress.ip_network(net, strict=False)
                print(f"{Colors.GREEN}✅ Réseau sélectionné: {Colors.BOLD}{net}{Colors.END}")
                return net
            except (ValueError, IndexError):
                print(f"{Colors.RED}❌ Format invalide ! ex: 192.168.1.0/24{Colors.END}")

    def ping_rapide(self, ip):
        """Ping ultra-rapide multi-ports"""
        test_ports = [80, 443, 22]
        for port in test_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                if s.connect_ex((str(ip), port)) == 0:
                    s.close()
                    return True
            except Exception:
                pass
        return False

    def scan_hosts(self, network):
        print(f"\n{Colors.BLUE}{Colors.BOLD}[2/4] DÉCOUVERTE HÔTES ({network}){Colors.END}")
        net = ipaddress.ip_network(network, strict=False)
        print(f"{Colors.WHITE}📡 {int(net.num_addresses):,} IPs à scanner...{Colors.END}")

        active = []
        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(self.ping_rapide, host): host for host in net.hosts()}
            total = len(futures)
            
            for i, future in enumerate(futures, 1):
                if i % 100 == 0 or i == total:
                    print(f"{Colors.YELLOW}\r⏳ {i}/{total} ({i/total*100:.0f}%)...{Colors.END}", end='')
                
                try:
                    if future.result():
                        ip = str(futures[future])
                        active.append(ip)
                        print(f"\n{Colors.GREEN}✅{Colors.END} {Colors.BOLD}{ip}{Colors.END}")
                except Exception:
                    pass

        self.active_hosts = active
        print(f"\n{Colors.BOLD}🎉 {Colors.GREEN}{len(active)}{Colors.END} hôtes actifs détectés !")
        return len(active) > 0

    def check_port(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            result = s.connect_ex((ip, port))
            s.close()
            return result == 0
        except Exception:
            return False

    def scan_de_ports(self, ip):
        """Scan de ports complet"""
        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.check_port, ip, port): port for port in self.ports}
            for future in futures:
                try:
                    if future.result():
                        open_ports.append(futures[future])
                except Exception:
                    pass
        return open_ports

    def deep_scan(self):
        print(f"\n{Colors.PURPLE}{Colors.BOLD}[3/4] SCAN PORTS PROFOND{Colors.END}")
        print(f"{Colors.WHITE}🎯 Analyse {len(self.active_hosts)} cibles...{Colors.END}")

        for i, ip in enumerate(self.active_hosts, 1):
            print(f"  {Colors.CYAN}[{i:2d}/{len(self.active_hosts)}]{Colors.END} {ip}", end=' ')
            ports = self.scan_de_ports(ip)

            if ports:
                self.vulnerable_hosts[ip] = ports
                services = ', '.join([f"{p}({self.services.get(p,'?')})" for p in ports])
                print(f"{Colors.RED}🚨{Colors.END} {Colors.BOLD}{len(ports)} ports: {services}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}🔒{Colors.END}")

        print(f"\n{Colors.BOLD}🎯 {Colors.RED}{len(self.vulnerable_hosts)}{Colors.END} cibles Potentiel !")

    def show_report(self):
        print(f"\n{Colors.GREEN}{Colors.BOLD}[4/4] RAPPORT FINAL{Colors.END}")
        print(f"{Colors.BOLD}{'═'*74}{Colors.END}")
        print(f"{Colors.CYAN}📊 STATISTIQUES{Colors.END}".center(74))
        print(f"{Colors.BOLD}{'═'*74}{Colors.END}")
        print(f"   🌐 Réseau: {Colors.BOLD}{self.network}{Colors.END}")
        print(f"   👥 Hôtes actifs: {Colors.GREEN}{len(self.active_hosts)}{Colors.END}")
        print(f"   🚨 Cibles Potentiellement vulnerables: {Colors.RED}{len(self.vulnerable_hosts)}{Colors.END}")

        if self.vulnerable_hosts:
            print(f"\n{Colors.RED}{Colors.BOLD}🎯 TOP CIBLES (Ports ouverts):{Colors.END}")
            print(f"{Colors.BOLD}─{'─'*72}─{Colors.END}")
            for ip, ports in sorted(self.vulnerable_hosts.items(), key=lambda x: len(x[1]), reverse=True):
                services = ', '.join([f"{p}({self.services.get(p,'?')})" for p in ports])
                print(f"{Colors.RED}🚨{Colors.END} {Colors.BOLD}{ip:15}{Colors.END} {Colors.RED}»{Colors.END} {services}")

    def enregistrement_json(self):
        data = {
            'network': self.network,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'active_hosts': self.active_hosts,
            'vulnerable_hosts': self.vulnerable_hosts
        }
        filename = f"WiFiScan_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\n{Colors.GREEN}💾{Colors.END} {Colors.BOLD}{filename}{Colors.END} sauvegardé !")

    def run(self):
        bannière()

        # Détection ou saisie réseau
        network = self.detecteur_reseau()
        if not network:
            network = self.demande_reseau()

        self.network = network

        # Scan complet
        if self.scan_hosts(network):
            self.deep_scan()
            self.show_report()
            self.enregistrement_json()
            print(f"\n{Colors.GREEN}{Colors.BOLD}✨ SCAN TERMINÉ - Bonne chasse ! 👊{Colors.END}")
        else:
            print(f"{Colors.RED}{Colors.BOLD}❌ Aucun hôte trouvé sur ce réseau{Colors.END}")

if __name__ == "__main__":
    Capcap().run()
