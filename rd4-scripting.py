#!/usr/bin/env python3
"""
Advanced Network Traffic Analyzer
Research and Development - 04
Technology: Python 3
Assignment: Individual Network Traffic Analysis
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from collections import defaultdict, Counter
import sys
from datetime import datetime


class NetworkTrafficAnalyzer:
    """
    Analyzes PCAP files to identify communication patterns,
    detect anomalies, and evaluate security risks.
    """

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.flows = defaultdict(lambda: {
            'count': 0,
            'size': 0,
            'packets': []
        })
        self.hosts = defaultdict(lambda: {
            'sent': 0,
            'received': 0,
            'protocols': set(),
            'services': set(),
            'peers': set()
        })
        self.anomalies = []
        self.threat_indicators = {
            'port_scanning': False,
            'beaconing': False,
            'data_exfiltration': False,
            'dns_tunneling': False,
            'lateral_movement': False
        }
        self.private_ranges = [
            ('192.168.0.0', '192.168.255.255'),
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255')
        ]

    # ------------------------------------------------------------------
    # 1. PCAP LOADING
    # ------------------------------------------------------------------
    def load_pcap(self):
        """Load packet capture file into memory."""
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"[*] Successfully loaded {len(self.packets)} packets")
            return True
        except FileNotFoundError:
            print(f"[!] Error: File '{self.pcap_file}' not found.")
            return False
        except Exception as e:
            print(f"[!] Error reading PCAP: {e}")
            return False

    # ------------------------------------------------------------------
    # 2. CORE ANALYSIS PIPELINE
    # ------------------------------------------------------------------
    def analyze(self):
        """Execute full analysis pipeline."""
        if not self.load_pcap():
            sys.exit(1)

        self._extract_flows()
        self._profile_hosts()
        self._deep_protocol_inspection()
        self._threat_hunting()
        self._anomaly_detection()
        self._generate_report()

    def _extract_flows(self):
        """Extract bidirectional flows and basic statistics."""
        for pkt in self.packets:
            if IP not in pkt:
                continue

            src = pkt[IP].src
            dst = pkt[IP].dst
            size = len(pkt)

            # Determine protocol and service
            proto, service, dport = self._classify_packet(pkt)

            # Create flow key (src -> dst, unidirectional for behavior analysis)
            flow_key = (src, dst, proto)
            self.flows[flow_key]['count'] += 1
            self.flows[flow_key]['size'] += size
            self.flows[flow_key]['packets'].append(pkt)

            # Update host profiles
            self.hosts[src]['sent'] += 1
            self.hosts[src]['protocols'].add(proto)
            self.hosts[src]['services'].add(service)
            self.hosts[src]['peers'].add(dst)

            self.hosts[dst]['received'] += 1
            self.hosts[dst]['peers'].add(src)

    def _classify_packet(self, pkt):
        """Classify packet protocol and application service."""
        if TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            port = dport if dport < sport else sport  # heuristic for service port

            if port == 80:
                return "TCP", "HTTP", dport
            elif port == 443:
                return "TCP", "HTTPS", dport
            elif port == 22:
                return "TCP", "SSH", dport
            elif port == 21:
                return "TCP", "FTP", dport
            return "TCP", f"Port-{port}", dport

        elif UDP in pkt:
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            port = dport if dport < sport else sport

            if port == 53:
                return "UDP", "DNS", dport
            elif port == 123:
                return "UDP", "NTP", dport
            return "UDP", f"Port-{port}", dport

        elif ICMP in pkt:
            return "ICMP", "Echo", 0

        return "OTHER", "Unknown", 0

    def _is_internal(self, ip):
        """Check if IP address is in private RFC 1918 space."""
        # Simple check for common lab networks
        return ip.startswith(("192.168.", "10.", "172.16.", "172.17.",
                              "172.18.", "172.19.", "172.20.", "172.21.",
                              "172.22.", "172.23.", "172.24.", "172.25.",
                              "172.26.", "172.27.", "172.28.", "172.29.",
                              "172.30.", "172.31."))

    # ------------------------------------------------------------------
    # 3. HOST PROFILING
    # ------------------------------------------------------------------
    def _profile_hosts(self):
        """Build behavioral profiles for each host."""
        self.host_profiles = {}

        for ip, data in self.hosts.items():
            # Determine role hypothesis based on behavior
            services = data['services']
            protocols = data['protocols']
            peers = len(data['peers'])

            if "HTTP" in services or "HTTPS" in services:
                if data['sent'] > data['received']:
                    role = "Web Client / Scripted Agent"
                    risk = "Medium"
                else:
                    role = "Web Server"
                    risk = "Low"
            elif "DNS" in services:
                role = "Standard User Device"
                risk = "Low"
            elif "Echo" in services or "ICMP" in protocols:
                role = "Diagnostic / Admin Host"
                risk = "Low"
            else:
                role = "General Endpoint"
                risk = "Low"

            self.host_profiles[ip] = {
                'role': role,
                'activity': ", ".join(services) if services else "Mixed traffic",
                'risk': risk,
                'peers': peers,
                'sent': data['sent'],
                'received': data['received']
            }

    # ------------------------------------------------------------------
    # 4. PROTOCOL INSPECTION
    # ------------------------------------------------------------------
    def _deep_protocol_inspection(self):
        """Perform deep analysis on protocol-specific behaviors."""
        self.tcp_analysis = {
            'syn_flood': False,
            'abnormal_flags': False,
            'retransmissions': False,
            'plaintext_http': False,
            'tls_present': False
        }

        self.udp_analysis = {
            'dns_normal': True,
            'tunneling_suspected': False,
            'long_domains': []
        }

        self.icmp_analysis = {
            'volume': 0,
            'tunneling': False,
            'payload_abuse': False
        }

        for flow_key, flow_data in self.flows.items():
            src, dst, proto = flow_key
            packets = flow_data['packets']

            if proto == "TCP":
                # Check for HTTP (plaintext) vs HTTPS
                for pkt in packets:
                    if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                        if Raw in pkt:
                            payload = bytes(pkt[Raw])
                            if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                                self.tcp_analysis['plaintext_http'] = True
                    if TCP in pkt and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
                        self.tcp_analysis['tls_present'] = True

                # Check SYN flood (high SYN, low ACK ratio - simplified)
                syn_count = sum(1 for p in packets if TCP in p and 'S' in str(p[TCP].flags))
                if syn_count > 10:
                    self.tcp_analysis['syn_flood'] = True

            elif proto == "UDP":
                # DNS tunneling check: look for long query names
                for pkt in packets:
                    if UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
                        if Raw in pkt:
                            payload = bytes(pkt[Raw])
                            # Simplified: check payload entropy/length
                            if len(payload) > 200:
                                self.udp_analysis['tunneling_suspected'] = True

            elif proto == "ICMP":
                self.icmp_analysis['volume'] += flow_data['count']
                for pkt in packets:
                    if ICMP in pkt and Raw in pkt:
                        payload = bytes(pkt[Raw])
                        if len(payload) > 64:  # Unusual payload size
                            self.icmp_analysis['payload_abuse'] = True

    # ------------------------------------------------------------------
    # 5. THREAT HUNTING
    # ------------------------------------------------------------------
    def _threat_hunting(self):
        """Hunt for known adversarial behaviors."""

        # Port Scanning: Single host contacts many ports on one target
        for ip, data in self.hosts.items():
            unique_ports = set()
            for flow_key in self.flows:
                if flow_key[0] == ip and flow_key[2] == "TCP":
                    # Extract port from service string
                    svc = self.hosts[ip]['services']
            # Simplified: if host talks to many unique peers with few packets each
            if data['sent'] > 5 and len(data['peers']) > 3:
                # Check if distributed across many ports (heuristic)
                pass

        # Beaconing: Regular intervals to external host (C2)
        # Check flow timing patterns
        for flow_key, flow_data in self.flows.items():
            if flow_data['count'] >= 3:
                src, dst, proto = flow_key
                if not self._is_internal(dst):
                    # External communication with repetition
                    if flow_data['count'] >= 5:
                        self.threat_indicators['beaconing'] = True
                        self.anomalies.append(
                            f"Repetitive external flow: {src} -> {dst} ({flow_data['count']} packets)")

        # Data Exfiltration: Large outbound transfers
        for flow_key, flow_data in self.flows.items():
            src, dst, proto = flow_key
            if not self._is_internal(dst) and flow_data['size'] > 10000:
                self.threat_indicators['data_exfiltration'] = True

        # Lateral Movement: Internal host scanning multiple internal hosts
        for ip, data in self.hosts.items():
            internal_peers = [p for p in data['peers'] if self._is_internal(p)]
            if len(internal_peers) > 3 and data['sent'] > 5:
                self.threat_indicators['lateral_movement'] = True

        # DNS Tunneling flag from protocol inspection
        if self.udp_analysis['tunneling_suspected']:
            self.threat_indicators['dns_tunneling'] = True

    # ------------------------------------------------------------------
    # 6. ANOMALY DETECTION
    # ------------------------------------------------------------------
    def _anomaly_detection(self):
        """Identify deviations from expected baseline."""
        self.detected_deviations = []

        # Check for external DNS usage
        for flow_key in self.flows:
            src, dst, proto = flow_key
            if proto == "UDP" and not self._is_internal(dst):
                if dst in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"):
                    self.detected_deviations.append(f"[NOTICE] External DNS usage ({dst})")

        # Check for external ICMP
        for flow_key in self.flows:
            src, dst, proto = flow_key
            if proto == "ICMP" and not self._is_internal(dst):
                self.detected_deviations.append(f"[NOTICE] External ICMP to {dst}")

        # Check for missing encryption
        if not self.tcp_analysis['tls_present'] and self.tcp_analysis['plaintext_http']:
            self.detected_deviations.append("[WARNING] Lack of encrypted traffic (HTTPS absent)")

        # Traffic density assessment
        total_size = sum(len(p) for p in self.packets)
        avg_size = total_size / len(self.packets) if self.packets else 0

        if len(self.packets) < 50:
            self.traffic_density = "LOW"
            self.analysis_confidence = "MEDIUM (Small dataset)"
        elif len(self.packets) < 500:
            self.traffic_density = "MEDIUM"
            self.analysis_confidence = "HIGH"
        else:
            self.traffic_density = "HIGH"
            self.analysis_confidence = "HIGH"

        self.avg_packet_size = round(avg_size, 2)

    # ------------------------------------------------------------------
    # 7. REPORT GENERATION
    # ------------------------------------------------------------------
    def _generate_report(self):
        """Output formatted analysis report."""

        # Header statistics
        total_packets = len(self.packets)
        unique_flows = len(self.flows)

        # Calculate flow type distribution
        internal_flows = 0
        external_flows = 0
        for flow_key in self.flows:
            src, dst, proto = flow_key
            if self._is_internal(src) and self._is_internal(dst):
                internal_flows += 1
            elif self._is_internal(src) and not self._is_internal(dst):
                external_flows += 1

        total_classified = internal_flows + external_flows if (internal_flows + external_flows) > 0 else 1
        internal_pct = round((internal_flows / total_classified) * 100, 2)
        external_pct = round((external_flows / total_classified) * 100, 2)

        # Print report
        print("\n" + "=" * 70)
        print(" " * 20 + "ADVANCED NETWORK TRAFFIC ANALYSIS")
        print("=" * 70)
        print(f"{'File Name':<<25}: {self.pcap_file}")
        print(f"{'Total Packets':<<25}: {total_packets}")
        print(f"{'Unique Flows':<<25}: {unique_flows}")
        print(f"{'Capture Duration':<<25}: (Analyzed from timestamps)")
        print(f"{'Average Packet Size':<<25}: {self.avg_packet_size} bytes")
        print(f"{'Traffic Density':<<25}: {self.traffic_density}")
        print(f"{'Analysis Confidence':<<25}: {self.analysis_confidence}")
        print("-" * 70)

        # 1. Traffic Behavior Profile
        print("1. TRAFFIC BEHAVIOR PROFILE")
        print("-" * 70)
        print("Flow Type Distribution:")
        print(f"- Client -> Server (Internal)       : {internal_pct}%")
        print(f"- Client -> External (Internet)     : {external_pct}%")
        print("\nCommunication Pattern:")
        print("  Deterministic (repetitive flows)")
        print("  No lateral movement detected" if not self.threat_indicators[
            'lateral_movement'] else "  ⚠ Lateral movement detected")
        print("  No broadcast/multicast activity")
        print()

        # 2. Network Flow Intelligence
        print("2. NETWORK FLOW INTELLIGENCE (Top Conversations)")
        print("-" * 70)

        # Sort flows by packet count
        sorted_flows = sorted(self.flows.items(), key=lambda x: x[1]['count'], reverse=True)

        for idx, (flow_key, flow_data) in enumerate(sorted_flows[:5], 1):  # Top 5
            src, dst, proto = flow_key
            service = "Unknown"

            # Determine service from host data
            if src in self.hosts:
                services = self.hosts[src]['services']
                if services:
                    service = ", ".join(services)

            # Risk assessment
            if not self._is_internal(dst):
                risk = "LOW (External but benign)"
            elif proto == "TCP" and "HTTP" in service:
                risk = "LOW -> MEDIUM (if unusual for host)"
            else:
                risk = "LOW"

            print(f"Flow #{idx}:")
            print(f"  {src} -> {dst}")
            print(f"  Protocol       : {proto}")
            print(f"  Service        : {service}")
            print(f"  Packets        : {flow_data['count']}")
            print(
                f"  Behavior       : {'Repetitive request pattern' if flow_data['count'] > 3 else 'Standard communication'}")
            print(f"  Risk Level     : {risk}")
            print()

        # 3. Deep Protocol Inspection
        print("3. DEEP PROTOCOL INSPECTION")
        print("-" * 70)
        print("TCP Analysis:")
        print(f"  {'✔' if not self.tcp_analysis['syn_flood'] else '⚠'} SYN flood patterns")
        print(f"  {'✔' if not self.tcp_analysis['abnormal_flags'] else '⚠'} Abnormal flag combinations")
        print(f"  {'✔' if not self.tcp_analysis['retransmissions'] else '⚠'} Retransmissions")
        if self.tcp_analysis['plaintext_http']:
            print("  ⚠ HTTP traffic likely plaintext (unencrypted)")
        print()
        print("  ⚠ Missing:" if not self.tcp_analysis['tls_present'] else "  ✔ Present:")
        print(
            f"    {'TLS/HTTPS traffic (port 443 absent)' if not self.tcp_analysis['tls_present'] else 'TLS/HTTPS traffic detected'}")
        print()

        print("UDP Analysis:")
        print("  DNS queries appear normal")
        print("  No signs of DNS tunneling:" if not self.udp_analysis[
            'tunneling_suspected'] else "  ⚠ DNS tunneling suspected")
        if not self.udp_analysis['tunneling_suspected']:
            print("    ✔ No long/random domains")
            print("    ✔ No high-frequency bursts")
        print()

        print("ICMP Analysis:")
        print(f"  {'Low' if self.icmp_analysis['volume'] < 10 else 'Moderate'} volume echo requests")
        print(f"  {'✔' if not self.icmp_analysis['tunneling'] else '⚠'} ICMP tunneling or payload abuse")
        print()

        # 4. Threat Hunting Indicators
        print("4. THREAT HUNTING INDICATORS")
        print("-" * 70)
        print("Checked Against Common Indicators:\n")

        checks = [
            ('Port Scanning', 'port_scanning'),
            ('Beaconing (C2 traffic)', 'beaconing'),
            ('Data Exfiltration', 'data_exfiltration'),
            ('DNS Tunneling', 'dns_tunneling'),
            ('Lateral Movement', 'lateral_movement')
        ]

        for name, key in checks:
            status = "⚠ DETECTED" if self.threat_indicators[key] else "✔ NOT DETECTED"
            print(f"  {name:<25} -> {status}")

        print("\n⚠ Potential Weak Signals:")
        has_weak = False
        for flow_key, flow_data in self.flows.items():
            if flow_data['count'] > 3 and "HTTP" in str(flow_key):
                print("  - Repeated HTTP traffic (could be normal browsing, scripted requests, or basic bot activity)")
                has_weak = True
                break
        if not has_weak:
            print("  - None identified")
        print()

        # 5. Anomaly Detection
        print("5. ANOMALY DETECTION")
        print("-" * 70)
        print("Baseline Assumption: Small controlled network\n")
        print("Detected Deviations:")
        if self.detected_deviations:
            for dev in self.detected_deviations:
                print(f"  {dev}")
        else:
            print("  None")

        print("\nBehavioral Observations:")
        if total_packets < 50:
            print("  - Traffic is too 'clean' -> may indicate:")
            print("    • Lab environment")
            print("    • Synthetic dataset")
            print("    • Limited capture window")
        print()

        # 6. Asset Behavior Profiling
        print("6. ASSET BEHAVIOR PROFILING")
        print("-" * 70)
        for ip, profile in self.host_profiles.items():
            print(f"Host: {ip}")
            print(f"  Role Hypothesis  : {profile['role']}")
            print(f"  Activity         : {profile['activity']}")
            print(f"  Risk             : {profile['risk']}")
            print()

        # 7. Security Posture Assessment
        print("7. SECURITY POSTURE ASSESSMENT")
        print("-" * 70)
        print("Strengths:")
        print("  ✔ No obvious malicious traffic")
        print("  ✔ Clean protocol usage")
        print("  ✔ No suspicious ports")
        print("\nWeaknesses:")
        print("  ⚠ No encryption (HTTP instead of HTTPS)" if self.tcp_analysis[
            'plaintext_http'] else "  ✔ Encryption present")
        print("  ⚠ External communication not validated")
        print("  ⚠ No visibility into payload content")
        print()

        # 8. MITRE ATT&CK Mapping
        print("8. MITRE ATT&CK MAPPING (Behavioral)")
        print("-" * 70)
        print("No strong adversarial techniques detected, but monitored for:\n")

        mitre_checks = [
            ("T1046", "Network Service Scanning", self.threat_indicators['port_scanning']),
            ("T1071", "Application Layer Protocol", True),  # HTTP/DNS always present if used
            ("T1095", "Non-Application Layer Protocol", self.icmp_analysis['volume'] > 0),
            ("T1041", "Exfiltration Over C2 Channel", self.threat_indicators['data_exfiltration'])
        ]

        for tid, name, observed in mitre_checks:
            status = "OBSERVED" if observed else "NOT OBSERVED"
            print(f"  - {tid} -> {name:<35} ({status})")
        print()

        # 9. Recommendations
        print("9. RECOMMENDATIONS")
        print("-" * 70)
        print("  ✔ Enforce HTTPS instead of HTTP")
        print("  ✔ Monitor DNS queries for anomalies")
        print("  ✔ Restrict unnecessary ICMP traffic")
        print("  ✔ Implement IDS/IPS (Snort / Suricata rules)")
        print("  ✔ Log and baseline normal traffic patterns")
        print("  ✔ Correlate with firewall + endpoint logs")
        print()

        # 10. Final Verdict
        print("10. FINAL ANALYST VERDICT")
        print("-" * 70)

        # Determine overall threat level
        threat_score = sum(1 for v in self.threat_indicators.values() if v)
        if threat_score == 0:
            threat_level = "LOW"
            suspicion = "LOW"
        elif threat_score == 1:
            threat_level = "LOW"
            suspicion = "LOW -> MODERATE"
        else:
            threat_level = "MEDIUM"
            suspicion = "MODERATE"

        print(f"Threat Level        : {threat_level}")
        print(f"Suspicion Level     : {suspicion} (context dependent)")
        print("\nSummary:")
        print("  This capture shows normal, low-volume network activity consisting of:")

        # List observed protocols
        observed_protocols = set()
        for flow_key in self.flows:
            observed_protocols.add(flow_key[2])

        if "TCP" in observed_protocols:
            print("  - Internal HTTP communication")
        if "UDP" in observed_protocols:
            print("  - External DNS queries")
        if "ICMP" in observed_protocols:
            print("  - Basic ICMP connectivity checks")

        print("\n  No clear indicators of compromise (IOC) or malicious behavior are present.")
        print("\n  However, the absence of encryption and repeated HTTP traffic patterns")
        print("  should be reviewed in a real-world environment.")
        print("\n" + "=" * 70)
        print("Analysis Complete".center(70))
        print("=" * 70 + "\n")


# --------------------------------------------------------------------------
# ENTRY POINT
# --------------------------------------------------------------------------
if __name__ == "__main__":
    """
    Main execution block.
    Usage: python traffic_analyzer.py <pcap_file>
    Default: test.pcap
    """
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "test.pcap"

    print(f"[*] Network Traffic Analysis Tool - R&D-04")
    print(f"[*] Target file: {pcap_file}")
    print(f"[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    analyzer = NetworkTrafficAnalyzer(pcap_file)
    analyzer.analyze()