"""
Traffic Generator Module.
Generates high-fidelity, realistic enterprise network telemetry modeling both
benign operational baselines and multi-stage APT attack progressions across MITRE ATT&CK stages.
Can export to CSV flow logs and raw PCAP captures.
"""

import os
import random
import numpy as np
import pandas as pd
from typing import Optional, List, Dict
from src.config import RAW_FLOW_FEATURES


class TrafficGenerator:
    """
    Generates synthetic enterprise traffic scenarios with realistic temporal dynamics.
    Accurately simulates:
    - Benign operational baselines (web, dns, internal shares)
    - MITRE ATT&CK stages: Recon -> Initial Access -> Lateral Movement -> C2 -> Exfiltration
    """

    def __init__(self, seed: int = 42):
        random.seed(seed)
        np.random.seed(seed)

    def generate_scenario(
        self,
        duration_seconds: int = 300,
        flows_per_second: float = 8.0,
        attack_start_time: int = 60,
        include_all_stages: bool = True
    ) -> pd.DataFrame:
        """
        Generates a chronological sequence of network flows reflecting an unfolding intrusion.
        """
        rows = []
        current_time = 1710000000.0  # Reference epoch timestamp

        # Enterprise host pools
        internal_hosts = [f"10.0.1.{i}" for i in range(10, 30)]
        internal_servers = ["10.0.2.10", "10.0.2.20", "10.0.2.50"]  # Web, DB, Domain Controller
        external_web_servers = ["93.184.216.34", "151.101.1.69", "142.250.190.46"]
        external_dns_servers = ["8.8.8.8", "1.1.1.1"]
        external_attacker_ip = "198.51.100.77"
        c2_server_ip = "203.0.113.99"

        compromised_host = "10.0.1.15"
        high_value_target = "10.0.2.50"  # Core Database / DC

        # Time checkpoints for attack stages (if attack starts at t = 60s)
        # Stage 1: Recon (60s - 110s)
        # Stage 2: Initial Access (110s - 160s)
        # Stage 3: Lateral Movement (160s - 210s)
        # Stage 4: C2 Beaconing (210s - 255s)
        # Stage 5: Exfiltration (255s - 300s)
        t_stage1 = attack_start_time
        t_stage2 = attack_start_time + 50
        t_stage3 = attack_start_time + 100
        t_stage4 = attack_start_time + 150
        t_stage5 = attack_start_time + 195

        total_steps = int(duration_seconds * flows_per_second)
        time_increments = np.random.exponential(scale=1.0 / flows_per_second, size=total_steps)

        for step in range(total_steps):
            elapsed = sum(time_increments[:step]) if step > 0 else 0.0
            t_now = current_time + elapsed
            if elapsed > duration_seconds:
                break

            # Determine whether this flow is benign or part of the attack
            stage = 0
            if include_all_stages and elapsed >= t_stage1:
                if elapsed < t_stage2:
                    stage = 1  # Reconnaissance
                elif elapsed < t_stage3:
                    stage = 2  # Initial Access
                elif elapsed < t_stage4:
                    stage = 3  # Lateral Movement
                elif elapsed < t_stage5:
                    stage = 4  # C2 Beaconing
                else:
                    stage = 5  # Exfiltration

            # Generate flow characteristics based on stage
            if stage == 0 or (stage > 0 and random.random() < 0.35):
                # Benign background enterprise flow
                flow = self._generate_benign_flow(
                    t_now, internal_hosts, internal_servers,
                    external_web_servers, external_dns_servers
                )
            elif stage == 1:
                # Stage 1: Reconnaissance (External port scan / service discovery)
                flow = self._generate_recon_flow(
                    t_now, external_attacker_ip, internal_servers
                )
            elif stage == 2:
                # Stage 2: Initial Access (Exploit delivery & brute force on web/ssh)
                flow = self._generate_initial_access_flow(
                    t_now, external_attacker_ip, compromised_host
                )
            elif stage == 3:
                # Stage 3: Lateral Movement (Internal SMB/RPC probing and pivoting)
                flow = self._generate_lateral_movement_flow(
                    t_now, compromised_host, internal_hosts, high_value_target
                )
            elif stage == 4:
                # Stage 4: Command & Control (Heartbeat beaconing to external drop)
                flow = self._generate_c2_flow(
                    t_now, compromised_host, c2_server_ip
                )
            elif stage == 5:
                # Stage 5: Exfiltration (Heavy encrypted outbound transfer)
                flow = self._generate_exfil_flow(
                    t_now, high_value_target, c2_server_ip
                )

            rows.append(flow)

        df = pd.DataFrame(rows)
        return df

    def _generate_benign_flow(
        self, t_now, internal_hosts, internal_servers,
        external_web_servers, external_dns_servers
    ) -> Dict:
        traffic_type = random.choice(["web", "dns", "internal_rpc", "idle_keepalive"])
        src_ip = random.choice(internal_hosts)
        
        if traffic_type == "web":
            dst_ip = random.choice(external_web_servers)
            dst_port = random.choice([80, 443])
            protocol = 6
            duration = random.uniform(0.1, 4.5)
            fwd_pkts = random.randint(5, 30)
            bwd_pkts = random.randint(8, 45)
            fwd_bytes = fwd_pkts * random.randint(64, 400)
            bwd_bytes = bwd_pkts * random.randint(400, 1460)
            flags = {"syn": 1, "ack": 1, "fin": 1, "rst": 0, "psh": random.randint(1, 4), "urg": 0}
            iat_mean = random.uniform(15.0, 60.0)
            ttl_mean = random.choice([64.0, 128.0])
        elif traffic_type == "dns":
            dst_ip = random.choice(external_dns_servers)
            dst_port = 53
            protocol = 17
            duration = random.uniform(0.01, 0.08)
            fwd_pkts = 1
            bwd_pkts = 1
            fwd_bytes = random.randint(45, 90)
            bwd_bytes = random.randint(90, 250)
            flags = {"syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0}
            iat_mean = 5.0
            ttl_mean = 56.0
        elif traffic_type == "internal_rpc":
            dst_ip = random.choice(internal_servers)
            dst_port = random.choice([445, 135, 8080])
            protocol = 6
            duration = random.uniform(0.5, 8.0)
            fwd_pkts = random.randint(10, 50)
            bwd_pkts = random.randint(10, 50)
            fwd_bytes = fwd_pkts * random.randint(100, 800)
            bwd_bytes = bwd_pkts * random.randint(200, 1200)
            flags = {"syn": 1, "ack": 1, "fin": 0, "rst": 0, "psh": 2, "urg": 0}
            iat_mean = random.uniform(20.0, 80.0)
            ttl_mean = 128.0
        else:
            dst_ip = random.choice(internal_servers)
            dst_port = 443
            protocol = 6
            duration = random.uniform(1.0, 15.0)
            fwd_pkts = 2
            bwd_pkts = 2
            fwd_bytes = 128
            bwd_bytes = 128
            flags = {"syn": 0, "ack": 1, "fin": 0, "rst": 0, "psh": 0, "urg": 0}
            iat_mean = 200.0
            ttl_mean = 64.0

        return {
            "timestamp": t_now,
            "src_ip": src_ip,
            "src_port": random.randint(49152, 65535),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "flow_duration": duration,
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "total_packets": fwd_pkts + bwd_pkts,
            "total_bytes": fwd_bytes + bwd_bytes,
            "bytes_bwd_fwd_ratio": float(bwd_bytes) / (float(fwd_bytes) + 1.0),
            "packets_bwd_fwd_ratio": float(bwd_pkts) / (float(fwd_pkts) + 1.0),
            "flag_syn": flags["syn"],
            "flag_ack": flags["ack"],
            "flag_fin": flags["fin"],
            "flag_rst": flags["rst"],
            "flag_psh": flags["psh"],
            "flag_urg": flags["urg"],
            "flow_iat_mean": iat_mean,
            "flow_iat_std": iat_mean * 0.4,
            "flow_iat_max": iat_mean * 2.5,
            "ttl_mean": ttl_mean,
            "ttl_var": random.uniform(0.0, 0.5),
            "tcp_window_mean": 64240.0,
            "retransmissions": random.choice([0, 0, 0, 1]),
            "attack_stage": 0
        }

    def _generate_recon_flow(self, t_now, attacker_ip, internal_servers) -> Dict:
        """Stage 1: Reconnaissance (SYN scan, rapid port probing, high RST)"""
        probed_port = random.choice([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 9200])
        target_ip = random.choice(internal_servers)
        port_open = probed_port in [80, 443, 8080]

        duration = random.uniform(0.001, 0.05)
        fwd_pkts = 1
        bwd_pkts = 1 if port_open else 0
        fwd_bytes = 60
        bwd_bytes = 60 if port_open else 0

        flags = {
            "syn": 1,
            "ack": 1 if port_open else 0,
            "fin": 0,
            "rst": 0 if port_open else 1,
            "psh": 0,
            "urg": 0
        }

        return {
            "timestamp": t_now,
            "src_ip": attacker_ip,
            "src_port": random.randint(30000, 60000),
            "dst_ip": target_ip,
            "dst_port": probed_port,
            "protocol": 6,
            "flow_duration": duration,
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "total_packets": fwd_pkts + bwd_pkts,
            "total_bytes": fwd_bytes + bwd_bytes,
            "bytes_bwd_fwd_ratio": float(bwd_bytes) / (float(fwd_bytes) + 1.0),
            "packets_bwd_fwd_ratio": float(bwd_pkts) / (float(fwd_pkts) + 1.0),
            "flag_syn": flags["syn"],
            "flag_ack": flags["ack"],
            "flag_fin": flags["fin"],
            "flag_rst": flags["rst"],
            "flag_psh": flags["psh"],
            "flag_urg": flags["urg"],
            "flow_iat_mean": random.uniform(1.0, 8.0),  # Very tight scan timing
            "flow_iat_std": 0.5,
            "flow_iat_max": 12.0,
            "ttl_mean": 48.0,  # External hop count
            "ttl_var": 0.0,
            "tcp_window_mean": 1024.0,  # Scanner synthetic stack window
            "retransmissions": random.choice([0, 1]),
            "attack_stage": 1
        }

    def _generate_initial_access_flow(self, t_now, attacker_ip, target_host) -> Dict:
        """Stage 2: Initial Access (Brute force bursts, web exploit payloads)"""
        duration = random.uniform(0.08, 0.4)
        fwd_pkts = random.randint(8, 25)
        bwd_pkts = random.randint(6, 20)
        fwd_bytes = fwd_pkts * random.randint(250, 850)  # Exploit payload chunks
        bwd_bytes = bwd_pkts * random.randint(120, 400)

        return {
            "timestamp": t_now,
            "src_ip": attacker_ip,
            "src_port": random.randint(40000, 50000),
            "dst_ip": target_host,
            "dst_port": 8080,
            "protocol": 6,
            "flow_duration": duration,
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "total_packets": fwd_pkts + bwd_pkts,
            "total_bytes": fwd_bytes + bwd_bytes,
            "bytes_bwd_fwd_ratio": float(bwd_bytes) / (float(fwd_bytes) + 1.0),
            "packets_bwd_fwd_ratio": float(bwd_pkts) / (float(fwd_pkts) + 1.0),
            "flag_syn": 1,
            "flag_ack": 1,
            "flag_fin": 0,
            "flag_rst": 0,
            "flag_psh": random.randint(4, 10),  # High PSH delivery
            "flag_urg": 0,
            "flow_iat_mean": random.uniform(5.0, 18.0),
            "flow_iat_std": 3.0,
            "flow_iat_max": 35.0,
            "ttl_mean": 48.0,
            "ttl_var": 0.8,
            "tcp_window_mean": 32120.0,
            "retransmissions": 2,
            "attack_stage": 2
        }

    def _generate_lateral_movement_flow(
        self, t_now, compromised_host, internal_hosts, high_value_target
    ) -> Dict:
        """Stage 3: Lateral Movement (East-west internal pivoting, SMB/RPC probes)"""
        dst_ip = random.choice([high_value_target, random.choice(internal_hosts)])
        dst_port = random.choice([445, 135, 3389, 5985])  # SMB, RPC, RDP, WinRM
        duration = random.uniform(0.1, 1.2)
        fwd_pkts = random.randint(6, 18)
        bwd_pkts = random.randint(6, 18)
        fwd_bytes = fwd_pkts * random.randint(180, 500)
        bwd_bytes = bwd_pkts * random.randint(150, 450)

        return {
            "timestamp": t_now,
            "src_ip": compromised_host,
            "src_port": random.randint(49152, 65535),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": 6,
            "flow_duration": duration,
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "total_packets": fwd_pkts + bwd_pkts,
            "total_bytes": fwd_bytes + bwd_bytes,
            "bytes_bwd_fwd_ratio": float(bwd_bytes) / (float(fwd_bytes) + 1.0),
            "packets_bwd_fwd_ratio": float(bwd_pkts) / (float(fwd_pkts) + 1.0),
            "flag_syn": 1,
            "flag_ack": 1,
            "flag_fin": 0,
            "flag_rst": 0,
            "flag_psh": random.randint(2, 6),
            "flag_urg": 0,
            "flow_iat_mean": random.uniform(10.0, 30.0),
            "flow_iat_std": 4.0,
            "flow_iat_max": 45.0,
            "ttl_mean": 128.0,  # Windows LAN default
            "ttl_var": 0.0,
            "tcp_window_mean": 64240.0,
            "retransmissions": 0,
            "attack_stage": 3
        }

    def _generate_c2_flow(self, t_now, compromised_host, c2_ip) -> Dict:
        """Stage 4: Command & Control (Periodic heartbeat beacons with jitter)"""
        duration = random.uniform(0.05, 0.2)
        fwd_pkts = random.randint(3, 6)
        bwd_pkts = random.randint(3, 6)
        fwd_bytes = fwd_pkts * 90  # Encrypted check-in payload
        bwd_bytes = bwd_pkts * 80  # Sleep command response

        return {
            "timestamp": t_now,
            "src_ip": compromised_host,
            "src_port": random.randint(50000, 60000),
            "dst_ip": c2_ip,
            "dst_port": 443,  # Encrypted HTTPS masquerade
            "protocol": 6,
            "flow_duration": duration,
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "total_packets": fwd_pkts + bwd_pkts,
            "total_bytes": fwd_bytes + bwd_bytes,
            "bytes_bwd_fwd_ratio": float(bwd_bytes) / (float(fwd_bytes) + 1.0),
            "packets_bwd_fwd_ratio": float(bwd_pkts) / (float(fwd_pkts) + 1.0),
            "flag_syn": 0,
            "flag_ack": 1,
            "flag_fin": 0,
            "flag_rst": 0,
            "flag_psh": 2,
            "flag_urg": 0,
            "flow_iat_mean": 10000.0,  # 10 second regular interval
            "flow_iat_std": 500.0,     # Small jitter
            "flow_iat_max": 10800.0,
            "ttl_mean": 128.0,
            "ttl_var": 0.0,
            "tcp_window_mean": 65535.0,
            "retransmissions": 0,
            "attack_stage": 4
        }

    def _generate_exfil_flow(self, t_now, staged_host, c2_ip) -> Dict:
        """Stage 5: Exfiltration (Heavy volumetric egress transfer)"""
        duration = random.uniform(2.0, 8.0)
        fwd_pkts = random.randint(150, 500)
        bwd_pkts = random.randint(20, 60)
        fwd_bytes = fwd_pkts * 1440  # Maximum Segment Size egress bulk
        bwd_bytes = bwd_pkts * 64    # ACKs

        return {
            "timestamp": t_now,
            "src_ip": staged_host,
            "src_port": random.randint(50000, 60000),
            "dst_ip": c2_ip,
            "dst_port": 443,
            "protocol": 6,
            "flow_duration": duration,
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "total_packets": fwd_pkts + bwd_pkts,
            "total_bytes": fwd_bytes + bwd_bytes,
            "bytes_bwd_fwd_ratio": float(bwd_bytes) / (float(fwd_bytes) + 1.0),
            "packets_bwd_fwd_ratio": float(bwd_pkts) / (float(fwd_pkts) + 1.0),
            "flag_syn": 0,
            "flag_ack": 1,
            "flag_fin": 0,
            "flag_rst": 0,
            "flag_psh": random.randint(20, 60),
            "flag_urg": 0,
            "flow_iat_mean": random.uniform(1.0, 4.0),
            "flow_iat_std": 0.8,
            "flow_iat_max": 8.0,
            "ttl_mean": 128.0,
            "ttl_var": 0.0,
            "tcp_window_mean": 65535.0,
            "retransmissions": random.randint(1, 5),
            "attack_stage": 5
        }

    def export_pcap(self, df_flows: pd.DataFrame, output_pcap_path: str, max_packets: int = 500):
        """
        Synthesizes an authentic Scapy PCAP capture file from generated flow records.
        """
        try:
            from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
        except ImportError:
            return

        packets = []
        for _, row in df_flows.head(max_packets).iterrows():
            t = float(row["timestamp"])
            src_ip = str(row["src_ip"])
            dst_ip = str(row["dst_ip"])
            sport = int(row["src_port"])
            dport = int(row["dst_port"])
            proto = int(row["protocol"])

            ip_layer = IP(src=src_ip, dst=dst_ip, proto=proto, ttl=int(row["ttl_mean"]))
            ip_layer.time = t

            if proto == 6:  # TCP
                flags = ""
                if row["flag_syn"]: flags += "S"
                if row["flag_ack"]: flags += "A"
                if row["flag_fin"]: flags += "F"
                if row["flag_rst"]: flags += "R"
                if row["flag_psh"]: flags += "P"
                if not flags: flags = "A"

                tcp_layer = TCP(sport=sport, dport=dport, flags=flags, window=int(row["tcp_window_mean"]))
                payload = Raw(load=b"X" * min(int(row["fwd_bytes"] / max(row["fwd_packets"], 1)), 64))
                pkt = Ether() / ip_layer / tcp_layer / payload
            else:  # UDP
                udp_layer = UDP(sport=sport, dport=dport)
                payload = Raw(load=b"U" * 32)
                pkt = Ether() / ip_layer / udp_layer / payload

            pkt.time = t
            packets.append(pkt)

        os.makedirs(os.path.dirname(output_pcap_path), exist_ok=True)
        wrpcap(output_pcap_path, packets)
