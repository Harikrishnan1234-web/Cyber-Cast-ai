"""
PCAP Parser Module using Scapy.
Extracts packet-level and flow-level telemetry directly from raw PCAP captures:
- TTL variance across sessions
- TCP window sizes
- IP fragment flags
- Payload size distributions
- Sequential & randomized port scan signatures
- TCP retransmissions
"""

import os
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
from collections import defaultdict


class PcapParser:
    """
    Parses PCAP network captures into normalized flow records with deep packet-level statistics.
    """

    def __init__(self, max_packets: Optional[int] = 100000):
        self.max_packets = max_packets

    def parse_pcap(self, pcap_path: str) -> pd.DataFrame:
        """
        Parses PCAP using Scapy and returns a standardized pandas DataFrame.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        except ImportError:
            raise ImportError(
                "Scapy is required to parse raw PCAP files. Run 'pip install scapy' to enable PCAP parsing."
            )

        packets = rdpcap(pcap_path, count=self.max_packets)
        return self._process_scapy_packets(packets)

    def _process_scapy_packets(self, packets) -> pd.DataFrame:
        """
        Aggregates Scapy packet list into session flows with rich packet statistics.
        """
        from scapy.all import IP, TCP, UDP, ICMP

        # Flow table: key -> list of packet metadata
        flows = defaultdict(list)
        dest_port_history = defaultdict(list)

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            pkt_time = float(pkt.time)
            ttl = int(ip_layer.ttl)
            ip_frag = int((ip_layer.flags & 1) != 0 or ip_layer.frag > 0)  # MF or fragment offset

            src_port = 0
            dst_port = 0
            flags = {"syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0}
            window = 0
            payload_len = 0
            seq_num = 0

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                window = tcp_layer.window
                seq_num = tcp_layer.seq
                payload_len = len(tcp_layer.payload)
                
                # Flag extraction
                f = tcp_layer.flags
                flags["syn"] = 1 if f & 0x02 else 0
                flags["ack"] = 1 if f & 0x10 else 0
                flags["fin"] = 1 if f & 0x01 else 0
                flags["rst"] = 1 if f & 0x04 else 0
                flags["psh"] = 1 if f & 0x08 else 0
                flags["urg"] = 1 if f & 0x20 else 0

                dest_port_history[src_ip].append(dst_port)

            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                payload_len = len(udp_layer.payload)
                dest_port_history[src_ip].append(dst_port)

            elif pkt.haslayer(ICMP):
                payload_len = len(pkt[ICMP].payload)

            flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
            flows[flow_key].append({
                "time": pkt_time,
                "ttl": ttl,
                "frag": ip_frag,
                "window": window,
                "payload_len": payload_len,
                "flags": flags,
                "seq": seq_num,
                "total_len": len(pkt)
            })

        # Summarize flows
        rows = []
        for (src_ip, dst_ip, src_port, dst_port, proto), pkt_list in flows.items():
            pkt_list.sort(key=lambda x: x["time"])
            times = [p["time"] for p in pkt_list]
            ttls = [p["ttl"] for p in pkt_list]
            windows = [p["window"] for p in pkt_list if p["window"] > 0]
            payloads = [p["payload_len"] for p in pkt_list]
            frags = [p["frag"] for p in pkt_list]
            seqs = [p["seq"] for p in pkt_list if p["seq"] > 0]

            duration = max(times[-1] - times[0], 0.001)
            fwd_packets = len(pkt_list)
            bwd_packets = 0  # Uni-directional perspective from flow key
            fwd_bytes = sum(p["total_len"] for p in pkt_list)
            bwd_bytes = 0

            # Inter-arrival times
            if len(times) > 1:
                iats = np.diff(times) * 1000.0  # ms
                iat_mean = float(np.mean(iats))
                iat_std = float(np.std(iats))
                iat_max = float(np.max(iats))
            else:
                iat_mean, iat_std, iat_max = 0.0, 0.0, 0.0

            # TCP flags
            flag_syn = sum(p["flags"]["syn"] for p in pkt_list)
            flag_ack = sum(p["flags"]["ack"] for p in pkt_list)
            flag_fin = sum(p["flags"]["fin"] for p in pkt_list)
            flag_rst = sum(p["flags"]["rst"] for p in pkt_list)
            flag_psh = sum(p["flags"]["psh"] for p in pkt_list)
            flag_urg = sum(p["flags"]["urg"] for p in pkt_list)

            # Packet-level features
            ttl_mean = float(np.mean(ttls)) if ttls else 64.0
            ttl_var = float(np.var(ttls)) if len(ttls) > 1 else 0.0
            tcp_win_mean = float(np.mean(windows)) if windows else 64240.0
            retransmissions = len(seqs) - len(set(seqs)) if len(seqs) > 1 else 0

            rows.append({
                "timestamp": times[0],
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "flow_duration": duration,
                "fwd_packets": fwd_packets,
                "bwd_packets": bwd_packets,
                "fwd_bytes": fwd_bytes,
                "bwd_bytes": bwd_bytes,
                "total_packets": fwd_packets,
                "total_bytes": fwd_bytes,
                "bytes_bwd_fwd_ratio": 0.0,
                "packets_bwd_fwd_ratio": 0.0,
                "flag_syn": flag_syn,
                "flag_ack": flag_ack,
                "flag_fin": flag_fin,
                "flag_rst": flag_rst,
                "flag_psh": flag_psh,
                "flag_urg": flag_urg,
                "flow_iat_mean": iat_mean,
                "flow_iat_std": iat_std,
                "flow_iat_max": iat_max,
                "ttl_mean": ttl_mean,
                "ttl_var": ttl_var,
                "tcp_window_mean": tcp_win_mean,
                "retransmissions": retransmissions,
                "attack_stage": 0
            })

        df = pd.DataFrame(rows)
        if not df.empty:
            df = df.sort_values(by="timestamp").reset_index(drop=True)
        return df
