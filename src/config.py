"""
CyberCast AI - Configuration & Constants
Defines feature schema, MITRE ATT&CK stage taxonomies, model hyperparameters,
and default time-window settings.
"""

from typing import List, Dict

# Time window parameters for network state aggregation
WINDOW_SIZE_SECONDS = 5.0
DEFAULT_ROLLOUT_STEPS = 5  # K steps forward simulation
SEQUENCE_HISTORY_STEPS = 10  # Number of past time windows fed into World Model

# MITRE ATT&CK Attack Phases
MITRE_STAGES: Dict[int, str] = {
    0: "Benign / Normal Operations",
    1: "Reconnaissance (T1595/T1046)",
    2: "Initial Access (T1190/T1078)",
    3: "Lateral Movement (T1021/T1570)",
    4: "Command & Control (C2) (T1071/T1573)",
    5: "Exfiltration / Impact (T1041/T1486)"
}

MITRE_STAGE_DESCRIPTIONS: Dict[int, str] = {
    0: "Baseline enterprise communications, standard web/DNS/internal traffic.",
    1: "Active host discovery, sequential/randomized port scanning, banner grabbing.",
    2: "Exploitation of public-facing applications, brute-force authentication, web shell drops.",
    3: "Internal pivoting across subnets, SMB/RPC/RDP probes, Pass-the-Hash, PsExec behavior.",
    4: "Periodic beaconing to external IP/domains, heartbeat traffic, jittered C2 communications.",
    5: "Unusual high-volume egress flows, encrypted archives leaving critical database servers."
}

MITRE_STAGE_COLORS: Dict[int, str] = {
    0: "#10b981",  # Green
    1: "#3b82f6",  # Blue
    2: "#f59e0b",  # Amber
    3: "#8b5cf6",  # Purple
    4: "#ec4899",  # Pink
    5: "#ef4444"   # Red
}

# Mitigation & Playbook Recommendations per Stage
MITRE_STAGE_PLAYBOOKS: Dict[int, Dict[str, str]] = {
    0: {
        "action": "Maintain Continuous Telemetry",
        "detail": "Standard baseline monitoring. No defensive countermeasures required.",
        "priority": "INFO"
    },
    1: {
        "action": "Enact Perimeter Rate-Limiting & Dynamic Honeypot Redirection",
        "detail": "Block scanner IPs at egress/ingress ACLs; deploy honeypot decoys on probed high-order ports.",
        "priority": "MEDIUM"
    },
    2: {
        "action": "Isolate Targeted Ingress Hosts & Revoke Exposed Credentials",
        "detail": "Trigger micro-segmentation for vulnerable web/VPN gateways; force MFA reset on targeted accounts.",
        "priority": "HIGH"
    },
    3: {
        "action": "Sever Internal Subnet Pivots & Restrict East-West RPC/SMB",
        "detail": "Quarantine compromised internal workstation; deploy zero-trust east-west firewall boundaries.",
        "priority": "CRITICAL"
    },
    4: {
        "action": "Null-Route C2 Egress Domains & Terminate Outbound Sessions",
        "detail": "Enforce DNS sinkholing for beaconing domains; terminate suspicious persistent encrypted outbound sockets.",
        "priority": "CRITICAL"
    },
    5: {
        "action": "Engage Automated Data-Loss Emergency Lockdown & Snapshot Recovery",
        "detail": "Throttle high-bandwidth egress pipes immediately; freeze database state; initiate incident response playbook IR-402.",
        "priority": "EMERGENCY"
    }
}

# Network State Vector Feature Schema (Aggregate Time-Window State)
# Combining both Flow-Level and Packet-Level attributes into a comprehensive telemetry representation
STATE_FEATURE_NAMES: List[str] = [
    # Flow-level features (NetFlow/IPFIX aggregations)
    "flow_count",              # Active concurrent flows in window
    "unique_src_ips",          # Unique source IPs observed
    "unique_dst_ips",          # Unique target IPs observed
    "unique_dst_ports",        # Unique destination ports targeted
    "total_bytes",             # Total volumetric byte count
    "total_packets",           # Total volumetric packet count
    "bytes_bwd_fwd_ratio",     # Ratio of inbound response bytes to outbound request bytes
    "packets_bwd_fwd_ratio",   # Ratio of response packets to request packets
    "iat_mean_ms",             # Mean Inter-Arrival Time (ms)
    "iat_std_ms",              # Standard deviation of Inter-Arrival Time
    "iat_max_ms",              # Max Inter-Arrival Time in window
    
    # TCP Flag bitmask distributions (Flow-level aggregate)
    "flag_syn_ratio",          # Ratio of SYN packets (recon / flood indicator)
    "flag_ack_ratio",          # Ratio of ACK packets (established sessions)
    "flag_fin_ratio",          # Ratio of FIN packets (clean closures)
    "flag_rst_ratio",          # Ratio of RST packets (connection rejections / aborts)
    "flag_psh_ratio",          # Ratio of PSH packets (interactive data transfer)
    "flag_urg_ratio",          # Ratio of URG packets
    
    # Packet-level features (PCAP-derived / deep inspection)
    "ttl_mean",                # Average Time-To-Live across packets
    "ttl_variance",            # Variance in TTL (signals spoofing or route variance)
    "tcp_window_mean",         # Average advertised TCP window size
    "tcp_window_min",          # Minimum advertised TCP window size
    "payload_size_mean",       # Average packet payload size
    "payload_size_variance",   # Variance in payload size
    "ip_frag_ratio",           # Fraction of fragmented IP packets (evasion indicator)
    "port_scan_entropy",       # Dispersion of accessed destination ports (0=single port, 1=high scan)
    "retransmission_rate",     # TCP packet retransmission frequency
    "east_west_traffic_ratio"  # Fraction of traffic staying inside private CIDR (lateral movement)
]

NUM_STATE_FEATURES = len(STATE_FEATURE_NAMES)  # 23 rich features

# Raw Flow Record Features (compatible with CIC-IDS-2018 / CTU-13 / NetFlow)
RAW_FLOW_FEATURES: List[str] = [
    "timestamp",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "flow_duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "flag_syn",
    "flag_ack",
    "flag_fin",
    "flag_rst",
    "flag_psh",
    "flag_urg",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "ttl_mean",
    "ttl_var",
    "tcp_window_mean",
    "retransmissions",
    "attack_stage"
]
