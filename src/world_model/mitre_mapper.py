"""
MITRE ATT&CK Mapping & Proactive Defensive Playbook Engine.
Maps continuous network state vectors and dynamics predictions to recognised
MITRE ATT&CK techniques, generating actionable mitigation commands before compromise occurs.
"""

import numpy as np
from typing import Dict, List, Any, Optional
from src.config import MITRE_STAGES, MITRE_STAGE_DESCRIPTIONS, MITRE_STAGE_PLAYBOOKS, MITRE_STAGE_COLORS


class MitreMapper:
    """
    Translates forecasted intrusion states into granular MITRE ATT&CK tactical techniques,
    sub-techniques, and executable defensive countermeasures (IPTables, Suricata, Snort, Zeek).
    """

    TECHNIQUE_CATALOG: Dict[int, List[Dict[str, Any]]] = {
        0: [
            {
                "id": "T0000",
                "name": "Normal Enterprise Baseline Operations",
                "tactic": "Baseline",
                "description": "Standard business operations: HTTP/HTTPS web egress, DNS lookups, and internal file shares.",
                "indicators": ["Normal IAT (>50ms)", "Low SYN/ACK ratio", "Standard TTL distribution"],
                "countermeasures": ["Maintain continuous NetFlow telemetry collection", "Periodic baseline drift verification"]
            }
        ],
        1: [
            {
                "id": "T1595.001",
                "name": "Active Scanning: IP Blocks",
                "tactic": "Reconnaissance",
                "description": "Sequential or sweeping ICMP/SYN requests targeting enterprise CIDR blocks.",
                "indicators": ["Elevated SYN flag ratio (>0.45)", "High unique destination IP count", "Low flow duration (<100ms)"],
                "countermeasures": ["Enable perimeter egress rate-limiting", "Blackhole scanner subnet at edge BGP/router"]
            },
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "tactic": "Reconnaissance",
                "description": "Port scanning over target servers (e.g. Nmap SYN stealth scan, masscan) probing high-order ports.",
                "indicators": ["High destination port entropy (>0.7)", "SYN-only packets with zero ACK pairs", "Abnormal TTL variance"],
                "countermeasures": ["Deploy Port-Knocking / Dynamic Honeypot traps", "Enforce stateful firewall SYN cookies"]
            }
        ],
        2: [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Exploitation of vulnerabilities in external web/VPN gateways (e.g. log4j, RCE, SQLi payloads).",
                "indicators": ["Anomalous payload size spikes", "Bursty bi-directional byte ratios", "Repeated connections to ports 80/443/8443"],
                "countermeasures": ["Apply WAF virtual patching rules", "Quarantine exposed public ingress service to DMZ sandbox"]
            },
            {
                "id": "T1078",
                "name": "Valid Accounts: Default / Compromised Credentials",
                "tactic": "Initial Access",
                "description": "Credential stuffing, password spraying, or brute force against SSH/RDP/VPN endpoints.",
                "indicators": ["Rapid connection teardowns (RST flags)", "High failure rate on port 22/3389", "Low IAT variance"],
                "countermeasures": ["Enforce mandatory MFA challenge", "Temporarily lock targeted account and terminate active sessions"]
            }
        ],
        3: [
            {
                "id": "T1021.002",
                "name": "Remote Services: SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
                "description": "Pivoting across internal subnets utilizing SMB (port 445), RPC (port 135), or PsExec.",
                "indicators": ["Surge in East-West traffic ratio (>0.60)", "Direct internal-to-internal flows", "High payload transfers to DC"],
                "countermeasures": ["Sever East-West SMB port 445 between workstations", "Enable Zero-Trust micro-segmentation"]
            },
            {
                "id": "T1570",
                "name": "Lateral Tool Transfer",
                "tactic": "Lateral Movement",
                "description": "Transferring hacking tools (e.g. Mimikatz, BloodHound, Cobalt Strike beacons) to secondary hosts.",
                "indicators": ["Sustained internal byte bursts", "High PSH flag ratio on non-standard ports", "Intermittent keepalives"],
                "countermeasures": ["Isolate pivot host via host-based EDR quarantine", "Block internal RPC dynamic port ranges"]
            }
        ],
        4: [
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols (C2 Beaconing)",
                "tactic": "Command and Control",
                "description": "Regular or jittered outbound beaconing over HTTP/HTTPS to an external C2 server.",
                "indicators": ["Periodic IAT with low variance (heartbeat)", "Small payload sizes (<500B)", "Consistent external destination IP/port 443"],
                "countermeasures": ["Null-route C2 domain/IP at DNS sinkhole", "Terminate outbound TLS session at next-gen firewall"]
            },
            {
                "id": "T1573.002",
                "name": "Encrypted Channel: Asymmetric Cryptography",
                "tactic": "Command and Control",
                "description": "Encrypted C2 tunneling over non-standard TLS or SSH encapsulation to evade inspection.",
                "indicators": ["High flow duration (>180s)", "Low packet size variance", "Non-standard high port communication"],
                "countermeasures": ["Reset TCP connections matching C2 fingerprint", "Enforce TLS decryption and inspection proxy"]
            }
        ],
        5: [
            {
                "id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": "Stealing sensitive database records, archives, or telemetry by pushing high-volume egress traffic.",
                "indicators": ["Massive outbound bytes (>10MB/min)", "High forward-to-backward byte ratio (>5.0)", "Sustained high bandwidth on egress"],
                "countermeasures": ["Throttle egress pipe to 10 KB/s on affected CIDR", "Trigger emergency DLP alert and snapshot database"]
            },
            {
                "id": "T1486",
                "name": "Data Encrypted for Impact (Ransomware)",
                "tactic": "Impact",
                "description": "Encrypting high-value storage volumes or Active Directory databases to cause denial of service.",
                "indicators": ["Rapid East-West burst targeting file servers", "Spike in RST/FIN connection turnover", "High IOPS signatures"],
                "countermeasures": ["Instantly isolate core backup and database storage", "Initiate cold-site failover protocol"]
            }
        ]
    }

    @classmethod
    def get_stage_info(cls, stage_id: int) -> Dict[str, Any]:
        """Returns metadata for a given MITRE attack stage."""
        stage_id = int(np.clip(stage_id, 0, 5))
        return {
            "stage_id": stage_id,
            "name": MITRE_STAGES.get(stage_id, "Unknown"),
            "description": MITRE_STAGE_DESCRIPTIONS.get(stage_id, ""),
            "color": MITRE_STAGE_COLORS.get(stage_id, "#6b7280"),
            "playbook": MITRE_STAGE_PLAYBOOKS.get(stage_id, {}),
            "techniques": cls.TECHNIQUE_CATALOG.get(stage_id, [])
        }

    @classmethod
    def generate_actionable_rules(cls, stage_id: int, target_ip: str = "10.0.1.15", target_port: int = 445) -> Dict[str, str]:
        """
        Synthesizes executable defensive rules ready for copy-pasting into enterprise firewalls / IDS:
        - IPTables
        - Suricata / Snort
        - Zeek Notice
        - Windows Defender Firewall PowerShell
        """
        stage_id = int(np.clip(stage_id, 0, 5))

        if stage_id == 0:
            return {
                "iptables": "# No intervention needed: Baseline enterprise telemetry active.",
                "suricata": "# Baseline state. Monitoring enabled.",
                "powershell": "# System operating normally. No ACL changes.",
                "zeek": "# Baseline monitoring active."
            }

        elif stage_id == 1:
            return {
                "iptables": f"sudo iptables -A INPUT -s {target_ip} -p tcp --syn -m limit --limit 5/s --limit-burst 10 -j ACCEPT\nsudo iptables -A INPUT -s {target_ip} -p tcp --tcp-flags ALL NONE -j DROP\nsudo iptables -A INPUT -s {target_ip} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP",
                "suricata": f'alert tcp {target_ip} any -> $HOME_NET any (msg:"CYBERCAST-AI: Forecasted Stealth Port Scan"; flags:S,12; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-recon; sid:9001001; rev:1;)',
                "powershell": f'New-NetFirewallRule -DisplayName "CyberCast-AntiScan-Drop-{target_ip}" -Direction Inbound -Action Block -Protocol TCP -LocalPort 1-1024 -RemoteAddress {target_ip}',
                "zeek": f'event connection_state_remove(c: connection) {{\n  if ( c$id$orig_h == "{target_ip}" && c$duration < 0.1sec && c$history == "S" ) {{\n    NOTICE([$note=Scan::Port_Scan, $msg="CyberCast AI Early Scan Warning for {target_ip}", $conn=c]);\n  }}\n}}'
            }

        elif stage_id == 2:
            return {
                "iptables": f"sudo iptables -I INPUT -s {target_ip} -j DROP\nsudo iptables -A INPUT -s {target_ip} -p tcp --dport 80,443 -m connlimit --connlimit-above 30 -j REJECT",
                "suricata": f'alert http any any -> $HOME_NET [80,443] (msg:"CYBERCAST-AI: Forecasted Ingress Exploitation Probe from {target_ip}"; flow:to_server,established; content:"/.."; nocase; sid:9002001; rev:1;)',
                "powershell": f'New-NetFirewallRule -DisplayName "CyberCast-Isolate-Attacker-{target_ip}" -Direction Inbound -Action Block -RemoteAddress {target_ip}',
                "zeek": f'event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {{\n  if ( c$id$orig_h == "{target_ip}" && |unescaped_URI| > 256 ) NOTICE([$note=HTTP::Large_URI, $msg="Exploit probe predicted from {target_ip}", $conn=c]);\n}}'
            }

        elif stage_id == 3:
            return {
                "iptables": f"# Block East-West SMB & RPC from host {target_ip}\nsudo iptables -I FORWARD -s {target_ip} -j DROP\nsudo iptables -A FORWARD -s {target_ip} -p tcp --dport 445 -j DROP\nsudo iptables -A FORWARD -s {target_ip} -p tcp --dport 135 -j DROP\nsudo iptables -A FORWARD -s {target_ip} -p tcp --dport 3389 -j DROP",
                "suricata": f'alert smb {target_ip} any -> $HOME_NET 445 (msg:"CYBERCAST-AI: Forecasted Lateral Movement via SMB Pipe from {target_ip}"; flow:to_server,established; content:"IPC$"; nocase; sid:9003001; rev:1;)',
                "powershell": f'# Quarantine internal workstation {target_ip}\nDisable-NetAdapter -Name "Ethernet*" -Confirm:$false\nNew-NetFirewallRule -DisplayName "CyberCast-ZeroTrust-Block-SMB" -Direction Inbound -Action Block -Protocol TCP -LocalPort 445,135,3389 -RemoteAddress {target_ip}',
                "zeek": f'event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string) {{\n  if ( c$id$orig_h == "{target_ip}" && ("ADMIN$" in path || "IPC$" in path) ) NOTICE([$note=SMB::Admin_Share_Pivot, $msg="Lateral pivot detected from {target_ip}", $conn=c]);\n}}'
            }

        elif stage_id == 4:
            return {
                "iptables": f"# Terminate persistent outbound C2 beacons for {target_ip}\nsudo iptables -I INPUT -s {target_ip} -j DROP\nsudo iptables -A OUTPUT -d {target_ip} -j DROP\nsudo iptables -A OUTPUT -p tcp --dport 443 -m length --length 100:600 -m limit --limit 1/s -j ACCEPT",
                "suricata": f'alert tcp $HOME_NET any -> {target_ip} any (msg:"CYBERCAST-AI: Forecasted C2 Beacon Heartbeat to {target_ip}"; flow:to_server,established; dsize:<500; stream_size:server,<,1000; sid:9004001; rev:1;)',
                "powershell": f'# DNS Sinkhole outbound C2 domains and block {target_ip}\nAdd-DnsClientNrptRule -Namespace "bad-c2-domain.com" -DnsSecValidationRequired -Action Block\nNew-NetFirewallRule -DisplayName "CyberCast-Block-C2-{target_ip}" -Direction Outbound -Action Block -RemoteAddress {target_ip}',
                "zeek": f'event connection_established(c: connection) {{\n  if ( c$id$resp_h == "{target_ip}" && c$id$resp_p == 443/tcp && c$duration > 300sec ) NOTICE([$note=C2::Persistent_Socket, $msg="Long-lived C2 socket predicted to {target_ip}", $conn=c]);\n}}'
            }

        else:  # stage_id == 5
            return {
                "iptables": f"# EMERGENCY EGRESS LOCKDOWN for host {target_ip}\nsudo iptables -I FORWARD -s {target_ip} -j DROP\nsudo iptables -I OUTPUT -d {target_ip} -j DROP\nsudo iptables -A OUTPUT -p tcp -j DROP\nsudo tc qdisc add dev eth0 root tbf rate 256kbit burst 10kb latency 50ms",
                "suricata": f'alert tcp {target_ip} any -> $EXTERNAL_NET any (msg:"CYBERCAST-AI: EMERGENCY Data Exfiltration Volume Threshold from {target_ip}"; flow:to_server,established; flowbits:isnotset,logged; threshold:type both, track by_src, count 10000, seconds 10; sid:9005001; rev:1;)',
                "powershell": f'# Emergency Network Isolation for {target_ip}\nSet-NetIPInterface -InterfaceAlias "vEthernet*" -Forwarding Disabled\nNew-NetFirewallRule -DisplayName "CyberCast-EMERGENCY-EGRESS-SHUTDOWN" -Direction Outbound -Action Block -RemoteAddress {target_ip}',
                "zeek": f'event connection_finished(c: connection) {{\n  if ( c$id$orig_h == "{target_ip}" && c$orig$size > 50000000 ) NOTICE([$note=Exfil::Massive_Egress, $msg="Volumetric exfiltration threshold reached for {target_ip}", $conn=c]);\n}}'
            }
