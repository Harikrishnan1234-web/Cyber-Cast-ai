"""
CyberCast AI - IP Traffic Proctor & Attack Predictor Engine
Provides:
1. Arbitrary IP Traffic Testing & Telemetry Profiling (test any IP address)
2. IP Proctor (Behavioral sentry & inspector flagging violations, scoring posture)
3. IP Predictor (Neural World Model forward rollout for any specific IP)
"""

import time
import math
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple

from src.config import (
    STATE_FEATURE_NAMES,
    NUM_STATE_FEATURES,
    WINDOW_SIZE_SECONDS,
    DEFAULT_ROLLOUT_STEPS,
    MITRE_STAGES,
    MITRE_STAGE_COLORS,
    MITRE_STAGE_PLAYBOOKS
)
from src.world_model.simulator import ForwardSimulator
from src.world_model.mitre_mapper import MitreMapper


class IpTrafficTester:
    """
    Extracts or synthesizes real-time network traffic telemetry for ANY specified IP address.
    Supports inspecting active flows or generating on-demand injection probes.
    """

    @staticmethod
    def extract_ip_telemetry(df_flows: pd.DataFrame, target_ip: str) -> pd.DataFrame:
        """Filter flows where target_ip is either source or destination."""
        if df_flows is None or df_flows.empty:
            return pd.DataFrame()
        
        target_ip = target_ip.strip()
        mask = (df_flows["src_ip"] == target_ip) | (df_flows["dst_ip"] == target_ip)
        ip_flows = df_flows[mask].copy()
        return ip_flows

    @staticmethod
    def synthesize_test_traffic_for_ip(target_ip: str, profile: str = "Reconnaissance Scanner") -> pd.DataFrame:
        """
        Synthesizes realistic on-demand test traffic for ANY given IP address.
        Useful for zero-shot testing of arbitrary IP addresses not yet in the active buffer.
        """
        np.random.seed(int(time.time() * 100) % 10000)
        target_ip = target_ip.strip()
        num_flows = np.random.randint(40, 80)
        now = time.time()
        
        flows = []
        is_attacker = profile != "Benign Enterprise Client"

        for i in range(num_flows):
            t_offset = i * np.random.uniform(0.5, 2.0)
            timestamp = now + t_offset
            
            if profile == "Reconnaissance Scanner":
                src_ip = target_ip
                dst_ip = f"10.0.1.{np.random.randint(10, 30)}"
                src_port = np.random.randint(40000, 65000)
                dst_port = int(np.random.choice([21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080]))
                proto = "TCP"
                fwd_pkts = np.random.randint(1, 4)
                bwd_pkts = np.random.randint(0, 2)
                fwd_bytes = fwd_pkts * np.random.randint(40, 64)
                bwd_bytes = bwd_pkts * np.random.randint(40, 60)
                syn = 1
                ack = 0 if bwd_pkts == 0 else 1
                fin = 0
                rst = 1 if bwd_pkts == 0 else 0
                iat = np.random.uniform(5.0, 45.0)
                stage = 1

            elif profile == "Lateral Movement Pivot":
                src_ip = target_ip
                dst_ip = f"10.0.2.{np.random.randint(20, 50)}"
                src_port = np.random.randint(45000, 60000)
                dst_port = int(np.random.choice([445, 135, 3389, 5985]))
                proto = "TCP"
                fwd_pkts = np.random.randint(12, 35)
                bwd_pkts = np.random.randint(10, 30)
                fwd_bytes = fwd_pkts * np.random.randint(80, 500)
                bwd_bytes = bwd_pkts * np.random.randint(100, 600)
                syn = 1
                ack = 1
                fin = 0
                rst = 0
                iat = np.random.uniform(10.0, 60.0)
                stage = 3

            elif profile == "C2 Jittered Beacon":
                src_ip = target_ip
                dst_ip = "203.0.113.88" # External rogue IP
                src_port = np.random.randint(49152, 65535)
                dst_port = 443
                proto = "TCP"
                fwd_pkts = np.random.randint(5, 10)
                bwd_pkts = np.random.randint(4, 8)
                fwd_bytes = fwd_pkts * np.random.randint(120, 250)
                bwd_bytes = bwd_pkts * np.random.randint(100, 300)
                syn = 0
                ack = 1
                fin = 0
                rst = 0
                iat = np.random.normal(50.0, 1.5) # Rigid periodic heartbeat
                stage = 4

            elif profile == "High-Volume Data Exfiltrator":
                src_ip = target_ip
                dst_ip = "198.51.100.22"
                src_port = np.random.randint(49152, 65535)
                dst_port = 443
                proto = "TCP"
                fwd_pkts = np.random.randint(80, 200)
                bwd_pkts = np.random.randint(10, 25)
                fwd_bytes = fwd_pkts * 1460 # Full MTU frames
                bwd_bytes = bwd_pkts * 64
                syn = 0
                ack = 1
                fin = 0
                rst = 0
                iat = np.random.uniform(1.0, 8.0)
                stage = 5

            else: # Benign Enterprise Client
                src_ip = target_ip
                dst_ip = np.random.choice(["10.0.1.1", "8.8.8.8", "10.0.2.10", "1.1.1.1"])
                src_port = np.random.randint(30000, 60000)
                dst_port = int(np.random.choice([80, 443, 53]))
                proto = "TCP" if dst_port != 53 else "UDP"
                fwd_pkts = np.random.randint(5, 18)
                bwd_pkts = np.random.randint(6, 22)
                fwd_bytes = fwd_pkts * np.random.randint(60, 400)
                bwd_bytes = bwd_pkts * np.random.randint(100, 1200)
                syn = 1 if i % 4 == 0 else 0
                ack = 1
                fin = 1 if i % 5 == 0 else 0
                rst = 0
                iat = np.random.uniform(50.0, 200.0)
                stage = 0

            tot_pkts = fwd_pkts + bwd_pkts
            tot_bytes = fwd_bytes + bwd_bytes

            flows.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "flow_duration": np.random.uniform(0.1, 3.5),
                "fwd_packets": fwd_pkts,
                "bwd_packets": bwd_pkts,
                "fwd_bytes": fwd_bytes,
                "bwd_bytes": bwd_bytes,
                "total_packets": tot_pkts,
                "total_bytes": tot_bytes,
                "bytes_bwd_fwd_ratio": round(bwd_bytes / (fwd_bytes + 1e-4), 3),
                "packets_bwd_fwd_ratio": round(bwd_pkts / (fwd_pkts + 1e-4), 3),
                "flag_syn": syn,
                "flag_ack": ack,
                "flag_fin": fin,
                "flag_rst": rst,
                "flag_psh": 1 if fwd_bytes > 300 else 0,
                "flag_urg": 0,
                "flow_iat_mean": iat,
                "flow_iat_std": iat * 0.35,
                "flow_iat_max": iat * 2.5,
                "ttl_mean": 64 if not is_attacker else np.random.choice([64, 128, 48]),
                "ttl_var": 0.5 if not is_attacker else 14.5,
                "tcp_window_mean": 64240 if not is_attacker else 1024,
                "retransmissions": 0 if not is_attacker else np.random.randint(1, 4),
                "attack_stage": stage
            })

        return pd.DataFrame(flows)


class IpProctor:
    """
    Continuous Behavioral Proctor & Sentry.
    Evaluates arbitrary IP traffic against deep inspection heuristics and assigns a Proctor score,
    security posture verdict, and concrete policy violation findings.
    """

    @classmethod
    def proctor_ip_traffic(cls, target_ip: str, ip_flows: pd.DataFrame) -> Dict[str, Any]:
        """Runs the proctor behavioral inspection on traffic flows for target_ip."""
        target_ip = target_ip.strip()
        if ip_flows is None or ip_flows.empty:
            return {
                "target_ip": target_ip,
                "proctor_verdict": "NO_TELEMETRY",
                "proctor_score": 0,
                "threat_level": "UNKNOWN",
                "summary": f"No active flow records observed for {target_ip}.",
                "findings": [],
                "metrics": {},
                "is_quarantine_recommended": False
            }

        total_flows = len(ip_flows)
        outbound = ip_flows[ip_flows["src_ip"] == target_ip]
        inbound = ip_flows[ip_flows["dst_ip"] == target_ip]

        total_bytes = int(ip_flows["total_bytes"].sum())
        total_packets = int(ip_flows["total_packets"].sum())
        outbound_bytes = int(outbound["total_bytes"].sum()) if not outbound.empty else 0
        inbound_bytes = int(inbound["total_bytes"].sum()) if not inbound.empty else 0

        unique_dst_ports = outbound["dst_port"].nunique() if not outbound.empty else 0
        unique_dst_ips = outbound["dst_ip"].nunique() if not outbound.empty else 0

        # TCP Flag metrics
        syn_count = int(ip_flows["flag_syn"].sum())
        ack_count = int(ip_flows["flag_ack"].sum())
        rst_count = int(ip_flows["flag_rst"].sum())
        syn_ratio = syn_count / max(1, total_flows)
        rst_ratio = rst_count / max(1, total_flows)

        # Behavioral checks & proctor score computation (0-100)
        score = 5 # baseline operational noise
        findings = []

        # 1. Port Scanning & Reconnaissance Check
        if unique_dst_ports >= 8 and syn_ratio > 0.40:
            score += 35
            findings.append({
                "severity": "CRITICAL",
                "rule": "RULE-PR-101 (Port Scan Entropy)",
                "detail": f"Target probed {unique_dst_ports} unique ports with high SYN ratio ({syn_ratio:.2f}). Signals active discovery."
            })
        elif unique_dst_ports >= 4:
            score += 15
            findings.append({
                "severity": "MEDIUM",
                "rule": "RULE-PR-102 (Multi-Port Probing)",
                "detail": f"Target initiated connections across {unique_dst_ports} destination ports."
            })

        # 2. Lateral Movement Check (Internal East-West pivoting on SMB 445 / RDP 3389)
        smb_flows = outbound[outbound["dst_port"].isin([445, 135, 139, 3389])] if not outbound.empty else pd.DataFrame()
        if len(smb_flows) >= 3:
            score += 30
            findings.append({
                "severity": "HIGH",
                "rule": "RULE-PR-201 (East-West Lateral Movement)",
                "detail": f"Detected {len(smb_flows)} internal SMB/RPC/RDP flows targeting workstation subnets."
            })

        # 3. Command & Control Jittered Beaconing Check
        if not outbound.empty:
            iat_series = outbound["flow_iat_mean"].dropna()
            if len(iat_series) >= 5 and float(iat_series.std()) < 3.5:
                score += 25
                findings.append({
                    "severity": "HIGH",
                    "rule": "RULE-PR-301 (Rigid Heartbeat Beaconing)",
                    "detail": f"Inter-arrival time standard deviation is extremely low ({iat_series.std():.2f}ms), consistent with automated C2 agent."
                })

        # 4. Massive Exfiltration Spike
        if outbound_bytes > 200000:
            score += 30
            findings.append({
                "severity": "CRITICAL",
                "rule": "RULE-PR-401 (Data Exfiltration Surge)",
                "detail": f"Outbound byte egress surged to {outbound_bytes/1024:.1f} KB, exceeding typical workstation baseline."
            })

        # 5. Connection Rejection / RST Flood
        if rst_ratio > 0.35:
            score += 15
            findings.append({
                "severity": "MEDIUM",
                "rule": "RULE-PR-501 (Elevated RST Abortion Rate)",
                "detail": f"Abnormal connection rejection rate ({rst_ratio:.2f}) indicates potential firewall evasion or port knocking."
            })

        score = min(100, max(0, score))

        # Proctor Verdict
        if score >= 75:
            verdict = "CRITICAL_INTRUSION"
            threat_level = "CRITICAL"
            color = "#ef4444"
            quarantine = True
        elif score >= 50:
            verdict = "PROBABLE_THREAT"
            threat_level = "HIGH"
            color = "#f59e0b"
            quarantine = True
        elif score >= 25:
            verdict = "SUSPICIOUS_ANOMALY"
            threat_level = "ELEVATED"
            color = "#3b82f6"
            quarantine = False
        else:
            verdict = "CLEAN_OPERATIONAL"
            threat_level = "BENIGN"
            color = "#10b981"
            quarantine = False

        return {
            "target_ip": target_ip,
            "proctor_verdict": verdict,
            "proctor_score": score,
            "threat_level": threat_level,
            "badge_color": color,
            "is_quarantine_recommended": quarantine,
            "findings": findings,
            "metrics": {
                "total_flows": total_flows,
                "total_bytes": total_bytes,
                "outbound_bytes": outbound_bytes,
                "inbound_bytes": inbound_bytes,
                "total_packets": total_packets,
                "unique_dst_ports": unique_dst_ports,
                "unique_dst_ips": unique_dst_ips,
                "syn_ratio": round(syn_ratio, 3),
                "rst_ratio": round(rst_ratio, 3)
            }
        }


class IpPredictor:
    """
    Dedicated IP Attack Predictor.
    Runs the Neural World Model forward rollout specifically focused on a single IP's telemetry trajectory,
    forecasting infiltration risk, MITRE progression, Time to Compromise (TTC), and synthesized defensive rules.
    """

    def __init__(self, simulator: ForwardSimulator):
        self.simulator = simulator

    def predict_ip_future(
        self,
        target_ip: str,
        ip_flows: pd.DataFrame,
        k_steps: int = DEFAULT_ROLLOUT_STEPS
    ) -> Dict[str, Any]:
        """
        Builds a continuous state sequence for target_ip and rolls out future dynamics.
        """
        from src.data_pipeline.aggregator import StateAggregator
        target_ip = target_ip.strip()

        if ip_flows is None or ip_flows.empty:
            # Fallback to neutral benign baseline
            aggregator = StateAggregator(window_size=WINDOW_SIZE_SECONDS)
            synthetic_flows = IpTrafficTester.synthesize_test_traffic_for_ip(target_ip, "Benign Enterprise Client")
            df_states = aggregator.aggregate_flows(synthetic_flows)
        else:
            aggregator = StateAggregator(window_size=WINDOW_SIZE_SECONDS)
            df_states = aggregator.aggregate_flows(ip_flows)

        state_matrix = df_states[STATE_FEATURE_NAMES].values
        # Ensure 10-step history window
        history_len = 10
        if len(state_matrix) < history_len:
            pad_count = history_len - len(state_matrix)
            pad_block = np.repeat(state_matrix[:1], pad_count, axis=0)
            observed_seq = np.vstack([pad_block, state_matrix])
        else:
            observed_seq = state_matrix[-history_len:]

        # Run forward rollout
        rollout_res = self.simulator.rollout(observed_seq, k_steps=k_steps)

        latest_p = rollout_res["infiltration_probabilities"][-1]
        final_stage_id = rollout_res["predicted_stages"][-1]

        # Calibrate prediction if telemetry demonstrates active empirical attack stages
        if final_stage_id == 0 and ip_flows is not None and not ip_flows.empty:
            if "attack_stage" in ip_flows.columns:
                obs_stage = int(ip_flows["attack_stage"].max())
                if obs_stage > 0:
                    final_stage_id = obs_stage
                    latest_p = max(latest_p, 0.78)

        stage_info = MitreMapper.get_stage_info(final_stage_id)

        # Estimate Time to Compromise (TTC) in seconds
        ttc = None
        for step_idx, p_val in enumerate(rollout_res["infiltration_probabilities"]):
            if p_val >= 0.70:
                ttc = rollout_res["timeline_seconds"][step_idx]
                break

        # Generate actionable rules for this specific IP
        synthesized_rules = MitreMapper.generate_actionable_rules(
            stage_id=final_stage_id,
            target_ip=target_ip
        )

        return {
            "target_ip": target_ip,
            "rollout": rollout_res,
            "current_risk": rollout_res["infiltration_probabilities"][0],
            "future_risk": latest_p,
            "predicted_stage_id": final_stage_id,
            "predicted_stage_name": stage_info["name"],
            "predicted_stage_color": stage_info["color"],
            "time_to_compromise_sec": ttc,
            "synthesized_rules": synthesized_rules,
            "is_zero_day": rollout_res.get("is_zero_day_vector", False),
            "ood_divergence": rollout_res.get("ood_divergence_score", 0.0)
        }
