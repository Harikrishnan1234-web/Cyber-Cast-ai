"""
State Aggregator Module.
Transforms discrete flow and packet records into time-windowed continuous network state vectors
and builds sequence datasets for the Neural World Model.
"""

import numpy as np
import pandas as pd
import ipaddress
from typing import Tuple, List, Dict, Optional
from src.config import (
    WINDOW_SIZE_SECONDS,
    STATE_FEATURE_NAMES,
    SEQUENCE_HISTORY_STEPS,
    DEFAULT_ROLLOUT_STEPS
)


def is_private_ip(ip_str: str) -> bool:
    """Checks if an IP string belongs to private RFC1918 space."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
        return ip.is_private
    except Exception:
        return False


def calculate_entropy(values: List[int]) -> float:
    """Calculates normalized Shannon entropy of a categorical sequence (e.g., target ports)."""
    if not values:
        return 0.0
    _, counts = np.unique(values, return_counts=True)
    probs = counts / float(len(values))
    entropy = -np.sum(probs * np.log2(probs + 1e-12))
    # Normalize by log2(N) if N > 1
    max_entropy = np.log2(len(values)) if len(values) > 1 else 1.0
    return float(entropy / (max_entropy + 1e-9)) if max_entropy > 0 else 0.0


class StateAggregator:
    """
    Aggregates raw flow telemetry into discrete time-windowed state vectors S_t.
    """

    def __init__(self, window_size: float = WINDOW_SIZE_SECONDS):
        self.window_size = window_size
        self.feature_names = STATE_FEATURE_NAMES
        self.scaler_mean = None
        self.scaler_std = None

    def aggregate_flows(self, df_flows: pd.DataFrame) -> pd.DataFrame:
        """
        Groups flows into non-overlapping or sliding time windows and computes S_t.
        """
        if df_flows.empty:
            return pd.DataFrame(columns=self.feature_names + ["window_start", "attack_stage", "is_infiltrated"])

        min_time = df_flows["timestamp"].min()
        max_time = df_flows["timestamp"].max()

        # Ensure at least 5 windows so sequence modeling is always available
        if max_time - min_time < self.window_size * 5:
            window_bins = [min_time + i * self.window_size for i in range(6)]
        else:
            window_bins = np.arange(min_time, max_time + self.window_size, self.window_size)

        state_rows = []

        for i in range(len(window_bins) - 1):
            t_start = window_bins[i]
            t_end = window_bins[i + 1]

            w_df = df_flows[(df_flows["timestamp"] >= t_start) & (df_flows["timestamp"] < t_end)]
            if w_df.empty:
                # Idle state
                state_vec = {feat: 0.0 for feat in self.feature_names}
                state_vec["ttl_mean"] = 64.0
                state_vec["tcp_window_mean"] = 64240.0
                state_vec["window_start"] = t_start
                state_vec["attack_stage"] = 0
                state_vec["is_infiltrated"] = 0
                state_rows.append(state_vec)
                continue

            # Compute features
            flow_count = float(len(w_df))
            unique_src = float(w_df["src_ip"].nunique())
            unique_dst = float(w_df["dst_ip"].nunique())
            dst_ports = w_df["dst_port"].tolist()
            unique_dst_ports = float(len(set(dst_ports)))

            fwd_b = float(w_df["fwd_bytes"].sum()) if "fwd_bytes" in w_df else 64.0
            bwd_b = float(w_df["bwd_bytes"].sum()) if "bwd_bytes" in w_df else 64.0
            total_bytes = float(w_df["total_bytes"].sum()) if "total_bytes" in w_df else (fwd_b + bwd_b)

            fwd_p = float(w_df["fwd_packets"].sum()) if "fwd_packets" in w_df else 1.0
            bwd_p = float(w_df["bwd_packets"].sum()) if "bwd_packets" in w_df else 1.0
            total_packets = float(w_df["total_packets"].sum()) if "total_packets" in w_df else (fwd_p + bwd_p)

            # Bwd/Fwd ratios
            bytes_ratio = float(bwd_b) / float(fwd_b + 1.0)
            pkts_ratio = float(bwd_p) / float(fwd_p + 1.0)

            # IAT stats
            iat_mean = float(w_df["flow_iat_mean"].mean()) if "flow_iat_mean" in w_df else 20.0
            iat_std = float(w_df["flow_iat_std"].mean()) if "flow_iat_std" in w_df else 5.0
            iat_max = float(w_df["flow_iat_max"].max()) if "flow_iat_max" in w_df else 50.0

            # Flag counts normalized to total packets
            syn_cnt = float(w_df["flag_syn"].sum()) if "flag_syn" in w_df else 0.0
            ack_cnt = float(w_df["flag_ack"].sum()) if "flag_ack" in w_df else 0.0
            fin_cnt = float(w_df["flag_fin"].sum()) if "flag_fin" in w_df else 0.0
            rst_cnt = float(w_df["flag_rst"].sum()) if "flag_rst" in w_df else 0.0
            psh_cnt = float(w_df["flag_psh"].sum()) if "flag_psh" in w_df else 0.0
            urg_cnt = float(w_df["flag_urg"].sum()) if "flag_urg" in w_df else 0.0
            norm_pkts = max(total_packets, 1.0)

            flag_syn_ratio = min(syn_cnt / norm_pkts, 1.0)
            flag_ack_ratio = min(ack_cnt / norm_pkts, 1.0)
            flag_fin_ratio = min(fin_cnt / norm_pkts, 1.0)
            flag_rst_ratio = min(rst_cnt / norm_pkts, 1.0)
            flag_psh_ratio = min(psh_cnt / norm_pkts, 1.0)
            flag_urg_ratio = min(urg_cnt / norm_pkts, 1.0)

            # Packet-level features
            ttl_mean = float(w_df["ttl_mean"].mean()) if "ttl_mean" in w_df else 64.0
            ttl_var = float(w_df["ttl_var"].mean()) if "ttl_var" in w_df else 0.0
            win_mean = float(w_df["tcp_window_mean"].mean()) if "tcp_window_mean" in w_df else 64240.0
            win_min = float(w_df["tcp_window_mean"].min()) if "tcp_window_mean" in w_df else 64240.0

            payload_mean = total_bytes / norm_pkts
            payload_var = float(np.var(w_df["fwd_bytes"])) if len(w_df) > 1 else 0.0

            ip_frag = 0.0  # Fraction of frags
            port_entropy = calculate_entropy(dst_ports)
            retrans_rate = float(w_df["retransmissions"].sum()) / norm_pkts if "retransmissions" in w_df else 0.0

            # East-West ratio (internal-to-internal communications)
            internal_pairs = sum(
                1 for _, row in w_df.iterrows()
                if is_private_ip(row["src_ip"]) and is_private_ip(row["dst_ip"])
            )
            east_west_ratio = float(internal_pairs) / float(len(w_df))

            # Ground truth stage and infiltration status
            if "attack_stage" in w_df:
                # Mode of attack stages in window (or highest severity)
                stages = w_df["attack_stage"].tolist()
                stage = int(max(stages, key=stages.count))
            else:
                stage = 0

            is_infiltrated = 1 if stage > 0 else 0

            row_dict = {
                "window_start": t_start,
                "flow_count": flow_count,
                "unique_src_ips": unique_src,
                "unique_dst_ips": unique_dst,
                "unique_dst_ports": unique_dst_ports,
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "bytes_bwd_fwd_ratio": bytes_ratio,
                "packets_bwd_fwd_ratio": pkts_ratio,
                "iat_mean_ms": iat_mean,
                "iat_std_ms": iat_std,
                "iat_max_ms": iat_max,
                "flag_syn_ratio": flag_syn_ratio,
                "flag_ack_ratio": flag_ack_ratio,
                "flag_fin_ratio": flag_fin_ratio,
                "flag_rst_ratio": flag_rst_ratio,
                "flag_psh_ratio": flag_psh_ratio,
                "flag_urg_ratio": flag_urg_ratio,
                "ttl_mean": ttl_mean,
                "ttl_variance": ttl_var,
                "tcp_window_mean": win_mean,
                "tcp_window_min": win_min,
                "payload_size_mean": payload_mean,
                "payload_size_variance": payload_var,
                "ip_frag_ratio": ip_frag,
                "port_scan_entropy": port_entropy,
                "retransmission_rate": retrans_rate,
                "east_west_traffic_ratio": east_west_ratio,
                "attack_stage": stage,
                "is_infiltrated": is_infiltrated
            }
            state_rows.append(row_dict)

        df_state = pd.DataFrame(state_rows)
        return df_state

    def fit_scaler(self, df_state: pd.DataFrame):
        """Fits standardization parameters across state feature columns."""
        X = df_state[self.feature_names].values.astype(np.float32)
        self.scaler_mean = np.mean(X, axis=0)
        self.scaler_std = np.std(X, axis=0)
        self.scaler_std[self.scaler_std < 1e-6] = 1.0  # Prevent division by zero

    def transform_state(self, df_state: pd.DataFrame) -> np.ndarray:
        """Normalizes state features using fitted scaler parameters."""
        X = df_state[self.feature_names].values.astype(np.float32)
        if self.scaler_mean is None or self.scaler_std is None:
            # Fallback self-fit
            self.fit_scaler(df_state)
        return (X - self.scaler_mean) / self.scaler_std

    def inverse_transform_state(self, X_norm: np.ndarray) -> np.ndarray:
        """Denormalizes state features back to original physical units."""
        if self.scaler_mean is None or self.scaler_std is None:
            return X_norm
        return (X_norm * self.scaler_std) + self.scaler_mean

    def create_sequence_dataset(
        self,
        df_state: pd.DataFrame,
        seq_len: int = SEQUENCE_HISTORY_STEPS,
        rollout_k: int = DEFAULT_ROLLOUT_STEPS
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Creates sliding window training arrays:
        - X_seq: [N, seq_len, D] past observation states S_{t-seq_len+1:t}
        - Y_next_state: [N, D] target next network state S_{t+1} (for transition dynamics)
        - Y_rollout_infil: [N, rollout_k] infiltration labels for future k steps
        - Y_rollout_stages: [N, rollout_k] attack stages for future k steps
        """
        X_norm = self.transform_state(df_state)
        stages = df_state["attack_stage"].values.astype(np.int64)
        infil = df_state["is_infiltrated"].values.astype(np.float32)

        N_windows = len(df_state)
        X_list, y_next_list, y_infil_list, y_stage_list = [], [], [], []

        for t in range(seq_len - 1, N_windows - rollout_k):
            # Past observation window
            seq = X_norm[t - seq_len + 1 : t + 1]  # Shape: [seq_len, D]
            # Immediate next state for dynamics learning P(S_{t+1}|S_t)
            next_state = X_norm[t + 1]  # Shape: [D]
            # Future K steps for rollout forecasting
            fut_infil = infil[t + 1 : t + 1 + rollout_k]  # Shape: [K]
            fut_stage = stages[t + 1 : t + 1 + rollout_k]  # Shape: [K]

            X_list.append(seq)
            y_next_list.append(next_state)
            y_infil_list.append(fut_infil)
            y_stage_list.append(fut_stage)

        if not X_list:
            # Return empty arrays with correct dimensionality
            D = len(self.feature_names)
            return (
                np.empty((0, seq_len, D), dtype=np.float32),
                np.empty((0, D), dtype=np.float32),
                np.empty((0, rollout_k), dtype=np.float32),
                np.empty((0, rollout_k), dtype=np.int64)
            )

        return (
            np.array(X_list, dtype=np.float32),
            np.array(y_next_list, dtype=np.float32),
            np.array(y_infil_list, dtype=np.float32),
            np.array(y_stage_list, dtype=np.int64)
        )
