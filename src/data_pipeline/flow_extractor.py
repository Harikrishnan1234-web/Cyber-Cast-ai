"""
Flow Extractor Module.
Ingests CSV flow records (e.g., CIC-IDS-2018, CTU-13, NetFlow/IPFIX)
and extracts structured flow-level features.
"""

import pandas as pd
import numpy as np
from typing import Dict, Any, Optional
import os


class FlowExtractor:
    """
    Extracts and standardizes flow-level telemetry features from CSV logs.
    Handles CIC-IDS-2018, CTU-13, and generic IPFIX/NetFlow formats.
    """

    # Column mappings for common dataset formats (CIC-IDS-2018 variations)
    COLUMN_ALIASES = {
        "timestamp": ["timestamp", "Timestamp", "Flow_Start_Time", "time", "Time"],
        "src_ip": ["src_ip", "Src IP", "Source IP", "srcip", "Source_IP"],
        "src_port": ["src_port", "Src Port", "Source Port", "sport", "Source_Port"],
        "dst_ip": ["dst_ip", "Dst IP", "Destination IP", "dstip", "Destination_IP"],
        "dst_port": ["dst_port", "Dst Port", "Destination Port", "dport", "Destination_Port"],
        "protocol": ["protocol", "Protocol", "proto"],
        "flow_duration": ["flow_duration", "Flow Duration", "duration", "Duration"],
        "fwd_packets": ["fwd_packets", "Tot Fwd Pkts", "Total Fwd Packets", "fwd_pkts", "Tot_Fwd_Pkts"],
        "bwd_packets": ["bwd_packets", "Tot Bwd Pkts", "Total Backward Packets", "bwd_pkts", "Tot_Bwd_Pkts"],
        "fwd_bytes": ["fwd_bytes", "TotLen Fwd Pkts", "Total Length of Fwd Packets", "fwd_bytes"],
        "bwd_bytes": ["bwd_bytes", "TotLen Bwd Pkts", "Total Length of Bwd Packets", "bwd_bytes"],
        "flag_syn": ["flag_syn", "SYN Flag Cnt", "SYN Flag Count", "syn_flag"],
        "flag_ack": ["flag_ack", "ACK Flag Cnt", "ACK Flag Count", "ack_flag"],
        "flag_fin": ["flag_fin", "FIN Flag Cnt", "FIN Flag Count", "fin_flag"],
        "flag_rst": ["flag_rst", "RST Flag Cnt", "RST Flag Count", "rst_flag"],
        "flag_psh": ["flag_psh", "PSH Flag Cnt", "PSH Flag Count", "psh_flag"],
        "flag_urg": ["flag_urg", "URG Flag Cnt", "URG Flag Count", "urg_flag"],
        "flow_iat_mean": ["flow_iat_mean", "Flow IAT Mean", "iat_mean"],
        "flow_iat_std": ["flow_iat_std", "Flow IAT Std", "iat_std"],
        "flow_iat_max": ["flow_iat_max", "Flow IAT Max", "iat_max"],
        "ttl_mean": ["ttl_mean", "TTL Mean", "Fwd Header Length"],
        "ttl_var": ["ttl_var", "TTL Var"],
        "tcp_window_mean": ["tcp_window_mean", "Init_Win_bytes_forward", "tcp_window"],
        "retransmissions": ["retransmissions", "Retransmissions", "Fwd Pkts/s"],
        "attack_stage": ["attack_stage", "Label", "label", "Attack", "stage"]
    }

    def __init__(self):
        pass

    def extract_from_csv(self, file_path_or_buffer) -> pd.DataFrame:
        """
        Reads CSV and maps column names to canonical internal names.
        Calculates bidirectional ratios and missing stats.
        Supports multi-encoding fallback (UTF-8, Latin1, CP1252) and auto-detects PCAP captures.
        """
        import io
        import tempfile

        if isinstance(file_path_or_buffer, str):
            if not os.path.exists(file_path_or_buffer):
                raise FileNotFoundError(f"Traffic file not found: {file_path_or_buffer}")
            with open(file_path_or_buffer, "rb") as f:
                raw_bytes = f.read()
        elif hasattr(file_path_or_buffer, "read"):
            raw_bytes = file_path_or_buffer.read()
            if hasattr(file_path_or_buffer, "seek"):
                file_path_or_buffer.seek(0)
        else:
            raw_bytes = bytes(file_path_or_buffer)

        # Check for PCAP magic bytes (e.g. 0xd4c3b2a1, 0xa1b2c3d4, 0x0a0d0d0a)
        PCAP_MAGICS = [
            b'\xd4\xc3\xb2\xa1',  # standard microsecond pcap (little-endian)
            b'\xa1\xb2\xc3\xd4',  # standard microsecond pcap (big-endian)
            b'\x4d\x3c\xb2\xa1',  # nanosecond pcap (little-endian)
            b'\xa1\xb2\x3c\x4d',  # nanosecond pcap (big-endian)
            b'\x0a\x0d\x0d\x0a'   # pcap-ng
        ]
        if any(raw_bytes.startswith(m) for m in PCAP_MAGICS):
            from src.data_pipeline.pcap_parser import PcapParser
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                tmp.write(raw_bytes)
                tmp_path = tmp.name
            try:
                parser = PcapParser(max_packets=50000)
                return parser.parse_pcap(tmp_path)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        # Multi-encoding CSV reading
        df = None
        for enc in ["utf-8", "utf-8-sig", "latin1", "cp1252", "iso-8859-1"]:
            try:
                df = pd.read_csv(io.BytesIO(raw_bytes), encoding=enc, low_memory=False)
                break
            except Exception:
                continue

        if df is None:
            # Fallback using python engine with delimiter sniffing and line skipping
            df = pd.read_csv(io.BytesIO(raw_bytes), encoding="latin1", sep=None, engine="python", on_bad_lines="skip")

        return self.standardize_dataframe(df)

    def standardize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Standardizes raw DataFrame columns and computes derived bidirectional metrics.
        """
        col_map = {}
        for canonical, aliases in self.COLUMN_ALIASES.items():
            for alias in aliases:
                if alias in df.columns:
                    col_map[alias] = canonical
                    break

        df_renamed = df.rename(columns=col_map)

        # Ensure essential columns exist, filling defaults if missing
        expected_cols = {
            "timestamp": 0.0,
            "src_ip": "192.168.1.100",
            "src_port": 50000,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": 6,
            "flow_duration": 1.0,
            "fwd_packets": 1,
            "bwd_packets": 1,
            "fwd_bytes": 64,
            "bwd_bytes": 64,
            "flag_syn": 0,
            "flag_ack": 1,
            "flag_fin": 0,
            "flag_rst": 0,
            "flag_psh": 0,
            "flag_urg": 0,
            "flow_iat_mean": 20.0,
            "flow_iat_std": 5.0,
            "flow_iat_max": 50.0,
            "ttl_mean": 64.0,
            "ttl_var": 0.0,
            "tcp_window_mean": 64240.0,
            "retransmissions": 0,
            "attack_stage": 0
        }

        for col, default_val in expected_cols.items():
            if col not in df_renamed.columns:
                df_renamed[col] = default_val

        # Compute total metrics and bidirectional flow ratios
        df_renamed["total_packets"] = df_renamed["fwd_packets"] + df_renamed["bwd_packets"]
        df_renamed["total_bytes"] = df_renamed["fwd_bytes"] + df_renamed["bwd_bytes"]

        # Bidirectional flow ratios with numerical stability
        df_renamed["bytes_bwd_fwd_ratio"] = (
            df_renamed["bwd_bytes"].astype(float) / (df_renamed["fwd_bytes"].astype(float) + 1.0)
        )
        df_renamed["packets_bwd_fwd_ratio"] = (
            df_renamed["bwd_packets"].astype(float) / (df_renamed["fwd_packets"].astype(float) + 1.0)
        )

        # Convert timestamps to float seconds if needed
        if df_renamed["timestamp"].dtype == object:
            try:
                df_renamed["timestamp"] = pd.to_datetime(df_renamed["timestamp"]).astype(int) / 1e9
            except Exception:
                # If not ISO datetime, try numeric conversion
                df_renamed["timestamp"] = pd.to_numeric(df_renamed["timestamp"], errors="coerce").fillna(0.0)

        # Sort chronologically
        df_renamed = df_renamed.sort_values(by="timestamp").reset_index(drop=True)

        return df_renamed
