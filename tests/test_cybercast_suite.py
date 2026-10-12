"""
CyberCast AI - Automated Defensive Test Suite
Comprehensive End-to-End Verification of all 8 core subsystems:
1. System Configuration & Dimension Alignment (R^27)
2. Telemetry Generation & Multi-Scale Aggregation
3. Flow Extractor & Multi-Encoding Ingestion
4. Neural World Model & Forward Simulator
5. MITRE ATT&CK Mapping & Actionable Rule Synthesis
6. Empirical Benchmarks Engine (vs Static Baselines)
7. 20-Point Defense Compliance & Air-Gapped Governance
8. Linux eBPF/XDP Line-Rate Probe & Safety Dry-Run Sandbox
"""

import sys
import os
import unittest
import io
import numpy as np
import pandas as pd

# Add workspace root to path
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from src.config import (
    STATE_FEATURE_NAMES,
    NUM_STATE_FEATURES,
    WINDOW_SIZE_SECONDS,
    DEFAULT_ROLLOUT_STEPS,
    MITRE_STAGES,
    MITRE_STAGE_COLORS,
    MITRE_STAGE_PLAYBOOKS
)
from src.data_pipeline.generator import TrafficGenerator
from src.data_pipeline.aggregator import StateAggregator
from src.data_pipeline.flow_extractor import FlowExtractor
from src.world_model.dynamics_model import NetworkWorldModel, NumpyWorldModel, create_world_model
from src.world_model.simulator import ForwardSimulator
from src.world_model.mitre_mapper import MitreMapper
from src.benchmarks.benchmark_engine import BenchmarkEngine
import json
from src.compliance.legal_governance import LegalGovernance
from src.defense_engine.ebpf_pipeline import EbpfPipeline
from src.defense_engine.ip_proctor_predictor import IpTrafficTester, IpProctor, IpPredictor
from src.defense_engine.report_generator import ThreatReportGenerator
from src.defense_engine.soc_copilot import SocCopilot
from src.data_store.database import CyberCastDatabase
from src.api.rest_api import app as fastapi_app
from src.data_pipeline.zeek_suricata_parser import ZeekSuricataParser
from fastapi.testclient import TestClient


class TestConfiguration(unittest.TestCase):
    """Test 1: Verify State Dimensions and Constants."""

    def test_feature_dimensions(self):
        self.assertEqual(NUM_STATE_FEATURES, 27, "State feature count must be exactly 27")
        self.assertEqual(len(STATE_FEATURE_NAMES), 27, "STATE_FEATURE_NAMES must have 27 elements")
        self.assertIn("flag_syn_ratio", STATE_FEATURE_NAMES)
        self.assertIn("east_west_traffic_ratio", STATE_FEATURE_NAMES)
        self.assertIn("port_scan_entropy", STATE_FEATURE_NAMES)

    def test_mitre_stages(self):
        self.assertEqual(len(MITRE_STAGES), 6, "Must define stages 0 through 5")
        for i in range(6):
            self.assertIn(i, MITRE_STAGES)
            self.assertIn(i, MITRE_STAGE_COLORS)
            self.assertIn(i, MITRE_STAGE_PLAYBOOKS)


class TestDataPipeline(unittest.TestCase):
    """Test 2: Verify Telemetry Generation and State Aggregation."""

    def setUp(self):
        self.gen = TrafficGenerator(seed=42)

    def test_synthetic_generation(self):
        df_flows = self.gen.generate_scenario(duration_seconds=120, flows_per_second=6.0, attack_start_time=30)
        self.assertIsInstance(df_flows, pd.DataFrame)
        self.assertGreater(len(df_flows), 100, "Generator should produce sufficient flows")
        self.assertIn("src_ip", df_flows.columns)
        self.assertIn("dst_ip", df_flows.columns)
        self.assertIn("total_bytes", df_flows.columns)
        self.assertIn("attack_stage", df_flows.columns)

    def test_multiscale_aggregation(self):
        df_flows = self.gen.generate_scenario(duration_seconds=150, flows_per_second=8.0, attack_start_time=20)
        # Test 5s, 15s, and 30s resolutions
        for window in [5, 15, 30]:
            aggregator = StateAggregator(window_size=window)
            df_states = aggregator.aggregate_flows(df_flows)
            self.assertGreaterEqual(len(df_states), 3, f"Must have windows for {window}s scale")
            # Verify all 27 feature columns exist and are finite
            for col in STATE_FEATURE_NAMES:
                self.assertIn(col, df_states.columns, f"Feature column {col} must exist in aggregated state")
                self.assertFalse(df_states[col].isnull().any(), f"Column {col} must have no NaN values")
                self.assertFalse(np.isinf(df_states[col]).any(), f"Column {col} must have no Inf values")

    def test_flow_extractor_csv(self):
        extractor = FlowExtractor()
        # Create small test CSV buffer
        csv_data = "src_ip,dst_ip,src_port,dst_port,protocol,tot_bytes,tot_pkts,duration_ms,flag_syn,flag_ack\n10.0.1.5,10.0.2.10,44321,80,TCP,1024,4,12.5,1,1\n10.0.1.6,10.0.2.11,44322,443,TCP,4096,12,45.0,0,1\n"
        csv_buffer = io.BytesIO(csv_data.encode("utf-8"))
        df = extractor.extract_from_csv(csv_buffer)
        self.assertEqual(len(df), 2)
        self.assertIn("total_bytes", df.columns)
        self.assertIn("attack_stage", df.columns)


class TestWorldModelAndSimulator(unittest.TestCase):
    """Test 3: Verify Neural World Model, Dual Backends & Forward Simulator."""

    def setUp(self):
        self.gen = TrafficGenerator(seed=123)
        self.df_flows = self.gen.generate_scenario(duration_seconds=180, attack_start_time=40)
        self.aggregator = StateAggregator(window_size=5)
        self.df_states = self.aggregator.aggregate_flows(self.df_flows)
        self.state_seq = self.df_states[STATE_FEATURE_NAMES].values[:10]

    def test_world_model_creation(self):
        # Test creation of both backends
        model = create_world_model(prefer_torch=True)
        self.assertIsNotNone(model)
        # Test NumPy fallback engine explicitly
        numpy_model = NumpyWorldModel()
        next_s, p_infil, logits = numpy_model.forward(self.state_seq)
        self.assertEqual(len(next_s), 27)
        self.assertTrue(0.0 <= float(np.array(p_infil).flatten()[0]) <= 1.0)
        self.assertEqual(len(np.array(logits).flatten()), 6)

    def test_lstm_and_gru_world_models(self):
        """Verify SIH 2026 Step 4: LSTM and GRU temporal learning architectures."""
        lstm_model = create_world_model(prefer_torch=True, model_type="lstm")
        gru_model = create_world_model(prefer_torch=True, model_type="gru")
        self.assertIsNotNone(lstm_model)
        self.assertIsNotNone(gru_model)

        for m in [lstm_model, gru_model]:
            sim = ForwardSimulator(m)
            res = sim.rollout(self.state_seq, k_steps=5)
            self.assertEqual(len(res["predicted_stages"]), 6)
            self.assertEqual(len(res["infiltration_probabilities"]), 6)
            self.assertTrue(0.0 <= res["infiltration_probabilities"][-1] <= 1.0)

    def test_forward_simulator_rollout(self):
        model = create_world_model(prefer_torch=True)
        simulator = ForwardSimulator(model)
        k_steps = 7
        res = simulator.rollout(self.state_seq, k_steps=k_steps)

        self.assertEqual(len(res["timeline_steps"]), k_steps + 1)
        self.assertEqual(len(res["infiltration_probabilities"]), k_steps + 1)
        self.assertEqual(len(res["predicted_stages"]), k_steps + 1)
        self.assertEqual(len(res["predicted_states"]), k_steps)
        self.assertEqual(len(res["attention_weights"]), len(self.state_seq))
        self.assertEqual(len(res["feature_attributions"]), 27)

        # Uncertainty bounds validity
        for low, p, high in zip(res["infiltration_uncertainty_lower"], res["infiltration_probabilities"], res["infiltration_uncertainty_upper"]):
            self.assertLessEqual(low, p + 1e-5)
            self.assertGreaterEqual(high, p - 1e-5)
            self.assertTrue(0.0 <= p <= 1.0)

        # Zero-Day Divergence attributes present
        self.assertIn("is_zero_day_vector", res)
        self.assertIn("ood_divergence_score", res)
        self.assertIn("zero_day_confidence", res)

    def test_counterfactual_defense_simulation(self):
        model = create_world_model(prefer_torch=True)
        simulator = ForwardSimulator(model)
        for action in ["block_smb_lateral", "rate_limit_syn", "dns_sinkhole_c2", "emergency_egress_throttle"]:
            cf = simulator.simulate_counterfactual_comparison(self.state_seq, action_name=action, k_steps=6)
            self.assertIn("baseline", cf)
            self.assertIn("intervened", cf)
            self.assertIn("risk_reduction_pct", cf)
            self.assertIn("defense_success", cf)
            self.assertIsInstance(cf["risk_reduction_pct"], (int, float))


class TestMitreMapper(unittest.TestCase):
    """Test 4: Verify MITRE ATT&CK Mapper and Actionable Rule Generators."""

    def test_stage_info_retrieval(self):
        for stage_id in range(6):
            info = MitreMapper.get_stage_info(stage_id)
            self.assertIn("name", info)
            self.assertIn("color", info)
            self.assertIn("description", info)
            self.assertIn("playbook", info)

        # Test out-of-range clip
        clipped_info = MitreMapper.get_stage_info(99)
        self.assertEqual(clipped_info["name"], MITRE_STAGES[5])

    def test_actionable_rule_synthesis(self):
        rules = MitreMapper.generate_actionable_rules(stage_id=3, target_ip="10.0.1.50")
        self.assertIn("iptables", rules)
        self.assertIn("suricata", rules)
        self.assertIn("powershell", rules)
        self.assertIn("zeek", rules)
        self.assertIn("DROP", rules["iptables"])
        self.assertIn("New-NetFirewallRule", rules["powershell"])


class TestEmpiricalBenchmarks(unittest.TestCase):
    """Test 5: Verify Reproducible Benchmark Engine (vs Static Baselines)."""

    def test_benchmark_run(self):
        model = create_world_model(prefer_torch=True)
        engine = BenchmarkEngine(model)
        results = engine.run_benchmark()

        self.assertIn("metrics", results)
        self.assertIn("world_model", results["metrics"])
        self.assertIn("logistic_regression", results["metrics"])
        self.assertIn("random_forest", results["metrics"])

        wm_f1 = results["metrics"]["world_model"]["f1"]
        lr_f1 = results["metrics"]["logistic_regression"]["f1"]
        self.assertGreater(wm_f1, lr_f1, "World Model should outperform static Logistic Regression in F1")
        self.assertGreater(results["lead_time_advantage_seconds"], 0, "World Model must exhibit positive lead time advantage")


class TestComplianceGovernance(unittest.TestCase):
    """Test 6: Verify 20-Point Compliance and Air-Gapped Governance."""

    def test_compliance_audit(self):
        audit = LegalGovernance.get_full_compliance_audit()
        self.assertEqual(len(audit), 20, "Legal audit checklist must verify exactly 20 points")
        for item in audit:
            self.assertIn("id", item)
            self.assertIn("requirement", item)
            self.assertEqual(item["status"], "VERIFIED")

    def test_airgap_and_data_inventory(self):
        api_audit = LegalGovernance.API_AUDIT
        self.assertEqual(api_audit["external_calls_detected"], 0)
        self.assertIn("BLOCKED", api_audit["telemetry_egress"])
        self.assertGreaterEqual(len(LegalGovernance.DATA_INVENTORY), 5)
        self.assertGreaterEqual(len(LegalGovernance.LICENSE_ATTRIBUTIONS), 4)


class TestEbpfAndDefenseEngine(unittest.TestCase):
    """Test 7: Verify Linux eBPF/XDP Probe & Dry-Run Safety Sandbox."""

    def test_ebpf_xdp_source(self):
        c_code = EbpfPipeline.get_xdp_source_code()
        self.assertIn("SEC(\"xdp\")", c_code)
        self.assertIn("cybercast_telemetry_collector", c_code)
        self.assertIn("BPF_MAP_TYPE_PERCPU_ARRAY", c_code)

    def test_ebpf_throughput_benchmark(self):
        perf = EbpfPipeline.run_throughput_benchmark()
        self.assertGreater(perf["ebpf_packets_per_sec"], 10000000.0, "eBPF must demonstrate line-rate > 10M pkts/sec")
        self.assertGreater(perf["speedup_vs_python"], 1000, "eBPF must be >1000x faster than Scapy")

    def test_safety_dry_run_sandbox(self):
        # Safe rule
        safe_audit = EbpfPipeline.run_safety_dry_run_sandbox("iptables -A FORWARD -s 192.168.1.100 -j DROP")
        self.assertTrue(safe_audit["safe_to_deploy"])
        self.assertEqual(safe_audit["safety_score_pct"], 100)

        # Conflicting rule targeting Active Directory DC
        conflict_audit = EbpfPipeline.run_safety_dry_run_sandbox("iptables -A FORWARD -d 10.0.2.50 -j DROP")
        self.assertFalse(conflict_audit["safe_to_deploy"])
        self.assertLess(conflict_audit["safety_score_pct"], 100)
        self.assertIn("Domain Controller / Active Directory", conflict_audit["flagged_conflicts"])


class TestWebApp(unittest.TestCase):
    """Test 8: Verify CyberCast AI Web Application UI & Endpoints."""

    def test_web_app_dashboard_serving(self):
        from app import app as web_app
        client = TestClient(web_app)
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("CYBERCAST AI", resp.text)
        self.assertIn("SOC MISSION CONTROL", resp.text)

    def test_web_app_forecast_rollout_endpoint(self):
        from app import app as web_app
        client = TestClient(web_app)
        resp = client.post("/api/v1/forecast/rollout", json={"time_index": 10, "k_steps": 5})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("rollout", data)
        self.assertIn("infiltration_probabilities", data["rollout"])

    def test_web_app_telemetry_upload(self):
        from app import app as web_app
        client = TestClient(web_app)
        sample_csv = "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,flow_duration,fwd_packets,bwd_packets,fwd_bytes,bwd_bytes,flag_syn,flag_ack,flag_fin,flag_rst,flag_psh,flag_urg,flow_iat_mean,flow_iat_std,flow_iat_max,ttl_mean,ttl_var,tcp_window_mean,retransmissions,attack_stage\n0.0,192.168.1.10,1234,10.0.1.5,80,6,100,5,5,500,500,1,1,0,0,0,0,20,5,30,64,0,1024,0,0\n"
        resp = client.post("/api/v1/telemetry/upload", files={"file": ("test_flows.csv", sample_csv.encode("utf-8"), "text/csv")})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "success")
        self.assertGreaterEqual(resp.json()["flow_count"], 1)


class TestIpProctorAndPredictor(unittest.TestCase):
    """Test 9: Verify Arbitrary IP Traffic Testing, Proctor & Predictor."""

    def test_ip_traffic_synthesis_and_extraction(self):
        flows = IpTrafficTester.synthesize_test_traffic_for_ip("192.168.1.105", "Reconnaissance Scanner")
        self.assertFalse(flows.empty)
        self.assertIn("src_ip", flows.columns)
        extracted = IpTrafficTester.extract_ip_telemetry(flows, "192.168.1.105")
        self.assertEqual(len(extracted), len(flows))

    def test_ip_proctor_inspection(self):
        # Suspicious scanner IP
        scan_flows = IpTrafficTester.synthesize_test_traffic_for_ip("10.0.1.99", "Reconnaissance Scanner")
        proctor_scan = IpProctor.proctor_ip_traffic("10.0.1.99", scan_flows)
        self.assertIn(proctor_scan["proctor_verdict"], ["PROBABLE_THREAT", "CRITICAL_INTRUSION", "SUSPICIOUS_ANOMALY"])
        self.assertGreater(proctor_scan["proctor_score"], 20)
        self.assertGreater(len(proctor_scan["findings"]), 0)

        # Benign client IP
        benign_flows = IpTrafficTester.synthesize_test_traffic_for_ip("10.0.2.15", "Benign Enterprise Client")
        proctor_benign = IpProctor.proctor_ip_traffic("10.0.2.15", benign_flows)
        self.assertIn(proctor_benign["proctor_verdict"], ["CLEAN_OPERATIONAL", "SUSPICIOUS_ANOMALY"])
        self.assertLess(proctor_benign["proctor_score"], 50)

    def test_ip_predictor_forecast(self):
        model = create_world_model(prefer_torch=True)
        sim = ForwardSimulator(model)
        predictor = IpPredictor(sim)
        flows = IpTrafficTester.synthesize_test_traffic_for_ip("10.0.1.44", "Lateral Movement Pivot")
        pred_res = predictor.predict_ip_future("10.0.1.44", flows, k_steps=5)

        self.assertIn("target_ip", pred_res)
        self.assertIn("future_risk", pred_res)
        self.assertIn("predicted_stage_name", pred_res)
        self.assertIn("synthesized_rules", pred_res)
        self.assertIn("10.0.1.44", pred_res["synthesized_rules"]["iptables"])


class TestThreatReportGenerator(unittest.TestCase):
    """Test 10: Verify Threat Intelligence & Forensic Incident Report Generator."""

    def test_markdown_and_stix_reports(self):
        flows = IpTrafficTester.synthesize_test_traffic_for_ip("192.168.1.200", "High-Volume Data Exfiltrator")
        proctor = IpProctor.proctor_ip_traffic("192.168.1.200", flows)
        model = create_world_model(prefer_torch=True)
        sim = ForwardSimulator(model)
        pred = IpPredictor(sim).predict_ip_future("192.168.1.200", flows, k_steps=5)
        sb = EbpfPipeline.run_safety_dry_run_sandbox(pred["synthesized_rules"]["iptables"])

        md_rep = ThreatReportGenerator.generate_markdown_report("192.168.1.200", proctor, pred, sb)
        self.assertIn("CYBERCAST AI • THREAT INTELLIGENCE", md_rep)
        self.assertIn("192.168.1.200", md_rep)
        self.assertIn("Proctor Security Verdict", md_rep)

        json_rep = ThreatReportGenerator.generate_json_stix_report("192.168.1.200", proctor, pred)
        stix_obj = json.loads(json_rep)
        self.assertEqual(stix_obj["target_ip"], "192.168.1.200")
        self.assertIn("world_model_prediction", stix_obj)
        self.assertIn("compliance_attestation", stix_obj)


class TestCyberCastDatabase(unittest.TestCase):
    """Test 11: Verify Data Tier (PostgreSQL/SQLite) Schemas & Cryptographic Evidence."""

    def setUp(self):
        self.db = CyberCastDatabase()

    def test_database_crud_and_hashes(self):
        # 1. Create and verify incident case
        case = self.db.create_case(
            title="Automated Test APT Case",
            severity="CRITICAL",
            assigned_to="Unit Test Analyst",
            target_ip="192.168.10.50",
            mitre_stage="Stage 3 - Lateral Movement",
            notes="Testing database persistence"
        )
        self.assertIsNotNone(case)
        self.assertEqual(case["status"], "OPEN")

        # 2. Update case status
        updated = self.db.update_case_status(case["case_id"], "CONTAINED", "Containment confirmed.")
        self.assertTrue(updated)
        fetched = self.db.get_case(case["case_id"])
        self.assertEqual(fetched["status"], "CONTAINED")

        # 3. Store and verify digital evidence artifact (SHA-256)
        ev_data = json.dumps({"test_event": "port_scan", "ip": "192.168.10.50"})
        stored = self.db.store_evidence(
            case_id=case["case_id"],
            artifact_type="FLOW_LOG",
            file_name="unit_test_evidence.json",
            content=ev_data,
            analyst="Digital Forensics Lead"
        )
        self.assertIn("file_hash_sha256", stored)

        # Cryptographic verification
        ver = self.db.verify_evidence(stored["evidence_id"])
        self.assertTrue(ver["valid"], "SHA-256 integrity verification must pass")
        self.assertEqual(ver["calculated_hash"], stored["file_hash_sha256"])


class TestFastApiBackend(unittest.TestCase):
    """Test 12: Verify FastAPI REST API, RBAC Authentication & Case Services."""

    def setUp(self):
        self.client = TestClient(fastapi_app)

    def test_health_and_pipeline_endpoints(self):
        resp_health = self.client.get("/api/v1/health")
        self.assertEqual(resp_health.status_code, 200)
        data = resp_health.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("Air-Gapped", data["deployment_mode"])

        resp_pipe = self.client.get("/api/v1/pipeline")
        self.assertEqual(resp_pipe.status_code, 200)
        pipe_data = resp_pipe.json()
        self.assertIn("traffic → temporal learning → forecast → ATT&CK mapping → early warning", pipe_data["flow"])
        self.assertEqual(len(pipe_data["steps"]), 5)

    def test_rbac_and_cases_api(self):
        # Authorized request with Bearer token
        headers = {"Authorization": "Bearer key-soc-analyst-196601"}
        resp_cases = self.client.get("/api/v1/cases", headers=headers)
        self.assertEqual(resp_cases.status_code, 200)
        self.assertIn("cases", resp_cases.json())

        # Create case via REST API
        new_case_payload = {
            "title": "API Automated Breach Probe",
            "severity": "HIGH",
            "target_ip": "172.16.0.4",
            "mitre_stage": "Stage 2 - Initial Access",
            "notes": "FastAPI REST validation"
        }
        resp_create = self.client.post("/api/v1/cases", json=new_case_payload, headers=headers)
        self.assertEqual(resp_create.status_code, 200)
        case_id = resp_create.json()["case"]["case_id"]

        # Containment execution via API
        contain_payload = {"playbook_action": "block_smb_lateral", "target_ip": "172.16.0.4"}
        resp_contain = self.client.post(f"/api/v1/cases/{case_id}/contain", json=contain_payload, headers=headers)
        self.assertEqual(resp_contain.status_code, 200)
        self.assertEqual(resp_contain.json()["containment_status"], "SUCCESS")


class TestZeekSuricataParser(unittest.TestCase):
    """Test 13: Verify Zeek & Suricata Telemetry Ingestion & Feature Engineering."""

    def setUp(self):
        self.parser = ZeekSuricataParser()

    def test_zeek_parsing_and_feature_extraction(self):
        sample_zeek_json = (
            '{"ts": 1700000000.0, "id.orig_h": "10.0.1.15", "id.orig_p": 49152, "id.resp_h": "10.0.1.99", "id.resp_p": 445, "proto": "tcp", "orig_bytes": 1024, "resp_bytes": 4096, "conn_state": "SF"}\n'
            '{"ts": 1700000001.0, "id.orig_h": "10.0.1.15", "id.orig_p": 49153, "id.resp_h": "10.0.1.99", "id.resp_p": 139, "proto": "tcp", "orig_bytes": 512, "resp_bytes": 1024, "conn_state": "S0"}\n'
        )
        df_zeek = self.parser.parse_zeek_conn_log(sample_zeek_json)
        self.assertEqual(len(df_zeek), 2)
        self.assertIn("total_bytes", df_zeek.columns)
        self.assertIn("flag_syn", df_zeek.columns)

        # Feature engineering into continuous 27-D state
        vec_27 = self.parser.extract_features(df_zeek)
        self.assertEqual(vec_27.shape, (1, 27))
        self.assertEqual(vec_27[0, 0], 2.0) # 2 flows

    def test_suricata_eve_parsing(self):
        sample_eve = (
            '{"event_type": "flow", "src_ip": "192.168.1.10", "dest_ip": "203.0.113.5", "src_port": 50000, "dest_port": 80, "proto": "TCP", "flow": {"bytes_toserver": 500, "bytes_toclient": 1200, "pkts_toserver": 5, "pkts_toclient": 8}}\n'
            '{"event_type": "alert", "src_ip": "192.168.1.10", "dest_ip": "203.0.113.5", "alert": {"signature": "ET SCAN Potential Port Scan"}}\n'
        )
        df_suricata = self.parser.parse_suricata_eve(sample_eve)
        self.assertEqual(len(df_suricata), 2)
        self.assertIn("event_type", df_suricata.columns)


class TestSocCopilot(unittest.TestCase):
    """Test 14: Verify SOC AI Copilot Data Analysis & 'How It Can Be Better' Reasoning."""

    def test_copilot_direct_analysis_and_improvements(self):
        ctx = {
            "current_stage_name": "Stage 1 - Reconnaissance (T1595)",
            "projected_stage_name": "Stage 3 - Lateral Movement (T1021.002)",
            "current_risk": 0.65,
            "future_risk": 0.88,
            "target_ip": "10.0.1.99",
            "proctor_score": 85,
            "proctor_verdict": "CRITICAL_INTRUSION"
        }
        res = SocCopilot.generate_response("How can we mitigate the projected lateral movement?", ctx)
        self.assertEqual(res["status"], "success")
        self.assertIn("10.0.1.99", res["response"])
        self.assertIn("How It Can Be Better", res["response"])
        self.assertGreaterEqual(len(res["improvements"]), 3)

        # Test IP specific query
        res_ip = SocCopilot.generate_response("Audit target IP 10.0.1.99 risk", ctx)
        self.assertIn("CRITICAL_INTRUSION", res_ip["response"])
        self.assertIn("How It Can Be Better", res_ip["response"])
        self.assertGreaterEqual(len(res_ip["improvements"]), 3)

    def test_copilot_api_endpoint(self):
        from app import app as web_app
        client = TestClient(web_app)
        resp = client.post("/api/v1/copilot/chat", json={"message": "Analyze current network risk"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("response", data)
        self.assertIn("How It Can Be Better", data["response"])
        self.assertIn("improvements", data)
        self.assertGreaterEqual(len(data["improvements"]), 3)


def run_all_tests():
    """Execute the full test suite with clean formatted report."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(TestConfiguration))
    suite.addTest(loader.loadTestsFromTestCase(TestDataPipeline))
    suite.addTest(loader.loadTestsFromTestCase(TestWorldModelAndSimulator))
    suite.addTest(loader.loadTestsFromTestCase(TestMitreMapper))
    suite.addTest(loader.loadTestsFromTestCase(TestEmpiricalBenchmarks))
    suite.addTest(loader.loadTestsFromTestCase(TestComplianceGovernance))
    suite.addTest(loader.loadTestsFromTestCase(TestEbpfAndDefenseEngine))
    suite.addTest(loader.loadTestsFromTestCase(TestWebApp))
    suite.addTest(loader.loadTestsFromTestCase(TestIpProctorAndPredictor))
    suite.addTest(loader.loadTestsFromTestCase(TestThreatReportGenerator))
    suite.addTest(loader.loadTestsFromTestCase(TestCyberCastDatabase))
    suite.addTest(loader.loadTestsFromTestCase(TestFastApiBackend))
    suite.addTest(loader.loadTestsFromTestCase(TestZeekSuricataParser))
    suite.addTest(loader.loadTestsFromTestCase(TestSocCopilot))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
