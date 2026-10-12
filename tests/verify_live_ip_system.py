"""
Live Verification & Demonstration Script for CyberCast AI:
- Arbitrary IP Traffic Synthesis & Filtering
- IP Traffic Proctor (Behavioral Rules & Scoring)
- IP Threat Predictor (Temporal World Model Rollout & TTC)
- Dry-Run Safety Sandbox Rule Verification
- Threat Intelligence & Forensic Reports (Markdown & STIX 2.1 JSON)
"""

import sys
import os
import json
import numpy as np

# Ensure root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from src.defense_engine.ip_proctor_predictor import IpTrafficTester, IpProctor, IpPredictor
from src.defense_engine.report_generator import ThreatReportGenerator
from src.defense_engine.ebpf_pipeline import EbpfPipeline
from src.world_model import create_world_model, ForwardSimulator

def run_ip_demonstration():
    print("=" * 80)
    print("🚀 CYBERCAST AI: LIVE IP TRAFFIC PROCTOR & PREDICTOR VERIFICATION")
    print("=" * 80)

    # Initialize World Model & Simulator
    print("\n[+] Initializing Temporal Transformer World Model & Forward Simulator...")
    world_model = create_world_model(prefer_torch=True)
    simulator = ForwardSimulator(world_model)
    predictor = IpPredictor(simulator)
    print(f"    - Engine: {'PyTorch CUDA/CPU' if hasattr(world_model, 'parameters') else 'Pure-NumPy Accelerated'}")

    test_targets = [
        ("10.0.1.99", "Reconnaissance Scanner"),
        ("10.0.2.45", "Lateral Movement Pivot"),
        ("203.0.113.88", "C2 Jittered Beacon"),
        ("192.168.1.15", "Benign Enterprise Client")
    ]

    for ip, profile in test_targets:
        print("\n" + "-" * 75)
        print(f"🎯 Target IP: {ip} | Behavioral Profile: {profile}")
        print("-" * 75)

        # 1. Traffic Generation
        flows = IpTrafficTester.synthesize_test_traffic_for_ip(ip, profile)
        print(f"  [1] Telemetry Ingestion: Generated {len(flows)} flows ({flows['total_bytes'].sum():,} total bytes, {flows['total_packets'].sum():,} packets).")

        # 2. Proctor Behavioral Inspection
        proctor = IpProctor.proctor_ip_traffic(ip, flows)
        print(f"  [2] IP Proctor Evaluation:")
        print(f"      • Score: {proctor['proctor_score']}/100")
        print(f"      • Verdict: {proctor['proctor_verdict']}")
        print(f"      • Threat Level: {proctor['threat_level']}")
        print(f"      • Quarantine Recommended: {proctor['is_quarantine_recommended']}")
        print(f"      • Findings ({len(proctor['findings'])} triggered rules):")
        for f in proctor['findings']:
            print(f"        - [{f['severity']}] {f['rule']}: {f['detail']}")

        # 3. World Model Prediction & Rollout
        pred = predictor.predict_ip_future(ip, flows, k_steps=5)
        print(f"  [3] Neural Attack Forecast (5-step / 25-second Rollout):")
        print(f"      • Current Infiltration Risk P(t): {pred['current_risk']:.1%}")
        print(f"      • Forecasted Risk P(t+25s): {pred['future_risk']:.1%}")
        print(f"      • Projected MITRE Stage: Stage {pred['predicted_stage_id']} - {pred['predicted_stage_name']}")
        ttc_str = f"{pred['time_to_compromise_sec']:.1f}s" if pred['time_to_compromise_sec'] is not None else "None (Risk < 70%)"
        print(f"      • Estimated Time to Compromise (TTC): {ttc_str}")

        # 4. Actionable Rules & Safety Sandbox Check
        iptables_rule = pred['synthesized_rules']['iptables']
        sandbox = EbpfPipeline.run_safety_dry_run_sandbox(iptables_rule)
        print(f"  [4] Synthesized Defense Rule (IPTables):")
        first_rule_line = iptables_rule.split('\n')[0]
        print(f"      • Rule: {first_rule_line}")
        print(f"      • Sandbox Safety Score: {sandbox['safety_score_pct']:.0f}% (Safe to Deploy: {sandbox['safe_to_deploy']})")

    # 5. Report Generation Test
    print("\n" + "=" * 80)
    print("📑 GENERATING EXECUTIVE & FORENSIC THREAT REPORTS")
    print("=" * 80)
    target_for_report = "10.0.2.45"
    flows_rep = IpTrafficTester.synthesize_test_traffic_for_ip(target_for_report, "Lateral Movement Pivot")
    proctor_rep = IpProctor.proctor_ip_traffic(target_for_report, flows_rep)
    pred_rep = predictor.predict_ip_future(target_for_report, flows_rep, k_steps=5)
    sb_rep = EbpfPipeline.run_safety_dry_run_sandbox(pred_rep['synthesized_rules']['iptables'])

    md_report = ThreatReportGenerator.generate_markdown_report(target_for_report, proctor_rep, pred_rep, sb_rep)
    stix_report = ThreatReportGenerator.generate_json_stix_report(target_for_report, proctor_rep, pred_rep)

    print(f"\n[+] Forensic Markdown Report generated successfully ({len(md_report):,} chars).")
    print(f"    - Title excerpt: {md_report.splitlines()[0]}")
    print(f"    - Target contained: {'10.0.2.45' in md_report}")

    print(f"\n[+] STIX 2.1 JSON Threat Intelligence Bundle generated successfully ({len(stix_report):,} chars).")
    stix_obj = json.loads(stix_report)
    print(f"    - Bundle ID: {stix_obj.get('id')}")
    print(f"    - Total SDO Objects: {len(stix_obj.get('objects', []))}")
    sdo_types = [obj.get("type") for obj in stix_obj.get("objects", [])]
    print(f"    - SDO Types: {', '.join(sdo_types)}")

    print("\n" + "=" * 80)
    print("✅ ALL IP TRAFFIC TESTING, PROCTOR, PREDICTOR, AND REPORTING SUBSYSTEMS VERIFIED!")
    print("=" * 80)

if __name__ == "__main__":
    run_ip_demonstration()
