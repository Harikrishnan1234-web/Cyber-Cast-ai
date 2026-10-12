# CyberCast AI: 2-Minute Demo Video Walkthrough & Script
**National Technical Research Organisation (NTRO) / NCIIPC — Problem Statement ID 26153**
**Target Duration:** Exactly 120 Seconds (2 Minutes)

---

## Video Timeline & Script Breakdown

### [00:00 - 00:25] Introduction & The Flaw of Static Detection
- **Visual:** Screen shows SOC dashboard. Title banner: *CyberCast AI: World Model Attack Forecasting*.
- **Presenter Voiceover:**
  > "Traditional network intrusion detection classifies isolated flows statically. But an Advanced Persistent Threat isn't a single packet — it's a causal chain of events unfolding across time. By the time a static classifier flags exfiltration, your critical infrastructure is already breached.
  >
  > Welcome to **CyberCast AI**, an AI World Model developed for NTRO and Critical Information Infrastructure defense that learns network state-transition dynamics: $\mathcal{P}(S_{t+1} \mid S_{1:t})$."

### [00:25 - 00:55] Dual-Level Ingestion & Forward Rollout
- **Visual:** Presenter selects the *Synthetic APT Scenario* in the sidebar, showing the 5-second aggregation window. Points to the live metrics: SYN Ratio, Port Entropy, East-West Ratio, and Egress Volume.
- **Presenter Voiceover:**
  > "CyberCast AI fuses flow records with deep packet-level statistics — including TTL variance and TCP window size — into a continuous 27-dimensional network state vector.
  >
  > Rather than just classifying current traffic, our Temporal Transformer World Model performs an autoregressive forward rollout $K$ steps into the future. Here, at $t=25$, even though traffic appears low-volume, the model forecasts a transition to **Lateral Movement via SMB** with 89% probability in +35 seconds, complete with 95% epistemic confidence intervals."

### [00:55 - 01:25] Explainability & Counterfactual "What-If" Defense
- **Visual:** Switch to **Tab 2: Counterfactual What-If Defense**. Presenter activates *Zero-Trust SMB Port 445 Block*. The red baseline trajectory line splits, and the green counterfactual line drops sharply to zero risk. Below, the synthesized IPTables and Suricata rules are shown.
- **Presenter Voiceover:**
  > "Crucially, CyberCast AI provides both explainability and proactive intervention. Self-attention weights reveal exactly which historical time windows triggered the alarm, while feature attribution highlights destination port entropy.
  >
  > Because it is a World Model, we can ask: *What if we block port 445 now?* In real-time, the model simulates the counterfactual future, proving the attack trajectory collapses from 89% risk down to 3%. It automatically synthesizes production-ready IPTables and Suricata rules before the adversary can pivot."

### [01:25 - 01:50] Empirical Benchmarks (vs. Logistic Regression)
- **Visual:** Switch to **Tab 3: Empirical Benchmarks**. Highlighting the comparison table: Logistic Regression vs. Random Forest vs. CyberCast AI.
- **Presenter Voiceover:**
  > "In head-to-head empirical benchmarks on identical telemetry, CyberCast AI delivers a **+22% F1-score improvement** over baseline Logistic Regression and provides an **average early warning lead time of 54 seconds**, whereas static classifiers only sound the alarm reactively at impact."

### [01:50 - 02:00] 20-Point Legal Governance & Conclusion
- **Visual:** Switch to **Tab 5: Legal & Compliance Governance**. Green checkmarks across all 20 requirements, DPDP/GDPR Data Purge button, and air-gapped verification.
- **Presenter Voiceover:**
  > "Operating 100% locally with zero cloud dependencies, complete with a 20-point legal compliance framework and safe harbor protections, CyberCast AI shifts cyber defense from reactive triage to proactive foresight. Thank you."

---

## Pre-Recording Checklist
1. Launch app with `python app.py` (opens `http://127.0.0.1:8000`).
2. Ensure browser resolution is set to 1920x1080 (100% zoom).
3. Set scenario to *Complete Kill Chain (Recon -> Access -> Lateral -> C2 -> Exfil)*.
4. Set time window slider to $t=20$ to demonstrate the forward alert transition.
