"""
Forward Simulation Engine for CyberCast AI World Model.
Performs K-step autoregressive forward rollouts into future time horizons,
computes infiltration probabilities, maps projected MITRE ATT&CK stages,
quantifies epistemic uncertainty, and simulates counterfactual defensive interventions.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from src.config import (
    STATE_FEATURE_NAMES,
    DEFAULT_ROLLOUT_STEPS,
    MITRE_STAGES,
    WINDOW_SIZE_SECONDS
)
from src.world_model.mitre_mapper import MitreMapper


class ForwardSimulator:
    """
    Executes forward simulation rollouts over the learned transition dynamics P(S_{t+1} | S_{1:t}).
    Enables proactive cyber defense before an adversary completes their kill-chain.
    """

    def __init__(self, world_model, feature_names: Optional[List[str]] = None):
        self.model = world_model
        self.feature_names = feature_names or STATE_FEATURE_NAMES
        self.feature_indices = {name: i for i, name in enumerate(self.feature_names)}

    def rollout(
        self,
        history_states: np.ndarray,
        k_steps: int = DEFAULT_ROLLOUT_STEPS,
        num_mc_samples: int = 5,
        intervention: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Rolls out the World Model K steps into the future.

        Args:
            history_states: [SeqLen, StateDim] sequence of observed historical network states.
            k_steps: Number of future time windows to simulate (e.g. 5 steps = 25 seconds).
            num_mc_samples: Number of Monte Carlo rollout trajectories for uncertainty quantification.
            intervention: Optional counterfactual defense applied at rollout step 1 or later.
                         e.g. {"step": 1, "action": "block_port_445", "feature_overrides": {"flag_syn_ratio": 0.05, "port_scan_entropy": 0.1}}

        Returns:
            Dictionary containing:
            - timeline_steps: List of step indices [0, 1, ..., k_steps]
            - timeline_seconds: Future seconds ahead [0, 5, 10, ...]
            - predicted_states: [k_steps, StateDim] array of projected future states
            - infiltration_probabilities: List of P(Infiltration) over time
            - infiltration_uncertainty_upper: Upper 95% confidence bound
            - infiltration_uncertainty_lower: Lower 95% confidence bound
            - predicted_stages: List of predicted MITRE stage IDs
            - predicted_stage_names: List of predicted stage names
            - top_driving_features: List of driving features for each step
            - attention_weights: Temporal attention distribution over past history
            - feature_attributions: Feature attribution vector at current step
        """
        if history_states.ndim == 2:
            current_seq = history_states.copy()
        elif history_states.ndim == 3:
            current_seq = history_states[0].copy()
        else:
            raise ValueError(f"Unexpected history shape: {history_states.shape}")

        seq_len, state_dim = current_seq.shape

        # Initial explanation metrics at t = 0 (current time)
        try:
            attn_weights = self.model.get_attention_weights(current_seq)
            if hasattr(attn_weights, "squeeze"):
                attn_weights = attn_weights.squeeze()
        except Exception:
            attn_weights = np.ones(seq_len) / seq_len

        try:
            feature_attrs = self.model.compute_feature_attribution(current_seq)
            if hasattr(feature_attrs, "squeeze"):
                feature_attrs = feature_attrs.squeeze()
        except Exception:
            feature_attrs = np.ones(state_dim) / state_dim

        # Primary deterministic rollout
        pred_states = []
        infil_probs = []
        predicted_stages = []
        predicted_stage_names = []
        driving_features_per_step = []

        # Current state evaluation
        sim_seq = current_seq.copy()
        _, cur_prob, cur_stage_logits = self.model.forward(sim_seq)
        cur_p = float(np.array(cur_prob).flatten()[0])
        cur_stage = int(np.argmax(np.array(cur_stage_logits).flatten()))

        infil_probs.append(cur_p)
        predicted_stages.append(cur_stage)
        predicted_stage_names.append(MITRE_STAGES.get(cur_stage, "Unknown"))

        # Rollout forward K steps
        for step in range(1, k_steps + 1):
            next_state_pred, p_infil, stage_logits = self.model.forward(sim_seq)

            s_next = next_state_pred[0] if isinstance(next_state_pred, (list, np.ndarray)) and next_state_pred.ndim > 1 else next_state_pred
            s_next = np.array(s_next, dtype=float).flatten()

            # Apply counterfactual intervention if requested
            if intervention and step >= intervention.get("step", 1):
                overrides = intervention.get("feature_overrides", {})
                for feat_name, override_val in overrides.items():
                    if feat_name in self.feature_indices:
                        idx = self.feature_indices[feat_name]
                        s_next[idx] = override_val

            prob_val = float(np.array(p_infil).flatten()[0])
            st_val = int(np.argmax(np.array(stage_logits).flatten()))

            # Determine top driving features for this projected state
            top_feats = self._extract_top_features(s_next)
            driving_features_per_step.append(top_feats)

            pred_states.append(s_next)
            infil_probs.append(prob_val)
            predicted_stages.append(st_val)
            predicted_stage_names.append(MITRE_STAGES.get(st_val, "Unknown"))

            # Shift simulation window forward: drop oldest, append predicted state
            sim_seq = np.vstack([sim_seq[1:], s_next])

        # Monte Carlo uncertainty estimation
        mc_trajectories = []
        for _ in range(num_mc_samples):
            mc_seq = current_seq.copy()
            mc_probs = [cur_p]
            for step in range(1, k_steps + 1):
                # Add slight epistemic noise perturbation to simulate transition stochasticity
                noise = np.random.normal(0, 0.03, size=state_dim)
                next_pred, mc_p, _ = self.model.forward(mc_seq)
                s_mc = np.array(next_pred[0] if next_pred.ndim > 1 else next_pred, dtype=float).flatten() + noise
                s_mc = np.clip(s_mc, 0, None)

                if intervention and step >= intervention.get("step", 1):
                    for feat_name, override_val in intervention.get("feature_overrides", {}).items():
                        if feat_name in self.feature_indices:
                            s_mc[self.feature_indices[feat_name]] = override_val

                prob_num = float(np.array(mc_p).flatten()[0])
                mc_probs.append(np.clip(prob_num + np.random.normal(0, 0.02), 0.0, 1.0))
                mc_seq = np.vstack([mc_seq[1:], s_mc])
            mc_trajectories.append(mc_probs)

        mc_arr = np.array(mc_trajectories)  # [num_mc, k_steps + 1]
        p_std = np.std(mc_arr, axis=0)
        upper_bound = np.clip(np.array(infil_probs) + 1.96 * p_std, 0.0, 1.0).tolist()
        lower_bound = np.clip(np.array(infil_probs) - 1.96 * p_std, 0.0, 1.0).tolist()

        timeline_steps = list(range(0, k_steps + 1))
        timeline_seconds = [step * WINDOW_SIZE_SECONDS for step in timeline_steps]

        # Out-of-Distribution (OOD) Zero-Day Anomaly Detection:
        # Measures how drastically the projected trajectory diverges from normal enterprise dynamics
        divergences = [float(np.linalg.norm(pred_states[i] - current_seq[-1]) / (np.linalg.norm(current_seq[-1]) + 1e-4)) for i in range(len(pred_states))]
        max_divergence = max(divergences) if divergences else 0.0
        is_zero_day = bool(max_divergence > 1.85 or (float(np.max(p_std)) > 0.16 and max(infil_probs) > 0.50))
        zero_day_conf = float(np.clip(max_divergence / 2.5, 0.0, 1.0))

        return {
            "timeline_steps": timeline_steps,
            "timeline_seconds": timeline_seconds,
            "predicted_states": np.array(pred_states),
            "infiltration_probabilities": infil_probs,
            "infiltration_uncertainty_upper": upper_bound,
            "infiltration_uncertainty_lower": lower_bound,
            "predicted_stages": predicted_stages,
            "predicted_stage_names": predicted_stage_names,
            "top_driving_features": driving_features_per_step,
            "attention_weights": attn_weights,
            "feature_attributions": feature_attrs,
            "is_intervention": intervention is not None,
            "is_zero_day_vector": is_zero_day,
            "ood_divergence_score": round(max_divergence, 2),
            "zero_day_confidence": round(zero_day_conf * 100, 1)
        }

    def simulate_counterfactual_comparison(
        self,
        history_states: np.ndarray,
        action_name: str,
        k_steps: int = DEFAULT_ROLLOUT_STEPS
    ) -> Dict[str, Any]:
        """
        Runs side-by-side rollout comparison:
        1. Non-intervened baseline trajectory (showing impending compromise).
        2. Proactive counterfactual intervention trajectory (showing threat deflection).
        """
        # Define defensive actions and their causal effect on state features
        INTERVENTION_PRESETS = {
            "rate_limit_syn": {
                "name": "Perimeter SYN Rate-Limiting & Anti-Scan Shield",
                "stage_target": 1,
                "step": 1,
                "feature_overrides": {
                    "flag_syn_ratio": 0.08,
                    "port_scan_entropy": 0.05,
                    "unique_dst_ports": 2.0
                },
                "playbook": "sudo iptables -A INPUT -p tcp --syn -m limit --limit 5/s -j ACCEPT"
            },
            "block_smb_lateral": {
                "name": "Zero-Trust Microsegmentation (Block East-West SMB/RPC)",
                "stage_target": 3,
                "step": 1,
                "feature_overrides": {
                    "east_west_traffic_ratio": 0.10,
                    "bytes_bwd_fwd_ratio": 0.95,
                    "unique_dst_ports": 1.0
                },
                "playbook": "sudo iptables -A FORWARD -p tcp --dport 445 -j DROP\nsudo iptables -A FORWARD -p tcp --dport 135 -j DROP"
            },
            "dns_sinkhole_c2": {
                "name": "DNS Sinkholing & C2 Outbound Socket Termination",
                "stage_target": 4,
                "step": 1,
                "feature_overrides": {
                    "flow_count": 5.0,
                    "retransmission_rate": 0.01,
                    "iat_std_ms": 150.0
                },
                "playbook": "sudo iptables -A OUTPUT -p tcp --dport 443 -d 203.0.113.0/24 -j DROP"
            },
            "emergency_egress_throttle": {
                "name": "Emergency Egress Bandwidth Throttling & DLP Lock",
                "stage_target": 5,
                "step": 1,
                "feature_overrides": {
                    "total_bytes": 15000.0,
                    "bytes_bwd_fwd_ratio": 1.0,
                    "total_packets": 30.0
                },
                "playbook": "sudo tc qdisc add dev eth0 root tbf rate 256kbit burst 10kb latency 50ms"
            }
        }

        preset = INTERVENTION_PRESETS.get(action_name, INTERVENTION_PRESETS["block_smb_lateral"])

        # Run non-intervened rollout
        baseline_rollout = self.rollout(history_states, k_steps=k_steps, intervention=None)

        # Run intervened rollout
        intervened_rollout = self.rollout(history_states, k_steps=k_steps, intervention=preset)

        # Compute lead-time gained (seconds before baseline reaches >0.70 risk)
        baseline_probs = baseline_rollout["infiltration_probabilities"]
        intervened_probs = intervened_rollout["infiltration_probabilities"]

        time_to_compromise = None
        for step_idx, p in enumerate(baseline_probs):
            if p >= 0.70:
                time_to_compromise = step_idx * WINDOW_SIZE_SECONDS
                break

        risk_reduction = float(max(0.0, baseline_probs[-1] - intervened_probs[-1]))

        return {
            "action_name": preset["name"],
            "playbook": preset["playbook"],
            "baseline": baseline_rollout,
            "intervened": intervened_rollout,
            "time_to_compromise_seconds": time_to_compromise,
            "risk_reduction_pct": round(risk_reduction * 100, 1),
            "defense_success": intervened_probs[-1] < 0.40
        }

    def _extract_top_features(self, state_vec: np.ndarray, top_n: int = 3) -> List[Tuple[str, float]]:
        """Identifies top contributing features by normalized magnitude."""
        # Find features with highest relative values
        scores = []
        for i, val in enumerate(state_vec):
            if i < len(self.feature_names):
                scores.append((self.feature_names[i], float(val)))
        scores.sort(key=lambda x: abs(x[1]), reverse=True)
        return scores[:top_n]
