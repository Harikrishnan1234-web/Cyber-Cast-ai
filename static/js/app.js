/**
 * CyberCast AI - Mission Control Frontend Controller
 * 100% Vanilla JavaScript & Air-Gapped Native HTML5 Canvas Visualization Engine
 */

// Application State
const state = {
  activeRole: 'soc_analyst',
  activeTab: 'forecast',
  timeIndex: 0,
  maxTimeIndex: 25,
  windowSec: 5,
  kRollout: 7,
  modelType: 'lstm',
  currentRisk: 0.12,
  isPlaying: false,
  playTimer: null,
  currentState: null,
  rolloutData: null,
  testedIpResult: null,
  counterfactualResult: null,
};

// Safe DOM Manipulation Utilities
function safeSetText(id, text, color) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = text !== undefined && text !== null ? text : '';
    if (color) el.style.color = color;
  }
}

function safeSetHtml(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html !== undefined && html !== null ? html : '';
}

// ============================================================================
// NATIVE HTML5 CANVAS CHARTING ENGINE (100% AIR-GAPPED & OFFLINE)
// ============================================================================
const CyberCharts = {
  setupCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    return { ctx, width: rect.width, height: rect.height };
  },

  drawTrajectory(canvasId, timeline, probs, lower, upper) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { ctx, width, height } = this.setupCanvas(canvas);
    ctx.clearRect(0, 0, width, height);

    const padLeft = 45;
    const padRight = 20;
    const padTop = 30;
    const padBottom = 35;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    if (!timeline || timeline.length === 0) return;

    const minX = timeline[0];
    const maxX = timeline[timeline.length - 1];

    const getX = (t) => padLeft + ((t - minX) / (maxX - minX || 1)) * plotW;
    const getY = (p) => padTop + (1 - Math.max(0, Math.min(1, p))) * plotH;

    // Gridlines
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let r = 0; r <= 1.0; r += 0.25) {
      const y = getY(r);
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(width - padRight, y);
      ctx.stroke();

      ctx.fillStyle = '#64748b';
      ctx.font = '10px "JetBrains Mono"';
      ctx.textAlign = 'right';
      ctx.fillText(`${Math.round(r * 100)}%`, padLeft - 8, y + 3);
    }

    // X-axis ticks
    timeline.forEach((t) => {
      const x = getX(t);
      ctx.beginPath();
      ctx.moveTo(x, padTop + plotH);
      ctx.lineTo(x, padTop + plotH + 4);
      ctx.stroke();

      ctx.fillStyle = '#64748b';
      ctx.font = '10px "JetBrains Mono"';
      ctx.textAlign = 'center';
      ctx.fillText(`+${Math.round(t)}s`, x, height - 12);
    });

    // 70% Breach Threshold line
    const y70 = getY(0.70);
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.7)';
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(padLeft, y70);
    ctx.lineTo(width - padRight, y70);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = '#ef4444';
    ctx.font = '10px "JetBrains Mono"';
    ctx.textAlign = 'right';
    ctx.fillText('BREACH THRESHOLD (70%)', width - padRight, y70 - 6);

    // Epistemic Uncertainty Band
    if (lower && upper && lower.length === timeline.length) {
      ctx.beginPath();
      ctx.moveTo(getX(timeline[0]), getY(lower[0]));
      for (let i = 1; i < timeline.length; i++) {
        ctx.lineTo(getX(timeline[i]), getY(lower[i]));
      }
      for (let i = timeline.length - 1; i >= 0; i--) {
        ctx.lineTo(getX(timeline[i]), getY(upper[i]));
      }
      ctx.closePath();
      const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
      grad.addColorStop(0, 'rgba(0, 240, 255, 0.3)');
      grad.addColorStop(1, 'rgba(0, 240, 255, 0.05)');
      ctx.fillStyle = grad;
      ctx.fill();
    }

    // Trajectory Line
    const isCritical = probs[probs.length - 1] >= 0.6;
    ctx.strokeStyle = isCritical ? '#ef4444' : '#00f0ff';
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(getX(timeline[0]), getY(probs[0]));
    for (let i = 1; i < timeline.length; i++) {
      ctx.lineTo(getX(timeline[i]), getY(probs[i]));
    }
    ctx.stroke();

    // Data points
    for (let i = 0; i < timeline.length; i++) {
      const px = getX(timeline[i]);
      const py = getY(probs[i]);
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.arc(px, py, 4, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = isCritical ? '#ef4444' : '#00f0ff';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
  },

  drawDualTrajectory(canvasId, timeline, baseProbs, intervProbs) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { ctx, width, height } = this.setupCanvas(canvas);
    ctx.clearRect(0, 0, width, height);

    const padLeft = 45;
    const padRight = 20;
    const padTop = 30;
    const padBottom = 35;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    if (!timeline || timeline.length === 0) return;

    const minX = timeline[0];
    const maxX = timeline[timeline.length - 1];

    const getX = (t) => padLeft + ((t - minX) / (maxX - minX || 1)) * plotW;
    const getY = (p) => padTop + (1 - Math.max(0, Math.min(1, p))) * plotH;

    // Gridlines
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let r = 0; r <= 1.0; r += 0.25) {
      const y = getY(r);
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(width - padRight, y);
      ctx.stroke();
      ctx.fillStyle = '#64748b';
      ctx.font = '10px "JetBrains Mono"';
      ctx.textAlign = 'right';
      ctx.fillText(`${Math.round(r * 100)}%`, padLeft - 8, y + 3);
    }

    timeline.forEach((t) => {
      const x = getX(t);
      ctx.beginPath();
      ctx.moveTo(x, padTop + plotH);
      ctx.lineTo(x, padTop + plotH + 4);
      ctx.stroke();
      ctx.fillStyle = '#64748b';
      ctx.font = '10px "JetBrains Mono"';
      ctx.textAlign = 'center';
      ctx.fillText(`+${Math.round(t)}s`, x, height - 12);
    });

    // Baseline Line (Red)
    ctx.strokeStyle = '#ef4444';
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(getX(timeline[0]), getY(baseProbs[0]));
    for (let i = 1; i < timeline.length; i++) {
      ctx.lineTo(getX(timeline[i]), getY(baseProbs[i]));
    }
    ctx.stroke();

    // Intervened Line (Green)
    ctx.strokeStyle = '#10b981';
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(getX(timeline[0]), getY(intervProbs[0]));
    for (let i = 1; i < timeline.length; i++) {
      ctx.lineTo(getX(timeline[i]), getY(intervProbs[i]));
    }
    ctx.stroke();

    // Legend
    ctx.fillStyle = '#ef4444';
    ctx.fillRect(padLeft + 10, padTop - 20, 10, 4);
    ctx.fillStyle = '#cbd5e1';
    ctx.font = '11px "Plus Jakarta Sans"';
    ctx.textAlign = 'left';
    ctx.fillText('Default Trajectory (No Defense)', padLeft + 25, padTop - 15);

    ctx.fillStyle = '#10b981';
    ctx.fillRect(padLeft + 210, padTop - 20, 10, 4);
    ctx.fillStyle = '#cbd5e1';
    ctx.fillText('Counterfactual (With Defense)', padLeft + 225, padTop - 15);
  },

  drawBarChart(canvasId, labels, values, color = '#3b82f6') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { ctx, width, height } = this.setupCanvas(canvas);
    ctx.clearRect(0, 0, width, height);

    const padLeft = 40;
    const padRight = 15;
    const padTop = 20;
    const padBottom = 30;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    if (!labels || labels.length === 0) return;

    const maxVal = Math.max(...values, 0.01);
    const barWidth = (plotW / labels.length) * 0.65;
    const step = plotW / labels.length;

    labels.forEach((lbl, i) => {
      const val = values[i];
      const h = (val / maxVal) * plotH;
      const x = padLeft + i * step + (step - barWidth) / 2;
      const y = padTop + plotH - h;

      ctx.fillStyle = color;
      ctx.fillRect(x, y, barWidth, h);

      // Label below
      ctx.fillStyle = '#94a3b8';
      ctx.font = '9.5px "JetBrains Mono"';
      ctx.textAlign = 'center';
      ctx.fillText(lbl, x + barWidth / 2, height - 10);
    });
  },

  drawHorizontalBars(canvasId, items, color = '#00f0ff') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { ctx, width, height } = this.setupCanvas(canvas);
    ctx.clearRect(0, 0, width, height);

    const padLeft = 140;
    const padRight = 45;
    const padTop = 15;
    const padBottom = 15;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    if (!items || items.length === 0) return;

    const maxVal = Math.max(...items.map(it => it.score), 0.01);
    const rowHeight = plotH / items.length;

    items.forEach((item, i) => {
      const y = padTop + i * rowHeight + 4;
      const barH = rowHeight - 8;
      const barW = (item.score / maxVal) * plotW;

      // Label
      ctx.fillStyle = '#cbd5e1';
      ctx.font = '10px "JetBrains Mono"';
      ctx.textAlign = 'right';
      ctx.fillText(item.feature.substring(0, 18), padLeft - 10, y + barH / 2 + 3);

      // Bar
      ctx.fillStyle = color;
      ctx.fillRect(padLeft, y, barW, barH);

      // Score
      ctx.fillStyle = '#94a3b8';
      ctx.textAlign = 'left';
      ctx.fillText(item.score.toFixed(2), padLeft + barW + 6, y + barH / 2 + 3);
    });
  }
};

// ============================================================================
// API CLIENT
// ============================================================================
const api = {
  async get(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return await res.json();
  },

  async post(url, data) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return await res.json();
  },

  async patch(url, data) {
    const res = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return await res.json();
  }
};

// ============================================================================
// UI CONTROLLERS & DATA FLOW
// ============================================================================

// Initialize application
async function initApp() {
  setupTabs();
  setupSliders();
  setupEventListeners();

  try {
    await fetchPipelineStatus();
    await generateScenarioTelemetry();
    await loadCases();
    await loadEvidence();
    await testIpThreat('10.0.1.99', 'Reconnaissance Scanner');
    await simulateCounterfactual('block_smb_lateral');
    await loadBenchmarks();
    await loadComplianceAudit();
    showToast('CyberCast AI Mission Control connected successfully!', 'success');
  } catch (err) {
    console.error('Initialization error:', err);
    showToast(`Connection notice: ${err.message}`, 'info');
  }
}

// Tab navigation
function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn, .tab-link, .tab-nav-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane, .tab-section').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      state.activeTab = targetId;
      const targetPane = document.getElementById(`tab-${targetId}`);
      if (targetPane) targetPane.classList.add('active');

      // Trigger chart re-render if switching to tabs with charts
      setTimeout(() => {
        if (targetId === 'forecast' && state.rolloutData) {
          CyberCharts.drawTrajectory('chart-trajectory', state.rolloutData.timeline_seconds, state.rolloutData.infiltration_probabilities, state.rolloutData.infiltration_uncertainty_lower, state.rolloutData.infiltration_uncertainty_upper);
          CyberCharts.drawBarChart('chart-attention', state.rolloutData.attention_labels, state.rolloutData.attention_weights);
          CyberCharts.drawHorizontalBars('chart-features', state.rolloutData.feature_items);
        } else if (targetId === 'counterfactual' && state.counterfactualResult) {
          CyberCharts.drawDualTrajectory('chart-whatif', state.counterfactualResult.baseline.timeline_seconds, state.counterfactualResult.baseline.infiltration_probabilities, state.counterfactualResult.intervened.infiltration_probabilities);
        } else if (targetId === 'ip_proctor' && state.testedIpResult) {
          const r = state.testedIpResult.prediction.rollout;
          CyberCharts.drawTrajectory('chart-ip-rollout', r.timeline_seconds, r.infiltration_probabilities, r.infiltration_uncertainty_lower, r.infiltration_uncertainty_upper);
        }
      }, 50);
    });
  });
}

// Sliders setup
function setupSliders() {
  const timeSlider = document.getElementById('time-slider');
  const timeVal = document.getElementById('time-val');
  if (timeSlider) {
    timeSlider.addEventListener('input', (e) => {
      state.timeIndex = parseInt(e.target.value);
      if (timeVal) timeVal.textContent = state.timeIndex;
      fetchStateAndRollout(state.timeIndex);
    });
  }

  const kSlider = document.getElementById('k-slider');
  const kVal = document.getElementById('k-val');
  if (kSlider) {
    kSlider.addEventListener('input', (e) => {
      state.kRollout = parseInt(e.target.value);
      if (kVal) kVal.textContent = `${state.kRollout} steps (${state.kRollout * state.windowSec}s)`;
      fetchStateAndRollout(state.timeIndex);
    });
  }

  const durationSlider = document.getElementById('duration-slider');
  const durationVal = document.getElementById('duration-val');
  if (durationSlider) {
    durationSlider.addEventListener('input', (e) => {
      if (durationVal) durationVal.textContent = `${e.target.value}s`;
    });
  }

  const rateSlider = document.getElementById('rate-slider');
  const rateVal = document.getElementById('rate-val');
  if (rateSlider) {
    rateSlider.addEventListener('input', (e) => {
      if (rateVal) rateVal.textContent = `${e.target.value}/s`;
    });
  }
}

// Event Listeners
function setupEventListeners() {
  // Role selector
  const roleSelect = document.getElementById('role-select');
  if (roleSelect) {
    roleSelect.addEventListener('change', (e) => {
      state.activeRole = e.target.value;
      showToast(`Switched operational persona: ${e.target.options[e.target.selectedIndex].text}`, 'info');
      const badgeRole = document.getElementById('badge-active-role');
      if (badgeRole) badgeRole.textContent = e.target.options[e.target.selectedIndex].text;
    });
  }

  // Model selector
  const modelSelect = document.getElementById('model-select');
  if (modelSelect) {
    modelSelect.addEventListener('change', async (e) => {
      state.modelType = e.target.value;
      await api.post('/api/v1/model/select', { model_type: state.modelType });
      const badgeModel = document.getElementById('badge-model-type');
      if (badgeModel) badgeModel.textContent = state.modelType.toUpperCase();
      showToast(`Temporal learning engine switched to ${state.modelType.toUpperCase()}`, 'success');
      fetchStateAndRollout(state.timeIndex);
    });
  }

  // Window Resolution selector
  const windowSelect = document.getElementById('window-select');
  if (windowSelect) {
    windowSelect.addEventListener('change', (e) => {
      state.windowSec = parseInt(e.target.value);
      const kVal = document.getElementById('k-val');
      if (kVal) kVal.textContent = `${state.kRollout} steps (${state.kRollout * state.windowSec}s)`;
      fetchStateAndRollout(state.timeIndex);
    });
  }

  // Ingest Telemetry button
  const btnIngest = document.getElementById('btn-ingest');
  if (btnIngest) {
    btnIngest.addEventListener('click', generateScenarioTelemetry);
  }

  // Purge button
  const btnPurge = document.getElementById('btn-purge');
  if (btnPurge) {
    btnPurge.addEventListener('click', purgeTelemetry);
  }

  // File Upload Handlers (Drag & Drop + File Picker)
  const fileInput = document.getElementById('file-upload-input');
  const dropzone = document.getElementById('dropzone');
  const btnUpload = document.getElementById('btn-upload-file');
  const dropLabel = document.getElementById('dropzone-label');
  async function handleUploadedFile(file) {
    if (!file) return;
    showToast(`Ingesting and parsing capture: ${file.name}...`, 'info');
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/v1/telemetry/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Upload failed');

      state.maxTimeIndex = data.state_count - 1;
      const timeSlider = document.getElementById('time-slider');
      if (timeSlider) {
        timeSlider.max = state.maxTimeIndex;
        timeSlider.value = Math.min(20, state.maxTimeIndex);
      }
      state.timeIndex = Math.min(20, state.maxTimeIndex);
      safeSetText('time-val', state.timeIndex);

      showToast(`✅ Ingested ${data.flow_count} flows from ${data.filename}!`, 'success');
      safeSetText('active-source-display', `Custom Upload: ${data.filename} (${data.flow_count} flows)`);
      await fetchStateAndRollout(state.timeIndex);

      const stage = document.getElementById('forecast-stage');
      if (stage) stage.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      showToast(`Upload error: ${err.message}`, 'error');
    }
  }

  if (fileInput) {
    fileInput.addEventListener('change', async (e) => {
      if (e.target.files && e.target.files[0]) {
        await handleUploadedFile(e.target.files[0]);
      }
    });
  }

  if (dropzone) {
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-active');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-active'));
    dropzone.addEventListener('drop', async (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-active');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        await handleUploadedFile(e.dataTransfer.files[0]);
      }
    });
  }

  // Trigger Replay of Real Dataset Test Slice
  window.triggerDatasetReplay = async function(datasetName) {
    showToast(`Loading test capture: ${datasetName}...`, 'info');
    try {
      const res = await api.post('/api/v1/telemetry/generate', {
        scenario_preset: datasetName,
        duration_seconds: 300,
        flows_per_second: 8.0
      });

      state.maxTimeIndex = res.state_count - 1;
      const timeSlider = document.getElementById('time-slider');
      if (timeSlider) {
        timeSlider.max = state.maxTimeIndex;
        timeSlider.value = Math.min(20, state.maxTimeIndex);
      }
      state.timeIndex = Math.min(20, state.maxTimeIndex);
      safeSetText('time-val', state.timeIndex);
      safeSetText('active-source-display', `${datasetName} · Ingested ${res.flow_count} flows`);

      showToast(`✅ Ingested ${res.flow_count} flows from ${datasetName}!`, 'success');
      await fetchStateAndRollout(state.timeIndex);

      const stage = document.getElementById('forecast-stage');
      if (stage) stage.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      showToast(`Replay error: ${err.message}`, 'error');
    }
  };

  // Quick One-Click Sample CSV File Ingestion
  window.loadSampleCsv = async function() {
    showToast('Generating sample CIC-IDS network flows...', 'info');
    let csvContent = "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,flow_duration,fwd_packets,bwd_packets,fwd_bytes,bwd_bytes,flag_syn,flag_ack,flag_fin,flag_rst,flag_psh,flag_urg,flow_iat_mean,flow_iat_std,flow_iat_max,ttl_mean,ttl_var,tcp_window_mean,retransmissions,attack_stage\n";
    for (let i = 0; i < 60; i++) {
      const stage = i < 15 ? 0 : i < 30 ? 1 : i < 45 ? 2 : 3;
      csvContent += `${(i * 2.0).toFixed(1)},192.168.1.${100 + (i % 8)},${40000 + i},10.0.1.15,${i % 3 === 0 ? 445 : 80},6,180,15,18,1800,3600,1,1,0,0,1,0,22.0,4.8,35.0,64,0,4096,0,${stage}\n`;
    }
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const file = new File([blob], 'cic_ids_sample_intrusion.csv', { type: 'text/csv' });
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/v1/telemetry/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Upload failed');

      state.maxTimeIndex = data.state_count - 1;
      const timeSlider = document.getElementById('time-slider');
      if (timeSlider) {
        timeSlider.max = state.maxTimeIndex;
        timeSlider.value = Math.min(20, state.maxTimeIndex);
      }
      state.timeIndex = Math.min(20, state.maxTimeIndex);
      safeSetText('time-val', state.timeIndex);

      safeSetText('dropzone-label', `Active File: ${data.filename} (${data.flow_count} flows)`);
      safeSetText('active-source-display', `Sample File: ${data.filename} (${data.flow_count} flows)`);

      showToast(`✅ Successfully ingested sample file: ${data.filename} (${data.flow_count} flows)!`, 'success');
      await fetchStateAndRollout(state.timeIndex);
    } catch (err) {
      showToast(`Sample load error: ${err.message}`, 'error');
    }
  };

  // Play/Pause simulation
  const btnPlay = document.getElementById('btn-play-sim');
  if (btnPlay) {
    btnPlay.addEventListener('click', togglePlaySimulation);
  }

  // IP Quick-test buttons
  document.querySelectorAll('.btn-quick-ip').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const ip = btn.getAttribute('data-ip');
      const profile = btn.getAttribute('data-profile');
      document.getElementById('input-target-ip').value = ip;
      document.getElementById('select-ip-profile').value = profile;
      testIpThreat(ip, profile);
    });
  });

  // IP Proctor button
  const btnProctor = document.getElementById('btn-run-ip');
  if (btnProctor) {
    btnProctor.addEventListener('click', () => {
      const ip = document.getElementById('input-target-ip').value.trim() || '10.0.1.99';
      const profile = document.getElementById('select-ip-profile').value;
      testIpThreat(ip, profile);
    });
  }

  // What-If Interventions
  document.querySelectorAll('input[name="whatif-action"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
      simulateCounterfactual(e.target.value);
    });
  });

  // New Case Modal
  const btnOpenModal = document.getElementById('btn-open-case-modal');
  const modal = document.getElementById('modal-new-case');
  const btnCloseModal = document.getElementById('btn-close-case-modal');
  if (btnOpenModal && modal) {
    btnOpenModal.addEventListener('click', () => modal.classList.add('active'));
  }
  if (btnCloseModal && modal) {
    btnCloseModal.addEventListener('click', () => modal.classList.remove('active'));
  }
  const formNewCase = document.getElementById('form-new-case');
  if (formNewCase) {
    formNewCase.addEventListener('submit', async (e) => {
      e.preventDefault();
      const title = document.getElementById('case-title').value;
      const severity = document.getElementById('case-severity').value;
      const target_ip = document.getElementById('case-target-ip').value;
      const mitre_stage = document.getElementById('case-stage').value;
      const notes = document.getElementById('case-notes').value;
      await createCase({ title, severity, target_ip, mitre_stage, notes });
      modal.classList.remove('active');
    });
  }

  // Deposit Evidence Form
  const formDeposit = document.getElementById('form-deposit-evidence');
  if (formDeposit) {
    formDeposit.addEventListener('submit', async (e) => {
      e.preventDefault();
      const case_id = document.getElementById('ev-case-id').value;
      const artifact_type = document.getElementById('ev-type').value;
      const file_name = document.getElementById('ev-fname').value;
      const content = document.getElementById('ev-content').value;
      await depositEvidence({ case_id, artifact_type, file_name, content });
    });
  }

  // Benchmark Run button
  const btnBench = document.getElementById('btn-run-benchmark');
  if (btnBench) {
    btnBench.addEventListener('click', runBenchmarks);
  }

  // Report Generator button
  const btnReport = document.getElementById('btn-gen-report');
  if (btnReport) {
    btnReport.addEventListener('click', () => {
      const ip = document.getElementById('rep-target-ip').value.trim() || '10.0.1.15';
      const fmt = document.getElementById('rep-format').value;
      generateReport(ip, fmt);
    });
  }

  // Copy Buttons
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const el = document.getElementById(targetId);
      if (el) {
        navigator.clipboard.writeText(el.innerText || el.textContent);
        showToast('Rule copied to clipboard!', 'success');
      }
    });
  });

  // REST API Sandbox button
  const btnTestApi = document.getElementById('btn-test-api');
  if (btnTestApi) {
    btnTestApi.addEventListener('click', testApiEndpoint);
  }
}

// Toggle simulation play
function togglePlaySimulation() {
  const btn = document.getElementById('btn-play-sim');
  if (state.isPlaying) {
    state.isPlaying = false;
    clearInterval(state.playTimer);
    if (btn) btn.innerHTML = '▶ Play Stream';
    showToast('Simulation stream paused', 'info');
  } else {
    state.isPlaying = true;
    if (btn) btn.innerHTML = '⏸ Pause Stream';
    showToast('Playing forward telemetry stream', 'success');
    state.playTimer = setInterval(() => {
      const nextT = (state.timeIndex + 1) % (state.maxTimeIndex + 1);
      state.timeIndex = nextT;
      const slider = document.getElementById('time-slider');
      const timeVal = document.getElementById('time-val');
      if (slider) slider.value = nextT;
      if (timeVal) timeVal.textContent = nextT;
      fetchStateAndRollout(nextT);
    }, 2000);
  }
}

// ----------------------------------------------------------------------------
// API CALLS & DATA SYNC
// ----------------------------------------------------------------------------

async function fetchPipelineStatus() {
  try {
    const data = await api.get('/api/v1/pipeline');
    safeSetText('badge-pipeline-status', 'LIVE & ACTIVE');
    if (data.steps && data.steps[3]) {
      safeSetText('badge-model-type', (data.steps[3].active_model || 'LSTM').toUpperCase());
    }
  } catch (err) {
    console.error('Pipeline status error:', err);
  }
}

async function generateScenarioTelemetry() {
  const presetEl = document.getElementById('scenario-select');
  const durEl = document.getElementById('duration-slider');
  const rateEl = document.getElementById('rate-slider');
  const preset = presetEl ? presetEl.value : 'Complete Kill Chain';
  const duration = durEl ? parseInt(durEl.value) : 300;
  const flows = rateEl ? parseFloat(rateEl.value) : 8.0;

  showToast('Generating temporal network telemetry...', 'info');
  try {
    const res = await api.post('/api/v1/telemetry/generate', {
      scenario_preset: preset,
      duration_seconds: duration,
      flows_per_second: flows
    });

    state.maxTimeIndex = res.state_count - 1;
    const timeSlider = document.getElementById('time-slider');
    if (timeSlider) {
      timeSlider.max = state.maxTimeIndex;
      timeSlider.value = Math.min(20, state.maxTimeIndex);
    }
    state.timeIndex = Math.min(20, state.maxTimeIndex);
    safeSetText('time-val', state.timeIndex);
    safeSetText('pipe-flow-count', `${res.flow_count} Flows`);
    safeSetText('active-source-display', `Scenario: ${preset} (${res.flow_count} flows)`);

    showToast(`Ingested ${res.flow_count} flows across ${res.state_count} temporal windows`, 'success');
    await fetchStateAndRollout(state.timeIndex);
  } catch (err) {
    showToast(`Ingestion error: ${err.message}`, 'error');
  }
}

async function purgeTelemetry() {
  try {
    await api.post('/api/v1/telemetry/purge', {});
    showToast('Telemetry memory purged. Zero traces retained (GDPR/DPDP).', 'info');
    safeSetText('pipe-flow-count', '0 Flows');
    safeSetText('active-source-display', 'Zeroized (Empty Buffer)');
  } catch (err) {
    showToast('Purge error: ' + err.message, 'error');
  }
}

async function fetchStateAndRollout(t) {
  try {
    const res = await api.post('/api/v1/forecast/rollout', {
      time_index: t,
      window_size_seconds: state.windowSec,
      k_steps: state.kRollout,
      model_type: state.modelType
    });

    state.currentState = res.current_state;
    state.rolloutData = res.rollout;

    // Update Top Threat Banner
    updateThreatBanner(res.rollout);

    // Update Metrics
    const s = res.current_state;
    if (s) {
      safeSetText('metric-flows', Math.round(s.flow_count));
      safeSetText('metric-ips', `${Math.round(s.unique_src_ips)} Src / ${Math.round(s.unique_dst_ips)} Dst IPs`);
      safeSetText('metric-syn', s.flag_syn_ratio.toFixed(2), s.flag_syn_ratio > 0.4 ? '#ef4444' : '#00e5ff');
      safeSetText('metric-flags', `ACK: ${s.flag_ack_ratio.toFixed(2)} | FIN: ${s.flag_fin_ratio.toFixed(2)}`);
      safeSetText('metric-entropy', s.port_scan_entropy.toFixed(2), s.port_scan_entropy > 0.5 ? '#f59e0b' : '#10b981');
      safeSetText('metric-ports', `${Math.round(s.unique_dst_ports)} Dst Ports Probed`);
      safeSetText('metric-ew', s.east_west_traffic_ratio.toFixed(2), s.east_west_traffic_ratio > 0.5 ? '#a855f7' : '#94a3b8');
      safeSetText('metric-egress', `${(s.bytes_total / 1024).toFixed(1)} KB`);
      safeSetText('metric-pkts', `${Math.round(s.packets_total)} Packets`);
    }

    safeSetText('metric-stage-name', res.current_stage_name, res.current_stage_color);
    safeSetText('metric-stage-sub', `Stage ${res.current_stage_id} of 5`);

    // Forecast projection details
    const r = res.rollout;
    if (r && r.projected_stage_info) {
      safeSetText('proj-stage-name', r.projected_stage_info.name, r.projected_stage_info.color);
      safeSetText('proj-stage-desc', r.projected_stage_info.description);
      safeSetText('proj-playbook', r.projected_stage_info.playbook?.action || 'Sever SMB East-West ports');
    }

    // Zero-Day advisory
    const zeroBox = document.getElementById('box-zero-day');
    if (zeroBox && r) {
      if (r.is_zero_day_vector) {
        zeroBox.style.display = 'block';
        safeSetText('zero-divergence', r.ood_divergence_score.toFixed(2));
        safeSetText('zero-conf', `${r.zero_day_confidence.toFixed(1)}%`);
      } else {
        zeroBox.style.display = 'none';
      }
    }

    // Render Charts
    if (r) {
      CyberCharts.drawTrajectory('chart-trajectory', r.timeline_seconds, r.infiltration_probabilities, r.infiltration_uncertainty_lower, r.infiltration_uncertainty_upper);
      CyberCharts.drawBarChart('chart-attention', r.attention_labels, r.attention_weights);
      CyberCharts.drawHorizontalBars('chart-features', r.feature_items);
    }

  } catch (err) {
    console.error('Rollout error:', err);
  }
}

function updateThreatBanner(rollout) {
  if (!rollout) return;
  const probs = rollout.infiltration_probabilities || [0.1];
  const latestRisk = probs[probs.length - 1];
  const stageInfo = rollout.projected_stage_info || { name: 'Benign Baseline' };
  const times = rollout.timeline_seconds || [5, 10, 15];

  let ttc = null;
  for (let i = 0; i < probs.length; i++) {
    if (probs[i] >= 0.70) {
      ttc = times[i];
      break;
    }
  }

  const banner = document.getElementById('threat-status-banner');
  const title = document.getElementById('threat-banner-title');
  const desc = document.getElementById('threat-banner-desc');
  const badgeRisk = document.getElementById('badge-threat-risk');

  if (badgeRisk) badgeRisk.textContent = `RISK: ${(latestRisk * 100).toFixed(1)}%`;

  if (latestRisk >= 0.70) {
    if (banner) banner.className = 'status-banner danger';
    if (title) title.innerHTML = `🚨 CRITICAL THREAT DETECTED • ATTACK PENETRATION IMMINENT (${stageInfo.name})`;
    if (desc) desc.innerHTML = `The AI World Model forecasts full network compromise in <b>+${ttc || times[times.length - 1]} seconds</b>. Threat actors are actively traversing the kill-chain. Proactive defense required!`;
    if (badgeRisk) badgeRisk.className = 'badge badge-red';
  } else if (latestRisk >= 0.40) {
    if (banner) banner.className = 'status-banner warning';
    if (title) title.innerHTML = `⚠️ ELEVATED SUSPICION • ANOMALOUS ACTIVITY OBSERVED (${stageInfo.name})`;
    if (desc) desc.innerHTML = `Unusual East-West port probing and flag ratios detected. Forward trajectory is trending towards compromise. Monitor closely or test countermeasures.`;
    if (badgeRisk) badgeRisk.className = 'badge badge-amber';
  } else {
    if (banner) banner.className = 'status-banner safe';
    if (title) title.innerHTML = `🟢 ALL SYSTEMS SECURE & OPERATIONAL (BENIGN BASELINE)`;
    if (desc) desc.innerHTML = `All telemetry flows are within safe enterprise operational baselines. Zero intrusion trajectory predicted across the next ${times[times.length - 1]} seconds.`;
    if (badgeRisk) badgeRisk.className = 'badge badge-green';
  }
}

// IP Proctor & Predictor
async function testIpThreat(ip, profile) {
  try {
    const res = await api.post('/api/v1/proctor/ip', {
      target_ip: ip,
      profile: profile
    });

    state.testedIpResult = res;
    const p = res.proctor_evaluation;
    const pred = res.neural_forecast;

    safeSetText('ip-inspected-host', ip);
    if (p && p.metrics) {
      safeSetText('ip-flows-pkts', `${p.metrics.total_flows} flows | ${p.metrics.total_packets} pkts`);
    }

    if (p) {
      safeSetText('ip-proctor-verdict', p.proctor_verdict, p.badge_color);
      safeSetHtml('ip-proctor-score-text', `Threat Score: <b>${p.proctor_score}/100</b>`);

      // Threat Meter
      const meter = document.getElementById('ip-threat-meter-fill');
      if (meter) {
        meter.style.width = `${Math.max(5, p.proctor_score)}%`;
        meter.style.backgroundColor = p.badge_color;
      }
      safeSetText('ip-meter-val', `${p.proctor_score} / 100`);
      safeSetText('ip-meter-title', `SECURITY THREAT METER: ${p.proctor_verdict}`);

      // Findings
      const findingsList = document.getElementById('ip-findings-list');
      if (findingsList) {
        findingsList.innerHTML = '';
        if (p.findings && p.findings.length > 0) {
          p.findings.forEach(f => {
            const item = document.createElement('div');
            item.className = `finding-item ${f.severity}`;
            item.innerHTML = `
              <span style="font-weight: 700; font-size: 11.5px;">[${f.severity}] ${f.rule}</span>
              <span style="color: #cbd5e1; font-size: 11.5px;">${f.detail}</span>
            `;
            findingsList.appendChild(item);
          });
        } else {
          findingsList.innerHTML = '<div style="color: #10b981; font-size: 12px; padding: 10px;">✅ Clean Proctor Record: Zero anomalous flags or port scans detected.</div>';
        }
      }
    }

    if (pred) {
      safeSetText('ip-future-risk', `${(pred.future_risk * 100).toFixed(1)}%`, pred.future_risk > 0.6 ? '#ef4444' : '#10b981');
      safeSetText('ip-convergence', `Convergence: ${pred.predicted_stage_name}`);

      // Rules
      const r = pred.synthesized_rules;
      if (r) {
        safeSetText('rule-iptables', r.iptables || '# No iptables rule required');
        safeSetText('rule-suricata', r.suricata || '# No suricata signature required');
        safeSetText('rule-powershell', r.powershell || '# No powershell rule required');
        safeSetText('rule-zeek', r.zeek || '# No zeek rule required');
      }

      // Chart
      const rRollout = pred.rollout;
      if (rRollout) {
        CyberCharts.drawTrajectory('chart-ip-rollout', rRollout.timeline_seconds, rRollout.infiltration_probabilities, rRollout.infiltration_uncertainty_lower, rRollout.infiltration_uncertainty_upper);
      }

      const ttcAlert = document.getElementById('ip-ttc-alert');
      if (ttcAlert) {
        if (pred.time_to_compromise_sec) {
          ttcAlert.innerHTML = `🚨 <b>Estimated Time-to-Compromise:</b> Host breaches defensive threshold in <b>+${Math.round(pred.time_to_compromise_sec)} seconds</b>.`;
          ttcAlert.style.display = 'block';
        } else {
          ttcAlert.style.display = 'none';
        }
      }
    }

  } catch (err) {
    showToast('IP test error: ' + err.message, 'error');
  }
}

// Counterfactual What-If
async function simulateCounterfactual(action) {
  try {
    const res = await api.post('/api/v1/counterfactual/simulate', {
      action_name: action,
      time_index: state.timeIndex,
      k_steps: state.kRollout
    });

    state.counterfactualResult = res;
    safeSetText('cf-risk-reduction', `-${res.risk_reduction_pct}% Risk`);
    safeSetText('cf-status', `Status: ${res.defense_success ? '✅ DEFENSE EFFECTIVE' : '⚠️ PARTIAL MITIGATION'}`);
    safeSetText('cf-lead-time', `Lead-Time Gained: ${res.time_to_compromise_seconds || 45} seconds`);

    // What-If Chart
    if (res.baseline && res.intervened) {
      CyberCharts.drawDualTrajectory('chart-whatif', res.baseline.timeline_seconds, res.baseline.infiltration_probabilities, res.intervened.infiltration_probabilities);
    }

    // Rules
    const r = res.synthesized_rules;
    if (r) {
      safeSetText('cf-iptables', r.iptables);
      safeSetText('cf-suricata', r.suricata);
      safeSetText('cf-powershell', r.powershell);
      safeSetText('cf-zeek', r.zeek);
    }

    // Sandbox
    const sb = res.safety_sandbox;
    if (sb) {
      safeSetText('sb-score', `${sb.safety_score_pct}%`);
      safeSetText('sb-recommendation', sb.recommendation);
      const sbList = document.getElementById('sb-assets-list');
      if (sbList && sb.passed_assets) {
        sbList.innerHTML = sb.passed_assets.map(a => `<li>✅ <b>${a}</b>: PASS (Unimpeded)</li>`).join('');
      }
    }

  } catch (err) {
    console.error('Counterfactual error:', err);
  }
}

// Case Workspace
async function loadCases() {
  try {
    const res = await api.get('/api/v1/cases');
    const container = document.getElementById('cases-container');
    container.innerHTML = '';

    if (!res.cases || res.cases.length === 0) {
      container.innerHTML = '<div style="color: #94a3b8; font-size: 12px; padding: 12px;">No active incident cases in database.</div>';
      return;
    }

    res.cases.forEach(c => {
      const card = document.createElement('div');
      card.style.cssText = 'background: rgba(13, 20, 36, 0.9); border: 1px solid #1e293b; border-radius: 10px; padding: 14px; margin-bottom: 10px;';
      const sevClass = c.severity === 'CRITICAL' ? 'badge-red' : (c.severity === 'HIGH' ? 'badge-amber' : 'badge-cyan');
      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span style="font-family: 'JetBrains Mono', monospace; font-weight: 800; color: #00f0ff;">${c.case_id}</span>
          <span class="badge-pill ${sevClass}">${c.severity}</span>
        </div>
        <div style="font-size: 13.5px; font-weight: 700; color: #f8fafc; margin-top: 6px;">${c.title}</div>
        <div style="font-size: 11.5px; color: #94a3b8; margin-top: 4px;">Target: <code>${c.target_ip}</code> | Stage: <b>${c.mitre_stage}</b></div>
        <div style="font-size: 11px; color: #cbd5e1; margin-top: 6px; background: rgba(0,0,0,0.3); padding: 6px; border-radius: 6px;">${c.notes}</div>
        <div style="margin-top: 8px; display: flex; justify-content: space-between; align-items: center; font-size: 11px;">
          <span style="color: #10b981; font-weight: 700;">Status: ${c.status}</span>
          <span style="color: #64748b;">Assigned: ${c.assigned_to}</span>
        </div>
        <div style="margin-top: 10px; display: flex; gap: 8px;">
          ${c.status !== 'CONTAINED' && c.status !== 'CLOSED' ? `<button class="btn btn-primary btn-sm" onclick="containCase('${c.case_id}', '${c.target_ip}')">⚡ eBPF Quarantine</button>` : ''}
          ${c.status !== 'CLOSED' ? `<button class="btn btn-secondary btn-sm" onclick="closeCase('${c.case_id}')">✅ Close Case</button>` : ''}
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error('Load cases error:', err);
  }
}

async function createCase(data) {
  try {
    await api.post('/api/v1/cases', data);
    showToast('Incident case created in workspace!', 'success');
    await loadCases();
  } catch (err) {
    showToast('Error creating case: ' + err.message, 'error');
  }
}

window.containCase = async function(caseId, targetIp) {
  try {
    const res = await api.post(`/api/v1/cases/${caseId}/contain`, {
      playbook_action: 'block_smb_lateral',
      target_ip: targetIp
    });
    showToast(`Case ${caseId} contained safely via eBPF XDP probe!`, 'success');
    await loadCases();
  } catch (err) {
    showToast('Containment error: ' + err.message, 'error');
  }
};

window.closeCase = async function(caseId) {
  try {
    await api.patch(`/api/v1/cases/${caseId}/status`, {
      status: 'CLOSED',
      notes: 'Threat neutralized by analyst.'
    });
    showToast(`Case ${caseId} closed successfully.`, 'info');
    await loadCases();
  } catch (err) {
    showToast('Error closing case: ' + err.message, 'error');
  }
};

// Evidence Vault
async function loadEvidence() {
  try {
    const res = await api.get('/api/v1/evidence');
    const container = document.getElementById('evidence-container');
    container.innerHTML = '';

    if (!res.evidence_items || res.evidence_items.length === 0) {
      container.innerHTML = '<div style="color: #94a3b8; font-size: 12px; padding: 12px;">Evidence vault is empty.</div>';
      return;
    }

    res.evidence_items.forEach(ev => {
      const card = document.createElement('div');
      card.style.cssText = 'background: rgba(10, 16, 29, 0.9); border: 1px solid #1e293b; border-radius: 10px; padding: 12px; margin-bottom: 8px;';
      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span style="font-family: 'JetBrains Mono', monospace; font-size: 11.5px; font-weight: 700; color: #38bdf8;">${ev.evidence_id}</span>
          <span class="badge-pill badge-cyan">${ev.artifact_type}</span>
        </div>
        <div style="font-size: 12.5px; font-weight: 700; color: #f8fafc; margin-top: 4px;">${ev.file_name}</div>
        <div style="font-size: 10.5px; font-family: 'JetBrains Mono', monospace; color: #94a3b8; word-break: break-all; margin-top: 4px;">
          SHA-256: <code>${ev.file_hash_sha256}</code>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 8px;">
          <span style="font-size: 10px; color: #64748b;">${ev.byte_size} bytes | ${ev.custody_analyst}</span>
          <button class="btn btn-secondary btn-sm" onclick="verifyEvidence('${ev.evidence_id}')">🔍 Verify SHA-256</button>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error('Load evidence error:', err);
  }
}

async function depositEvidence(data) {
  try {
    const res = await api.post('/api/v1/evidence', data);
    showToast(`Evidence deposited with SHA-256: ${res.evidence.file_hash_sha256.substring(0, 12)}...`, 'success');
    await loadEvidence();
  } catch (err) {
    showToast('Evidence deposit error: ' + err.message, 'error');
  }
}

window.verifyEvidence = async function(evidenceId) {
  try {
    const res = await api.get(`/api/v1/evidence/${evidenceId}/verify`);
    if (res.valid) {
      showToast(`✅ Cryptographic Hash Verified (NIST FIPS 180-4)! Artifact is 100% untampered: ${res.calculated_hash.substring(0, 16)}...`, 'success');
    } else {
      showToast('❌ Cryptographic verification failed!', 'error');
    }
  } catch (err) {
    showToast('Verification error: ' + err.message, 'error');
  }
};

// Benchmarks
async function loadBenchmarks() {
  try {
    const res = await api.get('/api/v1/benchmarks');
    state.benchmarkData = res;
    renderBenchmarkTable(res.summary_table);
    safeSetText('bench-f1-gain', `+${res.f1_improvement_pct}%`);
    safeSetText('bench-lead-time', `+${res.lead_time_advantage_seconds}s`);
    if (res.metrics && res.metrics.world_model) {
      safeSetText('bench-fpr', res.metrics.world_model.fpr.toFixed(3));
    }
  } catch (err) {
    console.error('Benchmark load error:', err);
  }
}

async function runBenchmarks() {
  showToast('Running reproducible benchmark evaluation suite...', 'info');
  try {
    const res = await api.post('/api/v1/benchmarks/run', {});
    state.benchmarkData = res;
    renderBenchmarkTable(res.summary_table);
    showToast('Benchmark run completed!', 'success');
  } catch (err) {
    showToast('Benchmark error: ' + err.message, 'error');
  }
}

function renderBenchmarkTable(items) {
  const tbody = document.getElementById('benchmark-tbody');
  if (!tbody || !items) return;
  tbody.innerHTML = items.map(it => `
    <tr>
      <td style="font-weight: 700; color: ${it.Model.includes('CyberCast') ? '#00f0ff' : '#f8fafc'};">${it.Model}</td>
      <td>${(it['F1-Score'] * 100).toFixed(1)}%</td>
      <td>${(it.Precision * 100).toFixed(1)}%</td>
      <td>${(it.Recall * 100).toFixed(1)}%</td>
      <td style="font-family: 'JetBrains Mono'; font-weight: 700; color: #00f0ff;">${it['Early Lead Time']}</td>
      <td>${it['Multi-Stage Dynamics']}</td>
    </tr>
  `).join('');
}

// Reports
async function generateReport(ip, fmt) {
  try {
    const res = await api.post('/api/v1/reports/generate', {
      target_ip: ip,
      format: fmt
    });
    const pre = document.getElementById('report-preview');
    if (pre) pre.textContent = res.content;
    showToast('Forensic report generated!', 'success');

    // Update download buttons
    const btnMd = document.getElementById('btn-dl-md');
    const btnStix = document.getElementById('btn-dl-stix');
    if (btnMd) {
      btnMd.onclick = () => downloadFile(`threat_report_${ip.replace(/\./g, '_')}.md`, res.markdown_content, 'text/markdown');
    }
    if (btnStix) {
      btnStix.onclick = () => downloadFile(`stix_bundle_${ip.replace(/\./g, '_')}.json`, res.stix_json_content, 'application/json');
    }
  } catch (err) {
    showToast('Report error: ' + err.message, 'error');
  }
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Downloaded ${filename}`, 'success');
}

// Compliance
async function loadComplianceAudit() {
  try {
    const res = await api.get('/api/v1/compliance/audit');
    const c1 = document.getElementById('audit-col-1');
    const c2 = document.getElementById('audit-col-2');
    if (c1 && c2 && res.audit_data) {
      const mid = Math.ceil(res.audit_data.length / 2);
      const left = res.audit_data.slice(0, mid);
      const right = res.audit_data.slice(mid);

      c1.innerHTML = left.map(it => `
        <div style="margin-bottom: 8px; font-size: 11.5px;">
          <span style="color: #10b981; font-weight: 700;">✅ #${it.id} ${it.requirement}:</span>
          <code style="color: #38bdf8;">${it.status}</code> — <span style="color: #cbd5e1;">${it.details}</span>
        </div>
      `).join('');

      c2.innerHTML = right.map(it => `
        <div style="margin-bottom: 8px; font-size: 11.5px;">
          <span style="color: #10b981; font-weight: 700;">✅ #${it.id} ${it.requirement}:</span>
          <code style="color: #38bdf8;">${it.status}</code> — <span style="color: #cbd5e1;">${it.details}</span>
        </div>
      `).join('');
    }

    // Policies
    if (res.policies) {
      safeSetText('policy-privacy', res.policies.privacy);
      safeSetText('policy-terms', res.policies.terms);
      safeSetText('policy-cookie', res.policies.cookie);
      safeSetText('policy-disclaimer', res.policies.disclaimer);
    }
  } catch (err) {
    console.error('Compliance error:', err);
  }
}

// REST Sandbox
async function testApiEndpoint() {
  const epEl = document.getElementById('api-test-endpoint');
  const endpoint = epEl ? epEl.value : '/api/v1/health';
  const outPre = document.getElementById('api-test-output');
  const statusEl = document.getElementById('api-test-status');

  try {
    let res;
    if (endpoint === '/api/v1/health') {
      res = await api.get('/api/v1/health');
    } else if (endpoint === '/api/v1/pipeline') {
      res = await api.get('/api/v1/pipeline');
    } else if (endpoint === '/api/v1/cases') {
      res = await api.get('/api/v1/cases');
    } else if (endpoint === '/api/v1/evidence') {
      res = await api.get('/api/v1/evidence');
    } else {
      res = await api.post('/api/v1/proctor/ip', { target_ip: '10.0.1.99', profile: 'Reconnaissance Scanner' });
    }

    safeSetText('api-test-status', 'HTTP 200 OK');
    if (outPre) outPre.textContent = JSON.stringify(res, null, 2);
    showToast(`Invoked ${endpoint} successfully`, 'success');
  } catch (err) {
    safeSetText('api-test-status', 'HTTP Error');
    if (outPre) outPre.textContent = err.message;
    showToast('API call error: ' + err.message, 'error');
  }
}

// Toast helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-shelf') || document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast-msg ${type}`;
  toast.innerHTML = `<span>●</span> <span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ============================================================================
// SOC AI COPILOT & THREAT ADVISORY CHATBOT CONTROLLER
// ============================================================================

function toggleCopilotDrawer() {
  const drawer = document.getElementById('copilot-drawer');
  if (!drawer) return;
  drawer.classList.toggle('open');
  if (drawer.classList.contains('open')) {
    const input = document.getElementById('copilot-chat-input');
    if (input) setTimeout(() => input.focus(), 150);
    scrollCopilotToBottom();
  }
}

function clearCopilotMessages() {
  const welcomeHtml = `
    <div class="copilot-msg bot">
      <div class="copilot-msg-avatar">🤖</div>
      <div class="copilot-msg-bubble">
        <div class="copilot-msg-title">🛡️ CyberCast AI SOC Copilot Initialized</div>
        <p>Conversation history reset. I am ready to analyze live telemetry and formulate <b>💡 How It Can Be Better</b> defense playbooks.</p>
      </div>
    </div>
  `;
  const m1 = document.getElementById('copilot-messages');
  const m2 = document.getElementById('copilot-main-messages');
  if (m1) m1.innerHTML = welcomeHtml;
  if (m2) m2.innerHTML = welcomeHtml;
  showToast('Copilot conversation cleared', 'info');
}

function scrollCopilotToBottom() {
  const m1 = document.getElementById('copilot-messages');
  const m2 = document.getElementById('copilot-main-messages');
  if (m1) m1.scrollTop = m1.scrollHeight;
  if (m2) m2.scrollTop = m2.scrollHeight;
}

function handleCopilotKeyDown(e) {
  if (e.key === 'Enter') {
    e.preventDefault();
    sendCopilotMessage();
  }
}

function handleMainCopilotKeyDown(e) {
  if (e.key === 'Enter') {
    e.preventDefault();
    sendMainCopilotMessage();
  }
}

function sendQuickCopilotPrompt(promptText) {
  const input = document.getElementById('copilot-chat-input');
  if (input) input.value = promptText;
  sendCopilotMessage();
}

function sendMainCopilotPrompt(promptText) {
  const input = document.getElementById('copilot-main-input');
  if (input) input.value = promptText;
  sendMainCopilotMessage();
}

function appendCopilotMessage(sender, htmlContent) {
  const containers = [
    document.getElementById('copilot-messages'),
    document.getElementById('copilot-main-messages')
  ];

  containers.forEach(container => {
    if (!container) return;
    const msgEl = document.createElement('div');
    msgEl.className = `copilot-msg ${sender}`;
    msgEl.innerHTML = `
      <div class="copilot-msg-avatar">${sender === 'user' ? '👤' : '🤖'}</div>
      <div class="copilot-msg-bubble">${htmlContent}</div>
    `;
    container.appendChild(msgEl);
  });

  scrollCopilotToBottom();
}

async function executeCopilotChat(messageText) {
  if (!messageText || !messageText.trim()) return;
  const q = messageText.trim();

  // Render user message
  appendCopilotMessage('user', `<div>${escapeHtml(q)}</div>`);

  // Show typing indicators
  const ind1 = document.getElementById('copilot-typing-indicator');
  const ind2 = document.getElementById('copilot-main-typing-indicator');
  if (ind1) ind1.style.display = 'flex';
  if (ind2) ind2.style.display = 'flex';
  scrollCopilotToBottom();

  // Gather live operational context
  const activePreset = document.getElementById('active-source-display')?.textContent || 'CTU-13 Neris';
  const targetIp = document.getElementById('proctor-target-ip')?.value || '10.0.1.99';
  const curStageName = document.getElementById('metric-stage-name')?.textContent || 'Stage 0 - Benign Baseline';
  const projStageName = document.getElementById('proj-stage-name')?.textContent || 'Stage 3 - Lateral Movement';
  const threatRiskText = document.getElementById('badge-threat-risk')?.textContent || '50%';
  const riskFloat = parseFloat(threatRiskText.replace(/[^0-9.]/g, '')) / 100 || 0.55;

  const contextPayload = {
    active_preset: activePreset,
    target_ip: targetIp,
    current_stage_name: curStageName,
    projected_stage_name: projStageName,
    current_risk: riskFloat,
    future_risk: Math.min(0.95, riskFloat + 0.35),
    time_to_compromise_sec: 42.0,
    model_type: state.modelType ? state.modelType.toUpperCase() : 'TRANSFORMER',
    proctor_score: state.testedIpResult ? state.testedIpResult.proctor.proctor_score : 85,
    proctor_verdict: state.testedIpResult ? state.testedIpResult.proctor.proctor_verdict : 'CRITICAL_INTRUSION'
  };

  try {
    const res = await api.post('/api/v1/copilot/chat', {
      message: q,
      context: contextPayload
    });

    if (ind1) ind1.style.display = 'none';
    if (ind2) ind2.style.display = 'none';

    // Format HTML response
    let responseHtml = `
      <div class="copilot-msg-title">${escapeHtml(res.headline || '🤖 SOC Threat Advisory')}</div>
      <div style="font-size: 12px; line-height: 1.6; color: #cbd5e1; margin-bottom: 8px;">
        ${formatMarkdown(res.analysis || res.response)}
      </div>
    `;

    if (res.improvements && res.improvements.length > 0) {
      responseHtml += `
        <div class="copilot-better-card">
          <div class="copilot-better-title">
            <span>💡</span> How It Can Be Better (Actionable Optimization Playbook):
          </div>
          <ul class="copilot-better-list">
            ${res.improvements.map(imp => `<li>${formatMarkdown(imp)}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    if (res.action_code) {
      const codeId = `copilot-cmd-${Date.now()}`;
      responseHtml += `
        <div style="margin-top: 10px; position: relative;">
          <div style="font-size: 11px; font-weight: 700; color: #38bdf8; margin-bottom: 4px;">⚡ Recommended Command:</div>
          <pre id="${codeId}" class="code-preview-block" style="padding: 8px 10px; margin: 0; font-size: 11px;">${escapeHtml(res.action_code)}</pre>
          <button class="code-copy-btn" onclick="copyText('${codeId}')">Copy</button>
        </div>
      `;
    }

    appendCopilotMessage('bot', responseHtml);
  } catch (err) {
    if (ind1) ind1.style.display = 'none';
    if (ind2) ind2.style.display = 'none';
    appendCopilotMessage('bot', `
      <div style="color: #ef4444; font-weight: 700;">⚠️ Copilot Advisory Notice</div>
      <div style="font-size: 11.5px; margin-top: 4px;">Unable to reach reasoning engine: ${escapeHtml(err.message)}</div>
    `);
  }
}

function sendCopilotMessage() {
  const input = document.getElementById('copilot-chat-input');
  if (!input) return;
  const val = input.value;
  input.value = '';
  executeCopilotChat(val);
}

function sendMainCopilotMessage() {
  const input = document.getElementById('copilot-main-input');
  if (!input) return;
  const val = input.value;
  input.value = '';
  executeCopilotChat(val);
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatMarkdown(text) {
  if (!text) return '';
  return text
    .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
    .replace(/`([^`]+)`/g, '<code style="background: rgba(56,189,248,0.15); color: #38bdf8; padding: 1px 4px; border-radius: 3px; font-family: monospace;">$1</code>')
    .replace(/\n\n/g, '<br><br>')
    .replace(/\n- /g, '<br>• ');
}

// Window globals
window.safeSetText = safeSetText;
window.safeSetHtml = safeSetHtml;
window.showToast = showToast;
window.testIpThreat = testIpThreat;
window.simulateCounterfactual = simulateCounterfactual;
window.toggleCopilotDrawer = toggleCopilotDrawer;
window.clearCopilotMessages = clearCopilotMessages;
window.sendQuickCopilotPrompt = sendQuickCopilotPrompt;
window.sendCopilotMessage = sendCopilotMessage;
window.handleCopilotKeyDown = handleCopilotKeyDown;
window.sendMainCopilotPrompt = sendMainCopilotPrompt;
window.sendMainCopilotMessage = sendMainCopilotMessage;
window.handleMainCopilotKeyDown = handleMainCopilotKeyDown;

// Window load trigger
window.addEventListener('DOMContentLoaded', initApp);
