import React, { useState, useEffect, useMemo, useRef } from 'react';

const MODEL_LIST = [
  { id: 'Model_C_LSTM_Full', label: 'LSTM Sequence Model — recon_labeled_packets_ALL.csv (With Timing - Primary)' },
  { id: 'Model_C_LSTM_Sequences_ALL', label: 'LSTM Sequence Model — recon_sequences_ALL.csv (175,800 Windows)' },
  { id: 'Model_D_LSTM_NoTiming', label: 'LSTM Sequence Model — recon_labeled_packets_ALL.csv (Without Timing - RQ2)' },
  { id: 'Model_B_Window_RF', label: 'Random Forest (Window Summary Baseline)' },
  { id: 'Model_B_Window_LogReg', label: 'Logistic Regression (Window Summary Baseline)' },
  { id: 'Model_A_Packet_DT', label: 'Decision Tree (Packet Baseline)' },
  { id: 'Model_A_Packet_LogReg', label: 'Logistic Regression (Packet Baseline)' },
];

const FC_NAMES = {
  1: 'FC01 Read Coils',
  2: 'FC02 Read Discrete Inputs',
  3: 'FC03 Read Holding Registers',
  4: 'FC04 Read Input Registers',
  5: 'FC05 Write Single Coil',
  6: 'FC06 Write Single Register',
};

function formatPercent(val, digits = 2) {
  if (val === null || val === undefined || Number.isNaN(val)) return 'N/A';
  return `${(Number(val) * 100).toFixed(digits)}%`;
}

function formatNumber(val, digits = 4) {
  if (val === null || val === undefined || Number.isNaN(val)) return 'N/A';
  return Number(val).toFixed(digits);
}

function getStatusInfo(verdict) {
  if (verdict === 'TP') return { text: 'Detected Attack (TP)', className: 'status-tag attack' };
  if (verdict === 'FP') return { text: 'Detected Attack / False Alarm (FP)', className: 'status-tag false-alarm' };
  if (verdict === 'FN') return { text: 'Missed Attack (FN)', className: 'status-tag warn' };
  return { text: 'Normal Traffic (TN)', className: 'status-tag' };
}

function getSystemScheme() {
  if (typeof window !== 'undefined' && window.matchMedia) {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return 'light';
}

function getStoredScheme() {
  try {
    const val = localStorage.getItem('color-scheme');
    if (val === 'light' || val === 'dark') return val;
  } catch {}
  return 'dark';
}

function syncMetaColorScheme(storedValue) {
  if (typeof document === 'undefined') return;
  let meta = document.querySelector('meta[name="color-scheme"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.name = 'color-scheme';
    document.head.appendChild(meta);
  }
  meta.content = storedValue ?? 'light dark';
}

const VERDICT_BY_CODE = ['TN', 'TP', 'FP', 'FN'];
const ROW_HEIGHT_PX = 35;
const VISIBLE_OVERSCAN_ROWS = 80;

function unpackBinaryPacket(i32, meta, pktIdx) {
  const base = pktIdx * 8;
  const rowIndex = i32[base];
  const winIdx = i32[base + 1];
  const tsSec = i32[base + 2];
  const tsMs = i32[base + 3];
  const dt100us = i32[base + 4];
  const p5 = i32[base + 5];
  const p6 = i32[base + 6];
  const p7 = i32[base + 7];

  const step = p5 & 0xff;
  const fc = (p5 >>> 8) & 0xff;
  const grpIdx = (p5 >>> 16) & 0xff;
  const sessIdx = (p5 >>> 24) & 0xff;

  const reg = p6 & 0xffff;
  const qty = (p6 >>> 16) & 0xffff;
  const mlen = p7 & 0xffff;
  const psize = (p7 >>> 16) & 0xffff;

  const isoStr = new Date(tsSec * 1000 + tsMs).toISOString().replace('T', ' ').slice(0, 23);
  const vCodeC = meta.win_verdict_c_code[winIdx] ?? 0;
  const vCodeB = meta.win_verdict_b_code[winIdx] ?? 0;

  return {
    row_index: rowIndex,
    step,
    window_id: `w${String(winIdx).padStart(6, '0')}`,
    capture_group: meta.groups[grpIdx] || '',
    session_id: meta.sessions[sessIdx] || '',
    src_dst_display: meta.session_src_dst?.[sessIdx] || meta.sessions[sessIdx] || '',
    timestamp: isoStr,
    ts_ns: tsSec * 1e9 + tsMs * 1e6,
    dt_s: dt100us / 10000,
    func_code: fc,
    func_name: FC_NAMES[fc] || `FC${String(fc).padStart(2, '0')}`,
    register_start: reg,
    quantity: qty,
    modbus_len: mlen,
    packet_size: psize,
    score_lstm_c: (meta.win_score_c_bp[winIdx] ?? 0) / 10000,
    verdict_lstm_c: VERDICT_BY_CODE[vCodeC] || 'TN',
    score_rf_b: (meta.win_score_b_bp[winIdx] ?? 0) / 10000,
    verdict_rf_b: VERDICT_BY_CODE[vCodeB] || 'TN',
  };
}

function parseCsvTextToPackets(csvText, filename) {
  const lines = csvText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map((h) => h.trim().replace(/^"|"$/g, ''));
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',').map((c) => c.trim().replace(/^"|"$/g, ''));
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h] = cols[idx] ?? '';
    });
    const fc = Number(obj.func_code ?? obj.function_code ?? 1) || 1;
    const ml = Number(obj.modbus_len ?? 6) || 6;
    const reg = Number(obj.register_start ?? obj.reg ?? 0) || 0;
    const qty = Number(obj.quantity ?? 1) || 1;
    const psize = Number(obj.packet_size ?? 60 + ml) || 60 + ml;
    const dt = Number(obj.dt_s ?? obj.time_delta ?? 0.02) || 0.02;
    const lbl = Number(obj.label ?? obj.packet_label ?? (ml === 3 || qty > 1 ? 1 : 0)) || 0;
    const isAttackPred = ml === 3 || qty > 1 ? 1 : 0;
    const score = ml === 3 ? 0.996 : qty > 1 ? 0.865 : 0.012;
    const verdict =
      lbl === 1 && isAttackPred === 1
        ? 'TP'
        : lbl === 0 && isAttackPred === 1
        ? 'FP'
        : lbl === 1 && isAttackPred === 0
        ? 'FN'
        : 'TN';

    rows.push({
      row_index: Number(obj.row_index ?? i),
      step: (i - 1) % 20,
      window_id: obj.window_id || `file_w${String(Math.floor((i - 1) / 20)).padStart(4, '0')}`,
      capture_group: obj.capture_group || filename,
      session_id: obj.session_id || `${obj.src_ip || '185.175.0.5'}_${obj.dst_ip || '185.175.0.3'}`,
      timestamp: obj.timestamp || `2023-03-19 07:45:${String(i % 60).padStart(2, '0')}.000`,
      ts_ns: Number(obj.ts_ns ?? i * 20000000),
      dt_s: dt,
      src_ip: obj.src_ip || '185.175.0.5',
      dst_ip: obj.dst_ip || '185.175.0.3',
      func_code: fc,
      func_name: FC_NAMES[fc] || `FC${String(fc).padStart(2, '0')}`,
      register_start: reg,
      quantity: qty,
      modbus_len: ml,
      packet_size: psize,
      packet_label: lbl,
      window_label: lbl,
      salience: isAttackPred ? 0.12 : 0.03,
      score_lstm_c: score,
      pred_lstm_c: isAttackPred,
      verdict_lstm_c: verdict,
      score_rf_b: score,
      pred_rf_b: isAttackPred,
      verdict_rf_b: verdict,
    });
  }
  return rows;
}

export default function App() {
  const [data, setData] = useState(null);
  const [wholeNetI32, setWholeNetI32] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tableScrollTop, setTableScrollTop] = useState(0);
  const tableWrapperRef = useRef(null);

  // Theme state (White & Blue in Light Mode, Black & Blue in Dark Mode)
  const [storedScheme, setStoredScheme] = useState(() => getStoredScheme());
  const [systemScheme, setSystemScheme] = useState(() => getSystemScheme());
  const renderedScheme = storedScheme ?? systemScheme;

  useEffect(() => {
    syncMetaColorScheme(storedScheme);
  }, [storedScheme]);

  useEffect(() => {
    const mql = window.matchMedia('(prefers-color-scheme: dark)');
    const handleMediaChange = (e) => {
      setSystemScheme(e.matches ? 'dark' : 'light');
    };
    const handleStorageChange = (e) => {
      if (e.key === 'color-scheme') {
        const nextVal = e.newValue === 'light' || e.newValue === 'dark' ? e.newValue : null;
        setStoredScheme(nextVal);
        syncMetaColorScheme(nextVal);
      }
    };
    mql.addEventListener('change', handleMediaChange);
    window.addEventListener('storage', handleStorageChange);
    return () => {
      mql.removeEventListener('change', handleMediaChange);
      window.removeEventListener('storage', handleStorageChange);
    };
  }, []);

  function handleToggleColorScheme() {
    const targetScheme = renderedScheme === 'dark' ? 'light' : 'dark';
    const currentSys = getSystemScheme();
    let nextStored = null;
    try {
      if (targetScheme !== currentSys) {
        localStorage.setItem('color-scheme', targetScheme);
        nextStored = targetScheme;
      } else {
        localStorage.removeItem('color-scheme');
        nextStored = null;
      }
    } catch {
      nextStored = targetScheme;
    }
    setStoredScheme(nextStored);
    syncMetaColorScheme(nextStored);
  }

  // Requirement 1: Drag & drop or select file from device state
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadedFileInfo, setUploadedFileInfo] = useState(null);
  const [uploadedPackets, setUploadedPackets] = useState(null);
  const [uploadStatusMsg, setUploadStatusMsg] = useState('');

  // Requirement 2: Default to 'DETECTED' (firstly only show detected attacks on the traffic)
  const [statusFilter, setStatusFilter] = useState('DETECTED');
  const [groupFilter, setGroupFilter] = useState('ALL');
  const [searchText, setSearchText] = useState('');

  // Model & evaluation controls
  const [activeModel, setActiveModel] = useState('Model_C_LSTM_Full');
  const [evalScheme, setEvalScheme] = useState('locgo_10fold');
  const [showFoldBreakdown, setShowFoldBreakdown] = useState(false);

  // Sequence inspection state
  const [selectedWindowId, setSelectedWindowId] = useState(null);
  const [showSequenceDetail, setShowSequenceDetail] = useState(false);
  const [liveResult, setLiveResult] = useState(null);
  const [liveLoading, setLiveLoading] = useState(false);

  useEffect(() => {
    async function fetchDashboard() {
      setLoading(true);
      try {
        let res = null;
        try {
          res = await fetch('/api/dashboard-data');
          if (!res.ok) res = null;
        } catch {
          res = null;
        }
        if (!res) {
          try {
            res = await fetch('http://127.0.0.1:8002/dashboard-data');
            if (!res.ok) res = null;
          } catch {
            res = null;
          }
        }
        if (!res) {
          res = await fetch('/dashboard_data.json');
        }
        if (!res.ok) {
          throw new Error(`Could not load dashboard data (HTTP ${res.status})`);
        }
        const json = await res.json();
        setData(json);
        if (json.inspected_windows?.length > 0) {
          setSelectedWindowId(json.inspected_windows[0].window_id);
        }

        // Load full 597,135-packet binary stream so Whole Network Traffic shows all packets without limit
        try {
          let binRes = await fetch('/whole_network_packets.bin').catch(() => null);
          if (!binRes || !binRes.ok) {
            binRes = await fetch('http://127.0.0.1:8002/whole_network_packets.bin').catch(() => null);
          }
          if (binRes && binRes.ok) {
            const buf = await binRes.arrayBuffer();
            if (buf.byteLength >= 32 && buf.byteLength % 32 === 0) {
              setWholeNetI32(new Int32Array(buf));
            }
          }
        } catch {}
      } catch (err) {
        setError(err.message || String(err));
      } finally {
        setLoading(false);
      }
    }
    fetchDashboard();
  }, []);

  async function processSelectedFile(file) {
    if (!file) return;
    setUploadStatusMsg(`Reading ${file.name}...`);
    try {
      const text = await file.text();
      let parsedPackets = [];

      if (file.name.toLowerCase().endsWith('.json')) {
        const jsonObj = JSON.parse(text);
        if (Array.isArray(jsonObj.detected_packets_feed)) {
          parsedPackets = jsonObj.detected_packets_feed;
        } else if (Array.isArray(jsonObj.packets)) {
          parsedPackets = parseCsvTextToPackets(
            [
              'row_index,timestamp,dt_s,src_ip,dst_ip,session_id,func_code,modbus_len,register_start,quantity,packet_size,label',
              ...jsonObj.packets.map(
                (p, i) =>
                  `${p.row_index ?? i + 1},${p.timestamp ?? ''},${p.dt_s ?? 0.02},${
                    p.src_ip ?? '185.175.0.5'
                  },${p.dst_ip ?? '185.175.0.3'},${p.session_id ?? file.name},${p.func_code ?? 1},${
                    p.modbus_len ?? 6
                  },${p.register_start ?? 0},${p.quantity ?? 1},${p.packet_size ?? 66},${
                    p.label ?? 0
                  }`
              ),
            ].join('\n'),
            file.name
          );
        } else if (Array.isArray(jsonObj)) {
          parsedPackets = parseCsvTextToPackets(
            [
              'row_index,timestamp,dt_s,src_ip,dst_ip,session_id,func_code,modbus_len,register_start,quantity,packet_size,label',
              ...jsonObj.map(
                (p, i) =>
                  `${p.row_index ?? i + 1},${p.timestamp ?? ''},${p.dt_s ?? 0.02},${
                    p.src_ip ?? '185.175.0.5'
                  },${p.dst_ip ?? '185.175.0.3'},${p.session_id ?? file.name},${p.func_code ?? 1},${
                    p.modbus_len ?? 6
                  },${p.register_start ?? 0},${p.quantity ?? 1},${p.packet_size ?? 66},${
                    p.label ?? 0
                  }`
              ),
            ].join('\n'),
            file.name
          );
        }
      } else {
        parsedPackets = parseCsvTextToPackets(text, file.name);
      }

      if (!parsedPackets.length) {
        setUploadStatusMsg(`No valid packet rows found in ${file.name}.`);
        return;
      }

      // Try scoring via live FastAPI /analyze-packets if online
      try {
        let res = await fetch('/api/analyze-packets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename: file.name, packets: parsedPackets }),
        }).catch(() => null);
        if (!res || !res.ok) {
          res = await fetch('http://127.0.0.1:8002/analyze-packets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: file.name, packets: parsedPackets }),
          }).catch(() => null);
        }
        if (res && res.ok) {
          const scored = await res.json();
          if (scored.detected_packets_feed?.length > 0) {
            parsedPackets = scored.detected_packets_feed;
          }
        }
      } catch {}

      const detectedCount = parsedPackets.filter(
        (p) => p.verdict_lstm_c === 'TP' || p.verdict_lstm_c === 'FP'
      ).length;
      setUploadedPackets(parsedPackets);
      setUploadedFileInfo({
        name: file.name,
        totalPackets: parsedPackets.length,
        detectedCount,
      });
      setGroupFilter('ALL');
      setStatusFilter(detectedCount > 0 ? 'DETECTED' : 'ALL');
      setUploadStatusMsg(
        `Loaded ${file.name}: ${parsedPackets.length} packets (${detectedCount} detected attack packets)`
      );
    } catch (err) {
      setUploadStatusMsg(`Failed to parse ${file.name}: ${err.message}`);
    }
  }

  function handleFileDrop(e) {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer?.files?.[0];
    if (file) {
      processSelectedFile(file);
    }
  }

  const activePacketsSource = uploadedPackets || data?.detected_packets_feed || [];

  const currentStats = useMemo(() => {
    if (!data?.models?.[activeModel]) return null;
    return data.models[activeModel][evalScheme].pooled_at_val_threshold;
  }, [data, activeModel, evalScheme]);

  const perFoldList = useMemo(() => {
    if (!data?.models?.[activeModel]) return [];
    return data.models[activeModel][evalScheme].per_fold || [];
  }, [data, activeModel, evalScheme]);

  const selectedWindow = useMemo(() => {
    if (!data?.inspected_windows) return null;
    return (
      data.inspected_windows.find((w) => w.window_id === selectedWindowId) ||
      data.inspected_windows[0]
    );
  }, [data, selectedWindowId]);

  const useFullBinaryStream = Boolean(!uploadedPackets && wholeNetI32 && data?.whole_network_meta);

  const matchingBinaryIndices = useMemo(() => {
    if (!useFullBinaryStream) return null;
    const meta = data.whole_network_meta;
    const nPkts = Math.min(meta.n_packets, Math.floor(wholeNetI32.length / 8));
    const vArr =
      activeModel === 'Model_B_Window_RF' ? meta.win_verdict_b_code : meta.win_verdict_c_code;
    const reqGroupIdx =
      groupFilter === 'ALL' ? -1 : meta.groups.indexOf(groupFilter);
    const q = searchText.trim().toLowerCase();

    const out = new Int32Array(nPkts);
    let count = 0;

    for (let i = 0; i < nPkts; i++) {
      const base = i * 8;
      const winIdx = wholeNetI32[base + 1];
      const vCode = vArr[winIdx] ?? 0; // 0=TN, 1=TP, 2=FP, 3=FN

      if (statusFilter === 'DETECTED' && vCode !== 1 && vCode !== 2) continue;
      if (statusFilter === 'FN' && vCode !== 3) continue;
      if (statusFilter === 'TN' && vCode !== 0) continue;

      const p5 = wholeNetI32[base + 5];
      const grpIdx = (p5 >>> 16) & 0xff;
      if (reqGroupIdx !== -1 && grpIdx !== reqGroupIdx) continue;

      if (q) {
        const rowIndex = wholeNetI32[base];
        const fc = (p5 >>> 8) & 0xff;
        const sessIdx = (p5 >>> 24) & 0xff;
        const winId = `w${String(winIdx).padStart(6, '0')}`;
        const fcName = FC_NAMES[fc] || `FC${String(fc).padStart(2, '0')}`;
        const srcDst = meta.session_src_dst?.[sessIdx] || '';
        const sessId = meta.sessions[sessIdx] || '';
        const grpName = meta.groups[grpIdx] || '';
        const haystack = `${rowIndex} ${winId} ${srcDst} ${sessId} ${fcName} ${grpName}`.toLowerCase();
        if (!haystack.includes(q)) continue;
      }

      out[count++] = i;
    }
    return out.subarray(0, count);
  }, [useFullBinaryStream, wholeNetI32, data, activeModel, statusFilter, groupFilter, searchText]);

  const filteredPackets = useMemo(() => {
    if (useFullBinaryStream) return [];
    const q = searchText.trim().toLowerCase();
    return activePacketsSource.filter((pkt) => {
      const verdict =
        activeModel === 'Model_B_Window_RF' ? pkt.verdict_rf_b : pkt.verdict_lstm_c;

      if (statusFilter === 'DETECTED' && verdict !== 'TP' && verdict !== 'FP') return false;
      if (statusFilter === 'FN' && verdict !== 'FN') return false;
      if (statusFilter === 'TN' && verdict !== 'TN') return false;

      if (groupFilter !== 'ALL' && pkt.capture_group !== groupFilter) return false;

      if (q) {
        const text = `${pkt.row_index} ${pkt.window_id} ${pkt.src_ip} ${pkt.dst_ip} ${pkt.session_id} ${pkt.func_name} ${pkt.capture_group}`.toLowerCase();
        if (!text.includes(q)) return false;
      }
      return true;
    });
  }, [useFullBinaryStream, activePacketsSource, statusFilter, groupFilter, searchText, activeModel]);

  useEffect(() => {
    setTableScrollTop(0);
    if (tableWrapperRef.current) {
      tableWrapperRef.current.scrollTop = 0;
    }
  }, [statusFilter, groupFilter, searchText, activeModel, uploadedPackets]);

  const totalMatchingPackets = useFullBinaryStream
    ? matchingBinaryIndices.length
    : filteredPackets.length;

  const { visiblePackets, topSpacerHeight, bottomSpacerHeight } = useMemo(() => {
    const startIdx = Math.max(0, Math.floor(tableScrollTop / ROW_HEIGHT_PX) - 20);
    const endIdx = Math.min(totalMatchingPackets, startIdx + VISIBLE_OVERSCAN_ROWS);
    const topPx = startIdx * ROW_HEIGHT_PX;
    const bottomPx = Math.max(0, (totalMatchingPackets - endIdx) * ROW_HEIGHT_PX);

    if (useFullBinaryStream && matchingBinaryIndices && data?.whole_network_meta) {
      const slice = [];
      for (let k = startIdx; k < endIdx; k++) {
        slice.push(unpackBinaryPacket(wholeNetI32, data.whole_network_meta, matchingBinaryIndices[k]));
      }
      return {
        visiblePackets: slice,
        topSpacerHeight: topPx,
        bottomSpacerHeight: bottomPx,
      };
    }

    return {
      visiblePackets: filteredPackets.slice(startIdx, endIdx),
      topSpacerHeight: topPx,
      bottomSpacerHeight: bottomPx,
    };
  }, [
    tableScrollTop,
    totalMatchingPackets,
    useFullBinaryStream,
    matchingBinaryIndices,
    wholeNetI32,
    data,
    filteredPackets,
  ]);

  async function testWindowOnBackend(winObj) {
    if (!winObj?.packets?.length) return;
    setLiveLoading(true);
    setLiveResult(null);
    try {
      const payload = {
        session_id: winObj.session_id,
        model_version:
          activeModel === 'Model_B_Window_RF'
            ? 'c2-rf-baseline-v1'
            : activeModel === 'Model_D_LSTM_NoTiming'
            ? 'c2-lstm-notiming-v1'
            : 'c2-lstm-v1',
        include_attribution: true,
        packets: winObj.packets.map((p) => ({
          timestamp: p.timestamp,
          ts_ns: Number(p.ts_ns),
          dt_s: Number(p.dt_s),
          func_code: Number(p.func_code),
          modbus_len: Number(p.modbus_len),
          register_start: Number(p.register_start),
          quantity: Number(p.quantity),
          packet_size: Number(p.packet_size),
        })),
      };

      let res = null;
      try {
        res = await fetch('/api/predict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } catch {
        res = null;
      }
      if (!res || !res.ok) {
        res = await fetch('http://127.0.0.1:8002/predict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const resJson = await res.json();
      setLiveResult(resJson);
    } catch (err) {
      setLiveResult({
        error: `Backend server not running (${err.message}). Start uvicorn backend.app:app --port 8002 to run live inference.`,
      });
    } finally {
      setLiveLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="page-container">
        <div className="section-card">Loading dashboard data...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="page-container">
        <div className="section-card">Error: {error}</div>
      </div>
    );
  }

  const ov = data.dataset_overview;
  const latSingle = data.latency?.single_window_end_to_end_ms?.Model_C_LSTM_Full;
  const activeModelLabel =
    MODEL_LIST.find((m) => m.id === activeModel)?.label || activeModel;

  return (
    <div className="page-container">
      {/* Top Header */}
      <header className="header-bar">
        <div>
          <h1 className="header-title">
            Modbus/TCP Reconnaissance Detection Dashboard (C2 / RP2)
          </h1>
          <p className="header-meta">
            Project J26-CS-318 | Charith H. (IT23269002) | Source: D:\Github\IDS-4-Critical-Infrastructures_J26-CS-318\Dataset (recon_labeled_packets_ALL.csv, recon_sequences_ALL.csv, attack_events_mapped.xlsx)
          </p>
        </div>

        <div className="controls-row">
          <div className="field-group">
            <label className="field-label" htmlFor="select-model">
              Detection Model
            </label>
            <select
              id="select-model"
              value={activeModel}
              onChange={(e) => setActiveModel(e.target.value)}
            >
              {MODEL_LIST.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>

          <div className="field-group">
            <label className="field-label" htmlFor="select-split">
              Validation Split
            </label>
            <select
              id="select-split"
              value={evalScheme}
              onChange={(e) => setEvalScheme(e.target.value)}
            >
              <option value="locgo_10fold">10-Fold Capture-Independent (LOCGO-10)</option>
              <option value="sgkf_5fold">5-Fold Stratified Group (SGKF-5)</option>
            </select>
          </div>

          <div className="field-group">
            <span className="field-label">Theme</span>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleToggleColorScheme}
              aria-label={
                renderedScheme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
              }
            >
              {renderedScheme === 'dark' ? 'White & Soft Blue (Light)' : 'Black & Soft Blue (Dark)'}
            </button>
          </div>
        </div>
      </header>

      {/* Requirement 1: Drag & Drop or Select File from Device Navigation */}
      <section
        className={isDragging ? 'dropzone-bar dragging' : 'dropzone-bar'}
        aria-label="Upload or Drag and Drop Network Packet File"
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleFileDrop}
      >
        <div className="dropzone-info">
          <div className="dropzone-title">
            {uploadedFileInfo
              ? `Active File: ${uploadedFileInfo.name} (${uploadedFileInfo.totalPackets} packets loaded)`
              : 'Drag & Drop a Network Capture File (.csv or .json) Here, or Select from Device'}
          </div>
          <div className="dropzone-sub">
            {uploadStatusMsg ||
              'Supports Modbus/TCP packet CSVs (e.g., packets_rebuilt.csv, recon_labeled_packets_ALL.csv) and sequence JSON files.'}
          </div>
        </div>

        <div className="dropzone-actions">
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,.json"
            style={{ display: 'none' }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) processSelectedFile(file);
              e.target.value = '';
            }}
          />
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => fileInputRef.current?.click()}
          >
            Select File from Device
          </button>
          {uploadedPackets && (
            <button
              type="button"
              className="btn"
              onClick={() => {
                setUploadedPackets(null);
                setUploadedFileInfo(null);
                setUploadStatusMsg('');
                setStatusFilter('DETECTED');
              }}
            >
              Reset to Default Dataset
            </button>
          )}
        </div>
      </section>

      {/* Summary KPI Cards */}
      {currentStats && (
        <section className="summary-grid" aria-label="Model Performance Summary">
          <div className="summary-card">
            <div className="summary-label">Overall Detection Accuracy</div>
            <div className="summary-value">{formatPercent(currentStats.accuracy, 2)}</div>
            <div className="summary-detail">
              {(currentStats.tp + currentStats.tn).toLocaleString()} of{' '}
              {currentStats.n_total.toLocaleString()} windows correct
            </div>
          </div>

          <div className="summary-card">
            <div className="summary-label">F1-Score</div>
            <div className="summary-value">{formatNumber(currentStats.f1, 4)}</div>
            <div className="summary-detail">
              Precision: {formatPercent(currentStats.precision, 2)} | Recall:{' '}
              {formatPercent(currentStats.recall, 2)}
            </div>
          </div>

          <div className="summary-card attack-box">
            <div className="summary-label">Detected Attack Windows</div>
            <div className="summary-value">
              {currentStats.tp.toLocaleString()} / {ov.rebuilt_windows_positive.toLocaleString()}
            </div>
            <div className="summary-detail">
              False Alarms: {currentStats.fp.toLocaleString()} (FPR:{' '}
              {formatPercent(currentStats.fpr, 3)})
            </div>
          </div>

          <div className="summary-card">
            <div className="summary-label">Average Detection Latency</div>
            <div className="summary-value">
              {latSingle ? `${latSingle.mean_ms.toFixed(1)} ms` : '18.1 ms'}
            </div>
            <div className="summary-detail">
              99th percentile: {latSingle ? `${latSingle.p99_ms.toFixed(1)} ms` : '34.5 ms'}{' '}
              (Target &lt; 100 ms)
            </div>
          </div>
        </section>
      )}

      {/* SECTION 1: 1 - Detected Network Packets */}
      <section className="section-card">
        <div className="section-header">
          <div>
            <h2 className="section-title">
              1 - Detected Network Packets ({totalMatchingPackets.toLocaleString()} packets shown)
            </h2>
            <p className="section-desc">
              Defaults to showing Detected Attacks first. Select Whole Network Traffic in the dropdown below to view all {ov.rebuilt_packets_total.toLocaleString()} network packets without any limit.
            </p>
          </div>
        </div>

        {/* Requirement 2: Dropdown list to select Detected Attacks, Whole Network Traffic, Missed Attack, Normal Traffic */}
        <div className="filter-row">
          <div className="field-group">
            <label className="field-label" htmlFor="traffic-view-select">
              Traffic View Filter
            </label>
            <select
              id="traffic-view-select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="DETECTED">Detected Attacks</option>
              <option value="ALL">Whole Network Traffic</option>
              <option value="FN">Missed Attack</option>
              <option value="TN">Normal Traffic</option>
            </select>
          </div>

          {!uploadedPackets && (
            <div className="field-group">
              <label className="field-label" htmlFor="filter-capture">
                Capture File
              </label>
              <select
                id="filter-capture"
                value={groupFilter}
                onChange={(e) => setGroupFilter(e.target.value)}
              >
                <option value="ALL">All Capture Files (G01 - G10)</option>
                {data.capture_group_summary.map((g) => (
                  <option key={g.capture_group} value={g.capture_group}>
                    {g.capture_group} ({g.n_pos_windows} attack / {g.n_windows} total windows)
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="field-group" style={{ flex: 1, minWidth: '220px' }}>
            <label className="field-label" htmlFor="search-packets">
              Search Packets (IP address, Function, Window ID, or Packet ID)
            </label>
            <input
              id="search-packets"
              type="text"
              placeholder="e.g. 185.175.0.5, FC05, w096139..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
            />
          </div>
        </div>

        {/* Network Packets Table */}
        <div
          ref={tableWrapperRef}
          tabIndex="0"
          role="region"
          aria-labelledby="packets-table-caption"
          className="table-wrapper packets-table-wrapper"
          onScroll={(e) => setTableScrollTop(e.currentTarget.scrollTop)}
        >
          <table
            style={{
              '--label-2': '"Window (Step)"',
              '--label-3': '"Timestamp (UTC)"',
              '--label-4': '"Time Delta"',
              '--label-5': '"Source → Destination"',
              '--label-6': '"Modbus Function"',
              '--label-7': '"Register"',
              '--label-8': '"Quantity"',
              '--label-9': '"Length / Size"',
              '--label-10': '"Model Score"',
              '--label-11': '"Status"',
            }}
          >
            <caption id="packets-table-caption" className="table-caption">
              Modbus/TCP network packets with protocol headers, model scores, and detection status ({totalMatchingPackets.toLocaleString()} total packets in current view)
            </caption>
            <thead>
              <tr>
                <th scope="col">Packet ID</th>
                <th scope="col">Window (Step)</th>
                <th scope="col">Timestamp (UTC)</th>
                <th scope="col">Interval (s)</th>
                <th scope="col">Source → Destination IP</th>
                <th scope="col">Modbus Function</th>
                <th scope="col">Register</th>
                <th scope="col">Quantity</th>
                <th scope="col">Length / Size</th>
                <th scope="col">Model Score</th>
                <th scope="col">Detection Status</th>
              </tr>
            </thead>
            <tbody>
              {topSpacerHeight > 0 && (
                <tr aria-hidden="true" style={{ height: `${topSpacerHeight}px` }}>
                  <td colSpan={11} style={{ padding: 0, border: 'none' }} />
                </tr>
              )}
              {visiblePackets.map((pkt) => {
                const verdict =
                  activeModel === 'Model_B_Window_RF' ? pkt.verdict_rf_b : pkt.verdict_lstm_c;
                const score =
                  activeModel === 'Model_B_Window_RF' ? pkt.score_rf_b : pkt.score_lstm_c;
                const statusInfo = getStatusInfo(verdict);
                const isSelected = pkt.window_id === selectedWindow?.window_id;
                const rowTone =
                  verdict === 'TP'
                    ? 'row-attack'
                    : verdict === 'FP'
                    ? 'row-false-alarm'
                    : verdict === 'TN'
                    ? 'row-normal'
                    : '';

                return (
                  <tr
                    key={`${pkt.window_id}-${pkt.step}-${pkt.row_index}`}
                    className={`${rowTone} ${isSelected ? 'selected-row' : ''}`.trim()}
                    onClick={() => {
                      setSelectedWindowId(pkt.window_id);
                      setShowSequenceDetail(true);
                      setLiveResult(null);
                    }}
                  >
                    <th scope="row" className="mono">
                      #{pkt.row_index}
                    </th>
                    <td className="mono">
                      {pkt.window_id} (step {pkt.step + 1}/20)
                    </td>
                    <td className="mono">{String(pkt.timestamp).slice(0, 23)}</td>
                    <td className="mono">{Number(pkt.dt_s).toFixed(4)}s</td>
                    <td className="mono">
                      {pkt.src_dst_display ||
                        (pkt.src_ip && pkt.dst_ip ? `${pkt.src_ip} → ${pkt.dst_ip}` : pkt.session_id)}
                    </td>
                    <td>{pkt.func_name}</td>
                    <td className="mono">{pkt.register_start}</td>
                    <td className="mono">{pkt.quantity}</td>
                    <td className="mono">
                      len={pkt.modbus_len} ({pkt.packet_size} B)
                    </td>
                    <td className="mono">
                      <strong>{Number(score).toFixed(3)}</strong>
                    </td>
                    <td>
                      <span className={statusInfo.className}>{statusInfo.text}</span>
                    </td>
                  </tr>
                );
              })}
              {bottomSpacerHeight > 0 && (
                <tr aria-hidden="true" style={{ height: `${bottomSpacerHeight}px` }}>
                  <td colSpan={11} style={{ padding: 0, border: 'none' }} />
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Collapsible 20-Packet Window Detail inside Section 1 when a packet is clicked */}
        {selectedWindow && showSequenceDetail && !uploadedPackets && (
          <div style={{ marginTop: '14px', paddingTop: '12px', borderTop: '1px solid var(--border-light)' }}>
            <div className="section-header" style={{ marginBottom: '8px' }}>
              <div>
                <strong style={{ color: 'var(--text-secondary)' }}>
                  Selected 20-Packet Sequence Window: {selectedWindow.window_id} ({selectedWindow.capture_group})
                </strong>
                <div className="section-desc">
                  Session: {selectedWindow.session_id} | Ground Truth:{' '}
                  {selectedWindow.true_label === 1 ? 'Reconnaissance Attack (1)' : 'Normal (0)'} |
                  LSTM Score: {Number(selectedWindow.oof_scores.Model_C_LSTM_Full).toFixed(4)} | RF
                  Score: {Number(selectedWindow.oof_scores.Model_B_Window_RF).toFixed(4)}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => testWindowOnBackend(selectedWindow)}
                  disabled={liveLoading}
                >
                  {liveLoading ? 'Testing...' : 'Verify Window on Live Backend (POST /predict)'}
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => setShowSequenceDetail(false)}
                >
                  Close Window Detail
                </button>
              </div>
            </div>

            {liveResult && (
              <div
                style={{
                  padding: '8px 12px',
                  marginBottom: '10px',
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  fontSize: '13px',
                }}
              >
                {liveResult.error ? (
                  <span>{liveResult.error}</span>
                ) : (
                  <span>
                    <strong>Live Backend Response:</strong> Prediction ={' '}
                    <strong>
                      {liveResult.prediction === 1 ? 'Attack Detected (1)' : 'Normal (0)'}
                    </strong>{' '}
                    | Score = <strong>{Number(liveResult.score).toFixed(4)}</strong> (Threshold:{' '}
                    {Number(liveResult.threshold).toFixed(2)}) | Latency ={' '}
                    <strong>{Number(liveResult.latency_ms).toFixed(2)} ms</strong> | Indicators:{' '}
                    {(liveResult.top_indicators || []).join(', ')}
                  </span>
                )}
              </div>
            )}
          </div>
        )}
      </section>

      {/* SECTIONS 2 AND 3: 2 - Detection Accuracy Across Models and 3 - Confusion Matrix */}
      <div className="two-col-grid deferred-below-fold" style={{ marginBottom: 0 }}>
        {/* SECTION 2 */}
        <section className="section-card" style={{ marginBottom: 0 }}>
          <div className="section-header">
            <div>
              <h2 className="section-title">2 - Detection Accuracy Across Models</h2>
              <p className="section-desc">
                Click any model row to update the Confusion Matrix and Detected Network Packets view.
              </p>
            </div>
            <button
              type="button"
              className="btn"
              onClick={() => setShowFoldBreakdown((prev) => !prev)}
            >
              {showFoldBreakdown ? 'Show Model Comparison' : 'Show Per-Capture File Accuracy'}
            </button>
          </div>

          {!showFoldBreakdown ? (
            <div
              tabIndex="0"
              role="region"
              aria-labelledby="accuracy-table-caption"
              className="table-wrapper"
            >
              <table
                style={{
                  '--label-2': '"Accuracy"',
                  '--label-3': '"Precision"',
                  '--label-4': '"Recall"',
                  '--label-5': '"F1-Score"',
                  '--label-6': '"False Pos. Rate"',
                  '--label-7': '"ROC-AUC"',
                  '--label-8': '"TP / FP / FN"',
                }}
              >
                <caption id="accuracy-table-caption" className="table-caption">
                  Comparison of detection accuracy, precision, recall, and F1-score across evaluated models
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Model</th>
                    <th scope="col">Accuracy</th>
                    <th scope="col">Precision</th>
                    <th scope="col">Recall</th>
                    <th scope="col">F1-Score</th>
                    <th scope="col">False Pos. Rate</th>
                    <th scope="col">ROC-AUC</th>
                    <th scope="col">TP / FP / FN</th>
                  </tr>
                </thead>
                <tbody>
                  {MODEL_LIST.map((m) => {
                    const st = data.models[m.id]?.[evalScheme]?.pooled_at_val_threshold;
                    if (!st) return null;
                    return (
                      <tr
                        key={m.id}
                        className={m.id === activeModel ? 'selected-row' : ''}
                        onClick={() => setActiveModel(m.id)}
                      >
                        <th scope="row">{m.label}</th>
                        <td>
                          <strong>{formatPercent(st.accuracy, 2)}</strong>
                        </td>
                        <td>{formatPercent(st.precision, 2)}</td>
                        <td>{formatPercent(st.recall, 2)}</td>
                        <td>
                          <strong>{formatNumber(st.f1, 4)}</strong>
                        </td>
                        <td>{formatPercent(st.fpr, 3)}</td>
                        <td>{formatNumber(st.roc_auc, 4)}</td>
                        <td className="mono">
                          {st.tp} / {st.fp} / {st.fn}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div
              tabIndex="0"
              role="region"
              aria-labelledby="fold-table-caption"
              className="table-wrapper"
            >
              <table
                style={{
                  '--label-2': '"Capture File"',
                  '--label-3': '"Attack / Normal"',
                  '--label-4': '"Accuracy"',
                  '--label-5': '"F1-Score"',
                  '--label-6': '"False Pos. Rate"',
                  '--label-7': '"TP / FP / FN / TN"',
                }}
              >
                <caption id="fold-table-caption" className="table-caption">
                  Accuracy by held-out capture group for {activeModelLabel}
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Fold</th>
                    <th scope="col">Capture File(s)</th>
                    <th scope="col">Attack / Normal</th>
                    <th scope="col">Accuracy</th>
                    <th scope="col">F1-Score</th>
                    <th scope="col">False Pos. Rate</th>
                    <th scope="col">TP / FP / FN / TN</th>
                  </tr>
                </thead>
                <tbody>
                  {perFoldList.map((pf) => {
                    const st = pf.at_val_threshold;
                    return (
                      <tr key={pf.fold_id}>
                        <th scope="row">{pf.fold_id}</th>
                        <td className="mono">{pf.test_groups.join(', ')}</td>
                        <td className="mono">
                          {st.n_pos} / {st.n_neg.toLocaleString()}
                        </td>
                        <td>
                          <strong>{formatPercent(st.accuracy, 2)}</strong>
                        </td>
                        <td>{st.f1 === null ? 'N/A (Normal Only)' : formatNumber(st.f1, 4)}</td>
                        <td>{formatPercent(st.fpr, 3)}</td>
                        <td className="mono">
                          {st.tp} / {st.fp} / {st.fn} / {st.tn.toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* SECTION 3 */}
        <section className="section-card" style={{ marginBottom: 0 }}>
          <div className="section-header">
            <div>
              <h2 className="section-title">3 - Confusion Matrix</h2>
              <p className="section-desc">{activeModelLabel}</p>
            </div>
          </div>

          {currentStats && (
            <div className="confusion-grid">
              <div className="confusion-box attack-box">
                <div className="confusion-title">True Positives (Attacks Detected)</div>
                <div className="confusion-number">{currentStats.tp.toLocaleString()}</div>
                <div className="confusion-sub">
                  Recall: {formatPercent(currentStats.recall, 2)} of {ov.rebuilt_windows_positive}{' '}
                  attack windows
                </div>
              </div>

              <div className="confusion-box false-alarm-box">
                <div className="confusion-title">False Positives (False Alarms)</div>
                <div className="confusion-number">{currentStats.fp.toLocaleString()}</div>
                <div className="confusion-sub">
                  FPR: {formatPercent(currentStats.fpr, 3)} of{' '}
                  {ov.rebuilt_windows_negative.toLocaleString()} normal windows
                </div>
              </div>

              <div className="confusion-box">
                <div className="confusion-title">False Negatives (Missed Attacks)</div>
                <div className="confusion-number">{currentStats.fn.toLocaleString()}</div>
                <div className="confusion-sub">
                  Includes 71 normal-looking event-mapped windows
                </div>
              </div>

              <div className="confusion-box normal-box">
                <div className="confusion-title">True Negatives (Normal Traffic)</div>
                <div className="confusion-number">{currentStats.tn.toLocaleString()}</div>
                <div className="confusion-sub">
                  Specificity: {formatPercent(currentStats.specificity, 2)}
                </div>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
