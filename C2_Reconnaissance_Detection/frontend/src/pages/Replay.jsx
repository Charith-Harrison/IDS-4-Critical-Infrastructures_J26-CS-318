import { useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api.js';
import { ContextPath, ScoreAxis, ScoreBar, Timeline } from '../components/charts.jsx';
import { Badge, Loading, Panel } from '../components/ui.jsx';
import { B3_FEATURES, FC, FINAL_MODEL, GROUP, MODELS, PHASE, SCENARIO, STRATUM, fmt } from '../labels.js';

const SPEEDS = [
  { label: '2 / s', ms: 500, step: 1 },
  { label: '10 / s', ms: 100, step: 1 },
  { label: '50 / s', ms: 100, step: 5 },
];

export function useRuns() {
  const [runs, setRuns] = useState(null);
  useEffect(() => {
    api.runs().then(setRuns);
  }, []);
  return runs;
}

export function RunSelect({ runs, value, onChange }) {
  const groups = ['recon', 'one_pass_normal', 'revisiting_normal'];
  return (
    <select className="select" value={value} onChange={(e) => onChange(e.target.value)}>
      {groups.map((g) => (
        <optgroup key={g} label={GROUP[g]}>
          {runs
            .filter((r) => r.group === g)
            .map((r) => (
              <option key={r.run_id} value={r.run_id}>
                {SCENARIO[r.scenario]} · Site {r.site} · {r.run_id.replace('final_v1-', '')}
              </option>
            ))}
        </optgroup>
      ))}
    </select>
  );
}

// stream key -> ordered list of global row indices; per-row position in its stream and the position where its
// context segment starts (the frozen pipeline resets the context after a 60 s idle gap: c2tb/model_data.windows).
export function streamIndex(rows) {
  const pos = new Array(rows.adu_id.length);
  const segStart = new Array(rows.adu_id.length);
  const streams = {};
  const last = {};
  rows.src_ip.forEach((s, i) => {
    const k = `${s}->${rows.dst_ip[i]}`;
    const list = (streams[k] ??= []);
    list.push(i);
    const p = list.length - 1;
    pos[i] = p;
    const prev = last[k];
    segStart[i] = prev === undefined || rows.t[i] - rows.t[prev.i] > 60 ? p : prev.seg;
    last[k] = { i, seg: segStart[i] };
  });
  return { streams, pos, segStart, key: (i) => `${rows.src_ip[i]}->${rows.dst_ip[i]}` };
}

export function contextWindow(si, i) {
  const s = si.streams[si.key(i)];
  return s.slice(Math.max(si.segStart[i], si.pos[i] - 19), si.pos[i] + 1);
}

export default function Replay() {
  const runs = useRuns();
  const runFromHash = () => new URLSearchParams(location.hash.split('?')[1]).get('run');
  const [runId, setRunId] = useState(() => runFromHash() ?? 'final_v1-r086');
  useEffect(() => {
    const on = () => {
      const r = runFromHash();
      if (r) setRunId(r);
    };
    addEventListener('hashchange', on);
    return () => removeEventListener('hashchange', on);
  }, []);
  const [data, setData] = useState(null);
  const [client, setClient] = useState('actor');
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [tlModel, setTlModel] = useState(FINAL_MODEL);
  const [verify, setVerify] = useState(null);
  const timer = useRef(null);

  useEffect(() => {
    setData(null);
    setVerify(null);
    setPlaying(false);
    api.run(runId).then((d) => {
      setData(d);
      const rows = d.rows;
      const actorIdx = rows.client.map((c, i) => (c === 'actor' ? i : -1)).filter((i) => i >= 0);
      const first = actorIdx.findIndex((i) => rows.recon[i] === 1 || rows.phase[i] === 'normal_workload');
      setClient('actor');
      setCursor(Math.max(0, first));
    });
  }, [runId]);

  const view = useMemo(() => {
    if (!data) return null;
    const r = data.rows;
    const idx = r.client.map((c, i) => (client === 'all' || c === client ? i : -1)).filter((i) => i >= 0);
    const si = streamIndex(r);
    const alerts = {};
    for (const m of MODELS) alerts[m.id] = r.saved_scores[m.id].map((v) => v > data.thresholds[m.id]);
    return { r, idx, si, alerts };
  }, [data, client]);

  useEffect(() => {
    clearInterval(timer.current);
    if (playing && view) {
      const sp = SPEEDS[speed];
      timer.current = setInterval(() => {
        setCursor((c) => {
          if (c + sp.step >= view.idx.length) {
            setPlaying(false);
            return view.idx.length - 1;
          }
          return c + sp.step;
        });
      }, sp.ms);
    }
    return () => clearInterval(timer.current);
  }, [playing, speed, view]);

  if (!runs || !view) return <Loading />;
  const { r, idx, si, alerts } = view;
  const info = data.info;
  const c = Math.min(cursor, idx.length - 1);
  const i = idx[c];
  const win = contextWindow(si, i);
  const firstSeen = r.saved_b3.h_current_first_seen;
  const isRecon = r.recon[i] === 1;
  const finalAlert = alerts[FINAL_MODEL][i];
  const jump = (pred) => {
    const k = idx.findIndex(pred);
    if (k >= 0) setCursor(k);
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Live / Replay Traffic · held-out test run</div>
          <h1>{info.caption}</h1>
          <div className="meta-line">
            <Badge>Site {info.site}</Badge>
            <Badge>{SCENARIO[info.scenario]}</Badge>
            <Badge>{info.partition === 'test_out_of_site' ? 'Site C test' : 'In-site test'}</Badge>
            <span className="muted">
              {info.requests.toLocaleString()} requests · target {info.target_ip} · HMI {info.hmi_ip} · actor {info.actor_ip}
            </span>
          </div>
        </div>
        <div className="head-controls">
          <RunSelect runs={runs} value={runId} onChange={setRunId} />
        </div>
      </div>

      <Panel
        title="Run timeline"
        note="Register address over time · orange = reconnaissance, grey = normal · ring = alert · click to jump"
        right={
          <div className="ctl-row">
            <label className="muted small">Client</label>
            <div className="seg">
              {[
                ['actor', 'Actor host'],
                ['hmi', 'HMI'],
                ['all', 'All'],
              ].map(([k, l]) => (
                <button key={k} className={client === k ? 'on' : ''} onClick={() => { setClient(k); setCursor(0); }}>
                  {l}
                </button>
              ))}
            </div>
            <label className="muted small">Alerts</label>
            <select className="select small" value={tlModel} onChange={(e) => setTlModel(e.target.value)}>
              {MODELS.map((m) => (
                <option key={m.id} value={m.id}>{m.name}</option>
              ))}
            </select>
          </div>
        }
      >
        <Timeline idx={idx} t={r.t} address={r.address} recon={r.recon} alert={alerts[tlModel]} cursor={c} onSeek={setCursor} />
        <div className="player">
          <button className="btn" onClick={() => setCursor(Math.max(0, c - 1))}>◀ Step</button>
          <button className="btn primary" onClick={() => setPlaying(!playing)}>{playing ? 'Pause' : 'Play'}</button>
          <button className="btn" onClick={() => setCursor(Math.min(idx.length - 1, c + 1))}>Step ▶</button>
          <div className="seg">
            {SPEEDS.map((s, k) => (
              <button key={s.label} className={speed === k ? 'on' : ''} onClick={() => setSpeed(k)}>{s.label}</button>
            ))}
          </div>
          <input type="range" min={0} max={idx.length - 1} value={c} onChange={(e) => setCursor(+e.target.value)} className="scrub" />
          <span className="muted small mono">{c + 1} / {idx.length}</span>
          {info.group === 'recon' && <button className="btn ghost small" onClick={() => jump((k) => r.recon[k] === 1)}>First recon request</button>}
          {info.group !== 'recon' && <button className="btn ghost small" onClick={() => jump((k) => r.phase[k] === 'normal_workload')}>Task start</button>}
        </div>
      </Panel>

      <div className="grid-replay">
        <Panel title="Current Message">
          <dl className="kv">
            <dt>Time</dt><dd className="mono">{r.t[i].toFixed(3)} s</dd>
            <dt>Client → target</dt><dd className="mono">{r.src_ip[i]}:{r.src_port[i]} → {r.dst_ip[i]}:502</dd>
            <dt>Transaction ID</dt><dd className="mono">{r.tid[i]} <span className="muted small">(pairing only, not a model input)</span></dd>
            <dt>Unit ID</dt><dd className="mono">{r.unit[i]}</dd>
            <dt>Function</dt><dd>FC{r.wire_fc[i]} · {FC[r.wire_fc[i]]}</dd>
            <dt>Address</dt><dd className="mono">{r.address[i]}</dd>
            <dt>Quantity</dt><dd className="mono">{r.quantity[i]}</dd>
            <dt>Frame</dt><dd className="mono">#{r.frame_number[i]}</dd>
            <dt>Request bytes</dt><dd className="mono small wrap">{r.adu_hex[i]}</dd>
            <dt>Response bytes</dt><dd className="mono small wrap">{r.response_hex[i]} <span className="muted">({r.latency_us[i]} µs)</span></dd>
          </dl>
          <div className="truth">
            <div className="truth-label">Ground Truth</div>
            <Badge tone={isRecon ? 'recon' : 'normal'}>{isRecon ? 'Reconnaissance' : 'Normal'}</Badge>
            <span className="muted small">
              {PHASE[r.phase[i]] === STRATUM[r.stratum[i]] ? PHASE[r.phase[i]] : `${PHASE[r.phase[i]]} · ${STRATUM[r.stratum[i]]}`} ·{' '}
              {SCENARIO[r.gt_scenario[i]] ?? r.gt_scenario[i]}
            </span>
          </div>
        </Panel>

        <Panel title="Model Prediction" note="Saved held-out test scores · tick = frozen threshold (5% FPR on validation revisiting normal)">
          <div className="preds">
            {MODELS.map((m) => {
              const sc = r.saved_scores[m.id][i];
              const a = alerts[m.id][i];
              return (
                <div key={m.id} className={`pred ${m.id === FINAL_MODEL ? 'final' : ''}`}>
                  <div className="pred-name"><span className={`model-tag ${m.kind}`}>{m.id}</span> {m.name}</div>
                  <ScoreBar score={sc} threshold={data.thresholds[m.id]} alert={a} />
                  <div className="pred-score mono">{sc < 0.001 ? sc.toExponential(1) : sc.toFixed(3)}</div>
                  <Badge tone={a ? 'alert' : 'quiet'}>{a ? 'Alert' : 'No alert'}</Badge>
                </div>
              );
            })}
            <div className="pred axis-row"><div /><ScoreAxis /><div /><div /></div>
          </div>
          <div className={`final-alert ${finalAlert ? (isRecon ? 'tp' : 'fp') : isRecon ? 'fn' : 'tn'}`}>
            <div>
              <div className="fa-label">Final alert ({FINAL_MODEL} · History-statistics RF)</div>
              <div className="fa-value">{finalAlert ? 'RECON ALERT' : 'No alert'}</div>
            </div>
            <div className="fa-outcome">
              {finalAlert ? (isRecon ? 'Correct detection' : 'False positive') : isRecon ? 'Missed' : 'Correctly quiet'}
            </div>
          </div>
          {!r.full_context[i] && <div className="footnote">Partial context: fewer than 20 earlier requests in this stream.</div>}
        </Panel>

        <Panel title="Temporal Context" note="History-statistics features of this request (model B3 input)">
          <div className="feat-grid">
            {B3_FEATURES.map((f) => (
              <div key={f.key} className="feat">
                <div className="feat-label">{f.label}</div>
                <div className="feat-value">{fmt(r.saved_b3[f.key][i], f.fmt)}</div>
              </div>
            ))}
            <div className="feat">
              <div className="feat-label">Revisited targets</div>
              <div className="feat-value">{Math.round((1 - r.saved_b3.h_unique_target_frac[i]) * r.saved_b3.h_context_len[i])} of {r.saved_b3.h_context_len[i]}</div>
            </div>
          </div>
          <div className="sub-head">Recent 20 address path</div>
          <ContextPath win={win} address={r.address} unit={r.unit} fc={r.wire_fc} firstSeen={firstSeen} recon={r.recon} />
          <div className="legend small">
            <span className="dot filled" /> first time in stream <span className="dot hollow" /> revisit
          </div>
        </Panel>
      </div>

      <Panel title="Recent 20 Requests" note={`Causal window for the current request · stream ${si.key(i)}`}>
        <table className="table compact mono">
          <thead>
            <tr>
              <th className="r">#</th><th className="r">Δt (ms)</th><th>Unit</th><th>FC</th><th className="r">Address</th>
              <th className="r">Qty</th><th>Target</th><th>Ground truth</th><th className="r">{FINAL_MODEL} score</th>
            </tr>
          </thead>
          <tbody>
            {win.map((k, n) => (
              <tr key={k} className={k === i ? 'current-row' : ''}>
                <td className="r">{n - win.length + 1 === 0 ? 'now' : n - win.length + 1}</td>
                <td className="r">{n ? ((r.t[k] - r.t[win[n - 1]]) * 1000).toFixed(0) : '–'}</td>
                <td>{r.unit[k]}</td>
                <td>FC{r.wire_fc[k]}</td>
                <td className="r">{r.address[k]}</td>
                <td className="r">{r.quantity[k]}</td>
                <td>{firstSeen[k] ? <span className="tag new">new</span> : <span className="tag rev">revisit</span>}</td>
                <td>{r.recon[k] ? <span className="tag recon">recon</span> : <span className="tag normal">normal</span>}</td>
                <td className="r">{r.saved_scores[FINAL_MODEL][k].toFixed(3)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel
        title="Reproduce predictions"
        note="Re-score this run's raw request table with the frozen pipeline and compare with the saved test predictions"
        right={<button className="btn" onClick={() => { setVerify('running'); api.verify(runId).then(setVerify).catch((e) => setVerify({ error: e.message })); }}>Verify with frozen models</button>}
      >
        {verify === 'running' && <Loading text="Running frozen pipeline…" />}
        {verify?.error && <div className="error">{verify.error}</div>}
        {verify?.models && (
          <table className="table compact">
            <thead>
              <tr><th>Model</th><th className="r">Max |score difference|</th><th className="r">Alert agreement</th><th className="r">Disagreements</th><th className="r">Exact threshold ties</th></tr>
            </thead>
            <tbody>
              {MODELS.map((m) => {
                const v = verify.models[m.id];
                return (
                  <tr key={m.id}>
                    <td>{m.name}</td>
                    <td className="r mono">{v.max_abs_score_diff.toExponential(1)}</td>
                    <td className="r">{(v.alert_agreement * 100).toFixed(2)}%</td>
                    <td className="r">{v.alert_disagreements - v.disagreements_at_exact_threshold_tie}</td>
                    <td className="r muted">{v.disagreements_at_exact_threshold_tie}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {verify?.models && (
          <div className="footnote">
            {verify.requests.toLocaleString()} requests re-scored · history features max difference {verify.b3_feature_max_abs_diff.toExponential(1)}.
            Exact threshold ties: score equals the frozen threshold; multithreaded tree averaging changes only the last bit (±2e-16), so a tie can
            land either side.
            Raw capture: <span className="mono">{info.pcap.file}</span> · {info.tshark_adus_checked.toLocaleString()} Modbus ADUs checked
            against tshark, {info.tshark_mismatches} mismatches.
          </div>
        )}
      </Panel>
    </div>
  );
}
