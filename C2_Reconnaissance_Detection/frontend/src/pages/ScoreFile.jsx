import { useState } from 'react';
import { api } from '../api.js';
import { Loading, Panel, Tile } from '../components/ui.jsx';
import { MODELS, num } from '../labels.js';
import { useRuns } from './Replay.jsx';

const REQUIRED = ['src_ip', 'dst_ip', 'ts_corr_ns (or ts_ns)', 'unit', 'wire_fc', 'address', 'quantity', 'mbap_len', 'frame_len'];
const OPTIONAL = ['run_id', 'frame_number', 'adu_id', 'tid', 'src_port'];

export default function ScoreFile() {
  const runs = useRuns();
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [name, setName] = useState('');
  const onFile = (f) => {
    if (!f) return;
    setName(f.name);
    setBusy(true);
    setErr(null);
    setRes(null);
    api
      .score(f)
      .then(setRes)
      .catch((e) => setErr(e.message))
      .finally(() => setBusy(false));
  };
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Frozen pipeline</div>
          <h1>Score a request table</h1>
        </div>
      </div>
      <div className="grid-2">
        <Panel title="Input" note="CSV or Parquet of Modbus/TCP read requests (one row per request)">
          <div className="pipeline">
            {['Schema check', 'Client → target streams', 'Chronological order', 'Frozen features', 'Last-20 contexts', 'Frozen scaling', 'Frozen models', 'Scores + alerts'].map((s, k) => (
              <span key={s} className="pipe-step">{k ? '→ ' : ''}{s}</span>
            ))}
          </div>
          <div className="sub-head">Required columns</div>
          <div className="mono small">{REQUIRED.join(', ')}</div>
          <div className="sub-head">Optional</div>
          <div className="mono small">{OPTIONAL.join(', ')}</div>
          <label className="drop">
            <input type="file" accept=".csv,.parquet" onChange={(e) => onFile(e.target.files[0])} />
            {name || 'Choose a file…'}
          </label>
          {runs && (
            <div className="small muted">
              Sample inputs (held-out runs, labels removed):{' '}
              {runs.slice(0, 4).map((r) => (
                <a key={r.run_id} className="link" href={`/api/runs/${r.run_id}/input.csv`}>{r.run_id.replace('final_v1-', '')}</a>
              ))}
            </div>
          )}
        </Panel>
        <Panel title="Result">
          {busy && <Loading text="Scoring with frozen models…" />}
          {err && <div className="error">{err}</div>}
          {res && (
            <>
              <div className="tiles small">
                <Tile label="Requests" value={num(res.requests)} />
                <Tile label="Streams" value={res.streams} />
              </div>
              <table className="table compact">
                <thead><tr><th>Model</th><th className="r">Alerts</th><th className="r">Share</th></tr></thead>
                <tbody>
                  {MODELS.map((m) => (
                    <tr key={m.id}>
                      <td>{m.name}</td>
                      <td className="r">{num(res.alerts[m.id])}</td>
                      <td className="r">{((res.alerts[m.id] / res.requests) * 100).toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </Panel>
      </div>
      {res && (
        <Panel title="Scored requests" note={`First ${res.truncated_to.toLocaleString()} rows`}>
          <div className="scroll">
            <table className="table compact mono">
              <thead>
                <tr>
                  <th>Stream</th><th className="r">t (s)</th><th className="r">Frame</th>
                  {MODELS.map((m) => <th key={m.id} className="r">{m.id}</th>)}
                  <th>Context</th>
                </tr>
              </thead>
              <tbody>
                {res.rows.adu_id.slice(0, 300).map((_, k) => (
                  <tr key={k}>
                    <td>{res.rows.src_ip[k]} → {res.rows.dst_ip[k]}</td>
                    <td className="r">{res.rows.t[k].toFixed(3)}</td>
                    <td className="r">{res.rows.frame_number[k]}</td>
                    {MODELS.map((m) => (
                      <td key={m.id} className={`r ${res.rows[`alert_${m.id}`][k] ? 'alert-cell' : ''}`}>{res.rows[m.id][k].toFixed(3)}</td>
                    ))}
                    <td>{res.rows.full_context[k] ? 'full' : 'partial'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
