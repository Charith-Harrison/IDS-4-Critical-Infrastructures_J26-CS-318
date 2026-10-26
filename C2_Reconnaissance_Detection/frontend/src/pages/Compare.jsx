import { useEffect, useMemo, useState } from 'react';
import { api } from '../api.js';
import { ContextPath } from '../components/charts.jsx';
import { Badge, Loading, Panel } from '../components/ui.jsx';
import { FINAL_MODEL, GROUP, MODELS, SCENARIO, fmt } from '../labels.js';
import { RunSelect, contextWindow, streamIndex, useRuns } from './Replay.jsx';

const COLUMNS = [
  { group: 'recon', def: 'final_v1-r086', title: 'Recon scan' },
  { group: 'one_pass_normal', def: 'final_v1-r200', title: 'Legitimate one-pass read' },
  { group: 'revisiting_normal', def: 'final_v1-r095', title: 'Normal polling' },
];

const median = (a) => {
  if (!a.length) return NaN;
  const s = [...a].sort((x, y) => x - y);
  return s[Math.floor(s.length / 2)];
};

function summarise(d) {
  const r = d.rows;
  // the actor host's task requests (reconnaissance, or the legitimate task) with full 20-request context
  const task = r.adu_id
    .map((_, i) => i)
    .filter((i) => r.client[i] === 'actor' && (r.recon[i] === 1 || r.phase[i] === 'normal_workload') && r.full_context[i]);
  const shapes = new Set(task.map((i) => `${r.unit[i]}|${r.wire_fc[i]}|${r.quantity[i]}`));
  const rate = (m) => task.filter((i) => r.saved_scores[m][i] > d.thresholds[m]).length / Math.max(task.length, 1);
  const si = streamIndex(r);
  const mid = task[Math.min(task.length - 1, 25)];
  return {
    task,
    shapes: shapes.size,
    funcs: new Set(task.map((i) => r.wire_fc[i])).size,
    feats: {
      unique: median(task.map((i) => r.saved_b3.h_unique_target_frac[i])),
      firstSeen: median(task.map((i) => r.saved_b3.h_first_seen_frac[i])),
      ascending: median(task.map((i) => r.saved_b3.h_ascending_step_frac[i])),
      interval: median(task.map((i) => r.saved_b3.h_iat_mean_log[i])),
    },
    alerts: Object.fromEntries(MODELS.map((m) => [m.id, rate(m.id)])),
    win: mid === undefined ? [] : contextWindow(si, mid),
  };
}

function Column({ col, runs }) {
  const [id, setId] = useState(col.def);
  const [d, setD] = useState(null);
  useEffect(() => {
    setD(null);
    api.run(id).then(setD);
  }, [id]);
  const s = useMemo(() => (d ? summarise(d) : null), [d]);
  return (
    <Panel
      title={col.title}
      right={<RunSelect runs={runs.filter((r) => r.group === col.group)} value={id} onChange={setId} />}
    >
      {!s ? (
        <Loading />
      ) : (
        <>
          <div className="meta-line">
            <Badge tone={col.group === 'recon' ? 'recon' : 'normal'}>{GROUP[col.group]}</Badge>
            <Badge>{SCENARIO[d.info.scenario]}</Badge>
            <Badge>Site {d.info.site}</Badge>
          </div>
          <div className="sub-head">Current message</div>
          <dl className="kv tight">
            <dt>Task requests</dt><dd>{s.task.length.toLocaleString()}</dd>
            <dt>Function codes used</dt><dd>{s.funcs}</dd>
            <dt>(unit, FC, quantity) shapes</dt><dd>{s.shapes}</dd>
            <dt>Current-message alerts</dt><dd>{fmt(s.alerts.A, 'pct')}</dd>
          </dl>
          <div className="sub-head">Temporal context (median over task requests)</div>
          <dl className="kv tight">
            <dt>Distinct keys in last 20</dt><dd>{fmt(s.feats.unique, 'pct')}</dd>
            <dt>First-seen share</dt><dd>{fmt(s.feats.firstSeen, 'pct')}</dd>
            <dt>Ascending steps</dt><dd>{fmt(s.feats.ascending, 'pct')}</dd>
            <dt>Mean interval</dt><dd>{fmt(s.feats.interval, 'log10s')}</dd>
          </dl>
          <div className="sub-head">Recent 20 address path (a task request)</div>
          <ContextPath
            win={s.win}
            address={d.rows.address}
            unit={d.rows.unit}
            fc={d.rows.wire_fc}
            firstSeen={d.rows.saved_b3.h_current_first_seen}
            recon={d.rows.recon}
          />
          <div className="sub-head">Alert rate on task requests</div>
          <div className="alert-rates">
            {MODELS.map((m) => (
              <div key={m.id} className={`ar ${m.id === FINAL_MODEL ? 'final' : ''}`}>
                <span className={`model-tag ${m.kind}`}>{m.id}</span>
                <div className="ar-track">
                  <div className={`ar-fill ${col.group === 'recon' ? 'good' : 'bad'}`} style={{ width: `${s.alerts[m.id] * 100}%` }} />
                </div>
                <span className="mono small">{fmt(s.alerts[m.id], 'pct')}</span>
              </div>
            ))}
          </div>
          <a className="btn ghost small" href={`#replay?run=${id}`}>Open in Traffic Replay</a>
        </>
      )}
    </Panel>
  );
}

export default function Compare() {
  const runs = useRuns();
  if (!runs) return <Loading />;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Held-out test runs · saved predictions</div>
          <h1>Compare three behaviours</h1>
          <p className="page-intro">A scan, a legitimate one-pass read and repeated polling. Alert rates below describe these example tasks; <a href="#metrics">full test metrics are separate</a>.</p>
        </div>
      </div>
      <div className="grid-3">
        {COLUMNS.map((c) => (
          <Column key={c.group} col={c} runs={runs} />
        ))}
      </div>
      <div className="callouts">
        <div className="callout"><b>Current message</b> — the examples use overlapping read fields. Model A is the current-message baseline; compare it with the history models.</div>
        <div className="callout"><b>Temporal context</b> — scans and one-pass reads keep reaching new request keys; polling repeats familiar ones. A key means unit + function + address + quantity, not a new IP address.</div>
        <div className="callout warn"><b>Known limitation</b> — a legitimate one-pass read produces the same history as a scan and is flagged.</div>
      </div>
    </div>
  );
}
