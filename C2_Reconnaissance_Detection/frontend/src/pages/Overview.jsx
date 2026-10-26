import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { RecallBars } from '../components/charts.jsx';
import { FINAL_MODEL, MODELS, SCENARIO, num, pct } from '../labels.js';
import { Loading, Panel } from '../components/ui.jsx';

export default function Overview() {
  const [s, setS] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => { api.summary().then(setS).catch((e) => setError(e.message)); }, []);
  if (error) return <Panel title="Results unavailable"><p className="error">{error}</p></Panel>;
  if (!s) return <Loading />;
  const byId = Object.fromEntries(s.models.map((m) => [m.id, m]));
  return <div className="page overview-page">
    <div className="page-head"><div><div className="eyebrow">Component 2 / RP2 · controlled testbed</div><h1>Reconnaissance detection</h1><p className="page-intro">A comparison of single-request detection, history statistics and an LSTM.</p></div><a href="#guide" className="btn">How to present this</a></div>
    <div className="result-lead"><div className="result-reading"><span className="section-number">The finding</span><h2>History helps with repeat polling.</h2>
      <p>On unseen Site C, B3 and the LSTM caught {pct(byId.B3.site_c.recall.value, 0)} of the tested recon requests, with scenarios weighted equally. The current-message baseline caught {pct(byId.A.site_c.recall.value)}.</p><p>B3 matched the LSTM’s recall with fewer false alarms. Legitimate one-pass reads remain a serious limitation.</p><div className="inline-links"><a href="#metrics">Inspect the metrics ↗</a><a href="#replay">Watch a recorded run ↗</a></div></div>
      <div className="lead-numbers" aria-label="B3 results on unseen Site C"><div><strong>{pct(byId.B3.site_c.recall.value)}</strong><span>Recon caught</span><small>B3 · scenario-balanced recall · Site C</small></div><div><strong>{pct(byId.B3.site_c.fpr_revisiting.rate)}</strong><span>Repeat-work false alarms</span><small>B3 · revisiting normal requests · Site C</small></div><div className="caution-number"><strong>{pct(byId.B3.site_c.fpr_one_pass.rate, 0)}</strong><span>One-pass false alarms</span><small>Legitimate backups and startup reads · Site C</small></div></div>
    </div>
    <div className="dataset-line"><span><b>{num(s.runs_accepted)}</b> / {s.runs_planned} runs accepted</span><span><b>{num(s.requests)}</b> requests</span><span><b>20</b> recent requests per input</span><span>Sites <b>A + B</b> · held-out <b>C</b></span></div>
    <Panel title="Detection across the five models" note="Scenario-balanced recall on held-out recon runs. Thresholds were selected for 5% validation false positives; actual test false alarms differ." right={<a href="#metrics" className="btn small">Precision, F1 & confusion matrix</a>}>
      <RecallBars rows={MODELS.map((m) => ({ label: `${m.id} · ${m.name}`, series: [{ name: 'In-site A+B', value: byId[m.id].in_site.recall.value, ci: byId[m.id].in_site.recall.ci95, cls: 'in-site' }, { name: 'Unseen Site C', value: byId[m.id].site_c.recall.value, ci: byId[m.id].site_c.recall.ci95, cls: 'site-c' }] }))} />
      <div className="legend"><span className="sw in-site" /> A+B · {s.recon_runs_in_site} recon runs <span className="sw site-c" /> C · {s.recon_runs_site_c} recon runs <span className="muted">Whiskers: 95% run-bootstrap intervals</span></div>
    </Panel>
    <Panel title="The trade-off" note="Full-context test requests. Recall is scenario-balanced; false-positive rates are request-pooled."><div className="table-scroll"><table className="table"><thead><tr><th>Model</th><th className="r">Recall · A+B</th><th className="r">Recall · C</th><th className="r">False alarms · C repeat work</th><th className="r">False alarms · C one-pass</th></tr></thead><tbody>
      {MODELS.map((m) => { const r = byId[m.id]; return <tr key={m.id} className={m.id === FINAL_MODEL ? 'highlight' : ''}><td><span className={`model-tag ${m.kind}`}>{m.id}</span> {m.name}{m.id === FINAL_MODEL && <span className="recommended">Default</span>}</td><td className="r">{pct(r.in_site.recall.value)}</td><td className="r">{pct(r.site_c.recall.value)}</td><td className="r">{pct(r.site_c.fpr_revisiting.rate)}</td><td className="r warn-text">{pct(r.site_c.fpr_one_pass.rate)}</td></tr>; })}
    </tbody></table></div><p className="footnote">A high detection rate is only useful alongside acceptable false alarms. The <a href="#metrics">Metrics page</a> shows all normal workloads, exact counts and definitions.</p></Panel>
    <div className="grid-2"><Panel title="Recall by scan style" note="In-site test · full histories"><div className="table-scroll"><table className="table compact"><thead><tr><th>Scenario</th>{MODELS.map((m) => <th key={m.id} className="r">{m.id}</th>)}</tr></thead><tbody>{Object.entries(s.per_scenario.in_site).map(([sc, v]) => <tr key={sc}><td>{SCENARIO[sc] ?? sc}</td>{MODELS.map((m) => <td key={m.id} className="r">{pct(v[m.id], 0)}</td>)}</tr>)}</tbody></table></div></Panel>
      <Panel title="A backup can look like a scan" tone="warn"><p>A legitimate engineer can read a table once in the same way an attacker would. The traffic does not reveal their intent.</p><p>B3 flags {pct(byId.B3.in_site.fpr_one_pass.rate, 0)} of the in-site one-pass workload. Lead-in maintenance also triggers alerts. This result needs to be shown alongside the high recall.</p><a href="#compare">Compare a scan, backup and polling run ↗</a></Panel></div>
    <div className="source-line">Controlled software testbed · final_v1 · current results use held-out predictions. CIC is a <a href="#history">separate forensic case study</a>.</div>
  </div>;
}
