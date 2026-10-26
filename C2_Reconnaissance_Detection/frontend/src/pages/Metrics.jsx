import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { MODELS, FINAL_MODEL, num, pct } from '../labels.js';
import { Loading, Panel } from '../components/ui.jsx';

const decimal = (x, digits = 3) => x == null ? '—' : x.toFixed(digits);
const NORMAL = {
  revisiting_normal: ['Revisiting work', 'Polling, monitoring and repeated maintenance reads.'],
  one_pass_normal: ['One-pass work', 'Backups, startup, backfill and commissioning reads.'],
  legitimate_lead_in: ['Lead-in activity', 'Legitimate requests before the main task begins.'],
  background: ['Background HMI', 'The monitoring client running throughout an experiment.'],
};
export const METRIC_WORDS = [
  ['Precision', 'When it raises an alert, how often is the request actually recon?', 'TP ÷ (TP + FP)'],
  ['Recall', 'Of the real recon requests, how many did it catch?', 'TP ÷ (TP + FN)'],
  ['F1', 'One score balancing precision and recall. It does not count correctly quiet normal traffic.', '2TP ÷ (2TP + FP + FN)'],
  ['False-positive rate', 'Of the normal requests, how many caused an unnecessary alert?', 'FP ÷ (FP + TN)'],
  ['Accuracy', 'How many requests received the correct decision? A large normal population can make this look flattering.', '(TP + TN) ÷ all selected requests'],
  ['ROC-AUC', 'How well do scores rank recon above normal across possible thresholds? 0.5 is chance; 1 is perfect ranking.', 'Uses saved scores, not just the alert decision'],
];
export function MetricDefinitions() {
  return <dl className="metric-definitions">{METRIC_WORDS.map(([name, meaning, formula]) => (
    <div key={name}><dt>{name}</dt><dd>{meaning}<code>{formula}</code></dd></div>
  ))}</dl>;
}
function ConfusionMatrix({ m }) {
  return <div className="confusion-wrap">
    <table className="confusion-table" aria-label="Confusion matrix of actual labels and model decisions">
      <thead><tr><th>Actual / model decision</th><th>Alert</th><th>No alert</th></tr></thead>
      <tbody><tr><th scope="row">Recon</th>
        <td className="cm-tp"><span>True positive · TP</span><strong>{num(m.tp)}</strong><small>Caught recon</small></td>
        <td className="cm-fn"><span>False negative · FN</span><strong>{num(m.fn)}</strong><small>Missed recon</small></td></tr>
        <tr><th scope="row">Normal</th><td className="cm-fp"><span>False positive · FP</span><strong>{num(m.fp)}</strong><small>Unnecessary alert</small></td>
        <td className="cm-tn"><span>True negative · TN</span><strong>{num(m.tn)}</strong><small>Correctly quiet</small></td></tr></tbody>
    </table>
    <p className="footnote">Rows are the experiment ledger’s labels. Columns are decisions at the frozen threshold. An alert is not ground truth.</p>
  </div>;
}
export default function Metrics() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [population, setPopulation] = useState('test_in_site');
  const [context, setContext] = useState('full');
  const [comparison, setComparison] = useState('revisiting');
  const [model, setModel] = useState(FINAL_MODEL);
  useEffect(() => { api.metrics().then(setData).catch((e) => setError(e.message)); }, []);
  if (error) return <Panel title="Metrics unavailable"><p className="error">{error}</p><p>Restart the demo server after updating the dashboard.</p></Panel>;
  if (!data) return <Loading text="Loading saved test metrics…" />;
  const pop = data.populations[population];
  const selected = pop.contexts[context];
  const view = selected.comparisons[comparison];
  const m = view.models[model];
  const name = MODELS.find((x) => x.id === model).name;
  const balanced = selected.scenario_balanced_recall[model];
  const csv = `/api/metrics.csv?population=${population}&context=${context}&comparison=${comparison}`;
  const scores = [
    ['Precision', pct(m.precision), 'Share of alerts that are recon'],
    ['Recall', pct(m.recall), 'Share of recon requests caught'],
    ['F1', decimal(m.f1), 'Balance of precision and recall · 0–1'],
    ['False alarms', pct(m.fpr, 2), 'Share of selected normal requests flagged'],
    ['Accuracy', pct(m.accuracy, 2), 'All selected requests correctly classified'],
    ['ROC-AUC', decimal(m.roc_auc), 'Score-ranking performance · 0–1'],
  ];
  return <div className="page metrics-page">
    <div className="page-head"><div><div className="eyebrow">Held-out results</div><h1>Test-set metrics</h1><p className="page-intro">Choose the test set and the kind of legitimate traffic you want to compare against recon.</p></div><a className="btn" href={csv} download>Download these results</a></div>
    <div className="metrics-controls">
      <label>Test set<select className="select" value={population} onChange={(e) => setPopulation(e.target.value)}>{Object.entries(data.populations).map(([id, p]) => <option key={id} value={id}>{p.label}</option>)}</select></label>
      <label>Normal workload<select className="select" value={comparison} onChange={(e) => setComparison(e.target.value)}>{Object.entries(data.comparisons).map(([id, v]) => <option key={id} value={id}>{v.label}</option>)}</select></label>
      <label>History length<select className="select" value={context} onChange={(e) => setContext(e.target.value)}><option value="full">Full 20-request histories</option><option value="all">All requests, including short histories</option></select></label>
      <label>Inspect model<select className="select" value={model} onChange={(e) => setModel(e.target.value)}>{MODELS.map((v) => <option key={v.id} value={v.id}>{v.id} · {v.name}</option>)}</select></label>
    </div>
    <div className="selection-note"><strong>{data.comparisons[comparison].label}.</strong> {data.comparisons[comparison].description}<div>{num(view.positive_requests)} recon + {num(view.normal_requests)} normal requests · {view.runs} runs in this comparison · thresholds unchanged</div><div>Each request counts equally here. Overview recall weights the scan scenarios equally.</div></div>
    {comparison === 'revisiting' && <p className="scope-note">These are not false-alarm rates for every legitimate task. <button className="text-button" onClick={() => setComparison('one_pass')}>See what happens to legitimate one-pass reads.</button></p>}
    <section aria-label={`${name} performance metrics`} className="metric-strip">{scores.map(([label, value, note]) => <div className="metric-number" key={label}><span>{label}</span><strong>{value}</strong><small>{note}</small></div>)}</section>
    <div className="metrics-detail-grid"><Panel title={`${model} · ${name}`} note={`Confusion matrix · ${num(m.requests)} selected requests`}><ConfusionMatrix m={m} /></Panel>
      <Panel title="How to explain these numbers"><p className="spoken-line">“Of {num(m.positive_requests)} recon requests, this model caught {num(m.tp)} and missed {num(m.fn)}. It also raised {num(m.fp)} alerts on {num(m.normal_requests)} normal requests.”</p>
        <dl className="kv tight"><dt>Frozen alert threshold</dt><dd className="mono">{decimal(m.threshold, 5)}</dd><dt>Request-pooled recall</dt><dd>{pct(m.recall)}</dd><dt>Scenario-balanced recall</dt><dd>{pct(balanced.value)}</dd></dl>
        <p className="footnote">The headline research result weights the scan scenarios equally. This matrix counts every selected request equally, so its recall may differ slightly.</p><p className="footnote">A model score is not a verified probability of malicious intent. The threshold was chosen using validation repeat-polling traffic, not this test set.</p>
      </Panel></div>
    <Panel title="All five models" note="Same selected requests and frozen thresholds. Select a row to inspect its confusion matrix."><div className="table-scroll"><table className="table metrics-table"><thead><tr><th>Model</th><th className="r">Precision</th><th className="r">Recall</th><th className="r">F1</th><th className="r">Accuracy</th><th className="r">False alarms</th><th className="r">AUC</th></tr></thead><tbody>
      {MODELS.map((v) => { const x = view.models[v.id]; return <tr key={v.id} className={model === v.id ? 'highlight' : ''}><td><button className="model-choice" onClick={() => setModel(v.id)}><span className={`model-tag ${v.kind}`}>{v.id}</span> {v.name}{v.id === FINAL_MODEL && <span className="recommended">Default</span>}</button></td><td className="r">{pct(x.precision)}</td><td className="r">{pct(x.recall)}</td><td className="r">{decimal(x.f1)}</td><td className="r">{pct(x.accuracy, 2)}</td><td className="r">{pct(x.fpr, 2)}</td><td className="r">{decimal(x.roc_auc)}</td></tr>; })}
    </tbody></table></div><p className="footnote">Precision and F1 depend on the selected normal population and class balance. Changing the workload changes the question; it does not change the fitted models.</p></Panel>
    <Panel title="False alarms across legitimate workloads" note={`${name} · ${selected.label}. The 5% target was set on validation revisiting work only.`}><div className="table-scroll"><table className="table"><thead><tr><th>Legitimate workload</th><th className="r">Requests</th><th className="r">False alerts</th><th className="r">False-positive rate</th><th className="r">95% interval</th></tr></thead><tbody>
      {Object.entries(selected.false_alarms).map(([id, v]) => <tr key={id}><td>{NORMAL[id][0]}<small className="cell-note">{NORMAL[id][1]}</small></td><td className="r">{num(v.requests)}</td><td className="r">{num(v.models[model].fp)}</td><td className={`r ${id === 'one_pass_normal' ? 'warn-text' : ''}`}>{pct(v.models[model].rate, 2)}</td><td className="r muted">{v.models[model].ci95 ? v.models[model].ci95.map((x) => pct(x, 2)).join(' – ') : '—'}</td></tr>)}
    </tbody></table></div><p className="footnote">Intervals are the saved run-bootstrap 95% intervals. A small full-history lead-in count is not a reliable estimate of startup behaviour; switch to all requests to include short histories.</p></Panel>
    <Panel title="Metric glossary"><MetricDefinitions /></Panel>
    <details className="source-details"><summary>Where the metrics come from</summary><p>{data.method}</p><p>{data.averaging}</p><ul>{data.source_files.filter((x) => x.path.includes(population) || x.path.endsWith('thresholds.json')).map((x) => <li key={x.path}><code>{x.path}</code></li>)}</ul><p>Source SHA256 values are retained in the metrics snapshot. Model weights, frozen predictions and test-opening records were not changed to add this page.</p></details>
  </div>;
}
