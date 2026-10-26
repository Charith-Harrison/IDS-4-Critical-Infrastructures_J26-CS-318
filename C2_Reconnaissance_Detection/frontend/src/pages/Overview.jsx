import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { RecallBars } from '../components/charts.jsx';
import { FINAL_MODEL, MODELS, SCENARIO, ci, num, pct } from '../labels.js';
import { Loading, Panel, Tile } from '../components/ui.jsx';

export default function Overview() {
  const [s, setS] = useState(null);
  useEffect(() => {
    api.summary().then(setS);
  }, []);
  if (!s) return <Loading />;
  const byId = Object.fromEntries(s.models.map((m) => [m.id, m]));
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">{s.component}</div>
          <h1>{s.title}</h1>
        </div>
      </div>

      <div className="tiles">
        <Tile label="Dataset" value="Controlled Modbus/TCP" sub="Real captured traffic, ledger ground truth" />
        <Tile label="Accepted runs" value={num(s.runs_accepted)} sub={`of ${s.runs_planned} planned`} />
        <Tile label="Requests" value={num(s.requests)} sub="Parsed and labelled" />
        <Tile label="Sites" value="A · B · C" sub="C unseen until final test" />
        <Tile label="Temporal context" value={`${s.context_length} requests`} sub="Causal, per client → target stream" />
      </div>

      <Panel title="Recon recall at 5% false positives on revisiting normal traffic" note="Held-out test sets · scenario-balanced · 95% run-bootstrap CI">
        <RecallBars
          rows={MODELS.map((m) => ({
            label: m.name,
            series: [
              { name: 'In-site test (A+B)', value: byId[m.id].in_site.recall.value, ci: byId[m.id].in_site.recall.ci95, cls: 'in-site' },
              { name: 'Unseen Site C', value: byId[m.id].site_c.recall.value, ci: byId[m.id].site_c.recall.ci95, cls: 'site-c' },
            ],
          }))}
        />
        <div className="legend">
          <span className="sw in-site" /> In-site test (A+B, {s.recon_runs_in_site} recon runs)
          <span className="sw site-c" /> Unseen Site C ({s.recon_runs_site_c} recon runs)
        </div>
      </Panel>

      <Panel title="Model comparison" note="Same targets, same 20-request windows, frozen thresholds">
        <table className="table">
          <thead>
            <tr>
              <th>Model</th>
              <th>Input</th>
              <th className="r">Recall (in-site)</th>
              <th className="r">Gain over current message</th>
              <th className="r">Recall (Site C)</th>
              <th className="r">FPR revisiting (in-site / C)</th>
              <th className="r">FPR background (in-site / C)</th>
              <th className="r">FPR one-pass (in-site / C)</th>
            </tr>
          </thead>
          <tbody>
            {MODELS.map((m) => {
              const r = byId[m.id];
              return (
                <tr key={m.id} className={m.id === FINAL_MODEL ? 'highlight' : ''}>
                  <td>
                    <span className={`model-tag ${m.kind}`}>{m.id}</span> {m.name}
                  </td>
                  <td className="muted">{r.input}</td>
                  <td className="r">
                    {pct(r.in_site.recall.value)} <span className="ci">{ci(r.in_site.recall.ci95)}</span>
                  </td>
                  <td className="r">
                    {r.in_site.gain_over_A ? (
                      <>
                        {r.in_site.gain_over_A.value >= 0 ? '+' : ''}
                        {(r.in_site.gain_over_A.value * 100).toFixed(1)} pts{' '}
                        <span className="ci">{ci(r.in_site.gain_over_A.ci95)}</span>
                      </>
                    ) : (
                      <span className="muted">baseline</span>
                    )}
                  </td>
                  <td className="r">
                    {pct(r.site_c.recall.value)} <span className="ci">{ci(r.site_c.recall.ci95)}</span>
                  </td>
                  <td className="r">
                    {pct(r.in_site.fpr_revisiting.rate)} / {pct(r.site_c.fpr_revisiting.rate)}
                  </td>
                  <td className="r">
                    {pct(r.in_site.fpr_background.rate, 2)} / {pct(r.site_c.fpr_background.rate, 2)}
                  </td>
                  <td className="r warn-text">
                    {pct(r.in_site.fpr_one_pass.rate)} / {pct(r.site_c.fpr_one_pass.rate)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="footnote">
          Highlighted: final alert model ({FINAL_MODEL}) — full recall with the lowest revisiting and background false-positive rates at both test
          sites. Tests opened once: in-site {s.test_openings.in_site.slice(0, 16).replace('T', ' ')} UTC, Site C{' '}
          {s.test_openings.site_c.slice(0, 16).replace('T', ' ')} UTC.
        </div>
      </Panel>

      <div className="grid-2">
        <Panel title="Recall by attack scenario" note="In-site test · full-context targets">
          <table className="table compact">
            <thead>
              <tr>
                <th>Scenario</th>
                {MODELS.map((m) => (
                  <th key={m.id} className="r">{m.id}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(s.per_scenario.in_site).map(([sc, v]) => (
                <tr key={sc}>
                  <td>{SCENARIO[sc] ?? sc}</td>
                  {MODELS.map((m) => (
                    <td key={m.id} className="r heat" style={{ '--h': v[m.id] }}>
                      {(v[m.id] * 100).toFixed(0)}%
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Known limitation" tone="warn">
          <ul className="facts">
            <li>
              History models flag legitimate <b>one-pass</b> reads (configuration backup, HMI cold start, historian backfill,
              commissioning) almost as often as scans: {pct(byId.B3.in_site.fpr_one_pass.rate)} for {FINAL_MODEL} in-site.
            </li>
            <li>
              Recon vs one-pass AUC stays near chance (Site C, {FINAL_MODEL}: {byId.B3.site_c.auc_vs_one_pass.toFixed(2)}) —
              the command sequences are the same; only intent differs.
            </li>
            <li>The LSTM does not beat the history-statistics RF; its false positives roughly double at unseen Site C.</li>
          </ul>
        </Panel>
      </div>
    </div>
  );
}
