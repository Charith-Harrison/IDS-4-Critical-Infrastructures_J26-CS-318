import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Badge, Loading, Panel, Tile } from '../components/ui.jsx';
import { GROUP, SCENARIO, num, pct } from '../labels.js';

const PART = { train: 'Train', validation: 'Validation', test_in_site: 'In-site test', test_out_of_site: 'Site C test' };

function Pass({ ok, children }) {
  return <Badge tone={ok ? 'pass' : 'fail'}>{children ?? (ok ? 'PASS' : 'FAIL')}</Badge>;
}

export default function Validation() {
  const [v, setV] = useState(null);
  useEffect(() => {
    api.validation().then(setV);
  }, []);
  if (!v) return <Loading />;
  const st = v.evidence.collection_status;
  const tot = v.evidence.per_run_totals;
  const g = v.gates;
  const split = {};
  for (const r of st.achieved_vs_planned) {
    const k = r.partition;
    split[k] ??= { planned: 0, accepted: 0, sites: new Set() };
    split[k].planned += r.planned;
    split[k].accepted += r.accepted;
    split[k].sites.add(r.site_id);
  }
  const integ = v.evidence.context_integrity;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Validation</div>
          <h1>Final dataset evidence</h1>
        </div>
      </div>

      <div className="tiles">
        <Tile label="Runs accepted" value={`${st.accepted_final} / ${st.planned_runs}`} sub={`${st.collection_errors} collection errors`} />
        <Tile label="Modbus ADUs vs tshark" value={num(tot.adus_checked_vs_tshark)} sub={`${tot.tshark_mismatches} mismatches`} tone={tot.tshark_mismatches ? 'bad' : 'good'} />
        <Tile label="Ledger ↔ wire 1:1" value={`${tot.ledger_wire_1to1_pass} / ${tot.runs_processed}`} sub="Every request matched exactly once" />
        <Tile label="Cross-run traffic" value={`${tot.no_cross_run_traffic_pass} / ${tot.runs_processed} clean`} sub="Isolated network per run" />
        <Tile label="Clock steps corrected" value={num(st.clock.steps_total)} sub={`≤ ${pct(st.clock.max_ambiguous_fraction, 2)} requests ambiguous per run`} />
      </div>

      <div className="grid-2">
        <Panel title="Split" note="Fixed in every frozen plan before collection">
          <table className="table">
            <thead>
              <tr><th>Partition</th><th>Sites</th><th className="r">Runs planned</th><th className="r">Accepted</th><th>Use</th></tr>
            </thead>
            <tbody>
              {['train', 'validation', 'test_in_site', 'test_out_of_site'].map((p) => (
                <tr key={p}>
                  <td>{PART[p]}</td>
                  <td>{[...split[p].sites].sort().join(', ')}</td>
                  <td className="r">{split[p].planned}</td>
                  <td className="r">{split[p].accepted}</td>
                  <td className="muted">
                    {{ train: 'Fitting + run-grouped CV', validation: 'Thresholds only', test_in_site: 'Opened once', test_out_of_site: 'Opened once, last' }[p]}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel title="Collection gates" note="Pre-registered; all must pass before any modelling">
          <table className="table">
            <tbody>
              <tr>
                <td>G1 value coverage</td>
                <td className="muted">Every recon field value also occurs in normal traffic</td>
                <td className="r"><Pass ok={g.G1.pass} /></td>
              </tr>
              <tr>
                <td>G2 shape coverage</td>
                <td className="muted">
                  Recon shapes seen in other runs' normal traffic, same site:{' '}
                  {Object.entries(g.G2.by_site).map(([s, x]) => `${s} ${pct(x, 0)}`).join(' · ')}
                </td>
                <td className="r"><Pass ok={g.G2.pass} /></td>
              </tr>
              <tr>
                <td>G3 no single-message solution</td>
                <td className="muted">
                  Best current-message model AUC{' '}
                  {Math.max(...Object.values(g.G3.max_by_scope).map((x) => x.roc_auc)).toFixed(3)} (limit 0.80)
                </td>
                <td className="r"><Pass ok={g.G3.pass} /></td>
              </tr>
              <tr>
                <td>Transaction ID check</td>
                <td className="muted">Raw TID variant (TID is never a model input)</td>
                <td className="r"><Pass ok={g.G3_raw_TID_variant.within_thresholds}>{g.G3_raw_TID_variant.within_thresholds ? 'WITHIN LIMITS' : 'OVER'}</Pass></td>
              </tr>
            </tbody>
          </table>
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title="Context integrity" note="Every 20-request window, all partitions">
          <table className="table">
            <thead>
              <tr><th>Partition</th><th className="r">Targets</th><th className="r">Windows crossing runs</th><th className="r">Windows with future requests</th></tr>
            </thead>
            <tbody>
              {Object.entries(integ).map(([p, x]) => (
                <tr key={p}>
                  <td>{PART[p]}</td>
                  <td className="r">{num(x.targets)}</td>
                  <td className="r">{x.windows_crossing_runs}</td>
                  <td className="r">{x.windows_with_future_requests}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel title="Rejected run" tone="warn">
          {st.failed_plans.map((f) => (
            <div key={f.run_id} className="rejected">
              <div className="mono">{f.run_id}</div>
              <div>
                Site {f.site_id} · {SCENARIO[f.scenario_id]} · {f.partition === 'test_out_of_site' ? 'Site C test' : f.partition}
              </div>
              <div className="muted">
                Recon plan truncated at the 75 s horizon (frozen-plan property). Retried once with the same plan, rejected again,
                not replaced. Site C reconnaissance test: {st.achieved_vs_planned.find((x) => x.site_id === 'C' && x.group === 'recon').accepted} of{' '}
                {st.achieved_vs_planned.find((x) => x.site_id === 'C' && x.group === 'recon').planned} runs.
              </div>
            </div>
          ))}
        </Panel>
      </div>

      <Panel title="Pilot iterations" note="Same gates throughout; failed designs were kept, not edited">
        <table className="table">
          <thead>
            <tr><th>Pilot</th><th className="r">Runs accepted</th><th>G1</th><th>G2</th><th>G3</th><th>Outcome</th></tr>
          </thead>
          <tbody>
            {Object.entries(v.pilots).map(([k, p]) => (
              <tr key={k}>
                <td>{k}</td>
                <td className="r">{p.runs_accepted} / {p.runs_total}</td>
                <td><Pass ok={p.G1} /></td>
                <td><Pass ok={p.G2} /></td>
                <td><Pass ok={p.G3} /></td>
                <td className="muted">
                  {{
                    v1: 'Rejected: normal traffic did not cover recon shapes; timing shortcut',
                    v2: 'Gates pass; recon too easy (normal always revisits)',
                    v3: 'Adds legitimate one-pass workloads, Site B, clock monitoring',
                  }[k]}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      <div className="footnote">Groups: {Object.values(GROUP).join(' · ')}.</div>
    </div>
  );
}
