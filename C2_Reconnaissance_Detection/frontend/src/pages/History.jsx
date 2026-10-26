import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Loading, Panel, Tile } from '../components/ui.jsx';
import { num, pct } from '../labels.js';

const STATE = {
  attack_associated_response: 'Exception replies from another attack (coil writes)',
  unsupported_heuristic: 'Unsupported heuristic',
  ambiguous: 'Ambiguous',
  supported_contextual: 'Supported reconnaissance context',
};

export default function History() {
  const [c, setC] = useState(null);
  useEffect(() => {
    api.cic().then(setC);
  }, []);
  if (!c) return <Loading />;
  const states = Object.entries(c.positive_label_states).sort((a, b) => b[1] - a[1]);
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Project evolution · CIC Modbus 2023 forensic audit</div>
          <h1>Why the dataset changed</h1>
        </div>
      </div>

      <div className="tiles">
        <Tile label="Inherited windows" value={num(c.legacy_windows)} sub={`${num(c.windows_with_backward_time)} with time running backwards`} tone="bad" />
        <Tile label="Inherited positive labels" value={num(c.legacy_positive_rows)} sub={`${num(c.positive_label_states.attack_associated_response)} were exception replies`} tone="bad" />
        <Tile label="One-line rule: length = 3" value={`F1 ${c.len3_rule_packet_F1.toFixed(3)}`} sub="Explains the old labels without any history" tone="bad" />
        <Tile label="Recovered real recon requests" value={num(c.recovered_recon_candidates)} sub={`${c.recovered_supported} with solid log support`} />
      </div>

      <div className="grid-2">
        <Panel title="What the inherited positive labels actually were">
          <div className="stack">
            {states.map(([k, v]) => (
              <div key={k} className="stack-row">
                <div className="stack-label">{STATE[k] ?? k}</div>
                <div className="stack-track">
                  <div className={`stack-fill ${k === 'supported_contextual' ? 'good' : 'bad'}`} style={{ width: `${(v / c.legacy_positive_rows) * 100}%` }} />
                </div>
                <div className="mono small">{num(v)} ({pct(v / c.legacy_positive_rows)})</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Decision">
          <ol className="steps">
            <li>Original CIC labels and sequences were audited against the raw PCAPs and attack logs.</li>
            <li>Most old positives were error replies from a different attack, not reconnaissance.</li>
            <li>Genuine CIC recon requests are obvious from the current message alone (bulk quantities), so CIC cannot test the temporal hypothesis.</li>
            <li>CIC is kept as secondary evidence only; a controlled Modbus/TCP testbed was built for the main experiment.</li>
          </ol>
          <div className="footnote">Source: {c.source}. The old CIC dashboard and its ~0.97 F1 result are not current results.</div>
        </Panel>
      </div>
    </div>
  );
}
