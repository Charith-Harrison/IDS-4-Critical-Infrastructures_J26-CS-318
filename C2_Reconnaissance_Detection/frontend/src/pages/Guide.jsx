import { Panel } from '../components/ui.jsx';
import { MetricDefinitions } from './Metrics.jsx';

const TOUR = [
  { url: 'overview', name: 'Overview', say: 'We are testing whether recent Modbus request history helps distinguish a scan from normal work.', look: 'Start with the B3 and LSTM results. The experiment has 383 accepted runs. Site C is a held-out software configuration, not a deployed factory.' },
  { url: 'metrics', name: 'Metrics', say: 'Recall tells us how much recon we caught. False-positive rate tells us how much legitimate work we interrupted.', look: 'Choose A+B or Site C, then choose the normal workload. Show precision, recall, F1 and the actual TP/FP/TN/FN counts. Switch to one-pass work before making any overall claim.' },
  { url: 'replay', name: 'Traffic replay', say: 'This is a recorded test run. Here is the request, its recent history and each model’s decision.', look: 'Use Play or Next. The timeline’s colours come from the experiment ledger. Alert rings are model decisions. The request bytes and frame number connect the example to its capture.' },
  { url: 'compare', name: 'Compare behaviours', say: 'Polling revisits familiar requests. A scan often reaches new ones. A legitimate backup can do the same.', look: 'Compare all three examples. A high alert rate is useful on recon and a false-alarm problem on a legitimate backup. These examples explain behaviour; they are not the entire test set.' },
  { url: 'validation', name: 'Data checks', say: 'The labels come from a separate experiment ledger, and the captured requests were checked against it.', look: 'Explain parser checks, isolated runs, clock correction and run-level train/validation/test separation. One failed run is kept in the record. Gates are declared checks, not proof that every possible shortcut is impossible.' },
  { url: 'history', name: 'CIC audit', say: 'The old public-data results were not reliable evidence for this hypothesis, so we kept CIC as a secondary case study.', look: 'Old labels included invalid coil-write exception replies and broken sequences. The current headline metrics belong to the controlled testbed, not those old CIC models.' },
  { url: 'score', name: 'Score a file', say: 'These already-trained models can score a table of parsed Modbus requests without retraining.', look: 'Use one of the supplied CSV or Parquet samples first. This input is a request table, not a raw PCAP. An unlabelled upload gives scores and alerts, not a measured accuracy.' },
];
export default function Guide() {
  return <div className="page guide-page">
    <div className="page-head"><div><div className="eyebrow">Presentation notes</div><h1>Walk Harry through the experiment.</h1><p className="page-intro">Follow this order. Explain the question first, the results second, and the limitation before finishing.</p></div></div>
    <div className="opening-script"><span className="section-number">Start here</span><p>“A scan can use perfectly valid Modbus requests. We tested whether remembering recent requests helps identify the behaviour. It helps against repeated polling, but a legitimate one-pass backup can look like a scan. A simple history-statistics model performed about as well as the LSTM.”</p></div>
    <ol className="walkthrough-list">{TOUR.map((x, i) => <li key={x.url}><div className="walkthrough-number">{String(i + 1).padStart(2, '0')}</div><div><a className="walkthrough-title" href={`#${x.url}`}>{x.name} <span aria-hidden="true">↗</span></a><blockquote>“{x.say}”</blockquote><p>{x.look}</p></div></li>)}</ol>
    <Panel title="The model names, without the jargon"><dl className="metric-definitions">
      <div><dt>A · Current message</dt><dd>One question at a time. No history. This is the baseline the other models must improve on.</dd></div>
      <div><dt>B1 · Flattened RF</dt><dd>Places the 20 × 19 input into one long row for a Random Forest. Position and history-derived features are still present.</dd></div>
      <div><dt>B2 · Order-free summary</dt><dd>Summarises the recent requests without preserving their step order. Its poorer transfer does not isolate order as the only cause.</dd></div>
      <div><dt>B3 · History statistics</dt><dd>A Random Forest using repetition, novelty, address changes and timing summaries. This is the dashboard’s default alert model.</dd></div>
      <div><dt>L · LSTM</dt><dd>A recurrent model reading the ordered 20-step input. It was evaluated, but was not clearly better than B3.</dd></div>
    </dl></Panel>
    <Panel title="Reading the replay"><dl className="metric-definitions">
      <div><dt>Current request</dt><dd>What the client asked: unit identifies the device, function identifies the operation, address is the starting position, and quantity is how many items it requested.</dd></div>
      <div><dt>Ground truth</dt><dd>The known role of that request in the experiment ledger. It is shown for checking decisions and is never a predictor.</dd></div>
      <div><dt>Score / threshold</dt><dd>The score is a model output, not a verified probability of attack. The line is its frozen alert cutoff. Each model has a different score scale.</dd></div>
      <div><dt>New request key</dt><dd>A new combination of unit, function, address and quantity since this stream segment began. It does not mean a newly discovered IP address.</dd></div>
      <div><dt>Recent 20 requests</dt><dd>Up to 20 requests ending at the selected request, from the same run/client/target stream. Nothing after the current request enters its history.</dd></div>
      <div><dt>First-seen memory</dt><dd>Some indicators remember whether a key appeared earlier in the stream, beyond the displayed 20 rows. This is past-only memory, not future information.</dd></div>
      <div><dt>Verify predictions</dt><dd>Runs the frozen inference pipeline on the example again and compares it with saved scores. This checks reproduction, not new test generalisation.</dd></div>
    </dl></Panel>
    <Panel title="Common metrics"><MetricDefinitions /></Panel>
    <Panel title="What changed since the old explanation?"><div className="table-scroll"><table className="table"><thead><tr><th>Part</th><th>Old CIC prototype</th><th>Current experiment</th></tr></thead><tbody>
      <tr><td>Evidence</td><td>Inherited packet labels and capture groups</td><td>Controlled runs with a separate ledger and raw-capture checks</td></tr>
      <tr><td>Target</td><td>Any positive packet inside a 20-packet window</td><td>The current request, with causal history</td></tr>
      <tr><td>Input</td><td>Legacy workbook 20 × 7; engineered CIC model also 20 × 19</td><td>20 × 19 with different feature meanings and stream memory</td></tr>
      <tr><td>Evaluation</td><td>Some named capture groups were pieces of one recording</td><td>Run-level partitions; Site C reserved for the out-of-site test</td></tr>
      <tr><td>Conclusion</td><td>High scores did not establish temporal recon detection</td><td>History helps for revisiting normal work; LSTM superiority and intent recognition are not established</td></tr>
    </tbody></table></div></Panel>
    <div className="closing-note"><strong>Finish with the limitation.</strong> This is a controlled software testbed result. It is not evidence of reliable intent detection, a universal 5% false-alarm guarantee, or a finished deployment in a real plant.</div>
  </div>;
}
