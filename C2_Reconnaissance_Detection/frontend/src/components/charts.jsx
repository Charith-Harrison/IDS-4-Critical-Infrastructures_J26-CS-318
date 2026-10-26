import { useMemo } from 'react';

const LOG_MIN = -4; // score axis: 1e-4 .. 1

export function logPos(v) {
  const x = Math.log10(Math.max(v, 10 ** LOG_MIN));
  return Math.min(Math.max((x - LOG_MIN) / -LOG_MIN, 0), 1);
}

export function ScoreBar({ score, threshold, alert }) {
  return (
    <div className="scorebar" title={`score ${score.toPrecision(4)} · threshold ${threshold.toPrecision(4)}`}>
      <div className={`scorebar-fill ${alert ? 'alert' : ''}`} style={{ width: `${logPos(score) * 100}%` }} />
      <div className="scorebar-thr" style={{ left: `${logPos(threshold) * 100}%` }} />
    </div>
  );
}

export function ScoreAxis() {
  return (
    <div className="scoreaxis">
      {[-4, -3, -2, -1, 0].map((e) => (
        <span key={e} style={{ left: `${((e - LOG_MIN) / -LOG_MIN) * 100}%` }}>
          {e === 0 ? '1' : `1e${e}`}
        </span>
      ))}
    </div>
  );
}

// Whole-run timeline: x = time, y = register address, colour = ground truth, ring = alert of the chosen model.
export function Timeline({ idx, t, address, recon, alert, cursor, onSeek, height = 170 }) {
  const W = 1000;
  const H = height;
  const pad = { l: 34, r: 8, t: 8, b: 18 };
  const { t0, t1, aMax } = useMemo(() => {
    let t0 = Infinity, t1 = -Infinity, aMax = 1;
    for (const i of idx) {
      t0 = Math.min(t0, t[i]);
      t1 = Math.max(t1, t[i]);
      aMax = Math.max(aMax, address[i]);
    }
    return { t0, t1: Math.max(t1, t0 + 1), aMax };
  }, [idx, t, address]);
  const x = (v) => pad.l + ((v - t0) / (t1 - t0)) * (W - pad.l - pad.r);
  const y = (a) => pad.t + (1 - a / aMax) * (H - pad.t - pad.b);
  const pts = useMemo(
    () =>
      idx.map((i) => (
        <circle key={i} cx={x(t[i])} cy={y(address[i])} r={2.1} className={recon[i] ? 'pt-recon' : 'pt-normal'} />
      )),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [idx, t0, t1, aMax]
  );
  const rings = useMemo(
    () =>
      idx
        .filter((i) => alert[i])
        .map((i) => <circle key={`a${i}`} cx={x(t[i])} cy={y(address[i])} r={4} className="pt-alert" />),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [idx, alert, t0, t1, aMax]
  );
  const cur = cursor >= 0 ? idx[cursor] : null;
  return (
    <svg
      className="timeline"
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      onClick={(e) => {
        const r = e.currentTarget.getBoundingClientRect();
        const tv = t0 + (((e.clientX - r.left) / r.width) * W - pad.l) / (W - pad.l - pad.r) * (t1 - t0);
        let best = 0;
        for (let k = 0; k < idx.length; k++) if (Math.abs(t[idx[k]] - tv) < Math.abs(t[idx[best]] - tv)) best = k;
        onSeek?.(best);
      }}
    >
      <line x1={pad.l} x2={W - pad.r} y1={H - pad.b} y2={H - pad.b} className="axis" />
      <text x={2} y={pad.t + 8} className="axis-label">{aMax}</text>
      <text x={2} y={H - pad.b} className="axis-label">0</text>
      <text x={pad.l} y={H - 4} className="axis-label">{`${t0.toFixed(0)} s`}</text>
      <text x={W - pad.r} y={H - 4} className="axis-label" textAnchor="end">{`${t1.toFixed(0)} s`}</text>
      {pts}
      {rings}
      {cur !== null && <line x1={x(t[cur])} x2={x(t[cur])} y1={pad.t} y2={H - pad.b} className="cursor" />}
    </svg>
  );
}

// The 20-request causal context: step order on x, register address on y, labelled with unit/FC.
export function ContextPath({ win, address, unit, fc, firstSeen, recon }) {
  const W = 520;
  const H = 150;
  const pad = { l: 28, r: 10, t: 10, b: 20 };
  const aMax = Math.max(1, ...win.map((i) => address[i]));
  const n = 20;
  const x = (k) => pad.l + (k / (n - 1)) * (W - pad.l - pad.r);
  const y = (a) => pad.t + (1 - a / aMax) * (H - pad.t - pad.b);
  const off = n - win.length;
  const d = win.map((i, k) => `${k ? 'L' : 'M'}${x(k + off)},${y(address[i])}`).join(' ');
  return (
    <svg className="ctxpath" viewBox={`0 0 ${W} ${H}`}>
      <line x1={pad.l} x2={W - pad.r} y1={H - pad.b} y2={H - pad.b} className="axis" />
      <text x={2} y={pad.t + 8} className="axis-label">{aMax}</text>
      <text x={2} y={H - pad.b} className="axis-label">0</text>
      <text x={pad.l} y={H - 5} className="axis-label">t−19</text>
      <text x={W - pad.r} y={H - 5} className="axis-label" textAnchor="end">current</text>
      <path d={d} className="ctx-line" />
      {win.map((i, k) => (
        <g key={i}>
          <circle
            cx={x(k + off)}
            cy={y(address[i])}
            r={k === win.length - 1 ? 6 : 4}
            className={`${recon[i] ? 'pt-recon' : 'pt-normal'} ${firstSeen[i] ? '' : 'revisit'} ${
              k === win.length - 1 ? 'current' : ''
            }`}
          >
            <title>{`unit ${unit[i]} · FC${fc[i]} · address ${address[i]}${firstSeen[i] ? ' · first time' : ' · revisit'}`}</title>
          </circle>
        </g>
      ))}
    </svg>
  );
}

// Grouped horizontal bars with CI whiskers (values in [0,1]).
export function RecallBars({ rows }) {
  return (
    <div className="recallbars">
      {rows.map((r) => (
        <div key={r.label} className="rb-row">
          <div className="rb-label">{r.label}</div>
          <div className="rb-tracks">
            {r.series.map((s) => (
              <div key={s.name} className="rb-track" title={`${s.name}: ${(s.value * 100).toFixed(1)}%`}>
                <div className={`rb-fill ${s.cls}`} style={{ width: `${s.value * 100}%` }} />
                {s.ci && (
                  <div className="rb-ci" style={{ left: `${s.ci[0] * 100}%`, width: `${(s.ci[1] - s.ci[0]) * 100}%` }} />
                )}
                <span className="rb-val">{(s.value * 100).toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
