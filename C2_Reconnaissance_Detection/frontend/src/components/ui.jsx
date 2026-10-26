export function Panel({ title, note, tone, children, right }) {
  return (
    <section className={`panel ${tone ?? ''}`}>
      {(title || right) && (
        <div className="panel-head">
          <div>
            {title && <h2>{title}</h2>}
            {note && <div className="panel-note">{note}</div>}
          </div>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function Tile({ label, value, sub, tone }) {
  return (
    <div className={`tile ${tone ?? ''}`}>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  );
}

export function Loading({ text = 'Loading…' }) {
  return <div className="loading">{text}</div>;
}

export function Badge({ tone, children }) {
  return <span className={`badge ${tone ?? ''}`}>{children}</span>;
}
