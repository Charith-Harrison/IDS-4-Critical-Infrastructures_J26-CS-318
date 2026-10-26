async function call(path, opts) {
  const r = await fetch(`/api${path}`, opts);
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      msg = (await r.json()).detail ?? msg;
    } catch {}
    throw new Error(msg);
  }
  return r.json();
}

export const api = {
  health: () => call('/health'),
  summary: () => call('/summary'),
  metrics: () => call('/metrics'),
  validation: () => call('/validation'),
  cic: () => call('/cic'),
  runs: () => call('/runs'),
  samples: () => call('/samples'),
  run: (id) => call(`/runs/${id}`),
  verify: (id) => call(`/runs/${id}/verify`, { method: 'POST' }),
  score: (file) => {
    const fd = new FormData();
    fd.append('file', file);
    return call('/score', { method: 'POST', body: fd });
  },
};
