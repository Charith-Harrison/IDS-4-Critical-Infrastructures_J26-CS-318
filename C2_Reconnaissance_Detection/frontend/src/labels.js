export const MODELS = [
  { id: 'A', name: 'Current message', short: 'Current msg', kind: 'baseline' },
  { id: 'B2', name: 'Order-free summary', short: 'Order-free', kind: 'history' },
  { id: 'B1', name: 'Flattened-history RF', short: 'Flattened RF', kind: 'history' },
  { id: 'B3', name: 'History-statistics RF', short: 'History stats', kind: 'history' },
  { id: 'L', name: 'LSTM', short: 'LSTM', kind: 'history' },
];
export const FINAL_MODEL = 'B3';

export const FC = {
  1: 'Read Coils',
  2: 'Read Discrete Inputs',
  3: 'Read Holding Registers',
  4: 'Read Input Registers',
};

export const SCENARIO = {
  R1_sequential_scan: 'Sequential scan',
  R2_sparse_strided_scan: 'Sparse scan',
  R3_randomized_scan: 'Randomised scan',
  R4_slow_jittered_scan: 'Slow jittered scan',
  R5_function_probe: 'Function-code probe',
  R6_unit_probe: 'Unit probe',
  N1_fixed_polling: 'Fixed polling',
  N2_variable_polling_bursts: 'Variable polling',
  N3_maintenance_blocks: 'Maintenance',
  N4_trend_watch: 'Trend watch',
  N5_hmi_cold_start: 'HMI cold start',
  N6_config_backup: 'Configuration backup',
  N7_historian_backfill: 'Historian backfill',
  N8_commissioning_checkout: 'Commissioning check',
};

export const STRATUM = {
  recon: 'Reconnaissance',
  revisiting_normal: 'Revisiting normal',
  one_pass_normal: 'One-pass normal',
  legitimate_lead_in: 'Lead-in maintenance',
  background: 'Background HMI',
};

export const PHASE = {
  recon: 'Reconnaissance',
  background_hmi: 'Background HMI polling',
  normal_workload: 'Normal task',
  pre_recon_legitimate_activity: 'Lead-in (before recon)',
  pre_task_legitimate_activity: 'Lead-in (before task)',
};

export const GROUP = { recon: 'Reconnaissance', one_pass_normal: 'Legitimate one-pass', revisiting_normal: 'Revisiting normal' };

// Pre-specified B3 history statistics (component2_testbed/c2tb/diagnostics.py, PILOT_PROTOCOL.md)
export const B3_FEATURES = [
  { key: 'h_unique_target_frac', label: 'Distinct request keys', fmt: 'pct' },
  { key: 'h_first_seen_frac', label: 'First-seen share', fmt: 'pct' },
  { key: 'h_current_first_seen', label: 'Current key first seen', fmt: 'yesno' },
  { key: 'h_ascending_step_frac', label: 'Ascending steps', fmt: 'pct' },
  { key: 'h_mean_abs_addr_delta', label: 'Mean |Δ address|', fmt: 'num1' },
  { key: 'h_fc_transition_frac', label: 'FC changes', fmt: 'pct' },
  { key: 'h_unit_transition_frac', label: 'Unit changes', fmt: 'pct' },
  { key: 'h_distinct_tables', label: 'Distinct tables', fmt: 'int' },
  { key: 'h_iat_mean_log', label: 'Mean interval', fmt: 'log10s' },
  { key: 'h_iat_cv', label: 'Interval CV', fmt: 'num2' },
];

export function fmt(v, kind) {
  if (v === null || v === undefined || Number.isNaN(v)) return '–';
  switch (kind) {
    case 'pct':
      return `${(v * 100).toFixed(0)}%`;
    case 'pct1':
      return `${(v * 100).toFixed(1)}%`;
    case 'yesno':
      return v >= 0.5 ? 'yes' : 'no';
    case 'int':
      return Math.round(v).toString();
    case 'num1':
      return v.toFixed(1);
    case 'num2':
      return v.toFixed(2);
    case 'log10s': {
      const s = Math.max(10 ** v - 1e-6, 0);
      return s < 1 ? `${(s * 1000).toFixed(0)} ms` : `${s.toFixed(2)} s`;
    }
    default:
      return String(v);
  }
}

export const pct = (x, d = 1) => (x === undefined || x === null ? '–' : `${(x * 100).toFixed(d)}%`);
export const ci = (c, d = 1) => (c ? `${(c[0] * 100).toFixed(d)}–${(c[1] * 100).toFixed(d)}%` : '');
export const num = (n) => n?.toLocaleString('en-GB') ?? '–';
