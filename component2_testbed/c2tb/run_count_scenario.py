"""Scenario-stratified run count (frozen design).  Uses per-run rates from run_count.py.

Between-run SD is pooled within scenario (scenario means removed), and a one-sided 80 % upper confidence limit of
that SD (chi-square, pooled df) is used because v3 has only 2 runs per scenario.  Required runs per scenario per
test population: smallest n with t_{0.975,n-1} * sd_ucl / sqrt(n) <= h.
"""
import json
import math
import sys

import numpy as np
import pandas as pd
from scipy import stats

rates = pd.read_csv(sys.argv[1])
H_SCENARIO = {"recon": 0.15, "revisiting_normal": 0.15, "one_pass_normal": 0.15}   # per-scenario CI half-width
COL = {"recon": "rate_history", "revisiting_normal": "rate_history", "one_pass_normal": "rate_history"}


def n_required(sd, h):
    for n in range(2, 1000):
        if stats.t.ppf(0.975, n - 1) * sd / math.sqrt(n) <= h:
            return n


out = {"method": __doc__.strip(), "h_per_scenario": H_SCENARIO, "strata": {}}
for st, h in H_SCENARIO.items():
    d = rates[rates.stratum == st]
    dev = d[COL[st]] - d.groupby("run_scenario_id")[COL[st]].transform("mean")
    dfree = len(d) - d.run_scenario_id.nunique()
    sd = float(np.sqrt((dev ** 2).sum() / dfree))
    sd_ucl = float(sd * np.sqrt(dfree / stats.chi2.ppf(0.20, dfree)))
    sd_cap = min(sd_ucl, 0.5)  # a rate's SD cannot exceed 0.5
    out["strata"][st] = {"runs": int(len(d)), "scenarios": int(d.run_scenario_id.nunique()), "pooled_df": dfree,
                         "pooled_within_scenario_sd": round(sd, 4), "sd_ucl80": round(sd_ucl, 4),
                         "sd_used": round(sd_cap, 4),
                         "required_runs_per_scenario_per_test_population": n_required(sd_cap, h),
                         "scenario_means": d.groupby("run_scenario_id")[COL[st]].mean().round(3).to_dict()}
d = rates[rates.stratum == "recon"]
g = d.rate_history - d.rate_current_without_tid
dev = g - g.groupby(d.run_scenario_id).transform("mean")
dfree = len(d) - d.run_scenario_id.nunique()
sd = float(np.sqrt((dev ** 2).sum() / dfree))
sd_ucl = min(float(sd * np.sqrt(dfree / stats.chi2.ppf(0.20, dfree))), 0.5)
# scenario-balanced mean gain over k recon scenarios with n runs each: SE = sd/sqrt(k*n); require half-width 0.10
k = d.run_scenario_id.nunique()
n_gain = next(n for n in range(1, 1000) if stats.t.ppf(0.975, k * n - k) * sd_ucl / math.sqrt(k * n) <= 0.10)
out["paired_gain_history_minus_current"] = {"pooled_within_scenario_sd": round(sd, 4), "sd_ucl80": round(sd_ucl, 4),
                                            "required_runs_per_recon_scenario_for_halfwidth_0.10": n_gain}
print(json.dumps(out, indent=1))
