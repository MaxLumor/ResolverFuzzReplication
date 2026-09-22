"""
run_experiment.py

Main entry point. Produces three plots in ../results/:

  1. elbow_sse.png        -- replicates Figure 3 (SSE vs k for bisecting
                              K-means), used to justify a chosen k.
  2. cluster_bug_recovery.png
                            -- My own analysis: does clustering the
                              diff vectors actually separate the three
                              injected bug classes (CP1 / CP2 / RC2)
                              from each other and from "no bug"? This
                              is a sanity check the original paper
                              couldn't run (no ground truth for real
                              resolvers) but we can, since we know
                              exactly which bug we coded into which
                              mock resolver.
  3. sensitivity_analysis.png
                            -- GOES BEYOND the paper's own figures:
                              a sweep over how "aggressively" the PCFG
                              targets out-of-bailiwick records (i.e.
                              the probability weight on the 'unrelated'
                              NAME-kind terminal, Appendix B Listing 2)
                              and its effect on (a) how many test cases
                              are needed to first observe a CP1-style
                              inconsistency, and (b) overall inconsistent-
                              case fraction. This extends the paper's own
                              PCFG-probability ablation (Sec 5.3, Fig 6b)
                              with a parameter they did not sweep.

Run:
    python run_experiment.py
"""

from __future__ import annotations

import json
import os

import numpy as np
import matplotlib
matplotlib.use("Agg")
import importlib

# Load pyplot dynamically so environments with incomplete matplotlib type
# metadata do not report a missing source module during static analysis.
plt = importlib.import_module("matplotlib.pyplot")

from fuzzer import FuzzRunConfig, run_fuzz_campaign
from oracle import summarize
from clustering import elbow_sse_curve, choose_k_by_elbow, cluster_vectors
from mock_resolvers import RESOLVER_CLASSES
import pcfg_generator as pg

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

RESOLVER_ORDER = tuple(sorted(RESOLVER_CLASSES.keys()))  # must match oracle.py's sort


# ---------------------------------------------------------------------------
# 1. Baseline campaign + elbow plot (replicates Figure 3)
# ---------------------------------------------------------------------------

def run_baseline_and_elbow(n_test_cases: int = 3000, seed: int = 42):
    cfg = FuzzRunConfig(n_test_cases=n_test_cases, seed=seed)
    results = run_fuzz_campaign(cfg)
    summary = summarize(results)
    print("Baseline campaign summary:", summary)

    inconsistent = [r for r in results if r.is_inconsistent]
    vectors = np.array([r.diff_vector for r in inconsistent], dtype=float)

    k_range = range(2, min(15, len(vectors)))
    sse_curve = elbow_sse_curve(vectors, k_range)
    chosen_k = choose_k_by_elbow(sse_curve)
    print(f"Chosen k (elbow method): {chosen_k}")

    plt.figure(figsize=(6, 4))
    ks = sorted(sse_curve.keys())
    plt.plot(ks, [sse_curve[k] for k in ks], marker="o", label="SSE")
    plt.axvline(chosen_k, color="red", linestyle="--", label="k selected")
    plt.xlabel("k")
    plt.ylabel("Sum of Squared Error (SSE)")
    plt.title("Bisecting K-Means elbow curve (replicates Fig. 3)")
    plt.legend()
    plt.tight_layout()
    out = os.path.join(RESULTS_DIR, "elbow_sse.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"Saved {out}")

    return results, inconsistent, vectors, chosen_k


# ---------------------------------------------------------------------------
# 2. Cluster -> known-bug-class recovery check
# ---------------------------------------------------------------------------

def bug_signature(bug_opportunities: frozenset) -> str:
    """Ground-truth label derived from the TEST CASE'S STRUCTURE (which
    documented bug mechanism its generated response exercises), NOT
    from the diff vector -- see fuzzer.structural_bug_opportunities.
    Deriving "ground truth" from the diff vector itself would be
    circular, since with a max-vs-any-other metric nearly every
    resolver ends up nonzero as soon as ANY divergence exists.
    """
    return "+".join(sorted(bug_opportunities)) if bug_opportunities else "no_opportunity"


def run_cluster_bug_recovery(vectors: np.ndarray, inconsistent, chosen_k: int):
    labels = cluster_vectors(vectors, chosen_k)
    ground_truth = [bug_signature(r.bug_opportunities) for r in inconsistent]

    # cross-tabulate cluster id vs "dominant divergent resolver"
    from collections import Counter, defaultdict
    table: dict[int, Counter] = defaultdict(Counter)
    for lbl, gt in zip(labels, ground_truth):
        table[int(lbl)][gt] += 1

    cluster_ids = sorted(table.keys())
    all_gt_labels = sorted({gt for c in table.values() for gt in c})

    matrix = np.array([[table[c][gt] for gt in all_gt_labels] for c in cluster_ids])

    plt.figure(figsize=(7, 4.5))
    im = plt.imshow(matrix, aspect="auto", cmap="Blues")
    plt.colorbar(im, label="# test cases")
    plt.xticks(range(len(all_gt_labels)), all_gt_labels, rotation=45, ha="right")
    plt.yticks(range(len(cluster_ids)), [f"cluster {c}" for c in cluster_ids])
    plt.title("Do bisecting K-means clusters separate known bug classes?")
    plt.tight_layout()
    out = os.path.join(RESULTS_DIR, "cluster_bug_recovery.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"Saved {out}")

    # simple purity metric
    purity = sum(c.most_common(1)[0][1] for c in table.values()) / len(ground_truth)
    print(f"Cluster purity vs dominant-resolver ground truth: {purity:.3f}")
    return purity


# ---------------------------------------------------------------------------
# 3. Sensitivity analysis -- BEYOND the paper's figures
# ---------------------------------------------------------------------------

def run_sensitivity_analysis(n_test_cases: int = 800, seed: int = 7):
    """Sweeps the weight on the 'unrelated' (out-of-bailiwick) NAME
    terminal in the response-record grammar (Appendix B, Listing 2)
    and measures two DISTINCT effects that the paper's own PCFG
    ablation (Fig. 6b) does not separate out:

      (a) OPPORTUNITY RATE: fraction of generated test cases that
          structurally contain an out-of-bailiwick Authority/
          Additional record at all (CP1_opportunity). This should
          scale with the swept weight roughly by construction, and
          serves as a sanity check on the generator.

      (b) CONDITIONAL SEVERITY: *given* a CP1_opportunity test case,
          how large is BIND's resulting cache divergence, on average?
          If this stayed flat while (a) rises, it would tell us the
          grammar change only affects how OFTEN the bug is exercised,
          not how BADLY -- a distinction the original ablation study
          (which only reports vulnerability-discovery time, not
          per-hit severity) does not report.

    The original paper's ablation (Sec 5.3) varies overall PCFG-vs-
    uniform weighting and message-sequence length; it does not sweep
    an individual field's weight or separate opportunity-rate from
    severity, so this is a genuine extension rather than a
    reproduction.
    """
    unrelated_weights = [0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.60]
    opportunity_rates = []
    conditional_severity = []

    bind_idx = RESOLVER_ORDER.index("BIND")

    for w in unrelated_weights:
        remaining = 1.0 - w
        each_other = remaining / 4
        custom_name_table = [
            ("queried", each_other), ("sub", each_other),
            ("same_level", each_other), ("parent", each_other),
            ("unrelated", w),
        ]
        # monkey-patch the module-level table for this run (simple &
        # explicit for a course replication; a production version would
        # thread this through PCFGGenerator's constructor instead)
        original_table = pg.NAME_TABLE_TEMPLATE
        pg.NAME_TABLE_TEMPLATE = custom_name_table
        try:
            cfg = FuzzRunConfig(n_test_cases=n_test_cases, seed=seed)
            results = run_fuzz_campaign(cfg)
        finally:
            pg.NAME_TABLE_TEMPLATE = original_table

        cp1_cases = [r for r in results if "CP1_opportunity" in r.bug_opportunities]
        opportunity_rates.append(len(cp1_cases) / n_test_cases)

        if cp1_cases:
            mean_severity = sum(r.diff_vector[bind_idx] for r in cp1_cases) / len(cp1_cases)
        else:
            mean_severity = 0.0
        conditional_severity.append(mean_severity)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    ax1.plot(unrelated_weights, opportunity_rates, marker="o", color="tab:blue")
    ax1.set_xlabel("PCFG weight on out-of-bailiwick ('unrelated') record NAME")
    ax1.set_ylabel("Fraction of test cases w/ CP1 opportunity")
    ax1.set_title("(a) Opportunity rate vs. bailiwick-violation weight")

    ax2.plot(unrelated_weights, conditional_severity, marker="s", color="tab:red")
    ax2.set_xlabel("PCFG weight on out-of-bailiwick ('unrelated') record NAME")
    ax2.set_ylabel("Mean BIND cache-diff size | CP1 opportunity present")
    ax2.set_title("(b) Conditional severity vs. bailiwick-violation weight")

    plt.suptitle("Sensitivity analysis: opportunity vs. severity (extends Fig. 6b)")
    plt.tight_layout()
    out = os.path.join(RESULTS_DIR, "sensitivity_analysis.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"Saved {out}")

    return {"weights": unrelated_weights,
            "opportunity_rates": opportunity_rates,
            "conditional_severity": conditional_severity}


# ---------------------------------------------------------------------------

def main():
    results, inconsistent, vectors, chosen_k = run_baseline_and_elbow()
    purity = run_cluster_bug_recovery(vectors, inconsistent, chosen_k)
    sensitivity = run_sensitivity_analysis()

    summary_path = os.path.join(RESULTS_DIR, "summary.json")
    with open(summary_path, "w") as f:
        json.dump({
            "baseline_summary": summarize(results),
            "chosen_k": chosen_k,
            "cluster_purity_vs_dominant_resolver": purity,
            "sensitivity_analysis": sensitivity,
        }, f, indent=2)
    print(f"Saved {summary_path}")


if __name__ == "__main__":
    main()
