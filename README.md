# ResolverFuzz Replication (COE 576 — Paper 12)

Replication project for:

> Qifan Zhang, Xuesong Bai, Xiang Li, Haixin Duan, Qi Li, Zhou Li.
> **ResolverFuzz: Automated Discovery of DNS Resolver Vulnerabilities
> with Query-Response Fuzzing.** USENIX Security 2024.

## What this replicates, and how

The original paper fuzzes six *real* DNS resolver binaries (BIND,
Unbound, Knot, PowerDNS, MaraDNS, Technitium) running in Docker
containers on a real (localized) network. Standing up and safely
attacking six live resolver binaries is outside the scope of a course
replication (time, infrastructure, and the same ethical reasoning the
paper itself gives in its Section 7 for *localizing* rather than
attacking the public Internet).

Instead, this project replicates the paper's **methodology** end to
end, in simulation:

1. **`src/pcfg_generator.py`** — a probabilistic context-free grammar
   (PCFG) query/response generator implemented directly from the
   paper's **Appendix B** grammar (Listings 1 & 2), including
   weighted field probabilities and byte-level mutation of terminals.
2. **`src/mock_resolvers.py`** — small resolver *caching-policy*
   models. Each model's divergent behavior is transcribed directly
   from a documented, named bug in the paper's **Table 2 / Section
   6**: `MockBIND` implements **CP1** (no bailiwick check on
   Authority/Additional records), `MockPowerDNS` implements **CP2**
   (proactive NS-glue caching), `MockUnbound` implements **RC2**
   (no type restriction on cached Authority/Additional records).
   `MockKnot` is left RFC-conformant, matching Table 2's largely
   "not vulnerable" row for Knot on these bug classes.
3. **`src/oracle.py`** — the differential-testing cache oracle from
   Section 4.3: for each test case, computes each resolver's maximum
   cache disagreement against every other resolver (no "golden
   model" assumed, exactly as the paper argues is necessary).
4. **`src/clustering.py`** — bisecting K-means + elbow-method `k`
   selection (Section 4.3, Figure 3), via `scikit-learn`, matching
   the paper's stated tooling.
5. **`src/fuzzer.py`** — orchestrates one fuzzing "round" per the
   paper's *constrained stateful fuzzing* design (Section 3.2): fresh
   resolver state each round, one query/response pair mutated per
   round.
6. **`src/run_experiment.py`** — runs the full campaign and produces
   three figures (see below).

This lets us test the paper's actual **central experimental claim** —
that differential testing across diverse resolver implementations,
combined with clustering, can surface cache-poisoning-relevant
inconsistencies without any ground-truth "correct" resolver — against
known, documented bug mechanisms, and check whether the pipeline
recovers them.

## Setup (VS Code / local)

```bash
git clone <this-repo-url>
cd resolverfuzz-replication
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Open the folder in VS Code (`code .`), select the `.venv` interpreter
when prompted (or via `Ctrl+Shift+P` → "Python: Select Interpreter").

## Running

```bash
# unit tests
python -m pytest tests/ -v

# quick smoke run of the fuzzing pipeline
python src/fuzzer.py

# full experiment: generates all figures into results/
python src/run_experiment.py
```

Outputs land in `results/`:

| File | Replicates | Description |
|---|---|---|
| `elbow_sse.png` | Figure 3 | SSE vs. `k` for bisecting K-means, with elbow-selected `k` marked |
| `cluster_bug_recovery.png` | — (novel) | Cross-tabulates cluster assignment against *structural* ground truth (which documented bug mechanism — CP1/CP2/RC2 — each test case's generated response actually exercises) to check whether clustering meaningfully separates bug classes |
| `sensitivity_analysis.png` | extends Fig. 6b | Sweeps the PCFG weight on out-of-bailiwick record generation and separates its effect on *opportunity rate* (how often the bug is exercised) from *conditional severity* (how large the resulting cache divergence is, given the opportunity) — a distinction the original ablation does not report |
| `summary.json` | — | Machine-readable summary of all of the above |

## Key finding from this replication

Differential testing does reliably flag *that* something is wrong
(96% of generated test cases show some cross-resolver cache
disagreement, comparable in spirit to the paper's own finding that a
majority of their test cases were inconsistent). However, clustering
those disagreements by cache-diff magnitude alone achieves only
moderate purity (~0.71) against the true underlying bug mechanism —
consistent with the paper's own account that raw clustering still
requires a further, manual sub-clustering/matching-rule pass
(Section 4.3) before individual bug classes can be confidently
separated. Our sensitivity analysis further shows that increasing a
grammar weight mainly increases how *often* a bug-eligible message is
generated, not how *severe* each resulting divergence is — a
distinction worth designing future PCFG weighting around.

## Known limitations of this replication

- Mock resolvers model documented *caching-policy* differences only;
  they do not model resource-consumption or crash bugs (RC/CC
  categories), nor real network/timing behavior.
- Only 4 of the paper's 6 resolvers are modeled (BIND, Unbound,
  PowerDNS, Knot) — MaraDNS and Technitium's cache dumps were not
  even fully available to the original authors either (see Sec. 5.1).
- The bisecting K-means elbow/`k` selection and structural
  ground-truth labels are our own instrumentation for validating the
  pipeline; the real paper did not have (or need) ground truth, since
  they were hunting for genuinely unknown bugs.
- Field/record counts and label lengths are capped below the paper's
  stated maxima (e.g. 30 vs. 128 labels) purely for runtime
  practicality in a course setting.

## Repository layout

```
resolverfuzz-replication/
├── README.md
├── requirements.txt
├── src/
│   ├── pcfg_generator.py     # Appendix B grammar
│   ├── mock_resolvers.py     # simulated caching policies (CP1/CP2/RC2)
│   ├── oracle.py             # differential-testing cache oracle (Sec 4.3)
│   ├── clustering.py         # bisecting K-means + elbow method (Fig 3)
│   ├── fuzzer.py             # campaign orchestration (Sec 3.2)
│   └── run_experiment.py     # main entry point, produces results/*.png
├── tests/
│   └── test_pcfg_generator.py
└── results/                  # generated figures + summary.json
```
