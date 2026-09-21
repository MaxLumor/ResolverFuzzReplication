"""
oracle.py

Differential-testing cache oracle, replicating Section 4.3's approach:

  "we consider si is abnormal when its trace differs from any
   sj in S \\ {si}. ... we represent si of each test case with the
   maximum number of different records of software i with other
   software" -- e.g. <0,0,0,5> means resolvers 1-3 agree, resolver 4
   has 5 extra/differing cache records.

No "golden model" is assumed -- exactly as the paper argues (they note
even BIND, the most mature implementation, has 100+ CVEs, so nothing
can serve as ground truth). Divergence itself is the signal.
"""

from __future__ import annotations

from dataclasses import dataclass

from mock_resolvers import MockResolver


@dataclass
class TestCaseResult:
    test_id: int
    diff_vector: tuple[int, ...]     # one entry per resolver, in a fixed order
    resolver_order: tuple[str, ...]
    is_inconsistent: bool
    bug_opportunities: frozenset = frozenset()  # structural ground truth (see fuzzer.py)


def run_differential_test(test_id: int, resolvers: dict[str, MockResolver],
                           bug_opportunities: frozenset = frozenset()) -> TestCaseResult:
    """Call AFTER each resolver in `resolvers` has processed the same
    test case and BEFORE resetting them. Computes the paper's per-
    resolver max-difference vector from the resolvers' cache snapshots."""
    order = tuple(sorted(resolvers.keys()))
    snapshots = {name: resolvers[name].cache_snapshot() for name in order}

    diff_vector = []
    for name in order:
        mine = snapshots[name]
        max_diff = 0
        for other in order:
            if other == name:
                continue
            # symmetric difference size = records that disagree between the two
            diff = len(mine.symmetric_difference(snapshots[other]))
            max_diff = max(max_diff, diff)
        diff_vector.append(max_diff)

    is_inconsistent = any(d > 0 for d in diff_vector)
    return TestCaseResult(test_id, tuple(diff_vector), order, is_inconsistent, bug_opportunities)


def summarize(results: list[TestCaseResult]) -> dict:
    total = len(results)
    inconsistent = [r for r in results if r.is_inconsistent]
    return {
        "total_test_cases": total,
        "inconsistent_test_cases": len(inconsistent),
        "inconsistent_fraction": len(inconsistent) / total if total else 0.0,
    }
