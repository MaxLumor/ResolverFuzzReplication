

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
