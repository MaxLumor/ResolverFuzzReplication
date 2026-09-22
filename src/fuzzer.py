

from __future__ import annotations

from dataclasses import dataclass

from pcfg_generator import PCFGGenerator, DNSResponse
from mock_resolvers import build_resolver_pool, is_in_bailiwick, MockResolver
from oracle import run_differential_test, TestCaseResult, summarize


def structural_bug_opportunities(response: DNSResponse, zone: str) -> frozenset:
    
    tags = set()
    for rec in response.authority + response.additional:
        if not is_in_bailiwick(rec.name, zone):
            tags.add("CP1_opportunity")  # out-of-bailiwick record present
        if rec.rtype not in MockResolver.ALLOWED_AUTHORITY_TYPES | MockResolver.ALLOWED_ADDITIONAL_TYPES:
            tags.add("RC2_opportunity")  # disallowed record type present

    ns_names = {r.name for r in response.authority if r.rtype == "NS"
                and is_in_bailiwick(r.name, zone)}
    if ns_names and any(r.rtype in ("A", "AAAA") for r in response.additional):
        tags.add("CP2_opportunity")  # NS + matching glue present

    return frozenset(tags) if tags else frozenset({"no_opportunity"})


@dataclass
class FuzzRunConfig:
    n_test_cases: int = 2000
    base_domain: str = "test-atkr.com"
    seed: int = 42
    opcode_table=None
    rcode_table=None
    byte_mutation_prob: float = 0.1


def run_fuzz_campaign(cfg: FuzzRunConfig) -> list[TestCaseResult]:
    gen = PCFGGenerator(
        base_domain=cfg.base_domain,
        seed=cfg.seed,
        opcode_table=cfg.opcode_table,
        rcode_table=cfg.rcode_table,
        byte_mutation_prob=cfg.byte_mutation_prob,
    )

    results: list[TestCaseResult] = []
    for i in range(cfg.n_test_cases):
        query, response = gen.generate_pair()
        pool = build_resolver_pool(cfg.base_domain)  # fresh resolvers each round
        for resolver in pool.values():
            resolver.process(query, response)
        opportunities = structural_bug_opportunities(response, cfg.base_domain)
        result = run_differential_test(i, pool, opportunities)
        results.append(result)
    return results


if __name__ == "__main__":
    cfg = FuzzRunConfig(n_test_cases=2000)
    results = run_fuzz_campaign(cfg)
    print(summarize(results))
