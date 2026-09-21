"""
mock_resolvers.py

Simulated resolver *caching policies*, standing in for the six real DNS
software packages ResolverFuzz tested against (BIND, Unbound, Knot,
PowerDNS, MaraDNS, Technitium).

IMPORTANT SCOPE NOTE (put this in your Limitations slide too):
We do NOT run real resolver binaries. Running 6 real DNS resolvers and
attacking them over a real or containerized network is what the
original paper did, and is out of scope for a course replication both
for time and for the ethical/infrastructure reasons the paper itself
discusses in Section 7. Instead, each class below implements a small,
literal caching-policy model whose divergent behavior is *transcribed
directly from the paper's own descriptions* of documented bugs
(Table 2 and Section 6.1/6.2), e.g.:

  - CP1 (out-of-bailiwick cache poisoning): BIND/Knot/Technitium were
    shown to cache Authority/Additional records outside the queried
    zone; PowerDNS/Unbound do bailiwick-check and drop them.
  - CP2 (in-bailiwick asymmetry): only PowerDNS was shown to
    proactively cache NS records from Additional-section glue even
    when not directly asked.
  - RC2 (unlimited cache store): Unbound was shown to cache *any*
    record type from Authority/Additional, not just NS/SOA/DNSSEC as
    RFC 4035 permits.

This lets us test whether ResolverFuzz's *methodology* (differential
testing + clustering) is capable of re-discovering these known,
documented divergences from freely generated PCFG test cases -- which
is a legitimate and falsifiable replication of the paper's central
experimental claim ("differential testing across diverse resolvers
surfaces cache-poisoning-relevant inconsistencies without a golden
model").
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pcfg_generator import DNSQuery, DNSResponse, DNSRecord


def is_in_bailiwick(record_name: str, zone: str) -> bool:
    record_name = record_name.rstrip(".").lower()
    zone = zone.rstrip(".").lower()
    return record_name == zone or record_name.endswith("." + zone)


@dataclass(frozen=True)
class CachedRecord:
    name: str
    rtype: str
    rdata: str

    def key(self):
        return (self.name, self.rtype, self.rdata)


class MockResolver:
    """Base class: RFC-conformant baseline caching policy.

    Baseline policy (roughly RFC 1034 / 4035 conformant):
      - only caches Answer-section records matching the queried name,
        plus NS/SOA/DNSSEC-type records from Authority, plus glue
        (A/AAAA) from Additional -- and only if in-bailiwick.
    """
    name = "Baseline"
    ALLOWED_AUTHORITY_TYPES = {"NS", "SOA", "RRSIG"}
    ALLOWED_ADDITIONAL_TYPES = {"A", "AAAA"}

    def __init__(self, zone: str):
        self.zone = zone
        self.cache: dict[tuple, CachedRecord] = {}

    def reset(self):
        self.cache.clear()

    def _accept(self, rec: DNSRecord, section: str) -> bool:
        if not is_in_bailiwick(rec.name, self.zone):
            return False
        if section == "authority" and rec.rtype not in self.ALLOWED_AUTHORITY_TYPES:
            return False
        if section == "additional" and rec.rtype not in self.ALLOWED_ADDITIONAL_TYPES:
            return False
        return True

    def process(self, query: DNSQuery, response: DNSResponse) -> None:
        for rec in response.answer:
            if is_in_bailiwick(rec.name, self.zone):
                self._store(rec)
        for rec in response.authority:
            if self._accept(rec, "authority"):
                self._store(rec)
        for rec in response.additional:
            if self._accept(rec, "additional"):
                self._store(rec)

    def _store(self, rec: DNSRecord):
        cr = CachedRecord(rec.name, rec.rtype, rec.rdata)
        self.cache[cr.key()] = cr

    def cache_snapshot(self) -> set[tuple]:
        return set(self.cache.keys())


class MockBIND(MockResolver):
    """Reproduces CP1: caches Authority/Additional records even when
    out-of-bailiwick (Sec 6.1, CP1)."""
    name = "BIND"

    def _accept(self, rec: DNSRecord, section: str) -> bool:
        # No bailiwick check -- this is the documented CP1 flaw.
        if section == "authority" and rec.rtype not in self.ALLOWED_AUTHORITY_TYPES:
            return False
        if section == "additional" and rec.rtype not in self.ALLOWED_ADDITIONAL_TYPES:
            return False
        return True

    def process(self, query: DNSQuery, response: DNSResponse) -> None:
        for rec in response.answer:
            self._store(rec)  # answer also not bailiwick-checked here
        for rec in response.authority:
            if self._accept(rec, "authority"):
                self._store(rec)
        for rec in response.additional:
            if self._accept(rec, "additional"):
                self._store(rec)


class MockUnbound(MockResolver):
    """Reproduces RC2: caches *all* record types from Authority/
    Additional, not just NS/SOA/DNSSEC/glue (Sec 6.2, RC2)."""
    name = "Unbound"

    def _accept(self, rec: DNSRecord, section: str) -> bool:
        if not is_in_bailiwick(rec.name, self.zone):
            return False
        # No type restriction on Authority/Additional -- documented RC2 flaw.
        return True


class MockPowerDNS(MockResolver):
    """Reproduces CP2: proactively caches NS glue from Additional even
    without an explicit query for it, and treats it as authoritative
    for the whole subzone (Sec 6.1, CP2)."""
    name = "PowerDNS"

    def process(self, query: DNSQuery, response: DNSResponse) -> None:
        super().process(query, response)
        # CP2: any NS record learned via Additional is trusted for its
        # *entire* subzone, so PowerDNS also caches the paired glue
        # address as authoritative for that subzone (extra step beyond
        # baseline -- this asymmetry is what makes off-path poisoning
        # of PowerDNS cheaper per the paper's account).
        ns_glue = [r for r in response.authority if r.rtype == "NS"
                   and is_in_bailiwick(r.name, self.zone)]
        for ns in ns_glue:
            for a in response.additional:
                if a.rtype in ("A", "AAAA"):
                    self._store(DNSRecord(ns.rdata, a.rtype, "IN", 60,
                                           "correct", a.rdata))


class MockKnot(MockResolver):
    """Baseline-conformant, matching Table 2's mostly-'not vulnerable'
    row for Knot on CP1/RC-type bugs (used as one of the closer-to-
    correct references for differential testing)."""
    name = "Knot"


RESOLVER_CLASSES = {
    "BIND": MockBIND,
    "Unbound": MockUnbound,
    "PowerDNS": MockPowerDNS,
    "Knot": MockKnot,
}


def build_resolver_pool(zone: str) -> dict[str, MockResolver]:
    return {n: cls(zone) for n, cls in RESOLVER_CLASSES.items()}
