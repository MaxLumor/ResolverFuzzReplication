

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

    name = "Unbound"

    def _accept(self, rec: DNSRecord, section: str) -> bool:
        if not is_in_bailiwick(rec.name, self.zone):
            return False
        # No type restriction on Authority/Additional -- documented RC2 flaw.
        return True


class MockPowerDNS(MockResolver):

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

    name = "Knot"


RESOLVER_CLASSES = {
    "BIND": MockBIND,
    "Unbound": MockUnbound,
    "PowerDNS": MockPowerDNS,
    "Knot": MockKnot,
}


def build_resolver_pool(zone: str) -> dict[str, MockResolver]:
    return {n: cls(zone) for n, cls in RESOLVER_CLASSES.items()}
