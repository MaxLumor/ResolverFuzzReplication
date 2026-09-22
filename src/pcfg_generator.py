
from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Weighted-choice helper
# ---------------------------------------------------------------------------

def weighted_choice(options: list[tuple[str, float]], rng: random.Random) -> str:
    """Pick one option according to its associated probability weight."""
    labels = [o[0] for o in options]
    weights = [o[1] for o in options]
    return rng.choices(labels, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Grammar tables (transcribed from Appendix B, Listings 1 & 2)
# ---------------------------------------------------------------------------

OPCODE_TABLE = [
    ("QUERY", 0.80), ("IQUERY", 0.04), ("STATUS", 0.04),
    ("NOTIFY", 0.04), ("UPDATE", 0.04), ("DSO", 0.04),
]

RCODE_TABLE = [
    ("NOERROR", 0.80), ("FORMERR", 0.01), ("SERVFAIL", 0.01),
    ("NXDOMAIN", 0.01), ("NOTIMP", 0.01), ("REFUSED", 0.01),
    ("YXDOMAIN", 0.01), ("YXRRSET", 0.01), ("NXRRSET", 0.01),
    ("NOTAUTH", 0.01), ("NOTZONE", 0.01), ("DSOTYPENI", 0.01),
    ("BADVERS", 0.01), ("BADKEY", 0.01), ("BADTIME", 0.01),
    ("BADMODE", 0.01), ("BADNAME", 0.01), ("BADALG", 0.01),
    ("BADTRUNC", 0.01), ("BADCOOKIE", 0.01),
]

QTYPE_OPTIONS = ["A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT",
                  "AAAA", "RRSIG", "SPF", "ANY"]

RTYPE_TABLE_TEMPLATE = [  # response record TYPE (Listing 2)
    ("QUERIED", 0.50),  # special: reuse the type that was queried
    ("A", 0.05), ("CNAME", 0.05), ("SOA", 0.05), ("PTR", 0.05),
    ("MX", 0.05), ("TXT", 0.05), ("AAAA", 0.05), ("RRSIG", 0.05),
    ("SPF", 0.05),
]

QNAME_TABLE = [
    ("base", 0.40),          # the base domain being tested
    ("sub", 0.40),           # first-level subdomain
    ("sub_2_9", 0.10),       # 2nd-9th level subdomain
    ("sub_10_max", 0.10),    # 10th+ level subdomain (up to 128 labels)
]

NAME_TABLE_TEMPLATE = [  # response record NAME (Listing 2)
    ("queried", 0.20), ("sub", 0.20), ("same_level", 0.20),
    ("parent", 0.20), ("unrelated", 0.20),
]

RRCOUNT_TABLE = [(str(i), 1 / 6) for i in range(6)]  # 0..5, uniform


def _rand_label(rng: random.Random, length: int = 6) -> str:
    return "".join(rng.choices(string.ascii_lowercase, k=length))


# ---------------------------------------------------------------------------
# Data classes for generated messages
# ---------------------------------------------------------------------------

@dataclass
class DNSQuery:
    txid: str
    opcode: str
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    ad: int
    cd: int
    rcode: str
    qname: str
    qtype: str
    qclass: str = "IN"


@dataclass
class DNSRecord:
    name: str
    rtype: str
    rclass: str
    ttl: int
    rdlength_mode: str  # "correct" | "over" | "under"
    rdata: str


@dataclass
class DNSResponse:
    txid: str
    opcode: str
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    ad: int
    cd: int
    rcode: str
    answer: list[DNSRecord] = field(default_factory=list)
    authority: list[DNSRecord] = field(default_factory=list)
    additional: list[DNSRecord] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class PCFGGenerator:
    
    def __init__(self, base_domain: str, seed: Optional[int] = None,
                 opcode_table=None, rcode_table=None,
                 byte_mutation_prob: float = 0.1):
        self.base_domain = base_domain
        self.rng = random.Random(seed)
        self.opcode_table = opcode_table or OPCODE_TABLE
        self.rcode_table = rcode_table or RCODE_TABLE
        self.byte_mutation_prob = byte_mutation_prob

    # -- helpers -----------------------------------------------------------

    def _bit(self) -> int:
        return self.rng.choice([0, 1])

    def _qname(self) -> str:
        kind = weighted_choice(QNAME_TABLE, self.rng)
        if kind == "base":
            name = self.base_domain
        elif kind == "sub":
            name = f"{_rand_label(self.rng)}.{self.base_domain}"
        elif kind == "sub_2_9":
            depth = self.rng.randint(2, 9)
            labels = [_rand_label(self.rng) for _ in range(depth)]
            name = ".".join(labels) + "." + self.base_domain
        else:  # sub_10_max
            depth = self.rng.randint(10, 30)  # 128 is paper's max; capped for practicality
            labels = [_rand_label(self.rng) for _ in range(depth)]
            name = ".".join(labels) + "." + self.base_domain
        return self._maybe_byte_mutate(name)

    def _record_name(self, qname: str, kind: str) -> str:
        if kind == "queried":
            name = qname
        elif kind == "sub":
            name = f"{_rand_label(self.rng)}.{qname}"
        elif kind == "same_level":
            parts = qname.split(".", 1)
            suffix = parts[1] if len(parts) > 1 else self.base_domain
            name = f"{_rand_label(self.rng)}.{suffix}"
        elif kind == "parent":
            parts = qname.split(".", 1)
            name = parts[1] if len(parts) > 1 else self.base_domain
        else:  # unrelated -- e.g. out-of-bailiwick (used by CP1-style resolvers)
            name = f"{_rand_label(self.rng)}.{_rand_label(self.rng)}.com"
        return self._maybe_byte_mutate(name)

    def _maybe_byte_mutate(self, s: str) -> str:
        
        if self.rng.random() >= self.byte_mutation_prob:
            return s
        special = [".", "\x00", "@", "/", "\\"]
        op = self.rng.choice(["insert", "delete", "replace"])
        chars = list(s)
        if not chars:
            return s
        idx = self.rng.randrange(len(chars))
        if op == "insert":
            chars.insert(idx, self.rng.choice(special))
        elif op == "delete":
            del chars[idx]
        else:
            chars[idx] = self.rng.choice(special)
        return "".join(chars)

    def _rdata(self, rtype: str) -> str:
        if rtype in ("A",):
            return ".".join(str(self.rng.randint(1, 254)) for _ in range(4))
        if rtype in ("AAAA",):
            return ":".join(f"{self.rng.randint(0, 0xffff):x}" for _ in range(8))
        if rtype in ("NS", "CNAME", "PTR"):
            return f"{_rand_label(self.rng)}.{self.base_domain}"
        if rtype == "SOA":
            return f"ns.{self.base_domain} admin.{self.base_domain} 1 3600 600 86400 60"
        if rtype == "MX":
            return f"10 mail.{self.base_domain}"
        if rtype == "TXT" or rtype == "SPF":
            return _rand_label(self.rng, 12)
        if rtype == "RRSIG":
            return f"A 8 2 60 20300101000000 20240101000000 12345 {self.base_domain} {_rand_label(self.rng, 16)}"
        return _rand_label(self.rng)

    def _record(self, qname: str, qtype: str) -> DNSRecord:
        name_kind = weighted_choice(NAME_TABLE_TEMPLATE, self.rng)
        name = self._record_name(qname, name_kind)

        rtype_choice = weighted_choice(RTYPE_TABLE_TEMPLATE, self.rng)
        rtype = qtype if rtype_choice == "QUERIED" else rtype_choice

        rdlength_mode = weighted_choice(
            [("correct", 0.90), ("over", 0.05), ("under", 0.05)], self.rng)

        return DNSRecord(
            name=name, rtype=rtype, rclass="IN", ttl=60,
            rdlength_mode=rdlength_mode, rdata=self._rdata(rtype),
        )

    def _record_list(self) -> list[DNSRecord]:
        n = int(weighted_choice(RRCOUNT_TABLE, self.rng))
        return n  # count only; actual records filled in by caller w/ qname/qtype

    # -- public API ----------------------------------------------------

    def generate_query(self) -> DNSQuery:
        qname = self._qname()
        qtype = self.rng.choice(QTYPE_OPTIONS)
        return DNSQuery(
            txid=f"{self.rng.getrandbits(16):04x}",
            opcode=weighted_choice(self.opcode_table, self.rng),
            aa=0, tc=self._bit(), rd=self._bit(), ra=self._bit(),
            z=self._bit(), ad=self._bit(), cd=self._bit(),
            rcode="NOERROR",
            qname=qname, qtype=qtype,
        )

    def generate_response(self, query: DNSQuery) -> DNSResponse:
        
        an_count = int(weighted_choice(RRCOUNT_TABLE, self.rng))
        ns_count = int(weighted_choice(RRCOUNT_TABLE, self.rng))
        ar_count = int(weighted_choice(RRCOUNT_TABLE, self.rng))

        answer = [self._record(query.qname, query.qtype) for _ in range(an_count)]
        authority = [self._record(query.qname, query.qtype) for _ in range(ns_count)]
        additional = [self._record(query.qname, query.qtype) for _ in range(ar_count)]

        return DNSResponse(
            txid=query.txid,
            opcode=query.opcode,
            aa=self._bit(), tc=self._bit(), rd=query.rd, ra=self._bit(),
            z=self._bit(), ad=self._bit(), cd=self._bit(),
            rcode=weighted_choice(self.rcode_table, self.rng),
            answer=answer, authority=authority, additional=additional,
        )

    def generate_pair(self) -> tuple[DNSQuery, DNSResponse]:
        q = self.generate_query()
        r = self.generate_response(q)
        return q, r
