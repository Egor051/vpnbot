from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from adapters import ip_asn

# iptoasn rows: range_start<TAB>range_end<TAB>asn<TAB>country<TAB>description.
# 91.79.3.0/24 is the LTE block from the false-positive report (AS8359, MTS);
# 109.252.72.0/21 covers the paired home-ISP address (AS25513, MGTS).
# The 192.0.2.0/24 row (TEST-NET-1) carries ASN 0 — iptoasn's "unrouted" marker.
_FIXTURE_ROWS = [
    ("91.79.3.0", "91.79.3.255", "8359", "RU", "MTS PJSC"),
    ("109.252.72.0", "109.252.79.255", "25513", "RU", "MGTS PJSC"),
    ("192.0.2.0", "192.0.2.255", "0", "None", "Not routed"),
]
_FIXTURE_TSV = "".join("\t".join(row) + "\n" for row in _FIXTURE_ROWS)

# The seven IPs from the report: one home-ISP address plus six rotating
# carrier addresses inside 91.79.3.0/24.
_REPORT_IPS = [
    "109.252.72.195",
    "91.79.3.141",
    "91.79.3.145",
    "91.79.3.151",
    "91.79.3.189",
    "91.79.3.222",
    "91.79.3.227",
]


@pytest.fixture
def asn_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    db = tmp_path / "ip2asn-v4.tsv"
    db.write_text(_FIXTURE_TSV, encoding="utf-8")
    monkeypatch.setenv("IP2ASN_DB_PATH", str(db))
    ip_asn.reset_cache()
    yield db
    ip_asn.reset_cache()


# --------------------------------------------------------------- ASN resolution


@pytest.mark.parametrize(
    "ip",
    ["91.79.3.141", "91.79.3.145", "91.79.3.151", "91.79.3.189", "91.79.3.222", "91.79.3.227"],
)
def test_carrier_ips_collapse_to_one_asn(asn_db: Path, ip: str) -> None:
    assert ip_asn.normalize_ip(ip) == "AS8359"


def test_home_isp_ip_resolves_to_its_asn(asn_db: Path) -> None:
    assert ip_asn.normalize_ip("109.252.72.195") == "AS25513"


def test_lookup_asn_returns_int_or_none(asn_db: Path) -> None:
    assert ip_asn.lookup_asn("91.79.3.141") == 8359
    assert ip_asn.lookup_asn("109.252.72.195") == 25513
    assert ip_asn.lookup_asn("203.0.113.7") is None  # not covered by the table


def test_seven_report_ips_collapse_to_two_networks(asn_db: Path) -> None:
    nets = {ip_asn.normalize_ip(ip) for ip in _REPORT_IPS}
    assert nets == {"AS8359", "AS25513"}
    assert len(nets) == 2  # < the default threshold of 3 -> no alert


# ------------------------------------------------------------------- fallbacks


def test_fallback_to_24_when_asn_unknown(asn_db: Path) -> None:
    # 203.0.113.7 is outside every fixture range -> collapse to its /24.
    assert ip_asn.normalize_ip("203.0.113.7") == "203.0.113.0/24"


def test_unrouted_asn_zero_falls_back_to_24(asn_db: Path) -> None:
    # The covering row has ASN 0 (unrouted), which is treated as "no ASN".
    assert ip_asn.lookup_asn("192.0.2.5") is None
    assert ip_asn.normalize_ip("192.0.2.5") == "192.0.2.0/24"


def test_missing_database_falls_back_to_24(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IP2ASN_DB_PATH", str(tmp_path / "does-not-exist.tsv"))
    ip_asn.reset_cache()
    try:
        assert ip_asn.lookup_asn("91.79.3.141") is None
        assert ip_asn.normalize_ip("91.79.3.141") == "91.79.3.0/24"
    finally:
        ip_asn.reset_cache()


# -------------------------------------------------------------- robust passthrough


@pytest.mark.parametrize("value", ["not-an-ip", "", "999.999.999.999", "1.2.3", "AS8359"])
def test_garbage_is_returned_unchanged(asn_db: Path, value: str) -> None:
    # Must never raise; unparseable input is passed through verbatim.
    assert ip_asn.normalize_ip(value) == value
    assert ip_asn.lookup_asn(value) is None


def test_ipv6_literal_is_returned_unchanged(asn_db: Path) -> None:
    # IPv4-only deployment: v6 literals leaking from logs are passed through.
    assert ip_asn.normalize_ip("2001:db8::1") == "2001:db8::1"
    assert ip_asn.lookup_asn("2001:db8::1") is None


# --------------------------------------------------------------- cache reloading


def test_cache_reloads_when_file_changes(asn_db: Path) -> None:
    assert ip_asn.normalize_ip("91.79.3.141") == "AS8359"
    # Rewrite the same path with a different ASN and a different size so the
    # (mtime, size) signature is guaranteed to change; the next lookup reloads.
    asn_db.write_text(
        "91.79.3.0\t91.79.3.255\t64500\tRU\tRENAMED-CARRIER\n",
        encoding="utf-8",
    )
    assert ip_asn.normalize_ip("91.79.3.141") == "AS64500"
