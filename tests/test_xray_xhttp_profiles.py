"""Static invariants for the XHTTP client transport profiles.

These are pure, static tests: they read ONLY the module-level constants of
``services.xray`` (``_XHTTP_PROFILE_EXTRA`` / ``_XHTTP_SERVER_MAX_EACH_POST_BYTES``)
and assert the client-side profile tuning stays within the bounds the
hand-maintained server inbound will accept. They never touch the filesystem
outside the repo, the network, ``/sys``, ``/usr/local``, ``.env``, or the xray
binary — so they pass identically in a clean CI container and on the host.
"""

from services.xray import _XHTTP_PROFILE_EXTRA, _XHTTP_SERVER_MAX_EACH_POST_BYTES


def _upper_bound(value: str) -> int:
    """Parse an xhttp range/scalar string ("N" or "N-M") to its upper bound.

    Both the client profiles and the server inbound express byte/ms tuning as
    either a single integer string ("1000000") or a "min-max" range
    ("800000-1000000"); the upper bound is what matters for the server ceiling.
    """
    parts = str(value).split("-")
    return int(parts[-1])


def test_upper_bound_helper_parses_scalar_and_range() -> None:
    assert _upper_bound("1000000") == 1_000_000
    assert _upper_bound("800000-1000000") == 1_000_000


def test_no_profile_exceeds_server_post_ceiling() -> None:
    """Every profile's scMaxEachPostBytes upper bound stays <= the server ceiling.

    A client that advertises an upper bound above the server's
    xhttpSettings.extra.scMaxEachPostBytes would have its oversized POSTs
    rejected by the inbound. Profiles without the key impose no ceiling and are
    skipped.
    """
    for profile, extra in _XHTTP_PROFILE_EXTRA.items():
        if not extra or "scMaxEachPostBytes" not in extra:
            continue
        upper = _upper_bound(str(extra["scMaxEachPostBytes"]))
        assert upper <= _XHTTP_SERVER_MAX_EACH_POST_BYTES, (
            f"profile {profile!r} advertises scMaxEachPostBytes upper bound {upper} "
            f"above the server ceiling {_XHTTP_SERVER_MAX_EACH_POST_BYTES}; the "
            f"inbound would reject oversized POSTs — lower the client bound or bump "
            f"both sides together"
        )


def test_no_profile_carries_max_concurrency() -> None:
    """maxConcurrency is mutually exclusive with maxConnections — Xray won't start.

    Guards against a profile ever gaining ``maxConcurrency`` (anywhere in its
    extra block, including inside ``xmux``), which makes Xray-core refuse to boot.
    """
    for profile, extra in _XHTTP_PROFILE_EXTRA.items():
        if not extra:
            continue
        assert "maxConcurrency" not in extra, f"profile {profile!r} top-level extra"
        xmux = extra.get("xmux")
        if isinstance(xmux, dict):
            assert "maxConcurrency" not in xmux, f"profile {profile!r} xmux"


def test_multi_rotation_is_duration_dominated() -> None:
    """multi's hMaxReusableSecs lower bound must stay >= 120s.

    Rotation in the multi profile exists ONLY to keep a connection from
    outliving the long-lived-session shaping threshold, not to reshuffle every
    minute. An accidental revert to aggressive values ("30-60") would pay a fresh
    REALITY handshake (extra RTT, mobile micro-freezes) far too often and expose
    a short-lived-TLS-session fingerprint; this guard makes that revert fail in
    CI.
    """
    multi = _XHTTP_PROFILE_EXTRA["multi"]
    assert multi is not None
    xmux = multi["xmux"]
    assert isinstance(xmux, dict)
    lower = int(str(xmux["hMaxReusableSecs"]).split("-")[0])
    assert lower >= 120, (
        f"multi hMaxReusableSecs lower bound {lower}s < 120s: rotation would fire "
        f"too often, each rotation costing a fresh REALITY handshake and adding a "
        f"short-lived-TLS-session statistical fingerprint"
    )


def test_multi_ranges_stay_strings() -> None:
    """All multi range tunings must remain "N-M" strings, never bare ints.

    v2rayN/v2rayNG/Nekobox/Happ decode the percent-encoded JSON ``extra`` back
    into xhttpSettings; the range form is the anti-cadence intent and must not
    silently collapse to a scalar int.
    """
    multi = _XHTTP_PROFILE_EXTRA["multi"]
    assert multi is not None
    xmux = multi["xmux"]
    assert isinstance(xmux, dict)
    for source, value in (
        ("scMaxEachPostBytes", multi["scMaxEachPostBytes"]),
        ("scMinPostsIntervalMs", multi["scMinPostsIntervalMs"]),
        ("xmux.cMaxReuseTimes", xmux["cMaxReuseTimes"]),
        ("xmux.hMaxReusableSecs", xmux["hMaxReusableSecs"]),
    ):
        assert isinstance(value, str), f"multi {source} must be a string, got {type(value).__name__}"
        assert "-" in value, f"multi {source} {value!r} must be a 'N-M' range"
