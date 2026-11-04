"""Protocol-dependent user texts: per-protocol fragments, one composer.

The rule this module enforces: a user is never told about a protocol that is
switched off — no description of it, no comparison with it, no «it is not
included» notice, no advice to pick it — and what is left still reads as one
whole text, with no holes and no dangling references.

How it is built:

* no catalogue string lists several protocols at once. Every paragraph (often
  every sentence) is its own i18n key tied to one protocol;
* a sentence that mentions ANOTHER protocol (a comparison, «not part of the
  subscription», «switch to ...») comes in variants, one per presence/absence of
  that protocol, and the variant is picked here from the availability snapshot;
* the texts are declared as data — :class:`Block` of :class:`Part` — and glued by
  :func:`compose`, the single composer. Handlers call the screen-level functions
  at the bottom of this module and never concatenate fragments themselves.

Admin screens are out of scope on purpose: an admin has to see a switched-off
protocol to switch it back on.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass

from bot.availability import Availability
from bot.keyboards.common import FAQ_TOPICS
from i18n import t
from models.enums import KeyBundleKind
from services.key_bundles import member_name, member_protocol
from services.protocol_availability import Protocol

X = Protocol.XRAY
XH = Protocol.XHTTP
A = Protocol.AWG
H = Protocol.HYSTERIA2
S = Protocol.SOCKS5
M = Protocol.MTPROTO

Condition = Callable[[Availability], bool]
Params = Callable[[Availability], Mapping[str, object]]


def _always(_: Availability) -> bool:
    return True


@dataclass(frozen=True, slots=True)
class Part:
    """One i18n fragment, rendered only when *when* holds for the snapshot."""

    key: str
    when: Condition = _always
    params: Params | None = None


@dataclass(frozen=True, slots=True)
class Block:
    """A paragraph: the parts that apply, joined by *sep* (a sentence gap by default)."""

    parts: tuple[Part, ...]
    sep: str = " "


Spec = tuple[Block, ...]


def compose(spec: Spec, available: Availability) -> str:
    """THE composer: render *spec* against *available* into one text.

    Parts whose condition fails are dropped, a paragraph left with no parts is
    dropped as a whole, and the survivors are joined by a blank line — so a
    switched-off protocol leaves neither a stray separator nor an empty paragraph
    behind.
    """
    paragraphs: list[str] = []
    for block in spec:
        pieces: list[str] = []
        for part in block.parts:
            if not part.when(available):
                continue
            params = part.params(available) if part.params is not None else {}
            piece = t(part.key, **params).strip()
            if piece:
                pieces.append(piece)
        if pieces:
            paragraphs.append(block.sep.join(pieces))
    return "\n\n".join(paragraphs)


# ── helpers ───────────────────────────────────────────────────────────────────


def _join(items: Sequence[str], conjunction_key: str) -> str:
    """«A», «A и B», «A, B и C» — the conjunction comes from the catalogue."""
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} {t(conjunction_key)} {items[-1]}"


def join_and(items: Sequence[str]) -> str:
    return _join(items, "list_and")


def join_or(items: Sequence[str]) -> str:
    return _join(items, "list_or")


def _named(available: Availability, names: Sequence[tuple[Protocol, str]]) -> list[str]:
    """The names of the available protocols, in the order *names* lists them."""
    return [name for protocol, name in names if protocol in available]


def _several(available: Availability) -> bool:
    """More than one VPN protocol — i.e. there is something to compare with."""
    return len(available.vpn) > 1


def _start(available: Availability) -> Protocol | None:
    """The protocol to start with: the first available of Xray > Hysteria2 > AWG."""
    return available.vpn[0] if available.vpn else None


def _has_vpn(available: Availability) -> bool:
    return bool(available.vpn)


def _has_links(available: Availability) -> bool:
    """A protocol whose key is delivered as a link (Xray / Hysteria2) is on."""
    return X in available or H in available


# ── FAQ: «Как подключиться?» ──────────────────────────────────────────────────


def _connect_apps(available: Availability) -> Mapping[str, object]:
    apps: list[str] = []
    if A in available:
        apps.append(t("faq_connect_apps_awg"))
    links = _named(available, ((X, "Xray"), (H, "Hysteria2")))
    if links:
        apps.append(t("faq_connect_apps_links", protocols=join_and(links)))
    return {"apps": "; ".join(apps)}


def _connect_tip_examples(available: Availability) -> Mapping[str, object]:
    examples = _named(available, ((A, "AWG"),))
    if XH in available:
        examples.append("Xray TCP/XHTTP")
    elif X in available:
        examples.append("Xray")
    examples.extend(_named(available, ((H, "Hysteria2"),)))
    return {"examples": join_and(examples)}


def _bundle_xray_hy2(available: Availability) -> bool:
    return {X, H} <= available.bundle_protocols


def _bundle_xray_transports(available: Availability) -> bool:
    return available.bundle_protocols == {X, XH}


_FAQ_CONNECT: Spec = (
    Block(
        (
            Part("faq_connect_intro_file", lambda a: A in a),
            Part("faq_connect_intro", lambda a: A not in a),
            Part("faq_connect_delivery_xray_hy2_awg", lambda a: X in a and H in a and A in a),
            Part("faq_connect_delivery_xray_awg", lambda a: X in a and H not in a and A in a),
            Part("faq_connect_delivery_hy2_awg", lambda a: X not in a and H in a and A in a),
            Part("faq_connect_delivery_awg", lambda a: A in a and not _has_links(a)),
            Part("faq_connect_delivery_link", lambda a: A not in a and _has_links(a)),
            Part("faq_connect_enable"),
        )
    ),
    Block((Part("faq_connect_apps", _has_vpn, _connect_apps),)),
    Block(
        (
            # The tip needs something to switch between: two protocols, or two
            # Xray transports.
            Part(
                "faq_connect_tip_protocols_transports",
                lambda a: _several(a) and XH in a,
                _connect_tip_examples,
            ),
            Part("faq_connect_tip_protocols", lambda a: _several(a) and XH not in a, _connect_tip_examples),
            Part("faq_connect_tip_transports", lambda a: not _several(a) and XH in a, _connect_tip_examples),
            # «All-in-One makes that easiest» — only while it is offered and would
            # carry more than one thing to switch between. Both variants imply the
            # tip above is present.
            Part("faq_connect_bundle_xray_hy2", _bundle_xray_hy2),
            Part("faq_connect_bundle_xray_transports", _bundle_xray_transports),
            Part(
                "faq_connect_bundle_no_awg",
                lambda a: A in a and (_bundle_xray_hy2(a) or _bundle_xray_transports(a)),
            ),
        )
    ),
)


# ── FAQ: «Какой протокол выбрать?» ────────────────────────────────────────────

_FAQ_CHOICE: Spec = (
    Block(
        (
            # «лучше всех» only when there is someone to be better than; the
            # transport is part of «the right config» only while XHTTP is offered.
            Part("faq_choice_xray_best_transport", lambda a: X in a and XH in a and _several(a)),
            Part("faq_choice_xray_best", lambda a: X in a and XH not in a and _several(a)),
            Part("faq_choice_xray_solo_transport", lambda a: X in a and XH in a and not _several(a)),
            Part("faq_choice_xray_solo", lambda a: X in a and XH not in a and not _several(a)),
        )
    ),
    Block((Part("faq_choice_awg", lambda a: A in a),)),
    Block(
        (
            Part("faq_choice_hy2_vs_awg", lambda a: H in a and A in a),
            Part("faq_choice_hy2", lambda a: H in a and A not in a),
            Part("faq_choice_hy2_vs_xray", lambda a: H in a and X in a),
        )
    ),
    # «Что выбрать»: absent with 0 or 1 protocols; otherwise the start protocol, then
    # a pointer to each other available one, in this fixed order.
    Block(
        (
            Part("faq_choice_start_xray", lambda a: _several(a) and _start(a) is X),
            Part("faq_choice_start_hy2", lambda a: _several(a) and _start(a) is H),
            Part("faq_choice_pick_awg", lambda a: _several(a) and A in a and _start(a) is not A),
            Part("faq_choice_pick_hy2", lambda a: _several(a) and H in a and _start(a) is not H),
        )
    ),
)


# ── FAQ: «Почему не работает?» ────────────────────────────────────────────────

_FAQ_TROUBLE: Spec = (
    Block((Part("faq_trouble_general"),)),
    Block((Part("faq_trouble_awg", lambda a: A in a),)),
    Block(
        (
            Part("faq_trouble_xray_transport", lambda a: X in a and XH in a),
            Part("faq_trouble_xray", lambda a: X in a and XH not in a),
            Part("faq_trouble_xray_fingerprint", lambda a: X in a),
        )
    ),
    Block(
        (
            Part("faq_trouble_hy2", lambda a: H in a),
            Part("faq_trouble_hy2_udp_switch_xray_awg", lambda a: H in a and X in a and A in a),
            Part("faq_trouble_hy2_udp_switch_xray", lambda a: H in a and X in a and A not in a),
            Part("faq_trouble_hy2_udp_switch_awg", lambda a: H in a and X not in a and A in a),
            Part("faq_trouble_hy2_udp", lambda a: H in a and X not in a and A not in a),
            # MTU is an AWG setting and the fingerprint an Xray one: each is
            # named only while the protocol that has it is on.
            Part("faq_trouble_hy2_no_mtu_fp", lambda a: H in a and A in a and X in a),
            Part("faq_trouble_hy2_no_fp", lambda a: H in a and X in a and A not in a),
            Part("faq_trouble_hy2_no_mtu", lambda a: H in a and A in a and X not in a),
        )
    ),
    Block((Part("faq_trouble_support"),)),
)


# ── FAQ: fingerprint / proxy / security / support ─────────────────────────────

_FAQ_FINGERPRINT: Spec = (
    Block((Part("faq_fingerprint_intro"),)),
    Block((Part("faq_fingerprint_options"),)),
    Block(
        (
            Part("faq_fingerprint_scope_awg", lambda a: A in a),
            Part("faq_fingerprint_scope", lambda a: A not in a),
        )
    ),
)

_FAQ_PROXY: Spec = (
    Block(
        (
            Part("faq_proxy_intro_both", lambda a: S in a and M in a),
            Part("faq_proxy_intro_one", lambda a: (S in a) != (M in a)),
            Part("faq_proxy_socks5", lambda a: S in a),
            Part("faq_proxy_mtproto", lambda a: M in a),
        ),
        sep="\n",
    ),
    Block((Part("faq_proxy_independent"),)),
)


def _security_protocols(available: Availability) -> Mapping[str, object]:
    names = _named(available, ((A, "AmneziaWG"), (X, "VLESS+REALITY"), (H, "Hysteria2")))
    return {"protocols": " / ".join(names)}


_FAQ_SECURITY: Spec = (
    Block((Part("faq_security_logs"),)),
    Block(
        (
            Part("faq_security_encryption_many", _several, _security_protocols),
            Part("faq_security_encryption_one", lambda a: len(a.vpn) == 1, _security_protocols),
        )
    ),
    Block((Part("faq_security_notes"),)),
    Block((Part("faq_security_contact"),)),
)


def _support_key_types(available: Availability) -> Mapping[str, object]:
    return {"protocols": join_or(_named(available, ((A, "AWG"), (X, "Xray"), (H, "Hysteria2"))))}


_FAQ_SUPPORT: Spec = (
    Block((Part("faq_support_contact"),)),
    Block(
        (
            Part("faq_support_include"),
            # With a single protocol the key type tells support nothing.
            Part("faq_support_key_type", _several, _support_key_types),
            Part("faq_support_key_number", lambda a: not _several(a)),
            Part("faq_support_device_tried"),
        ),
        sep="\n",
    ),
    Block((Part("faq_support_reply"),)),
)


def _static(topic: str) -> Spec:
    return (Block((Part(f"faq_{topic}"),)),)


_FAQ_SPECS: dict[str, Spec] = {
    "connect": _FAQ_CONNECT,
    "choice": _FAQ_CHOICE,
    "trouble": _FAQ_TROUBLE,
    "device": _static("device"),
    "key_statuses": _static("key_statuses"),
    "stats": _static("stats"),
    "expired": _static("expired"),
    "revoke_delete": _static("revoke_delete"),
    "note_why": _static("note_why"),
    "settings": _static("settings"),
    "proxy": _FAQ_PROXY,
    "fingerprint": _FAQ_FINGERPRINT,
    "mtu": _static("mtu"),
    "server_restart": _static("server_restart"),
    "security": _FAQ_SECURITY,
    "support": _FAQ_SUPPORT,
}

# A topic about one protocol disappears from the list with it. Topics not named
# here are always shown.
_FAQ_VISIBLE: dict[str, Condition] = {
    "connect": _has_vpn,
    "choice": _has_vpn,
    "fingerprint": lambda a: X in a,
    "mtu": lambda a: A in a,
    "proxy": lambda a: S in a or M in a,
}


def faq_topics(available: Availability) -> list[tuple[str, str]]:
    """The FAQ topics to list, as ``(topic, button key)``, in the usual order."""
    return [(topic, button) for topic, button in FAQ_TOPICS if _FAQ_VISIBLE.get(topic, _always)(available)]


def faq_answer(topic: str, available: Availability) -> str | None:
    """The answer to *topic*, or None when the topic is unknown or hidden now."""
    spec = _FAQ_SPECS.get(topic)
    if spec is None or not _FAQ_VISIBLE.get(topic, _always)(available):
        return None
    return compose(spec, available)


# ── All-in-One ────────────────────────────────────────────────────────────────

# Composition member → its fragment in a kind description. The three VLESS (HTTP)
# profiles collapse into one phrase.
_BUNDLE_PART_KEYS: dict[Protocol, str] = {
    X: "bundle_part_vless_tcp",
    H: "bundle_part_hysteria2",
    XH: "bundle_part_vless_http",
}


def bundle_kinds(available: Availability) -> tuple[KeyBundleKind, ...]:
    """The subscription kinds worth offering now.

    A kind whose available composition is empty is not offered, and «extended» is
    dropped while it would hold exactly what «basic» holds (XHTTP off): two
    buttons for one set of keys would only make the user wonder what the
    difference is.
    """
    basic = available.bundle_members(KeyBundleKind.BASIC)
    extended = available.bundle_members(KeyBundleKind.EXTENDED)
    kinds: list[KeyBundleKind] = []
    if basic:
        kinds.append(KeyBundleKind.BASIC)
    if extended and {member_name(m) for m in extended} != {member_name(m) for m in basic}:
        kinds.append(KeyBundleKind.EXTENDED)
    return tuple(kinds)


def _bundle_listing(kind: KeyBundleKind) -> Params:
    def params(available: Availability) -> Mapping[str, object]:
        protocols = list(dict.fromkeys(member_protocol(m) for m in available.bundle_members(kind)))
        parts: list[str] = []
        for protocol in protocols:
            # Hysteria2 is «the alternative» only next to the VLESS it backs up.
            if protocol is H and kind is KeyBundleKind.BASIC and X in protocols:
                parts.append(t("bundle_part_hysteria2_alt"))
            else:
                parts.append(t(_BUNDLE_PART_KEYS[protocol]))
        return {"members": join_and(parts)}

    return params


def _bundle_size(kind: KeyBundleKind, available: Availability) -> int:
    return len({member_protocol(m) for m in available.bundle_members(kind)})


_BUNDLE_KIND_DESC: dict[KeyBundleKind, Spec] = {
    KeyBundleKind.BASIC: (
        Block(
            (
                Part(
                    "bundle_kind_basic_desc_pair",
                    lambda a: _bundle_size(KeyBundleKind.BASIC, a) > 1,
                    _bundle_listing(KeyBundleKind.BASIC),
                ),
                Part(
                    "bundle_kind_basic_desc_single",
                    lambda a: _bundle_size(KeyBundleKind.BASIC, a) == 1,
                    _bundle_listing(KeyBundleKind.BASIC),
                ),
            )
        ),
    ),
    KeyBundleKind.EXTENDED: (
        Block(
            (
                Part(
                    "bundle_kind_extended_desc",
                    lambda a: _bundle_size(KeyBundleKind.EXTENDED, a) > 0,
                    _bundle_listing(KeyBundleKind.EXTENDED),
                ),
            )
        ),
    ),
}


def bundle_kind_description(kind: KeyBundleKind, available: Availability) -> str:
    """What a *kind* subscription would hold, built from the available composition."""
    return compose(_BUNDLE_KIND_DESC[kind], available)


_BUNDLE_AWG_NOTICE: Spec = (Block((Part("bundle_awg_separate", lambda a: A in a),)),)


def bundle_awg_notice(available: Availability) -> str | None:
    """«AmneziaWG is issued separately» — only while AmneziaWG is offered at all."""
    return compose(_BUNDLE_AWG_NOTICE, available) or None


# ── settings / proxy ──────────────────────────────────────────────────────────

_CABINET_PROTOCOLS: tuple[tuple[Protocol, str], ...] = ((X, "Xray"), (A, "AWG"), (H, "Hysteria2"))


def cabinet_active_keys_line(counts: Mapping[Protocol, int], available: Availability) -> str:
    """«Активные ключи: N (Xray: …, …)» with a breakdown entry per protocol.

    A protocol is listed while it is available — or while the user still holds an
    active key of it, which is theirs to see whatever the switch says.
    """
    breakdown = [
        f"{name}: {counts.get(protocol, 0)}"
        for protocol, name in _CABINET_PROTOCOLS
        if protocol in available or counts.get(protocol, 0)
    ]
    total = sum(counts.get(protocol, 0) for protocol, _ in _CABINET_PROTOCOLS)
    spec: Spec = (
        Block(
            (
                Part(
                    "cabinet_active_keys_by_protocol",
                    lambda _: bool(breakdown),
                    lambda _: {"total": total, "protocols": ", ".join(breakdown)},
                ),
                Part("cabinet_active_keys", lambda _: not breakdown, lambda _: {"total": total}),
            )
        ),
    )
    return compose(spec, available)


def proxy_traffic_note(available: Availability, held: Collection[Protocol] = ()) -> str:
    """The «no per-user proxy traffic» note, naming only proxies the user can see.

    *held* are the proxy types the screen lists for the user — named even when the
    type has since been switched off, because the access itself is on screen.
    """
    names = [
        name
        for protocol, name in ((S, "SOCKS5"), (M, "MTProto"))
        if protocol in available or protocol in held
    ]
    spec: Spec = (
        Block(
            (
                Part("proxy_traffic_unavailable", lambda _: bool(names), lambda _: {"proxies": "/".join(names)}),
                Part("proxy_traffic_unavailable_generic", lambda _: not names),
            )
        ),
    )
    return compose(spec, available)
