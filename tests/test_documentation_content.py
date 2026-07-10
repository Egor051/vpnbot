"""Documentation content guards (doc-lint).

These tests assert that key operational and security guidance stays present — and
free of dangerous recommendations — in the project docs and READMEs. They check
*wording*, not runtime behaviour: the behavioural guarantees they describe are
enforced by the service / adapter / privileged-helper tests. They are kept
separate from the deploy-manifest guards (test_deploy_manifests_and_security_docs)
so that a docs rewrite fails here as a docs signal, rather than masquerading as a
privilege-separation regression.
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_readme_and_security_docs_do_not_recommend_recursive_user_chown() -> None:
    text = (
        _read("README.md")
        + "\n"
        + _read("docs/deployment.md")
        + "\n"
        + _read("docs/security/privilege-separation-plan.md")
        + "\n"
        + _read("deploy/helpers/README.md")
    )

    forbidden = re.compile(
        r"chown -R\s+(?:\"\$USER\":\"\$USER\"|\$USER:\$USER|vpn-bot:vpn-bot)\s+/opt/vpn-service(?:\s|$)"
    )
    assert forbidden.search(text) is None


def test_docs_require_nonroot_helper_preflight_postflight() -> None:
    check_path = ROOT / "deploy" / "check-nonroot-helper-mode.py"
    assert check_path.exists()

    text = (
        _read("README.md")
        + "\n"
        + _read("docs/deployment.md")
        + "\n"
        + _read("docs/operations.md")
        + "\n"
        + _read("docs/security/privilege-separation-plan.md")
        + "\n"
        + _read("deploy/helpers/README.md")
    )

    # Presence check only: the preflight/postflight script must be referenced in the
    # docs. A fixed occurrence count (>= 3) was brittle against harmless doc edits.
    assert "deploy/check-nonroot-helper-mode.py" in text
    assert "mandatory preflight and postflight" in text.lower()


def test_helper_install_docs_pin_ownership_and_modes() -> None:
    text = _read("deploy/helpers/README.md") + "\n" + _read("deploy/sudoers.d/vpn-bot.example")

    assert "root:root" in text
    assert "0755" in text
    assert "0440" in text
    assert "not a generic root shell" in text


def test_privilege_plan_mentions_required_components() -> None:
    text = _read("docs/security/privilege-separation-plan.md").lower()

    for term in (
        "xray",
        "awg",
        "socks5",
        "mtproto",
        "sqlite",
        ".env",
        "systemd",
    ):
        assert term in text


def test_helper_contracts_require_socks5_prefix_password_stdin_and_secret_redaction() -> None:
    text = (
        _read("docs/security/privilege-separation-plan.md")
        + "\n"
        + _read("deploy/helpers/README.md")
    ).lower()

    assert "configured login prefix" in text
    assert "password read from stdin" in text or "password remains stdin-only" in text
    assert "never print passwords" in text
    assert "never prints raw mtproto secrets" in text or "never print raw mtproto secrets" in text
    assert "redact" in text
