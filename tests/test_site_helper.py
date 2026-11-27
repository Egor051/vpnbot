"""scripts/vpn-bot-site on a fake host (tests/site_fakes.py): no network, no real nginx.

What is pinned: an archive with an evil entry (a path out of the tree, a link, a device, a
hidden or non-static file, too many / too big files, a decompression bomb) is refused and
leaves the site, .env and the host exactly as they were; a deploy swaps the docroot in one
step and keeps the replaced tree, a revert brings the kept one back; any failed step, a
failed verify or a failed commit puts everything back; the spiderX pool follows the pages
of the site (and an empty pool stays empty).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile
import warnings
import zipfile
from pathlib import Path
from typing import Any

import pytest
from site_fakes import DOCROOT, DOMAIN, HELPER, SITE_V1, SITE_V2, SiteHost, tar_gz_bytes, tree_digest, zip_bytes

pytestmark = [pytest.mark.timeout(180)]

INDEX = {"index.html": b"<html>ok</html>"}


@pytest.fixture
def host(tmp_path: Path) -> SiteHost:
    return SiteHost(tmp_path)


def snapshot(host: SiteHost) -> dict[str, Any]:
    """Everything a refused archive must leave as it was."""
    www = sorted(p.name for p in host.file("/var/www").iterdir())
    work = host.file("/var/lib/vpn-bot-site/work")
    return {"site": host.tree(), "env": host.env(), "www": www,
            "work": sorted(p.name for p in work.iterdir()) if work.is_dir() else [],
            "state": host.state()}


def plan_deploy(host: SiteHost, data: bytes, run_id: int = 1) -> tuple[int, dict[str, Any], str]:
    digest = host.upload(data)
    return host.helper("plan", "deploy", "--run", str(run_id), "--digest", digest)


# --------------------------------------------------------------------------- #
# status: where the site is, what is live
# --------------------------------------------------------------------------- #
def test_status_finds_the_hand_made_site_from_the_nginx_vhost(host: SiteHost) -> None:
    rc, status, _ = host.helper("status")
    assert rc == 0, status
    assert status["docroot"] == DOCROOT and status["domain"] == DOMAIN
    assert status["vhost"] == "/etc/nginx/conf.d/anycastedge.conf"
    cur = status["current"]
    assert cur["tree"] == tree_digest(SITE_V1) and cur["pages"] == 3 and cur["files"] == 5
    assert cur["source"] == "host" and cur["deployed_at"] is None
    assert status["pages"] == ["/", "/about.html", "/blog/"]
    assert status["spx"] == {"enabled": True, "pool": ["/", "/about.html", "/blog/"], "missing": [], "in_sync": True}
    assert status["hy2"]["layout"] == "proxy"
    assert status["revert_to"] is None and status["releases"] == []
    assert status["limits"]["archive"] == 20 << 20
    assert not any("curl" in c or "openssl" in c for c in host.calls()), "status only reads"


def test_the_bot_installed_self_steal_is_found_too(host: SiteHost) -> None:
    host.file("/etc/nginx/conf.d/anycastedge.conf").unlink()
    host.write("/etc/nginx/conf.d/selfsteal.conf", (Path(__file__).resolve().parents[1] / "deploy/nginx/selfsteal.conf")
               .read_text().replace("@DOMAIN@", DOMAIN).replace("@SITE_ROOT@", "/var/www/selfsteal"))
    host.put_tree("/var/www/selfsteal", INDEX)
    rc, status, _ = host.helper("status")
    assert rc == 0 and status["docroot"] == "/var/www/selfsteal" and status["domain"] == DOMAIN


@pytest.mark.parametrize(("vhost", "why"), [
    ("server { listen 127.0.0.1:9443 ssl; root /var/www/x; }", "no nginx vhost listens"),
    (f"server {{ listen 127.0.0.1:8443 ssl; server_name {DOMAIN}; root /etc/nginx; }}", "not a directory below /var/www/"),
    (f"server {{ listen 127.0.0.1:8443 ssl; server_name {DOMAIN}; root /var/www; }}", "not a directory below /var/www/"),
    (f"server {{ listen 127.0.0.1:8443 ssl; server_name {DOMAIN}; root /var/www/a/../../etc; }}", "not a directory below"),
    (f"server {{ listen 127.0.0.1:8443 ssl; server_name {DOMAIN}; root /var/www/$host; }}", "not a literal path"),
    (f"server {{ listen 127.0.0.1:8443 ssl; server_name {DOMAIN}; }}", "has no `root`"),
    (f"server {{ listen 127.0.0.1:8443 ssl; server_name {DOMAIN}; root /var/www/a; location / {{ root /var/www/b; }} }}",
     "more than one `root`"),
    (f"server {{ listen 127.0.0.1:8443 ssl proxy_protocol; server_name {DOMAIN}; root {DOCROOT}; }}",
     "expects the PROXY protocol"),
])
def test_a_site_the_helper_cannot_tell_or_must_not_touch_is_refused(host: SiteHost, vhost: str, why: str) -> None:
    host.write("/etc/nginx/conf.d/anycastedge.conf", vhost)
    rc, status, _ = host.helper("status")
    assert rc == 3 and any(why in p for p in status["problems"]), status
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    assert rc == 3 and any(why in b for b in plan["blocking"]), plan
    assert host.tree() == SITE_V1


def test_two_vhosts_on_the_self_steal_port_are_ambiguous(host: SiteHost) -> None:
    host.write("/etc/nginx/sites-enabled/other", f"server {{ listen 8443 ssl; server_name {DOMAIN}; root /var/www/other; }}")
    rc, status, _ = host.helper("status")
    assert rc == 3 and "2 nginx vhosts listen" in status["problems"][0]


def test_a_symlinked_docroot_is_refused(host: SiteHost) -> None:
    real = host.file("/var/www/real")
    host.file(DOCROOT).rename(real)
    host.file(DOCROOT).symlink_to(real)
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    assert rc == 3 and any("is a symlink" in b for b in plan["blocking"])


# --------------------------------------------------------------------------- #
# The archive: every evil entry refused before anything reaches the site
# --------------------------------------------------------------------------- #
def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = mode << 16
    return info


def _tar_member(name: str, kind: bytes, linkname: str = "") -> tuple[tarfile.TarInfo, bytes | None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    return info, None


def _zip_with(entries: list[tuple[zipfile.ZipInfo | str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries:
                zf.writestr(name, data)
    return buf.getvalue()


def _encrypted_zip() -> bytes:
    """zipfile never writes an encrypted member: the flag (bit 0 of the general purpose
    bits) is set by hand in the central directory entry of secret.html."""
    data = bytearray(_zip_with([("index.html", b"x"), ("secret.html", b"x")]))
    at = data.index(b"PK\x01\x02", data.index(b"PK\x01\x02") + 4)
    data[at + 8] |= 0x1
    return bytes(data)


ZEROS_15M = b"\0" * (15 << 20)
EVIL: dict[str, tuple[bytes, str]] = {
    "zip_absolute": (zip_bytes({**INDEX, "/etc/cron.d/x.txt": b"x"}), "an absolute path"),
    "zip_dotdot": (zip_bytes({**INDEX, "../../etc/x.txt": b"x"}), "`..`"),
    "zip_dotdot_inside": (zip_bytes({**INDEX, "css/../../x.css": b"x"}), "`..`"),
    "zip_backslash": (zip_bytes({**INDEX, "..\\..\\x.css": b"x"}), "backslash"),
    "zip_symlink": (_zip_with([("index.html", b"x"), (_zip_info("evil.html", stat.S_IFLNK | 0o777), b"/etc/shadow")]),
                    "a symlink"),
    "zip_fifo": (_zip_with([("index.html", b"x"), (_zip_info("p.html", stat.S_IFIFO | 0o644), b"")]),
                 "not a regular file"),
    "zip_hidden": (zip_bytes({**INDEX, ".htaccess": b"x"}), "not a plain name"),
    "zip_hidden_dir": (zip_bytes({**INDEX, ".git/config.txt": b"x"}), "not a plain name"),
    "zip_php": (zip_bytes({**INDEX, "shell.php": b"<?php"}), "not a static file"),
    "zip_shell": (zip_bytes({**INDEX, "run.sh": b"#!/bin/sh"}), "not a static file"),
    "zip_no_extension": (zip_bytes({**INDEX, "CNAME": b"x"}), "not a static file"),
    "zip_encrypted": (_encrypted_zip(), "encrypted"),
    "zip_duplicate": (_zip_with([("index.html", b"a"), ("index.html", b"b")]), "twice"),
    "zip_file_and_dir": (zip_bytes({**INDEX, "x.css": b"a", "x.css/y.css": b"b"}), "same name"),
    "zip_too_deep": (zip_bytes({**INDEX, "/".join(["d"] * 13) + "/x.css": b"x"}), "deeper than"),
    "zip_too_many": (zip_bytes({**INDEX, **{f"f{i}.txt": b"x" for i in range(1000)}}), "more than 1000 files"),
    "zip_no_index": (zip_bytes({"about.html": b"x"}), "no index.html"),
    "zip_index_two_folders_down": (zip_bytes({"a/b/index.html": b"x"}), "no index.html"),
    "tar_symlink": (tar_gz_bytes(INDEX, members=[_tar_member("x.html", tarfile.SYMTYPE, "/etc/shadow")]), "a symlink"),
    "tar_hardlink": (tar_gz_bytes(INDEX, members=[_tar_member("x.html", tarfile.LNKTYPE, "/etc/shadow")]), "a hard link"),
    "tar_fifo": (tar_gz_bytes(INDEX, members=[_tar_member("x.html", tarfile.FIFOTYPE)]), "not a regular file"),
    "tar_char_device": (tar_gz_bytes(INDEX, members=[_tar_member("x.html", tarfile.CHRTYPE)]), "not a regular file"),
    "tar_absolute": (tar_gz_bytes({**INDEX, "/etc/passwd.txt": b"x"}), "an absolute path"),
    "tar_dotdot": (tar_gz_bytes({**INDEX, "../x.html": b"x"}), "`..`"),
    "tar_file_too_big": (tar_gz_bytes({**INDEX, "big.txt": b"\0" * ((16 << 20) + 1)}), "per file"),
    "tar_bomb_total": (tar_gz_bytes({**INDEX, **{f"z{i}.txt": ZEROS_15M for i in range(5)}}), "bytes unpacked"),
    "zip_bomb_total": (zip_bytes({**INDEX, **{f"z{i}.txt": ZEROS_15M for i in range(5)}}), "bytes unpacked"),
    "not_an_archive": (b"just some text, not an archive", "neither a zip nor a tar.gz"),
    "plain_tar": (b"x" * 600, "neither a zip nor a tar.gz"),
    "broken_gzip": (b"\x1f\x8b" + b"\0" * 100, "not a readable tar.gz"),
    "broken_zip": (b"PK\x03\x04" + b"\0" * 100, "not a readable zip"),
}


@pytest.mark.parametrize("case", sorted(EVIL))
def test_an_evil_archive_is_refused_and_changes_nothing(host: SiteHost, case: str) -> None:
    data, why = EVIL[case]
    before = snapshot(host)
    rc, result, text = plan_deploy(host, data)
    assert rc == 3, text
    assert result["error"] == "refused" and why in result["detail"], result
    assert snapshot(host) == before, "the site, .env and the host are untouched"
    assert not host.file("/var/lib/vpn-bot-site/work/1").exists(), "the unpacked archive is gone"
    assert not any(c.startswith(("curl", "openssl")) for c in host.calls()), "a refused archive reaches nothing"


def test_the_upload_must_be_the_announced_archive(host: SiteHost) -> None:
    host.upload(zip_bytes(SITE_V2))
    rc, result, _ = host.helper("plan", "deploy", "--run", "1", "--digest", "0" * 16)
    assert rc == 3 and "sha256 differs" in result["detail"]
    assert host.tree() == SITE_V1


def test_a_symlinked_upload_is_not_followed(host: SiteHost) -> None:
    secret = host.file("/root/secret.zip")
    secret.parent.mkdir(parents=True)
    secret.write_bytes(zip_bytes(SITE_V2))
    host.file("/run/vpn-bot/site/upload.bin").symlink_to(secret)
    d = hashlib.sha256(secret.read_bytes()).hexdigest()[:16]
    rc, result, _ = host.helper("plan", "deploy", "--run", "1", "--digest", d)
    assert rc == 3 and "upload.bin" in result["detail"]
    assert host.tree() == SITE_V1 and secret.exists()


def test_a_symlinked_upload_directory_is_not_followed(host: SiteHost) -> None:
    elsewhere = host.file("/root/elsewhere")
    elsewhere.mkdir(parents=True)
    (elsewhere / "upload.bin").write_bytes(zip_bytes(SITE_V2))
    host.file("/run/vpn-bot/site").rmdir()
    host.file("/run/vpn-bot/site").symlink_to(elsewhere)
    d = hashlib.sha256((elsewhere / "upload.bin").read_bytes()).hexdigest()[:16]
    rc, result, _ = host.helper("plan", "deploy", "--run", "1", "--digest", d)
    assert rc == 3 and "/run/vpn-bot/site" in result["detail"]
    assert (elsewhere / "upload.bin").exists() and host.tree() == SITE_V1


def test_an_oversized_upload_is_refused_before_it_is_read(host: SiteHost) -> None:
    upload = host.file("/run/vpn-bot/site/upload.bin")
    with open(upload, "wb") as fh:
        fh.truncate((20 << 20) + 1)
    rc, result, _ = host.helper("plan", "deploy", "--run", "1", "--digest", "0" * 16)
    assert rc == 3 and "bytes (1..20971520)" in result["detail"]


def test_one_folder_is_unwrapped_and_mac_junk_skipped(host: SiteHost) -> None:
    files = {f"site/{k}": v for k, v in SITE_V2.items()}
    files.update({"__MACOSX/site/._index.html": b"junk", "site/.DS_Store": b"junk"})
    rc, plan, text = plan_deploy(host, zip_bytes(files))
    assert rc == 0, text
    assert plan["new"]["unwrapped"] == "site/" and plan["new"]["skipped"] == 2
    assert plan["new"]["tree"] == tree_digest(SITE_V2)


def test_a_tar_gz_made_with_dot_entries_deploys(host: SiteHost) -> None:
    members = [(tarfile.TarInfo("./"), None)]
    members[0][0].type = tarfile.DIRTYPE
    data = tar_gz_bytes({f"./{k}": v for k, v in SITE_V2.items()}, members=members)
    rc, result = host.deploy(data)
    assert rc == 0, result
    assert host.tree() == SITE_V2


# --------------------------------------------------------------------------- #
# Deploy, keep, revert
# --------------------------------------------------------------------------- #
def test_a_deploy_swaps_the_site_keeps_the_old_one_and_follows_with_the_pool(host: SiteHost) -> None:
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    assert rc == 0 and not plan["blocking"]
    assert plan["diff"]["n_added"] == 4 and plan["diff"]["n_removed"] == 3 and plan["diff"]["n_changed"] == 2
    assert plan["pages"]["removed"] == ["/about.html", "/blog/"]
    spx = plan["spx"]
    assert spx["changed"] and spx["after"] == ["/", "/docs/", "/docs/api.html", "/status.html"]
    assert spx["removed"] == ["/about.html", "/blog/"]
    assert (spx["keys_moved"], spx["keys_with_spx"]) == (2, 3), "u-2 and u-3 point at pages the new site has not"
    assert host.tree() == SITE_V1, "the plan changes nothing"
    assert not host.file("/run/vpn-bot/site/upload.bin").exists(), "the plan took the upload"

    rc, result, text = host.helper("apply", "--run", "1", "--expect-plan", plan["sha256"])
    assert rc == 0 and result["atomic"] is True and result["env_changed"] is True, text
    assert host.tree() == SITE_V2
    assert host.pool() == ["/", "/docs/", "/docs/api.html", "/status.html"]
    env = host.env()
    assert env.startswith("BOT_TOKEN=1\nHYSTERIA2_SNI=") and env.endswith("OTHER=x\n"), "every other line as it was"
    assert stat.S_IMODE(host.file("/opt/vpn-service/.env").stat().st_mode) == 0o640, "the mode is kept"
    rc, result, _ = host.helper("verify", "--run", "1")
    assert rc == 0 and result["ok"], result
    assert {c["key"] for c in result["checks"]} >= {"tree", "tls", "page:/", "page:/docs/", "page:/docs/api.html", "spx_pool"}
    rc, result, _ = host.helper("commit", "--run", "1")
    assert rc == 0 and result["pool_changed"]

    state = host.state()
    assert state["current"]["tree"] == tree_digest(SITE_V2) and state["current"]["run"] == 1
    (kept,) = state["releases"]
    assert kept["kind"] == "previous" and kept["tree"] == tree_digest(SITE_V1) and kept["source"] == "host"
    assert host.tree(f"/var/lib/vpn-bot-site/releases/{kept['id']}") == SITE_V1
    assert sorted(p.name for p in host.file("/var/www").iterdir()) == ["anycastedge"], "no stage left behind"
    assert not host.file("/var/lib/vpn-bot-site/work/1").exists()
    for path in host.file(DOCROOT).rglob("*"):
        assert stat.S_IMODE(path.stat().st_mode) == (0o755 if path.is_dir() else 0o644), path
    assert not any("nginx" in c and ("reload" in c or "restart" in c) for c in host.calls()), "nginx is never reloaded"

    rc, status, _ = host.helper("status")
    assert status["current"]["source"] == "upload" and status["revert_to"] == kept["id"]
    assert status["spx"]["in_sync"] is True


def test_revert_brings_the_kept_version_back_and_keeps_the_reverted_one(host: SiteHost) -> None:
    assert host.deploy(zip_bytes(SITE_V2), 1)[0] == 0
    rc, result = host.revert(2)
    assert rc == 0, result
    assert host.tree() == SITE_V1 and host.pool() == ["/", "/about.html", "/blog/"]
    state = host.state()
    assert state["current"]["source"] == "revert" and state["current"]["tree"] == tree_digest(SITE_V1)
    (kept,) = state["releases"]
    assert kept["kind"] == "rolled_back" and kept["tree"] == tree_digest(SITE_V2)
    rc, plan, _ = host.helper("plan", "revert", "--run", "3")
    assert rc == 3 and any("no kept version" in b for b in plan["blocking"]), "a reverted version is no revert target"


def test_revert_restores_symlinks_and_modes_of_a_hand_made_site(host: SiteHost) -> None:
    os.symlink("about.html", host.file(f"{DOCROOT}/old-about.html"))
    host.file(f"{DOCROOT}/about.html").chmod(0o600)
    assert host.deploy(zip_bytes(SITE_V2), 1)[0] == 0
    assert host.revert(2)[0] == 0
    assert os.readlink(host.file(f"{DOCROOT}/old-about.html")) == "about.html"
    assert stat.S_IMODE(host.file(f"{DOCROOT}/about.html").stat().st_mode) == 0o600


def test_the_last_five_versions_are_kept(host: SiteHost) -> None:
    for n in range(1, 8):
        site = {"index.html": f"<html>v{n}</html>".encode(), "css/a.css": b"x"}
        assert host.deploy(zip_bytes(site), n)[0] == 0, n
    releases = host.state()["releases"]
    assert len(releases) == 5
    dirs = sorted(p.name for p in host.file("/var/lib/vpn-bot-site/releases").iterdir())
    assert dirs == sorted(r["id"] for r in releases)


def test_the_same_archive_again_is_nothing_to_do(host: SiteHost) -> None:
    assert host.deploy(zip_bytes(SITE_V2), 1)[0] == 0
    rc, plan, _ = plan_deploy(host, tar_gz_bytes(SITE_V2), 2)
    assert rc == 0 and plan["nothing_to_do"] is True
    assert not host.file("/var/lib/vpn-bot-site/work/2").exists()


def test_without_rename_exchange_two_renames_do_it(host: SiteHost) -> None:
    rc, result = host.deploy(zip_bytes(SITE_V2), 1, VPN_BOT_SITE_SELFTEST_NO_EXCHANGE="1")
    assert rc == 0, result
    assert host.tree() == SITE_V2 and len(host.state()["releases"]) == 1
    assert sorted(p.name for p in host.file("/var/www").iterdir()) == ["anycastedge"]


# --------------------------------------------------------------------------- #
# Failures put everything back
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("step", ["site_stage", "site_swap", "site_env"])
@pytest.mark.parametrize("exchange", [True, False])
def test_a_failed_step_is_rolled_back(host: SiteHost, step: str, exchange: bool) -> None:
    before = snapshot(host)
    extra = {"VPN_BOT_SITE_SELFTEST_FAIL": step}
    if not exchange:
        extra["VPN_BOT_SITE_SELFTEST_NO_EXCHANGE"] = "1"
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    rc, result, text = host.helper("apply", "--run", "1", "--expect-plan", plan["sha256"], **extra)
    assert rc == 6, text
    assert result["error"] == "step_failed" and result["failed_step"] == step and result["rollback_errors"] == []
    assert snapshot(host) == before
    assert host.journal()["state"] == "rolled_back"


@pytest.mark.parametrize("exchange", [True, False])
def test_a_failed_verify_is_rolled_back(host: SiteHost, exchange: bool) -> None:
    before = snapshot(host)
    (host.st / "fail_curl_path").write_text("/docs/api.html")
    extra = {} if exchange else {"VPN_BOT_SITE_SELFTEST_NO_EXCHANGE": "1"}
    rc, result = host.deploy(zip_bytes(SITE_V2), 1, **extra)
    assert rc == 4
    assert [c["key"] for c in result["checks"] if not c["ok"]] == ["page:/docs/api.html"]
    assert snapshot(host) == before, "the site and .env are back as the plan found them"


def test_a_failed_commit_is_rolled_back(host: SiteHost) -> None:
    before = snapshot(host)
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    assert host.helper("apply", "--run", "1", "--expect-plan", plan["sha256"])[0] == 0
    rc, _, _ = host.helper("commit", "--run", "1", VPN_BOT_SITE_SELFTEST_FAIL="commit")
    assert rc != 0
    assert host.helper("rollback", "--run", "1")[0] == 0
    after = snapshot(host)
    assert after == before
    assert not host.file("/var/lib/vpn-bot-site/releases").exists() or not any(host.file("/var/lib/vpn-bot-site/releases").iterdir())


def test_a_site_that_changed_since_the_plan_is_not_touched(host: SiteHost) -> None:
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    host.file(f"{DOCROOT}/about.html").write_bytes(b"edited by the freshen hook")
    rc, result, _ = host.helper("apply", "--run", "1", "--expect-plan", plan["sha256"])
    assert rc == 3 and result["error"] == "plan_changed"
    assert host.tree()["about.html"] == b"edited by the freshen hook" and "docs/api.html" not in host.tree()


def test_a_broken_self_steal_blocks_the_plan(host: SiteHost) -> None:
    host.fail("openssl")
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    assert rc == 3 and any("fix the certificate first" in b for b in plan["blocking"])
    assert not host.file("/var/lib/vpn-bot-site/work/1").exists()


def test_recover_rolls_back_an_apply_whose_unit_was_killed(host: SiteHost) -> None:
    before = snapshot(host)
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    assert host.helper("apply", "--run", "1", "--expect-plan", plan["sha256"])[0] == 0
    assert host.tree() == SITE_V2 and host.journal()["state"] == "applied"
    rc, blocked, _ = plan_deploy(host, zip_bytes(SITE_V1), 2)
    assert rc == 3 and any("unfinished change" in b for b in blocked["blocking"])
    rc, result, _ = host.helper("recover")
    assert rc == 0 and result["ok"] and result["run"] == 1
    assert snapshot(host) == before
    assert host.helper("recover")[1]["nothing_to_do"] is True


def test_rollback_after_commit_changes_nothing(host: SiteHost) -> None:
    assert host.deploy(zip_bytes(SITE_V2), 1)[0] == 0
    rc, result, _ = host.helper("rollback", "--run", "1")
    assert rc == 0 and result["nothing_to_do"] is True
    assert host.tree() == SITE_V2


# --------------------------------------------------------------------------- #
# The spiderX pool
# --------------------------------------------------------------------------- #
def test_an_empty_pool_stays_empty(tmp_path: Path) -> None:
    host = SiteHost(tmp_path, pool="")
    env = host.env()
    rc, result = host.deploy(zip_bytes(SITE_V2))
    assert rc == 0, result
    assert host.env() == env and result["pool_changed"] is False


def test_a_pool_of_the_same_pages_is_not_rewritten(host: SiteHost) -> None:
    env = host.env()
    site = {**SITE_V1, "css/style.css": b"body{margin:1px}"}
    rc, result = host.deploy(zip_bytes(site))
    assert rc == 0 and result["pool_changed"] is False
    assert host.env() == env


def test_the_pool_is_capped_and_holds_only_linkable_paths(host: SiteHost) -> None:
    site = {**INDEX, **{f"p{i:03d}.html": b"x" for i in range(100)}}
    rc, plan, _ = plan_deploy(host, zip_bytes(site))
    assert rc == 0
    after = plan["spx"]["after"]
    assert len(after) == 64 and after[0] == "/" and all(p.startswith("/") and "," not in p for p in after)


def test_a_missing_database_still_plans(host: SiteHost) -> None:
    host.file("/opt/vpn-service/data/vpn.db").unlink()
    rc, plan, _ = plan_deploy(host, zip_bytes(SITE_V2))
    assert rc == 0 and plan["spx"]["keys_moved"] is None


# --------------------------------------------------------------------------- #
# The seam
# --------------------------------------------------------------------------- #
def test_the_selftest_needs_its_root(host: SiteHost) -> None:
    import subprocess
    import sys

    env = host.base_env(VPN_BOT_SITE_ROOT="/")
    proc = subprocess.run([sys.executable, "-I", str(HELPER), "status", "--json"], capture_output=True, text=True,
                          env=env, timeout=60, check=False)
    assert proc.returncode == 3 and "VPN_BOT_SITE_ROOT" in proc.stdout + proc.stderr


def test_usage_errors_exit_2(host: SiteHost) -> None:
    rc, _, _ = host.helper("plan", "deploy")
    assert rc == 2
    rc, _, _ = host.helper("apply", "--run", "1", "--expect-plan", "nothex")
    assert rc == 3


def test_the_redaction_is_the_bots() -> None:
    """vpn-bot-site's log patterns == utils/redact.py's (a log never leaves unredacted)."""
    import importlib.machinery
    import importlib.util
    import sys

    from utils import redact as bot_redact

    loader = importlib.machinery.SourceFileLoader("vpn_bot_site_for_test", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module  # its dataclasses look their module up
    try:
        loader.exec_module(module)
    finally:
        sys.modules.pop(loader.name, None)
    ours = {p.pattern for p, _ in module._REDACT}
    theirs = {getattr(bot_redact, n).pattern for n in dir(bot_redact) if n.endswith("_RE")}
    assert theirs <= ours
    sample = "token=abc secret=x https://u:p@h/ Bearer abcdefghijklmnopqrstu " + "f" * 40
    assert module.redact(sample) == bot_redact.redact_text(sample)
    assert json.dumps(module.pages_of(["index.html", "a/index.html", "b.htm", "c.css"])) == '["/", "/a/", "/b.htm"]'
