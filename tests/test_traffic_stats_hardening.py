
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from adapters.awg_config import MACHINE_OUTPUT_LIMIT as AWG_MACHINE_OUTPUT_LIMIT
from adapters.awg_config import AwgConfigAdapter
from adapters.shell_runner import ShellRunner
from adapters.xray_stats import MACHINE_OUTPUT_LIMIT as XRAY_MACHINE_OUTPUT_LIMIT
from adapters.xray_stats import XrayStatsAdapter
from models.dto import ShellResult, TrafficStats, VpnKey
from models.enums import VpnKeyStatus, VpnKeyType
from services.traffic_stats import PUBLIC_BACKEND_STATS_ERROR, TrafficStatsService


def _xray_key() -> VpnKey:
    return VpnKey(
        id=10,
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid="uuid",
        email_label="xray_A7kQz",
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


def _awg_key() -> VpnKey:
    return VpnKey(
        id=11,
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.AWG,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=None,
        email_label="awg_A7kQz",
        public_key="public",
        client_ip="10.0.0.2",
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


def _stats(
    *,
    downloaded: int = 0,
    uploaded: int = 0,
    raw_downloaded: int | None = None,
    raw_uploaded: int | None = None,
) -> TrafficStats:
    return TrafficStats(
        key_id=10,
        downloaded_bytes=downloaded,
        uploaded_bytes=uploaded,
        last_raw_downloaded_bytes=raw_downloaded,
        last_raw_uploaded_bytes=raw_uploaded,
        last_success_at="old",
        last_attempt_at="old",
        available=True,
        unavailable_reason=None,
        source="xray statsquery",
    )


class _StatsRepo:
    def __init__(self) -> None:
        self.last: TrafficStats | None = None

    async def upsert_success(
        self,
        *,
        key_id: int,
        downloaded_bytes: int,
        uploaded_bytes: int,
        raw_downloaded_bytes: int | None,
        raw_uploaded_bytes: int | None,
        now: str,
        source: str,
    ) -> TrafficStats:
        self.last = TrafficStats(
            key_id=key_id,
            downloaded_bytes=downloaded_bytes,
            uploaded_bytes=uploaded_bytes,
            last_raw_downloaded_bytes=raw_downloaded_bytes,
            last_raw_uploaded_bytes=raw_uploaded_bytes,
            last_success_at=now,
            last_attempt_at=now,
            available=True,
            unavailable_reason=None,
            source=source,
        )
        return self.last


def _service(repo: _StatsRepo) -> TrafficStatsService:
    return TrafficStatsService(
        stats=repo,  # type: ignore[arg-type]
        vpn_keys=SimpleNamespace(),
        users_repo=SimpleNamespace(),
        users=SimpleNamespace(clock=SimpleNamespace(now=lambda: "now")),
        awg=SimpleNamespace(),
        xray=SimpleNamespace(),
    )


def test_shell_runner_default_output_stays_compact() -> None:
    async def run() -> None:
        shell = ShellRunner(max_output_chars=128)
        result = await shell.run([sys.executable, "-c", "print('x' * 512)"], timeout=5)
        assert result.ok
        assert len(result.stdout) < 160
        assert result.stdout.endswith("...[truncated]")

    asyncio.run(run())


def test_xray_stats_large_json_uses_machine_output_limit() -> None:
    stats = [
        {"name": f"user>>>xray_{index:05d}>>>traffic>>>downlink", "value": index}
        for index in range(600)
    ]
    payload = json.dumps({"stat": stats})
    assert len(payload) > 4096

    class Shell:
        async def run(self, args: list[str], **kwargs: object) -> ShellResult:
            assert kwargs["max_output_chars"] == XRAY_MACHINE_OUTPUT_LIMIT
            return ShellResult(tuple(args), 0, payload, "")

    async def run() -> None:
        adapter = XrayStatsAdapter(shell=Shell(), stats_server="127.0.0.1:10085")  # type: ignore[arg-type]
        parsed = await adapter.query_all()
        assert parsed["user>>>xray_00599>>>traffic>>>downlink"] == 599

    asyncio.run(run())


def test_awg_transfer_large_output_uses_machine_output_limit() -> None:
    lines = [f"public-{index} {index} {index + 1}" for index in range(600)]
    payload = "\n".join(lines)
    assert len(payload) > 4096

    class Shell:
        async def run(self, args: list[str], **kwargs: object) -> ShellResult:
            assert kwargs["max_output_chars"] == AWG_MACHINE_OUTPUT_LIMIT
            return ShellResult(tuple(args), 0, payload, "")

    async def run() -> None:
        adapter = AwgConfigAdapter(
            config_path=Path(__file__),
            interface="awg0",
            backup=SimpleNamespace(),
            shell=Shell(),  # type: ignore[arg-type]
            persistent_keepalive=25,
        )
        parsed = await adapter.list_transfer()
        assert parsed["public-599"] == (599, 600)

    asyncio.run(run())


def test_xray_missing_uplink_does_not_reset_uploaded_raw() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _service(repo)
        result = await service._refresh_xray_key(  # noqa: SLF001
            _xray_key(),
            _stats(downloaded=1000, uploaded=500, raw_downloaded=1000, raw_uploaded=500),
            {"user>>>xray_A7kQz>>>traffic>>>downlink": 1100},
            None,
        )
        assert result.downloaded_bytes == 1100
        assert result.uploaded_bytes == 500
        assert result.last_raw_downloaded_bytes == 1100
        assert result.last_raw_uploaded_bytes == 500

    asyncio.run(run())


def test_xray_missing_downlink_does_not_reset_downloaded_raw() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _service(repo)
        result = await service._refresh_xray_key(  # noqa: SLF001
            _xray_key(),
            _stats(downloaded=1000, uploaded=500, raw_downloaded=1000, raw_uploaded=500),
            {"user>>>xray_A7kQz>>>traffic>>>uplink": 600},
            None,
        )
        assert result.downloaded_bytes == 1000
        assert result.uploaded_bytes == 600
        assert result.last_raw_downloaded_bytes == 1000
        assert result.last_raw_uploaded_bytes == 600

    asyncio.run(run())


def test_xray_restored_partial_counter_increments_from_preserved_raw() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _service(repo)
        partial = await service._refresh_xray_key(  # noqa: SLF001
            _xray_key(),
            _stats(downloaded=1000, uploaded=500, raw_downloaded=1000, raw_uploaded=500),
            {"user>>>xray_A7kQz>>>traffic>>>downlink": 1100},
            None,
        )
        restored = await service._refresh_xray_key(  # noqa: SLF001
            _xray_key(),
            partial,
            {
                "user>>>xray_A7kQz>>>traffic>>>downlink": 1200,
                "user>>>xray_A7kQz>>>traffic>>>uplink": 600,
            },
            None,
        )
        assert restored.downloaded_bytes == 1200
        assert restored.uploaded_bytes == 600

    asyncio.run(run())


def test_legacy_total_does_not_decrease_when_previous_raw_is_missing() -> None:
    service = _service(_StatsRepo())

    assert service._next_total(1000, None, 100) == 1000  # noqa: SLF001
    assert service._next_total(1000, None, 1500) == 1500  # noqa: SLF001
    assert service._next_total(1500, 1200, 100) == 1600  # noqa: SLF001
    assert service._next_total(1500, 1200, 1400) == 1700  # noqa: SLF001


def test_xray_stats_internal_error_is_not_returned_as_public_reason() -> None:
    class Xray:
        async def query_all(self) -> dict[str, int]:
            raise RuntimeError("stderr: /usr/local/etc/xray/config.json token=secret")

    async def run() -> None:
        service = TrafficStatsService(
            stats=_StatsRepo(),  # type: ignore[arg-type]
            vpn_keys=SimpleNamespace(),
            users_repo=SimpleNamespace(),
            users=SimpleNamespace(clock=SimpleNamespace(now=lambda: "now")),
            awg=SimpleNamespace(),
            xray=Xray(),  # type: ignore[arg-type]
        )

        _, reason = await service._load_xray_stats([_xray_key()])  # noqa: SLF001

        assert reason == PUBLIC_BACKEND_STATS_ERROR
        assert reason is not None
        assert "xray" not in reason.lower()
        assert "secret" not in reason
        assert "/usr/local" not in reason

    asyncio.run(run())


def test_awg_peer_not_in_transfer_output_stores_zero_bytes_first_reading() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _service(repo)
        result = await service._refresh_awg_key(  # noqa: SLF001
            _awg_key(),
            None,
            {},
            None,
        )
        assert result.available
        assert result.downloaded_bytes == 0
        assert result.uploaded_bytes == 0
        assert result.last_raw_downloaded_bytes == 0
        assert result.last_raw_uploaded_bytes == 0

    asyncio.run(run())


def test_awg_peer_not_in_transfer_output_preserves_previous_total_after_restart() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _service(repo)
        previous = TrafficStats(
            key_id=11,
            downloaded_bytes=1000,
            uploaded_bytes=500,
            last_raw_downloaded_bytes=1000,
            last_raw_uploaded_bytes=500,
            last_success_at="old",
            last_attempt_at="old",
            available=True,
            unavailable_reason=None,
            source="awg/wg transfer",
        )
        result = await service._refresh_awg_key(  # noqa: SLF001
            _awg_key(),
            previous,
            {},
            None,
        )
        assert result.available
        assert result.downloaded_bytes == 1000
        assert result.uploaded_bytes == 500
        assert result.last_raw_downloaded_bytes == 0
        assert result.last_raw_uploaded_bytes == 0

    asyncio.run(run())


def test_awg_peer_accumulates_after_restart_and_reconnect() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _service(repo)
        previous = TrafficStats(
            key_id=11,
            downloaded_bytes=1000,
            uploaded_bytes=500,
            last_raw_downloaded_bytes=1000,
            last_raw_uploaded_bytes=500,
            last_success_at="old",
            last_attempt_at="old",
            available=True,
            unavailable_reason=None,
            source="awg/wg transfer",
        )
        after_restart = await service._refresh_awg_key(  # noqa: SLF001
            _awg_key(),
            previous,
            {},
            None,
        )
        reconnected = await service._refresh_awg_key(  # noqa: SLF001
            _awg_key(),
            after_restart,
            {"public": (200, 300)},
            None,
        )
        assert reconnected.downloaded_bytes == 1300
        assert reconnected.uploaded_bytes == 700

    asyncio.run(run())


def test_awg_stats_internal_error_is_not_returned_as_public_reason() -> None:
    class Awg:
        async def list_transfer(self) -> dict[str, tuple[int, int]]:
            raise RuntimeError("awg show failed: /etc/amnezia/amneziawg/awg0.conf")

    async def run() -> None:
        service = TrafficStatsService(
            stats=_StatsRepo(),  # type: ignore[arg-type]
            vpn_keys=SimpleNamespace(),
            users_repo=SimpleNamespace(),
            users=SimpleNamespace(clock=SimpleNamespace(now=lambda: "now")),
            awg=Awg(),  # type: ignore[arg-type]
            xray=SimpleNamespace(),
        )

        _, reason = await service._load_awg_transfers([_awg_key()])  # noqa: SLF001

        assert reason == PUBLIC_BACKEND_STATS_ERROR
        assert reason is not None
        assert "awg0.conf" not in reason
        assert "/etc" not in reason

    asyncio.run(run())
