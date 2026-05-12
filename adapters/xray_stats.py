
import json

from adapters.shell_runner import ShellRunner

MACHINE_OUTPUT_LIMIT = 1024 * 1024


class XrayStatsUnavailable(RuntimeError):
    pass


class XrayStatsAdapter:
    def __init__(self, *, shell: ShellRunner, stats_server: str) -> None:
        self.shell = shell
        self.stats_server = stats_server.strip()

    async def query_all(self) -> dict[str, int]:
        if not self.stats_server:
            raise XrayStatsUnavailable("XRAY_STATS_SERVER не задан, Xray stats API не настроен")
        result = await self.shell.run(
            ["xray", "api", "statsquery", f"--server={self.stats_server}"],
            timeout=15,
            max_output_chars=MACHINE_OUTPUT_LIMIT,
        )
        if not result.ok:
            raise XrayStatsUnavailable(f"Xray stats API недоступен: {result.stderr or result.stdout}")
        return self.parse_statsquery_output(result.stdout)

    @staticmethod
    def parse_statsquery_output(text: str) -> dict[str, int]:
        if not text.strip():
            return {}
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise XrayStatsUnavailable("Xray stats API вернул невалидный JSON") from exc
        stats = data.get("stat") if isinstance(data, dict) else None
        if not isinstance(stats, list):
            return {}
        result: dict[str, int] = {}
        for item in stats:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if not isinstance(name, str):
                continue
            try:
                result[name] = int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                result[name] = 0
        return result
