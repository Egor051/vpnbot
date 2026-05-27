
from pathlib import Path

from adapters.shell_runner import ShellRunner
from models.dto import ShellResult


class SystemCtlAdapter:
    def __init__(self, shell: ShellRunner) -> None:
        self.shell = shell

    async def restart(self, service_name: str) -> ShellResult:
        """Restart the given systemd service."""
        return await self.shell.run(["systemctl", "restart", service_name], timeout=20)

    async def reload(self, service_name: str) -> ShellResult:
        """Reload the given systemd service."""
        return await self.shell.run(["systemctl", "reload", service_name], timeout=20)

    async def is_active(self, service_name: str) -> ShellResult:
        """Query whether the given systemd service is active."""
        return await self.shell.run(["systemctl", "is-active", service_name], timeout=10)

    async def daemon_reload(self) -> ShellResult:
        """Reload the systemd manager configuration."""
        return await self.shell.run(["systemctl", "daemon-reload"], timeout=20)

    async def xray_test_config(self, config_path: Path) -> ShellResult:
        """Validate the Xray config at the given path using xray run -test."""
        return await self.shell.run(["xray", "run", "-test", "-config", str(config_path)], timeout=20)
