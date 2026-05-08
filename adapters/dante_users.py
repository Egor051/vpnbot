from __future__ import annotations

import re
from pathlib import Path

from adapters.errors import DanteUserError, DanteUserNotFoundError
from adapters.privileged_helpers import PrivilegedHelperRunner
from adapters.shell_runner import ShellRunner

_LOGIN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")


class DanteUserAdapter:
    def __init__(
        self,
        *,
        shell: ShellRunner,
        login_prefix: str,
        system_user_shell: str,
        helper_runner: PrivilegedHelperRunner | None = None,
        helper_path: Path | None = None,
    ) -> None:
        self.shell = shell
        self.login_prefix = login_prefix
        self.system_user_shell = system_user_shell
        self.helper_runner = helper_runner
        self.helper_path = helper_path or Path("/usr/local/sbin/vpnbot-socks5-user")

    async def exists(self, login: str) -> bool:
        self._ensure_managed_login(login)
        if self.helper_runner is not None:
            result = await self.helper_runner.run(self.helper_path, ["exists", login], timeout=10)
            if result.returncode == 0:
                return True
            if result.returncode == 2:
                return False
            raise DanteUserError(f"Не удалось проверить SOCKS5 Linux user через helper: rc={result.returncode}")
        result = await self.shell.run(["getent", "passwd", login], timeout=5, max_output_chars=512)
        if result.returncode == 0:
            return True
        if result.returncode == 2:
            return False
        raise DanteUserError(f"Не удалось проверить SOCKS5 Linux user: rc={result.returncode}")

    async def create_user(self, login: str, password: str) -> None:
        self._ensure_managed_login(login)
        if await self.exists(login):
            raise DanteUserError("SOCKS5 Linux user уже существует")
        if self.helper_runner is not None:
            created = await self.helper_runner.run(self.helper_path, ["create", login], timeout=20)
            if not created.ok:
                raise DanteUserError(f"Не удалось создать SOCKS5 Linux user через helper: rc={created.returncode}")
            password_set = await self.helper_runner.run(
                self.helper_path,
                ["set-password", login],
                input_text=f"{password}\n",
                timeout=20,
                sensitive_values=(password,),
            )
            if not password_set.ok:
                raise DanteUserError(
                    f"Не удалось установить пароль SOCKS5 Linux user через helper: rc={password_set.returncode}"
                )
            return
        created = await self.shell.run(
            ["useradd", "-r", "-s", self.system_user_shell, login],
            timeout=15,
            max_output_chars=1024,
        )
        if not created.ok:
            raise DanteUserError(f"Не удалось создать SOCKS5 Linux user: rc={created.returncode}")
        password_set = await self.shell.run(
            ["chpasswd"],
            input_text=f"{login}:{password}\n",
            timeout=15,
            sensitive_values=(password,),
            max_output_chars=1024,
        )
        if not password_set.ok:
            raise DanteUserError(f"Не удалось установить пароль SOCKS5 Linux user: rc={password_set.returncode}")

    async def lock_user(self, login: str) -> None:
        self._ensure_managed_login(login)
        if not await self.exists(login):
            raise DanteUserNotFoundError("SOCKS5 Linux user не найден")
        if self.helper_runner is not None:
            result = await self.helper_runner.run(self.helper_path, ["lock", login], timeout=20)
            if not result.ok:
                raise DanteUserError(f"Не удалось заблокировать SOCKS5 Linux user через helper: rc={result.returncode}")
            return
        result = await self.shell.run(["passwd", "-l", login], timeout=15, max_output_chars=1024)
        if not result.ok:
            raise DanteUserError(f"Не удалось заблокировать SOCKS5 Linux user: rc={result.returncode}")

    async def delete_user(self, login: str) -> None:
        self._ensure_managed_login(login)
        if not await self.exists(login):
            return
        if self.helper_runner is not None:
            result = await self.helper_runner.run(self.helper_path, ["delete", login], timeout=20)
            if not result.ok:
                raise DanteUserError(f"Не удалось удалить SOCKS5 Linux user через helper: rc={result.returncode}")
            return
        result = await self.shell.run(["userdel", login], timeout=15, max_output_chars=1024)
        if not result.ok:
            raise DanteUserError(f"Не удалось удалить SOCKS5 Linux user: rc={result.returncode}")

    def _ensure_managed_login(self, login: str) -> None:
        if not login.startswith(self.login_prefix):
            raise DanteUserError("SOCKS5 Linux user не принадлежит bot-managed prefix")
        if _LOGIN_RE.fullmatch(login) is None:
            raise DanteUserError("Некорректный SOCKS5 Linux login")
