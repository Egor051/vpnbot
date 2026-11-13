"""The effective superadmins: ADMIN_IDS + the users who claimed the bot.

``Settings.admin_ids`` has always been the one place every consumer asks "who is
superadmin": role assignment (UserService.ensure_user), the protections against
demoting or blocking one, every alert broadcast, the admin command menu and the
maintenance gate. A fresh install (scripts/install.sh) starts with ADMIN_IDS empty
and gets its first superadmin from a one-time deep link at runtime, so the set
must be able to grow while the bot runs — without a restart and without teaching
a dozen consumers about a second source.

:class:`SuperadminSet` is that live set. Bot startup builds it from ADMIN_IDS and
the ``claimed_superadmins`` table and puts it into ``Settings.admin_ids``
(``dataclasses.replace``); a successful claim adds the claimant. It is a read-only
``collections.abc.Set`` to every consumer, so ``in``, ``len`` and iteration behave
exactly as they did on the frozenset.

Iteration walks a sorted SNAPSHOT: a broadcast awaits between recipients, and a
claim landing in the middle must not raise "Set changed size during iteration".
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from collections.abc import Set as AbstractSet


class SuperadminSet(AbstractSet[int]):
    def __init__(self, configured: Iterable[int], claimed: Iterable[int] = ()) -> None:
        self._configured: frozenset[int] = frozenset(configured)
        self._claimed: set[int] = set(claimed)

    @property
    def configured(self) -> frozenset[int]:
        """The superadmins from ADMIN_IDS (.env)."""
        return self._configured

    @property
    def claimed(self) -> frozenset[int]:
        """The superadmins who claimed the bot (claimed_superadmins)."""
        return frozenset(self._claimed)

    def add_claimed(self, telegram_user_id: int) -> None:
        """Record a claim that has just been committed to the database."""
        self._claimed.add(telegram_user_id)

    def __contains__(self, item: object) -> bool:
        return item in self._configured or item in self._claimed

    def __iter__(self) -> Iterator[int]:
        return iter(sorted(self._configured | self._claimed))

    def __len__(self) -> int:
        return len(self._configured | self._claimed)

    def __repr__(self) -> str:
        return f"SuperadminSet(configured={sorted(self._configured)}, claimed={sorted(self._claimed)})"
