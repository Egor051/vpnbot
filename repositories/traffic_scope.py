"""The one definition of "which traffic rows an aggregate counts".

Before this module three places each answered that question on their own and
answered it differently, which is why the personal cabinet and the admin
dashboard printed different gigabyte figures for the same account:

  * the cabinet summed only ``↓`` over an owner's non-deleted keys,
  * the dashboard summed ``↓ + ↑`` over every key plus the deleted-key archive,
  * the subscription header had a third variant of its own.

Nothing was wrong with any of the numbers — they answered different questions
and none of them said which. The fix is not one number: it is one query with an
explicit scope, so a screen has to name the question it is asking and two
screens asking the same question cannot drift.

Both scopes exclude ``vpn_keys`` rows with ``status = 'deleted'``. For
:data:`ALL_TIME` that is the anti-double-count guard: a deleted key's traffic
lives in ``deleted_key_traffic_archive``, so counting the ``vpn_keys`` row too
would count it twice. Today the two sets do not overlap in practice (deletion
archives the totals and drops the stats row), but nothing enforced that — hence
the guard rather than a comment.
"""

from __future__ import annotations

from dataclasses import dataclass

from models.enums import VpnKeyStatus


@dataclass(frozen=True)
class TrafficScope:
    """Which traffic rows an aggregate counts.

    :param include_archive: also count ``deleted_key_traffic_archive`` — the
        totals of keys that no longer exist.
    :param include_deleted_keys: also count live ``vpn_keys`` rows parked in
        ``status = 'deleted'``.
    """

    include_archive: bool
    include_deleted_keys: bool

    def __post_init__(self) -> None:
        if self.include_archive and self.include_deleted_keys:
            # A deleted key is archived; counting both sides of the UNION would
            # count its bytes twice. Refuse the combination at construction time
            # instead of shipping a silently inflated total.
            raise ValueError(
                "TrafficScope(include_archive=True, include_deleted_keys=True) "
                "double-counts deleted keys"
            )


#: What the user can verify right now: the keys they still have.
CURRENT_KEYS = TrafficScope(include_archive=False, include_deleted_keys=False)

#: Everything the account has ever moved, including keys that were deleted.
ALL_TIME = TrafficScope(include_archive=True, include_deleted_keys=False)


#: Columns every row of :func:`traffic_rows_query` carries, so each caller can
#: aggregate the same dataset its own way (per owner, per protocol, or a plain
#: sum) without a second query shape to keep in step.
ROW_COLUMNS = ("owner_user_id", "key_type", "username", "downloaded_bytes", "uploaded_bytes")


def traffic_rows_query(
    scope: TrafficScope, *, owner_user_id: int | None = None
) -> tuple[str, tuple[object, ...]]:
    """Return ``(sql, params)`` for a subquery yielding one row per traffic record.

    The SQL is a parenthesised ``SELECT`` meant to be embedded as a derived table:
    ``f"SELECT SUM(...) FROM {sql}"``. Only the scope decides its shape, and the
    scope arrives as a value, so the two callers cannot drift apart the way two
    hand-written queries did.
    """
    live_conditions = []
    live_params: list[object] = []
    if not scope.include_deleted_keys:
        live_conditions.append("k.status <> ?")
        live_params.append(VpnKeyStatus.DELETED.value)
    if owner_user_id is not None:
        live_conditions.append("k.owner_user_id = ?")
        live_params.append(owner_user_id)
    live_where = f"WHERE {' AND '.join(live_conditions)}" if live_conditions else ""

    branches = [
        f"""
        SELECT k.owner_user_id                    AS owner_user_id,
               k.key_type                         AS key_type,
               COALESCE(u.username, k.username)   AS username,
               t.downloaded_bytes                 AS downloaded_bytes,
               t.uploaded_bytes                   AS uploaded_bytes
        FROM vpn_key_traffic_stats t
        JOIN vpn_keys k ON k.id = t.key_id
        LEFT JOIN users u ON u.telegram_user_id = k.owner_user_id
        {live_where}
        """
    ]
    params: list[object] = list(live_params)

    if scope.include_archive:
        archive_where = ""
        if owner_user_id is not None:
            archive_where = "WHERE a.owner_user_id = ?"
            params.append(owner_user_id)
        branches.append(
            f"""
            SELECT a.owner_user_id                                        AS owner_user_id,
                   a.key_type                                             AS key_type,
                   COALESCE(u.username, CAST(a.owner_user_id AS TEXT))    AS username,
                   a.downloaded_bytes                                     AS downloaded_bytes,
                   a.uploaded_bytes                                       AS uploaded_bytes
            FROM deleted_key_traffic_archive a
            LEFT JOIN users u ON u.telegram_user_id = a.owner_user_id
            {archive_where}
            """
        )

    return "(" + "UNION ALL".join(branches) + ")", tuple(params)
