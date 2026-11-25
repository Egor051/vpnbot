
from aiogram.fsm.state import State, StatesGroup


class CreateKeyStates(StatesGroup):
    waiting_xhttp_profile = State()
    # «Подключение: напрямую / через <relay>» — only while a relay is enabled.
    waiting_route = State()
    # All-in-one: basic or extended.
    waiting_bundle_kind = State()
    waiting_note = State()
    waiting_fp = State()
    waiting_mtu = State()
    waiting_mtu_custom = State()
    waiting_expiry = State()
    waiting_custom_days = State()
    confirming = State()


class EditNoteStates(StatesGroup):
    waiting_note = State()
    confirming = State()


class EditFpStates(StatesGroup):
    waiting_fp = State()


class ProxyStates(StatesGroup):
    confirming = State()


class AdminCreateKeyStates(StatesGroup):
    choosing_type = State()
    waiting_xhttp_profile = State()
    # «Подключение: напрямую / через <relay>» — only while a relay is enabled.
    waiting_route = State()
    waiting_note = State()
    waiting_fp = State()
    waiting_mtu = State()
    waiting_mtu_custom = State()
    waiting_expiry = State()
    waiting_custom_days = State()
    confirming = State()


class AdminEditUserNoteStates(StatesGroup):
    waiting_note = State()


class AdminUserSearchStates(StatesGroup):
    """«🔎 Найти» in the users list: waiting for a Telegram id or a username."""

    waiting_query = State()


class AdminAnnouncementStates(StatesGroup):
    choosing_roles = State()
    choosing_protocols = State()
    choosing_transports = State()
    waiting_message = State()
    confirming = State()
    waiting_schedule_time = State()


class MaintenanceStates(StatesGroup):
    waiting_message = State()


class TrialRequestStates(StatesGroup):
    choosing_protocol = State()
    confirming = State()


class WarpConfigStates(StatesGroup):
    waiting_config = State()


class WarpSplitStates(StatesGroup):
    waiting_cidrs = State()
    # New prefix source: slug / title / URL / format, one per line.
    waiting_source = State()


class AdminRelayStates(StatesGroup):
    """The ONE relay screen's typed steps (bot/handlers/admin_relays.py)."""

    # «Добавить relay»: name → public host (→ keep an IPv4?) → the main server's name.
    add_name = State()
    add_host = State()
    add_host_ipv4 = State()
    add_target = State()
    # «🔗 Подключить агент» when the main server's DNS name is not known.
    attach_target = State()
    # «🔌 Подключить»: the relay's SSH address.
    pair_address = State()
    # «⚙️ Порты / цель» of a relay with an agent.
    forward = State()
    edit_host = State()
    edit_source_ips = State()
    edit_label = State()
    edit_note = State()


class TotpStates(StatesGroup):
    """The superadmin's TOTP (bot/handlers/security.py, bot/totp_gate.py)."""

    # «Включить TOTP»: the QR/secret are on screen, waiting for the first code.
    enroll_code = State()
    # A dangerous action asked for a code (or a backup code).
    gate_code = State()
    # «Отключить TOTP»: a TOTP code or a backup code.
    disable_code = State()
    # «Перевыпустить резервные коды»: a TOTP code (a backup code is not enough).
    reissue_code = State()


class RelaySshPortStates(StatesGroup):
    """«🔑 SSH-порт relay» (bot/handlers/ssh_port.py): the new port, typed."""

    port = State()


class AdminFallbackStates(StatesGroup):
    """«🛟 Режим фолбэка» typed steps (bot/handlers/admin_fallback.py)."""

    # A name for the failover set.
    name = State()
    # The DNS API token: the message is deleted as soon as it is read.
    token = State()
    # The main server's / the hub's IPv4 override ("-" — derived again).
    main_ipv4 = State()
    hub_ipv4 = State()
    # The direct links' host ("-" — .env again).
    direct_host = State()
    # «🛟 Сделать hub»: the origin name.
    origin = State()


class CertStates(StatesGroup):
    """«🔐 Сертификат и DNS» typed steps (bot/handlers/admin_cert.py)."""

    # The names of «Выпустить» (comma-separated).
    names = State()
    # The bot's Cloudflare token: the message is deleted as soon as it is read.
    token = State()


class SetupStates(StatesGroup):
    """«🧭 Первичная настройка» typed steps (bot/handlers/first_setup.py)."""

    # The domain the server serves.
    domain = State()
    # The bot's Cloudflare token: the message is deleted as soon as it is read.
    token = State()
