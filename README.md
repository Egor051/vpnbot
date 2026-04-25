# VPN Telegram Bot

Production-ready skeleton Telegram-бота для управления доступом к VPN-проекту на одном VDS без Docker, Redis, PostgreSQL и тяжёлого ORM.

## Архитектура

Поток вызовов:

```text
Telegram update/callback
  -> bot/handlers
  -> services
  -> repositories / adapters
  -> SQLite / Xray config / AWG config / systemctl / subprocess
```

Правила слоёв:

- `handlers`: Telegram input, простая валидация, вызов сервисов, русский ответ пользователю.
- `services`: бизнес-сценарии, права, status progression, audit, rollback orchestration.
- `repositories`: только SQLite CRUD и точечные запросы.
- `adapters`: Xray, AWG, backup/restore, systemctl, subprocess, IP allocation.
- `models`: компактные `dataclass(slots=True)` DTO и `Enum`.

## Дерево проекта

```text
main.py
init_db.py
requirements.txt
.env.example
deploy/vpn-bot.service
bot/
config/
db/
models/
repositories/
services/
adapters/
utils/
```

## База данных

SQLite-файл по умолчанию: `/opt/vpn-service/data/vpn.db`.
Миграции выполняются автоматически при запуске бота или `init_db.py`.

Схема лежит в `db/schema.sql` и создаёт таблицы:

- `users`
- `access_requests`
- `vpn_keys`
- `proxy_entries`
- `audit_log`
- `vpn_key_traffic_stats`

Текущая версия схемы: `4`.

Миграция v4:

- добавляет partial unique index на одну pending-заявку на пользователя;
- добавляет индексы для восстановления зависших VPN-ключей;
- для новых БД добавляет FK от заявок и ключей к `users`;
- на существующих БД FK не перестраивает таблицы, чтобы не рисковать потерей данных, но логирует найденные orphan-записи.

Bootstrap:

```bash
cd /opt/vpn-service
/opt/vpn-service/.venv/bin/python init_db.py
```

## Переменные окружения

Скопируйте `.env.example` в `/opt/vpn-service/.env` и заполните значения:

```bash
BOT_TOKEN=
ADMIN_IDS=123456789,987654321

DB_PATH=/opt/vpn-service/data/vpn.db
LOG_DIR=/opt/vpn-service/logs

XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json
XRAY_SERVICE_NAME=xray
XRAY_INBOUND_TAG=
XRAY_PUBLIC_HOST=
XRAY_PUBLIC_PORT=443
XRAY_REALITY_PUBLIC_KEY=
XRAY_SNI=
XRAY_FLOW=xtls-rprx-vision

AWG_CONFIG_PATH=/etc/amnezia/amneziawg/awg0.conf
AWG_INTERFACE=awg0
AWG_NETWORK=10.0.0.0/24
AWG_SERVER_ADDRESS=10.0.0.1
AWG_ENDPOINT_HOST=
AWG_ENDPOINT_PORT=
AWG_SERVER_PUBLIC_KEY=
AWG_CLIENT_DNS=1.1.1.1
AWG_ALLOWED_IPS=0.0.0.0/0, ::/0
AWG_PERSISTENT_KEEPALIVE=25

AUDIT_RETENTION_DAYS=180
CONFIG_BACKUP_KEEP_LAST=20
```

## Установка на Ubuntu 24

```bash
sudo mkdir -p /opt/vpn-service/{bot,data,logs,scripts}
sudo chown -R "$USER":"$USER" /opt/vpn-service
cd /opt/vpn-service

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

cp .env.example .env
nano .env

.venv/bin/python init_db.py
.venv/bin/python -m compileall .
```

Установить systemd unit:

```bash
sudo cp deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot
```

## Безопасность

- Bot token, ADMIN_IDS, endpoint и proxy secrets берутся только из `.env`.
- Приватные ключи, preshared keys, proxy passwords, UUID/shortId и полные конфиги маскируются в audit details рекурсивно.
- Xray/AWG конфиги изменяются только через adapter flow с file lock, timestamped backup, проверкой mtime и restore при ошибке.
- Backup-файлы конфигов создаются с правами `600`; количество хранимых backup ограничивает `CONFIG_BACKUP_KEEP_LAST`.
- SQLite DB и директории data/logs получают приватные права на Linux, если бот управляет этими путями.
- При старте бот пытается безопасно восстановить зависшие статусы `pending_apply`, `pending_revoke`, `pending_delete`, `delete_failed`.
- Опасные действия в боте требуют confirm/cancel.
- Чужие конфиги доступны только владельцу или `SUPERADMIN`.

## Linux permission QA

POSIX mode preservation tests are skipped on Windows. Run this check on Ubuntu 24 VDS/CI:

```bash
.venv/bin/python -m pytest -q tests/test_followup_hardening.py -k mode
```

Expected result: main Xray/AWG config files keep their original owner/group/mode after mutation or rollback (for example `0644` stays `0644`), while generated backup files are `0600`.

## Допущения

- Xray-ссылка генерируется как VLESS Reality.
- Если `XRAY_INBOUND_TAG` пустой, используется первый inbound с `settings.clients`.
- AWG adapter добавляет только bot-managed `[Peer]` блоки с маркерами `vpn-bot peer start/end`.
- AWG IP переиспользуется только после статусов `revoked`, `deleted` или `failed`.
