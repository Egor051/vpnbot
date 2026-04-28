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
- на существующих БД FK не перестраивает таблицы, чтобы не рисковать потерей данных, но останавливает запуск при найденных orphan-записях.

Bootstrap:

```bash
cd /opt/vpn-service
/opt/vpn-service/.venv/bin/python init_db.py
```

## Переменные окружения

Канонический список переменных находится в `.env.example`. Не ведите второй список
вручную: при установке скопируйте example-файл и заполните значения в `.env`:

```bash
cp .env.example .env
nano .env
```

`AWG_DNS` — основная переменная для DNS в клиентском AWG config.
`AWG_CLIENT_DNS` поддерживается только как legacy alias для старых установок.

`XRAY_APPLY_MODE=reload` — безопасный режим по умолчанию: бот применяет Xray config
через `systemctl reload xray`. Если unit на конкретном VDS не поддерживает reload,
в single-server setup можно явно поставить `XRAY_APPLY_MODE=restart`. Restart кратко
прерывает Xray-соединения, но не использует `reload-or-restart` или `kill -HUP`.

`BOT_DROP_PENDING_UPDATES=true` допустим только для первичного перехода с webhook или ручной очистки очереди Telegram. Для production polling по умолчанию оставляйте `false`, чтобы restart бота не терял pending callback/messages.

Если bootstrap останавливается с сообщением про orphan-записи в SQLite, не удаляйте данные автоматически. Сделайте backup `vpn.db`, найдите строки без связанного пользователя через `LEFT JOIN users`, затем вручную восстановите владельца или удалите orphan-записи только после проверки.

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
