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

Текущая версия схемы: `5`.

Миграция v4:

- добавляет partial unique index на одну pending-заявку на пользователя;
- добавляет индексы для восстановления зависших VPN-ключей;
- для новых БД добавляет FK от заявок и ключей к `users`;
- на существующих БД FK не перестраивает таблицы, чтобы не рисковать потерей данных, но останавливает запуск при найденных orphan-записях.

Миграция v5:

- добавляет reserved unique index для AWG `client_ip` в статусах `pending_apply`, `active`, `pending_revoke`, `pending_delete`, `delete_failed`;
- перед созданием индекса останавливает запуск при найденных duplicate reserved `client_ip`;
- валидирует orphan `vpn_key_traffic_stats.key_id` и actor/reference поля, где это критично;
- для новых БД включает CHECK constraints для enum-like полей.

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

`XRAY_APPLY_MODE=restart` — рекомендуемый production-режим по умолчанию для
single-server setup: бот проверяет config и применяет изменения через
`systemctl restart xray`. Restart кратко прерывает Xray-соединения, но даёт более
предсказуемое применение config, чем reload. `XRAY_APPLY_MODE=reload` всё ещё
поддерживается, если ваш unit гарантированно применяет reload; бот не использует
`reload-or-restart` или `kill -HUP`.

Если `XRAY_INBOUND_TAG` пустой, бот использует VLESS/Reality inbound только когда
такой inbound ровно один. При нескольких VLESS/Reality inbound укажите tag явно,
иначе создание/удаление Xray-ключа остановится с ошибкой, чтобы не изменить
неправильный inbound.

`AWG_SERVER_ADDRESS` должен быть IPv4-адресом внутри `AWG_NETWORK` и не может быть
network/broadcast address. Если в server config есть `Address`, его IPv4-адрес
должен совпадать с `AWG_SERVER_ADDRESS`.

Boolean env-переменные парсятся строго. Допустимые true: `1,true,yes,y,on`,
false: `0,false,no,n,off`. Любое другое непустое значение останавливает запуск,
чтобы опечатка вроде `treu` не включала/выключала режим молча.

`XRAY_NETWORK_TYPE` должен быть `tcp` или `raw`; `XRAY_FINGERPRINT` проверяется
по whitelist распространённых fingerprints; `XRAY_REALITY_PUBLIC_KEY` должен
быть base64url-совместимой строкой без пробелов.

Новые ключи получают короткие пользовательские labels вида `xray_Ab3dE` или
`awg_A7kQz`. Старые labels не мигрируются. Для AWG файл конфигурации отправляется
как `<awg_label>.conf`.

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
- SQLite DB является secret storage: в `vpn_keys.payload_json` хранятся приватные данные ключей, поэтому backup и доступ к файлам DB должны быть ограничены.
- SQLite sidecar-файлы `vpn.db-wal` и `vpn.db-shm`, если они существуют, также выставляются в `0600` на POSIX.
- Systemd unit задаёт `UMask=0077`, чтобы новые файлы процесса не становились world-readable.
- Приватные ключи, preshared keys, proxy passwords, UUID/shortId и полные конфиги маскируются в audit details рекурсивно.
- Xray/AWG конфиги изменяются только через adapter flow с file lock, timestamped backup, проверкой mtime и restore при ошибке.
- `XRAY_CONFIG_PATH` и `AWG_CONFIG_PATH` не должны быть symlink: бот останавливает такие пути, чтобы root-run процесс не писал в неожиданный target.
- File lock на config bounded: если другой процесс держит lock, операция падает с понятной ошибкой `config lock busy`, а не ждёт бесконечно.
- Backup-файлы конфигов создаются с правами `600`; количество хранимых backup ограничивает `CONFIG_BACKUP_KEEP_LAST`.
- SQLite DB и директории data/logs получают приватные права на Linux, если бот управляет этими путями.
- При старте бот пытается безопасно восстановить зависшие статусы `pending_apply`, `apply_failed`, `pending_revoke`, `pending_delete`, `delete_failed`. Если reconciliation для Xray или AWG завершается с ошибкой, мутирующие операции этого backend переходят в degraded mode до ручной проверки и перезапуска.
- Опасные действия в боте требуют confirm/cancel.
- Чужие конфиги доступны только владельцу или `SUPERADMIN`.
- Пользовательские заметки к ключам являются private owner note: владелец видит и редактирует свою заметку, `SUPERADMIN` не видит и не перезаписывает чужую private note.
- Объявления отправляются всем non-blocked пользователям, включая pending/approved/admin, но исключая заблокированных.

## Linux permission QA

POSIX mode preservation tests are skipped on Windows. Run this check on Ubuntu 24 VDS/CI:

```bash
.venv/bin/python -m pytest -q tests/test_followup_hardening.py -k mode
```

Expected result: main Xray/AWG config files keep their original owner/group/mode after mutation or rollback (for example `0644` stays `0644`), while generated backup files are `0600`.

## Допущения

- Xray-ссылка генерируется как VLESS Reality.
- Если `XRAY_INBOUND_TAG` пустой, допускается только один VLESS/Reality inbound.
- AWG adapter добавляет только bot-managed `[Peer]` блоки с маркерами `vpn-bot peer start/end`.
- AWG unmanaged peer с `AllowedIPs` subnet внутри `AWG_NETWORK` резервирует весь диапазон subnet для allocator; subnet вне `AWG_NETWORK` игнорируется для allocation.
- AWG IP переиспользуется только после статусов `revoked`, `deleted` или `failed`.
- R01 (`/start` в группах) сознательно закрыт продуктово запретом приглашения бота в группы.
- R34 (proxy password как shared secret) является ожидаемым поведением продукта.
