# VPN Telegram Bot

Telegram-бот для управления доступом к self-hosted VPN на Ubuntu VDS. Бот управляет пользователями, одобрением заявок, ключами Xray VLESS Reality, ключами AmneziaWG, отзывом/удалением ключей, записями аудита и базовой статистикой трафика.

Проект рассчитан на развёртывание на одном сервере без Docker, Redis, PostgreSQL и тяжёлых ORM.

## Возможности

- Регистрация пользователей в Telegram и процесс одобрения доступа.
- Панель администратора: заявки, пользователи, выдача ключей, аудит, статистика, объявления.
- Создание ключей Xray VLESS Reality, доставка конфигурации, отзыв, удаление и сверка при запуске.
- Создание ключей AmneziaWG, доставка конфигурации клиента, отзыв, удаление, выделение IP и сверка при запуске.
- Отдельный раздел «Прокси» в Telegram для автоматической выдачи SOCKS5/Dante и ссылок Telegram MTProto Proxy.
- MTProto поддерживает режим совместимости `static` и режим `managed` с персональными секретами для каждого пользователя, safe apply и rollback.
- Опциональный модуль WARP-сокрытия исходящего IP: серверный AmneziaWG-туннель (`out-warp`), скрывающий outbound IP сервера для выбранных приложений-шпионов, с автоматическим health-based fallback. Выключен по умолчанию; см. [WARP: сокрытие исходящего IP](#warp-сокрытие-исходящего-ip).
- Опциональная таблица legacy-записей прокси, заполняемая из `DEFAULT_PROXY_*`, используется только как внутреннее хранилище для совместимости; пользовательский интерфейс прокси работает через `proxy_accesses`.
- Проверки владельца: пользователи могут просматривать собственные конфигурации и статистику; деструктивные операции с VPN и прокси доступны только администраторам.
- Audit log с рекурсивной маскировкой чувствительных значений.
- Хранилище SQLite с миграциями из `db/schema.sql`.
- Ротируемые локальные логи в `LOG_DIR`.
- Развёртывание через systemd: `deploy/vpn-bot.service`.
- Целевая платформа: Ubuntu VDS с установленными Xray и/или AmneziaWG.

## Stack

- Python 3.12 (3.12.x)
- aiogram 3
- SQLite via aiosqlite
- python-dotenv
- systemd
- Xray VLESS Reality
- AmneziaWG / WireGuard-совместимые инструменты
- Ubuntu / Linux VDS

## Структура репозитория

```text
main.py                    # Точка входа бота
init_db.py                 # Инициализация/миграция схемы SQLite
requirements.txt           # Runtime-зависимости
constraints.txt            # Зафиксированные версии зависимостей для production
.env.example               # Шаблон переменных окружения
db/schema.sql              # Схема базы данных
deploy/vpn-bot.service     # Шаблон systemd-юнита vpn-bot
deploy/run-mtproxy-managed # Wrapper MTProxy для managed-режима, устанавливается при деплое
deploy/mtproxy-vpnbot-managed.conf # Systemd drop-in для MTProxy, устанавливается при деплое
bot/                       # Telegram handlers, keyboards, FSM, форматирование
services/                  # Бизнес-логика и управление правами доступа
repositories/              # Слой доступа к SQLite
adapters/                  # Адаптеры для Xray, AWG, systemctl, backup, shell
warp/                      # Модуль WARP-сокрытия исходящего IP (туннель, маршруты, health-монитор)
scripts/                   # sudo-хелперы vpnbot-warp-*
config/settings.py         # Разбор переменных окружения и валидация
tests/                     # Регрессионные тесты и hardening-тесты
```

## Предупреждение о безопасности

Проект работает с VPN-ключами и секретами Telegram. Никогда не коммитьте и не публикуйте:

- Файлы `.env`.
- Токены Telegram-бота.
- Приватные ключи или preshared keys.
- Реальную конфигурацию сервера/клиента Xray Reality.
- Реальную конфигурацию сервера/клиента AmneziaWG.
- Полные конфигурации VPN-клиентов.
- Базы данных SQLite или их дампы.
- IP-адреса серверов в сочетании с credentials.
- Credentials от SSH, панелей управления, хостинга и другого серверного доступа.
- Рекомендуемая настройка BotFather: отключите добавление бота в группы. Бот рассчитан на работу только в личных чатах; групповые чаты могут раскрыть данные пользователей, действия администраторов или конфиденциальные сообщения.

Используйте `.env.example` только как шаблон. Храните production-конфигурацию на сервере, вне истории Git.

## Переменные окружения

Скопируйте `.env.example` в `.env` и замените placeholder'ы реальными значениями. `BOT_TOKEN` и `ADMIN_IDS` обязательны для запуска. Заполните соответствующие поля Xray или AWG перед выдачей ключей нужного типа.

```dotenv
BOT_TOKEN=<telegram_bot_token>
ADMIN_IDS=<telegram_user_id>,<telegram_user_id>

DB_PATH=/opt/vpn-service/data/vpn.db
SQLITE_SYNCHRONOUS=FULL
LOG_DIR=/opt/vpn-service/logs
BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock

# Режим root+api (по умолчанию): PRIVILEGE_HELPERS_ENABLED=false или не указывать. Не-root режим: установить true и указать пути ниже.
PRIVILEGE_HELPERS_ENABLED=false
HELPER_STAGING_ROOT=/run/vpn-bot
SOCKS5_USER_HELPER_PATH=/usr/local/sbin/vpnbot-socks5-user
XRAY_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-xray-apply
AWG_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-awg-apply
MTPROTO_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-mtproxy-apply

XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json
XRAY_SERVICE_NAME=xray
XRAY_APPLY_MODE=api
XRAY_INBOUND_TAG=vless-in
XRAY_PUBLIC_HOST=<vpn_public_host>
XRAY_PUBLIC_PORT=443
XRAY_REALITY_PUBLIC_KEY=<xray_reality_public_key>
XRAY_SNI=<xray_reality_sni>
XRAY_FLOW=xtls-rprx-vision
XRAY_FINGERPRINT=chrome
XRAY_NETWORK_TYPE=tcp
XRAY_SHORT_ID=<xray_short_id>
XRAY_MANAGE_SHORT_IDS=false
XRAY_ALLOW_RESTART_ON_ROLLBACK=false
XRAY_STATS_SERVER=127.0.0.1:10085

AWG_CONFIG_PATH=/etc/amnezia/amneziawg/awg0.conf
AWG_INTERFACE=awg0
AWG_NETWORK=10.0.0.0/24
AWG_SERVER_ADDRESS=10.0.0.1
AWG_ENDPOINT_HOST=<awg_endpoint_host>
AWG_ENDPOINT_PORT=<awg_endpoint_port>
AWG_SERVER_PUBLIC_KEY=<awg_server_public_key>
AWG_DNS=1.1.1.1
AWG_MTU=
AWG_ALLOWED_IPS=0.0.0.0/0, ::/0
AWG_PERSISTENT_KEEPALIVE=25
AWG_USE_PRESHARED_KEY=true

DEFAULT_PROXY_TYPE=
DEFAULT_PROXY_HOST=
DEFAULT_PROXY_PORT=
DEFAULT_PROXY_LOGIN=
DEFAULT_PROXY_PASSWORD=
DEFAULT_PROXY_NOTE=

SOCKS5_ENABLED=false
SOCKS5_HOST=
SOCKS5_PORT=31337
SOCKS5_LOGIN_PREFIX=vpn_socks_
SOCKS5_SYSTEM_USER_SHELL=/usr/sbin/nologin
SOCKS5_SERVICE_NAME=danted
SOCKS5_PUBLIC_NAME=SOCKS5 Proxy
SOCKS5_NOTE=SOCKS5 Dante proxy on VDS

MTPROTO_ENABLED=false
MTPROTO_MODE=static
MTPROTO_HOST=
MTPROTO_PORT=8443
MTPROTO_SECRET=
MTPROTO_PUBLIC_NAME=Telegram MTProto Proxy
MTPROTO_NOTE=MTProto proxy for Telegram

# MTProto managed-режим с персональными секретами
MTPROTO_SERVICE_NAME=mtproxy
MTPROTO_BINARY_PATH=/usr/local/bin/mtproto-proxy
MTPROTO_RUN_USER=mtproxy
MTPROTO_RUN_GROUP=mtproxy
MTPROTO_CONFIG_DIR=/etc/mtproxy
MTPROTO_PROXY_SECRET_PATH=/etc/mtproxy/proxy-secret
MTPROTO_PROXY_MULTI_CONF_PATH=/etc/mtproxy/proxy-multi.conf
MTPROTO_MANAGED_DIR=/etc/mtproxy/vpnbot
MTPROTO_MANAGED_SECRETS_PATH=/etc/mtproxy/vpnbot/managed-secrets.json
MTPROTO_MANAGED_ENV_PATH=/etc/mtproxy/vpnbot/mtproxy.env
MTPROTO_MANAGED_WRAPPER_PATH=/opt/vpn-service/scripts/run-mtproxy-managed
MTPROTO_BACKUP_DIR=/etc/mtproxy/vpnbot/backups
MTPROTO_INTERNAL_STATS_PORT=8888
MTPROTO_WORKERS=1
MTPROTO_APPLY_TIMEOUT_SECONDS=10
MTPROTO_ROLLBACK_ON_APPLY_FAILURE=true
MTPROTO_KEEP_LAST_BACKUPS=10
MTPROTO_STATS_URL=

AUDIT_RETENTION_DAYS=180
CONFIG_BACKUP_KEEP_LAST=20

BOT_LANGUAGE=ru
```

### Полный справочник переменных окружения

Все переменные из `config/settings.py`. Переменные, помеченные **Обязательна**, должны быть заданы до запуска; остальные имеют указанное значение по умолчанию.

> ⚠️ **Security-sensitive переменные** помечены 🔒. Никогда не коммитьте их; храните на сервере в `.env` (режим `0600`, только root).

Полная таблица переменных — в [английском README](README.md#complete-environment-variable-reference);
все переменные также представлены в `.env.example`. Краткая справка по
дополнительным (тонким) настройкам:

| Переменная | По умолчанию | Описание |
|---|---|---|
| `BOT_DROP_PENDING_UPDATES` | `false` | Сбросить очередь Telegram-обновлений при запуске. |
| `BOT_LANGUAGE` | `ru` | Язык UI бота: `ru` или `en`. |
| `HEALTH_HOST` | `127.0.0.1` | Хост HTTP-эндпоинта проверки работоспособности (опционально). |
| `HEALTH_PORT` | _(отключён)_ | Порт HTTP-эндпоинта. Не указывать для отключения. |
| `AWG_STATS_INTERVAL` | `60` | Интервал (сек) сбора статистики трафика AWG (0–3600). |
| `KEY_EXPIRY_CHECK_INTERVAL` | `1800` | Как часто (сек) проверять истечение ключей (0–86400). |
| `KEY_EXPIRY_NOTIFY_DAYS` | _(пусто)_ | Дни до истечения для уведомления пользователя, через запятую. Например: `7,3,1`. |
| `KEY_MAX_TRIAL_DAYS` | `365` | Максимальная длительность (дней) пробных VPN-ключей (1–3650). |
| `OFFSITE_BACKUP_ENCRYPTION_KEY` | _(отключён)_ | 🔒 Fernet-ключ для шифрования резервных копий DB. Оставьте пустым для отключения. |
| `OFFSITE_BACKUP_INTERVAL` | `604800` | Интервал (сек) между загрузками резервных копий. По умолчанию — 7 дней. |
| `ANOMALY_CHECK_INTERVAL` | `300` | Как часто (сек) запускать анализ аномалий (0–86400). |
| `ANOMALY_WINDOW_SECONDS` | `3600` | Окно наблюдения за трафиком (сек). |
| `ANOMALY_MIN_UNIQUE_IPS` | `3` | Мин. уникальных source IP в окне для флага. |
| `ANOMALY_AUTO_REVOKE` | `false` | Автоматически отзывать помеченные ключи без подтверждения администратора. |
| `ANOMALY_COOLDOWN_SECONDS` | `7200` | Cooldown перед повторным флагом того же ключа (сек). |
| `ANOMALY_CONCURRENT_WINDOW_SECONDS` | `600` | Окно для обнаружения одновременных соединений (сек). |
| `XRAY_XHTTP_ENABLED` | `false` | Включить второй VLESS-транспорт (XHTTP) через REALITY catch-all fallback `vless-in` на loopback-inbound. При включении создание ключа предлагает выбор VLESS (TCP) / VLESS (HTTP). |
| `XRAY_XHTTP_INBOUND_TAG` | `vless-xhttp-reality` | Тег loopback XHTTP-inbound (fallback-dest) в `config.json` (должен отличаться от `XRAY_INBOUND_TAG`). Обязателен при `XRAY_XHTTP_ENABLED=true`. |
| `XRAY_XHTTP_PORT` | `8443` | Оставлен для обратной совместимости; **не** используется при построении ссылок VLESS (HTTP). Ссылка идёт через публичный порт `vless-in` (`XRAY_PUBLIC_PORT`); XHTTP-inbound слушает loopback как fallback-dest REALITY. |
| `XRAY_XHTTP_PATH` | `/v1/messages/stream` | Путь XHTTP для ссылок VLESS (HTTP); должен совпадать с `xhttpSettings.path` inbound (валидируется на inbound, не в fallback). |
| `XRAY_XHTTP_MODE` | `stream-one` | Клиентский режим XHTTP в ссылках VLESS (HTTP): `auto`, `packet-up`, `stream-up`, `stream-one`. По умолчанию `stream-one` (одна full-duplex h2-сессия, чище всего для direct REALITY); `packet-up` — переключаемая опция для троттлинга на длинных сессиях или прохода через CDN. |
| `XRAY_ACCESS_LOG_PATH` | _(пусто)_ | Путь к access-логу Xray для обнаружения аномалий. |
| `XRAY_HELPER_STAGING_DIR` | `$HELPER_STAGING_ROOT/xray` | Staging-каталог для файлов Xray-хелпера. |
| `AWG_HELPER_STAGING_DIR` | `$HELPER_STAGING_ROOT/awg` | Staging-каталог для файлов AWG-хелпера. |
| `MTPROTO_HELPER_STAGING_DIR` | `$HELPER_STAGING_ROOT/mtproxy` | Staging-каталог для файлов MTProto-хелпера. |

> **XHTTP fallback topology.** У VLESS (HTTP) нет собственного публичного порта:
> `vless-in` (`:443`) терминирует REALITY и через **дефолтный catch-all** `fallback`
> (`{ "dest": 8001, "xver": 0 }`, без `path`) форвардит на loopback XHTTP-inbound
> (`security: none`); путь валидируется на этом inbound. Path-based fallback **не** матчит
> HTTP/2 XHTTP — h2 `:path` лежит в HPACK, а не в request-line — поэтому catch-all
> обязателен. Топология заводится один раз вручную; см.
> [`docs/xray-xhttp-inbound.md`](docs/xray-xhttp-inbound.md).

Примечания:

- Если `XRAY_INBOUND_TAG` пустой, адаптер использует первый inbound с `settings.clients`.
- Если `XRAY_MANAGE_SHORT_IDS=false`, необходимо указать `XRAY_SHORT_ID`.
- `XRAY_APPLY_MODE=api` — режим apply по умолчанию (развёртывание под root; добавляет/удаляет ключи без перезапуска Xray, поэтому соединения не обрываются). `restart`/`reload` используйте только в non-root режиме с privilege helpers — helper игнорирует `api`/`reload` и всегда перезапускает Xray.

> 📌 **Примечание для production — переключайте режим вручную для серьёзных развёртываний:**
> Дефолтный `XRAY_APPLY_MODE=api` запускает бота **под root** (`PRIVILEGE_HELPERS_ENABLED=false`) ради применения ключей без обрыва соединений. Это удобно, но бот остаётся привилегированным. Для серьёзного production-развёртывания **вручную переключитесь** на non-root модель с privilege helpers: задайте `PRIVILEGE_HELPERS_ENABLED=true`, `XRAY_APPLY_MODE=restart` (или `reload`), запускайте под `User=vpn-bot` и установите sudo-helpers. См. раздел «Обзор развёртывания».

> ⚠️ **ВАЖНО — XRAY_APPLY_MODE=api и развёртывание под root:**
> - `XRAY_APPLY_MODE=api` — **единственный** режим, позволяющий добавлять/удалять ключи Xray без перезапуска сервиса. Без него каждое создание или удаление ключа вызывает полный перезапуск Xray, обрывая все активные подключения.
> - `XRAY_APPLY_MODE=api` **несовместим** с `PRIVILEGE_HELPERS_ENABLED=true` — бот откажет в запуске, если оба параметра заданы одновременно.
> - Для api-режима бот **должен запускаться под root** (`User=root` в service-файле) с `PRIVILEGE_HELPERS_ENABLED=false`.
> - `deploy/vpn-bot.service` в репозитории — **авторитетный источник**: каждый деплой перезаписывает `/etc/systemd/system/vpn-bot.service` из него. Ручные правки системного service-файла теряются при следующем деплое. Файл в репозитории должен отражать актуальную production-конфигурацию.
> - См. раздел [Xray API Mode](#xray-api-mode) для необходимых переменных окружения и разовой настройки сервера.

- `XRAY_APPLY_MODE=api` несовместим с `PRIVILEGE_HELPERS_ENABLED=true`. При включённых privilege helpers бот применяет изменения конфигурации Xray через sudo-helper `vpnbot-xray-apply`, который всегда вызывает `systemctl restart xray`, игнорируя `XRAY_APPLY_MODE`. Используйте режим `restart` с helpers; режимы `reload` и `api` helper'ом не поддерживаются.
- `SQLITE_SYNCHRONOUS=FULL` — более безопасный вариант по умолчанию для этой control-plane базы данных. `NORMAL` быстрее, но может потерять последние зафиксированные транзакции при сбое ОС или питания, когда состояние VPN-backend уже изменилось.
- `AWG_CLIENT_DNS` поддерживается только как legacy-alias; для новых развёртываний используйте `AWG_DNS`.
- `AWG_ENDPOINT_HOST` и `AWG_ENDPOINT_PORT` должны указывать на публичный AWG endpoint, который будут использовать клиенты.
- `SOCKS5_ENABLED=true` требует `SOCKS5_HOST`, `SOCKS5_PORT` и безопасного `SOCKS5_LOGIN_PREFIX`. Dante должен быть уже установлен и слушать порт; бот только создаёт/блокирует/удаляет управляемых Linux-пользователей с этим префиксом.
- `MTPROTO_ENABLED=true` требует `MTPROTO_HOST`. `MTPROTO_MODE=static` также требует `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` — режим совместимости: бот показывает общий MTProto-секрет и может только деактивировать запись пользователя в SQLite. Настоящий per-user server-side revoke в static-режиме невозможен без ротации общего секрета.
- `MTPROTO_MODE=managed` создаёт уникальный секрет для каждого пользователя. В production helper-режиме бот размещает managed-файлы в `/run/vpn-bot/mtproxy`; `/usr/local/sbin/vpnbot-mtproxy-apply` записывает `/etc/mtproxy/vpnbot`, перезапускает `mtproxy`, проверяет работоспособность сервиса/порта и откатывает managed-файлы при ошибке apply. Systemd drop-in и wrapper устанавливаются при деплое, а не пишутся ботом в runtime.
- `MTPROTO_SECRET`, пароли SOCKS5 и реальные production-endpoints с credentials никогда не должны попадать в репозиторий. В `.env.example` секреты прокси намеренно оставлены пустыми.
- `DEFAULT_PROXY_*` — legacy-хранилище для совместимости, не управляет новым пользовательским proxy access flow.
- **Развёртывание под root с api-режимом** (текущий дефолт `deploy/vpn-bot.service`): `User=root`, `PRIVILEGE_HELPERS_ENABLED=false`, `XRAY_APPLY_MODE=api`. Бот пишет конфигурацию Xray и применяет изменения напрямую через Xray gRPC API; sudo-helpers не нужны. См. раздел [Xray API Mode](#xray-api-mode).
- **Альтернативное развёртывание без root (privilege helper mode, `User=vpn-bot`)**: Запускайте бота от имени `vpn-bot:vpn-bot` с `PRIVILEGE_HELPERS_ENABLED=true`. Root-only операции выполняются через фиксированные sudo-helpers, описанные в `deploy/helpers/README.md`. В этой модели используйте `XRAY_APPLY_MODE=restart` или `reload`; api-режим при включённых helpers не поддерживается.
- Код проекта, файлы деплоя, `.env` и `.venv` должны быть недоступны для записи от имени сервисного аккаунта. В root-режиме доступны все пути; в не-root режиме запись разрешена только в `/opt/vpn-service/data`, `/opt/vpn-service/logs` (если включены файловые логи) и `/run/vpn-bot`.
- `BOT_LANGUAGE=ru` — язык бота. Поддерживаемые значения: `ru` (по умолчанию) и `en`.

## Xray API Mode

> ⚠️ **ВАЖНО — `XRAY_APPLY_MODE=api` требует root и несовместим с privilege helpers:**
> - `XRAY_APPLY_MODE=api` — **единственный** режим, позволяющий добавлять/удалять ключи Xray без перезапуска сервиса Xray. Без него каждое создание или удаление ключа вызывает полный перезапуск Xray, обрывая все активные подключения.
> - `XRAY_APPLY_MODE=api` **несовместим** с `PRIVILEGE_HELPERS_ENABLED=true` — бот откажет в запуске, если оба параметра заданы одновременно.
> - Для api-режима бот **должен запускаться под root** (`User=root` в service-файле) с `PRIVILEGE_HELPERS_ENABLED=false`.
> - `deploy/vpn-bot.service` в репозитории — **авторитетный источник**: каждый деплой перезаписывает `/etc/systemd/system/vpn-bot.service` из него. Ручные правки системного service-файла теряются при следующем деплое. Файл в репозитории должен отражать актуальную production-конфигурацию.

### Переменные .env для api-режима

```dotenv
XRAY_APPLY_MODE=api
XRAY_INBOUND_TAG=vless-in          # должен совпадать с полем "tag" VLESS inbound в config.json
XRAY_STATS_SERVER=127.0.0.1:10085  # должен совпадать с портом API inbound dokodemo-door
```

Также установите `PRIVILEGE_HELPERS_ENABLED=false` (или не указывайте) при использовании api-режима.

### Разовая подготовка сервера

Перед запуском бота в api-режиме настройте Xray API inbound и задайте тег VLESS inbound в `/usr/local/etc/xray/config.json`:

1. Добавьте `"tag": "vless-in"` к объекту VLESS inbound (используйте тег, совпадающий с `XRAY_INBOUND_TAG`):

```json
{
  "inbounds": [
    {
      "tag": "vless-in",
      "port": 443,
      "protocol": "vless",
      "...": "..."
    }
  ]
}
```

2. Убедитесь, что блок Xray API и `dokodemo-door` API inbound присутствуют в `config.json`. Порт должен совпадать с `XRAY_STATS_SERVER`:

```json
{
  "api": {
    "tag": "api",
    "services": ["HandlerService", "StatsService", "LoggerService"]
  },
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    }
  ],
  "routing": {
    "rules": [
      { "inboundTag": ["api-in"], "outboundTag": "api", "type": "field" }
    ]
  }
}
```

3. Перезапустите Xray один раз, чтобы тег вступил в силу, и проверьте конфигурацию:

```bash
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo systemctl restart xray
sudo systemctl status xray --no-pager
```

4. Установите service-файл и запустите бота:

```bash
sudo cp deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot
```

`deploy/vpn-bot.service` уже содержит `User=root`, `ProtectSystem=false` и не имеет ограничений `ReadWritePaths` — ручные правки service-файла не нужны.

## Политика жизненного цикла доступа

- Одобренные пользователи могут создавать собственные ключи Xray/AWG, просматривать свои активные конфигурации и статистику, редактировать заметки к своим ключам.
- Одобренные пользователи могут получать и просматривать собственный SOCKS5/MTProto proxy access при включённом backend.
- Revoke/delete для ключей Xray и AWG доступны только администраторам. Обычные пользователи не видят кнопки отзыва/удаления, а прямые callback/service-вызовы отклоняются.
- Revoke/delete для SOCKS5 и MTProto proxy access доступны только администраторам. Страница прокси для пользователей только выдаёт/показывает активный доступ и статистику.
- Блокировка пользователя — действие администратора. Она блокирует доступ к боту и пытается отозвать активные/проблемные VPN-ключи и SOCKS5/MTProto proxy access.
- В `MTPROTO_MODE=static` блокировка/отзыв только деактивирует запись в боте/SQLite; скопированный общий секрет продолжает работать до ротации.
- В `MTPROTO_MODE=managed` admin revoke удаляет MTProto-секрет этого пользователя из управляемого active list, не затрагивая других пользователей.

## Backend Degraded Mode

Бот помечает backend как DEGRADED, когда сверка или post-apply компенсация не могут подтвердить, что SQLite и серверный runtime безопасно изменять автоматически. DEGRADED специфичен для каждого backend:

- Xray DEGRADED блокирует только Xray create/revoke/delete/manual reconcile.
- AWG DEGRADED блокирует только AWG create/revoke/delete/manual reconcile.
- SOCKS5 DEGRADED блокирует только SOCKS5 issue/revoke/delete.
- MTProto DEGRADED блокирует только MTProto issue/revoke/delete.
- Остальные backends продолжают работать, если они не находятся в состоянии DEGRADED.

В панели администратора есть раздел «Диагностика backend», показывающий `OK` или `DEGRADED` для Xray, AWG, SOCKS5 и MTProto с причиной без секретных деталей. Для полного контекста проверьте `journalctl -u vpn-bot`, строки audit log, lifecycle-статусы в SQLite и конфигурацию/runtime backend, описанные в runbook'ах ниже. Для восстановления исправьте состояние сервера из резервных копий или путём ручной проверки, затем перезапустите `vpn-bot`, чтобы startup reconciliation заново проверила backend.

## Заметки по развёртыванию прокси

Бот не устанавливает Dante или MTProxy. Подготовьте их на VDS заранее, затем включите соответствующие флаги в окружении.

Требования к SOCKS5/Dante:

- Dante слушает на настроенном публичном host/порту, например `0.0.0.0:31337`.
- Аутентификация — через логин/пароль системного Linux-пользователя.
- В production процесс бота не вызывает инструменты управления аккаунтами напрямую. Он использует `sudo -n /usr/local/sbin/vpnbot-socks5-user ...`; только helper имеет право вызывать `getent`, `useradd`, `chpasswd`, `passwd -l` и `userdel`.
- Бот отказывается управлять Linux-пользователями, логин которых не начинается с `SOCKS5_LOGIN_PREFIX`.

MTProto static mode:

- Установите `MTPROTO_MODE=static` и задайте `MTPROTO_SECRET`.
- MTProxy управляется вне бота через собственный systemd unit.
- В static-режиме бот не редактирует файлы MTProxy.
- Вывод для пользователя всегда содержит обе Telegram-ссылки: сначала обычный секрет, затем вариант с random padding `dd`.
- Static-режим использует общий секрет; блокировка одного пользователя деактивирует только запись в боте и не отзывает доступ на уровне сервера.

MTProto managed mode:

- Установите `MTPROTO_MODE=managed`; не задавайте общий production-секрет в `MTPROTO_SECRET` для новых пользователей.
- MTProxy должен быть уже установлен и иметь рабочие файлы `proxy-secret` и `proxy-multi.conf`.
- Установите managed wrapper/drop-in один раз при деплое. Модель по умолчанию — root-wrapper: wrapper запускается от root; systemd запускает wrapper под root, wrapper читает managed env/секреты, доступные только root, и запускает `mtproto-proxy` с `-u mtproxy` из `MTPROTO_RUN_USER`, чтобы процесс прокси сбрасывал привилегии изнутри.
  ```bash
  sudo install -m 700 -d /opt/vpn-service/scripts
  sudo install -m 700 deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed
  sudo install -m 700 -d /etc/systemd/system/mtproxy.service.d
  sudo install -m 600 deploy/mtproxy-vpnbot-managed.conf /etc/systemd/system/mtproxy.service.d/vpnbot-managed.conf
  sudo install -m 700 -d /etc/mtproxy/vpnbot /etc/mtproxy/vpnbot/backups
  sudo chown root:root /opt/vpn-service/scripts/run-mtproxy-managed /etc/mtproxy/vpnbot /etc/mtproxy/vpnbot/backups
  sudo /opt/vpn-service/.venv/bin/python - <<'PY'
  import json, secrets
  from pathlib import Path
  managed = Path("/etc/mtproxy/vpnbot")
  placeholder = secrets.token_hex(16)
  (managed / "managed-secrets.json").write_text(json.dumps({
      "version": 1,
      "generation": 0,
      "managed_by": "vpn-bot",
      "secrets": [],
      "runtime_secrets": [{"secret": placeholder, "fingerprint": "empty-placeholder", "purpose": "empty-placeholder"}],
  }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
  (managed / "mtproxy.env").write_text(
      "MTPROTO_BINARY_PATH=/usr/local/bin/mtproto-proxy\n"
      "MTPROTO_RUN_USER=mtproxy\n"
      "MTPROTO_RUN_GROUP=mtproxy\n"
      "MTPROTO_PROXY_SECRET_PATH=/etc/mtproxy/proxy-secret\n"
      "MTPROTO_PROXY_MULTI_CONF_PATH=/etc/mtproxy/proxy-multi.conf\n"
      "MTPROTO_MANAGED_SECRETS_PATH=/etc/mtproxy/vpnbot/managed-secrets.json\n"
      "MTPROTO_PORT=8443\n"
      "MTPROTO_INTERNAL_STATS_PORT=8888\n"
      "MTPROTO_WORKERS=1\n",
      encoding="utf-8",
  )
  PY
  sudo chmod 600 /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
  sudo chown root:root /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
  sudo systemctl daemon-reload
  sudo systemctl restart mtproxy
  sudo systemctl status mtproxy --no-pager
  sudo ss -tlnp | grep 8443
  ```
- Drop-in очищает любые существующие `User=`/`Group=` из `mtproxy.service`; вывод `systemctl show mtproxy -p User -p Group -p ExecStart` должен показывать пустые `User`/`Group` и `ExecStart=/opt/vpn-service/scripts/run-mtproxy-managed`.
- Если `MTPROTO_MANAGED_WRAPPER_PATH` или `MTPROTO_MANAGED_ENV_PATH` отличаются от значений по умолчанию, отредактируйте установленный wrapper/drop-in при деплое и вручную выполните `systemctl daemon-reload`.
- Не устанавливайте `MTPROTO_MODE=managed` в `vpn-bot`, пока управляемая baseline-конфигурация выше не перезапустится успешно и `mtproxy` не будет активен/слушает порт. Issue/revoke откажут, если `MTPROTO_MANAGED_SECRETS_PATH` или `MTPROTO_MANAGED_ENV_PATH` отсутствуют, поэтому первый apply helper'а всегда имеет known-good файлы для rollback.
- Во время работы бот размещает MTProxy-кандидаты в `/run/vpn-bot/mtproxy`. Helper `/usr/local/sbin/vpnbot-mtproxy-apply` валидирует эти файлы, записывает `MTPROTO_MANAGED_SECRETS_PATH`, записывает `MTPROTO_MANAGED_ENV_PATH`, поддерживает `MTPROTO_BACKUP_DIR/<backup-id>/`, перезапускает `mtproxy`, проверяет `systemctl is-active`, проверяет, что `MTPROTO_PORT` слушает, и восстанавливает предыдущие managed-файлы при ошибке apply.
- Обычные issue/revoke не пишут в `/etc/systemd/system` и не запускают `systemctl daemon-reload`; устанавливайте или обновляйте MTProxy unit/drop-in вручную при деплое.
- Managed mode обеспечивает реальный per-user revoke: удаляется только секрет конкретного пользователя из active MTProxy list. Секреты других пользователей остаются в managed-файле.
- Сырые MTProto-секреты не отображаются в статусе администратора, audit log, логах, README или `.env.example`; диагностика администратора использует только счётчики и fingerprint'ы.
- Managed secrets и env-файлы: root:root `0600`; директории backup: root:root `0700`; файлы backup, содержащие секреты: root:root `0600`; wrapper: root:root `0700`; systemd drop-in не содержит секретов и может быть root:root `0600`.

Проверки видимости секретов в MTProto managed mode:

- `systemctl cat mtproxy` и `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment` должны показывать только пути к wrapper/env, но не сырые секреты. В дефолтной root-wrapper модели `User` и `Group` пусты на уровне сервиса.
- `journalctl -u vpn-bot` и `journalctl -u mtproxy` не должны содержать сырых MTProto-секретов; бот маскирует данные audit/ошибок, а wrapper не выводит секреты. Если ваша сборка MTProxy логирует принятые секреты или сгенерированные ссылки, не используйте managed mode, пока логирование не отключено или бинарник не заменён.
- Официальный бинарник `mtproto-proxy` принимает клиентские секреты как аргументы `-S <secret>`. Это означает, что сырые секреты могут быть видны в argv процесса для root и для непривилегированных пользователей, если `/proc` не защищён. Ограничьте shell-доступ, рассмотрите монтирование `/proc` с `hidepid=2` и не включайте managed mode с этим бинарником, если требование — «сырые MTProto-секреты никогда не видны при инспекции процессов на уровне root».

Ручной rollback для MTProto managed mode:

1. Остановите `vpn-bot`.
2. Проверьте `MTPROTO_BACKUP_DIR`, по умолчанию `/etc/mtproxy/vpnbot/backups`.
3. Восстановите предыдущие managed secrets/env-файлы из последнего known-good backup, если автоматический rollback не сработал.
4. Выполните `sudo systemctl restart mtproxy`.
5. Проверьте `sudo systemctl status mtproxy --no-pager` и `sudo ss -tlnp | grep 8443`.

Статистика прокси — это lifecycle/accounting-статистика из SQLite: выдано, активно, отозвано/деактивировано, временные метки, статус, причина, ошибка. Бот не придумывает per-user трафик для Dante или MTProxy. Без per-login accounting в Dante или надёжного агрегированного stats endpoint для MTProxy трафик отображается как недоступный.

## WARP: сокрытие исходящего IP

Опциональный серверный модуль, который скрывает исходящий IP сервера для выбранных
приложений-шпионов: направляет их трафик через AmneziaWG-туннель (`out-warp`), так
что их соединения выходят с endpoint туннеля, а не с реального IP сервера, и
автоматически переключается на прямой выход, когда туннель недоступен. **Выключен по
умолчанию** и ничего не делает, пока superadmin не загрузит конфиг и не включит модуль
из админ-панели (📡 WARP-туннель).

Как это работает:

1. `awg-quick up` поднимает интерфейс `out-warp` из `/etc/amnezia/out-warp.conf`.
2. Через `out-warp` добавляются системные маршруты `ip route` для CIDR из конфига.
3. Фоновая asyncio-задача пингует туннель каждые 10 с. После **2** провалов подряд
   маршруты снимаются (трафик → напрямую); после **3** успехов подряд —
   восстанавливаются.
4. Выключение модуля снимает маршруты и опускает интерфейс.

Бот работает непривилегированно: каждое root-действие проходит через sudo-хелперы
`vpnbot-warp-*`. Системный DNS-резолвер не трогается. Маршруты по умолчанию
(`0.0.0.0/0`, `::/0`) в `AllowedIPs` молча пропускаются routes-хелпером, чтобы не
изолировать хост случайно — при пропуске хелпер пишет предупреждение. Если нужен
full-tunnel, настройте отдельную таблицу маршрутизации и policy-правила вне бота,
а не через `AllowedIPs`.

### Формат конфига

Загрузите клиентский конфиг **AmneziaWG** (не обычный WireGuard) как документ
`.conf`. Он должен содержать `[Interface]`/`[Peer]`, `PrivateKey`/`PublicKey`/
`Endpoint`, поля обфускации AmneziaWG (`Jc`, `S1`, `S2`, …) и непустой
`AllowedIPs`. Модуль уводит в туннель **всех AmneziaWG-клиентов** (`10.0.0.0/24`),
так что исходящий IP клиентов — это endpoint WARP, а не реальный IP сервера, при
этом сам хост (SSH, бот, обновления) всегда остаётся на прямом пути. Используйте
full-tunnel `AllowedIPs = 0.0.0.0/0, ::/0`, чтобы `Table = auto` построил
маршрут по умолчанию туннеля. `AllowedIPs` никогда не изменяется: install-хелпер
дословно извлекает его в `/etc/amnezia/out-warp-routes.list` (один CIDR на строку,
сохраняется для счётчика маршрутов в админ-панели).

> **Примечание:** хост защищён по дизайну — `vpnbot-warp-routes` снимает
> host-bypass awg-quick сразу после подъёма интерфейса и ставит одно узкое правило
> `from 10.0.0.0/24`, поэтому full-tunnel `AllowedIPs` никогда не утянет хост (или
> вашу SSH-сессию) в туннель. Хелпер делает самопроверку и откатывается к прямому
> выходу клиентов, если она не прошла.

При установке хелпер удаляет любую строку `DNS = …`, принудительно ставит
`Table = auto` в `[Interface]` (обязательно — это задаёт fwmark WG-сокета и
динамическую таблицу маршрутизации; прежний `Table = off` создавал петлю
маршрутизации) и добавляет `PersistentKeepalive = 25` в `[Peer]`, если их нет.

### Установка

`awg-quick`/`awg` (userspace-инструменты AmneziaWG) должны быть установлены в
`/usr/bin/awg-quick` / `/usr/bin/awg`. Установите хелперы и выдайте sudo
(см. `deploy/helpers/README.md` и `deploy/sudoers.d/vpnbot.example`):

```bash
install -o root -g root -m 0755 scripts/vpnbot-warp-install /usr/local/sbin/vpnbot-warp-install
install -o root -g root -m 0755 scripts/vpnbot-warp-iface   /usr/local/sbin/vpnbot-warp-iface
install -o root -g root -m 0755 scripts/vpnbot-warp-routes  /usr/local/sbin/vpnbot-warp-routes
install -o root -g root -m 0755 scripts/vpnbot-warp-status  /usr/local/sbin/vpnbot-warp-status
install -o root -g root -m 0440 deploy/sudoers.d/vpnbot.example /etc/sudoers.d/vpnbot
visudo -cf /etc/sudoers.d/vpnbot
```

Если `awg-quick` отсутствует, модуль отказывается стартовать и показывает понятную
ошибку в админ-панели.

### Переменные окружения WARP

По умолчанию совпадают с путями из шаблона sudoers. Смена `WARP_CONFIG_PATH` или
`WARP_INTERFACE` требует согласованного обновления `/etc/sudoers.d/vpnbot` и
скриптов `vpnbot-warp-*`; рассогласование вызывает молчаливые сбои sudo. Меняйте,
только если понимаете, что делаете.

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `WARP_CONFIG_PATH` | `/etc/amnezia/out-warp.conf` | Путь установленного конфига туннеля |
| `WARP_INTERFACE` | `out-warp` | Имя интерфейса AmneziaWG |
| `WARP_INSTALL_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-install` | Хелпер установки конфига |
| `WARP_IFACE_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-iface` | Хелпер up/down интерфейса |
| `WARP_ROUTES_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-routes` | Хелпер add/del маршрутов |
| `WARP_STATUS_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-status` | Хелпер `awg show` |
| `WARP_HELPER_STAGING_DIR` | `/run/vpn-bot/warp` | Приватный каталог для staged-загрузок |
| `WARP_PING_TARGET` | `162.159.140.245` | ICMP-цель, которую health-монитор пингует для определения up/down туннеля. По умолчанию — Cloudflare anycast, присутствующий в типичных `AllowedIPs` WARP. Переопределите, если ваш `AllowedIPs` не покрывает этот адрес, иначе монитор будет давать ложные провалы. |
| `WARP_MONITOR_OBSERVER_MODE` | `true` | Когда `true` (по умолчанию), health-монитор бота только **наблюдает** за туннелем (пробы, состояние в БД, уведомления админам) и никогда не трогает интерфейс и маршруты — ими владеет systemd (`awg-quick@out-warp` + `warp-routes.service`). Установите `false` только чтобы вернуть устаревшую модель, где бот сам поднимает/опускает интерфейс и добавляет/снимает маршруты. |
| `WARP_MONITOR_FAIL_THRESHOLD` | `4` | Сколько подряд неудачных проб нужно, прежде чем монитор объявит туннель упавшим и уведомит админов. Держится выше 1, чтобы одна потерянная ICMP-проба не вызывала ложную тревогу. |
| `WARP_MONITOR_SUCCESS_THRESHOLD` | `3` | Сколько подряд успешных проб нужно, прежде чем монитор объявит туннель восстановленным. |

#### Владение интерфейсом и маршрутами (observer mode)

В режиме observer (по умолчанию) у интерфейса `out-warp` и его policy-маршрутов один владелец — **systemd**. Интерфейс поднимает `awg-quick@out-warp.service`, а policy-правила, default-маршрут в таблице 200 и метки по демонам ставит `warp-routes.service`; health-монитор бота — чистый наблюдатель: он сообщает о состоянии туннеля, но никогда не запускает `awg-quick`, `ip route` или `ip rule`. Это убирает флаппинг, возникавший, когда `warp-routes.service` (на загрузке) и монитор бота боролись за одни и те же записи `ip rule`/`ip route`. Тумблер WARP в админ-панели теперь запускает/останавливает **только** наблюдающий монитор — его выключение больше не роняет туннель и не стирает маршруты.

Разверните оба юнита (сначала интерфейс, затем маршруты поверх него):

```bash
# awg-quick резолвит имя "out-warp" в /etc/amnezia/amneziawg/out-warp.conf, а install-хелпер
# пишет канонический конфиг в /etc/amnezia/out-warp.conf — направьте имя на него симлинком:
mkdir -p /etc/amnezia/amneziawg
ln -sf /etc/amnezia/out-warp.conf /etc/amnezia/amneziawg/out-warp.conf
systemctl enable --now awg-quick@out-warp
systemctl enable --now warp-routes.service
```

## Обзор развёртывания

> ⚠️ **ВАЖНО — `deploy/vpn-bot.service` является авторитетным источником:**
> Каждый деплой копирует `deploy/vpn-bot.service` дословно в `/etc/systemd/system/vpn-bot.service`. Ручные правки системного service-файла перезаписываются при следующем деплое. Текущий файл в репозитории запускает бота как `User=root` с `ProtectSystem=false` для работы в `XRAY_APPLY_MODE=api`. При смене модели развёртывания сначала обновите `deploy/vpn-bot.service` — не редактируйте системный файл напрямую.

Поставляемый systemd unit ожидает проект в `/opt/vpn-service`. Если развёртываете в другое место, обновите `deploy/vpn-bot.service` перед установкой.

**Root deployment model (текущий дефолт — api mode, `User=root`):**

Файл сервиса в репозитории уже настроен для root+api mode. См. раздел [Xray API Mode](#xray-api-mode) для необходимых переменных `.env` и разовой подготовки конфигурации Xray. Создавать системного пользователя `vpn-bot` или устанавливать sudo-helpers для этой модели не нужно.

**Non-root deployment model (privilege helper mode, `User=vpn-bot`):**

Обновите `deploy/vpn-bot.service`, установив `User=vpn-bot`, `Group=vpn-bot`, `ProtectSystem=strict` и восстановив `ReadWritePaths` перед деплоем. Затем выполните следующие шаги:

1. Держите `/opt/vpn-service`, файлы деплоя, `.env` и `.venv` под владением root/оператора, недоступными для записи от `vpn-bot`.
2. Создайте системную учётную запись `vpn-bot:vpn-bot`.
3. Предоставьте `vpn-bot` право на запись только в каталоги runtime-состояния: `/opt/vpn-service/data`, `/opt/vpn-service/logs` (если включены файловые логи) и `/run/vpn-bot`, создаваемый systemd.
4. Установите фиксированные helpers в `/usr/local/sbin` и установите `/etc/sudoers.d/vpnbot` только с этими точками входа.
5. Включите `PRIVILEGE_HELPERS_ENABLED=true`.
6. Установите `deploy/vpn-bot.service`.

Первичная установка:

```bash
sudo install -o root -g root -m 0755 -d /opt/vpn-service
sudo git clone https://github.com/Egor051/vpnbot.git /opt/vpn-service
cd /opt/vpn-service

sudo python3 -m venv .venv
sudo /opt/vpn-service/.venv/bin/pip install --upgrade pip
sudo /opt/vpn-service/.venv/bin/pip install -r requirements.txt -c constraints.txt

sudo deploy/create-vpn-bot-user.sh
sudo install -o vpn-bot -g vpn-bot -m 0700 -d /opt/vpn-service/data /opt/vpn-service/logs
sudo install -o root -g root -m 0600 .env.example .env
sudoedit .env
```

Установка helpers и sudoers:

```bash
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-socks5-user /usr/local/sbin/vpnbot-socks5-user
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-xray-apply /usr/local/sbin/vpnbot-xray-apply
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-awg-apply /usr/local/sbin/vpnbot-awg-apply
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-mtproxy-apply /usr/local/sbin/vpnbot-mtproxy-apply
sudo install -o root -g root -m 0440 deploy/sudoers.d/vpnbot.example /etc/sudoers.d/vpnbot
sudo visudo -cf /etc/sudoers.d/vpnbot
```

Установка и запуск systemd-сервиса:

```bash
python deploy/check-nonroot-helper-mode.py
sudo cp deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot
python deploy/check-nonroot-helper-mode.py
```

Не делайте рекурсивный chown всего дерева приложения на login-пользователя в production. Не давайте права на запись в checkout репозитория, файлы деплоя или `.venv` пользователю `vpn-bot`; скомпрометированный процесс бота не должен иметь возможности переписать собственный код, зависимости, units или исходники helpers.

Если включён `MTPROTO_MODE=managed`, держите `/etc/mtproxy/vpnbot` под владением root и управлением helper. Не предоставляйте `vpn-bot.service` права на запись в `/etc/systemd/system` или широкий write-доступ в `/etc/mtproxy`; устанавливайте или обновляйте MTProxy drop-in и wrapper вручную при деплое, затем запускайте `systemctl daemon-reload` вне runtime бота.

Чек-лист после деплоя:

1. `python deploy/check-nonroot-helper-mode.py` проходит.
2. `systemctl show vpn-bot -p User -p Group -p RuntimeDirectory -p NoNewPrivileges -p ReadWritePaths` показывает `vpn-bot`, `vpn-bot`, `vpn-bot`, без включённого `NoNewPrivileges` и только ожидаемые writable paths.
3. `sudo -u vpn-bot test ! -w /opt/vpn-service/.venv && sudo -u vpn-bot test ! -w /opt/vpn-service/deploy`.
4. `sudo visudo -cf /etc/sudoers.d/vpnbot` проходит и файл не содержит `NOPASSWD: ALL`.
5. Выдайте/отзовите один тестовый ключ Xray или AWG и один proxy access для включённого backend, затем проверьте `journalctl -u vpn-bot -n 100 --no-pager` на ошибки helper или утечку секретов.

## Локальные проверки

Установите runtime и dev-зависимости перед запуском проверок:

```bash
python -m pip install -r requirements.txt -c constraints.txt
python -m pip install -r requirements-dev.txt
```

Запустите те же проверки, что использует CI:

```bash
make audit   # python -m pip_audit -r requirements.txt -r constraints.txt (+ документированный список --ignore-vuln)
python -m ruff check .
python -m compileall .
python -m mypy --strict bot/ services/ adapters/ config/ models/ utils/ repositories/ main.py init_db.py
python -m pytest --cov=. --cov-report=term-missing --cov-fail-under=60
```

> Аудит игнорирует два advisory aiohttp (`CVE-2026-34993`, `CVE-2026-47265`),
> исправленные только в aiohttp 3.14.0 — который дерево не может принять, пока
> `aiogram` держит `aiohttp<3.14` — и которые не применимы к использованию бота
> (aiohttp только как клиент к доверённому хосту Telegram). Обоснование — в
> `Makefile` (`PIP_AUDIT_IGNORES`); пересмотрите, когда `aiogram` поднимет
> ограничение.

### Обновление зависимостей

После изменения `requirements.txt` или `requirements-dev.txt` пересоберите файлы
constraints и закоммитьте их:

```bash
make update-hashes   # запускать под Python 3.12 (единственный поддерживаемый runtime)
git add constraints.txt constraints-hashed.txt constraints-dev-hashed.txt
git commit -m "chore: update pinned constraints"
```

`make update-hashes` запускает `pip-compile --generate-hashes` для обоих
hashed-файлов, затем `sync-constraints`, который переписывает `constraints.txt`
как зеркало без хешей из `constraints-hashed.txt`. Всегда запускайте под
**Python 3.12**, чтобы разрешённый набор совпадал с runtime.

Зачем три файла:

- `constraints-hashed.txt` / `constraints-dev-hashed.txt` — то, что CI ставит с
  `--require-hashes`; сборка падает, если закоммиченные хеши не совпадают с тем,
  что отдаёт PyPI (защита от supply-chain-подмены).
- `constraints.txt` — зеркало без хешей, которое сканирует `pip-audit`.
  Генерируется из `constraints-hashed.txt` (вручную не редактируется), поэтому
  аудируемый набор не может разойтись с устанавливаемым.

## CI

GitHub Actions запускает локальные проверки без production-секретов и живых сервисов:

- `dependency-audit`: `make audit` (`pip_audit` по `requirements.txt` + `constraints.txt` за вычетом документированного списка `--ignore-vuln`) — блокирует job `tests` при обнаружении уязвимостей.
- `tests` (needs `dependency-audit`): Python 3.12 — установка зависимостей с `--require-hashes`, `ruff check .` (стиль, безопасность, bugbear), `compileall`, `mypy --strict`, `pytest ≥60% coverage`. Сторонние actions запиннены по commit-SHA.

## Обслуживание

Обновление с GitHub:

```bash
cd /opt/vpn-service
sudo git pull --ff-only
sudo /opt/vpn-service/.venv/bin/pip install -r requirements.txt -c constraints.txt
python deploy/check-nonroot-helper-mode.py
sudo systemctl restart vpn-bot
python deploy/check-nonroot-helper-mode.py
```

Не запускайте production DB-миграции от root против `/opt/vpn-service/data/vpn.db`. Сервис инициализирует схему/миграции при запуске от имени `vpn-bot`; если необходимо запустить `init_db.py` вручную, делайте это с той же непривилегированной учётной записью и окружением, что и сервис.

Проверка статуса:

```bash
sudo systemctl status vpn-bot
```

Перезапуск сервиса:

```bash
sudo systemctl restart vpn-bot
```

Просмотр логов:

```bash
sudo journalctl -u vpn-bot -f
tail -f /opt/vpn-service/logs/bot.log
```

## Production Operations Runbook

### Pre-deploy checklist

- `.env` существует, не закоммичен и доступен только оператору/root.
- Родительский каталог `DB_PATH` и `LOG_DIR` существуют и не доступны для чтения всем.
- Установленный systemd unit соответствует `deploy/vpn-bot.service`. В дефолтной конфигурации root+api: `User=root`, `Group=root`, `ProtectSystem=false`, `RuntimeDirectory=vpn-bot`, `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
- Для root+api mode: `PRIVILEGE_HELPERS_ENABLED=false` (или отсутствует), `XRAY_APPLY_MODE=api`, `XRAY_INBOUND_TAG` задан, `XRAY_STATS_SERVER` указывает на адрес Xray API. Для non-root helper mode: `PRIVILEGE_HELPERS_ENABLED=true`, пути helpers указывают на `/usr/local/sbin/vpnbot-*`, `/etc/sudoers.d/vpnbot` проходит `visudo -cf`.
- `python deploy/check-nonroot-helper-mode.py` проходит перед перезапуском сервиса.
- Конфигурация Xray существует по `XRAY_CONFIG_PATH` и валидна перед тем, как бот начнёт в неё писать.
- Конфигурация/интерфейс AWG существуют, если будут выдаваться AWG-ключи.
- Правила firewall известны перед открытием VPN-портов.
- Место назначения backup существует и файлы backup не доступны для чтения всем.
- Код, файлы деплоя и `.venv` недоступны для записи от `vpn-bot` или других недоверенных пользователей.
- Если включён managed MTProto, `vpn-bot.service` не имеет `ReadWritePaths=/etc/systemd/system`; MTProxy wrapper/drop-in установлены вручную и не содержат сырых секретов.
- Если включён managed MTProto, `/etc/mtproxy/vpnbot/managed-secrets.json`, `/etc/mtproxy/vpnbot/mtproxy.env` и `/etc/mtproxy/vpnbot/backups/*` доступны для чтения только root/операторам сервиса.

### Общая проверка работоспособности бота

```bash
cd /opt/vpn-service
python deploy/check-nonroot-helper-mode.py
sudo systemctl status vpn-bot --no-pager
sudo journalctl -u vpn-bot -n 100 --no-pager
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check;"
.venv/bin/python -m compileall .
.venv/bin/python -m pytest
```

### Package 7 Healthcheck — preflight, postflight и диагностика администратора

> ⚠️ **Примечание:** `deploy/check-nonroot-helper-mode.py` предназначен для **non-root privilege-helper deployment model** (`User=vpn-bot` + `PRIVILEGE_HELPERS_ENABLED=true`). Если вы используете **root+api mode** (`User=root` + `XRAY_APPLY_MODE=api`), этот checker сообщит `FAIL: User=root` — это ожидаемо и корректно для root deployment. Пропустите этот checker в root mode; используйте `systemctl status vpn-bot` и панель диагностики администратора.

`deploy/check-nonroot-helper-mode.py` — обязательный preflight и postflight инструмент для non-root privilege-separated deployment. Запускайте до и после каждого деплоя.

**Стандартный вывод (по умолчанию):**

```bash
cd /opt/vpn-service
python deploy/check-nonroot-helper-mode.py
```

Коды выхода:
- `0` — все проверки прошли (warnings информационные, не failures)
- `1` — одна или более проверок не прошла; устраните failures перед запуском или перезапуском сервиса

**Machine-readable JSON (для автоматизации/CI):**

```bash
python deploy/check-nonroot-helper-mode.py --json
```

JSON-формат: `{"overall": "ok|warning|failed", "failures": N, "warnings": N, "checks": [{"status": "ok|warning|failed", "message": "..."}]}`

**Pre-start mode (по умолчанию — до `systemctl start vpn-bot`):**

```bash
python deploy/check-nonroot-helper-mode.py --mode pre-start
```

В `pre-start` mode отсутствие `/run/vpn-bot` ожидаемо (systemd создаёт `RuntimeDirectory` при старте сервиса) и выдаёт warning, не failure.

**Post-start mode (после `systemctl start vpn-bot`):**

```bash
python deploy/check-nonroot-helper-mode.py --mode post-start
```

В `post-start` mode `/run/vpn-bot` должен существовать и быть writable для `vpn-bot`. Отсутствие — failure.

**Что проверяет checker (Package 5D + Package 7):**

- `vpn-bot.service` содержит `User=vpn-bot`, `Group=vpn-bot`, `RuntimeDirectory=vpn-bot`, `RuntimeDirectoryMode=0700`, `ProtectSystem=strict`
- `vpn-bot.service` не содержит `User=root`, `Group=root`, `NoNewPrivileges=true`
- `/etc/sudoers.d/vpnbot` root:root 0440, выдаёт права только на 4 фиксированных helper, без широких грантов (`NOPASSWD: ALL`, `ALL=(ALL)`)
- Бинарники helpers root:root 0755
- `/opt/vpn-service`, `.venv`, `deploy` не доступны для записи от `vpn-bot`
- Существование и writability `/run/vpn-bot` (зависит от mode)
- `.env` не world-readable и доступен для чтения от `vpn-bot`
- SQLite `PRAGMA quick_check`
- Синтаксическая проверка конфигурации Xray (`xray run -test -config`)
- Strip-проверка конфигурации AWG (`awg-quick strip`)
- MTProxy managed files читаемы и структурно корректны (JSON)
- `sudo -n <helper> status` выполняются успешно (проверка, что sudoers grants работают end-to-end)
- `systemctl is-active` для: `vpn-bot`, `xray`, `awg-quick@awg0`, `danted`, `mtproxy`

**Диагностика администратора в боте (по запросу):**

Откройте панель администратора в Telegram → *Диагностика backend*. Выполняется live read-only healthcheck и отображается:

```
Diagnostics  OK
2026-05-12 10:30:00 UTC

✓ Non-root OK (uid=1001)
✓ PRIVILEGE_HELPERS_ENABLED=true
✓ Xray: OK
✓ AWG: OK
✓ SOCKS5: OK
✓ MTProto: OK
✓ SQLite PRAGMA quick_check: ok
✓ vpn-bot: active
✓ xray: active
✓ awg-quick@awg0: active
...
```

Общий статус: `OK / WARNING / DEGRADED / FAILED`. Секреты, токены, приватные ключи и сырые hex-значения не показываются — только безопасный статус и причина.

**Ожидаемые sudo log-записи:**

При `PRIVILEGE_HELPERS_ENABLED=true` каждая привилегированная операция (Xray/AWG config apply, SOCKS5 user create/delete, MTProto secret apply) создаёт sudo log-запись вида:

```
vpn-bot : TTY=... ; PWD=... ; USER=root ; COMMAND=/usr/local/sbin/vpnbot-xray-apply apply ...
```

Эти записи **ожидаемы и нормальны**. Они подтверждают корректную работу least-privilege модели.

**Признаки, требующие rollback:**

- `FAIL: ... User=root` в выводе checker — сервис настроен на запуск под root (ожидаемо и корректно в root+api mode; failure только в non-root helper mode)
- `FAIL: ... NOPASSWD: ALL` — присутствует широкий sudo grant
- `FAIL: ... writable by vpn-bot` на каталогах кода/venv/deploy
- SQLite `PRAGMA quick_check` возвращает что-то кроме `ok`
- Бот запускается, выдаёт один ключ, но Xray/AWG сервис немедленно DEGRADED с ошибкой config apply
- `sudo -n <helper> status` возвращает permission errors — sudoers файл некорректен
- Бинарник helper не root:root 0755 — необходимо исправить до того, как бот сможет его использовать

При необходимости rollback см. раздел «Rollback после неудачного деплоя» ниже.

### Backup

Сделайте резервную копию как минимум этих файлов перед деплоями, миграциями и ручными правками backend:

```bash
sudo install -m 700 -d /root/vpn-service-backups
sudo tar --xattrs --acls -czf /root/vpn-service-backups/vpn-service-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  /opt/vpn-service/.env \
  /opt/vpn-service/data/vpn.db \
  /usr/local/etc/xray/config.json \
  /etc/amnezia/amneziawg/awg0.conf \
  /etc/mtproxy
sudo chmod 600 /root/vpn-service-backups/vpn-service-*.tar.gz
```

Включайте `/opt/vpn-service/logs` только если операционные логи нужны для анализа инцидентов. Обращайтесь со всеми backups как с конфиденциальными: они могут содержать токены Telegram, VPN-ключи, Xray UUID, AWG private/preshared keys и серверные endpoints.

### Восстановление

```bash
sudo systemctl stop vpn-bot
sudo tar -xzf /root/vpn-service-backups/<backup>.tar.gz -C /
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo awg-quick strip /etc/amnezia/amneziawg/awg0.conf >/dev/null
cd /opt/vpn-service
sudo install -o vpn-bot -g vpn-bot -m 0700 -d /opt/vpn-service/data /opt/vpn-service/logs
sudo chown -R vpn-bot:vpn-bot /opt/vpn-service/data /opt/vpn-service/logs
python deploy/check-nonroot-helper-mode.py
sudo systemctl start vpn-bot
sudo systemctl status vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

Если `awg-quick` недоступен, но на сервере используется `wg-quick`, запустите эквивалентную проверку `wg-quick strip`. Не запускайте `awg set`, `wg set`, `systemctl restart xray` и другие команды, изменяющие runtime-состояние, пока конфигурационные файлы не прошли read-only проверки.

### Firewall и открытые порты

- По возможности держите SSH открытым только для доверенных источников.
- Откройте публичный TCP-порт Xray, обычно `443/tcp`.
- Откройте публичный UDP-порт AWG endpoint из `AWG_ENDPOINT_PORT` или `ListenPort` в конфигурации AWG.
- Открывайте Dante/SOCKS только если намеренно развёртываете отдельный прокси с защитой.
- Держите `XRAY_STATS_SERVER` привязанным только к localhost, например `127.0.0.1:<port>`. Никогда не открывайте Xray stats API в интернет.
- Если политика UFW для перенаправленного трафика по умолчанию `deny`, явно разрешите трафик, необходимый AWG-клиентам.

Примеры read-only проверок:

```bash
sudo ufw status verbose
sudo ss -tulnp
```

### Read-only health checks

```bash
sudo systemctl status vpn-bot --no-pager
sudo systemctl status xray --no-pager
sudo systemctl status danted --no-pager
sudo ss -tlnp | grep 31337
sudo systemctl status mtproxy --no-pager
sudo ss -tlnp | grep 8443
sudo journalctl -u vpn-bot -n 100 --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo awg show
sudo awg-quick strip /etc/amnezia/amneziawg/awg0.conf >/dev/null
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check; SELECT status, key_type, COUNT(*) FROM vpn_keys GROUP BY status, key_type;"
```

Если `XRAY_STATS_SERVER` настроен локально, запрашивайте его только с сервера или localhost. После операций create/revoke/delete убедитесь, что статусы в DB бота, клиенты в Xray config, peers в AWG config и AWG runtime peers согласованы.

### Восстановление после деградации Xray

Xray DEGRADED блокирует только Xray create/revoke/delete/manual reconcile. AWG, SOCKS5 и MTProto продолжают работать, если они не деградированы отдельно.

```bash
sudo systemctl status xray --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo jq '[.inbounds[]?.settings.clients[]? | {email}]' /usr/local/etc/xray/config.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='xray' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Проверьте наличие ручных клиентов/orphan-записей, неудачных pending-статусов и синтаксических ошибок конфигурации. Восстановите из backup или удалите только подтверждённые bot-managed расхождения, затем перезапустите `vpn-bot` и повторно откройте диагностику backend в панели администратора.

### Восстановление после деградации AWG

AWG DEGRADED блокирует только AWG create/revoke/delete/manual reconcile. Xray, SOCKS5 и MTProto продолжают работать.

```bash
sudo systemctl status awg-quick@awg0 --no-pager
sudo awg show
sudo awk '/^# vpnbot key_id=|^PublicKey =|^AllowedIPs =/{print}' /etc/amnezia/amneziawg/awg0.conf
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='awg' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Не выводите AWG private keys или preshared keys в тикеты/чаты. Сравнивайте только public keys/client IP, исправляйте подтверждённые расхождения из backup или вручную, затем перезапустите `vpn-bot`.

### Восстановление после деградации SOCKS5

SOCKS5 DEGRADED блокирует только SOCKS5 issue/revoke/delete. Xray, AWG и MTProto продолжают работать.

```bash
sudo systemctl status danted --no-pager
getent passwd | awk -F: '$1 ~ /^vpn_socks_/ {print $1}'
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='socks5' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Убедитесь, что каждый управляемый Linux-пользователь начинается с `SOCKS5_LOGIN_PREFIX`; не выводите SOCKS5-пароли. Блокируйте/удаляйте только подтверждённых bot-managed «посторонних» пользователей, восстановите SQLite из backup при необходимости, затем перезапустите `vpn-bot`.

### Восстановление после деградации MTProto

MTProto DEGRADED блокирует только MTProto issue/revoke/delete. Xray, AWG и SOCKS5 продолжают работать.

```bash
sudo systemctl status mtproxy --no-pager
sudo jq '{secret_count: (.secrets | length), fingerprints: [.secrets[]?.fingerprint]}' /etc/mtproxy/vpnbot/managed-secrets.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='mtproto' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Не выводите сырые MTProto-секреты. В static-режиме per-user server-side revoke невозможен; ротируйте `MTPROTO_SECRET`, если необходимо инвалидировать скопированный общий секрет. В managed mode сравнивайте счётчики/fingerprints, восстановите managed-файлы из `/etc/mtproxy/vpnbot/backups` при необходимости, перезапустите `mtproxy`, затем перезапустите `vpn-bot`.

### Rollback после неудачного деплоя

> ⚠️ **Сначала сделайте backup.** Всегда создавайте резервную копию перед откатом кода (см. раздел [Резервное копирование](#резервное-копирование)). Откат кода не откатывает runtime-состояние — SQLite, конфигурация Xray и AWG требуют отдельного восстановления, если деплой уже их изменил.

**Шаг 1 — остановите сервис и создайте backup:**

```bash
sudo systemctl stop vpn-bot
sudo tar --xattrs --acls -czf /root/vpn-service-backups/pre-rollback-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  /opt/vpn-service/.env \
  /opt/vpn-service/data/vpn.db \
  /usr/local/etc/xray/config.json \
  /etc/amnezia/amneziawg/awg0.conf
sudo chmod 600 /root/vpn-service-backups/pre-rollback-*.tar.gz
```

**Шаг 2 — откатите код:**

```bash
cd /opt/vpn-service
git log --oneline -5
git reset --hard <previous_commit>
.venv/bin/pip install -r requirements.txt -c constraints.txt
```

`git reset --hard` отбрасывает все локальные изменения кода на сервере. Используйте только для отката нежелательного деплоя.

> **`init_db.py` только для чистых установок.** НЕ запускайте `init_db.py` при откате — он требует `BOT_TOKEN`/`ADMIN_IDS` и попытается применить прямые миграции к существующей базе данных. Бот сам применяет схему при старте; если предыдущая версия совместима по схеме, достаточно просто перезапустить сервис.

**Шаг 3 — восстановите runtime-состояние из backup, если деплой его изменил:**

```bash
# Восстановить SQLite DB
sudo tar -xzf /root/vpn-service-backups/pre-rollback-<timestamp>.tar.gz -C / opt/vpn-service/data/vpn.db

# Восстановить конфигурацию Xray и проверить
sudo tar -xzf /root/vpn-service-backups/pre-rollback-<timestamp>.tar.gz -C / usr/local/etc/xray/config.json
sudo xray run -test -config /usr/local/etc/xray/config.json

# Восстановить конфигурацию AWG
sudo tar -xzf /root/vpn-service-backups/pre-rollback-<timestamp>.tar.gz -C / etc/amnezia/amneziawg/awg0.conf
```

**Шаг 4 — запустите и проверьте:**

```bash
sudo systemctl start vpn-bot
sudo systemctl status vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

### Ручная проверка на VDS после исправлений

На тестовом пользователе перед production:

1. Создайте один Xray-ключ, убедитесь, что он активен в DB и присутствует в конфигурации Xray.
2. Отзовите и удалите Xray-ключ, убедитесь, что DB/config/runtime больше не предоставляют доступ.
3. Создайте один AWG-ключ, убедитесь, что DB, `awg0.conf` и `awg show` согласованы.
4. Отзовите и удалите AWG-ключ, убедитесь, что peer удалён из config и runtime.
5. Откройте «Прокси» от имени одобренного тестового пользователя, выдайте SOCKS5 после подтверждения и убедитесь, что сообщение содержит Host, Port, Login, Password и URL.
6. Выдайте MTProto после подтверждения и убедитесь, что обычная Telegram-ссылка идёт перед `dd`-ссылкой.
7. В `MTPROTO_MODE=managed` выдайте MTProto тестовому пользователю A и запишите только несекретный fingerprint/count из статуса администратора.
8. Выдайте MTProto тестовому пользователю B и убедитесь, что статус администратора показывает два активных managed MTProto access.
9. Заблокируйте или admin-revoke тестового пользователя A, затем убедитесь, что managed secrets file больше не содержит fingerprint A, а fingerprint B остаётся активным.
10. Убедитесь, что Telegram MTProto-ссылка пользователя B продолжает работать после отзыва пользователя A.
11. Симулируйте неудачный apply на staging, например временно направив `MTPROTO_SERVICE_NAME` на failing test unit или остановив проверку порта, затем выполните revoke/issue и убедитесь, что rollback восстанавливает предыдущие managed secrets/env-файлы и `mtproxy` возвращается в active/listening.
12. В `MTPROTO_MODE=static` заблокируйте пользователя и убедитесь, что MTProto деактивирован только в SQLite.
13. Убедитесь, что логи бота и audit-вывод не содержат SOCKS5-паролей, `MTPROTO_SECRET` или сырых managed MTProto-секретов.
14. Проверьте `systemctl cat mtproxy`, `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment` и `journalctl -u mtproxy -n 100 --no-pager` на отсутствие сырых MTProto-секретов.
15. Проверьте права managed-файлов:
    ```bash
    sudo stat -c '%U:%G %a %n' /opt/vpn-service/scripts/run-mtproxy-managed /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
    sudo find /etc/mtproxy/vpnbot/backups -maxdepth 2 -printf '%u:%g %m %p\n'
    ```
16. Отправьте объявление с одобренными, ожидающими и заблокированными тестовыми пользователями; его должны получить только одобренные пользователи и superadmin'ы.

## База данных

SQLite используется как локальный backend хранилища. По умолчанию путь к базе данных:

```text
/opt/vpn-service/data/vpn.db
```

`init_db.py` открывает базу данных и применяет инициализацию схемы/миграции. Бот также инициализирует базу данных при создании приложения.

Текущие таблицы схемы:

- `users`
- `access_requests`
- `vpn_keys`
- `trial_key_requests`
- `proxy_entries`
- `proxy_accesses`
- `audit_log`
- `vpn_key_traffic_stats`
- `announcement_batches`
- `announcement_deliveries`
- `protocol_modules`
- `warp_settings`

(`schema_meta` внутренне отслеживает применённую версию схемы.)

## Статус проекта

Ранний self-hosted проект. Пригоден для использования как специализированный бот управления VPN, но production-использование требует тщательной проверки, серверного тестирования, операционных резервных копий, дисциплины работы с секретами и hardening окружающей инфраструктуры Xray/AWG/сервера.

## Лицензия

MIT License. См. [LICENSE](LICENSE).
