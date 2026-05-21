# VPN Telegram Bot

Telegram-бот для управления доступом к самостоятельно развёрнутому VPN на Ubuntu VDS. Бот управляет пользователями, одобрением заявок, ключами Xray VLESS Reality, ключами AmneziaWG, отзывом/удалением ключей, записями аудита и базовой статистикой трафика.

Проект рассчитан на развёртывание на одном сервере без Docker, Redis, PostgreSQL и тяжёлых ORM.

## Возможности

- Регистрация пользователей в Telegram и процесс одобрения доступа.
- Панель администратора для обработки заявок, управления пользователями, выдачи ключей, аудита, статистики и объявлений.
- Создание ключей Xray VLESS Reality, доставка конфигурации, отзыв, удаление и сверка при запуске.
- Создание ключей AmneziaWG, доставка конфигурации клиента, отзыв, удаление, выделение IP-адресов и сверка при запуске.
- Отдельный раздел «Прокси» в Telegram для автоматической выдачи SOCKS5/Dante и ссылок Telegram MTProto Proxy.
- MTProto поддерживает режим совместимости `static` и режим `managed` с персональными секретами для каждого пользователя, безопасным применением изменений и откатом.
- Опциональная таблица устаревших записей прокси, заполняемая из `DEFAULT_PROXY_*`, используется только как внутреннее хранилище для совместимости; пользовательский интерфейс прокси работает через `proxy_accesses`.
- Проверки владельца: пользователи могут просматривать собственные конфигурации и статистику; деструктивные операции с VPN и прокси доступны только администраторам.
- Журнал аудита с рекурсивной маскировкой чувствительных значений.
- Хранилище SQLite с миграциями из `db/schema.sql`.
- Ротируемые локальные логи в `LOG_DIR`.
- Развёртывание через systemd с использованием `deploy/vpn-bot.service`.
- Целевая платформа: Ubuntu VDS с установленными Xray и/или AmneziaWG.

## Стек технологий

- Python 3.12+
- aiogram 3
- SQLite через aiosqlite
- python-dotenv
- systemd
- Xray VLESS Reality
- AmneziaWG / совместимые с WireGuard инструменты
- Ubuntu / Linux VDS

## Структура репозитория

```text
main.py                    # Точка входа бота
init_db.py                 # Точка входа для инициализации/миграции схемы SQLite
requirements.txt           # Зависимости для выполнения
constraints.txt            # Зафиксированные версии зависимостей для продакшена
.env.example               # Шаблон переменных окружения
db/schema.sql              # Схема базы данных
deploy/vpn-bot.service     # Шаблон systemd-юнита vpn-bot
deploy/run-mtproxy-managed # Обёртка MTProxy для управляемого режима, устанавливаемая при деплое
deploy/mtproxy-vpnbot-managed.conf # Drop-in для MTProxy, устанавливаемый при деплое
bot/                       # Хендлеры Telegram, клавиатуры, FSM, форматирование
services/                  # Бизнес-логика и управление правами доступа
repositories/              # Слой доступа к SQLite
adapters/                  # Адаптеры для Xray, AWG, systemctl, бэкапов, shell
config/settings.py         # Разбор переменных окружения и валидация
tests/                     # Регрессионные и нагрузочные тесты
```

## Предупреждение о безопасности

Проект работает с операционными VPN и секретами Telegram. Никогда не коммитьте и не публикуйте:

- Файлы `.env`.
- Токены Telegram-бота.
- Приватные ключи или общие ключи (preshared keys).
- Реальную конфигурацию сервера/клиента Xray Reality.
- Реальную конфигурацию сервера/клиента AmneziaWG.
- Полные конфигурации VPN-клиентов.
- Базы данных SQLite или дампы баз данных.
- IP-адреса серверов в сочетании с учётными данными.
- Учётные данные SSH, панелей управления, хостинга или иного серверного доступа.
- Рекомендуемая настройка BotFather: отключите добавление бота в группы. Бот рассчитан на работу только в личных чатах; групповые чаты могут раскрыть данные пользователей, действия администраторов или конфиденциальные операционные сообщения.

Используйте `.env.example` только как шаблон. Храните конфигурацию продакшена на сервере, вне истории Git.

## Переменные окружения

Скопируйте `.env.example` в `.env` и замените заглушки реальными значениями вашего сервера. `BOT_TOKEN` и `ADMIN_IDS` обязательны для запуска. Заполните соответствующие поля Xray или AWG перед выдачей ключей нужного типа.

```dotenv
BOT_TOKEN=<telegram_bot_token>
ADMIN_IDS=<telegram_user_id>,<telegram_user_id>

DB_PATH=/opt/vpn-service/data/vpn.db
SQLITE_SYNCHRONOUS=FULL
LOG_DIR=/opt/vpn-service/logs
BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock

# Режим root+api (по умолчанию): PRIVILEGE_HELPERS_ENABLED=false или не указывать. Непривилегированный режим: установить true и указать пути ниже.
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

# Управляемый режим MTProto с персональными секретами
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

Примечания:

- Если `XRAY_INBOUND_TAG` пустой, адаптер использует первый inbound с `settings.clients`.
- Если `XRAY_MANAGE_SHORT_IDS=false`, необходимо указать `XRAY_SHORT_ID`.
- `XRAY_APPLY_MODE=restart` — режим применения по умолчанию; `reload` используйте только если ваш юнит Xray надёжно обрабатывает reload.

> ⚠️ **ВАЖНО — XRAY_APPLY_MODE=api и развёртывание под root:**
> - `XRAY_APPLY_MODE=api` — **единственный** режим, позволяющий добавлять/удалять ключи Xray без перезапуска сервиса. Без него каждое создание или удаление ключа вызывает полный перезапуск Xray, что обрывает все активные подключения.
> - `XRAY_APPLY_MODE=api` **несовместим** с `PRIVILEGE_HELPERS_ENABLED=true` — бот откажет в запуске, если оба параметра установлены одновременно.
> - Для использования api-режима бот **должен запускаться под root** (`User=root` в service-файле) с `PRIVILEGE_HELPERS_ENABLED=false`.
> - `deploy/vpn-bot.service` в репозитории является **авторитетным источником** — каждый деплой перезаписывает `/etc/systemd/system/vpn-bot.service` из него. Ручные правки системного service-файла будут потеряны при следующем деплое. Файл в репозитории должен отражать актуальную конфигурацию продакшена.
> - Смотрите раздел [Режим Xray API](#режим-xray-api) для необходимых переменных окружения и единоразовой настройки сервера.

- `XRAY_APPLY_MODE=api` несовместим с `PRIVILEGE_HELPERS_ENABLED=true`. При включённых привилегированных помощниках бот применяет изменения конфигурации Xray через sudo-помощника `vpnbot-xray-apply`, который всегда вызывает `systemctl restart xray`, игнорируя `XRAY_APPLY_MODE`. Используйте режим `restart` с помощниками; режимы `reload` и `api` помощником не поддерживаются.
- `SQLITE_SYNCHRONOUS=FULL` — более безопасный вариант по умолчанию для этой управляющей базы данных. `NORMAL` быстрее, но может потерять последние закоммиченные транзакции при сбое ОС или питания, когда состояние VPN-бэкенда уже изменилось.
- `AWG_CLIENT_DNS` поддерживается только как устаревший алиас; для новых развёртываний используйте `AWG_DNS`.
- `AWG_ENDPOINT_HOST` и `AWG_ENDPOINT_PORT` должны указывать на публичный эндпоинт AWG, который будут использовать клиенты.
- `SOCKS5_ENABLED=true` требует `SOCKS5_HOST`, `SOCKS5_PORT` и безопасного `SOCKS5_LOGIN_PREFIX`. Dante должен быть уже установлен и слушать порт; бот только создаёт/блокирует/удаляет управляемых системных пользователей Linux с этим префиксом.
- `MTPROTO_ENABLED=true` требует `MTPROTO_HOST`. `MTPROTO_MODE=static` также требует `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` — режим совместимости: бот показывает общий секрет MTProto и может только деактивировать запись пользователя в SQLite. Настоящий отзыв доступа на уровне сервера для конкретного пользователя в статичном режиме невозможен без ротации общего секрета.
- `MTPROTO_MODE=managed` создаёт уникальный секрет для каждого пользователя. В продакшен-режиме с помощниками бот размещает управляемые файлы в `/run/vpn-bot/mtproxy`; `/usr/local/sbin/vpnbot-mtproxy-apply` записывает `/etc/mtproxy/vpnbot`, перезапускает `mtproxy`, проверяет работоспособность сервиса/порта и откатывает управляемые файлы при ошибке применения. Drop-in для systemd и обёртка устанавливаются при деплое, а не записываются ботом во время работы.
- `MTPROTO_SECRET`, пароли SOCKS5 и реальные продакшен-эндпоинты с учётными данными никогда не должны коммититься. В `.env.example` секреты прокси намеренно оставлены пустыми.
- `DEFAULT_PROXY_*` — устаревшее совместимостное хранилище, не управляющее новым пользовательским UX прокси-доступа.
- **Развёртывание под root с api-режимом** (текущий дефолт `deploy/vpn-bot.service`): `User=root`, `PRIVILEGE_HELPERS_ENABLED=false`, `XRAY_APPLY_MODE=api`. Бот записывает конфигурацию Xray и применяет изменения напрямую через gRPC API Xray; sudo-помощники не нужны. Смотрите раздел [Режим Xray API](#режим-xray-api).
- **Альтернативное развёртывание без root с привилегированными помощниками**: Запускайте бота от имени `vpn-bot:vpn-bot` с `PRIVILEGE_HELPERS_ENABLED=true`. Операции, требующие root, выполняются через фиксированные sudo-помощники, описанные в `deploy/helpers/README.md`. В этой модели используйте `XRAY_APPLY_MODE=restart` или `reload`; api-режим при включённых помощниках не поддерживается.
- Код проекта, файлы деплоя, `.env` и `.venv` должны быть недоступны для записи от имени сервисного аккаунта. В root-режиме доступны все пути; в непривилегированном режиме запись должна быть разрешена только в `/opt/vpn-service/data`, `/opt/vpn-service/logs` (если включены файловые логи) и `/run/vpn-bot`.
- `BOT_LANGUAGE=ru` — язык бота. Поддерживаемые значения: `ru` (по умолчанию) и `en`.

## Режим Xray API

> ⚠️ **ВАЖНО — `XRAY_APPLY_MODE=api` требует root и несовместим с привилегированными помощниками:**
> - `XRAY_APPLY_MODE=api` — **единственный** режим, позволяющий добавлять/удалять ключи Xray без перезапуска сервиса Xray. Без него каждое создание или удаление ключа вызывает полный перезапуск Xray, что обрывает все активные подключения.
> - `XRAY_APPLY_MODE=api` **несовместим** с `PRIVILEGE_HELPERS_ENABLED=true` — бот откажет в запуске, если оба параметра установлены одновременно.
> - Для использования api-режима бот **должен запускаться под root** (`User=root` в service-файле) с `PRIVILEGE_HELPERS_ENABLED=false`.
> - `deploy/vpn-bot.service` в репозитории является **авторитетным источником** — каждый деплой перезаписывает `/etc/systemd/system/vpn-bot.service` из него. Ручные правки системного service-файла будут потеряны при следующем деплое. Файл в репозитории должен отражать актуальную конфигурацию продакшена.

### Необходимые переменные .env для api-режима

```dotenv
XRAY_APPLY_MODE=api
XRAY_INBOUND_TAG=vless-in          # должен совпадать с полем "tag" VLESS-inbound в config.json
XRAY_STATS_SERVER=127.0.0.1:10085  # должен совпадать с портом API-inbound dokodemo-door
```

Также установите `PRIVILEGE_HELPERS_ENABLED=false` (или не указывайте его) при использовании api-режима.

### Единоразовая подготовка сервера

Перед запуском бота в api-режиме настройте API-inbound Xray и присвойте тег VLESS-inbound в `/usr/local/etc/xray/config.json`:

1. Добавьте `"tag": "vless-in"` к объекту VLESS-inbound (используйте любой тег, совпадающий с `XRAY_INBOUND_TAG`):

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

2. Убедитесь, что блок Xray API и `dokodemo-door` API-inbound присутствуют в `config.json`. Порт должен совпадать с `XRAY_STATS_SERVER`:

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

- Одобренные пользователи могут создавать собственные ключи Xray/AWG, просматривать свои активные конфигурации, статистику и редактировать заметки к своим ключам.
- Одобренные пользователи могут получать и просматривать собственный SOCKS5/MTProto прокси-доступ при включённом бэкенде.
- Отзыв/удаление ключей Xray и AWG доступны только администраторам. Обычные пользователи не видят кнопки отзыва/удаления, а прямые вызовы через callback/сервис отклоняются.
- Отзыв/удаление SOCKS5 и MTProto прокси-доступа доступны только администраторам. Страница прокси для пользователей только выдаёт/показывает активный доступ и статистику.
- Блокировка пользователя — действие администратора. Она блокирует доступ к боту и пытается отозвать активные/проблемные VPN-ключи и SOCKS5/MTProto прокси-доступ.
- В `MTPROTO_MODE=static` блокировка/отзыв только деактивирует запись в боте/SQLite; скопированный общий секрет продолжает работать до ротации.
- В `MTPROTO_MODE=managed` отзыв администратором удаляет MTProto-секрет этого пользователя из управляемого активного списка, не затрагивая других пользователей.

## Деградированный режим бэкенда

Бот помечает бэкенд как ДЕГРАДИРОВАН (DEGRADED), когда сверка или компенсация после применения не могут подтвердить, что SQLite и серверный рантайм безопасно мутировать автоматически. DEGRADED специфичен для каждого бэкенда:

- Xray DEGRADED блокирует только создание/отзыв/удаление Xray и ручную сверку Xray.
- AWG DEGRADED блокирует только создание/отзыв/удаление AWG и ручную сверку AWG.
- SOCKS5 DEGRADED блокирует только выдачу/отзыв/удаление SOCKS5.
- MTProto DEGRADED блокирует только выдачу/отзыв/удаление MTProto.
- Остальные бэкенды продолжают работать, если они не находятся в состоянии DEGRADED.

В панели администратора есть раздел «Диагностика backend», показывающий `OK` или `DEGRADED` для Xray, AWG, SOCKS5 и MTProto с непривилегированной причиной. Для полного контекста проверьте `journalctl -u vpn-bot`, строки аудита, статусы жизненного цикла SQLite и конфигурацию/рантайм бэкенда, описанные в runbook'ах ниже. Для восстановления исправьте состояние сервера из резервных копий или путём ручной проверки, затем перезапустите `vpn-bot`, чтобы сверка при запуске могла повторно проверить бэкенд.

## Заметки по развёртыванию прокси

Бот не устанавливает Dante или MTProxy. Подготовьте их на VDS заранее, затем включите соответствующие флаги в окружении.

Требования к SOCKS5/Dante:

- Dante слушает на настроенном публичном хосте/порту, например `0.0.0.0:31337`.
- Аутентификация — через логин/пароль системного пользователя Linux.
- Процесс бота в продакшене не вызывает инструменты управления аккаунтами напрямую. Он использует `sudo -n /usr/local/sbin/vpnbot-socks5-user ...`; только помощник имеет право вызывать `getent`, `useradd`, `chpasswd`, `passwd -l` и `userdel`.
- Бот отказывается управлять системными пользователями Linux, логин которых не начинается с `SOCKS5_LOGIN_PREFIX`.

Статичный режим MTProto:

- Установите `MTPROTO_MODE=static` и укажите `MTPROTO_SECRET`.
- MTProxy управляется вне бота через собственный systemd-юнит.
- В статичном режиме бот не редактирует файлы MTProxy.
- Вывод для пользователя всегда содержит обе ссылки Telegram: сначала обычный секрет, затем вариант с random padding `dd`.
- Статичный режим использует общий секрет; блокировка одного пользователя деактивирует только запись в боте и не отзывает доступ на уровне сервера.

Управляемый режим MTProto:

- Установите `MTPROTO_MODE=managed`; не задавайте общий производственный секрет в `MTPROTO_SECRET` для новых пользователей.
- MTProxy должен быть уже установлен и иметь рабочие файлы `proxy-secret` и `proxy-multi.conf`.
- Установите управляемую обёртку/drop-in один раз при деплое. Модель по умолчанию — root-wrapper: обёртка запускается от root; systemd запускает обёртку под root, обёртка читает управляемые env/секреты, доступные только root, и запускает `mtproto-proxy` с `-u mtproxy` из `MTPROTO_RUN_USER`, чтобы процесс прокси сбрасывал привилегии изнутри.
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
- Если `MTPROTO_MANAGED_WRAPPER_PATH` или `MTPROTO_MANAGED_ENV_PATH` отличаются от значений по умолчанию, отредактируйте установленную обёртку/drop-in при деплое и вручную выполните `systemctl daemon-reload`.
- Не устанавливайте `MTPROTO_MODE=managed` в `vpn-bot`, пока описанная выше управляемая базовая конфигурация не перезапустится успешно и `mtproxy` не будет активен/слушает порт. Выдача/отзыв откажут, если `MTPROTO_MANAGED_SECRETS_PATH` или `MTPROTO_MANAGED_ENV_PATH` отсутствуют, поэтому первое применение помощника всегда имеет известные рабочие файлы для отката.
- Во время работы непривилегированный бот размещает кандидатов MTProxy в `/run/vpn-bot/mtproxy`. Помощник `/usr/local/sbin/vpnbot-mtproxy-apply` валидирует staged-файлы, записывает `MTPROTO_MANAGED_SECRETS_PATH`, записывает `MTPROTO_MANAGED_ENV_PATH`, поддерживает `MTPROTO_BACKUP_DIR/<backup-id>/`, перезапускает `mtproxy`, проверяет `systemctl is-active`, проверяет, что `MTPROTO_PORT` слушает, и восстанавливает предыдущие управляемые файлы при ошибке применения.
- Обычная выдача/отзыв не записывают в `/etc/systemd/system` и не запускают `systemctl daemon-reload`; устанавливайте или обновляйте юнит/drop-in MTProxy вручную при деплое.
- Управляемый режим обеспечивает реальный отзыв на уровне пользователя путём удаления только его секрета из активного списка MTProxy. Секреты других пользователей остаются в управляемом файле.
- Сырые MTProto-секреты не отображаются в статусе администратора, аудите, логах, README или `.env.example`; диагностика администратора использует только счётчики и fingerprint'ы.
- Управляемые секреты и env-файлы имеют права root:root `0600`; директории бэкапов — root:root `0700`; файлы бэкапов, которые могут содержать секреты, — root:root `0600`; обёртка — root:root `0700`; drop-in для systemd не содержит секретов и может быть root:root `0600`.

Проверки видимости управляемого режима MTProto:

- `systemctl cat mtproxy` и `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment` должны показывать только пути к обёртке/env, но не сырые секреты. В модели root-wrapper по умолчанию `User` и `Group` пусты на уровне сервиса.
- `journalctl -u vpn-bot` и `journalctl -u mtproxy` не должны содержать сырых MTProto-секретов; бот маскирует данные аудита/ошибок, а обёртка не выводит секреты. Если ваша сборка MTProxy логирует принятые секреты или сгенерированные ссылки, не используйте управляемый режим, пока логирование не отключено или бинарник не заменён.
- Официальный бинарник `mtproto-proxy` принимает клиентские секреты как аргументы `-S <secret>`. Это означает, что сырые секреты могут быть видны в argv процесса для root и для непривилегированных пользователей, если `/proc` не защищён. Ограничьте shell-доступ, рассмотрите монтирование `/proc` с `hidepid=2` и не включайте управляемый режим с этим бинарником, если требование — «сырые MTProto-секреты никогда не видны при инспекции процесса на уровне root».

Ручной откат управляемого MTProto:

1. Остановите `vpn-bot`.
2. Проверьте `MTPROTO_BACKUP_DIR`, по умолчанию `/etc/mtproxy/vpnbot/backups`.
3. Восстановите предыдущие управляемые секреты/env-файлы из последнего известного рабочего бэкапа, если автоматический откат не восстановил работу.
4. Выполните `sudo systemctl restart mtproxy`.
5. Проверьте `sudo systemctl status mtproxy --no-pager` и `sudo ss -tlnp | grep 8443`.

Статистика прокси — это статистика жизненного цикла и учёта из SQLite: выдано, активно, отозвано/деактивировано, временные метки, статус, причина и ошибка. Бот не выдумывает трафик для конкретных пользователей Dante или MTProxy. Без поучётного логирования Dante или безопасного агрегированного эндпоинта статистики MTProxy трафик отображается как недоступный.

## Обзор процесса развёртывания

> ⚠️ **ВАЖНО — `deploy/vpn-bot.service` является авторитетным источником:**
> Каждый деплой копирует `deploy/vpn-bot.service` дословно в `/etc/systemd/system/vpn-bot.service`. Ручные правки системного service-файла будут перезаписаны при следующем деплое. Текущий файл в репозитории запускает бота как `User=root` с `ProtectSystem=false` для работы в `XRAY_APPLY_MODE=api`. Если вы меняете модель развёртывания, сначала обновите `deploy/vpn-bot.service` — не редактируйте системный файл напрямую.

Поставляемый юнит systemd ожидает проект в `/opt/vpn-service`. Если развёртываете в другое место, обновите `deploy/vpn-bot.service` перед установкой.

**Модель развёртывания под root (текущий дефолт — api-режим, `User=root`):**

Файл сервиса в репозитории уже настроен для режима root+api. Смотрите раздел [Режим Xray API](#режим-xray-api) для необходимых переменных `.env` и единоразовой подготовки конфигурации Xray. Создавать системного пользователя `vpn-bot` или устанавливать sudo-помощники для этой модели не нужно.

**Модель развёртывания без root (режим привилегированных помощников, `User=vpn-bot`):**

Обновите `deploy/vpn-bot.service`, установив `User=vpn-bot`, `Group=vpn-bot`, `ProtectSystem=strict` и восстановив `ReadWritePaths` перед деплоем. Затем выполните следующие шаги:

1. Держите `/opt/vpn-service`, файлы деплоя, `.env` и `.venv` под владением root/оператора, недоступными для записи от `vpn-bot`.
2. Создайте системную учётную запись `vpn-bot:vpn-bot`.
3. Предоставьте `vpn-bot` право на запись только в каталоги рантайм-состояния: `/opt/vpn-service/data`, `/opt/vpn-service/logs` (если включены файловые логи) и `/run/vpn-bot`, создаваемый systemd.
4. Установите фиксированные помощники в `/usr/local/sbin` и установите `/etc/sudoers.d/vpnbot` только с этими точками входа помощников.
5. Включите `PRIVILEGE_HELPERS_ENABLED=true`.
6. Установите `deploy/vpn-bot.service`.

Краткое описание первичной установки:

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

Установка помощников и sudoers:

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

Не делайте рекурсивный chown всего дерева приложения на логин-пользователя в продакшене. Не давайте права на запись в чекаут репозитория, файлы деплоя или `.venv` пользователю `vpn-bot`; скомпрометированный процесс бота не должен иметь возможности переписать собственный код, зависимости, юниты или исходники помощников.

Если включён `MTPROTO_MODE=managed`, держите `/etc/mtproxy/vpnbot` под владением root и управлением помощника. Не предоставляйте `vpn-bot.service` права на запись в `/etc/systemd/system` или широкий доступ на запись в `/etc/mtproxy`; устанавливайте или обновляйте drop-in и обёртку MTProxy вручную при деплое, затем запускайте `systemctl daemon-reload` вне рантайма бота.

Чек-лист после деплоя:

1. `python deploy/check-nonroot-helper-mode.py` проходит.
2. `systemctl show vpn-bot -p User -p Group -p RuntimeDirectory -p NoNewPrivileges -p ReadWritePaths` показывает `vpn-bot`, `vpn-bot`, `vpn-bot`, без включённого `NoNewPrivileges` и только ожидаемые пути для записи.
3. `sudo -u vpn-bot test ! -w /opt/vpn-service/.venv && sudo -u vpn-bot test ! -w /opt/vpn-service/deploy`.
4. `sudo visudo -cf /etc/sudoers.d/vpnbot` проходит и файл не содержит `NOPASSWD: ALL`.
5. Выдайте/отзовите один тестовый ключ Xray или AWG и один прокси-доступ для включённого бэкенда, затем проверьте `journalctl -u vpn-bot -n 100 --no-pager` на наличие ошибок помощника или утечки секретов.

## Локальные проверки

Установите зависимости для выполнения и разработки перед запуском проверок:

```bash
python -m pip install -r requirements.txt -c constraints.txt
python -m pip install -r requirements-dev.txt
```

Запустите те же основные проверки, что использует CI:

```bash
python -m ruff check . --select=E9,F63,F7,F82
python -m compileall .
python -m pytest
python -m pip_audit -r requirements.txt -r constraints.txt --no-deps
```

## CI-проверки

GitHub Actions запускает локальные проверки без продакшен-секретов и живых сервисов:

- Python 3.12: установка зависимостей для выполнения и разработки, `python -m ruff check . --select=E9,F63,F7,F82`, `python -m compileall .`, `python -m mypy` и `python -m pytest`.
- Аудит зависимостей на Python 3.12: `python -m pip_audit -r requirements.txt -r constraints.txt --no-deps`.

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

Не запускайте миграции продакшен-БД от root против `/opt/vpn-service/data/vpn.db`. Сервис инициализирует схему/миграции при запуске от имени `vpn-bot`; если необходимо запустить `init_db.py` вручную, делайте это с той же непривилегированной учётной записью и окружением, что и сервис.

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

## Runbook по операционной эксплуатации

### Предеплойный чек-лист

- `.env` существует, не закоммичен и доступен только оператору/root.
- Родительский каталог `DB_PATH` и `LOG_DIR` существуют и не доступны для чтения всем.
- Установленный юнит systemd соответствует `deploy/vpn-bot.service`. В конфигурации root+api по умолчанию: `User=root`, `Group=root`, `ProtectSystem=false`, `RuntimeDirectory=vpn-bot`, `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
- Для режима root+api: `PRIVILEGE_HELPERS_ENABLED=false` (или отсутствует), `XRAY_APPLY_MODE=api`, `XRAY_INBOUND_TAG` задан, `XRAY_STATS_SERVER` указывает на адрес Xray API. Для непривилегированного режима с помощниками: `PRIVILEGE_HELPERS_ENABLED=true`, пути помощников указывают на `/usr/local/sbin/vpnbot-*`, `/etc/sudoers.d/vpnbot` проходит `visudo -cf`.
- `python deploy/check-nonroot-helper-mode.py` проходит перед перезапуском сервиса.
- Конфигурация Xray существует по `XRAY_CONFIG_PATH` и валидна перед тем, как бот начнёт в неё писать.
- Конфигурация/интерфейс AWG существуют, если будут выдаваться AWG-ключи.
- Правила файрвола известны перед открытием VPN-портов.
- Место назначения бэкапов существует и файлы бэкапов не доступны для чтения всем.
- Код, файлы деплоя и `.venv` недоступны для записи от `vpn-bot` или других недоверенных пользователей.
- Если включён управляемый MTProto, `vpn-bot.service` не имеет `ReadWritePaths=/etc/systemd/system`; обёртка/drop-in MTProxy установлены вручную и не содержат сырых секретов.
- Если включён управляемый MTProto, `/etc/mtproxy/vpnbot/managed-secrets.json`, `/etc/mtproxy/vpnbot/mtproxy.env` и `/etc/mtproxy/vpnbot/backups/*` доступны для чтения только root/операторам сервиса.

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

### Восстановление после деградации Xray

Xray DEGRADED блокирует только создание/отзыв/удаление Xray и ручную сверку. AWG, SOCKS5 и MTProto продолжают работать, если они не деградированы отдельно.

```bash
sudo systemctl status xray --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo jq '[.inbounds[]?.settings.clients[]? | {email}]' /usr/local/etc/xray/config.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='xray' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Проверьте наличие ручных клиентов/orphan-записей, неудачных статусов pending и синтаксических ошибок конфигурации. Восстановите из бэкапа или удалите только подтверждённые расхождения, управляемые ботом, затем перезапустите `vpn-bot` и повторно откройте диагностику бэкенда в панели администратора.

### Восстановление после деградации AWG

AWG DEGRADED блокирует только создание/отзыв/удаление AWG и ручную сверку. Xray, SOCKS5 и MTProto продолжают работать.

```bash
sudo systemctl status awg-quick@awg0 --no-pager
sudo awg show
sudo awk '/^# vpnbot key_id=|^PublicKey =|^AllowedIPs =/{print}' /etc/amnezia/amneziawg/awg0.conf
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='awg' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Не выводите приватные ключи AWG или preshared-ключи в тикеты/чаты. Сравнивайте только публичные ключи/клиентские IP, исправляйте подтверждённые расхождения из бэкапа или вручную, затем перезапустите `vpn-bot`.

### Восстановление после деградации SOCKS5

SOCKS5 DEGRADED блокирует только выдачу/отзыв/удаление SOCKS5. Xray, AWG и MTProto продолжают работать.

```bash
sudo systemctl status danted --no-pager
getent passwd | awk -F: '$1 ~ /^vpn_socks_/ {print $1}'
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='socks5' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Убедитесь, что каждый управляемый пользователь Linux начинается с `SOCKS5_LOGIN_PREFIX`; не выводите пароли SOCKS5. Блокируйте/удаляйте только подтверждённых «посторонних» пользователей, управляемых ботом, восстановите SQLite из бэкапа при необходимости, затем перезапустите `vpn-bot`.

### Восстановление после деградации MTProto

MTProto DEGRADED блокирует только выдачу/отзыв/удаление MTProto. Xray, AWG и SOCKS5 продолжают работать.

```bash
sudo systemctl status mtproxy --no-pager
sudo jq '{secret_count: (.secrets | length), fingerprints: [.secrets[]?.fingerprint]}' /etc/mtproxy/vpnbot/managed-secrets.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='mtproto' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Не выводите сырые MTProto-секреты. В статичном режиме отзыв на уровне сервера для конкретного пользователя невозможен; ротируйте `MTPROTO_SECRET`, если необходимо инвалидировать скопированный общий секрет. В управляемом режиме сравнивайте счётчики/fingerprint'ы, восстановите управляемые файлы из `/etc/mtproxy/vpnbot/backups` при необходимости, перезапустите `mtproxy`, затем перезапустите `vpn-bot`.

### Откат после неудачного деплоя

```bash
cd /opt/vpn-service
git log --oneline -5
git reset --hard <previous_commit>
.venv/bin/pip install -r requirements.txt -c constraints.txt
.venv/bin/python init_db.py
sudo systemctl restart vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

Используйте `git reset --hard` только когда намеренно отбрасываете локальные изменения кода на сервере. Восстановите `.env`, SQLite, конфигурацию Xray и AWG из бэкапа, если неудачный деплой изменил состояние рантайма.

### Бэкап

Сделайте резервную копию как минимум этих файлов перед деплоями, миграциями и ручными правками бэкенда:

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

Включайте `/opt/vpn-service/logs` только если операционные логи нужны для анализа инцидентов. Обращайтесь со всеми бэкапами как с конфиденциальными, поскольку они могут содержать токены Telegram, VPN-ключи, UUID Xray, приватные/preshared ключи AWG и серверные эндпоинты.

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

### Файрвол и открытые порты

- По возможности держите SSH открытым только для доверенных источников.
- Откройте публичный TCP-порт Xray, обычно `443/tcp`.
- Откройте публичный UDP-порт эндпоинта AWG из `AWG_ENDPOINT_PORT` или `ListenPort` в конфигурации AWG.
- Открывайте Dante/SOCKS только если намеренно развёртываете отдельный прокси с защитой.
- Держите `XRAY_STATS_SERVER` привязанным только к localhost, например `127.0.0.1:<port>`. Никогда не открывайте Xray stats API в интернет.
- Если политика UFW для перенаправленного трафика по умолчанию `deny`, явно разрешите перенаправляемый трафик, необходимый клиентам AWG.

## База данных

SQLite используется как локальный бэкенд хранилища. По умолчанию путь к базе данных:

```text
/opt/vpn-service/data/vpn.db
```

`init_db.py` открывает базу данных и применяет инициализацию схемы/миграции. Бот также инициализирует базу данных при создании приложения.

Текущие таблицы схемы включают:

- `users`
- `access_requests`
- `vpn_keys`
- `proxy_entries`
- `proxy_accesses`
- `audit_log`
- `vpn_key_traffic_stats`

## Статус проекта

Начинающий самостоятельный проект. Он пригоден для использования как специализированный бот управления VPN, но продакшен-использование требует тщательной проверки, серверного тестирования, операционных резервных копий, дисциплины работы с секретами и усиления защиты окружающей инфраструктуры Xray/AWG/сервера.

## Лицензия

Лицензия MIT. Смотрите [LICENSE](LICENSE).
