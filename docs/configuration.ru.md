# Справочник конфигурации

Полный справочник по каждой переменной окружения, которую разбирает `config/settings.py`.

Шаблон для копирования — [`.env.example`](../.env.example) (там каждая переменная тоже
описана комментариями). Скопируйте его в `.env` и замените placeholder'ы значениями для вашего
сервера. `BOT_TOKEN` и `ADMIN_IDS` обязательны для запуска; заполните соответствующие поля Xray
или AWG перед выдачей ключей нужного типа.

Переменные, помеченные **Обязательна**, должны быть заданы до запуска; остальные имеют
указанное значение по умолчанию.

> ⚠️ **Security-sensitive переменные** помечены 🔒. Никогда не коммитьте их; храните на сервере
> в `.env` (режим `0600`, только root).

## Core

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `BOT_TOKEN` | **Да** | — | Токен Telegram Bot API из BotFather. 🔒 |
| `ADMIN_IDS` | **Да** | — | Telegram user ID **суперадминов** через запятую. Дополнительные модераторы назначаются в боте суперадмином (переменной окружения нет). |
| `DB_PATH` | Нет | `/opt/vpn-service/data/vpn.db` | Путь к файлу базы данных SQLite. |
| `SQLITE_SYNCHRONOUS` | Нет | `FULL` | Режим synchronous SQLite: `FULL`, `NORMAL` или `EXTRA`. `FULL` безопаснее всего. |
| `LOG_DIR` | Нет | `/opt/vpn-service/logs` | Каталог для ротируемых логов. |
| `BOT_LOCK_PATH` | Нет | `/run/vpn-bot/vpn-bot.lock` | Путь к PID-локу single-instance. |
| `BOT_DROP_PENDING_UPDATES` | Нет | `false` | Сбрасывать очередь Telegram-обновлений при запуске. Полезно после простоя. |
| `BOT_LANGUAGE` | Нет | `ru` | Язык UI бота. Поддерживается: `ru`, `en`. |
| `AUDIT_RETENTION_DAYS` | Нет | `180` | Сколько дней хранить записи audit log (0 = вечно, макс. 3650). |
| `CONFIG_BACKUP_KEEP_LAST` | Нет | `20` | Сколько config-бэкапов хранить на backend (1–500). |

## Health Endpoint

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `HEALTH_HOST` | Нет | `127.0.0.1` | Хост опционального HTTP health-эндпоинта. |
| `HEALTH_PORT` | Нет | _(отключён)_ | Порт HTTP health-эндпоинта. Не указывать для отключения. |

## Privilege Helpers (non-root развёртывание)

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `PRIVILEGE_HELPERS_ENABLED` | Нет | `false` | Включить non-root развёртывание через sudo-хелперы. Несовместимо с `XRAY_APPLY_MODE=api`. |
| `HELPER_STAGING_ROOT` | Нет | `/run/vpn-bot` | Корневой каталог staging-файлов, передаваемых sudo-хелперам. |
| `SOCKS5_USER_HELPER_PATH` | Нет | `/usr/local/sbin/vpn-bot-socks5-user` | Абсолютный путь к sudo-хелперу управления SOCKS5-пользователями. |
| `XRAY_APPLY_HELPER_PATH` | Нет | `/usr/local/sbin/vpn-bot-xray-apply` | Абсолютный путь к sudo-хелперу применения конфига Xray. |
| `AWG_APPLY_HELPER_PATH` | Нет | `/usr/local/sbin/vpn-bot-awg-apply` | Абсолютный путь к sudo-хелперу применения конфига AWG. |
| `MTPROTO_APPLY_HELPER_PATH` | Нет | `/usr/local/sbin/vpn-bot-mtproxy-apply` | Абсолютный путь к sudo-хелперу применения MTProto. |
| `XRAY_HELPER_STAGING_DIR` | Нет | `$HELPER_STAGING_ROOT/xray` | Staging-каталог для файлов Xray-хелпера. |
| `AWG_HELPER_STAGING_DIR` | Нет | `$HELPER_STAGING_ROOT/awg` | Staging-каталог для файлов AWG-хелпера. |
| `MTPROTO_HELPER_STAGING_DIR` | Нет | `$HELPER_STAGING_ROOT/mtproxy` | Staging-каталог для файлов MTProto-хелпера. |

## Xray VLESS Reality

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `XRAY_CONFIG_PATH` | Нет | `/usr/local/etc/xray/config.json` | Путь к конфигу Xray. |
| `XRAY_SERVICE_NAME` | Нет | `xray` | Имя systemd-сервиса Xray. |
| `XRAY_APPLY_MODE` | Нет | `api` | Как применять изменения конфига Xray: `restart`, `reload` или `api`. Дефолт `api` (root, без обрыва соединений). `api` требует root и несовместим с хелперами; `restart`/`reload` используйте в non-root privilege-helper модели. |
| `XRAY_INBOUND_TAG` | Нет* | _(первый inbound)_ | Тег VLESS inbound в `config.json`. Обязателен для `api` mode. |
| `XRAY_PUBLIC_HOST` | Нет* | — | Публичный hostname/IP для подключения клиентов. Нужен для выдачи ключей. |
| `XRAY_PUBLIC_PORT` | Нет | `443` | Публичный TCP-порт для VLESS. |
| `XRAY_REALITY_PUBLIC_KEY` | Нет* | — | Публичный ключ Xray Reality (base64url). Нужен для выдачи ключей. |
| `XRAY_SNI` | Нет* | — | SNI для Reality. Нужен для выдачи ключей. |
| `XRAY_FLOW` | Нет | `xtls-rprx-vision` | VLESS flow control. |
| `XRAY_FINGERPRINT` | Нет | `chrome` | Глобальный fallback TLS-fingerprint (при создании ключа пользователь выбирает per key). Один из: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`, `randomized`, `randomizedalpn`, `randomizednoalpn`. |
| `XRAY_NETWORK_TYPE` | Нет | `tcp` | Тип сети: `tcp` или `raw`. |
| `XRAY_SHORT_ID` | Нет* | — | Hex short ID (≤16 символов). Обязателен, если `XRAY_MANAGE_SHORT_IDS=false`. |
| `XRAY_MANAGE_SHORT_IDS` | Нет | `false` | Разрешить боту управлять short ID автоматически. |
| `XRAY_ALLOW_RESTART_ON_ROLLBACK` | Нет | `false` | Разрешить рестарт сервиса при rollback конфига. |
| `XRAY_STATS_SERVER` | Нет* | — | Адрес gRPC stats/API сервера Xray. Нужен для `api` mode. |
| `XRAY_STATS_INTERVAL` | Нет | `60` | Интервал (сек) фонового сбора статистики трафика Xray (0–3600; 0 отключает). `statsquery` читается без `-reset` (не сбрасывает счётчики), поэтому ручные просмотры опрашивают API напрямую; этот цикл лишь держит кэш свежим между ними, чтобы дашборд обновлялся без действий пользователя. |
| `XRAY_XHTTP_ENABLED` | Нет | `false` | Включить второй VLESS-транспорт (XHTTP) через REALITY catch-all fallback `vless-in` на loopback-inbound. При включении создание ключа предлагает VLESS (TCP) / VLESS (HTTP). |
| `XRAY_XHTTP_INBOUND_TAG` | Нет* | `vless-xhttp-reality` | Тег loopback XHTTP fallback-dest inbound в `config.json` (должен отличаться от `XRAY_INBOUND_TAG`). Обязателен при `XRAY_XHTTP_ENABLED=true`. |
| `XRAY_XHTTP_PORT` | Нет | `8443` | Оставлен для обратной совместимости; **не** используется при построении ссылок VLESS (HTTP). Ссылка идёт через публичный порт `vless-in` (`XRAY_PUBLIC_PORT`); XHTTP-inbound слушает loopback как fallback-dest REALITY. |
| `XRAY_XHTTP_PATH` | Нет | `/v1/messages/stream` | Путь XHTTP в ссылках VLESS (HTTP); должен совпадать с `xhttpSettings.path` inbound (валидируется на inbound, не в fallback). |
| `XRAY_XHTTP_MODE` | Нет | `stream-one` | Клиентский режим XHTTP в ссылках VLESS (HTTP): `auto`, `packet-up`, `stream-up`, `stream-one`. Дефолт `stream-one` (одна full-duplex h2-сессия, чище для direct REALITY); `packet-up` — для троттлинга на длинных сессиях или прохода через CDN. |
| `XRAY_SPIDER_X_POOL` | Нет | _(пусто)_ | Пул per-key REALITY spiderX (`spx`): пути через запятую, каждый начинается с `/`. Пусто — `spx` не эмитится (дефолт). См. примечание ниже. |
| `XRAY_ACCESS_LOG_PATH` | Нет | _(пусто)_ | Путь к access-логу Xray для обнаружения аномалий. Пусто — отключено. |

_Legacy-aliases: `XRAY_SERVER_ADDRESS` (= `XRAY_PUBLIC_HOST`), `XRAY_SERVER_PORT` (= `XRAY_PUBLIC_PORT`), `XRAY_PUBLIC_KEY` (= `XRAY_REALITY_PUBLIC_KEY`), `XRAY_SERVER_NAME` (= `XRAY_SNI`)._

> Разовая серверная настройка транспорта VLESS (HTTP) описана в
> [`xray-xhttp-inbound.ru.md`](xray-xhttp-inbound.ru.md). У VLESS (HTTP) нет своего публичного
> порта: `vless-in` (`:443`) терминирует REALITY и через **дефолтный catch-all** `fallback`
> форвардит на loopback XHTTP-inbound, где валидируется путь. Path-based fallback **не** матчит
> HTTP/2 XHTTP (h2 `:path` лежит в HPACK), поэтому catch-all обязателен.

> **Профили транспорта по ключу.** `XRAY_XHTTP_MODE` задаёт клиентский `mode` только
> для профиля **base**. Флоу создания ключа VLESS (HTTP) предлагает три клиентских
> профиля — **base** / **antisib** (анти-блокировка) / **multi** (мультиподключение), —
> которые переопределяют `mode` и добавляют тюнинг `xhttpSettings.extra` в генерируемую
> ссылку (без изменений на сервере; профиль хранится по ключу). См.
> [`xray-xhttp-inbound.ru.md`](xray-xhttp-inbound.ru.md#клиентские-профили-транспорта-vless-http).

> **Per-key spiderX (`XRAY_SPIDER_X_POOL`).** spiderX — чисто **клиентский** параметр
> REALITY: он добавляется в клиентские ссылки VLESS как `&spx=<url-encoded>` и **никогда**
> не пишется в серверный inbound — `config.json` не трогается, xray не перезапускается.
> XTLS рекомендует уникальное значение на каждого клиента, поэтому вместо глобальной
> константы каждый ключ берёт значение из этого пула, выбранное **детерминированно** по
> хэшу UUID ключа (стабильно между перезапусками и воспроизводимо). Значение хранится по
> ключу в колонке `vpn_keys.spider_x` (nullable; `NULL` = не эмитить, полная обратная
> совместимость со старыми ключами). Пустая или незаданная переменная ничего не меняет.
> Если задать — при следующем старте существующие xray-ключи **backfill**-ятся
> (идемпотентно; уже проставленные значения не перезаписываются), поэтому включать
> можно в любой момент, не только при апгрейде на v31. Каждый путь должен начинаться
> с `/` (проверяется при старте).

## AmneziaWG

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `AWG_CONFIG_PATH` | Нет | `/etc/amnezia/amneziawg/awg0.conf` | Путь к серверному конфигу AWG. |
| `AWG_INTERFACE` | Нет | `awg0` | Имя сетевого интерфейса AWG/WireGuard. |
| `AWG_NETWORK` | Нет | `10.0.0.0/24` | IPv4-подсеть VPN. |
| `AWG_SERVER_ADDRESS` | Нет | `10.0.0.1` | IPv4-адрес сервера внутри VPN-подсети. |
| `AWG_ENDPOINT_HOST` | Нет* | — | Публичный hostname/IP для AWG endpoint. Нужен для выдачи ключей. |
| `AWG_ENDPOINT_PORT` | Нет | `0` | Публичный UDP-порт для AWG endpoint. |
| `AWG_SERVER_PUBLIC_KEY` | Нет | _(пусто)_ | Публичный ключ сервера AWG (base64). Показывается в клиентских конфигах. |
| `AWG_DNS` | Нет | `1.1.1.1` | DNS-сервер для AWG-клиентов. |
| `AWG_MTU` | Нет | _(авто)_ | MTU клиентского интерфейса AWG (576–1500). Пусто — пусть решает клиент. |
| `AWG_ALLOWED_IPS` | Нет | `0.0.0.0/0, ::/0` | Allowed IPs для маршрутизации AWG-клиента (по умолчанию full-tunnel). |
| `AWG_PERSISTENT_KEEPALIVE` | Нет | `25` | Интервал keepalive в секундах (0–86400). |
| `AWG_USE_PRESHARED_KEY` | Нет | `true` | Генерировать и включать preshared key для каждого клиента. |
| `AWG_STATS_INTERVAL` | Нет | `60` | Интервал (сек) фонового сбора статистики трафика (0–3600). |

_Legacy-alias: `AWG_CLIENT_DNS` (= `AWG_DNS`)._

## SOCKS5 / Dante

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `SOCKS5_ENABLED` | Нет | `false` | Включить SOCKS5 proxy backend. |
| `SOCKS5_HOST` | Нет* | _(пусто)_ | Публичный host для SOCKS5 (нужен при `SOCKS5_ENABLED=true`). |
| `SOCKS5_PORT` | Нет | `31337` | Публичный порт для SOCKS5. |
| `SOCKS5_LOGIN_PREFIX` | Нет | `vpn_socks_` | Префикс для всех управляемых Linux-пользователей. Должен быть уникальным и неуниверсальным. |
| `SOCKS5_SYSTEM_USER_SHELL` | Нет | `/usr/sbin/nologin` | Shell для управляемых SOCKS5 Linux-пользователей. |
| `SOCKS5_SERVICE_NAME` | Нет | `danted` | Имя systemd-сервиса Dante. |
| `SOCKS5_PUBLIC_NAME` | Нет | `SOCKS5 Proxy` | Отображаемое имя в UI бота. |
| `SOCKS5_NOTE` | Нет | `SOCKS5 Dante proxy on server` | Описание в карточках proxy access. |

## MTProto Proxy

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `MTPROTO_ENABLED` | Нет | `false` | Включить MTProto proxy backend. |
| `MTPROTO_MODE` | Нет | `static` | Режим: `static` (общий секрет) или `managed` (персональные секреты). |
| `MTPROTO_HOST` | Нет* | _(пусто)_ | Публичный host для MTProto (нужен при `MTPROTO_ENABLED=true`). |
| `MTPROTO_PORT` | Нет | `8443` | Публичный порт для MTProto. |
| `MTPROTO_SECRET` | Нет* | _(пусто)_ | 🔒 Общий MTProto-секрет (нужен при `MTPROTO_MODE=static` и включённом backend). |
| `MTPROTO_PUBLIC_NAME` | Нет | `Telegram MTProto Proxy` | Отображаемое имя в UI бота. |
| `MTPROTO_NOTE` | Нет | `MTProto proxy for Telegram` | Описание в карточках proxy access. |
| `MTPROTO_STATS_URL` | Нет | _(пусто)_ | URL эндпоинта статистики MTProto. |
| `MTPROTO_SERVICE_NAME` | Нет | `mtproxy` | Имя systemd-сервиса MTProxy. |
| `MTPROTO_BINARY_PATH` | Нет | `/usr/local/bin/mtproto-proxy` | Путь к бинарнику MTProto proxy. |
| `MTPROTO_RUN_USER` | Нет | `mtproxy` | Пользователь, под которым работает процесс MTProto proxy. |
| `MTPROTO_RUN_GROUP` | Нет | `mtproxy` | Группа процесса MTProto proxy. |
| `MTPROTO_CONFIG_DIR` | Нет | `/etc/mtproxy` | Каталог базовых конфигов MTProxy. |
| `MTPROTO_PROXY_SECRET_PATH` | Нет | `/etc/mtproxy/proxy-secret` | Путь к файлу `proxy-secret` MTProxy. |
| `MTPROTO_PROXY_MULTI_CONF_PATH` | Нет | `/etc/mtproxy/proxy-multi.conf` | Путь к файлу `proxy-multi.conf` MTProxy. |
| `MTPROTO_MANAGED_DIR` | Нет | `/etc/mtproxy/vpn-bot` | Каталог для bot-managed файлов MTProto. |
| `MTPROTO_MANAGED_SECRETS_PATH` | Нет | `$MTPROTO_MANAGED_DIR/managed-secrets.json` | 🔒 Путь к managed secrets JSON. |
| `MTPROTO_MANAGED_ENV_PATH` | Нет | `$MTPROTO_MANAGED_DIR/mtproxy.env` | Путь к managed env-файлу MTProxy. |
| `MTPROTO_MANAGED_WRAPPER_PATH` | Нет | `/opt/vpn-service/scripts/run-mtproxy-managed` | Путь к wrapper-скрипту managed-режима. |
| `MTPROTO_BACKUP_DIR` | Нет | `$MTPROTO_MANAGED_DIR/backups` | Каталог бэкапов managed-файлов MTProto. |
| `MTPROTO_INTERNAL_STATS_PORT` | Нет | `8888` | Внутренний stats-порт MTProxy (1–65535). |
| `MTPROTO_WORKERS` | Нет | `1` | Количество worker-процессов MTProxy (1–1024). |
| `MTPROTO_APPLY_TIMEOUT_SECONDS` | Нет | `10` | Таймаут (сек) на apply + health check (1–3600). |
| `MTPROTO_ROLLBACK_ON_APPLY_FAILURE` | Нет | `true` | Автоматически восстанавливать бэкап при ошибке apply. |
| `MTPROTO_KEEP_LAST_BACKUPS` | Нет | `10` | Сколько managed-бэкапов хранить (0–1000). |

## Hysteria2

Hysteria2 работает как отдельный data plane (сервер `hysteria` плюс отдельный
эндпоинт `hy2_auth`), независимо от процесса бота. Эти переменные нужны только
чтобы бот собирал клиентские ссылки и гейтил выдачу. Hysteria2 работает на
чистом QUIC поверх UDP/443 (см. `deploy/hysteria/config.yaml`) — salamander-
обфускация убрана; `HYSTERIA2_OBFS_PASSWORD` задепрекейчен и игнорируется.

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `HYSTERIA2_ENABLED` | Нет | `false` | Включить выдачу Hysteria2-ключей в боте. Data plane работает независимо. |
| `HYSTERIA2_HOST` | Нет* | — | Публичный хост/IP, к которому подключаются клиенты. Нужен для выдачи ключей. |
| `HYSTERIA2_PORT` | Нет | `443` | Публичный UDP-порт сервера Hysteria2 (1–65535). Сосуществует с Xray REALITY на TCP/443. |
| `HYSTERIA2_SNI` | Нет* | — | TLS SNI в клиентской ссылке. Должен совпадать с CN/SAN серверного сертификата. Нужен для выдачи ключей. |
| `HYSTERIA2_OBFS_PASSWORD` | Нет | — | **Задепрекейчен** — salamander-обфускация убрана; значение парсится (чтобы существующий `.env` не ронял старт), но больше не используется. 🔒 |
| `HYSTERIA2_INSECURE` | Нет | `false` | Ставит `insecure=1` в ссылку (пропуск проверки TLS-сертификата на клиенте). См. ниже. |
| `HYSTERIA2_AUTH_LISTEN` | Нет | `127.0.0.1:8444` | Loopback `host:port`, который слушает эндпоинт `hy2_auth`. Хост обязан быть loopback. |
| `HYSTERIA2_STATS_LISTEN` | Нет | `127.0.0.1:9999` | Loopback `host:port` Traffic Stats API. Должен совпадать с `trafficStats.listen` в `config.yaml`; хост обязан быть loopback. |
| `HYSTERIA2_STATS_SECRET` | Нет | — | Секрет Traffic Stats API; ОБЯЗАН совпадать с `trafficStats.secret` в `config.yaml`. Пусто — трафик/онлайн/kick для hy2 отключены. 🔒 |
| `HYSTERIA2_STATS_INTERVAL` | Нет | `60` | Интервал фонового сбора статистики hy2 в секундах (0–3600; 0 отключает цикл). |
| `HYSTERIA2_SERVICE_NAME` | Нет | `hysteria-server` | systemd-юнит сервера Hysteria2, проверяется админ-диагностикой (`systemctl is-active`). |
| `HYSTERIA2_AUTH_SERVICE_NAME` | Нет | `vpn-bot-hy2-auth` | systemd-юнит эндпоинта `hy2_auth`, проверяется админ-диагностикой. |
| `HYSTERIA2_CONFIG_PATH` | Нет | `/etc/hysteria/config.yaml` | Путь к конфигу hysteria-server; кладётся в офсайт recovery-архив (если recovery включён), чтобы пересозданный сервер восстановил data plane. Отсутствующий файл пропускается. |
| `HYSTERIA2_HEALTH_INTERVAL` | Нет | `60` | Частота (сек) опроса `hy2_auth` `GET /healthz`, отражается в записи **Hysteria2: OK/DEGRADED** на дашборде/в health (0–3600; 0 отключает). Активно только при `HYSTERIA2_ENABLED`. |

### Паритет по backend health и диагностике

При `HYSTERIA2_ENABLED=true` бот доводит Hysteria2 до паритета с Xray/AWG по
операционной наблюдаемости: панель админ-**диагностики** запускает `systemctl
is-active` для `HYSTERIA2_AUTH_SERVICE_NAME` и `HYSTERIA2_SERVICE_NAME`, а фоновый
цикл опрашивает `hy2_auth` `GET /healthz` каждые `HYSTERIA2_HEALTH_INTERVAL`
секунд и обновляет запись **Hysteria2: OK/DEGRADED** в backend health на
дашборде. Это сигнал только о живости data plane — так как выдача/отзыв
Hysteria2 — это чистые записи в `vpn.db` без шага apply, статус `DEGRADED`
никогда не блокирует выдачу или отзыв ключей (в отличие от Xray/AWG, где
degraded-бэкенд блокирует мутации).

> **Важно — трафик, счётчик онлайна и kick при отзыве по-прежнему требуют
> Traffic Stats API** (`HYSTERIA2_STATS_SECRET`, ниже). Эти данные можно получить
> только из собственного Traffic Stats API `hysteria-server`, который оператор
> включает в `config.yaml`; бот не может получить их из другого источника.
> Поэтому полный паритет по наблюдаемости *условен* — он требует настройки этого API.

### Traffic Stats API (`HYSTERIA2_STATS_*`) — трафик, онлайн, kick при отзыве

В отличие от `hy2_auth` (который только аутентифицирует хендшейки), per-key
счётчики трафика, счётчик онлайн-клиентов и мгновенный разрыв сессии при отзыве
обслуживает **Traffic Stats API** Hysteria2 — отдельный аутентифицируемый
HTTP-сервер, который поднимает сам `hysteria-server`. Включите его в
`/etc/hysteria/config.yaml`:

```yaml
trafficStats:
  listen: 127.0.0.1:9999   # должно совпадать с HYSTERIA2_STATS_LISTEN (только loopback)
  secret: s3cret           # должно совпадать с HYSTERIA2_STATS_SECRET
```

Бот только *читает* API (`GET /traffic`, `GET /online`) и делает `POST /kick`
при отзыве/удалении/истечении ключа. Без `HYSTERIA2_STATS_SECRET` hy2-ключи не
показывают трафик и онлайн, а отзыв блокирует только новые хендшейки (живая
сессия доживает до переподключения) — поведение до Stats API. `id` из API — это
stats-label ключа (`hy2_<hex>`), тот же, что возвращает `hy2_auth`.

### `HYSTERIA2_INSECURE` — по умолчанию выключен (валидный сертификат)

Сервер предъявляет валидный сертификат Let's Encrypt для `HYSTERIA2_SNI`,
который выпускает и продлевает `acme.sh` (dns_duckdns) вне этого репозитория —
см. `deploy/hysteria/config.yaml`. С настоящим сертификатом клиентам не нужно
пропускать проверку TLS, поэтому `HYSTERIA2_INSECURE` по умолчанию `false`, и
`insecure=1` вообще не добавляется в выдаваемые ссылки.

Включайте `true` только временно (например, сертификат ещё не выпущен для
свежего домена). Пока `true` включён, клиент пропускает проверку
TLS-сертификата; это не ослабляет секрет авторизации ключа, но слепой on-path
атакующий может видеть и прощупывать handshake, хотя не может расшифровать
данные QUIC-приложения или аутентифицироваться без валидного секрета ключа.

## Истечение ключей и пробный доступ

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `KEY_EXPIRY_CHECK_INTERVAL` | Нет | `1800` | Как часто (сек) проверять истекающие/истёкшие ключи (0–86400). |
| `KEY_EXPIRY_NOTIFY_DAYS` | Нет | _(пусто)_ | Дни до истечения для уведомления пользователя, через запятую. Например: `7,3,1`. |
| `KEY_MAX_TRIAL_DAYS` | Нет | `365` | Максимальная длительность (дней) пробных VPN-ключей (1–3650). |

> **Флоу пробного доступа.** Одобренный пользователь без активного ключа может запросить временный *пробный* ключ; суперадмин или модератор одобряет/отклоняет запрос из админ-панели, а выданный ключ ограничен `KEY_MAX_TRIAL_DAYS`. Право на пробный доступ отслеживается по пользователю (`users.trial_quota_reset_at`), чтобы пробники нельзя было фармить; запросы хранятся в таблице `trial_key_requests`.

## All-in-one подписка

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `SUBSCRIPTION_ENABLED` | Нет | `false` | Включает all-in-one подписки: одна родительская запись (`key_bundles`) владеет несколькими VPN-ключами, чтобы один sub-URL отдавал сразу все протоколы. Пока `false`, сервис подписок отказывает в любой операции. |

Бандл провижнит **по одному дочернему ключу на каждый включённый протокол** —
VLESS (TCP), каждый профиль VLESS (HTTP) (`base`, `antisib`, `multi`) и
Hysteria2 — через тот же путь создания, что и одиночный ключ, поэтому дети
сохраняют обычные метки `xray_tcp_*` / `xray_http_*` / `hy2_*` и остаются
видимы для reconcile и детекта аномалий. AWG исключён (конфиги WireGuard не
едут в base64-подписку), прокси SOCKS5/MTProto — тоже (это отдельная сущность).
Всем детям бандла ставится один и тот же `expires_at`, чтобы они истекали
вместе.

Политика частичного провижна: протокол, **выключенный** (флагом в `.env` или
админским тумблером модуля), пропускается молча, а фактический состав пишется в
audit-лог; протокол, **включённый, но degraded**, прерывает создание целиком —
бандл, в котором молча нет протокола, дефектен навсегда, а прерванное создание
пользователь просто повторит.

## Рассылки

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `SCHEDULED_ANNOUNCEMENTS_INTERVAL` | Нет | `60` | Как часто (сек) фоновый цикл доставляет запланированные рассылки (0–86400). `0` отключает цикл; рассылки можно запланировать, доставка произойдёт после перезапуска. |

## Офсайтовый зашифрованный бэкап

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `OFFSITE_BACKUP_ENCRYPTION_KEY` | Нет | _(отключён)_ | 🔒 Fernet-ключ для шифрования офсайтовых бэкапов БД. Сгенерировать: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Пусто — офсайт-бэкапы отключены. |
| `OFFSITE_BACKUP_INTERVAL` | Нет | `604800` | Интервал (сек) между загрузками бэкапов (0 = отключено). По умолчанию 7 дней. |
| `OFFSITE_BACKUP_INCLUDE_CONFIGS` | Нет | `true` | Дополнительно отправлять зашифрованный **бандл восстановления** (`.env` + конфиги Xray/AWG/Hysteria2/MTProto/WARP) рядом с бэкапом БД, чтобы поднять сервис на чистом сервере. Шифруется тем же ключом; файл `vpnbot_recovery_*.tar.gz.enc`. |
| `OFFSITE_BACKUP_ENV_PATH` | Нет | _(авто)_ | 🔒 Путь к `.env`, попадающему в бандл восстановления. Пусто — автоопределение `.env`, загруженного при старте. |

## Обнаружение аномалий

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `ANOMALY_CHECK_INTERVAL` | Нет | `300` | Как часто (сек) запускать сканирование аномалий (0–86400). |
| `ANOMALY_WINDOW_SECONDS` | Нет | `3600` | Окно наблюдения за трафиком в секундах (60–86400). |
| `ANOMALY_MIN_UNIQUE_IPS` | Нет | `3` | **Устарело.** Используется только как значение по умолчанию для `ANOMALY_UNIQUE_NETS`; детектор больше не считает «сырые» IP (1–1000). |
| `ANOMALY_UNIQUE_NETS` | Нет | `ANOMALY_MIN_UNIQUE_IPS` | Порог алерта в **уникальных сетях** на ключ за окно (1–1000). Каждый source IP приводится к своей ASN (по локальной базе iptoasn в `IP2ASN_DB_PATH`, по умолчанию `/opt/vpn-service/data/ip2asn-v4.tsv`) или, если ASN неизвестна, к `/24`. Подсчёт сетей вместо «сырых» IP исключает ложные срабатывания от ротации IP оператора и переключений мобильный↔Wi-Fi одного легального пользователя. Базу обновляет `deploy/vpn-bot-ip2asn.timer`. |
| `ANOMALY_AUTO_REVOKE` | Нет | `false` | Автоматически отзывать помеченные ключи без подтверждения администратора. Для AWG/Xray (детекция по IP) авто-отзыв срабатывает только при `ANOMALY_CONCURRENT_WINDOW_SECONDS > 0` — см. примечание ниже. |
| `ANOMALY_COOLDOWN_SECONDS` | Нет | `7200` | Cooldown перед повторным флагом того же ключа (0–86400). |
| `ANOMALY_CONCURRENT_WINDOW_SECONDS` | Нет | `600` | Окно для обнаружения одновременных соединений (0–86400). |
| `ANOMALY_HYSTERIA2_MAX_CONN` | Нет | `0` | Флаг для Hysteria2-ключа с >= стольким числом одновременных соединений (через Traffic Stats API `/online`). `0` отключает проверку hy2; требует `HYSTERIA2_STATS_SECRET`. |

> **Условие авто-отзыва.** За полное окно наблюдения один роумящий/мобильный
> пользователь закономерно накапливает много IP, поэтому отзыв только по этому
> сигналу задевал бы легитимных пользователей. Поэтому для AWG/Xray
> `ANOMALY_AUTO_REVOKE=true` отзывает только при
> `ANOMALY_CONCURRENT_WINDOW_SECONDS > 0` (нужен сигнал одновременности); при
> нулевом окне детектор работает в режиме только-оповещения и пишет предупреждение
> при старте. Hysteria2 использует изначально «одновременный» счётчик `/online`,
> поэтому его авто-отзыв следует `ANOMALY_AUTO_REVOKE` напрямую, независимо от
> настройки concurrent-окна.

## WARP-сокрытие исходящего IP

Операционные детали — в [`warp.ru.md`](warp.ru.md). По умолчанию пути совпадают с шаблоном
sudoers. Смена `WARP_CONFIG_PATH` или `WARP_INTERFACE` требует согласованного обновления
`/etc/sudoers.d/vpn-bot` и скриптов `vpn-bot-warp-*`; рассогласование вызывает молчаливые сбои
sudo. Меняйте, только если понимаете, что делаете.

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `WARP_CONFIG_PATH` | `/etc/amnezia/out-warp.conf` | Путь установленного конфига туннеля |
| `WARP_INTERFACE` | `out-warp` | Имя интерфейса AmneziaWG |
| `WARP_INSTALL_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-install` | Хелпер установки конфига |
| `WARP_IFACE_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-iface` | Хелпер up/down интерфейса |
| `WARP_ROUTES_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-routes` | Хелпер add/del маршрутов |
| `WARP_STATUS_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-status` | Хелпер `awg show` |
| `WARP_HELPER_STAGING_DIR` | `/run/vpn-bot/warp` | Приватный каталог для staged-загрузок |
| `WARP_PING_TARGET` | `162.159.140.245` | ICMP-цель, которую health-монитор пингует для определения up/down туннеля. По умолчанию — Cloudflare anycast, присутствующий в типичных `AllowedIPs` WARP. Переопределите, если ваш `AllowedIPs` его не покрывает, иначе монитор даст ложные провалы. |
| `WARP_MONITOR_OBSERVER_MODE` | `true` | Когда `true` (по умолчанию), health-монитор только **наблюдает** за туннелем (пробы, состояние в БД, уведомления админам) и никогда не трогает интерфейс/маршруты — ими владеет systemd (`awg-quick@out-warp` + `warp-routes.service`). `false` — вернуть устаревшую модель, где бот сам поднимает/опускает интерфейс и управляет маршрутами. |
| `WARP_MONITOR_FAIL_WINDOW_SECONDS` | `60` | Сколько секунд **подряд** не должно быть ответа, прежде чем монитор объявит туннель упавшим (и уведомит админов). Один успешный пинг сбрасывает окно. |
| `WARP_MONITOR_RECOVER_WINDOW_SECONDS` | `60` | Сколько секунд **подряд** успешных проб до объявления туннеля восстановленным. Один провал сбрасывает окно. |
| `WARP_MONITOR_INTERVAL_SECONDS` | `10` | Интервал пинга при нормальной работе. |
| `WARP_MONITOR_FAST_INTERVAL_SECONDS` | `3` | Учащённый интервал пинга, как только проба осталась без ответа. |
| `WARP_SPLIT_LIST_PATH` | `/etc/vpn-bot/warp-split.list` | Путь к списку selective-split префиксов. Бот читает файл напрямую (0644); запись только через `WARP_SPLIT_APPLY_HELPER_PATH`. Меняйте, только если переносите файл — обновите sudo-грант. |
| `WARP_SPLIT_APPLY_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-split-apply` | Привилегированный хелпер: валидирует, атомарно пишет split-список и перезапускает `vpn-bot-warp-split`. root:root 0755 с грантом `NOPASSWD`. |
| `WARP_SPLIT_STATE_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-split-state` | Привилегированный on/off/restart/status хелпер для split-**маршрутизации** (таблица T). Кнопки Вкл/Выкл/Перезапуск вызывают его для снятия/применения per-prefix маршрутов `dev out-warp` и записи маркера — он не трогает `awg-quick@out-warp`. root:root 0755 с pinned-verb грантами `NOPASSWD`. |
| `WARP_SPLIT_DISABLED_MARKER_PATH` | `/etc/vpn-bot/warp-split.disabled` | Root-owned (0644) маркер «выключено». Когда присутствует, `vpn-bot-warp-split` реконсайлит таблицу T в пусто на каждом boot-apply, поэтому «выключено» переживает перезагрузку. Бот читает напрямую; пишет только state-хелпер. |
| `WARP_PROXY_EGRESS_ENABLED` | `false` | Заворачивать в WARP-туннель и ЛОКАЛЬНЫЙ egress прокси (Dante/Xray/MTProto). Когда `true`, генератор конфига Xray привязывает source egress у freedom-outbound к IP туннеля (`sendThrough` = `[Interface] Address`), и его трафик заворачивается через `vpn-bot-warp-routes`. По умолчанию выключено; включать только в рамках ручного runbook'а [WARP proxy egress](warp.ru.md#warp-proxy-egress-маскировка-исходящего-ip-прокси). Легаси-алиас: `WARP_PROXY_EGRESS`. |

## Legacy / совместимость

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `DEFAULT_PROXY_TYPE` | Нет | _(пусто)_ | Legacy proxy entry type (только внутреннее использование; не управляет пользовательским proxy-flow). |
| `DEFAULT_PROXY_HOST` | Нет | _(пусто)_ | Legacy proxy host. |
| `DEFAULT_PROXY_PORT` | Нет | _(пусто)_ | Legacy proxy port. |
| `DEFAULT_PROXY_LOGIN` | Нет | _(пусто)_ | Legacy proxy login. |
| `DEFAULT_PROXY_PASSWORD` | Нет | _(пусто)_ | 🔒 Legacy proxy password. |
| `DEFAULT_PROXY_NOTE` | Нет | _(пусто)_ | Legacy proxy note. |

## Примечания

- Если `XRAY_INBOUND_TAG` пустой, адаптер использует первый inbound с `settings.clients`.
- Если `XRAY_MANAGE_SHORT_IDS=false`, необходимо указать `XRAY_SHORT_ID`.
- `XRAY_APPLY_MODE=api` — режим apply по умолчанию (root; добавляет/удаляет ключи без перезапуска Xray, соединения не обрываются). `restart`/`reload` — только в non-root privilege-helper модели; helper игнорирует `api`/`reload` и всегда перезапускает Xray.
- `XRAY_APPLY_MODE=api` несовместим с `PRIVILEGE_HELPERS_ENABLED=true`. При включённых хелперах бот применяет изменения через `vpn-bot-xray-apply`, который всегда вызывает `systemctl restart xray`, игнорируя `XRAY_APPLY_MODE`. Используйте `restart`; `reload` и `api` хелпером не поддерживаются. См. [Развёртывание → Xray API Mode](deployment.ru.md#xray-api-mode).
- `SQLITE_SYNCHRONOUS=FULL` — более безопасный дефолт для этой control-plane базы. `NORMAL` быстрее, но может потерять последние зафиксированные транзакции при сбое ОС/питания, когда состояние VPN-backend уже изменилось.
- `AWG_CLIENT_DNS` поддерживается только как legacy-alias; для новых развёртываний используйте `AWG_DNS`.
- `AWG_ENDPOINT_HOST` и `AWG_ENDPOINT_PORT` должны указывать на публичный AWG endpoint клиентов.
- `SOCKS5_ENABLED=true` требует `SOCKS5_HOST`, `SOCKS5_PORT` и безопасного `SOCKS5_LOGIN_PREFIX`. Dante должен быть уже установлен и слушать порт; бот только создаёт/блокирует/удаляет управляемых Linux-пользователей с этим префиксом.
- `MTPROTO_ENABLED=true` требует `MTPROTO_HOST`. `MTPROTO_MODE=static` также требует `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` — режим совместимости: бот показывает общий секрет и может только деактивировать запись в SQLite. Настоящий per-user server-side revoke невозможен без ротации общего секрета.
- `MTPROTO_MODE=managed` создаёт уникальный секрет для каждого пользователя. Полная операционная модель — в [Прокси-бэкенды → MTProto managed mode](proxy.ru.md).
- `MTPROTO_SECRET`, пароли SOCKS5 и реальные production-endpoints с credentials никогда не должны попадать в репозиторий. В `.env.example` секреты прокси намеренно пустые.
- `DEFAULT_PROXY_*` — legacy-хранилище для совместимости, не управляет новым пользовательским proxy access flow.
