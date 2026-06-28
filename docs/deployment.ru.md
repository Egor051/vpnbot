# Развёртывание

Поставляемый systemd-юнит ожидает проект в `/opt/vpn-service`. Если развёртываете в другое
место, обновите `deploy/vpn-bot.service` перед установкой.

Есть две модели развёртывания:

- **Root-развёртывание (текущий дефолт — `XRAY_APPLY_MODE=api`, `User=root`).** Применение ключей без обрыва соединений через Xray gRPC API; sudo-хелперы не нужны. Под это уже настроен поставляемый `deploy/vpn-bot.service`.
- **Non-root развёртывание (privilege-helper mode, `User=vpn-bot`).** Усиленная модель: каждое привилегированное изменение бэкенда идёт через фиксированные sudo-хелперы. Включается правкой юнита и `PRIVILEGE_HELPERS_ENABLED=true`.

> ⚠️ **`deploy/vpn-bot.service` — авторитетный источник.**
> Каждый деплой копирует его дословно в `/etc/systemd/system/vpn-bot.service`. Ручные правки
> системного файла перезаписываются при следующем деплое. Текущий файл запускает бота как
> `User=root` с `ProtectSystem=false` для `XRAY_APPLY_MODE=api`. При смене модели сначала
> обновите `deploy/vpn-bot.service` — не редактируйте системный файл напрямую.

## Xray API Mode

> ⚠️ **`XRAY_APPLY_MODE=api` требует root и несовместим с privilege helpers.**
> Это **единственная каноническая формулировка** правила api/root; остальные доки ссылаются сюда.
> - `XRAY_APPLY_MODE=api` — **единственный** режим, позволяющий добавлять/удалять ключи Xray без перезапуска сервиса. Без него каждое создание/удаление ключа вызывает полный перезапуск Xray, обрывая все активные подключения.
> - `XRAY_APPLY_MODE=api` **несовместим** с `PRIVILEGE_HELPERS_ENABLED=true` — бот откажет в запуске, если заданы оба.
> - Для api-режима бот **должен запускаться под root** (`User=root` в service-файле) с `PRIVILEGE_HELPERS_ENABLED=false`.
> - В non-root privilege-helper модели используйте `XRAY_APPLY_MODE=restart` (или `reload`); helper игнорирует `api`/`reload` и всегда перезапускает Xray.

Для усиленного production-развёртывания предпочтительна non-root privilege-helper модель: она
оставляет бота непривилегированным ценой короткого рестарта Xray при каждом изменении ключа.

### Переменные `.env` для api-режима

```dotenv
XRAY_APPLY_MODE=api
XRAY_INBOUND_TAG=vless-in          # должен совпадать с полем "tag" VLESS inbound в config.json
XRAY_STATS_SERVER=127.0.0.1:10085  # должен совпадать с портом API inbound dokodemo-door
```

Также установите `PRIVILEGE_HELPERS_ENABLED=false` (или не указывайте) при использовании
api-режима.

### Разовая подготовка сервера

Перед запуском бота в api-режиме настройте Xray API inbound и задайте тег VLESS inbound в
`/usr/local/etc/xray/config.json`:

1. Добавьте `"tag": "vless-in"` к объекту VLESS inbound (тег должен совпадать с `XRAY_INBOUND_TAG`):

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

2. Убедитесь, что блок Xray API и `dokodemo-door` API inbound присутствуют в `config.json`.
   Порт должен совпадать с `XRAY_STATS_SERVER`:

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

`deploy/vpn-bot.service` уже содержит `User=root`, `ProtectSystem=false` и не имеет
ограничений `ReadWritePaths` — ручные правки service-файла не нужны.

## Root-развёртывание (api mode, `User=root`)

Файл сервиса в репозитории уже настроен для root+api mode. См. [Xray API Mode](#xray-api-mode)
выше для необходимых переменных `.env` и разовой подготовки конфигурации Xray. Создавать
системного пользователя `vpn-bot` или устанавливать sudo-хелперы для этой модели не нужно.

## Non-root развёртывание (privilege-helper mode, `User=vpn-bot`)

Обновите `deploy/vpn-bot.service`, установив `User=vpn-bot`, `Group=vpn-bot`,
`ProtectSystem=strict` и восстановив `ReadWritePaths` перед деплоем. Затем:

1. Держите `/opt/vpn-service`, файлы деплоя, `.env` и `.venv` под владением root/оператора, недоступными для записи от `vpn-bot`.
2. Создайте системную учётную запись `vpn-bot:vpn-bot`.
3. Дайте `vpn-bot` право на запись только в runtime-состояние: `/opt/vpn-service/data`, `/opt/vpn-service/logs` (если включены файловые логи) и `/run/vpn-bot`, создаваемый systemd.
4. Установите фиксированные хелперы в `/usr/local/sbin` и `/etc/sudoers.d/vpnbot` только с этими точками входа.
5. Включите `PRIVILEGE_HELPERS_ENABLED=true`.
6. Установите `deploy/vpn-bot.service`.

В этой модели используйте `XRAY_APPLY_MODE=restart` (или `reload`); api-режим хелпером не
поддерживается. Полная архитектура privilege separation — в
[`security/privilege-separation-plan.ru.md`](security/privilege-separation-plan.ru.md), контракты
хелперов — в [`../deploy/helpers/README.md`](../deploy/helpers/README.md).

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

Установка хелперов и sudoers:

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

Не делайте рекурсивный chown всего дерева приложения на login-пользователя в production. Не
давайте права на запись в checkout репозитория, файлы деплоя или `.venv` пользователю
`vpn-bot`; скомпрометированный процесс бота не должен иметь возможности переписать собственный
код, зависимости, units или исходники хелперов.

Если включён `MTPROTO_MODE=managed`, держите `/etc/mtproxy/vpnbot` под владением root и
управлением хелпером. Не давайте `vpn-bot.service` права на запись в `/etc/systemd/system` или
широкий write-доступ в `/etc/mtproxy`; устанавливайте/обновляйте MTProxy drop-in и wrapper
вручную при деплое, затем запускайте `systemctl daemon-reload` вне runtime бота.

## Hysteria2 data plane (эндпоинт `hy2_auth`)

Поддержка Hysteria2 **по умолчанию выключена** и работает как отдельный data
plane, независимо от `vpn-bot.service`. Бот только пишет строки ключей в базу;
сама авторизация handshake'ов выполняется отдельным процессом `hy2_auth`,
который сервер `hysteria` вызывает по loopback HTTP. Поскольку этот процесс
читает **живую** базу, отзыв или удаление вступают в силу на следующем
handshake — нет шага apply и нет перезапуска data plane.

Устанавливаются три вещи: сам сервер `hysteria`, его HTTP-auth, указывающий на
`hy2_auth`, и systemd-юнит `vpnbot-hy2-auth.service`.

### 1. Установка systemd-юнита `hy2_auth`

```bash
sudo cp deploy/vpnbot-hy2-auth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpnbot-hy2-auth
```

Юнит запускает `python -m hy2_auth` из venv проекта, читает тот же
`/opt/vpn-service/.env`, биндится **только на loopback** (`HYSTERIA2_AUTH_LISTEN`,
по умолчанию `127.0.0.1:8444`) и открывает базу **только на чтение** (`mode=ro`).
Он не запускает sudo-хелперов, поэтому полностью захардижен
(`NoNewPrivileges=yes`, `ProtectSystem=strict`, syscall-фильтр `@system-service`
и т.д.) и должен продолжать работать, даже когда `vpn-bot.service` остановлен.

> **WAL / `ReadWritePaths` (обязательно).** Бот держит `vpn.db` в режиме WAL, и
> *читатель* WAL обязан мочь писать индекс разделяемой памяти (`-shm`) и sidecar
> `-wal` — даже если он только читает строки. Поэтому юнит выдаёт
> `ReadWritePaths=/opt/vpn-service/data` (а не `ReadOnlyPaths`); при каталоге
> данных только-на-чтение SQLite не сможет открыть эти sidecar'ы и упадёт с
> `unable to open database file` / `SQLITE_CANTOPEN`, отклоняя каждый handshake.
> Это **не** ослабляет гарантию read-only для самих данных: приложение открывает
> коннекшен с `mode=ro`, поэтому любая запись в основной файл базы всё равно
> бросает ошибку — read-write-доступ нужен только для WAL-sidecar'ов.

### 2. Указать серверу `hysteria` на эндпоинт

В `/etc/hysteria/config.yaml` используйте HTTP-auth и тот же адрес прослушивания:

```yaml
auth:
  type: http
  http:
    url: http://127.0.0.1:8444/auth   # должно совпадать с HYSTERIA2_AUTH_LISTEN
```

`HYSTERIA2_OBFS_PASSWORD` в `.env` обязан совпадать с паролем salamander-обфускации
в этом файле — несовпадение даёт тихий таймаут клиента, а не ошибку. Запускайте
`hysteria-server.service` после `vpnbot-hy2-auth` (юнит объявляет
`Before=hysteria-server.service`).

### 3. Поведение fail-closed и health

- Эндпоинт **всегда отвечает HTTP 200** с `{"ok": <bool>, "id": "<label>"}`,
  чтобы `hysteria` никогда не видел 5xx. `ok` равно `false` для
  неизвестного/отозванного токена, битого тела или сбоя базы — он всегда
  отказывает **закрыто** (fail-closed).
- Неподошедший токен логируется тихо (debug); сбой базы (locked, corrupt)
  логируется на уровне **error** со счётчиком сбоев, поэтому сломанный data plane
  виден в `journalctl -u vpnbot-hy2-auth`, а не прячется за безобидными отказами.
- `GET /healthz` делает пробный read: **200** `{"ok": true}`, когда база читается,
  и **503** `{"ok": false}`, когда нет — пригодно для watchdog или ручного
  `curl http://127.0.0.1:8444/healthz`.

См. [Конфигурация → Hysteria2](configuration.ru.md#hysteria2) по переменным
`.env`, включая MITM-компромисс `HYSTERIA2_INSECURE=true`.

## Smoke-чеклист после деплоя

1. `python deploy/check-nonroot-helper-mode.py` проходит.
2. `systemctl show vpn-bot -p User -p Group -p RuntimeDirectory -p NoNewPrivileges -p ReadWritePaths` показывает `vpn-bot`, `vpn-bot`, `vpn-bot`, без включённого `NoNewPrivileges` и только ожидаемые writable paths.
3. `sudo -u vpn-bot test ! -w /opt/vpn-service/.venv && sudo -u vpn-bot test ! -w /opt/vpn-service/deploy`.
4. `sudo visudo -cf /etc/sudoers.d/vpnbot` проходит и файл не содержит `NOPASSWD: ALL`.
5. Выдайте/отзовите один тестовый ключ Xray или AWG и один proxy access для включённого backend, затем проверьте `journalctl -u vpn-bot -n 100 --no-pager` на ошибки хелпера или утечку секретов.

> Чекер `deploy/check-nonroot-helper-mode.py` — обязательный preflight и postflight инструмент
> для non-root privilege-helper модели. В root+api mode он сообщает `FAIL: User=root`, что
> ожидаемо — пропустите его и используйте `systemctl status vpn-bot` плюс диагностику
> администратора в боте. См. [Эксплуатация → Healthcheck-инструмент](operations.ru.md).
