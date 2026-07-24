# Production Operations Runbook

Операционные процедуры для работы бота в production: предварительные проверки, health-проверки,
backup/restore, восстановление по бэкендам из degraded, rollback и ручная проверка.

## Pre-deploy чеклист

- `.env` существует, не закоммичен и доступен только оператору/root.
- Родительский каталог `DB_PATH` и `LOG_DIR` существуют и не доступны для чтения всем.
- Установленный systemd unit соответствует `deploy/vpn-bot.service`. В дефолте root+api: `User=root`, `Group=root`, `ProtectSystem=false`, `RuntimeDirectory=vpn-bot`, `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
- Для root+api: `PRIVILEGE_HELPERS_ENABLED=false` (или отсутствует), `XRAY_APPLY_MODE=api`, `XRAY_INBOUND_TAG` задан, `XRAY_STATS_SERVER` указывает на адрес Xray API. Для non-root helper mode: `PRIVILEGE_HELPERS_ENABLED=true`, пути хелперов на `/usr/local/sbin/vpn-bot-*`, `/etc/sudoers.d/vpn-bot` проходит `visudo -cf`.
- `python deploy/check-nonroot-helper-mode.py` проходит перед перезапуском сервиса (non-root).
- Конфиг Xray существует по `XRAY_CONFIG_PATH` и валиден до того, как бот начнёт в него писать.
- Конфиг/интерфейс AWG существуют, если будут выдаваться AWG-ключи.
- Правила firewall известны перед открытием VPN-портов.
- Место назначения backup существует и файлы не доступны для чтения всем.
- Код, файлы деплоя и `.venv` недоступны для записи от `vpn-bot` или других недоверенных пользователей.
- Если включён managed MTProto, `vpn-bot.service` не имеет `ReadWritePaths=/etc/systemd/system`; MTProxy wrapper/drop-in установлены вручную и не содержат сырых секретов.
- Если включён managed MTProto, `/etc/mtproxy/vpn-bot/managed-secrets.json`, `mtproxy.env` и `backups/*` доступны для чтения только root/операторам.

## Общая проверка работоспособности

```bash
cd /opt/vpn-service
python deploy/check-nonroot-helper-mode.py
sudo systemctl status vpn-bot --no-pager
sudo systemctl status vpn-bot-hy2-auth hysteria-server --no-pager  # если включён Hysteria2
sudo journalctl -u vpn-bot -n 100 --no-pager
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check;"
.venv/bin/python -m compileall .
.venv/bin/python -m pytest
```

## Healthcheck-инструмент — preflight, postflight и диагностика администратора

> ⚠️ **Примечание:** `deploy/check-nonroot-helper-mode.py` предназначен для **non-root
> privilege-helper deployment model** (`User=vpn-bot` + `PRIVILEGE_HELPERS_ENABLED=true`). В
> **root+api mode** (`User=root` + `XRAY_APPLY_MODE=api`) чекер сообщит `FAIL: User=root` — это
> ожидаемо и корректно для root. Пропустите чекер в root mode; используйте
> `systemctl status vpn-bot` и панель диагностики администратора.

`deploy/check-nonroot-helper-mode.py` — обязательный preflight и postflight инструмент для
non-root privilege-separated развёртывания. Запускайте до и после каждого деплоя.

**Стандартный вывод (по умолчанию):**

```bash
cd /opt/vpn-service
python deploy/check-nonroot-helper-mode.py
```

Коды выхода:
- `0` — все проверки прошли (warnings информационные, не failures)
- `1` — одна или более проверок не прошла; устраните до запуска/перезапуска сервиса

**Machine-readable JSON (для автоматизации/CI):**

```bash
python deploy/check-nonroot-helper-mode.py --json
```

Формат JSON: `{"overall": "ok|warning|failed", "failures": N, "warnings": N, "checks": [{"status": "ok|warning|failed", "message": "..."}]}`

**Pre-start mode (по умолчанию — до `systemctl start vpn-bot`):**

```bash
python deploy/check-nonroot-helper-mode.py --mode pre-start
```

В `pre-start` отсутствие `/run/vpn-bot` ожидаемо (systemd создаёт `RuntimeDirectory` при старте)
и даёт warning, не failure.

**Post-start mode (после `systemctl start vpn-bot`):**

```bash
python deploy/check-nonroot-helper-mode.py --mode post-start
```

В `post-start` `/run/vpn-bot` должен существовать и быть writable для `vpn-bot`. Отсутствие —
failure.

**Что проверяет чекер:**

- `vpn-bot.service` содержит `User=vpn-bot`, `Group=vpn-bot`, `RuntimeDirectory=vpn-bot`, `RuntimeDirectoryMode=0700`, `ProtectSystem=strict`
- `vpn-bot.service` не содержит `User=root`, `Group=root`, `NoNewPrivileges=true`
- `/etc/sudoers.d/vpn-bot` root:root 0440, права на 4 фиксированных базовых хелпера (и, когда включён модуль WARP, на его хелперы `vpn-bot-warp-*` / `vpn-bot-warp-split-*`), без широких грантов (`NOPASSWD: ALL`, `ALL=(ALL)`)
- Бинарники хелперов root:root 0755
- `/opt/vpn-service`, `.venv`, `deploy` не доступны для записи от `vpn-bot`
- Существование и writability `/run/vpn-bot` (зависит от mode)
- `.env` не world-readable и доступен для чтения от `vpn-bot`
- SQLite `PRAGMA quick_check`
- Синтаксическая проверка конфига Xray (`xray run -test -config`)
- Strip-проверка конфига AWG (`awg-quick strip`)
- MTProxy managed files читаемы и структурно корректны (JSON)
- `sudo -n <helper> status` выполняются успешно (sudoers grants работают end-to-end)
- `systemctl is-active` для: `vpn-bot`, `xray`, `awg-quick@awg0`, `danted`, `mtproxy`

**Диагностика администратора в боте (по запросу):**

Откройте панель администратора в Telegram → *Диагностика backend*. Выполняется live read-only
healthcheck и отображается:

```
Diagnostics  OK
2026-05-12 10:30:00 UTC

✓ Non-root OK (uid=1001)
✓ PRIVILEGE_HELPERS_ENABLED=true
✓ Xray: OK
✓ AWG: OK
✓ Hysteria2: OK        (при HYSTERIA2_ENABLED; liveness data plane, выдачу ключей не гейтит)
✓ SOCKS5: OK
✓ MTProto: OK
✓ SQLite PRAGMA quick_check: ok
✓ vpn-bot: active
✓ xray: active
✓ awg-quick@awg0: active
✓ vpn-bot-hy2-auth: active   (когда включён Hysteria2)
...
```

Общий статус: `OK / WARNING / DEGRADED / FAILED`. Секреты, токены, приватные ключи и сырые
hex-значения не показываются — только безопасный статус и причина.

**Признаки, требующие rollback:**

- `FAIL: ... User=root` — сервис настроен на запуск под root (ожидаемо в root+api; failure только в non-root helper mode)
- `FAIL: ... NOPASSWD: ALL` — присутствует широкий sudo grant
- `FAIL: ... writable by vpn-bot` на каталогах кода/venv/deploy
- SQLite `PRAGMA quick_check` возвращает что-то кроме `ok`
- Бот запускается, выдаёт ключ, но Xray/AWG немедленно DEGRADED с ошибкой config apply
- `sudo -n <helper> status` возвращает permission errors — sudoers некорректен
- Бинарник хелпера не root:root 0755

При необходимости см. [Rollback после неудачного деплоя](#rollback-после-неудачного-деплоя).

## Аудит sudoers в deploy-гейте: артефакты cloud-init `NOPASSWD: ALL`

`scripts/deploy.sh` в Phase 1 (`check_sudoers_dir`) проверяет **весь** каталог
`/etc/sudoers.d/`, а не только `/etc/sudoers.d/vpn-bot`. Любой *активный* файл с грантом
`NOPASSWD: ALL` (или с обобщённым shell/интерпретатором) — это hard-fail, который прерывает
деплой:

```
[deploy][FAIL] /etc/sudoers.d/<file> contains a NOPASSWD: ALL grant
```

Файлы, в имени которых есть `.` или которые заканчиваются на `~`, инертны (sudo их игнорирует)
и понижаются до `WARN` — но одно переименование делает их активными, поэтому их всё равно
помечают. Запустить аудит read-only, без мутаций, можно так:
`PHASE1_ONLY=1 sudo scripts/deploy.sh`.

**Это корректное срабатывание, а не ложное. Не ослабляйте проверку и не добавляйте
проблемный файл в allowlist по имени.**

### cloud-init пишет `90-cloud-init-users`

На образах, провижёненных cloud-init, `/etc/sudoers.d/90-cloud-init-users` обычно содержит:

```
ubuntu ALL=(ALL) NOPASSWD:ALL
```

cloud-init **пересоздаёт этот файл каждый раз, когда на загрузке отрабатывает его модуль
`users-groups`** — при репровизе или на первой загрузке после очистки состояния cloud-init.
Поэтому даже после удаления переразвёрнутый хост вернёт файл: это ожидаемое поведение, а не
регрессия, и аудит справедливо снова упадёт, пока удаление не применят повторно. На статичном,
давно провижёненном VDS, который не переразворачивают, шаги ниже делают удаление устойчивым.

### 1. Докажите, что грант инертен, до удаления

Грант `ubuntu` эксплуатируем только если под `ubuntu` реально можно войти. Докажите, что
нельзя:

```bash
# Пароль должен быть заблокирован ("L"). "P"/"NP" — пригодный (или пустой!) пароль.
sudo passwd -S ubuntu

# authorized_keys должен быть пустым (0 байт) или отсутствовать — без ключей вход по ключу невозможен.
sudo stat -c '%s %n' /home/ubuntu/.ssh/authorized_keys 2>/dev/null || echo "no authorized_keys"

# sshd не должен принимать пароли и не должен брать ключи из неожиданного места.
sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|authorizedkeysfile|authorizedkeyscommand)\b'

# Shell (информативно): nologin/false shell сам по себе доказывает невозможность интерактивного входа.
getent passwd ubuntu
```

Грант **инертен**, когда *либо* shell аккаунта — `nologin`/`false`, *либо* одновременно
выполняется всё: пароль заблокирован (`passwd -S` → `L`), `passwordauthentication no` и
keyboard-interactive/challenge-response выключены, `authorizedkeysfile` указывает только на
пустой/отсутствующий `~/.ssh/authorized_keys`, и нет `authorizedkeyscommand`, подающего ключи
откуда-то ещё. Если хоть одна проверка не прошла (пригодный/пустой пароль, непустой
`authorized_keys`, ключи из другого пути, включён password auth) — считайте грант **живым** и
сначала закройте путь входа (`sudo passwd -l ubuntu`, отключить password auth, убрать лишние
ключи).

### 2. Удалите грант

Бот работает под root, поэтому грант `ubuntu` не нужен независимо от того, инертен он или нет:

```bash
sudo rm -f /etc/sudoers.d/90-cloud-init-users
sudo visudo -c                          # оставшийся набор sudoers по-прежнему валиден
PHASE1_ONLY=1 sudo scripts/deploy.sh    # аудит снова зелёный
```

### 3. Не дайте cloud-init пересоздать файл

**Предпочтительно на статичном, уже провижёненном VDS — отключить cloud-init целиком:**

```bash
sudo touch /etc/cloud/cloud-init.disabled
```

При наличии этого флага cloud-init ничего не делает на последующих загрузках, поэтому и не
переписывает `90-cloud-init-users`. Компромисс: cloud-init тогда перестаёт применять **любую**
конфигурацию на загрузке (сидинг пользователей/SSH-ключей, сеть, mounts, growpart и т. д.). Для
хоста, который провижёнили один раз давно и теперь ведут вручную, это желаемое состояние —
у cloud-init не осталось работы, а его заморозка убирает целый класс сюрпризов на загрузке.
**Не** ставьте этот флаг на хосте, который переразворачивают, автоскейлят или который полагается
на cloud-init для сидинга сети/SSH.

**Если cloud-init нужно оставить, но отключить только его запись пользователей/sudo**, добавьте
drop-in вместо глобального выключателя:

```bash
sudo tee /etc/cloud/cloud.cfg.d/99-no-users-sudo.cfg >/dev/null <<'EOF'
# Оставить cloud-init активным, но запретить ему управлять пользователями и
# переписывать грант `ubuntu` NOPASSWD в /etc/sudoers.d/90-cloud-init-users.
users: []
disable_root: true
EOF
```

`users: []` не трогает существующий аккаунт `ubuntu`, но говорит cloud-init не управлять ни
одним пользователем, поэтому модуль `users-groups` больше не пишет файл sudoers. (Это заодно
прекращает сидинг SSH-ключей для cloud-пользователей — на хосте с ручным управлением это норма.)
После любого из изменений перезапустите `PHASE1_ONLY=1 sudo scripts/deploy.sh` и, если возможно,
разово перезагрузитесь, чтобы убедиться, что файл не вернулся.

> **Планируемое улучшение deploy-гейта (отдельная работа).** В будущем аудит можно сделать
> *семантическим*, а не только по шаблону: грант `NOPASSWD: ALL` считается безопасным **только
> если** целевой пользователь доказуемо не может войти интерактивно (nologin/false shell **или**
> заблокированный пароль **и** пустой/отсутствующий `authorized_keys` **и** выключенный password
> auth); любой такой грант для пользователя, который *может* войти, остаётся hard-fail. Это
> намеренно отдельный, осознанный PR, а не костыль ради разблокировки одного деплоя. Пока он не
> сделан — убирайте грант на хосте, как описано выше.

## Режим обслуживания (блокировка бота)

Суперадмин может из админ-панели перевести весь бот в обслуживание (🛠 *Режим обслуживания* → включить). Пока он включён, `MaintenanceModeMiddleware` отбрасывает каждый входящий апдейт от не-суперадминов и отвечает баннером обслуживания; полный доступ сохраняют только суперадмины из `ADMIN_IDS`. Состояние сохраняется в таблице `maintenance_settings`, поэтому **переживает рестарт бота** — не забудьте выключить его из панели по завершении. Используйте как блокировку на уровне бота для безопасных правок БД или backend; она не зависит от systemd-юнита и от состояния backend DEGRADED (которое гейтит один backend, а не весь бот).

## Панель статуса сервера

Раздел статуса сервера в админ-панели показывает снимок в реальном времени (CPU, диск, сеть, онлайн-клиенты). Переключатель суперадмина включает детальный вид; выбор сохраняется в `server_status_settings.detailed_enabled`. Это read-only панель наблюдения, она никогда не меняет состояние backend.

## Backup

Сделайте резервную копию как минимум этих файлов перед деплоями, миграциями и ручными правками
backend:

```bash
sudo install -m 700 -d /root/vpn-service-backups
sudo tar --xattrs --acls -czf /root/vpn-service-backups/vpn-service-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  /opt/vpn-service/.env \
  /opt/vpn-service/data/vpn.db \
  /usr/local/etc/xray/config.json \
  /etc/amnezia/amneziawg/awg0.conf \
  /etc/hysteria/config.yaml \
  /etc/mtproxy
sudo chmod 600 /root/vpn-service-backups/vpn-service-*.tar.gz
```

При включённом Hysteria2 держите `/etc/hysteria/config.yaml` в списке — в нём незаменимые
секреты TLS/trafficStats (тот же файл, что сохраняет офсайтовый бандл
восстановления); на развёртываниях без Hysteria2 уберите строку, чтобы `tar` не ругался на
отсутствующий путь. Включайте `/opt/vpn-service/logs` только если логи нужны для анализа
инцидентов. Все backup
конфиденциальны: могут содержать токены Telegram, VPN-ключи, Xray UUID, AWG private/preshared
keys и серверные endpoints.

## Restore

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

Если `awg-quick` недоступен, но на сервере используется `wg-quick`, запустите эквивалентную
проверку `wg-quick strip`. Не запускайте `awg set`, `wg set`, `systemctl restart xray` и другие
команды, изменяющие runtime, пока конфиги не прошли read-only проверки.

## Офсайтовый бэкап: покрытие и бандл восстановления

Плановый офсайтовый бэкап (`OFFSITE_BACKUP_ENCRYPTION_KEY`) отправляет админам в Telegram два
зашифрованных документа:

- `vpnbot_backup_*.db.enc` — полный снимок SQLite (пользователи, ключи, proxy-доступы, статистика, настройки). Per-client данные пере-применяются в конфиги при старте.
- `vpnbot_recovery_*.tar.gz.enc` — **бандл восстановления** (при `OFFSITE_BACKUP_INCLUDE_CONFIGS=true`): `.env`, Xray `config.json` (REALITY private key + shortIds), AWG `.conf` (interface private key), managed-секреты MTProto, конфиг WARP и (когда включён Hysteria2) `config.yaml` hysteria-server. Это незаменимые серверные секреты, которых **нет** в БД — без них пересозданный сервер выдаст новые пары ключей и сломает все ранее выданные конфиги. Недоступные/отсутствующие файлы пропускаются и фиксируются в `MANIFEST.json`.

Восстановление из бандла на чистом сервере:

```bash
# Расшифровка (KEY = OFFSITE_BACKUP_ENCRYPTION_KEY, хранится ОТДЕЛЬНО от бандла):
python -c "from cryptography.fernet import Fernet; open('recovery.tar.gz','wb').write(Fernet(b'KEY').decrypt(open('vpnbot_recovery_*.tar.gz.enc','rb').read()))"
tar xzf recovery.tar.gz            # MANIFEST.json содержит исходный абсолютный путь каждого файла
# Разложите файлы по путям из MANIFEST, восстановите снимок .db.enc, проверьте
# конфиги (см. «Restore» выше) и запустите vpn-bot — отработает реконсиляция.
```

Так как бандл содержит `.env` (а в нём — сам `OFFSITE_BACKUP_ENCRYPTION_KEY`), храните ключ в
отдельном секрет-хранилище, иначе бандл нечем будет расшифровать.

## Firewall и открытые порты

- По возможности держите SSH открытым только для доверенных источников.
- Откройте публичный TCP-порт Xray, обычно `443/tcp`.
- Откройте публичный UDP-порт AWG endpoint из `AWG_ENDPOINT_PORT` или `ListenPort` в конфиге AWG.
- Если включён Hysteria2, откройте публичный **UDP**-порт Hysteria2 из `HYSTERIA2_PORT` (дефолт `443` — чистый QUIC, без salamander; сосуществует с Xray на TCP/443, другой транспорт). Эндпоинт `hy2_auth` (`HYSTERIA2_AUTH_LISTEN`) и Traffic Stats API (`HYSTERIA2_STATS_LISTEN`) держите только на loopback — никогда не открывайте их в интернет.
- Открывайте Dante/SOCKS только если намеренно развёртываете отдельный прокси с защитой.
- Держите `XRAY_STATS_SERVER` привязанным только к localhost, например `127.0.0.1:<port>`. Никогда не открывайте Xray stats API в интернет.
- Если политика UFW для перенаправленного трафика по умолчанию `deny`, явно разрешите трафик AWG-клиентов.

Примеры read-only проверок:

```bash
sudo ufw status verbose
sudo ss -tulnp
```

## Read-only health checks

```bash
sudo systemctl status vpn-bot --no-pager
sudo systemctl status xray --no-pager
sudo systemctl status danted --no-pager
sudo ss -tlnp | grep 31337
sudo systemctl status mtproxy --no-pager
sudo ss -tlnp | grep 8443
sudo systemctl status hysteria-server vpn-bot-hy2-auth --no-pager   # если включён Hysteria2
sudo ss -ulnp | grep :443                                          # публичный UDP-порт Hysteria2
curl -s http://127.0.0.1:8444/healthz                              # liveness hy2_auth (loopback)
sudo systemctl status vpn-bot-subscription --no-pager              # если развёрнут эндпоинт подписки
sudo ss -tlnp | grep -E '8445|2096'                                # его loopback- и публичный HTTPS-порт
curl -si http://127.0.0.1:8445/sub/not-a-real-token | head -1       # ожидаем 404 (см. docs/subscription.ru.md)
sudo journalctl -u vpn-bot -n 100 --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo awg show
sudo awg-quick strip /etc/amnezia/amneziawg/awg0.conf >/dev/null
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check; SELECT status, key_type, COUNT(*) FROM vpn_keys GROUP BY status, key_type;"
```

Если `XRAY_STATS_SERVER` настроен локально, запрашивайте его только с сервера или localhost.
После операций create/revoke/delete убедитесь, что статусы в DB бота, клиенты в Xray config,
peers в AWG config и AWG runtime peers согласованы.

## Восстановление из degraded

Бот помечает backend как DEGRADED, когда сверка или post-apply компенсация не могут подтвердить,
что SQLite и серверный runtime безопасно изменять автоматически. DEGRADED специфичен для каждого
backend — остальные продолжают работать, если они не DEGRADED.

### Восстановление после деградации Xray

Xray DEGRADED блокирует только Xray create/revoke/delete/manual reconcile. AWG, SOCKS5 и MTProto
продолжают работать, если не деградированы отдельно.

```bash
sudo systemctl status xray --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo jq '[.inbounds[]?.settings.clients[]? | {email}]' /usr/local/etc/xray/config.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='xray' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Проверьте ручных клиентов/orphan-записи, неудачные pending-статусы и синтаксис конфига.
Восстановите из backup или удалите только подтверждённые bot-managed расхождения, затем
перезапустите `vpn-bot` и повторно откройте диагностику backend.

### Восстановление после деградации AWG

AWG DEGRADED блокирует только AWG create/revoke/delete/manual reconcile. Xray, SOCKS5 и MTProto
продолжают работать.

```bash
sudo systemctl status awg-quick@awg0 --no-pager
sudo awg show
sudo awk '/^# vpn-bot key_id=|^PublicKey =|^AllowedIPs =/{print}' /etc/amnezia/amneziawg/awg0.conf
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='awg' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Не выводите AWG private keys или preshared keys в тикеты/чаты. Сравнивайте только public
keys/client IP, исправляйте подтверждённые расхождения из backup или вручную, затем
перезапустите `vpn-bot`.

### Восстановление после деградации SOCKS5

SOCKS5 DEGRADED блокирует только SOCKS5 issue/revoke/delete. Xray, AWG и MTProto продолжают
работать.

```bash
sudo systemctl status danted --no-pager
getent passwd | awk -F: '$1 ~ /^vpn_socks_/ {print $1}'
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='socks5' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Убедитесь, что каждый управляемый Linux-пользователь начинается с `SOCKS5_LOGIN_PREFIX`; не
выводите SOCKS5-пароли. Блокируйте/удаляйте только подтверждённых bot-managed «посторонних»
пользователей, восстановите SQLite из backup при необходимости, затем перезапустите `vpn-bot`.

### Восстановление после деградации MTProto

MTProto DEGRADED блокирует только MTProto issue/revoke/delete. Xray, AWG и SOCKS5 продолжают
работать.

```bash
sudo systemctl status mtproxy --no-pager
sudo jq '{secret_count: (.secrets | length), fingerprints: [.secrets[]?.fingerprint]}' /etc/mtproxy/vpn-bot/managed-secrets.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='mtproto' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Не выводите сырые MTProto-секреты. В static-режиме per-user server-side revoke невозможен;
ротируйте `MTPROTO_SECRET`, если нужно инвалидировать скопированный общий секрет. В managed mode
сравнивайте счётчики/fingerprints, восстановите managed-файлы из `/etc/mtproxy/vpn-bot/backups`
при необходимости, перезапустите `mtproxy`, затем `vpn-bot`.

### Health и восстановление Hysteria2

В отличие от Xray/AWG/SOCKS5/MTProto, отметка Hysteria2 `DEGRADED` — **информационная и никогда
не блокирует** выдачу/отзыв ключей: issuance/revocation Hysteria2 — это чистые записи в `vpn.db`
без apply-шага, гейтить нечего. Запись `Hysteria2: OK/DEGRADED` отражает только **liveness data
plane**: фоновый цикл опрашивает эндпоинт `hy2_auth` `GET /healthz` каждые
`HYSTERIA2_HEALTH_INTERVAL` секунд. Поэтому `DEGRADED` означает «data plane авторизации handshake
недоступен», т.е. новые handshake отклоняются, хотя строки ключей в БД целы.

```bash
sudo systemctl status vpn-bot-hy2-auth --no-pager        # loopback-эндпоинт авторизации handshake
sudo systemctl status hysteria-server --no-pager         # собственно data plane Hysteria2
curl -s http://127.0.0.1:8444/healthz                    # 200 {"ok":true}, когда vpn.db читается
sudo journalctl -u vpn-bot-hy2-auth -n 100 --no-pager    # ошибки БД логируются здесь на ERROR
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, COUNT(*) FROM vpn_keys WHERE key_type='hysteria2' GROUP BY status;"
```

Восстановление — на уровне сервиса, а не сверки конфигов: верните `vpn-bot-hy2-auth` (и при
необходимости `hysteria-server`) в active — эндпоинт читает **живую** базу, поэтому после
восстановления отзывы/выдачи применяются на следующем handshake без перезапуска data plane. Если
`GET /healthz` вернул `503`, эндпоинт не может прочитать `vpn.db` (locked/corrupt или отсутствует
WAL-грант `ReadWritePaths` — см. [Развёртывание → Hysteria2 data plane](deployment.ru.md#hysteria2-data-plane-эндпоинт-hy2_auth));
сначала почините доступ к базе. Per-key трафик, счётчик онлайна и revoke-`/kick` дополнительно
требуют Traffic Stats API (`HYSTERIA2_STATS_SECRET`); без него они остаются пустыми, но на
авторизацию handshake и на health-запись не влияют.

## Rollback после неудачного деплоя

> ⚠️ **Сначала сделайте backup.** Всегда создавайте резервную копию перед откатом кода (см.
> [Backup](#backup)). Откат кода не откатывает runtime-состояние — SQLite, конфиги Xray и AWG
> требуют отдельного восстановления, если деплой их изменил.

> **Автоматический деплой (`scripts/deploy.sh`).** Скрипт деплоя сам выполняет откат при
> провале любой проверки, восстанавливая код, venv, БД, конфиги и unit. Два важных момента:
> он восстанавливает снапшот БД, снятый *до* запуска нового кода, поэтому записи, сделанные
> пока новый бот был жив в окне post-start health-check, теряются; и он выполняет деплой
> только в рамках той же модели привилегий (смена модели закрыта за `ALLOW_MODEL_SWITCH=1` и
> требует предварительной миграции хоста — см. раздел Deploy в [README](../README.md)). Шаги
> ниже — для ручного отката, когда вы не используете скрипт.

**Шаг 1 — остановите сервис и создайте backup runtime-состояния:**

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

`git reset --hard` отбрасывает все локальные изменения кода на сервере. Используйте только для
отката нежелательного деплоя.

> **`init_db.py` только для чистых установок.** НЕ запускайте `init_db.py` при откате — он
> требует `BOT_TOKEN`/`ADMIN_IDS` и попытается применить прямые миграции к существующей базе.
> Бот сам применяет схему при старте; если предыдущая версия совместима по схеме, достаточно
> перезапустить сервис.

**Шаг 3 — восстановите runtime-состояние из backup, если деплой его изменил:**

```bash
# Восстановить SQLite DB
sudo cp /root/vpn-service-backups/<backup>.tar.gz /tmp/
sudo tar -xzf /tmp/<backup>.tar.gz -C / opt/vpn-service/data/vpn.db

# Восстановить конфиг Xray и проверить
sudo tar -xzf /tmp/<backup>.tar.gz -C / usr/local/etc/xray/config.json
sudo xray run -test -config /usr/local/etc/xray/config.json

# Восстановить конфиг AWG
sudo tar -xzf /tmp/<backup>.tar.gz -C / etc/amnezia/amneziawg/awg0.conf
```

**Шаг 4 — запустите и проверьте:**

```bash
sudo systemctl start vpn-bot
sudo systemctl status vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

## Обслуживание — обновление с GitHub

```bash
cd /opt/vpn-service
sudo git pull --ff-only
sudo /opt/vpn-service/.venv/bin/pip install -r requirements.txt -c constraints.txt
python deploy/check-nonroot-helper-mode.py
sudo systemctl restart vpn-bot
python deploy/check-nonroot-helper-mode.py
```

**Managed MTProto: обновляйте wrapper после каждого апдейта.** `git pull` выше обновляет
tracked-источник `deploy/run-mtproxy-managed`, но systemd реально запускает установленную
runtime-копию по пути `/opt/vpn-service/scripts/run-mtproxy-managed`
(`MTPROTO_MANAGED_WRAPPER_PATH`). Этот путь — gitignore-артефакт установки: его не обновляют
ни `git pull`/`git reset`, ни `scripts/deploy.sh` (который ставит только `vpn-bot.service`),
поэтому обновлённый wrapper — включая security-фиксы вроде allowlist ключей env и валидации
портов — не попадёт в работающий прокси, пока вы не переустановите его явно. Пропустите этот
шаг — и прокси продолжит работать на устаревшем wrapper'е.

```bash
# Переустановить managed-MTProto wrapper из обновлённого tracked-источника (root:root 0700).
sudo install -m 700 -o root -g root \
  deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed
sudo systemctl restart mtproxy
sudo systemctl status mtproxy --no-pager
# Убедиться, что runtime-копия совпала с источником, а дерево осталось чистым:
sudo cmp deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed \
  && echo "wrapper up to date"
git status --porcelain   # scripts/run-mtproxy-managed в gitignore -> не показывается
```

Не запускайте production DB-миграции от root против `/opt/vpn-service/data/vpn.db`. Сервис
инициализирует схему/миграции при запуске от `vpn-bot`; если нужно запустить `init_db.py`
вручную, делайте это с той же непривилегированной учётной записью и окружением, что и сервис.

## Ручная проверка на VDS после исправлений

На тестовом пользователе перед production:

1. Создайте один Xray-ключ, убедитесь, что он активен в DB и присутствует в конфиге Xray.
2. Отзовите и удалите Xray-ключ, убедитесь, что DB/config/runtime больше не дают доступ.
3. Создайте один AWG-ключ, убедитесь, что DB, `awg0.conf` и `awg show` согласованы.
4. Отзовите и удалите AWG-ключ, убедитесь, что peer удалён из config и runtime.
5. (Hysteria2, при `HYSTERIA2_ENABLED`) Создайте один Hysteria2-ключ, убедитесь, что он активен в БД (`key_type='hysteria2'`) и что свежий client handshake авторизуется — принятый handshake виден в `journalctl -u vpn-bot-hy2-auth`.
6. Отзовите Hysteria2-ключ и убедитесь, что следующий handshake отклоняется **без перезапуска data plane** (эндпоинт `hy2_auth` читает живую БД). При включённом Traffic Stats API (`HYSTERIA2_STATS_SECRET`) убедитесь, что уже установленная сессия также рвётся best-effort `/kick`.
7. Откройте «Прокси» от одобренного тестового пользователя, выдайте SOCKS5 после подтверждения и убедитесь, что сообщение содержит Host, Port, Login, Password и URL.
8. Выдайте MTProto после подтверждения и убедитесь, что обычная Telegram-ссылка идёт перед `dd`-ссылкой.
9. В `MTPROTO_MODE=managed` выдайте MTProto пользователю A и запишите только несекретный fingerprint/count из статуса администратора.
10. Выдайте MTProto пользователю B и убедитесь, что статус показывает два активных managed MTProto access.
11. Заблокируйте или admin-revoke пользователя A, затем убедитесь, что managed secrets file больше не содержит fingerprint A, а fingerprint B остаётся активным.
12. Убедитесь, что Telegram MTProto-ссылка пользователя B работает после отзыва A.
13. Симулируйте неудачный apply на staging (например, временно направив `MTPROTO_SERVICE_NAME` на failing test unit или остановив проверку порта), затем revoke/issue и убедитесь, что rollback восстанавливает предыдущие managed secrets/env-файлы и `mtproxy` возвращается в active/listening.
14. В `MTPROTO_MODE=static` заблокируйте пользователя и убедитесь, что MTProto деактивирован только в SQLite.
15. Убедитесь, что логи бота и audit-вывод не содержат SOCKS5-паролей, `MTPROTO_SECRET` или сырых managed MTProto-секретов.
16. Проверьте `systemctl cat mtproxy`, `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment` и `journalctl -u mtproxy -n 100 --no-pager` на отсутствие сырых MTProto-секретов.
17. Проверьте права managed-файлов:
    ```bash
    sudo stat -c '%U:%G %a %n' /opt/vpn-service/scripts/run-mtproxy-managed /etc/mtproxy/vpn-bot/managed-secrets.json /etc/mtproxy/vpn-bot/mtproxy.env
    sudo find /etc/mtproxy/vpn-bot/backups -maxdepth 2 -printf '%u:%g %m %p\n'
    ```
18. Отправьте объявление с одобренными, ожидающими и заблокированными тестовыми пользователями; его должны получить только одобренные пользователи и superadmin'ы.
