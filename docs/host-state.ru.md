# Состояние хоста как код

[English version](host-state.md)

Чекаут в `/opt/vpn-service` — ещё не всё развёртывание. На рабочем хосте есть и файлы вне него:
настройки ядра, правило ротации логов, переопределение порта ssh, хук раскладки сертификата,
перезагрузка по расписанию. Пока они живут только на хосте, пересобранному или перенесённому
серверу их неоткуда восстановить, а разъехавшуюся ручную правку никто не замечает.

Поэтому `scripts/deploy.sh` владеет объявленным набором файлов хоста. Он их ставит, чинит при
drift, удаляет выведенные из оборота — а в Phase 1 сообщает обо всех остальных файлах в
сканируемых каталогах хоста, которые ничем не учтены.

## Пять классов

Каждый файл хоста относится ровно к одному из них:

| Класс | Источник истины | Кто пишет его на хосте |
|---|---|---|
| **repo-managed** | побайтная копия в репо | `deploy.sh` (а для `deploy/*.service`, кроме бота, — оператор после drift-гейта) |
| **шаблон + значения хоста** | в репо — *форма*, на хосте — значения | оператор / бот, проверяется гейтом деплоя |
| **backup-only** | по замыслу не в репо; перечислен в `deploy/host/known-unmanaged.list` | сторонний установщик, провайдер или оператор — и offsite-бэкап |
| **retired** | запись `class absent`: файла быть *не* должно | `deploy.sh` его удаляет |
| **дефолт пакета** | сам пакет: запись `class pristine` называет `dpkg:<package>` или `ucf:<template>` | `deploy.sh`, и только обратно к дефолту пакета — [Дефолты пакетов](#дефолты-пакетов-class-pristine) |

`known-unmanaged.list` помечает каждую backup-only запись тем, кто её пишет: `installer`
(Xray-install, get.hy2.sh, `setup-nonroot-helper-mode.sh`…), `provider` (образ VPS),
`backup-only` (наш файл, хранится только в offsite system-бандле) или `deployment-local`
(уникален для этого развёртывания по замыслу и не может лежать в репо).

## Все файлы хоста

Колонка **Offsite-бэкап** говорит, что уносит файл с хоста: элемент
`DEFAULT_OFFSITE_SYSTEM_PATHS` (`config/settings.py`) — для system-бандла, *бандл
восстановления* или `—`, если ничего (файл переустанавливается своим установщиком или выведен из
оборота). Копии конфигов `*.bak*` рядом с перечисленными файлами намеренно не берутся — см.
[Что системный бандл не берёт](operations.ru.md#что-системный-бандл-не-берёт). Бандл несёт и
состояние, которое не является разворачиваемым файлом и потому здесь не перечислено: сайт-приманку
(`/var/www`), `/root/.acme.sh`, `/etc/sudoers.d`, `/etc/passwd` и `/etc/group` и другое
([полный список](operations.ru.md#что-именно-закрывает-системный-бандл)).

### main

| Путь | Класс | Кто ставит | Offsite-бэкап | Заметки |
|---|---|---|---|---|
| `/etc/logrotate.d/xray` | repo-managed (`logrotate`) | deploy.sh | `/etc/logrotate.d` | `copytruncate`: xray не умеет переоткрывать логи, а пишет их с `O_APPEND` |
| `/etc/systemd/system/even-day-reboot.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | перезагружает хост — деплой его **никогда** не запускает |
| `/etc/systemd/system/even-day-reboot.timer` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | дни 5,10,…,30 в 01:00 UTC (04:00 MSK); `enable --now` только если он был enabled или файла не было |
| `/etc/sysctl.d/90-no-mptcp.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | MPTCP выключен до ядра с исправлением CVE-2026-98432; файл побайтно равен копии хоста, поэтому причина записана здесь, а не в нём |
| `/etc/sysctl.d/99-bbr.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | `fq` + BBR |
| `/etc/sysctl.d/99-network-buffers.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | буферы сокетов, backlog, dirty ratios |
| `/etc/sysctl.d/99-swap-tuning.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | |
| `/etc/sysctl.d/99-vpn-forwarding.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | единственный `net.ipv4.ip_forward=1` |
| `/etc/systemd/journald.conf.d/10-vpn-bot.conf` | repo-managed (`journald`) | deploy.sh | `/etc/systemd` | `SystemMaxUse=500M`; заменяет ручную правку `journald.conf` |
| `/etc/systemd/journald.conf` | дефолт пакета (`pristine`, `dpkg:systemd`) | пакет `systemd`; deploy.sh возвращает дефолт пакета | `/etc/systemd` | старая ручная правка (`SystemMaxUse=500M`) лишь дублирует drop-in: Phase 2 возвращает стоковый файл, когда Phase 1 доказала, что ничего эффективного не меняется, затем перезапускает journald |
| `/etc/systemd/resolved.conf.d/10-vpn-bot.conf` | repo-managed (`resolved`) | deploy.sh | `/etc/systemd` | `DNS=1.1.1.1 8.8.8.8`, `FallbackDNS=1.0.0.1 8.8.4.4`; заменяет ручную правку `resolved.conf` — [DNS на основном сервере](#dns-на-основном-сервере) |
| `/etc/systemd/resolved.conf` | дефолт пакета (`pristine`, `dpkg:systemd-resolved`) | пакет systemd-resolved; deploy.sh возвращает дефолт пакета | `/etc/systemd` | ручная правка (`DNS=`, `FallbackDNS=`) дублирует drop-in: возвращается как `journald.conf`, затем reload как у класса `resolved` |
| `/etc/resolv.conf` | repo-managed (`plain`) | deploy.sh, из `deploy/host/dns/resolv.conf` | — (в репо) | обычный файл, а не stub-symlink resolved; побайтно равен копии хоста; инвариант `path-regular` |
| `/etc/systemd/networkd.conf.d/10-keep-foreign-rules.conf` | repo-managed (`networkd`) | deploy.sh | `/etc/systemd` | не даёт networkd сбрасывать `ip rule` WARP; действует со следующего старта networkd |
| `/usr/local/sbin/acme-reload.sh` | repo-managed (`hook`, `when=/etc/vpn-bot/tls/fullchain.pem`) | deploy.sh, из `deploy/vpn-bot-acme-reload.sh` | `/usr/local/sbin` | `Le_ReloadCmd` у acme.sh; только там, где есть сертификат; [subscription.ru.md](subscription.ru.md#tls-терминация) |
| `/etc/ssh/sshd_config.d/00-root-key-only.conf` | repo-managed (`ssh`) | deploy.sh | `/etc/ssh` | вход root только по ключу; см. [ALLOW_SSH_CHANGE](#allow_ssh_change-и-риск-потери-доступа) |
| `/etc/systemd/system/ssh.socket.d/override.conf` | шаблон + значения хоста (`ssh`, `render=ssh-port`) | deploy.sh, рендер из `SSH_PORT` | `/etc/systemd` | `ListenStream` на `SSH_PORT` (IPv4 + IPv6); во время переезда — на обоих портах, [SSH-порт](#ssh-порт). Для 54321 байт в байт прежний фиксированный файл |
| `/etc/ssh/sshd_config.d/00-vpn-bot-port.conf` | шаблон + значения хоста (`ssh`, `render=ssh-port`) | deploy.sh, рендер из `SSH_PORT` | `/etc/ssh` | `Port SSH_PORT` (запасной путь: ssh.service без сокета) + `LogLevel VERBOSE` (доказательство по журналу) |
| `/etc/systemd/system/vpn-bot-ssh-port.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | oneshot `vpn-bot-ssh-port advance`: фаза 2 доказанного переезда; его подтягивает `vpn-bot-host-check.service` (`Wants=`), сам не включается |
| `/var/lib/vpn-bot/ssh-migration.json` | состояние | `vpn-bot-ssh-port` | — | переезд (`from`, `to`, `phase`, `since`, доказательство); атомарно, `root` `0644`; его читает бот |
| `/etc/systemd/system/vpn-bot-ufw-deadman.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | oneshot `vpn-bot-ufw-apply deadman-check`: недоказанная смена политики UFW после перезагрузки остаётся или откатывается; его подтягивает `vpn-bot-host-check.service` (`Wants=`), сам не включается — [Фаервол (UFW)](#фаервол-ufw) |
| `/etc/ufw/user.rules`, `/etc/ufw/user6.rules`, `/etc/default/ufw` | вычисляется (`vpn-bot-ufw-apply`) | деплой и бот через `vpn-bot-ufw-apply`; никогда не `ufw allow` руками | `/etc/ufw/user.rules`, `/etc/ufw/user6.rules`, `/etc/default/ufw` | набор: таблица модулей + ssh + `deploy/host/ufw/extra.list`; политики из `deploy/host/ufw/policy` (routed не трогается) |
| `/var/lib/vpn-bot/ufw-deadman.json` | состояние | `vpn-bot-ufw-apply` | — | смена политики под dead-man (`pending`, `confirmed`, `reverted`); атомарно, `root` `0644`; его читает бот |
| `/etc/ssh/sshd_config` | дефолт пакета (`pristine`, `ucf:/usr/share/openssh/sshd_config`) | openssh-server (ucf); deploy.sh возвращает шаблон | `/etc/ssh` | активные `PasswordAuthentication yes` / `PermitRootLogin yes` образа провайдера после `Include` — LATENT, который останавливает Phase 1: файл возвращается, когда доказано, что `sshd -T` побайтно не меняется, — без `ALLOW_SSH_CHANGE` |
| `/etc/cloud/cloud-init.disabled` | repo-managed (`plain`) | deploy.sh, из `deploy/host/cloud/cloud-init.disabled` | — (в репо) | пустой маркер: cloud-init выключен (на ребуте он переписывал sshd и sudoers) |
| `/etc/systemd/system/vpn-bot-host-check.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | oneshot: проверка инвариантов хоста — [Эффективное состояние](#эффективное-состояние) |
| `/etc/systemd/system/vpn-bot-host-check.timer` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | через 5 минут после загрузки, затем раз в сутки; `enable --now`, как любой таймер реестра |
| `/var/lib/vpn-bot-host-check/last.json` | состояние | `vpn-bot-host-check` | — | последний вердикт (атомарно, `root` `0644`); его читает бот |
| `/etc/systemd/system/danted.service.d/vpn-bot-warp.conf` | repo-managed (`unit`) | deploy.sh, из `deploy/danted-warp.conf` | `/etc/systemd` | порядок запуска после интерфейса WARP |
| `/etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf` | repo-managed (`unit`, `gate=MTPROTO`) | deploy.sh, из `deploy/mtproxy-vpn-bot-managed.conf` | `/etc/systemd` | только пока `MTPROTO_ENABLED=true`; побайтно равный файл со старым именем `vpnbot-managed.conf` переименовывается. При выключенном MTProxy оставшийся drop-in показывается как сирота |
| `/etc/systemd/system/vpn-bot.service` | repo-managed | deploy.sh, как есть | `/etc/systemd` | действуют гейты модели привилегий |
| `/etc/systemd/system/<deploy/*.service, *.timer>` | repo-managed | оператор, руками | `/etc/systemd` | drift-гейт юнитов в Phase 1 печатает команды установки |
| `/usr/local/sbin/vpn-bot-warp-*`, `warp-failsafe`, `vpnbot-hy2-warp-mark`, `vpn-bot-db-perms`, `vpn-bot-host-check`, `vpn-bot-ssh-port`, `vpn-bot-ufw-apply` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | `/usr/local/sbin` | из `scripts/` |
| `/usr/local/sbin/vpn-bot-{xray,awg,mtproxy}-apply`, `vpn-bot-socks5-user` | backup-only (`installer`) | `deploy/setup-nonroot-helper-mode.sh` | `/usr/local/sbin` | исходники в `deploy/helpers/` |
| `/usr/local/etc/xray/config.json` | шаблон + значения хоста | бот (клиенты) / оператор | бандл восстановления | структуру проверяет `deploy/backend-config-sync.py` |
| `/etc/amnezia/amneziawg/awg0.conf` | шаблон + значения хоста | бот (peers) / оператор | бандл восстановления; `/etc/amnezia` | тот же гейт |
| `/etc/hysteria/config.yaml` | шаблон + значения хоста | `deploy/hysteria/install-config.sh` | бандл восстановления (при включённом Hysteria2); `/etc/hysteria` | тот же гейт |
| `/opt/vpn-service/.env` | шаблон + значения хоста | оператор | бандл восстановления | `.env.example` |
| `/etc/vpn-bot/tls/*` | значения хоста | acme.sh; права ставит хук | `/etc/vpn-bot` | каталог `root:root 0755`, `fullchain.pem`/`privkey.pem` `root:vpn-bot 0640` |
| `/etc/systemd/system/xray*.service` (+ `.d/`), `/usr/local/bin/xray` | backup-only (`installer`) | Xray-install | юниты: `/etc/systemd`; бинарник: — (переустанавливается) | |
| `/etc/systemd/system/hysteria-server*.service` (+ `.d/`), `/usr/local/bin/hysteria` | backup-only (`installer`) | get.hy2.sh | юниты: `/etc/systemd`; бинарник: — (переустанавливается) | |
| `/usr/local/bin/wgcf`, `/usr/local/bin/qr` | backup-only (`installer`) | их собственные установщики | — (переустанавливаются) | |
| `/etc/nginx/conf.d/*.conf` | backup-only | оператор | `/etc/nginx/conf.d` | vhost decoy / self-steal с доменом хоста; шаблон в репо — отдельная задача |
| `/etc/netplan/*` | backup-only (`provider`) | образ VPS | `/etc/netplan` | вне сканируемого набора; перечислен для полноты |
| `/var/spool/cron/crontabs/root` | backup-only | acme.sh (строка `--cron`) | `/var/spool/cron/crontabs` | |
| `/usr/local/sbin/site-freshen.py` | backup-only (`deployment-local`) | оператор | `/usr/local/sbin` | перезаписыватель decoy — [по замыслу](hysteria.ru.md) никогда не в репо, поэтому offsite system-бандл — его единственная копия вне хоста |
| `/etc/sysctl.d/99-amneziawg.conf` | retired | — | — | дубль `ip_forward=1` |
| `/etc/systemd/system/warp-sample.timer` | retired | — | — | `disable --now`, затем удаляется |
| `/etc/systemd/system/warp-sample.service` | retired | — | — | `disable --now`, затем удаляется |
| `/usr/local/sbin/site-freshen.sh` | retired | — | — | его работу теперь делает `deploy/vpn-bot-decoy-freshen.sh` |
| `/etc/ssh/sshd_config.d/50-cloud-init.conf` | retired | — | — | `PasswordAuthentication yes` от cloud-init; сначала удалён руками, запись не даёт ему вернуться (удаление перезагружает ssh) |
| `/etc/sudoers.d/90-cloud-init-users` | retired | — | — | `NOPASSWD:ALL` от cloud-init; сначала удалён руками |

### relay

На relay нет бота, поэтому offsite-бэкап он не отправляет: его файлы возвращаются из репо, а
`90-vpn-relay.conf` заново рендерится из `.env` relay.

| Путь | Класс | Кто ставит | Заметки |
|---|---|---|---|
| `/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf` | repo-managed (`ssh`) | deploy.sh | вход только по ключу |
| `/etc/ssh/sshd_config` | дефолт пакета (`pristine`, `ucf:/usr/share/openssh/sshd_config`) | openssh-server (ucf); deploy.sh возвращает шаблон | как на main |
| `/usr/local/sbin/vpn-relay-apply` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | |
| `/usr/local/sbin/vpn-bot-host-check` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | проверка инвариантов хоста |
| `/usr/local/sbin/vpn-bot-ssh-port` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | переезд SSH-порта — [SSH-порт](#ssh-порт) |
| `/etc/systemd/system/ssh.socket.d/override.conf`, `/etc/ssh/sshd_config.d/00-vpn-bot-port.conf` | шаблон + значения хоста (`ssh`, `render=ssh-port`) | deploy.sh, рендер из `SSH_PORT` | как на main; у relay override не было (22 из пакета) — его первый деплой начинает переезд 22 → 54321 |
| `/etc/systemd/system/vpn-bot-ssh-port.service` | repo-managed (`unit`) | deploy.sh | как на main |
| `/var/lib/vpn-bot/ssh-migration.json` | состояние | `vpn-bot-ssh-port` | как на main (бот его здесь не читает) |
| `/etc/systemd/system/vpn-bot-host-check.service`, `.timer` | repo-managed (`unit`) | deploy.sh | как на main; вердикт relay остаётся в его журнале — [Между деплоями](#между-деплоями) |
| `/etc/cloud/cloud-init.disabled` | repo-managed (`plain`) | deploy.sh | cloud-init выключен |
| `/etc/ssh/sshd_config.d/50-cloud-init.conf`, `/etc/sudoers.d/90-cloud-init-users` | retired | — | вход по паролю и `NOPASSWD:ALL` от cloud-init |
| `/etc/systemd/system/vpn-relay.service` | repo-managed | deploy.sh, как есть | |
| `/etc/sysctl.d/90-vpn-relay.conf` | шаблон + значения хоста | `vpn-relay-apply apply`, из `.env` relay | |

## Как деплой с ними обращается

Реестр — массив `MANAGED_HOST_FILES` в `scripts/deploy.sh`, одна запись на файл:

```text
"<src в чекауте>|<dst>|<mode>|<owner:group>|<class>|<role>[|<opts>]"
```

`role` — `main` или `relay`: хост видит только записи своей роли. У класса `pristine` `src` —
не файл чекаута, а откуда берётся дефолт пакета: `dpkg:<package>` или `ucf:<template>`. `opts`
необязателен:
`gate=<PROTO>` делает запись существующей только при включённом `<PROTO>_ENABLED` в `.env`,
`when=<path>` — только на хосте, где есть `<path>`, а `legacy=<path>` называет старое имя того же
файла. Закрытый gate означает, что запись не ставится и не проверяется. `render=ssh-port` делает
`src` шаблоном: каждая строка с `@SSH_PORT@` пишется по разу на каждый порт, который решил план
SSH-порта ([SSH-порт](#ssh-порт)), а отрендеренная копия сравнивается, проверяется и ставится как
любой файл репо.

| class | Phase 1 проверяет кандидата | Phase 2 после фактического изменения |
|---|---|---|
| `logrotate` | `logrotate -d` — ни одной строки `^error` | — |
| `sysctl` | каждый ключ есть под `/proc/sys` (ключ nf_conntrack / mptcp при незагруженном модуле — только предупреждение) | `sysctl -e -p <file>` |
| `unit` | `systemd-analyze verify` (advisory, те же фатальные шаблоны, что для `vpn-bot.service`); drop-in — структура `[Section]` | `daemon-reload`; `*.timer` получает `enable --now`, если был enabled или файла не было. Сервисы никогда не запускаются и не перезапускаются |
| `journald` | секция `[Journal]` | `systemctl restart systemd-journald` |
| `networkd` | секция `[Network]` | — (действует со следующего старта networkd) |
| `hook` | `<кандидат> --dry-run` выходит с 0 | — |
| `plain` | — (ставится как есть) | — (ничего не перезагружается) |
| `resolved` | секция `[Resolve]` | `systemctl try-reload-or-restart systemd-resolved`, затем `getent ahosts github.com` в течение 10 с — иначе деплой откатывается (rollback тоже перезагружает resolved) |
| `ssh` | `sshd -t` на `sshd_config`, где кандидат подставлен в копию каталога drop-in'ов; drop-in сокета должен оставлять порт `ListenStream` | см. [ниже](#allow_ssh_change-и-риск-потери-доступа) |
| `absent` | ничто не должно на него ссылаться (ниже) | `disable --now`, если это unit-файл, затем удаление; после файла из `sshd_config.d` — `sshd -t` + reload + проверка порта, как после изменения ssh |
| `pristine` | у копии md5 самого пакетного менеджера; её установка не меняет ничего эффективного (host check `--pristine`; для `sshd_config` ещё `sshd -T`) | атомарная установка; `journald.conf` → restart journald, `resolved.conf` → как `resolved`, `sshd_config` → как `ssh` — [ниже](#дефолты-пакетов-class-pristine) |

**Phase 1** (только чтение, в том числе при `PHASE1_ONLY=1`) сверяет каждую запись с
`origin/main` и показывает состояние каждого файла: `synced`, `absent` (будет установлен),
`drift` (будет переустановлен — печатается diff), `meta` (содержимое верное, права/владелец нет —
чинится на месте), `rename`, `present` / `gone` (выведенные файлы), `gated-off`, `cannot-restore`
(дефолт пакета не удалось получить или проверить: WARN, никогда не остановка). Она проверяет
каждого кандидата, которого поставит Phase 2, и **останавливается до любых изменений**, если
валидатор его отверг, если на выведенный файл ещё есть ссылка, если файл со старым именем
отличается от репо, если ssh-файл отличается без `ALLOW_SSH_CHANGE=1` или если возврат дефолта
пакета изменил бы эффективную конфигурацию.

**Phase 2** сначала кладёт каждый путь, который может тронуть, в архив бэкапа, затем ставит, чинит
и удаляет, выполняет post-action каждого класса один раз для того, что реально изменилось, и
сканирует заново: ничего не должно остаться absent, в drift или present. Любой сбой идёт обычным
rollback, который возвращает каждый сохранённый файл — или снова удаляет его, если его не было, —
и заново применяет восстановленное состояние: enable юнитов, прежние значения sysctl в рантайме,
journald, ssh.

## Дефолты пакетов (class pristine)

Некоторые файлы хоста репо нести *не* должно, но они всё равно дело деплоя: conffile dpkg, чья
ручная правка лишь дублирует drop-in из репо (`SystemMaxUse` в `journald.conf`, `DNS=` /
`FallbackDNS=` в `resolved.conf`), и управляемый ucf `sshd_config`, где образ провайдера оставляет
активными `PasswordAuthentication yes` / `PermitRootLogin yes` после `Include`. Эти строки —
LATENT на auth-ключе sshd, то есть FAIL в Phase 1, на каждом новом хосте из этого образа. Никаких
ручных скриптов: запись `class pristine` заставляет деплой самому вернуть **дефолт пакета** — и так
же откатывать любые будущие ручные правки.

```text
"dpkg:<package>|<dst>|0644|root:root|pristine|<role>"
"ucf:<template>|<dst>|0644|root:root|pristine|<role>"
```

**Откуда берётся копия** (Phase 1, только чтение хоста; все временные файлы — в приватном рабочем
каталоге деплоя, который удаляется при выходе):

- `dpkg:<package>` — версия = `dpkg-query ${Version}` **установленного** пакета (вторая буква
  `${db:Status-Abbrev}` — `i`: удерживаемый пакет, `hi`, тоже подходит). `.deb` берётся
  сначала из `/var/cache/apt/archives` (`:` эпохи в имени файла — `%3a`), иначе
  `apt-get download <package>=<version>` скачивает его в рабочий каталог (под `timeout`).
  `dpkg-deb --fsys-tarfile | tar -xO ./<dst>` извлекает один файл, и его md5 обязан совпасть с тем,
  что `dpkg-query ${Conffiles}` записывает для `<dst>`. Копия хоста, у которой уже этот md5, *и
  есть* дефолт пакета: ничего не скачивается, запись — `synced`.
- `ucf:<template>` — копия = шаблон, который поставляет пакет. Его md5 обязан совпасть с тем, что
  dpkg записал для него (`md5sums` пакета-владельца, `dpkg-query --control-path <pkg> md5sums`), а
  `<dst>` должен быть зарегистрирован в `/var/lib/ucf/hashfile`. То, что ucf зарегистрировал для
  `<dst>`, **не** возвращается: это шаблон в том виде, как его отрендерил maintainer-скрипт при
  установке, с ответами debconf. На обоих хостах этот md5 — `eb86be66…`: шаблон с
  `PermitRootLogin yes`, который postinst openssh-server пишет, когда
  `openssh-server/permit-root-login` = false (так его предзадаёт образ провайдера), а шаблон —
  `0a12ef5c…` (= md5sums dpkg). Отчёт печатает оба.
- Копии нет (не в кэше и не скачивается, нет нужной утилиты, файл не conffile этого пакета, ucf
  его не регистрирует) или md5 не совпал → `WARN … cannot restore: <почему>`; файл остаётся ровно
  таким, как есть, деплой идёт дальше.

**Доказательство эффекта** — Phase 1, до любых изменений; это единственный способ узнать, значила
ли ручная правка что-нибудь:

- `scripts/vpn-bot-host-check --pre-install --pristine <dst>=<copy>` оценивает хост с копией на
  месте файла (тот же overlay, что для файлов репо) и сравнивает эффективное значение **каждого**
  ключа семейства файла — не только ключей из репо; для sshd ещё и каждую директиву внутри блоков
  `Match`, включая мульти-ключи (`DenyUsers`, `AllowUsers`, …), каждую со всеми объемлющими
  условиями (`Match` в файле, подключённом под `Match`, действует только там, где выполнены оба), —
  с ней и без неё. Дефолт пакета для `/etc/systemd/<x>.conf` оценивается как *тот самый* главный
  файл, вместо vendor-файла в `/usr/lib` (systemd читает файл из `/etc` вместо него). Для systemd
  `*.conf` отвергается и значение копии хоста, которое другой файл перекрывает *другим*
  значением: оно мертво, только если настройка действительно last-wins, а накопительная
  (как `DNSStubListenerExtra=`) его потеряет. Проходит лишь точный дубль (ручная правка повторяет
  drop-in) или смоделированная списочная настройка. Обе стороны — хост таким, каким его иначе оставит Phase 2 (файлы репо
  на месте, выведенные удалены), поэтому оценивается только сам возврат. Любое отличие —
  `MISMATCH` семейства `pristine` и FAIL в Phase 1:
  `<file> sets <key>=<value> that no repo file carries — move it into a repo drop-in first`.
  Без отличий — строка `OK pristine`, это и есть доказательство, оно печатается в логе и в отчёте;
  без этой строки Phase 1 тоже падает.
- Для `sshd_config` ещё: `sshd -T` на приватной копии дерева sshd с `sshd_config` хоста и на копии
  с дефолтом пакета — каталог drop-in'ов с обеих сторон один и тот же, такой, каким его оставит
  Phase 2, а `Include` этого каталога внутри самих drop-in'ов тоже указывают на приватную копию, —
  должен выдать побайтно одно и то же. Это ловит то, что host check не оценивает
  (`Port`, `ListenAddress` и другие мульти-ключи). Другой вывод, `sshd -T`, который не отработал,
  или нет `sshd` → FAIL. С обеих сторон лежит **отрендеренный** Port-drop-in
  (`00-vpn-bot-port.conf` для портов, которые оставит Phase 2 — [SSH-порт](#ssh-порт)), никогда не
  шаблон. `Port` накапливается по файлам: строка `Port` в `sshd_config` хоста слушает
  *вдобавок* к `SSH_PORT`, в дефолте пакета её нет — выводы различаются, и FAIL так и говорит:
  поставьте этот порт в `SSH_PORT` или уберите строку (SSH-порт теперь — это `SSH_PORT`).
- Это доказательство и есть защита от потери доступа для `sshd_config`, поэтому возврату его
  дефолта пакета **не** нужен `ALLOW_SSH_CHANGE` — осознанное, задокументированное исключение.
  Ручка по-прежнему защищает каждый repo-managed ssh-файл.

**Phase 2**: оригинал сохраняется вместе с остальными путями хоста; копия ставится атомарно
(временный файл в том же каталоге, mode и owner из записи, затем `mv`); затем post-action
семейства — `journald.conf`: `systemctl restart systemd-journald`; `resolved.conf`: как у класса
`resolved` (`try-reload-or-restart` + `getent ahosts` с повторами); `sshd_config`: как у класса
`ssh` (`sshd -t`, reload, ssh active и слушает). Потом обычный host check Phase 2. Любой сбой —
`rollback_now`: оригинал возвращается, и post-action выполняется на нём ещё раз.

**Правило conffile'ов.** Деплой никогда не пишет conffile dpkg (`CONFFILE_REPORT_PATHS` только в
отчёте) — с ровно одним исключением: запись `class pristine`, и только с копией, проверенной md5
самого пакетного менеджера. Содержимое, написанное в репо, деплой в conffile не кладёт никогда.
Локально изменённый conffile с такой записью в `--pre-install` — `PENDING` («Phase 2 restores the
package default»), а не WARN, и после установки его WARN пропадает сам; без записи он остаётся WARN.

**Выведенные файлы защищены.** Перед удалением Phase 1 ищет путь или его basename в crontab root и
во всех остальных файлах под `/var/spool/cron`, в `/etc/crontab`, `/etc/cron.d`, в каталогах юнитов
`/etc/systemd/system` и `/usr/lib/systemd/system` (включая drop-in'ы) и в `.env`. Совпадение
**проваливает** деплой с указанием файла и строки: сначала уберите ссылку или отмените вывод.

## Эффективное состояние

Запись в реестре гарантирует, что файл из репо лежит на хосте байт в байт, с нужными mode и owner.
Она **не** гарантирует, что этот файл действует. На relay `00-vpnrelay-keyonly.conf`
(`PasswordAuthentication no`) выигрывал у `50-cloud-init.conf` (`yes`) и у активных строк
`PasswordAuthentication yes` / `PermitRootLogin yes` в главном `sshd_config` только за счёт порядка
разбора — переименуйте файл, и хост молча начнёт принимать пароли, а каждый деплой останется
зелёным. На main было то же самое с `00-root-key-only.conf`.

`scripts/vpn-bot-host-check` закрывает этот класс. Скрипт строго read-only — единственный файл
хоста, который он пишет, это его собственный state-файл; генератор, который он запускает, пишет во
временный каталог проверки, удаляемый при выходе ([Вывод генераторов](#вывод-генераторов)) — и это
единственная реализация: её вызывают
Phase 1 деплоя, Phase 2 деплоя и `vpn-bot-host-check.timer`. Вручную:
`sudo /usr/local/sbin/vpn-bot-host-check --no-state`.

### Вердикты

| Вердикт | Значение | Phase 1 деплоя | Phase 2 деплоя | Бот (main) |
|---|---|---|---|---|
| **BEATEN** | значение из repo-managed файла не действует: выигрывает другой файл | FAIL | rollback | алерт |
| **MISMATCH** | живое значение (`sshd -T`, `sysctl -n`, `systemctl show`) ≠ тому, что дают файлы, для ключа, который задаёт repo-файл; юнит из репо замаскирован, ждёт `daemon-reload` или (таймер, который ставит деплой) не enabled+active; строка `invariants.list` не выполняется; (`--pristine`) возврат дефолта пакета изменил бы ключ | FAIL | rollback | алерт |
| **LATENT** | сейчас верно, но проигравший файл — не repo и не vendor — держит другое значение: уберут победителя, и значение молча перевернётся. В строке — победитель, проигравшие и `winner gone -> <значение> from <файл>` | FAIL для auth-ключа sshd¹, иначе WARN | в отчёте | алерт, если новый |
| **ACCEPTED** | LATENT из `deploy/host/accepted-overrides.list` | в отчёте | в отчёте | — |
| **WARN** | состояние хоста вне репо, на которое стоит посмотреть (ниже) | WARN | в отчёте | — |
| **PENDING** | только Phase 1: деплой сейчас это меняет; проверит Phase 2 (в том числе изменённый conffile, который Phase 2 вернёт к дефолту пакета) | в отчёте | — | — |

¹ `PasswordAuthentication`, `KbdInteractiveAuthentication`, `PermitRootLogin`,
`PermitEmptyPasswords`, `PubkeyAuthentication`, `AuthenticationMethods`.

`PHASE1_ONLY=1` (`CHECK=1`) показывает FAIL, не останавливаясь, как и остальные drift-гейты.
**Ручки**, чтобы пройти FAIL в настоящем деплое, нет — чините хост или репо.

**Phase 1 оценивает хост таким, каким его оставит Phase 2** (`--pre-install`): каждый repo-файл
роли — на месте копии хоста (и ещё не установленные тоже), каждый выведенный из оборота файл —
удалён, побайтно равное старое имя — удалено. Поэтому repo-файл, который перебил бы другой файл,
ловится до любой установки; живое значение, которое деплой сейчас поменяет, — PENDING. **Phase 2**
запускает проверку ещё раз сразу после установки файлов хоста и юнита роли (на main — до старта
бота), пишет state-файл и откатывается на любом BEATEN/MISMATCH — тем же путём, что ssh-гейт.
Строки есть и в отчёте `PHASE1_ONLY`, и в `DEPLOY OK`.

### Правило vendor

VENDOR = файл в `/usr/lib`, `/lib` или `/usr/local/lib` **плюс** файл в `/etc`, который
принадлежит пакету (`dpkg -S` одним вызовом) и не изменён локально (md5 совпадает со строкой из
`dpkg-query -W -f='${Conffiles}'`). Repo-значение поверх vendor — норма, не LATENT: на обоих
хостах `99-bbr.conf` перекрывает неизменённый `/etc/sysctl.d/10-bufferbloat.conf` из procps, а
провайдерский `99-cloudimg-ipv6.conf` — неизменённый `10-ipv6-privacy.conf`. Проигравший
**изменённый** conffile — LATENT. Symlink оценивается по своей цели.

`/etc/ssh/sshd_config` управляется ucf, а не является conffile dpkg: проверка conffile'ов его не
видит, поэтому он никогда не vendor — его строки оцениваются как строки любого другого файла.

### Вывод генераторов

Drop-in юнита в `/run/systemd/generator/`, `generator.early/` или `generator.late/` никто туда не
клал: при каждом `daemon-reload` systemd очищает эти каталоги и заново запускает все генераторы
(systemd.generator(7)). Такой drop-in — прочтение конфигурации хоста генератором, производное
состояние, а не состояние хоста вне репо, **если** генератор, который запускает systemd, — файл
пакета: drop-in называет его (`# Automatically generated by <имя>`), `<имя>` ищется в каталогах
генераторов в порядке systemd (`/run/systemd/system-generators`, `/etc/systemd/system-generators`,
`/usr/local/lib/systemd/system-generators`, `/usr/lib/systemd/system-generators`; файл в более
раннем каталоге перекрывает одноимённый в позднем), и этот файл принадлежит пакету (`dpkg -S`) и
не изменён локально (его md5 из `dpkg-query --control-show <пакет> md5sums`). Тогда проверка
запускает этот генератор так, как его запускает systemd, — `<генератор> <dir> <dir-early>
<dir-late>`, три свежих каталога во временном `mktemp -d` в `$TMPDIR` (у юнита таймера
`PrivateTmp=`), удаляемом при выходе, — и сравнивает то, что он пишет, с файлом в `/run`:

| Что найдено | Вердикт |
|---|---|
| байт в байт то же | `INFO` «generated by <генератор> (<пакет>, unmodified) from <источник>» — для `sshd-socket-generator` источник — строки `Port`/`ListenAddress` конфигурации sshd, каждая как `файл:строка` |
| сейчас он пишет другое или ничего | `MISMATCH` «stale generator output — daemon-reload needed»: конфигурация изменилась после последнего `daemon-reload`, юнит работает со старым файлом |
| генератора нет ни в одном каталоге генераторов, он замаскирован (`-> /dev/null`), завершился не с 0 или по таймауту (30 с) | `WARN` — не оценивается, никогда не LATENT |
| нет строки `# Automatically generated by`; генератор не принадлежит пакету (в том числе файл в `/etc/systemd/system-generators`, перекрывающий пакетный); изменён локально; md5 не записан | `LATENT`, как любой чужой drop-in |

Подход «уберут победителя — перевернётся» к выводу генератора не применяется: удаление файла
ничего надолго не меняет — следующий `daemon-reload` пишет его снова. Важно то, что даёт
генератор, и для `ssh.socket` это проверяется отдельно ([SSH-порт](#ssh-порт)): порты из
`ListenStream=` генератора должны совпадать с SSH-портами.

Замерено на noble (openssh-server 1:9.6p1-3ubuntu13.20, systemd 255): `sshd-socket-generator`
требует хотя бы один аргумент (без аргументов: `Expected at least one argument.`, exit 1) и пишет
только в первый — `<dir>/ssh.socket.d/addresses.conf`: заголовок, пустая строка, `[Socket]`, сброс
`ListenStream=`, затем `0.0.0.0:<порт>` и `[::]:<порт>` для каждого `Port` (`ListenAddress` даёт
этот адрес). С одним `Port 22` он не пишет ничего (`No custom listen addresses configured`,
exit 0); сломанная строка `Port` — exit 255.

### Старшинство по семействам

- **sshd** — `/etc/ssh/sshd_config` обходится так, как его читает sshd: `Include` раскрывается на
  месте (glob, сортировка C-locale, относительный путь — от `/etc/ssh`); выигрывает **первое**
  значение. Главный файл участвует наравне с drop-in'ами: его строки после `Include` — тоже
  проигравшие, строки до него перебивают любой drop-in. Ключи внутри `Match` (до следующего
  `Match` или конца того файла) исключаются из анализа и печатаются как INFO. Мульти-ключи не
  оцениваются: `Port`, `ListenAddress`, `HostKey`, `HostCertificate`, `AcceptEnv`, `SetEnv`,
  `Subsystem`, `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`. Алиасы:
  `ChallengeResponseAuthentication` = `KbdInteractiveAuthentication`,
  `prohibit-password` = `without-password`. Живое значение: `sshd -T`.
- **sysctl** — при загрузке порядок `systemd-analyze cat-config sysctl.d`; выигрывает
  **последнее** значение. Порядок `sysctl --system` замеряется, а не предполагается:
  `sysctl --system --dry-run` (procps ≥ 4.0.3; на хостах 4.0.4; ничего не пишет), его строки
  `* Applying <path>`. Замер на хостах: `/etc/sysctl.conf` применяется ещё раз в самом конце, хотя
  уже прилинкован как `99-sysctl.conf`. Ключ, у которого победитель при загрузке ≠ победителю
  `sysctl --system`, — LATENT. Без `--dry-run` порядок предполагается (порядок загрузки, затем
  `/etc/sysctl.conf`), и отчёт это помечает. Ключ с `/` без `.` приводится к точкам; ведущий `-`
  срезается; пробелы в значении схлопываются; ключ с `*` с `/proc` не сверяется. Живое значение:
  `sysctl -n`.
- **systemd `*.conf` + `*.conf.d`** — `journald`, `networkd`, `resolved`, `logind`, `timesyncd`,
  `system`: порядок `systemd-analyze cat-config systemd/<x>.conf` (главный файл, затем drop-in'ы
  по имени), ключ = `Section.Key`, выигрывает **последнее** значение. Кроме списочных настроек —
  `Resolve.DNS`, `Resolve.FallbackDNS`, `Resolve.Domains`, `Resolve.DNSStubListenerExtra`, `Time.NTP`,
  `Time.FallbackNTP`: у них
  значения всех файлов складываются, а пустое присваивание сбрасывает список, поэтому сверяется
  накопленный список (сервер, оставшийся в `resolved.conf` рядом с серверами drop-in, — BEATEN).
  Общего способа прочитать для них живое значение нет, поэтому они оцениваются только по
  старшинству.
- **Юниты, которые ставит репо**, по роли, из тех же источников, что `UNIT_SET` и
  `MANAGED_HOST_FILES`: на main — `deploy/vpn-bot.service`, каждый установленный на хосте
  `deploy/*.service|*.timer` и юниты и drop-in'ы реестра; на relay — `deploy/relay/*.service` и
  записи реестра. `*.example.*` — никогда. `FragmentPath` не наш или юнит замаскирован → BEATEN;
  `NeedDaemonReload=yes` → MISMATCH; нашего drop-in нет в `DropInPaths` → BEATEN; там же drop-in,
  который не наш и не vendor (`/etc`, `/run`), → LATENT; drop-in генератора в
  `/run/systemd/generator*/` → [Вывод генераторов](#вывод-генераторов); таймер, который ставит деплой,
  не `enabled` + `active` → MISMATCH. (`deploy/*.timer`, которые оператор ставит руками, относятся
  к модульным подсистемам и работать не обязаны.) Вывод `systemctl show` читается построчно как
  `Key=Value` и никогда не исполняется.

### Что ожидается

Только явные списки — никаких «логичных» умолчаний:

- **ключи sysctl, sshd и systemd `*.conf` выводятся из repo-файлов роли автоматически**: добавили
  файл в `MANAGED_HOST_FILES` — его ключи проверяются (`tests/test_host_check.py` проверяет это на
  настоящем реестре);
- сверх этого — **`deploy/host/invariants.list`**, одна строка на инвариант:

  ```text
  <main|relay|all>|<probe>|<key>|<expected>|<причина, не короче 20 символов>
  ```

  Типы probe — закрытый список, произвольных команд нет: `sshd` (против `sshd -T`), `sysctl`
  (против `sysctl -n`), `systemd-conf:<x>` (против файлов), `unit-prop:<unit>:<Prop>`
  (`systemctl show`), `path-present`, `path-absent`, `path-regular` (существует и **не** symlink),
  `tcp-listen:<port>`. Ожидаемое `~X` значит «содержит X целым токеном» (`~22` совпадает с
  `[::]:22 (Stream)`, но не с `:2222`). Засеяно: на main `even-day-reboot.timer` enabled и
  active, `/etc/resolv.conf` — обычный файл; на relay `ufw.service` masked (его входной фильтр —
  `table inet vpnrelay_input`, см. [docs/relay.ru.md](relay.ru.md#входной-фильтр)); на обеих
  ролях есть `/etc/cloud/cloud-init.disabled`. SSH-порта в списке **нет** (фиксированный порт
  противоречил бы `SSH_PORT` во время и после переезда): его оценивает семейство `ssh-port` —
  [SSH-порт](#ssh-порт).

### Как принять LATENT

LATENT, который должен остаться, записывается в **`deploy/host/accepted-overrides.list`** — это
единственный санкционированный способ; ручки `ALLOW_*` нет (`redeploy.sh` её бы и не передал):

```text
<path>|<key>|<причина, не короче 20 символов>
```

`path` — файл, который называет строка (проигравший, чужой drop-in или файл, который выигрывает
при `sysctl --system`), `key` — ключ строки (ключ sysctl, keyword sshd в нижнем регистре,
`Section.Key`, имя юнита для drop-in или `generator` для портов генератора ssh.socket). Запись
превращает в ACCEPTED ровно эту строку и ничего
больше; запись, которая ни с чем не совпала, печатается как INFO. Формат проверяет
`tests/test_host_check.py`. По правилу vendor стартовый список **пустой**.

### WARN-проверки

Состояние хоста вне репо — в отчёте, никогда не фатально, ключи и пароли не печатаются никогда:
cloud-init жив (нет `/etc/cloud/cloud-init.disabled`); строки `logrotate -d /etc/logrotate.conf`,
которые **начинаются** с `error:`, и `duplicate log entry` (никогда не подстрока «error»: она есть
в путях вроде `error.log`); `NOPASSWD: ALL` в sudoers; не-root аккаунт с login shell и рабочим
паролем (`passwd -S` = P, читается из `/etc/shadow`) или непустым `authorized_keys`; локально
изменённый conffile dpkg в `/etc/systemd`, `/etc/sysctl*`, `/etc/logrotate*`, `/etc/cloud` или
`/etc/sudoers*` — с ключами, которые он задаёт (настройка, живущая только в изменённом conffile,
— состояние хоста вне репо). Conffile с записью `class pristine` в `--pre-install` вместо этого
`PENDING`, если у деплоя есть его дефолт пакета, а его WARN пропадает, когда Phase 2 его вернула —
[Дефолты пакетов](#дефолты-пакетов-class-pristine).

Проверка никогда не удаляет и не правит файлы вне реестра. Найденное закрывается реестром: файл,
которым должен владеть репо, получает запись; файл, который не должен вернуться, — `class absent`
(`50-cloud-init.conf` и `90-cloud-init-users` от cloud-init на обеих ролях); маркер — `class plain`
(`/etc/cloud/cloud-init.disabled`).

### Между деплоями

`vpn-bot-host-check.timer` (юнит реестра на обеих ролях) запускает проверку через 5 минут после
каждой загрузки и затем раз в сутки (`RandomizedDelaySec=30min`, `Persistent=true`). Загрузочный
прогон — главный: cloud-init, провайдер и apt меняют хост именно на ребуте, а
`even-day-reboot.timer` перезагружает его раз в 5 дней. Каждый прогон — и Phase 2 каждого деплоя —
атомарно переписывает `/var/lib/vpn-bot-host-check/last.json` (`root`, `0644`): время, роль,
счётчики, строки. На BEATEN/MISMATCH сервис выходит с кодом 1: юнит виден как failed, а строки
есть в `journalctl -u vpn-bot-host-check`.

На **main** бот читает этот файл каждые `HOST_CHECK_INTERVAL` секунд и шлёт алерт суперадминам
(`ADMIN_IDS`, та же рассылка, что у алертов relay), когда строка становится BEATEN или MISMATCH,
когда появляется новый LATENT, и один раз, когда последний BEATEN/MISMATCH ушёл. Без повторов по
той же строке: отправленное хранится в базе, рестарт его не повторяет. INFO, OK, WARN, PENDING и
ACCEPTED алерта не дают никогда; уже отправленный LATENT, который стал INFO (`addresses.conf`
ssh.socket, когда проверка узнала в нём [вывод генератора](#вывод-генераторов)), просто убирается
из отправленного, без сообщения.

На **relay** бота нет, и канала от бота к relay тоже нет — relay — это строки в базе, которые
проверяются снаружи TLS-handshake'ом через их DNAT, — поэтому новый канал ради этого не строится.
Вердикт relay — в его журнале (`journalctl -u vpn-bot-host-check`, failed-юнит) и в Phase 1
каждого деплоя relay (`CHECK=1` показывает его без деплоя).

### DNS на основном сервере

- `/etc/resolv.conf` — **обычный файл**, а не stub-symlink systemd-resolved (переписан
  2026-08-25): `nameserver 1.1.1.1`, `nameserver 8.8.8.8`. Это `deploy/host/dns/resolv.conf`
  (класс `plain`, побайтно равен копии хоста — sha256 закреплён в
  `tests/test_deploy_host_state.py`), а инвариант `path-regular` падает, если вернётся symlink.
- systemd-resolved по-прежнему работает; его upstream'ы `DNS=1.1.1.1 8.8.8.8` и
  `FallbackDNS=1.0.0.1 8.8.4.4` жили только в ручной правке conffile dpkg
  `/etc/systemd/resolved.conf`. Теперь это `deploy/host/resolved/10-vpn-bot.conf` (класс
  `resolved`): после изменения — `systemctl try-reload-or-restart systemd-resolved`, затем
  `getent ahosts github.com` должен ответить в течение 10 с, иначе деплой откатывается (rollback
  возвращает старый файл и так же перезагружает resolved).
- Сам `/etc/systemd/resolved.conf` возвращается к дефолту пакета через свою запись `class
  pristine` — без ручного скрипта: Phase 1 доказывает, что эффективные `DNS=` / `FallbackDNS=`
  (из drop-in) не меняются, Phase 2 возвращает стоковый файл и перезагружает resolved как у класса
  `resolved`. Ничего эффективного не меняется: drop-in несёт значения conffile, а `resolv.conf`
  уже synced.

## Файлы, которые ничем не учтены

Phase 1 перечисляет каждый файл в этих каталогах, который не ставится деплоем для этой роли, не
принадлежит пакету (`dpkg -S`, одним вызовом) и не совпадает с `deploy/host/known-unmanaged.list`:

`/etc/systemd/system` (файлы и drop-in'ы `*.d/`; ссылки `*.wants` и симлинки пропускаются),
`/etc/sysctl.d`, `/usr/local/sbin`, `/usr/local/bin`, `/etc/logrotate.d`, `/etc/cron.d`,
`/var/spool/cron/crontabs`, `/etc/ssh/sshd_config.d`, `/etc/nginx/conf.d`, `/etc/systemd/*.conf.d`.

Каждый — `WARN` с mtime, никогда не фатально. Drop-in, чьего юнита не существует, помечается как
**orphan drop-in for absent unit**. По каждому предупреждению решите: положить в репо (запись
реестра), вывести из оборота (`class absent`) или записать причину в `known-unmanaged.list`:

```text
<абсолютный path-glob>  # <installer|provider|backup-only|deployment-local> — <причина, ≥ 20 символов>
```

## Как добавить файл хоста

1. Скопируйте файл хоста в `deploy/host/<подсистема>/` **побайтно**
   (`scp host:/etc/... deploy/host/...`, затем сравните `sha256sum` с обеих сторон). Отличающаяся
   копия будет переустановлена следующим деплоем — а для `ssh` отвергнута.
2. Добавьте запись в `MANAGED_HOST_FILES` с теми правами и владельцем, что у файла на хосте сейчас
   (`stat -c '%a %U:%G'`).
3. Добавьте путь в таблицу выше. `tests/test_deploy_host_state.py` проверяет, что каждый источник
   существует, каждая запись корректна и каждый путь назначения описан здесь; для файлов, которые
   должны показать `synced` на первом деплое, закрепите там же sha256 хоста.
4. `sudo CHECK=1 bash scripts/redeploy.sh` — запись должна показать ожидаемое состояние до
   настоящего деплоя.

Чтобы вывести файл из оборота, добавьте `"-|<path>|-|-|absent|<role>"`. Его копия остаётся в
архивах деплоя (`/var/backups/vpn-bot`, последние `BACKUP_KEEP`).

Чтобы вернуть собственный файл пакета к его дефолту, добавьте
`"dpkg:<package>|<path>|0644|root:root|pristine|<role>"` (conffile dpkg) или
`"ucf:<template>|<path>|0644|root:root|pristine|<role>"` (файл под ucf). Путь должен быть в
семействе, которое покрывает доказательство эффекта: `/etc/ssh/sshd_config`,
`/etc/systemd/<x>.conf`, sysctl. `tests/test_deploy_pristine.py` закрепляет форму и то, что путь —
conffile этого пакета.

## ALLOW_SSH_CHANGE и риск потери доступа

Неверный drop-in `sshd_config.d` или `ListenStream` отрезает все новые ssh-подключения. Поэтому для
класса `ssh` деплой никогда сам не заменяет копию хоста, которая **отличается** от репо: Phase 1
печатает diff и останавливается, ничего не изменив. (*Отсутствующий* ssh-файл ставится — терять
нечего; *synced* никогда не трогается.)

Решите, какая сторона права:

- **прав хост** — скопируйте его файл в `deploy/host/ssh/` побайтно и задеплойте снова;
- **прав репо** — откройте **вторую ssh-сессию** к хосту и держите её открытой, затем:

  ```bash
  sudo ALLOW_SSH_CHANGE=1 bash scripts/redeploy.sh
  ```

С этим флагом Phase 2 ставит файл и запускает `sshd -t`. При изменении `ListenStream` — делает
`daemon-reload` + `systemctl restart ssh.socket`, а если sshd запущен, ещё и
`systemctl restart ssh`: работающий sshd держит сокеты, полученные при старте, и один перезапуск
сокета оставил бы его на старом порту (открытые сессии рестарт переживают). При изменении
sshd_config — `systemctl reload ssh`. Затем слушающий юнит (`ssh.socket`, если он активен, иначе
`ssh.service`) должен быть active, а каждый ожидаемый порт — и слушаться, и **отвечать
SSH-баннером**: при socket activation один listener ничего не доказывает. Если нет — деплой
откатывается: старый файл восстанавливается, на нём запускается `sshd -t`, и сокет / ssh
перезапускаются или получают reload так же — **кроме случая, когда `sshd -t` падает на
восстановленном конфиге**: тогда ssh не трогается, а отчёт об откате говорит об этом заглавными
буквами.

Проверка порта ловит мёртвый порт, но не ключ, с которым больше нельзя войти. Тогда спасает вторая
сессия: проверьте из неё новый вход, прежде чем что-либо закрывать.

Сам `/etc/ssh/sshd_config` — не класс `ssh`: он только возвращается к своему дефолту пакета (класс
`pristine`) после того, как Phase 1 доказала, что `sshd -T` побайтно не меняется, — там защищает
это доказательство, и ручка не нужна и не читается.

**Переезду SSH-порта** ручка тоже не нужна: два файла `render=ssh-port` меняются без неё ровно
тогда, когда копия на хосте — рендер портов, на которых ssh слушает сейчас, то есть шаг
[переезда](#ssh-порт), который защищают двойное прослушивание и доказательство. Ручная правка этих
файлов — обычный дрейф, ей ручка нужна.

## SSH-порт

**Одна настройка, обе роли:** `SSH_PORT` в `/opt/vpn-service/.env` (main и relay; нет или пусто =
**54321**). Проверяется до любых изменений: целое 1..65535 без ведущего нуля; не TCP-порт сервиса
этой роли — main: `XRAY_PUBLIC_PORT` (443), `XRAY_XHTTP_PORT`, `SUBSCRIPTION_BIND_PORT`,
`SUBSCRIPTION_PUBLIC_PORT`, `SOCKS5_PORT`, `MTPROTO_PORT`, `MTPROTO_INTERNAL_STATS_PORT`,
`HEALTH_PORT`; relay: `RELAY_FORWARD_TCP_PORTS` (443), `RELAY_INPUT_EXTRA_TCP`,
`RELAY_INPUT_CLOSED_TCP` — и не порт, который слушает другой процесс (`ss`). Отказ останавливает
Phase 1: `ssh port: REFUSED — …; nothing was changed`.

С дефолтом main не двигается (он уже слушает 54321 через `ssh.socket`, его override рендерится байт
в байт), а существующий relay сам переезжает с 22 из пакета на 54321 при следующем деплое.

### Два файла, рендер

| Файл | Строка шаблона | Зачем |
|---|---|---|
| `/etc/systemd/system/ssh.socket.d/override.conf` | `ListenStream=0.0.0.0:@SSH_PORT@`, `ListenStream=[::]:@SSH_PORT@` после сброса | сокет: на чём слушает ssh |
| `/etc/ssh/sshd_config.d/00-vpn-bot-port.conf` | `Port @SSH_PORT@`, плюс `LogLevel VERBOSE` | запасной путь: `ssh.service`, запущенный **без** `ssh.socket`, сам слушает `Port` — там же, где сокет, а не на 22 за файрволом |

`scripts/vpn-bot-ssh-port render` пишет каждую строку с `@SSH_PORT@` по разу на порт, по
возрастанию. `sshd-socket-generator` Ubuntu 24.04 превращает те же строки `Port` в
`/run/systemd/generator/ssh.socket.d/addresses.conf` при каждом `daemon-reload` (замерено на
openssh-server 1:9.6p1-3ubuntu13: он идёт по `Include` в `sshd_config.d`); `override.conf`
сортируется после `addresses.conf` и сбрасывает `ListenStream=`, так что решает файл репо.
Значит, `addresses.conf` выведен из собственного Port drop-in репо, а не чужой: host check,
запустив генератор, показывает его как INFO ([Вывод генераторов](#вывод-генераторов)) и сверяет
порты, которые тот даёт, с SSH-портами — `SSH_PORT` плюс старый порт (порты), пока миграция в
фазе 1. Если они расходятся (например, лишняя строка `Port` где-то ещё в конфигурации sshd) —
LATENT `ssh-port generator`: только `override.conf` держит ssh.socket на SSH-портах; уберите его, и
сокет встанет на порты генератора.

### Переезд: две фазы, обе автоматические

Когда порт, на котором слушает ssh (`systemctl show -p Listen ssh.socket`), — не `SSH_PORT`:

1. **Фаза 1 — деплой.** Оба файла рендерятся для старого порта (портов) **и** `SSH_PORT`: ssh
   слушает оба. Файрвол следует за ними: на relay `table inet vpnrelay_input` сам берёт порты ssh
   из `ss` (рестарт `vpn-relay` в деплое применяет его заново, изменённый набор подтверждает проба
   с main — [docs/relay.ru.md](relay.ru.md#входной-фильтр)); на main деплой открывает `SSH_PORT`
   в UFW **до** изменения сокета: `vpn-bot-ufw-apply apply` (установлен на main — файрвол его,
   [Фаервол (UFW)](#фаервол-ufw)) кладёт в набор оба порта; правило с комментарием
   `vpn-bot:ssh-migration` — только там, где хелпера нет. Старый порт не
   трогается. Состояние пишется в `/var/lib/vpn-bot/ssh-migration.json` (`from`, `to`,
   `phase: 1`, `since`).
2. **Фаза 2 — только после доказательства**, что `SSH_PORT` работает **снаружи**: старый порт
   убирается из сокета и Port-drop-in (`Port SSH_PORT` один), файрвол его закрывает — main:
   удаляются правила, разрешающие ровно старый порт (`ufw show added`: `<port>[/tcp]`, `… port
   <port> [proto tcp]`), а правило миграции на месте получает комментарий `vpn-bot:ssh` (ufw
   обновляет комментарий без окна); правило без протокола открывает tcp **и** udp (ufw(8)), поэтому
   оно разделяется — сначала добавляется то же правило для udp, потом удаляется общее, и
   udp-сервис на том же номере (например, Hysteria2) свой порт сохраняет; правило, которое так не убрать (app-профиль, список портов),
   — заметка, а не ошибка: оставить порт открытым — безопасная сторона. Relay: входной фильтр
   применяется заново (`vpn-relay-apply apply`, одна транзакция nft) и отбрасывает старый порт.
   `phase: 2`.

**Доказательство** — любое одно, позже начала фазы 1 (`since`):

| Доказательство | Роль | Откуда |
|---|---|---|
| `relay-probe` | relay | проба с main (`POST /relay/ssh-probe`) подключилась к `SSH_PORT` через входной фильтр: в `/etc/vpn-relay/input.confirmed` `confirmed_by=main-probe`, в наборе `tcp=` есть `SSH_PORT`, `confirmed_at` ≥ `since` |
| `journal` | обе | sshd записал подключение с **нелокального** адреса на `SSH_PORT` (`journalctl -u ssh.service --since @<since>`). openssh 9.6 пишет `Connection from <raddr> port <rport> on <laddr> port <lport> rdomain ""` **только при `LogLevel VERBOSE`** — проверено бинарником из noble; при `INFO` такой строки нет, отсюда `LogLevel VERBOSE` в Port-drop-in. Loopback, собственные адреса хоста (`ip -o addr`) и `raddr == laddr` ничего не доказывают |
| `bot` | main | суперадмин нажал **«Подтвердить»** под сообщением бота «SSH теперь и на порту N — подключись на него и нажми Подтвердить»; бот запускает `vpn-bot-ssh-port confirm --port N --since S --admin ID` (sudo, точный путь в `deploy/sudoers.d/vpn-bot.example`; при `ProtectSystem=strict` бота без root хелпер сначала входит в mount namespace PID 1, как и остальные хелперы) |

**Без доказательства фазы 2 не будет никогда.** Его ищут каждый деплой (план Phase 1; деплой,
который его нашёл, сам выполняет фазу 2 с `rollback_now`), загрузка и ежедневный прогон
(`vpn-bot-host-check.timer` → `vpn-bot-host-check.service` `Wants=` `vpn-bot-ssh-port.service` →
`vpn-bot-ssh-port advance`), сразу после каждого DEPLOY OK хоста в фазе 1 (relay, чей фильтр только
что подтвердила проба с main, заканчивает в том же прогоне) и сразу после «Подтвердить». `advance`
берёт lock деплоя (`/run/vpn-bot-deploy.lock`) или оставляет работу идущему деплою; трогает только
файлы, которые ровно такие, какими их оставила фаза 1.

Бот один раз сообщает суперадминам о старте фазы 1 (с кнопкой) и один раз — о завершении
(`schema_meta` помнит это через рестарты). На relay бота нет: его состояние — в отчёте деплоя и в
журнале. Деплой печатает состояние в Phase 1, в отчёте и в DEPLOY OK, например

```text
ssh port: migrating 22 -> 54321 (waiting for proof: main's probe of tcp 54321 (RELAY_CONFIRM_URL), or an ssh connection from outside on 54321 in the sshd log)
```

`SSH_PORT` снова изменили во время ожидания — новая фаза 1 от исходного порта к новому значению
(недоказанный порт убирается, исходный не закрывается); `SSH_PORT` вернули на исходный порт —
недоказанный убирается (`phase: 0`, отменено).

### Пост-проверка каждой фазы

`sshd -t` на установленной конфигурации; `daemon-reload`, `restart ssh.socket` и — если sshd
работает — `restart ssh` (работающий sshd держит сокеты, с которыми стартовал); затем `ssh.socket`
должен быть active, `systemctl show -p Listen ssh.socket` — содержать **ровно** запланированные
порты, каждый запланированный порт — слушать и отвечать SSH-баннером, а убранный шагом порт —
больше не слушать. Любой сбой: в деплое `rollback_now` — прежние файлы, прежний state-файл,
открытое фазой 1 правило UFW снова удалено, сокет и ssh перезапущены на восстановленном наборе; в
`advance` — собственный откат к прежнему набору, причина — в `last_error` state-файла (host check:
WARN).

**Открытые сессии не рвутся.** Проверено на пакете noble: `ssh.socket` — `Accept=no`, его
включение создаёт `ssh.service.requires/ssh.socket`, поэтому рестарт сокета рестартит и
`ssh.service` — а у `ssh.service` `KillMode=process`: SIGTERM получает только слушающий sshd;
каждая сессия — отдельный дочерний sshd (`sshd: user@pts/N`; в openssh 9.6 ещё нет
`sshd-session` — он с 9.8) со своим TCP-соединением, и он остаётся. Сессия на старом порту
переживает и фазу 2: файрвол пропускает установленные соединения (`ctstate RELATED,ESTABLISHED` в
UFW, `ct state established,related accept` в фильтре relay). Сам деплой идёт под `systemd-run`,
вне ssh-сессии.

### Что говорит host check (семейство `ssh-port`)

| План | Установленный хост (таймер, Phase 2) | `--pre-install` (Phase 1) |
|---|---|---|
| на `SSH_PORT` | `OK ssh.socket`; `OK fallback`, если `sshd -T` даёт ровно `SSH_PORT`, иначе `MISMATCH fallback` (Port-drop-in не действует) | то же; fallback `PENDING`, пока деплой ставит drop-in |
| `SSH_PORT` ≠ слушающему, переезд не начат | `MISMATCH migration` — следующий деплой начнёт фазу 1 | `PENDING` (этот деплой её начинает) |
| фаза 1, доказательства нет | `PENDING migration` с тем, чего ждём | то же |
| фаза 1, доказано | `PENDING` (дальше фаза 2); упавшая и откатанная фаза 2 добавляет `WARN` | `PENDING` |
| `SSH_PORT` отклонён | `MISMATCH SSH_PORT` с причиной | то же (Phase 1 всё равно откажет) |
| порты `sshd-socket-generator` (его `addresses.conf` оценивается как [вывод генератора](#вывод-генераторов)) | `OK generator`, если это SSH-порты (`SSH_PORT`; в фазе 1 ещё и старые), иначе `LATENT generator`; `INFO` (не сверяется), пока план — начать миграцию | то же; `PENDING`, пока деплой меняет файл в `/etc/ssh` |

## Фаервол (UFW)

UFW основного сервера **вычисляется**, руками его никто не набирает: `scripts/vpn-bot-ufw-apply`
(ставит deploy.sh, `OUT_OF_REPO_HELPERS`, `required` на main) выводит весь набор правил из
репозитория и `.env` и приводит к нему хост. У relay UFW нет: его входной фильтр —
`vpnrelay_input` ([docs/relay.ru.md](relay.ru.md#входной-фильтр)).

### Набор

| Часть | Откуда | Комментарий правила |
|---|---|---|
| модули | одна таблица в хелпере (`MODULE_TABLE`), и это единственный список правил модуля вообще: `xray` → `XRAY_PUBLIC_PORT/tcp` (`XRAY_SERVER_PORT`, 443); `hysteria2` → `HYSTERIA2_PORT/udp`; `socks5` → `SOCKS5_PORT/tcp`; `subscription` → `SUBSCRIPTION_PUBLIC_PORT/tcp`; `mtproto` → `MTPROTO_PORT/tcp`; `awg` → `ListenPort/udp` AWG (`awg0.conf`, иначе `AWG_ENDPOINT_PORT`) + `route allow in on <AWG_INTERFACE> out on <WAN> from <AWG_NETWORK>` (WAN — устройство IPv4 default route). Модуль в наборе, только пока `.env` его включает (`*_ENABLED`; у Xray и AWG флага нет) **и** у него нет маркера удаления (`/etc/vpn-bot/uninstalled/<модуль>`) | `vpn-bot:<модуль>` |
| ssh | `SSH_PORT` и, пока идёт переезд, его другие порты — набор `listen` из плана [SSH-порта](#ssh-порт) (деплой передаёт его как `--ssh-ports`; иначе хелпер спрашивает `vpn-bot-ssh-port plan`) | `vpn-bot:ssh` |
| extra | `deploy/host/ufw/extra.list`, `role\|rule\|reason` (reason ≥ 20 символов): все прочие правила — так, как их печатает `ufw show added`, — и `closed <port>/<tcp\|udp>` для слушателя, закрытого намеренно. Замер 2026-11-12: пусто — каждое правило main принадлежит модулю или ssh | `vpn-bot:extra` |
| политики | `deploy/host/ufw/policy`, строки `role\|incoming\|outgoing`; засеяны замером (`deny` / `allow`). **routed не управляется никогда** (форвардинг AWG и WARP живёт на route-правилах) — строка `routed` отклоняет план | — |

### `apply`

1. добавляет недостающее — и недостающую v4- или v6-копию (`ufw allow` добавляет обе; IPv6
   учитывается только при `IPV6=yes` **и** ядре с IPv6 — правило самого ufw) — и переподписывает
   (**adopt**) совпадающее правило без нашего комментария: ufw меняет комментарий на месте, порт не
   закрывается ни на миг;
2. ставит политику outgoing; политику incoming и включение неактивного ufw — под dead-man (ниже);
3. удаляет правило с комментарием `vpn-bot:`, которого нет в наборе, и **непомеченное** правило,
   совпадающее с правилом из таблицы, — модуль выключен или удалён, старый порт ssh (22 — порт
   пакета; `from` переезда). Так уходят с хоста route-правило удалённого AWG из замера и старое
   `22/tcp`. Route-правило удаляется через `ufw route delete …` (`ufw delete route …` ufw 0.36
   отвергает);
4. прочие непомеченные правила не трогает — `WARN`, никогда не удаляет;
5. перечитывает результат: всё, что осталось добавить, переподписать или удалить, — провал (exit 4).

**Потери доступа не бывает.** Правило, открывающее порт, на котором sshd **реально** слушает, —
объединение `sshd -T`, `systemctl show -p Listen ssh.socket` и строк `ss` от sshd (или от PID 1 для
порта сокета), — не удаляется никогда (`keep`); если ни один источник не ответил, не удаляется
ничего, ufw не включается и политика incoming не меняется. Перед любым из этих двух шагов каждый
такой порт ещё и открывается (`vpn-bot:ssh`) и перечитывается из ufw (копии v4 и v6): `SSH_PORT`
может быть не там, где ssh (неактивный `ssh.socket`, sshd всё ещё на 22). Проверка идёт в порядке
самого ufw — первое совпадение выигрывает (ufw(8)): более раннее `deny`/`reject` для этого порта с
любого источника или более раннее правило с этим портом, которое не разобрать, считаются закрытием.
Порт, открытость которого не подтвердилась, блокирует оба шага. Все команды идут с `LC_ALL=C` (ufw
переводит `Status: active`); строка статуса, которая не читается ни так ни так, — ошибка, а не
пропущенное включение. Потом такое правило только сохраняется, пока sshd там слушает.
Включённый модуль, правило которого здесь не записать (порт неизвестен, нет default route),
сохраняет всё, что узнаваемо его, — по ключу или по комментарию `vpn-bot:<модуль>`.

### Dead-man

Включение неактивного ufw и смена политики incoming — два шага, которые могут отрезать ssh. Оба идут
под dead-man, как входной фильтр relay (#328): `/var/lib/vpn-bot/ufw-deadman.json` помнит, что было
до, transient-таймер (`vpn-bot-ufw-deadman-watch`) раз в минуту запускает
`vpn-bot-ufw-apply deadman-check`, и смена остаётся только с **доказательством, что ssh отвечает
снаружи**, — теми же, что у переезда SSH-порта: новое подключение с нелокального адреса на порт ssh
в журнале sshd (`vpn-bot-ssh-port proof-journal`, `LogLevel VERBOSE`) или «Подтвердить» под
сообщением бота (`vpn-bot-ufw-apply confirm`, sudo, grant по точному пути). Без доказательства через
10 минут после смены возвращается прежняя политика incoming (и неактивный ufw) — с проверкой
результата; неудавшийся откат остаётся pending и повторяется каждую минуту. Перезагрузка
обрывает таймер: `vpn-bot-ufw-deadman.service`, который подтягивает `vpn-bot-host-check.service`
(через 5 минут после загрузки и ежедневно), взводит его снова или откатывает. Таймер не взвёлся —
политика не меняется (exit 9). **Обычный деплой политику не меняет и dead-man не взводит.**

### Где это работает

| Кто | Когда | Как |
|---|---|---|
| deploy.sh Phase 1 | каждый деплой main | `plan` из checkout: раздел «UFW» и отчёт. Останавливается (`PHASE1_ONLY=1`: в отчёте) на отклонённом плане, на main без ufw и на публичном слушателе, которого набор не разрешает и не объявляет закрытым |
| deploy.sh Phase 2 | после хелперов | `save` состояния UFW (файлы, включён ли, состояние dead-man) — до того, как SSH-порт что-то откроет |
| | после host-файлов и состояния SSH-порта | `apply`, затем `listeners`; провал любого — `rollback_now`, откат делает `restore` сохранённого — у восстановленной смены, которая ещё ждала доказательства, dead-man снова работает (таймер взводится заново, а после срока — сразу откат) |
| | DEPLOY OK | `status`, одна строка |
| бот | включение протокола в «Модули протоколов»; удаление протокола с сервера | `apply` (sudo, grant по точному пути). `vpn-bot-protocol-uninstall` ufw больше не трогает — его маркер выводит модуль из набора: **у правил один владелец** |
| `vpn-bot-ssh-port` | фаза 1 / фаза 2 переезда | `firewall-open` / `firewall-close` вызывают `apply` |

### Слушатели

Каждый TCP `LISTEN` на публичном или wildcard-адресе должен быть разрешён набором или объявлен
закрытым (`main|closed <port>/tcp|<почему>`). UDP проверяется только на UDP-портах таблицы модулей
(и только на публичном или wildcard-адресе); все прочие UDP-сокеты — строки `INFO`, не ошибка:
listen-port awg/wg-интерфейса (`awg show all listen-port` — сокет ядра, без процесса, случайный при
каждом подъёме: `*:32808` у out-warp на замеренном хосте; порты не хардкодятся) и исходящие сокеты
на частном адресе (`172.16.0.2:*` через WARP).

### Что говорит host check (семейство `ufw`)

| Находка | Установленный хост | `--pre-install` (Phase 1) |
|---|---|---|
| ufw не установлен, план отклонён | `MISMATCH` | `MISMATCH` |
| ufw неактивен | `MISMATCH` | `PENDING` (деплой включит его под dead-man) |
| политика не та, что в `deploy/host/ufw/policy` | `MISMATCH` | `PENDING` |
| нет правила из набора или его v4/v6-копии | `MISMATCH` | `PENDING` |
| правило с комментарием `vpn-bot:`, которого нет в наборе | `MISMATCH` | `PENDING` |
| непомеченное правило вне набора | `LATENT` (`apply` удаляет правило таблицы, о прочих — WARN) | `PENDING` для правила таблицы, иначе `LATENT` |
| правило набора без нашего комментария | `INFO` (`apply` переподпишет) | `PENDING` |
| правило оставлено, потому что на его порту слушает sshd | `WARN` | `WARN` |
| dead-man ждёт / откатил | `PENDING` / `WARN` | так же |

Руками: `sudo /usr/local/sbin/vpn-bot-ufw-apply plan` (только чтение, строки `key=value`),
`… apply`, `… status`. Никогда не `ufw allow` — следующий apply его переподпишет или удалит.
