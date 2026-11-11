# Состояние хоста как код

[English version](host-state.md)

Чекаут в `/opt/vpn-service` — ещё не всё развёртывание. На рабочем хосте есть и файлы вне него:
настройки ядра, правило ротации логов, переопределение порта ssh, хук раскладки сертификата,
перезагрузка по расписанию. Пока они живут только на хосте, пересобранному или перенесённому
серверу их неоткуда восстановить, а разъехавшуюся ручную правку никто не замечает.

Поэтому `scripts/deploy.sh` владеет объявленным набором файлов хоста. Он их ставит, чинит при
drift, удаляет выведенные из оборота — а в Phase 1 сообщает обо всех остальных файлах в
сканируемых каталогах хоста, которые ничем не учтены.

## Четыре класса

Каждый файл хоста относится ровно к одному из них:

| Класс | Источник истины | Кто пишет его на хосте |
|---|---|---|
| **repo-managed** | побайтная копия в репо | `deploy.sh` (а для `deploy/*.service`, кроме бота, — оператор после drift-гейта) |
| **шаблон + значения хоста** | в репо — *форма*, на хосте — значения | оператор / бот, проверяется гейтом деплоя |
| **backup-only** | по замыслу не в репо; перечислен в `deploy/host/known-unmanaged.list` | сторонний установщик, провайдер или оператор — и offsite-бэкап |
| **retired** | запись `class absent`: файла быть *не* должно | `deploy.sh` его удаляет |

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
| `/etc/systemd/journald.conf` | conffile dpkg | пакет `systemd` | `/etc/systemd` | деплой его не пишет; Phase 1 сообщает **MODIFIED**, пока в нём осталась старая ручная правка — верните стоковый файл руками, когда drop-in уже действует |
| `/etc/systemd/resolved.conf.d/10-vpn-bot.conf` | repo-managed (`resolved`) | deploy.sh | `/etc/systemd` | `DNS=1.1.1.1 8.8.8.8`, `FallbackDNS=1.0.0.1 8.8.4.4`; заменяет ручную правку `resolved.conf` — [DNS на основном сервере](#dns-на-основном-сервере) |
| `/etc/systemd/resolved.conf` | conffile dpkg | пакет systemd-resolved | `/etc/systemd` | деплой его не пишет; в отчёте **MODIFIED**, пока отдельный ручной скрипт не вернёт его к дефолту пакета |
| `/etc/resolv.conf` | repo-managed (`plain`) | deploy.sh, из `deploy/host/dns/resolv.conf` | — (в репо) | обычный файл, а не stub-symlink resolved; побайтно равен копии хоста; инвариант `path-regular` |
| `/etc/systemd/networkd.conf.d/10-keep-foreign-rules.conf` | repo-managed (`networkd`) | deploy.sh | `/etc/systemd` | не даёт networkd сбрасывать `ip rule` WARP; действует со следующего старта networkd |
| `/usr/local/sbin/acme-reload.sh` | repo-managed (`hook`, `when=/etc/vpn-bot/tls/fullchain.pem`) | deploy.sh, из `deploy/vpn-bot-acme-reload.sh` | `/usr/local/sbin` | `Le_ReloadCmd` у acme.sh; только там, где есть сертификат; [subscription.ru.md](subscription.ru.md#tls-терминация) |
| `/etc/ssh/sshd_config.d/00-root-key-only.conf` | repo-managed (`ssh`) | deploy.sh | `/etc/ssh` | вход root только по ключу; см. [ALLOW_SSH_CHANGE](#allow_ssh_change-и-риск-потери-доступа) |
| `/etc/systemd/system/ssh.socket.d/override.conf` | repo-managed (`ssh`) | deploy.sh | `/etc/systemd` | `ListenStream` на 54321 (IPv4 + IPv6) |
| `/etc/cloud/cloud-init.disabled` | repo-managed (`plain`) | deploy.sh, из `deploy/host/cloud/cloud-init.disabled` | — (в репо) | пустой маркер: cloud-init выключен (на ребуте он переписывал sshd и sudoers) |
| `/etc/systemd/system/vpn-bot-host-check.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | oneshot: проверка инвариантов хоста — [Эффективное состояние](#эффективное-состояние) |
| `/etc/systemd/system/vpn-bot-host-check.timer` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | через 5 минут после загрузки, затем раз в сутки; `enable --now`, как любой таймер реестра |
| `/var/lib/vpn-bot-host-check/last.json` | состояние | `vpn-bot-host-check` | — | последний вердикт (атомарно, `root` `0644`); его читает бот |
| `/etc/systemd/system/danted.service.d/vpn-bot-warp.conf` | repo-managed (`unit`) | deploy.sh, из `deploy/danted-warp.conf` | `/etc/systemd` | порядок запуска после интерфейса WARP |
| `/etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf` | repo-managed (`unit`, `gate=MTPROTO`) | deploy.sh, из `deploy/mtproxy-vpn-bot-managed.conf` | `/etc/systemd` | только пока `MTPROTO_ENABLED=true`; побайтно равный файл со старым именем `vpnbot-managed.conf` переименовывается. При выключенном MTProxy оставшийся drop-in показывается как сирота |
| `/etc/systemd/system/vpn-bot.service` | repo-managed | deploy.sh, как есть | `/etc/systemd` | действуют гейты модели привилегий |
| `/etc/systemd/system/<deploy/*.service, *.timer>` | repo-managed | оператор, руками | `/etc/systemd` | drift-гейт юнитов в Phase 1 печатает команды установки |
| `/usr/local/sbin/vpn-bot-warp-*`, `warp-failsafe`, `vpnbot-hy2-warp-mark`, `vpn-bot-db-perms`, `vpn-bot-host-check` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | `/usr/local/sbin` | из `scripts/` |
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
| `/usr/local/sbin/vpn-relay-apply` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | |
| `/usr/local/sbin/vpn-bot-host-check` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | проверка инвариантов хоста |
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

`role` — `main` или `relay`: хост видит только записи своей роли. `opts` необязателен:
`gate=<PROTO>` делает запись существующей только при включённом `<PROTO>_ENABLED` в `.env`,
`when=<path>` — только на хосте, где есть `<path>`, а `legacy=<path>` называет старое имя того же
файла. Закрытый gate означает, что запись не ставится и не проверяется.

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

**Phase 1** (только чтение, в том числе при `PHASE1_ONLY=1`) сверяет каждую запись с
`origin/main` и показывает состояние каждого файла: `synced`, `absent` (будет установлен),
`drift` (будет переустановлен — печатается diff), `meta` (содержимое верное, права/владелец нет —
чинится на месте), `rename`, `present` / `gone` (выведенные файлы), `gated-off`. Она проверяет
каждого кандидата, которого поставит Phase 2, и **останавливается до любых изменений**, если
валидатор его отверг, если на выведенный файл ещё есть ссылка, если файл со старым именем
отличается от репо или если ssh-файл отличается без `ALLOW_SSH_CHANGE=1`.

**Phase 2** сначала кладёт каждый путь, который может тронуть, в архив бэкапа, затем ставит, чинит
и удаляет, выполняет post-action каждого класса один раз для того, что реально изменилось, и
сканирует заново: ничего не должно остаться absent, в drift или present. Любой сбой идёт обычным
rollback, который возвращает каждый сохранённый файл — или снова удаляет его, если его не было, —
и заново применяет восстановленное состояние: enable юнитов, прежние значения sysctl в рантайме,
journald, ssh.

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

`scripts/vpn-bot-host-check` закрывает этот класс. Скрипт строго read-only — единственный файл,
который он пишет, это его собственный state-файл — и это единственная реализация: её вызывают
Phase 1 деплоя, Phase 2 деплоя и `vpn-bot-host-check.timer`. Вручную:
`sudo /usr/local/sbin/vpn-bot-host-check --no-state`.

### Вердикты

| Вердикт | Значение | Phase 1 деплоя | Phase 2 деплоя | Бот (main) |
|---|---|---|---|---|
| **BEATEN** | значение из repo-managed файла не действует: выигрывает другой файл | FAIL | rollback | алерт |
| **MISMATCH** | живое значение (`sshd -T`, `sysctl -n`, `systemctl show`) ≠ тому, что дают файлы, для ключа, который задаёт repo-файл; юнит из репо замаскирован, ждёт `daemon-reload` или (таймер, который ставит деплой) не enabled+active; строка `invariants.list` не выполняется | FAIL | rollback | алерт |
| **LATENT** | сейчас верно, но проигравший файл — не repo и не vendor — держит другое значение: уберут победителя, и значение молча перевернётся. В строке — победитель, проигравшие и `winner gone -> <значение> from <файл>` | FAIL для auth-ключа sshd¹, иначе WARN | в отчёте | алерт, если новый |
| **ACCEPTED** | LATENT из `deploy/host/accepted-overrides.list` | в отчёте | в отчёте | — |
| **WARN** | состояние хоста вне репо, на которое стоит посмотреть (ниже) | WARN | в отчёте | — |
| **PENDING** | только Phase 1: деплой сейчас это меняет; проверит Phase 2 | в отчёте | — | — |

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
  по имени), ключ = `Section.Key`, выигрывает **последнее** значение. Общего способа прочитать для
  них живое значение нет, поэтому они оцениваются только по старшинству.
- **Юниты, которые ставит репо**, по роли, из тех же источников, что `UNIT_SET` и
  `MANAGED_HOST_FILES`: на main — `deploy/vpn-bot.service`, каждый установленный на хосте
  `deploy/*.service|*.timer` и юниты и drop-in'ы реестра; на relay — `deploy/relay/*.service` и
  записи реестра. `*.example.*` — никогда. `FragmentPath` не наш или юнит замаскирован → BEATEN;
  `NeedDaemonReload=yes` → MISMATCH; нашего drop-in нет в `DropInPaths` → BEATEN; там же drop-in,
  который не наш и не vendor (`/etc`, `/run`, генераторы), → LATENT; таймер, который ставит деплой,
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
  `[::]:22 (Stream)`, но не с `:2222`). Засеяно: на main `ssh.socket` слушает 54321,
  `even-day-reboot.timer` enabled и active, `/etc/resolv.conf` — обычный файл; на relay
  `ssh.socket` слушает 22; на обеих ролях есть `/etc/cloud/cloud-init.disabled`.

### Как принять LATENT

LATENT, который должен остаться, записывается в **`deploy/host/accepted-overrides.list`** — это
единственный санкционированный способ; ручки `ALLOW_*` нет (`redeploy.sh` её бы и не передал):

```text
<path>|<key>|<причина, не короче 20 символов>
```

`path` — файл, который называет строка (проигравший, чужой drop-in или файл, который выигрывает
при `sysctl --system`), `key` — ключ строки (ключ sysctl, keyword sshd в нижнем регистре,
`Section.Key` или имя юнита для drop-in). Запись превращает в ACCEPTED ровно эту строку и ничего
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
— состояние хоста вне репо; сейчас на main это `journald.conf`, дублирующий managed drop-in, и
`resolved.conf`, см. ниже).

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
той же строке: отправленное хранится в базе, рестарт его не повторяет.

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
- Сам `/etc/systemd/resolved.conf` деплой никогда не пишет (он в отчёте как изменённый conffile).
  После деплоя этой раскладки его вернут к дефолту пакета отдельным ручным скриптом, который
  проверяет, что эффективная конфигурация не изменилась. Первый деплой ничего эффективного не
  меняет: drop-in несёт значения conffile, а `resolv.conf` уже synced.

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
