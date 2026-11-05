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
| `/etc/systemd/networkd.conf.d/10-keep-foreign-rules.conf` | repo-managed (`networkd`) | deploy.sh | `/etc/systemd` | не даёт networkd сбрасывать `ip rule` WARP; действует со следующего старта networkd |
| `/usr/local/sbin/acme-reload.sh` | repo-managed (`hook`, `when=/etc/vpn-bot/tls/fullchain.pem`) | deploy.sh, из `deploy/vpn-bot-acme-reload.sh` | `/usr/local/sbin` | `Le_ReloadCmd` у acme.sh; только там, где есть сертификат; [subscription.ru.md](subscription.ru.md#tls-терминация) |
| `/etc/ssh/sshd_config.d/00-root-key-only.conf` | repo-managed (`ssh`) | deploy.sh | `/etc/ssh` | вход root только по ключу; см. [ALLOW_SSH_CHANGE](#allow_ssh_change-и-риск-потери-доступа) |
| `/etc/systemd/system/ssh.socket.d/override.conf` | repo-managed (`ssh`) | deploy.sh | `/etc/systemd` | `ListenStream` на 54321 (IPv4 + IPv6) |
| `/etc/systemd/system/danted.service.d/vpn-bot-warp.conf` | repo-managed (`unit`) | deploy.sh, из `deploy/danted-warp.conf` | `/etc/systemd` | порядок запуска после интерфейса WARP |
| `/etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf` | repo-managed (`unit`, `gate=MTPROTO`) | deploy.sh, из `deploy/mtproxy-vpn-bot-managed.conf` | `/etc/systemd` | только пока `MTPROTO_ENABLED=true`; побайтно равный файл со старым именем `vpnbot-managed.conf` переименовывается. При выключенном MTProxy оставшийся drop-in показывается как сирота |
| `/etc/systemd/system/vpn-bot.service` | repo-managed | deploy.sh, как есть | `/etc/systemd` | действуют гейты модели привилегий |
| `/etc/systemd/system/<deploy/*.service, *.timer>` | repo-managed | оператор, руками | `/etc/systemd` | drift-гейт юнитов в Phase 1 печатает команды установки |
| `/usr/local/sbin/vpn-bot-warp-*`, `warp-failsafe`, `vpnbot-hy2-warp-mark`, `vpn-bot-db-perms` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | `/usr/local/sbin` | из `scripts/` |
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

### relay

На relay нет бота, поэтому offsite-бэкап он не отправляет: его файлы возвращаются из репо, а
`90-vpn-relay.conf` заново рендерится из `.env` relay.

| Путь | Класс | Кто ставит | Заметки |
|---|---|---|---|
| `/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf` | repo-managed (`ssh`) | deploy.sh | вход только по ключу |
| `/usr/local/sbin/vpn-relay-apply` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | |
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
| `ssh` | `sshd -t` на `sshd_config`, где кандидат подставлен в копию каталога drop-in'ов; drop-in сокета должен оставлять порт `ListenStream` | см. [ниже](#allow_ssh_change-и-риск-потери-доступа) |
| `absent` | ничто не должно на него ссылаться (ниже) | `disable --now`, если это unit-файл, затем удаление |

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
