# Удаление протокола с сервера

В «Модулях протоколов» админ-панели два способа выключить протокол:

| Кнопка | В боте | На сервере |
|---|---|---|
| **Только выключить** | доступ каждого клиента снимается на бэкенде; ключи Xray/AWG/Hysteria2 удаляются из базы (трафик архивируется), прокси-доступы SOCKS5/MTProto помечаются удалёнными (записи остаются); модуль выключается | сервис, конфиги, бинарники, юниты и правила firewall остаются — «Включить» возвращает протокол |
| **Выключить и удалить с сервера** | сначала то же снятие доступа | затем root-хелпер `deploy/helpers/vpn-bot-protocol-uninstall` удаляет то, что для протокола названо в его манифесте, — и ничего больше |

У уже выключенного модуля (AWG и MTProto на основном сервере) есть своя кнопка
**🗑 Удалить с сервера**: выключение с хоста ничего не удаляло.

## Порядок

1. **План.** Бот запускает `vpn-bot-protocol-uninstall plan <proto>` (только чтение) и
   показывает: юниты и что с каждым будет (stop / disable / mask), файлы и каталоги с
   размерами, правила UFW, пакеты, пользователей, что **пропущено как общее** и почему,
   что **уже отсутствует**, путь бэкапа. Для Xray бот добавляет предупреждение, если в
   базе есть relay: их VLESS-ключи перестанут работать.
2. **Подтверждение.** Кнопка несёт первые 12 символов sha256 плана: старое сообщение с
   планом не может применить новый план, которого никто не видел.
3. **Apply.**
   1. План пересчитывается; другой sha256 (сервер изменился) — отказ и новый план на
      подтверждение.
   2. Существующее снятие доступа (`disable_protocol`). **Если хоть одна запись не
      снялась, с сервера ничего не удаляется** — у этих клиентов доступ может остаться.
   3. Бэкап всего, что изменится (файлы, каталоги, unit-файлы, drop-in'ы, symlink'и
      enable/mask, `.env`, conffile'ы удаляемого пакета) плюс `ufw status numbered`,
      `ufw show added`, строки `getent` удаляемых пользователей и таблица mangle
      (Hysteria2) — в `/var/backups/vpn-bot/uninstall/<proto>-<UTC ts>.tar.gz` (root 0600,
      каталог 0700), проверка `tar -tzf`. Нет валидного бэкапа — ничего не трогается.
   4. Юниты: stop → disable → (AWG: mask) → unit-файлы и drop-in'ы из манифеста →
      `daemon-reload` → `reset-failed`.
   5. Файлы и каталоги поимённо, каждый перепроверяется `realpath` прямо перед `rm`
      (путь или родитель, ставший symlink'ом, останавливает запуск).
   6. UFW: `ufw delete allow <port>/<proto>` (копии v4 и v6), затем `ufw show added` /
      `ufw status` не должны его показывать.
   7. `apt-get purge -y` пакетов манифеста со статусом dpkg `ii` (purge, который потянул
      бы другие пакеты, блокируется ещё в плане).
   8. `userdel` (никогда не `-r`) пользователей манифеста — только если `find / -xdev
      -uid <uid>` больше ничего не находит и нет процессов; иначе пользователь
      остаётся, отчёт объясняет почему.
   9. `.env`: `<PROTO>_ENABLED=false` для SOCKS5 / Hysteria2 / MTProto — заменяется ровно
      одна строка (последнее присваивание) или дописывается одна, владелец и права
      сохраняются.
   10. Маркер `/etc/vpn-bot/uninstalled/<proto>` (JSON: ts, sha256, backup).

   Ошибка на шагах 4–10 восстанавливает всё из архива, переустанавливает удалённый пакет
   (`--force-confold`, восстановленный conffile остаётся), пересоздаёт удалённых
   пользователей с их uid/gid и хешем пароля, снимает mask, снова включает/запускает
   юниты, которые были enabled/active, и возвращает правила UFW с комментариями. Отчёт
   называет шаг и говорит, полным ли был откат.
4. **Отчёт**: удалено / уже отсутствовало / пропущено / ошибки, бэкап, команда ручного
   отката. Повторный apply на удалённом протоколе — «нечего делать».

Лог: `/var/log/vpn-bot-uninstall.log`. Аудит: `protocol_uninstalled`,
`protocol_uninstall_failed` (sha256 плана, бэкап, шаг).

### Что покрывает хеш плана

То, что apply **решает**: какие юниты, unit-файлы, пути, правила UFW, пакеты и
пользователи затрагиваются, правка `.env` и маркер. Не покрывает: размеры, active-
состояния, `*.bak` внутри каталога, удаляемого целиком, файлы AWG по шаблону и
SOCKS5-пользователей по префиксу+shell — шаг 2 (снятие доступа) по замыслу создаёт
свежие бэкапы и удаляет именно этих пользователей.

## Манифесты, сознательно не удаляемое, после удаления

Полные таблицы — в английской версии [protocol-uninstall.md](protocol-uninstall.md):
манифесты по протоколам, глобальный deny-list хелпера и список **сознательно не
удаляемого** с причинами (nobody, nginx и decoy-сайт, сертификаты и acme.sh,
`/etc/logrotate.d/xray`, каталоги `/etc/amnezia`, всё out-warp и warp-*, пакеты
amneziawg*, файлы пакета dante-server, чужие SOCKS5-пользователи, tracked-файлы
репозитория, база, sshd, порты 22/54321, eth0, sysctl).

Источник истины — маркер. Бот читает его при старте и после apply: startup reconcile,
сборщики статистики Xray/AWG/Hysteria2, health-probe Hysteria2, детектор аномалий,
состав подписок и доступность протоколов пропускают протокол; BackendHealth
показывает **UNINSTALLED** (не degraded); «Включить» отвечает «Протокол удалён с
сервера, нужна переустановка». `scripts/deploy.sh` убирает юниты протокола из
`UNIT_SET` и drift-проверки, держит закрытым его gate в `MANAGED_HOST_FILES`
(drop-in danted — `gate=SOCKS5`), пропускает его `OUT_OF_REPO_HELPERS` и
`WARP_ONESHOTS`.

## Ручной откат (runbook)

От root, из бэкапа из отчёта (или самого свежего
`/var/backups/vpn-bot/uninstall/<proto>-*.tar.gz`):

```bash
A=/var/backups/vpn-bot/uninstall/<proto>-<ts>.tar.gz
tar -xzf "$A" -C /tmp vpn-bot-uninstall-meta && cat /tmp/vpn-bot-uninstall-meta/ROLLBACK.txt
tar -xzf "$A" -C / --numeric-owner --preserve-permissions --xattrs --acls \
    --no-overwrite-dir --exclude=vpn-bot-uninstall-meta      # файлы, юниты, .env
apt-get install -y -o Dpkg::Options::=--force-confold dante-server=<версия>   # SOCKS5: packages.txt
groupadd -g <gid> <name>; useradd -u <uid> -g <gid> -d <home> -M -s <shell> <name>  # getent-*.txt
systemctl unmask awg-quick@awg0.service                     # только AWG
systemctl daemon-reload && systemctl enable --now <unit> ... # units.txt
ufw allow 443/tcp comment 'Xray Reality HTTPS'              # строки из ufw-show-added.txt
rm -f /etc/vpn-bot/uninstalled/<proto> && systemctl restart vpn-bot   # затем «Включить» в панели
```

Переустановка без архива заканчивается так же: протокол ставится своим способом,
`/etc/vpn-bot/uninstalled/<proto>` удаляется, `<PROTO>_ENABLED=true` возвращается там,
где флаг есть, бот перезапускается, модуль включается.

## Привилегии

Обе модели. Root (`PRIVILEGE_HELPERS_ENABLED=false`): бот запускает хелпер из своего
checkout — та же версия кода, нет установленной копии, которая могла бы отстать.
Helper-режим: `sudo -n /usr/local/sbin/vpn-bot-protocol-uninstall`, ставит
`deploy/setup-nonroot-helper-mode.sh`, права — по протоколу в
`deploy/sudoers.d/vpn-bot.example`. Внутри песочницы `ProtectSystem=strict` хелпер
входит в mount namespace PID 1 (`nsenter`). `PROTOCOL_UNINSTALL_HELPER_PATH`
переопределяет путь в любой модели.
