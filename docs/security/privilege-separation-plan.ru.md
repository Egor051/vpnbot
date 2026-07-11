# Архитектура privilege separation

Статус: архитектура хелперов privilege separation реализована и поставляется. Поддерживаются две
модели развёртывания:

- **root+api mode (дефолт поставки).** `deploy/vpn-bot.service` работает как `User=root` с `ProtectSystem=false`; изменения бэкенда идут через Xray API и прямое управление сервисами, а `PRIVILEGE_HELPERS_ENABLED` по умолчанию `false`. Sudo-хелперы в этом режиме не используются.
- **non-root helper mode (усиленный opt-in).** Бот работает как `User=vpn-bot`/`Group=vpn-bot` из `deploy/vpn-bot.nonroot.example.service`, и каждая привилегированная мутация бэкенда изолирована за фиксированными sudo-хелперами. Эту модель описывает и валидирует остальная часть документа и `deploy/check-nonroot-helper-mode.py`.

## Non-root Helper Mode

- Установите `deploy/vpn-bot.nonroot.example.service` как активный unit. Поставляемый `deploy/vpn-bot.service` работает root+api и намеренно **не** non-root; он не прошёл бы non-root preflight.
- `PRIVILEGE_HELPERS_ENABLED=true`.
- `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
- systemd создаёт `/run/vpn-bot` с `RuntimeDirectory=vpn-bot` и `RuntimeDirectoryMode=0700`.
- Код, файлы деплоя, `.env`, service units и `.venv` недоступны для записи от `vpn-bot`.
- `vpn-bot` пишет только runtime-состояние:
  - `/opt/vpn-service/data`
  - `/opt/vpn-service/logs`, если файловые логи включены
  - `/run/vpn-bot` — staging хелперов и lock-файлы
- Каноническое состояние бэкендов остаётся root-owned:
  - `/usr/local/etc/xray/config.json`
  - `/etc/amnezia/amneziawg/awg0.conf`
  - `/etc/mtproxy/vpn-bot`
  - `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` и `/etc/.pwd.lock`

Базовые привилегированные точки входа бэкендов, разрешённые через `/etc/sudoers.d/vpn-bot`:

- `/usr/local/sbin/vpn-bot-socks5-user`
- `/usr/local/sbin/vpn-bot-xray-apply`
- `/usr/local/sbin/vpn-bot-awg-apply`
- `/usr/local/sbin/vpn-bot-mtproxy-apply`

Когда включён опциональный модуль WARP-сокрытия исходящего IP, тот же sudoers-файл
дополнительно грантит фиксированные точки входа его хелперов — `vpn-bot-warp-install`,
`vpn-bot-warp-iface`, `vpn-bot-warp-routes`, `vpn-bot-warp-status` и хелперы
split-маршрутизации `vpn-bot-warp-split-apply` / `vpn-bot-warp-split-state` (см.
[`../warp.ru.md`](../warp.ru.md) и `deploy/sudoers.d/vpn-bot.example`). Они подчиняются
той же границе, что и хелперы бэкендов: фиксированные пути, пиннинг по глаголам (без
wildcard на split-глаголах) и валидация argv на стороне хелпера. Авторитетный список
грантов — `deploy/sudoers.d/vpn-bot.example`, а `deploy/check-nonroot-helper-mode.py`
валидирует и базовый, и WARP-набор хелперов.

Валидируйте живые хосты до и после рестартов сервиса:

```bash
python deploy/check-nonroot-helper-mode.py
visudo -cf /etc/sudoers.d/vpn-bot
```

## Почему NoNewPrivileges не включён

`NoNewPrivileges=true` блокирует повышение привилегий через setuid-бинарники. Архитектура хелперов
намеренно использует `sudo -n` из непривилегированного Python-процесса для доступа к узкому набору
root-owned точек входа. Включение `NoNewPrivileges` помешало бы sudo выполнить этот переход и
сломало бы apply для Xray, AWG, SOCKS5 и managed MTProxy.

Граница безопасности поэтому такова:

- процесс бота остаётся non-root;
- sudoers выдаёт только фиксированные команды-хелперы, никогда `NOPASSWD: ALL`;
- файлы хелперов `root:root` `0755`;
- `/etc/sudoers.d/vpn-bot` — `root:root` `0440`;
- хелперы валидируют argv, staged-пути, префиксы, форму файла и цели бэкенда перед мутацией root-owned состояния.

## Инвентарь привилегированных операций

| Компонент | Поведение в production | Root-only граница | Прямой доступ Telegram-бота |
| --- | --- | --- | --- |
| vpn-bot systemd runtime | В non-root helper mode работает как `vpn-bot:vpn-bot` из `deploy/vpn-bot.nonroot.example.service`; `ProtectSystem=strict`; `ReadWritePaths=/opt/vpn-service/data /opt/vpn-service/logs /run/vpn-bot`. | Установка unit, кода, `.env` и управление сервисом — работа оператора/root. | Нет root runtime. |
| Каталог данных SQLite | `DB_PATH` по умолчанию `/opt/vpn-service/data/vpn.db`; файлы DB/WAL/SHM — runtime-состояние бота. | sudoers не нужен. | Да, прямое чтение/запись в SQLite ожидаемо. |
| Работа с `.env` | systemd читает `EnvironmentFile=/opt/vpn-service/.env`; файл не должен быть writable для `vpn-bot`. | Root/оператор владеет production-секретами и restart-time конфигом. | Окружение наследуется; прямой записи нет. |
| Логи и lock-пути | `LOG_DIR=/opt/vpn-service/logs`; `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`; `RuntimeDirectory=vpn-bot`. | sudoers не нужен. | Да, прямая запись в узкие runtime-пути. |
| Apply конфига Xray | Бот стейджит кандидата под `/run/vpn-bot/xray`; хелпер валидирует JSON и синтаксис Xray, атомарно ставит канонический конфиг, перезапускает фиксированный сервис `xray`, проверяет active state и откатывается при ошибке. | `/usr/local/sbin/vpn-bot-xray-apply` через sudoers. | Нет прямой записи в канонический конфиг Xray или generic управления сервисом. |
| Apply конфига/runtime AWG | Бот стейджит кандидата под `/run/vpn-bot/awg`; хелпер валидирует через `awg-quick strip` или совместимый инструмент, ставит `/etc/amnezia/amneziawg/awg0.conf`, применяет fixed-interface runtime sync и проверяет `awg-quick@awg0`. | `/usr/local/sbin/vpn-bot-awg-apply` через sudoers. | Нет прямой записи в канонический конфиг AWG или generic сетевых мутаций. |
| Чтение статуса/трафика AWG | Хелпер возвращает sanitized status, peer и transfer для фиксированного интерфейса `awg0`. | `/usr/local/sbin/vpn-bot-awg-apply status`, `show-peers`, `show-transfer`. | Нет raw AWG/WG-команд в sudoers. |
| Жизненный цикл SOCKS5 Linux-пользователей | Хелпер управляет только логинами с configured login prefix, напр. `vpn_socks_`; password remains stdin-only. | `/usr/local/sbin/vpn-bot-socks5-user` действия `exists`, `create`, `set-password`, `lock`, `delete`. | Нет прямой записи в account database или raw `useradd`/`chpasswd`/`passwd`/`userdel`. |
| Состояние сервиса Dante | Бот предполагает, что Dante установлен и слушает; он не перезапускает Dante. | Жизненный цикл сервиса — работа оператора/root, пока не добавлен фиксированный хелпер. | Нет мутаций сервиса. |
| Managed-файлы/apply MTProxy | Бот стейджит `managed-secrets.json` и `mtproxy.env` под `/run/vpn-bot/mtproxy`; хелпер валидирует форму без вывода секретов, ставит файлы `/etc/mtproxy/vpn-bot` атомарно, перезапускает фиксированный сервис `mtproxy`, проверяет сервис/порт и откатывается при ошибке. | `/usr/local/sbin/vpn-bot-mtproxy-apply` через sudoers. | Нет прямой записи в `/etc/mtproxy` или generic управления сервисом. |
| Бэкапы бэкендов | Хелперы создают и хранят бэкапы канонических файлов Xray/AWG/MTProxy с приватными режимами. | Helper-owned root-пути. | Нет прямой записи бэкапов бэкенда. |
| Скрипты деплоя и владение | Деплой и обновления — работа root/оператора. Рекурсивные изменения владения не должны делать код или `.venv` writable для `vpn-bot`. | `deploy/create-vpn-bot-user.sh`, установка хелперов, sudoers и unit. | Нет deploy-time записи в код или unit-файлы. |

## Контракты хелперов

### SOCKS5 helper

Путь: `/usr/local/sbin/vpn-bot-socks5-user`.

Обязательные свойства:

- Root-owned и не writable для `vpn-bot`.
- Вызывается `vpn-bot` только через sudoers.
- Разрешённые действия: `exists <login>`, `create <login>`, `set-password <login>` с password read from stdin, `lock <login>`, `delete <login>`.
- Применяет configured login prefix, например `vpn_socks_`.
- Применяет строгий login-regex, совместимый с именованием Linux-аккаунтов, например `^[A-Za-z_][A-Za-z0-9_]{0,31}$`.
- Никогда не принимает произвольные имена пользователей.
- Никогда не принимает shell-пути из недоверенных args. Login shell — фиксированное безопасное значение, например `/usr/sbin/nologin`.
- Never prints passwords.
- Редактирует (redact) секреты в ошибках и логах.

### Xray helper

Путь: `/usr/local/sbin/vpn-bot-xray-apply`.

Обязательные свойства:

- Принимает кандидатов только из `/run/vpn-bot/xray`.
- Валидирует JSON перед вызовом Xray.
- Запускает `xray run -test -config <candidate>` против кандидата.
- Атомарно ставит в `/usr/local/etc/xray/config.json`.
- Применяет фиксированным рестартом сервиса `xray`.
- Проверяет, что Xray active после apply.
- Реализует rollback внутри хелпера, так как он владеет установкой канонического конфига и apply сервиса.

### AWG helper

Путь: `/usr/local/sbin/vpn-bot-awg-apply`.

Обязательные свойства:

- Принимает кандидатов только из `/run/vpn-bot/awg`.
- Валидирует через `awg-quick strip` или настроенный совместимый инструмент.
- Атомарно ставит `/etc/amnezia/amneziawg/awg0.conf`.
- Ставит как `root:vpn-bot` mode `0640` (world-unreadable; group-readable, чтобы бот мог читать статус). Замечание: это делает серверный WireGuard `PrivateKey` читаемым для группы `vpn-bot` — принятый trade-off ради non-root чтения статуса; держите процесс бота и членство в группе строго ограниченными.
- Применяет runtime через fixed-interface `syncconf` для `awg0`, согласно существующему дизайну адаптера, избегающему полного рестарта туннеля.
- Проверяет, что `awg-quick@awg0` active.
- Предоставляет sanitized read-only status/peer/transfer для фиксированного интерфейса.

### MTProxy helper

Путь: `/usr/local/sbin/vpn-bot-mtproxy-apply`.

Обязательные свойства:

- Принимает кандидатов только из `/run/vpn-bot/mtproxy`.
- Ставит managed secret и env-файлы атомарно как `root:vpn-bot` mode `0640` в каталоге `0750` `root:vpn-bot` (world-unreadable; group-readable для non-root чтения).
- Перезапускает `mtproxy`, используя фиксированное имя сервиса.
- Проверяет active state сервиса и слушающий порт.
- Never prints raw MTProto secrets или сгенерированные ссылки.
- Редактирует (redact) секреты в ошибках, логах и rollback-сводках.

## Граница sudoers

`/etc/sudoers.d/vpn-bot` должен выдавать только helper-алиасы из `deploy/sudoers.d/vpn-bot.example`.
Он не должен содержать `NOPASSWD: ALL`, `ALL=(ALL) ALL`, raw `systemctl`, raw Linux account tools,
copy/install tools, raw `xray`, raw `awg`/`wg` или raw MTProxy-бинарники.

Wildcard-аргументы в sudoers допустимы только потому, что прикреплены к фиксированным
точкам входа-хелперам, и хелперы независимо валидируют staging-корни, симлинки, имена действий и
идентификаторы бэкендов.

## Состояние развёртывания

Развёртывание privilege separation завершено:

1. Хелперы реализованы и установлены как фиксированные root-owned точки входа.
2. `deploy/vpn-bot.service` — поставляемый root+api unit; `deploy/vpn-bot.nonroot.example.service` — non-root helper-mode unit для установки при выборе этой модели.
3. `deploy/vpn-bot.root-legacy.example.service` сохранён только как аварийный root/direct fallback.
4. Helper mode — opt-in через `PRIVILEGE_HELPERS_ENABLED=true` (по умолчанию `false`).
5. `deploy/check-nonroot-helper-mode.py` — обязательный preflight и postflight host-check для non-root helper mode.

## Заметки об аварийном откате

Root-run mode больше не рекомендуемый production-путь. Используйте его только как аварийный откат
при восстановлении доступности сервиса или расследовании поломки helper-mode развёртывания.

Форма отката:

1. Остановите `vpn-bot`.
2. Восстановите забэкапленный pre-cutover systemd unit и соответствующий `.env` из живого набора бэкапов.
3. Установите `PRIVILEGE_HELPERS_ENABLED=false` только для rollback-unit.
4. Выполните `systemctl daemon-reload`.
5. Запустите `vpn-bot` и проверьте логи/состояние бэкендов.
6. Вернитесь на non-root helper-mode путь, как только инцидент исправлен.

Не расширяйте sudoers как rollback-шорткат. Не используйте `NOPASSWD: ALL`. Не делайте
`/opt/vpn-service`, файлы деплоя или `.venv` writable для `vpn-bot`.
