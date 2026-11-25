# Установка протокола из бота

После `scripts/install.sh` бот работает вообще без протоколов. Всё дальнейшее — в Telegram:
в **⚙️ Модули протоколов** протокол, который бот умеет ставить и которого нет на сервере,
показан как **📦 <протокол>** с кнопкой **📦 Установить**. Кнопка запускает прогон режима
мастера `protocol` ([wizard.ru.md](wizard.ru.md)): сначала план со всеми изменениями, затем
**✅ Применить** — TOTP перед обоими шагами, — затем apply → verify и откат, если любой из них
не прошёл.

🇬🇧 English version: [protocol-install.md](protocol-install.md)

Что ставит этот релиз: **Xray (VLESS + REALITY) с self-steal на nginx**. Hysteria2, SOCKS5,
оркестровка WARP и переустановка протокола, удалённого с сервера, — следующие шаги; место для
них в манифесте helper'а уже есть.

## Перед началом

* **Сертификат бота.** Протокол обслуживает домен сертификата бота
  ([certificate.ru.md](certificate.ru.md)): «🔐 Сертификат и DNS» → сначала выпустите или
  примите его. Без принятого сертификата с рабочим ключом (осталось 7+ дней) план
  останавливается с этой причиной. Домен должен указывать на этот сервер (A-запись).
* **`.env` в том виде, в каком его пишет `install.sh`.** Установщик раскладывает раскладку
  прода: `XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json`, `XRAY_SERVICE_NAME=xray`,
  `XRAY_PUBLIC_PORT=443`, `XRAY_INBOUND_TAG=vless-in`,
  `XRAY_XHTTP_INBOUND_TAG=vless-xhttp-reality`, `XRAY_STATS_SERVER=127.0.0.1:10085` (пустое
  значение допустимо; другое останавливает план — сгенерированный конфиг не совпал бы с тем,
  что описывает `.env`).

## Root-helper `vpn-bot-protocol-install`

`scripts/vpn-bot-protocol-install` (ставится в `/usr/local/sbin` через `deploy.sh`,
`OUT_OF_REPO_HELPERS`, политика `required`, роль main; на чистом хосте — `install.sh`,
`INSTALL_HELPERS`). Боту он не выдаётся: его запускает от root режим мастера
`vpn-bot-wizard-protocol` внутри собственного systemd-юнита прогона.

| Команда | Что делает |
|---|---|
| `manifest <proto> [--json]` | Манифест, вкомпилированный в helper (ниже). |
| `status [--json]` | По каждому протоколу: `installed` / `partial` / `absent` / `uninstalled` (его маркер), состояние последнего журнала. |
| `plan <proto> [--domain D] [--json]` | Только чтение. Каждое изменение (`create`, `install`, `start`, `deploy`, `replace`, `set`, `remove`), что остаётся как есть и почему, строки `.env`, что блокирует, релиз и его sha256, sha256 самого плана. |
| `apply <proto> --expect-plan SHA [--domain D] [--json]` | План считается заново: другой sha256 (хост изменился) — отказ, ничего не меняется. Затем бэкап, шаги, журнал; сбой шага откатывает все шаги. |
| `verify <proto> [--domain D] [--json]` | Только чтение: протокол работает (ниже). |
| `rollback <proto> [--json]` | Журнал последнего apply в обратном порядке. После commit — отказ. |
| `commit <proto> [--json]` | Последний apply окончательный: мастер делает commit после зелёного verify. |

Коды выхода: 0 ок · 2 использование · 3 отказ (блокирующая находка, план изменился, идёт
другая установка или удаление, уже committed) · 4 verify не прошёл · 5 не могу (инструмент,
файл, загрузка) · 6 шаг упал, откат удался · 7 шаг упал, откат удался не полностью. Только
stdlib; каждая команда — список argv; при запуске из другого mount namespace перезапускается
в namespace PID 1. Лог: `/var/log/vpn-bot-protocol-install.log` (редактируется: приватный
ключ REALITY туда не попадает). Одна установка за раз и никогда параллельно с удалением
(`/run/vpn-bot-protocol-install.lock` и lock удаления).

### Манифест — симметричен удалению

То, чем helper **владеет** для протокола, — ровно то, что удаляет
[`vpn-bot-protocol-uninstall`](protocol-uninstall.ru.md), и ничего больше:
`tests/test_protocol_install_helper.py` сравнивает `manifest <proto>` обоих helper'ов (юниты,
файлы юнитов, пути, пакеты, пользователи, флаг `<PROTO>_ENABLED`) и на одном фейковом хосте
прогоняет установку → настоящее удаление → установку заново. То, что протоколу нужно, но ему
не принадлежит, — **общее**: ставится, если его нет, и никогда не удаляется (каждый общий путь
защищён deny-list'ом удаления — это проверяет тот же тест).

| Протокол | Свой (удаление его убирает) | Общий (не удаляется) | `.env` |
|---|---|---|---|
| Xray | `xray.service` (включён, запущен), `xray@.service`, `/etc/systemd/system/xray{,@}.service{,.d}`, `/usr/local/bin/xray`, `/usr/local/share/xray`, `/usr/local/etc/xray`, `/var/log/xray` | пользователь `nobody`; nginx (пакет, `/etc/nginx/conf.d/selfsteal.conf`, `/var/www/selfsteal`); реестр сертификата `/etc/vpn-bot/tls`; `/etc/logrotate.d/xray` (deploy.sh) | `XRAY_PUBLIC_HOST`, `XRAY_SNI`, `XRAY_REALITY_PUBLIC_KEY`, `XRAY_SHORT_ID`, `XRAY_INBOUND_TAG`, `XRAY_STATS_SERVER`, `XRAY_XHTTP_ENABLED`, `XRAY_XHTTP_INBOUND_TAG` — настройки, после удаления инертны (маркер), поэтому удаление их оставляет |

Маркер удаления `/etc/vpn-bot/uninstalled/<proto>`, который удаление пишет последним,
установка снимает **последним** шагом (переустановка).

### Apply по шагам

Каждый шаг записывает свою запись в журнал (`/var/lib/vpn-bot-protocol-install/<proto>.journal.json`,
root 0600) **до** действия, поэтому сбой — или kill — на полпути тоже откатывается. Каждый
существующий путь, который шаг может изменить, включая `.env`, сначала попадает в бэкап:
`/var/backups/vpn-bot/install/<proto>-<UTC ts>.tar.gz` (root 0600, каталог 0700), проверяется
обратным чтением. Существующее никогда не заменяется: установленный `xray`, `config.json` с
клиентами, vhost nginx оператора — в плане это `keep`.

| Шаг | Что | Откат |
|---|---|---|
| `nginx_pkg` | `apt-get install --no-install-recommends nginx` с `/usr/sbin/policy-rc.d` (exit 101), чтобы nginx не стартовал с сайтом по умолчанию на `:80`; этот сайт (`sites-enabled/default`) отключается. Только если nginx не установлен | purge ровно тех пакетов, что поставил этот прогон; ссылка возвращается |
| `nginx_start` | `systemctl enable --now nginx` — нашего vhost ещё нет, сертификат он не читает | stop / disable, как было |
| `cert` | `vpn-bot-cert deploy`: nginx становится потребителем реестра, как только есть его юнит ([certificate.ru.md](certificate.ru.md)); пара раскладывается в `/etc/vpn-bot/tls`, nginx перечитывает конфиг | ничего — пара реестра общая (её читает и эндпоинт подписки) |
| `nginx_site` | сайт-приманка `deploy/site/default` → `/var/www/selfsteal` (нейтральный, без брендов), `deploy/nginx/selfsteal.conf` → `/etc/nginx/conf.d/selfsteal.conf` (`listen 127.0.0.1:8443 ssl http2`, `ssl_protocols TLSv1.3`, `server_name` — домен, пара реестра), `nginx -t`, reload. Если nginx уже обслуживает `127.0.0.1:8443` своим vhost, он остаётся (предупреждение) | файлы удаляются, nginx перечитывает конфиг |
| `xray_bin` | официальный релиз GitHub **закреплённой** версии (`XRAY_VERSION`, `Xray-linux-64.zip` / `Xray-linux-arm64-v8a.zip`): его sha256 должен совпасть с закреплённым в helper'е **и** со строкой `SHA2-256` из `.dgst` самого релиза. `xray` → `/usr/local/bin` (0755), `geoip.dat` / `geosite.dat` → `/usr/local/share/xray` | удаляется |
| `xray_units` | `deploy/xray/xray.service`, `xray@.service` и drop-in'ы single-config `10-donot_touch_single_conf.conf` — юниты upstream-установщика, байт в байт; `daemon-reload` | удаляются |
| `xray_logs` | `/var/log/xray` (`nobody:nogroup 0700`), `access.log`, `error.log` (0600) | удаляется |
| `xray_config` | `/usr/local/etc/xray/config.json`, `nobody:vpn-bot 0640` (`nobody:nogroup` без группы `vpn-bot` — модель root); генерируется из `deploy/xray/config.skeleton.json`: новая пара x25519 (`xray x25519`), один shortId, `serverNames` — домен, REALITY `target` 127.0.0.1:8443, XHTTP fallback inbound на 127.0.0.1:8001 (`XRAY_XHTTP_PATH`), api inbound на 127.0.0.1:10085, `sendThrough` на freedom outbound при включённом WARP proxy egress (правило самого бота). Проверяется `xray run -test` **до** установки на место | удаляется |
| `env` | `XRAY_*` выше: последнее присваивание каждого ключа заменяется или строка дописывается — все прочие строки байт в байт, владелец и режим сохраняются, запись атомарная | `.env` из бэкапа |
| `xray_start` | `systemctl enable xray`, `restart`, active | stop / disable |
| `marker` | `/etc/vpn-bot/uninstalled/<proto>` снимается — ПОСЛЕДНИМ | маркер возвращается |

Сгенерированный конфиг сериализуется ровно так, как его пишет бот (`adapters/xray_config.py`),
поэтому reconcile бота ничего в нём не меняет: тест прогоняет настоящий startup reconcile,
проверку shortId, повторное применение WARP, проверку дрейфа деплоя по скелету
(`deploy/backend-config-sync.py check`) и `Settings.validate_xray_ready()` на том, что записал
helper, и сравнивает байты.

### Verify

Только чтение, каждая проверка — пункт отчёта прогона:

* `xray run -test -config /usr/local/etc/xray/config.json`;
* `xray.service` и `nginx.service` активны;
* слушатели (`ss -Hltn`): `0.0.0.0:443` (vless-in), `127.0.0.1:10085` (api),
  `127.0.0.1:8001` (XHTTP), `127.0.0.1:8443` (self-steal);
* `serverNames` содержит домен, `XRAY_SHORT_ID` — shortId vless-in,
  `XRAY_REALITY_PUBLIC_KEY` — публичная половина ключа REALITY (`xray x25519 -i`);
* `openssl s_client -connect 127.0.0.1:8443 -servername <домен> -alpn h2 -verify_hostname
  <домен>`: сертификат домена проверяется, TLS 1.3, ALPN h2;
* `curl --http2 --resolve <домен>:8443:127.0.0.1 https://<домен>:8443/` → 200.

## Режим мастера `protocol`

`scripts/wizard/vpn-bot-wizard-protocol`, параметры `proto` (`xray`) и `domain` (одно
DNS-имя, которое покрывает сертификат; пусто — имя самого сертификата). Запускается из
«⚙️ Модули протоколов», а не из меню мастера. Опасный: TOTP перед планом и перед apply.

* **plan** — план helper'а текстом: изменения, что остаётся, строки `.env` (было → станет;
  генерируемые ключи — `<generated>`), предупреждения и блокировки, релиз, бэкап. Ниже —
  шаги, все ⚪. План, в котором нечего делать, завершает прогон (`succeeded`).
* **apply** — события шагов helper'а становятся прогрессом прогона (⚪ 🔄 ✅ ❌ ⏭,
  `bot/progress.py`) в одном сообщении.
* **verify** — проверки выше зелёными/красными пунктами; всё зелёное: установка
  фиксируется (commit), бот перезапускается (`systemctl try-restart --no-block vpn-bot`) —
  `XRAY_*` он читает при старте. Прогон живёт в своём юните; отчёт отправляет новый процесс
  бота.
* **rollback** — журнал helper'а в обратном порядке (если упал verify, журнал в состоянии
  applied: всё, что поставлено, убирается).

Ни один шаг не меняет сетевую конфигурацию хоста: файрвол принадлежит
[`vpn-bot-ufw-apply`](host-state.ru.md). После успешного прогона бот перед отчётом
запускает `vpn-bot-ufw-apply apply` (протокол снова в наборе модулей — так же, как после
удаления) и пишет об этом в отчёте.

## Что показывает бот

* «⚙️ Модули протоколов»: протокол, который ставит helper, у которого не все пробы на месте
  (`/usr/local/bin/xray`, `/etc/systemd/system/xray.service`, `/usr/local/etc/xray/config.json`
  — `status` helper'а и `services/protocol_install.py` читают один и тот же список, тест держит
  их равными) и нет маркера удаления: **📦 <протокол>** с **📦 Установить**.
* Сообщение прогона: план, затем шаги с состоянием, затем отчёт (пункты verify, результат,
  строка UFW), «📄 Лог».

## Файлы

| Файл | |
|---|---|
| `scripts/vpn-bot-protocol-install` | root-helper |
| `scripts/wizard/vpn-bot-wizard-protocol` | режим мастера |
| `deploy/xray/xray.service`, `xray@.service`, `xray{,@}.service.d/10-donot_touch_single_conf.conf` | юниты upstream |
| `deploy/xray/config.skeleton.json` | форма конфига (и проверка дрейфа деплоя) |
| `deploy/nginx/selfsteal.conf` | шаблон vhost self-steal (`@DOMAIN@`, `@SITE_ROOT@`) |
| `deploy/site/default/` | сайт-приманка |
| `services/protocol_install.py`, `bot/handlers/admin_modules.py` | сторона бота |
