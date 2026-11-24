# Relay (ключи «через relay»)

**Relay** — второй вход на этот сервер: небольшой VPS (здесь — в России), который
форвардит клиентский трафик на L4 на основной сервер. Ключ «через relay» — обычный
ключ, ссылка которого указывает на relay вместо основного хоста. Relay может быть
**несколько**. Они живут в ОДНОЙ таблице (`relays` в `vpn.db`) и на ОДНОМ экране бота:
**🛡 Админ-панель → 🧩 Протоколы и маршрутизация → 🛰 Relay** (пункт «🛰 Relay» мастера настройки
открывает этот же экран). Пока в таблице нет ни одного relay, функция не видна.

**Одна модель.** Как управляется relay — свойство самого relay, а не отдельная сущность:

- **с агентом** — бот ходит к `vpn-relay-agent` на relay по SSH своим ключом и со страницы relay
  выполняет статус, обновление, смену портов/цели и снятие с хоста;
- **без агента** — relay, настроенный вручную (в том числе бывший из `RELAY_*` в `.env`). Он
  работает как прежде; на его странице есть **«🔗 Подключить агент (ключи не меняются)»** — агент
  подключается, а имя, хост, метка и ключи relay не меняются.

Новый relay добавляется [одной командой из бота](#установка-relay-одной-командой) —
**«➕ Добавить relay»** — единственный способ его создать.

## Топология

```
клиент ──TCP+UDP/443──▶ relay (RU VPS)
                          nftables DNAT tcp+udp dport 443 → <основной сервер>:443
                                         │
                                         ▼
                 основной сервер :443 ── xray vless-in (REALITY)
                                         ├─ XHTTP fallback → vless-xhttp-reality
                                         └─ (UDP) hysteria2
```

- Relay меняет только адрес назначения (DNAT) и маскарадит источник, поэтому
  основной сервер видит каждое подключение через relay как пришедшее с **egress-IP
  relay**. PROXY protocol нет — реальный адрес клиента до сервера не доходит.
- Клиент через relay попадает в **те же inbound'ы**, что и прямой: VLESS (TCP) и все
  профили VLESS (HTTP) на vless-in :443, Hysteria2 на UDP/443. На основном сервере
  про relay не знает ничего.
- Сам relay-хост (таблицы nftables, `ip_forward`, его systemd-unit) разворачивается **из
  этого репозитория** тем же `scripts/redeploy.sh` в роли хоста `NODE_ROLE=relay` — см.
  [Relay-хост](#relay-хост-node_rolerelay).

### DNS — указывайте имя, а не адрес

Заведите DNS-имя на relay — например, `relay.anycastedge.net` — в Cloudflare **без
проксирования** (DNS only, серое облако): HTTP-прокси Cloudflare не пропускает ни
REALITY, ни QUIC. Это имя и указывайте как **host** relay.

Это важно, потому что ссылка одиночного ключа содержит host как есть. Если host — имя,
переезд relay на новый IP — это смена A-записи, и переимпортировать ключи не нужно.
Если host — IPv4-адрес, его смена в панели сразу перенаправляет **подписки** (они
рендерятся на каждый запрос), но каждый **одиночный relay-ключ**, импортированный
пользователем ссылкой, хранит старый адрес и требует переимпорта — при смене host
панель показывает, сколько таких ключей.

## Relay-хост (`NODE_ROLE=relay`)

На relay-хосте работает **одно**: `vpn-relay.service` — oneshot-unit, который выполняет
`/usr/local/sbin/vpn-relay-apply apply`. Хелпер рендерит из `.env` relay две таблицы nftables —
`ip vpnrelay` (проброс) и `inet vpnrelay_input` ([входной фильтр](#входной-фильтр)), — применяет
обе **одной атомарной транзакцией `nft -f`** (для каждой: `table …` + `delete table …` + новая
таблица — nft применяет всё целиком или оставляет прежние таблицы как были) и затем выставляет
sysctl — `net.ipv4.ip_forward = 1` и два значения
conntrack из `.env` (см. [conntrack](#conntrack)) — в рантайме и в
`/etc/sysctl.d/90-vpn-relay.conf`.

Больше ничего из репозитория там не работает: ни `vpn-bot`, ни `vpn-bot-subscription`, ни
`hy2_auth`, ни БД, ни Xray, AmneziaWG, WARP, и **никакого Telegram** — тот же `BOT_TOKEN` на
втором хосте конфликтовал бы с основным ботом за `getUpdates`. `config/settings.py` не
загружается, у relay свой минимальный `.env`. В таблице проброса нет hook `input`/`output`
(закреплено тестами): входящее к самому relay — дело [входного фильтра](#входной-фильтр), а
`output` не цепляет никто.

Для портов по умолчанию таблица проброса ровно та, что работала на relay, собранном вручную
(входная таблица идёт за ней в том же файле, см. [ниже](#входной-фильтр)):

```
table ip vpnrelay
delete table ip vpnrelay
table ip vpnrelay {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "eth0" tcp dport 443 counter dnat to <upstream>:443
    iifname "eth0" udp dport 443 counter dnat to <upstream>:443
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eth0" ip daddr <upstream> ct status dnat counter masquerade
  }
  chain relayfwd {
    type filter hook forward priority filter; policy drop;
    tcp flags syn tcp option maxseg size set rt mtu
    ct state established,related accept
    ct status dnat ip daddr <upstream> accept
    counter
  }
}
```

Каждый пробрасываемый порт получает одно правило DNAT на **тот же** порт upstream; masquerade,
MSS clamp и forward-цепочка (policy drop, проходят только DNAT'нутые потоки и ответы на них)
от портов не зависят. Flowtable и прочий тюнинг не нужны: на relay с 1 vCPU 107 Мбит/с
форварда оставляли CPU простаивающим на 96–98 %.

### Входной фильтр

Входящее к **самому** relay по умолчанию отбрасывается — как UFW делает это на основном
сервере, но таблицей, которой владеет репозиторий: `table inet vpnrelay_input` (`inet`: sshd
слушает и IPv4, и IPv6), её применяет `vpn-relay-apply` в той же транзакции, что и
`ip vpnrelay`. На проходящий через relay трафик она не влияет: DNAT'нутые потоки идут через
hook forward и до `input` не доходят.

```
table inet vpnrelay_input {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    meta l4proto ipv6-icmp accept
    ip6 saddr fe80::/10 udp dport 546 accept comment "dhcpv6 client"
    tcp dport 22 accept comment "ssh"
    tcp dport { … } accept comment "RELAY_INPUT_EXTRA_TCP"
    udp dport { … } accept comment "RELAY_INPUT_EXTRA_UDP"
    counter
  }
}
```

- ICMPv6 проходит всегда (без него ломается NDP, а с ним и IPv6), как и DHCPv6-клиент (udp 546
  с link-local). Последний `counter` считает то, что отбрасывает политика.
- **Порты SSH не настраиваются.** Они берутся из `ss -Hltunp`: каждый TCP-listener на
  не-loopback адресе, принадлежащий `sshd` (или `sshd-session`), либо удерживаемый systemd на
  порту, который объявляет `ssh.socket` (`systemctl show -p Listen ssh.socket` — socket
  activation до первого запуска sshd). Перенесёте sshd на другой порт — следующий apply пойдёт
  за ним; поэтому [переезду SSH-порта](host-state.ru.md#ssh-порт) (`SSH_PORT`, по умолчанию 54321:
  relay, который ещё на 22, переезжает при следующем деплое) правила здесь не нужны: в фазе 1 ssh
  слушает 22 и 54321, и рестарт `vpn-relay` пускает оба (набор TCP изменился — его подтверждает
  проба с main, и это подтверждение 54321 и есть доказательство переезда); в фазе 2 22 уходит из
  `ssh.socket`, и следующий apply его отбрасывает. **Порт SSH не найден → не применяется ничего**: `no SSH port found — refusing to
  install a drop policy`, код `8`, ни одна таблица не меняется. Unit упорядочен
  `After=ssh.socket ssh.service`, поэтому при загрузке sshd слушает раньше, чем apply смотрит.
- Правила записаны ровно так, как их печатает `nft list` (один порт — без фигурных скобок),
  поэтому `check` сравнивает живую таблицу с рендером напрямую.
- **UFW на relay остаётся masked** — никогда не делайте там `ufw enable`: forward-цепочка UFW
  (policy DROP) — отдельная базовая цепочка на том же hook, и она режет проброс 443 независимо
  от `table ip vpnrelay`. Это держит host check: `ufw.service` `UnitFileState=masked` — инвариант
  relay (`deploy/host/invariants.list`), иначе MISMATCH, фатальный в Phase 1 деплоя.
- `RELAY_INPUT_FILTER=off` удаляет таблицу той же транзакцией; INPUT ничем не фильтруется, и
  `check` ждёт, что таблицы нет.

#### Как не потерять доступ: dead-man и `input-confirm`

Консоль не нужна никогда. Набор TCP-портов, который пропускает фильтр (порты SSH плюс
`RELAY_INPUT_EXTRA_TCP`), хешируется; в `/etc/vpn-relay/input.confirmed` лежит хеш последнего
подтверждённого набора.

- **Первое включение и любая смена этого набора** (новый extra-порт TCP, sshd на другом
  порту): `apply` сначала ставит dead-man,
  `systemd-run --on-active=300 --unit=vpn-relay-input-deadman vpn-relay-apply input-off`, и
  только потом применяет таблицы. Если dead-man не ставится — не применяется ничего (код `9`).
- **Подтверждает основной сервер** ([ниже](#main-подтверждает-фильтр-post-relayssh-probe)):
  сразу после такого apply relay просит main подключиться к его портам SSH снаружи. Если
  отвечают все, фильтр подтверждается ровно так, как это сделал бы `input-confirm`, и деплой
  заканчивается строкой

  ```
  input filter     : CONFIRMED by main probe (tcp 22; 2026-11-12 10:00:05 UTC)
  ```

  и делать ничего не нужно. Если main подтвердить не смог, деплой заканчивается строкой

  ```
  input filter     : PENDING CONFIRM (reverts at 2026-11-12 10:05:00 UTC) — main probe did not confirm it: <причина>
  ```

  вместо `OK` и инструкцией под ней.
- **Бот подтверждает сам** на relay с агентом: каждый вызов агента — НОВАЯ ssh-сессия бота (в
  режиме фолбэка — через hub, [ниже](#управление-ru-relay-через-hub)), поэтому, когда `status`
  показывает `PENDING CONFIRM`, бот отправляет `input-confirm`, и агент запускает
  `vpn-relay-apply input-confirm` внутри этой сессии (её проверка «сессия началась после apply»
  и есть доказательство; в маркере — `confirmed_by=ssh-session`). Это происходит сразу после
  «⬆️ Обновить агент», в цикле health и по кнопке «🛡 Подтвердить входной фильтр» на странице
  relay. Проба main тогда не нужна.
- **Или вручную: откройте НОВУЮ ssh-сессию** к relay и в течение 5 минут выполните
  `vpn-relay-apply input-confirm`: таймер останавливается, маркер с хешем записывается. Если
  нет ни того, ни другого, таймер запустит `input-off`: снимется только
  `table inet vpnrelay_input` (проброс не трогается), причина уйдёт в журнал
  (`journalctl -u vpn-relay-input-deadman`, или `-t vpn-relay-apply` при ручном запуске), и
  relay будет доступен ровно как раньше. Повторите деплой и подтвердите вовремя.
- **Сессия, из которой шёл деплой, ничего не доказывает**: она едет по established-соединению,
  которое фильтр пропускает всегда. `input-confirm` проверяет, что его собственная ssh-сессия
  (ближайший предок-`sshd` команды) началась после применения фильтра, и иначе отказывает — в
  том числе с консоли или из tmux/screen, запущенного раньше. Запускайте прямо в новой сессии;
  `ssh root@<relay> vpn-relay-apply input-confirm` со своей машины — тоже новая сессия.
- **Тот же набор, что в маркере → ни dead-man, ни подтверждения**: обычный деплой остаётся
  полностью автоматическим. UDP-порты подтверждения не требуют никогда (SSH они стоить не могут).
- При загрузке `vpn-relay.service` применяет обе таблицы: подтверждённому набору ничего не
  нужно, неподтверждённый снова ставит dead-man.
- `vpn-relay-apply input-status` печатает состояние одной строкой — `OK (tcp 22; confirmed … by
  ssh-session|main-probe)`, `CONFIRMED by main probe (tcp 22; …)` (сразу после apply, чья проба
  его подтвердила), `PENDING CONFIRM (reverts at …) — <почему main не подтвердил>`,
  `ABSENT — the dead-man removed it at …`, `off (RELAY_INPUT_FILTER=off)`; DEPLOY OK печатает её
  как `input filter`. В маркере записано, кто подтвердил: `confirmed_by=ssh-session` или
  `main-probe`. Если проба main не запустилась или main не ответил, строка PENDING говорит
  причину простыми словами (`no answer in time: main is not reachable from this relay (blocked
  on the way? the fallback mode)`, `the connection to main was cut`, 404, который покрывает и
  запрос через hub, …; `main probe: no result for this TCP set`, если результата нет) и что
  остаётся: новая ssh-сессия — бота (сам или по кнопке на странице) или ваша.

#### Main подтверждает фильтр: `POST /relay/ssh-probe`

`input-confirm` доказывает, что **новое** TCP-соединение снаружи проходит через фильтр к порту
SSH. То же может доказать основной сервер — и тогда деплою relay не нужна и ssh-сессия:

1. После `apply`, оставившего фильтр в PENDING (dead-man взведён, таблицы и sysctl на месте),
   relay отправляет POST со своими портами SSH — JSON-массив, например `[22]` — на endpoint
   подписки main, `RELAY_CONFIRM_URL` (по умолчанию `https://<RELAY_CHECK_SNI>:2096/relay/ssh-probe`).
   curl проверяет сертификат, не использует прокси, не следует редиректам и всегда соединяется
   с `RELAY_UPSTREAM_IPV4` (`--resolve`): запрос не уходит никуда, кроме основного сервера.
2. Main отвечает только вызывающему, чей адрес входит в **source IPs включённого relay** в
   админ-панели (таблица `relays` читается вживую); всем остальным, а также на любой запрос при
   `SUBSCRIPTION_ENABLED=false` — обычный пустой `404` этого endpoint'а. Тело, в котором не 1–4
   разных порта из 1..65535, — `400`. Затем main делает TCP connect обратно **на адрес самого
   вызывающего** — никогда на адрес из запроса — к каждому порту, параллельно, по 5 с, и отвечает
   `{"22":"ok"}` (или `"fail"`). У него свой rate limit (6 запросов в минуту на адрес, до проверки
   relay), в лог — имя relay и вердикты, ничего больше.
3. **Все порты SSH `ok`** → relay подтверждает фильтр тем же путём, что и `input-confirm`
   (dead-man остановлен, маркер записан с `confirmed_by=main-probe`). **Всё остальное** — нет URL,
   нет `curl`, main недоступен (один повтор), `404`, порт с `fail`, больше 4 портов SSH, порт SSH,
   который ещё и пробрасывается (main попал бы через DNAT сам в себя), — оставляет фильтр в
   PENDING с причиной в `input-status` и в DEPLOY OK; dead-man откатит его, если не придёт
   `input-confirm`, который работает ровно как раньше. Проба никогда не роняет `apply`.

Что для этого нужно:

- **На main**: endpoint подписки опубликован (`SUBSCRIPTION_ENABLED=true`,
  `SUBSCRIPTION_PUBLIC_PORT`, TLS — [docs/subscription.ru.md](subscription.ru.md)), и relay
  **добавлен в админ-панели, включён, а адрес, с которого он ходит на main, есть в его source IPs**
  — до первого деплоя relay.
- **На relay**: `curl` и URL — `RELAY_CHECK_SNI` для умолчания
  (`https://<RELAY_CHECK_SNI>:2096/relay/ssh-probe`: на main, у которого `XRAY_SNI` — его
  собственный домен, как с self-steal decoy, это домен и порт подписки) или
  `RELAY_CONFIRM_URL=https://<домен подписки>[:<порт>]` (путь по умолчанию `/relay/ssh-probe`).
  `RELAY_CONFIRM_URL=off` выключает пробу: только ручное подтверждение.

Неудачная проба с URL по умолчанию так и говорит (`… set RELAY_CONFIRM_URL`): сертификат, не
подходящий к `RELAY_CHECK_SNI`, или пустой `:2096` значат, что подписка живёт в другом месте.

#### Как открыть порт

Для сервиса на самом relay, который должен быть доступен снаружи (скажем, exporter на 9100):

1. `RELAY_INPUT_EXTRA_TCP=9100` (или `RELAY_INPUT_EXTRA_UDP=…`) в `/opt/vpn-service/.env`;
2. `sudo FORCE=1 bash scripts/redeploy.sh` — новый TCP-порт меняет набор: ставится dead-man, и
   его подтверждает проба main (DEPLOY OK: `CONFIRMED by main probe`);
3. только если DEPLOY OK говорит PENDING CONFIRM: в НОВОЙ ssh-сессии
   `vpn-relay-apply input-confirm`.

Порт, который слушает на публичном адресе, но фильтром **не** пропускается, — ошибка `check`
(код `18`, `tcp/9100 listening but filtered: …`), а каждый деплой заканчивается `check`, так что
новый сервис никогда не окажется молча мёртвым за политикой drop. Откройте его, как выше,
привяжите к loopback или — если снаружи он должен оставаться закрытым — объявите это:
`RELAY_INPUT_CLOSED_TCP=9100` (`RELAY_INPUT_CLOSED_UDP` для UDP). Listener'ы на loopback и
DHCPv6-клиент не оцениваются.

### `.env` relay

`/opt/vpn-service/.env` из [`deploy/relay/relay.env.example`](../deploy/relay/relay.env.example).
Читается тем же sed-парсером, которым `deploy.sh` читает `NODE_ROLE` (а fwmark-хелпер
Hysteria2 — `HYSTERIA2_PORT`): необязательный `export`, пробелы вокруг `=`, кавычки,
комментарии `# …` в конце строки, побеждает **последнее** присваивание, пустое значение
равно отсутствующему.

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `NODE_ROLE` | `main` | `relay` на relay-хосте. Любое другое значение отвергается до каких-либо изменений. |
| `SSH_PORT` | `54321` | Порт, на котором слушает ssh — [SSH-порт](host-state.ru.md#ssh-порт). Деплой переводит ssh туда в две фазы (оба порта, затем — когда это доказали проба с main или подключение извне в журнале sshd — только новый), без `ALLOW_SSH_CHANGE`. Не может быть пробрасываемым, extra или closed TCP-портом (отказ). |
| `RELAY_UPSTREAM_IPV4` | — | IPv4 основного сервера; или |
| `RELAY_UPSTREAM_HOST` | — | его DNS-имя (ровно одна из двух; установщик пишет эту) — [DNS-имя как upstream](#dns-имя-как-upstream). |
| `RELAY_FORWARD_TCP_PORTS` | `443` | Через запятую, 1..65535; каждый пробрасывается 1:1. |
| `RELAY_FORWARD_UDP_PORTS` | `443` | То же для UDP (Hysteria2). |
| `RELAY_WAN_IFACE` | интерфейс IPv4 default route | WAN-интерфейс правил DNAT/masquerade. Без неё хелпер отказывает, если default route нет или он уходит через несколько интерфейсов. |
| `RELAY_CHECK_SNI` | — | Если задана (и 443 пробрасывается), `vpn-relay-apply check` дополнительно делает TLS-handshake к upstream с этим SNI и **проверяет сертификат**. Укажите `XRAY_SNI` основного сервера: REALITY отдаёт незнакомого клиента своему decoy, чей сертификат валиден для этого имени. |
| `RELAY_CONNTRACK_MAX` | `65536` | `net.netfilter.nf_conntrack_max`, целое 8192..1048576. Каждый проходящий через relay поток — одна запись conntrack; когда таблица заполнена, ядро отбрасывает новые потоки. |
| `RELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT` | `86400` | `net.netfilter.nf_conntrack_tcp_timeout_established`, секунды, 300..432000 (по умолчанию в ядре 432000 = 5 суток). |
| `RELAY_INPUT_FILTER` | `on` | `on`: [входной фильтр](#входной-фильтр) (политика drop). `off`: `table inet vpnrelay_input` нет, INPUT не фильтруется. |
| `RELAY_INPUT_EXTRA_TCP` | — | TCP-порты через запятую, которые входной фильтр пропускает помимо SSH. Изменение снова требует `input-confirm`. |
| `RELAY_INPUT_EXTRA_UDP` | — | То же для UDP (без подтверждения). |
| `RELAY_INPUT_CLOSED_TCP`, `RELAY_INPUT_CLOSED_UDP` | — | Порты, которые слушают на публичном адресе, но снаружи должны оставаться закрытыми: `check` не называет их «listening but filtered». Порт не может быть одновременно extra и closed; порт SSH закрыть нельзя. |
| `RELAY_CONFIRM_URL` | `https://<RELAY_CHECK_SNI>:2096/relay/ssh-probe`; без `RELAY_CHECK_SNI` — нет | Куда `apply` обращается к main, чтобы [подтвердить ожидающий фильтр](#main-подтверждает-фильтр-post-relayssh-probe): `https://<DNS-имя>[:<порт>][/<путь>]` (без пути — `/relay/ssh-probe`; адрес, `http`, query или userinfo отклоняются), всегда на `RELAY_UPSTREAM_IPV4`. `off` — без пробы. |

Значение вне диапазона, со знаком, единицей измерения или ведущим нулём отвергается с кодом
`3` до каких-либо изменений — так же, как неверный порт.

### `vpn-relay-apply`

| Команда | Что делает |
|---|---|
| `apply` | Рендер + атомарное применение обеих таблиц (если набор TCP-портов входного фильтра не подтверждён — сначала dead-man), затем sysctl-файл и три значения в рантайме (сначала conntrack, `ip_forward=1` последним); для неподтверждённого набора последней — [проба main](#main-подтверждает-фильтр-post-relayssh-probe). Это запускает unit. |
| `check` | Только чтение: обе живые таблицы совпадают с рендером (счётчики не сравниваются; при расхождении печатается diff), каждый порт, слушающий на публичном адресе, пропущен фильтром или объявлен закрытым, `ip_forward=1`, оба значения conntrack равны `.env`, TCP-connect к upstream на **каждый** пробрасываемый TCP-порт и TLS-handshake, если задан `RELAY_CHECK_SNI`. Ожидающее подтверждение показывается, а не считается ошибкой; таблица conntrack, заполненная больше чем на 80 %, — предупреждение. Им заканчивается каждый деплой. |
| `check --dry-run` | Проверить `.env`, найти порты SSH и отрендерить; сказать, подтверждён ли набор TCP-портов и какой URL возьмёт проба main; под root ещё `nft -c` (проверка синтаксиса, ничего не применяется). Это запускает Phase 1 деплоя из checkout. |
| `show` | Напечатать отрендеренный ruleset. |
| `input-confirm` | Оставить входной фильтр: из НОВОЙ ssh-сессии, пока взведён dead-man. Останавливает таймер, пишет `/etc/vpn-relay/input.confirmed` (`confirmed_by=ssh-session`) — тот же путь, что у пробы main. |
| `input-off` | Снять только `table inet vpnrelay_input`, причину — в журнал. Это запускает dead-man; вручную — до следующего apply. |
| `input-status` | Состояние входного фильтра одной строкой (его печатает DEPLOY OK). |
| `resolve` | Только с `RELAY_UPSTREAM_HOST`: резолвит заново и применяет, если текущая цель DNAT больше не среди его адресов (его раз в 5 минут запускает `vpn-relay-resolve.timer`). |

Коды выхода: `0` ok · `2` использование · `3` неверное/отсутствующее значение в `.env` · `4`
не определён WAN-интерфейс · `5` не root / нет утилиты · `6` nft отверг ruleset (живые таблицы
не изменились) · `7` не удалось записать sysctl-файл или выставить sysctl (в том числе
`nf_conntrack_max` так и нет после `modprobe nf_conntrack`) · `8` порт SSH не найден — ничего не
применено · `9` dead-man не ставится — ничего не применено · `10` таблицы нет · `11` живая
таблица отличается от рендера · `12` ip_forward не равен 1 · `13` upstream не отвечает на
пробрасываемом TCP-порту · `14` TLS-handshake не прошёл · `15` значение conntrack отличается от
`.env` · `16` `table inet vpnrelay_input` нет, хотя `RELAY_INPUT_FILTER=on` (например, её снял
dead-man), или она есть, хотя `off` · `17` входная таблица отличается от рендера · `18` порт
слушает, но закрыт фильтром · `19` `input-confirm` отказал (нечего подтверждать, поздно или не
новая ssh-сессия) · `20` `RELAY_UPSTREAM_HOST` не резолвится и для него нет последнего
известного адреса (apply/check), или `resolve` не смог его разрешить (живая таблица остаётся). `check` проверяет по порядку таблицу → входную таблицу → слушающие порты →
ip_forward → conntrack → TCP → TLS, сообщает обо всех сбоях и выходит с кодом первого.

### conntrack

Каждый поток через relay (каждое VLESS-соединение, каждый UDP-поток Hysteria2) — запись в
таблице conntrack ядра: в ней живут DNAT и masquerade. Когда таблица заполнена, ядро
отбрасывает **новые** потоки (`nf_conntrack: table full, dropping packet` в `dmesg`), поэтому
relay сам выставляет лимит, а не полагается на значение ядра по умолчанию, и сокращает
5-суточный таймаут установленных TCP-записей, из-за которого иначе висят записи клиентов,
пропавших без FIN.

`apply` рендерит `/etc/sysctl.d/90-vpn-relay.conf` целиком:

```
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = <RELAY_CONNTRACK_MAX>
net.netfilter.nf_conntrack_tcp_timeout_established = <RELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT>
```

и выставляет те же значения через `sysctl -w` **после** `nft -f`, перечитывая каждое. Одного
файла недостаточно: при загрузке `systemd-sysctl` применяет его рано, **до загрузки модуля
nf_conntrack** — модуль загружают ct/nat-выражения таблицы, то есть `nft -f` в `apply`, — поэтому
ключей `net.netfilter.*` ещё нет, и он их пропускает (строка `Couldn't write … ignoring` про них в
его журнале ожидаема). Поэтому `apply` выставляет их при каждом старте `vpn-relay.service`. Если
после `nft -f` ключа `net.netfilter.nf_conntrack_max` всё ещё нет, `apply` выполняет `modprobe
nf_conntrack` и пробует снова; если не помогло — выходит с кодом `7`.

`check` берёт заполненность из sysctl `net.netfilter.nf_conntrack_count` (не из
`/proc/net/stat/nf_conntrack` — на ядре 6.8 relay его нет) и печатает `WARNING`, если она выше
80 % от `nf_conntrack_max`; тогда увеличьте `RELAY_CONNTRACK_MAX`.

Relay, развёрнутый до появления этих ключей, работает со значениями ядра, поэтому первый деплой,
который их приносит, показывает в live check Phase 1 код `15` («the table and ip_forward match;
the conntrack sysctls differ») вместо PASS; Phase 2 их выставляет. Откат возвращает значения,
которые были в рантайме до деплоя.

### Что делает `scripts/redeploy.sh` на relay

Те же команды, что на основном сервере; `deploy.sh` читает `NODE_ROLE` и отказывает хосту,
сервисы которого противоречат роли (роль `relay`, а активен `vpn-bot` или `xray`; роль `main`,
а активен `vpn-relay` и unit'а `vpn-bot` нет вовсе).

- **Phase 1** (только чтение; `CHECK=1` на ней останавливается и печатает отчёт): fetch
  `origin/main` и тегов, выбор [ревизии для деплоя](#какую-ревизию-деплоит-relay) — по умолчанию
  самый новый релиз, только вперёд — и передача управления `deploy.sh` ЭТОЙ ревизии; на ней тот же
  гейт ruff / compileall / pytest, что и на основном сервере (тестовый venv собирается в `/var/lib/vpn-bot-deploy/`, поэтому relay нужен
  `python3-venv` — если `ensurepip` нет, `deploy.sh` сам ставит `python3.X-venv`
  ([deployment.ru.md](deployment.ru.md#ensurepip)) — и ~1 ГиБ свободного места; полностью зелёный
  `CHECK=1` позволяет деплою сразу после него не гонять тесты:
  [отметка Phase 1](deployment.ru.md#отметка-phase-1)), `vpn-relay-apply check --dry-run` из checkout,
  исходное состояние relay (включая `nf_conntrack_max` и
  `nf_conntrack_tcp_timeout_established` в рантайме), сравнение каждого unit'а
  [набора relay](#какие-unitы-ставит-деплой-relay) с его копией в `deploy/relay/` (`absent`,
  `synced`, `differs`; `legacy` — для собранного вручную `vpn-relay.service`) и `check` из checkout против живого relay — на relay, где
  ещё работает ruleset, собранный вручную, `ok: table ip vpnrelay matches` здесь доказывает,
  что репозиторий воспроизводит его 1:1 (код `16`, пока нет [входного фильтра](#входной-фильтр),
  `15`, пока не выставлены значения [conntrack](#conntrack), PASS — после обоих). Dry-run
  называет найденные порты SSH и говорит, подтверждён ли набор TCP-портов входного фильтра, то
  есть поставит ли Phase 2 dead-man, и URL пробы main, которая его подтвердит; порт, который
  слушает, но был бы закрыт фильтром, отмечается отдельно: `check` в Phase 2 откатил бы деплой.
- **Phase 2**: бэкап живых `nft list table ip vpnrelay` и `nft list table inet vpnrelay_input`,
  установленных хелперов (`vpn-relay-apply`, агент, …), каждого unit'а набора, sysctl-файла и маркера подтверждения
  `/etc/vpn-relay/input.confirmed` (`/var/backups/vpn-bot/backup-relay-<sha>-<ts>.tar.gz`; ради бэкапа ничего не
  останавливается); `git checkout -f --detach <цель>` (checkout relay стоит detached на своём
  релизе — локальная ветка, на которой он был, остаётся на месте); установка хелперов через
  `OUT_OF_REPO_HELPERS` (роль `relay`) и каждого unit'а набора как есть (копия, которая уже
  совпадает, не переписывается); `daemon-reload`, `enable` `vpn-relay` и каждого таймера,
  `reload-or-restart vpn-relay` (работающий relay **перезагружается**: `ExecReload` — тот же
  атомарный apply, без `ExecStop` перед ним, поэтому нет момента без DNAT — так всегда делал
  установщик; неработающий relay запускается; неподтверждённый набор здесь же подтверждает проба
  main), `start` таймера, который не активен;
  проверка `vpn-relay-apply check` и **ровно одного DNAT на каждый проброшенный порт во всём
  ruleset** (второй в другой таблице — например, из `/etc/nftables.conf` при загрузке — конкурировал
  бы с relay; установщик проверял это всегда). **Upstream, который не отвечал и до деплоя, его
  не откатывает**: если единственные провалы `check` в verify — пробы upstream (`FAIL: TCP connect …`
  / `FAIL: TLS handshake …`, exit 13/14 — таблицы, входной фильтр и sysctl прошли) и каждый из них
  был среди провалов проверки живого relay в Phase 1 (тот же адрес и порты), деплой — DEPLOY OK с
  `WARN` `upstream unreachable before and after (pre-existing)` и маркером
  `[deploy:warn upstream_preexisting]`: main, заблокированный на пути relay (ТСПУ), деплой ни вызвать,
  ни исправить не может. Любой другой провал, upstream, который до деплоя отвечал, или другой адрес
  или порт, чем видел Phase 1, откатывают как всегда (`reason=upstream` — если дело в upstream).
  Вердикт читается по строкам FAIL, как `only_input_filter_failures` агента: `check` выходит с кодом
  только ПЕРВОГО провала. Вокруг файлов хоста двигается [SSH-порт](host-state.ru.md#ssh-порт),
  когда этого требует `SSH_PORT` (фаза 1: оба порта; reload `vpn-relay` пускает их, проба с main
  их подтверждает); сразу после DEPLOY OK `vpn-bot-ssh-port.service` один раз ищет доказательство —
  если проба с main прошла, relay заканчивает переезд в том же прогоне; если нет (режим фолбэка,
  заблокированный порт), бот просит суперадмина подтвердить закрытие старого порта и доказывает
  новый собственным вызовом агента на нём, без redeploy
  ([host-state.ru.md](host-state.ru.md#переезд-relay-из-бота)).
  В DEPLOY OK есть `ssh port: …` и `input filter : …` из
  `vpn-relay-apply input-status` — `CONFIRMED by main probe (…)`, и делать ничего не нужно, или
  `PENDING CONFIRM (…) — <причина>`, за которым идут причина и инструкция выполнить
  `input-confirm` из НОВОЙ ssh-сессии в течение 5 минут.
- **Любой сбой** откатывает: прежний checkout (`PREV_SHA`, detached), хелперы, unit'ы и sysctl-файл (или их отсутствие),
  сохранённая таблица проброса применяется заново одной транзакцией, входной фильтр — как был:
  подтверждённый восстанавливается из дампа, отсутствовавший снимается, ждавший `input-confirm`
  тоже снимается (восстановленный, он мог бы пережить свой dead-man; снять — безопасное
  направление), маркер подтверждения — как был (подтверждение, которое проба main записала во
  время рестарта, относится к набору, которого больше нет в живых), а dead-man, поставленный
  деплоем, останавливается; восстанавливаются enabled/active
  каждого unit'а (unit, которого до деплоя не было, останавливается, выключается и удаляется;
  таймер, который до деплоя не был активен / включён, снова останавливается / выключается;
  отчёт об откате перечисляет каждый unit), прежний `ip_forward` и прежние значения conntrack в рантайме (каждое перечитывается;
  значение, которое до деплоя не читалось — nf_conntrack не был загружен, — остаётся таким, как
  его выставил `apply`). Деплой выходит с ненулевым кодом и отчётом об откате.
- Unit, установленный вручную и загружающий `/etc/vpn-relay.nft`, — **ожидаемый первый
  переход**, а не drift. После первого успешного деплоя `/etc/vpn-relay.nft` переименовывается
  в `/etc/vpn-relay.nft.pre-repo.<ts>` (не удаляется) и больше никем не читается.

#### Прогресс «Обновить агент»

**Одно сообщение, одно подтверждение.** «⬆️ Обновить агент» правит ЭТО же сообщение: шаги деплоя ⚪
(preflight, fetch, тесты, проверки, бэкап, установка, рестарт, verify) с «✅ Подтвердить» / «✖️ Отмена».
Если нужен TOTP, код спрашивается в этом же сообщении и он и есть подтверждение — второго шага и
«▶️ Продолжить» нет (`require_totp_in_place`, bot/totp_gate.py). Пока обновление идёт, под сообщением
только «📄 Лог» (`update-log` агента 5: конец деплой-лога файлом; агент старше — путь к логу на relay);
повторное нажатие «Обновить» отвечает «уже идёт, запуск #N» и ничего не меняет. По завершении —
итог, «📄 Лог» и «Назад» (для [чужого sshd-override](#чужой-sshd-override) — ещё его кнопка).

Затем исполнение: долгий вызов `update`, а
рядом, раз в 10 с, **`update-status`** — лёгкий запрос агента без блокировки, отвечающий
`/var/lib/vpn-relay/update.json`, куда агент не чаще раза в 2 с пишет прогресс деплоя, пока читает
его вывод (`deploy_progress`: шаги по [маркерам](deployment.ru.md#маркеры-шагов-и-результата)
deploy.sh и тесты — пройдено из `[deploy:tests total=N]`). Между опросами строка активности
крутится локально. Почему файл состояния и опрос, а не поток: агент отвечает ОДНИМ JSON на вызов,
его канал `update` занят `systemd-run --wait`; файл переживает обрыв ssh (и хоп через hub) и стоит
одну короткую ssh-сессию на опрос. Итог закрывает шаги — ✅ или ❌ на шаге, где deploy.sh упал, с
причиной.

- **Ответ опроса, пришедший после конца обновления, отбрасывается.** Опросчик останавливается до
  того, как итог расставит финальные состояния, а итог рисуется, не дожидаясь опроса «в полёте»
  (его ssh-вызов завершится сам). До v3.2.1 включительно такой поздний ответ «running» возвращал «🔄 тесты — N/M»
  поверх ✅ — нестабильный тест Phase 1 на he2 (1 vCPU) и был этой гонкой.
- **Агент без `update-status`** (AGENT_VERSION меньше 3, т. е. релиз до v3.2.1 — версия из последнего
  `status` или его «not an agent command» на первый опрос) не получает неподвижного списка шагов:
  ОДНА строка «агент v3.2.0 — прогресс по шагам появится после этого обновления» и строка
  активности; дальше его не опрашивают.
- **Шаг ошибки** — `step` итога ([строка результата](deployment.ru.md#маркеры-шагов-и-результата)
  deploy.sh); агент старше маркеров отдаёт только однострочное сообщение, и шаг читается из него:
  строка `[deploy:result failed step=…]`, иначе причина, которую называет текст
  (`Phase 1 gate: pytest/ruff/compileall failed` → тесты, откат → «проверка после рестарта», …),
  через ОДНУ таблицу — `REASON_STEPS` в services/deploy_result.py, обратную `deploy_fail_reason`
  из deploy.sh (тест прогоняет эту функцию для каждого шага). Ничто не называет шаг — ❌ ни на
  одном шаге и «шаг неизвестен», никогда не догадка на первый шаг (на he2 ❌ стоял на «проверки
  перед деплоем», хотя упал pytest).
- **Остановка до изменений** («stopped before any change … — nothing was changed»): шаг и причину
  даёт таблица «текст итога → шаг» — `TEXT_STEPS` в services/deploy_result.py: собственные слова
  deploy.sh с шагом, на котором он умирает (`host invariants:` → проверки, `NODE_ROLE` → preflight,
  цель релиза relay → fetch, test venv → тесты, бэкап → бэкап, …). Тест перебирает КАЖДОЕ «nothing
  was changed» из deploy.sh и сверяет его шаг — новое сообщение без строки в таблице роняет тест.
  he2 (агент v3.2.0): «host invariants: 2 fatal finding(s)» показывалось с «шаг неизвестен» — теперь
  «проверки».
- **Находки проверки хоста** в итоге: ключ, файл:строка, что победило что
  («passwordauthentication: 00-password-login.conf:1 = yes побеждает значение репо no из
  00-vpnrelay-keyonly.conf»). Агент 5 отдаёт их полем `findings` (блок DEPLOY VERDICT читает строки
  `FAIL BEATEN …` вывода деплоя); агенту старше их приносит сам текст: deploy.sh дописывает находки в
  свою строку отказа («… — nothing was changed. Fatal: BEATEN sshd passwordauthentication: …»), а её
  агент передаёт как есть.

#### Какую ревизию деплоит relay

Relay следует за **релизами**, и движок обновления у него ОДИН — этот деплой. `sudo bash
scripts/redeploy.sh` на relay и «⬆️ Обновить агент» в боте ([`update`](#агент-vpn-relay-agent)
агента) оба заканчиваются в `deploy.sh` и выбирают одну и ту же ревизию:

- **по умолчанию** — самый новый тег релиза: `vMAJOR.MINOR[.PATCH[.BUILD]]`, сравнение как чисел
  (`v1.10.0` новее `v1.9.0`). Всё прочее — не релиз: `v.3.1.0` (тег-опечатка в репозитории),
  `v3.2.0-rc1`, `v3`. Правило записано дважды — `relay_latest_release` в `deploy.sh`,
  `latest_release` в агенте, — и `tests/test_relay_release_tag.py` прогоняет оба на одних и тех же
  тегах, так что разойтись они не могут.
- **`DEPLOY_REF=main`** — `origin/main`; **`DEPLOY_REF=<тег>`** или **`DEPLOY_REF=<sha коммита>`**
  — этот коммит. На основном сервере `DEPLOY_REF` отклоняется, если это не `main`: main всегда
  деплоит `origin/main` на локальную `main`.

И только **вперёд**:

| Checkout | Деплой |
|---|---|
| позади цели (её предок) | деплоит её; checkout оказывается **detached** на цели, откат возвращает `PREV_SHA` тоже detached |
| на цели | `nothing to deploy` (`FORCE=1` деплоит заново, `CHECK=1` проверяет) |
| впереди цели | `INFO: … is ahead of latest release vX.Y.Z … nothing to deploy; DEPLOY_REF=main to follow main` — выход 0, relay никогда не откатывается назад |
| на другой линии истории | отказ до любых изменений («never moves sideways») |

Detached на теге релиза или впереди него — нормальное состояние relay: Phase 1 сообщает, где дерево
и куда оно пойдёт (`tree : … -> latest release vX.Y.Z (…), detached`), без WARN.

Работает **собственный** `deploy.sh` цели: `redeploy.sh` (сам — копия из `origin/main`: чекаут
relay на теге релиза обычно от неё отличается, и после fetch обёртка переисполняет себя этой
копией, см. [docs/operations.ru.md](operations.ru.md#какая-копия-redeploysh-работает)) запускает
`deploy.sh` из `origin/main`, тот выбирает цель и передаёт управление (`exec`) `deploy.sh` этой
ревизии — relay, который деплоит более
старый релиз, не должен прогонять более новый код реестров против более старого дерева. Цель,
`deploy.sh` которой старше деплоя relay по релизам, отклоняется (она задеплоила бы `origin/main`);
`DEPLOY_REF=main` деплоит main.

Relay, задеплоенный раньше из `main` — на 2026-11-16 это ru1 на `1a87f67`, тогда как самый новый
релиз `v3.1.0` старше, — при обычном запуске остаётся на месте (строка INFO выше); за релизами он
снова пойдёт, когда появится релиз новее его коммита. Чтобы до тех пор держать его на main (этот
же запуск ставит агента, который обновляет через `deploy.sh`), запускайте `redeploy.sh` **из
`origin/main`** с `DEPLOY_REF=main`, а не копию из чекаута: копия на `1a87f67` старше и проброса
`DEPLOY_REF`, и переисполнения, поэтому `sudo DEPLOY_REF=main bash scripts/redeploy.sh` там
печатает `deploy.sh env: <none>`, и переменная до `deploy.sh` не доходит (замерено 2026-11-16):

```bash
sudo git -C /opt/vpn-service fetch origin main
```

```bash
sudo git -C /opt/vpn-service show origin/main:scripts/redeploy.sh | sudo tee /root/redeploy-main.sh > /dev/null
```

```bash
sudo CHECK=1 DEPLOY_REF=main bash /root/redeploy-main.sh
```

```bash
sudo DEPLOY_REF=main bash /root/redeploy-main.sh
```

В строке `deploy.sh env:` должно быть `DEPLOY_REF=main` (`PHASE1_ONLY=1 DEPLOY_REF=main` для
запуска с `CHECK=1`). Когда relay уже на main, `scripts/redeploy.sh` сам переисполняет себя копией
из `origin/main`.

#### Какие unit'ы ставит деплой relay

Набор unit'ов relay — **все `deploy/relay/*.service` и `*.timer`** (файл `*.example.*` — не
unit). Это одно правило (`relay_unit_names`), дословно одинаковое в `scripts/deploy.sh`,
`scripts/install.sh --relay` и `scripts/vpn-bot-host-check`: деплой ставит ровно то, что ставит
установщик и ждёт проверка хоста, — и никакого захардкоженного списка
(`tests/test_deploy_relay_units.py` держит все три вместе). Сейчас:

| Unit | Phase 2 |
|---|---|
| `vpn-relay.service` | ставится как есть, включается, перезагружается, если работает, — запускается, если нет (`systemctl reload-or-restart`: `vpn-relay-apply apply` без остановки между) |
| `vpn-relay-resolve.timer` | ставится как есть, включается, запускается, если не активен |
| `vpn-relay-resolve.service` | только ставится как есть — его запускает таймер; деплой его не запускает никогда |

Unit, установленная копия которого уже совпадает, не переписывается: повторный деплой
показывает каждый unit как `synced` и ни один не меняет. Гейтом остаётся проверка
[host invariants](host-state.ru.md#эффективное-состояние) после установки: отсутствующий unit
набора, unit, загруженный не из `/etc/systemd/system/`, или таймер, который не enabled + active, —
это MISMATCH и откат деплоя. С `RELAY_UPSTREAM_IPV4` (адрес, а не
[имя](#dns-имя-как-upstream)) таймер всё равно стоит и активен: `vpn-relay-apply resolve` тогда
пишет `no RELAY_UPSTREAM_HOST (the upstream is an address) — nothing to do`, выходит с кодом 0 и
ничего не трогает. Relay, развёрнутый до того, как деплой начал ставить resolve-unit'ы (на нём
только `vpn-relay.service`), получает их при следующем деплое — раньше проверка хоста из-за них
откатывала этот деплой.

### Новый relay с нуля

На relay (Ubuntu 24.04, root по SSH-ключу):

```bash
apt-get update && apt-get install -y git python3-venv nftables
```

UFW на relay должен оставаться выключенным ([почему](#входной-фильтр)) — замаскируйте его
(работает и с пакетом, и без; host check отказывает relay, где он не masked):

```bash
systemctl mask --now ufw.service
```

```bash
git clone https://github.com/Egor051/vpnbot.git /opt/vpn-service
```

```bash
install -m 0600 -o root -g root /opt/vpn-service/deploy/relay/relay.env.example /opt/vpn-service/.env
```

Отредактируйте `/opt/vpn-service/.env`: `RELAY_UPSTREAM_IPV4` = IPv4 основного сервера и
желательно `RELAY_CHECK_SNI` = `XRAY_SNI` основного сервера — из него же собирается URL, по
которому relay просит пробу main (`https://<RELAY_CHECK_SNI>:2096/relay/ssh-probe`); если endpoint
подписки на другом домене или порту, задайте ещё `RELAY_CONFIRM_URL=https://<тот домен>:<порт>`.

До первого деплоя на **основном сервере**: A-запись DNS для relay и relay в админ-панели,
**включённый**, с egress-IPv4 relay в source IPs (шаги 1–2 ниже) — проба main отвечает только
адресу включённого relay. (Новый relay создаётся **не** «в подписках»: подписки получат его, только
когда вы нажмёте «➕ Добавить в подписки» на его странице — удобно сделать это после деплоя.) Затем
проверка и деплой:

```bash
cd /opt/vpn-service && sudo CHECK=1 DEPLOY_REF=main bash scripts/redeploy.sh
```

```bash
cd /opt/vpn-service && sudo FORCE=1 DEPLOY_REF=main bash scripts/redeploy.sh
```

`DEPLOY_REF=main` и `FORCE=1` — только в этот первый раз: свежий clone уже стоит на
`origin/main` — впереди самого нового релиза, о чём обычный запуск только сообщил бы
([какую ревизию деплоит relay](#какую-ревизию-деплоит-relay)), — а `FORCE=1` потому, что он уже на
цели. Дальше обновления обычные: `sudo CHECK=1 bash scripts/redeploy.sh`, затем
`sudo bash scripts/redeploy.sh` — следующий релиз новее этого коммита; чтобы следовать за main,
оставьте `DEPLOY_REF=main` в обоих.

Первый деплой включает [входной фильтр](#входной-фильтр), проба main его подтверждает, и
DEPLOY OK говорит `input filter : CONFIRMED by main probe (…)` — запускать ничего не нужно. Только
если там `PENDING CONFIRM (reverts at …) — <причина>`: исправьте названное или в течение 5 минут
откройте **новую** ssh-сессию и выполните

```bash
vpn-relay-apply input-confirm
```

Проверка: `systemctl status vpn-relay`, `nft list table ip vpnrelay`,
`nft list table inet vpnrelay_input`, `/usr/local/sbin/vpn-relay-apply input-status`,
`/usr/local/sbin/vpn-relay-apply check`.

На **основном сервере**:

1. A-запись DNS для relay — например, `relay2.anycastedge.net` → IPv4 relay — в Cloudflare
   **без проксирования** (см. [DNS](#dns--указывайте-имя-а-не-адрес)).
2. До первого деплоя relay должен быть строкой `relays` (probe main отвечает только адресу
   включённого relay). Панель создаёт relay только через pairing-код: НОВЫЙ relay —
   **«➕ Добавить relay»**, [установщик](#установка-relay-одной-командой) сделает всё, что этот раздел
   делает руками, и relay сразу будет с агентом. Relay, развёрнутый вручную и уже стоящий в таблице
   (бывший legacy), получает агента кнопкой **«🔗 Подключить агент»** на своей странице: установщик
   [примет](#adoption-ручной-установки) ручную установку.
3. **«🔍 Проверить сейчас»** на странице relay: health-проба проходит через DNAT relay до
   основного inbound'а и обратно (и спрашивает агента, если он есть).

Изменение `RELAY_FORWARD_*` (или любого значения в `.env` relay) не двигает `HEAD`, поэтому
применяйте его через `sudo FORCE=1 bash scripts/redeploy.sh` — с бэкапом, рестартом,
проверкой и откатом, — а не голым `systemctl restart vpn-relay`.

### Проброс порта подписки (2096) через relay

В этом релизе не сделано; что для этого нужно:

- **На relay** — простая половина: `RELAY_FORWARD_TCP_PORTS=443,2096` и
  `sudo FORCE=1 bash scripts/redeploy.sh`. TCP/2096 тогда доходит до subscription-endpoint
  основного сервера, а `check` проверяет ещё и `<upstream>:2096`.
- **На основном сервере** — часть, требующая кода:
  - URL подписки, который получает пользователь, строится на основном домене
    (`https://<HYSTERIA2_SNI>:<SUBSCRIPTION_PUBLIC_PORT>/sub/<token>`); чтобы скачивать
    подписку через relay, нужен URL с host relay, то есть отдельный URL подписки на relay в
    боте;
  - TLS терминируется на основном сервере сертификатом основного домена, значит имя relay
    должно быть в этом сертификате (SAN; раз relay пробрасывает 443 на основной сервер,
    практичнее выпускать через DNS-01);
  - rate limit endpoint'а считается по адресу пира, а каждый запрос через relay приходит с
    egress-IP relay — все пользователи relay делили бы один bucket
    (`SUBSCRIPTION_RATE_LIMIT_BURST` за `SUBSCRIPTION_RATE_LIMIT_SECONDS`), если source IPs
    relay не получат отдельной обработки;
  - правило UFW для `SUBSCRIPTION_PUBLIC_PORT` (модуль `subscription` в
    `scripts/vpn-bot-ufw-apply`) relay уже пропускает (оно не ограничено по источнику), а
    монитор доступности по-прежнему проверял бы только `XRAY_PUBLIC_PORT`.

## Установка relay одной командой

**🛡 Админ-панель → 🧩 Протоколы и маршрутизация → 🛰 Relay → ➕ Добавить relay** (или «🛰 Relay»
мастера — это тот же экран) спрашивает три вещи и показывает **одну строку** для relay:

1. **имя** relay — записывается в каждый его ключ и не меняется (предлагается свободное `relayN`);
2. **публичный хост для ссылок** — на него указывает ссылка каждого ключа. DNS-имя (рекомендуется:
   новый IP relay — это смена A-записи, ключи не переимпортируются); IPv4-адрес принимается с
   предупреждением — сгоревший IP придётся менять у всех клиентов. Это НЕ адрес, через который бот
   управляет relay: адрес для SSH спрашивается отдельно при завершении pairing и хранится отдельно
   (`ssh_host` агента);
3. **DNS-имя основного сервера**, куда relay пересылает трафик (бот предлагает `XRAY_PUBLIC_HOST`).

Relay устанавливается по строке сам, а бот подключается к нему по SSH и дальше управляет им.
**У relay нет своего Telegram-бота, и он никогда не обращается к Telegram API**: основной сервер и
relay связывает только SSH-ключ бота, строка которого в `authorized_keys` relay запускает лишь
[агента](#агент-vpn-relay-agent).

Тот же механизм кодов **подключает агента к уже существующему relay** («🔗 Подключить агент» на
странице relay, [ниже](#подключение-агента-к-существующему-relay)): имя не спрашивается, а в relay и
его ключах ничего не меняется.

### Pairing-код

`base64url(JSON)` без паддинга, ровно эти поля (`services/relay_pairing.py`; установщик
разбирает его по тем же правилам):

```json
{"v": 1, "target_host": "vpn.example.com", "ports": ["443/tcp", "443/udp"],
 "main_pubkey": "ssh-ed25519 AAAA…", "one_time_token": "<43 символа>", "exp": 1763300000}
```

- `target_host` — **DNS-имя** основного сервера, никогда не адрес: relay перерезолвит его раз
  в 5 минут ([ниже](#dns-имя-как-upstream)), поэтому новый IP основного сервера — это смена
  A-записи, на relay ничего делать не нужно. Бот предлагает `XRAY_PUBLIC_HOST` (иначе
  `HYSTERIA2_HOST`, `HYSTERIA2_SNI`), если это имя; можно ввести другое.
- `ports` — `XRAY_PUBLIC_PORT/tcp` и `HYSTERIA2_PORT/udp` (оба 443), пересылаются 1:1.
- `main_pubkey` — ключ бота для всех relay, `/etc/vpn-bot/relay_ssh/id_ed25519`, создаётся один
  раз (ed25519, `0600`, владелец — пользователь бота, никогда не заменяется; файл-симлинк или
  читаемый кем-то ещё отвергается). В модели helper-nonroot, где бот не может писать
  `/etc/vpn-bot`, создайте его один раз от root:
  `install -d -m 0700 -o vpn-bot /etc/vpn-bot/relay_ssh && sudo -u vpn-bot ssh-keygen -t ed25519 -N '' -C vpn-bot-relay -f /etc/vpn-bot/relay_ssh/id_ed25519`.
  Рядом лежит **jump-ключ** бота, `/etc/vpn-bot/relay_ssh/id_ed25519_jump`, — та же модель
  хранения (создаётся при первом вызове через hub; в модели helper-nonroot создайте его так же,
  с `-C vpn-bot-relay-jump -f …/id_ed25519_jump`). До агента он не доходит никогда: его знает
  только sshd hub'а, и только для проброса к relay за hub ([ниже](#управление-ru-relay-через-hub)).
- `one_time_token` — 32 случайных байта; relay хранит только их sha256. Бот держит токен, пока
  pairing ждёт (таблица `relay_pairings`), и стирает его в момент завершения, отмены или
  истечения.
- `exp` — 30 минут. Установщик принимает код до 5 минут после (расхождение часов); бот завершает
  pairing, а агент принимает первый `hello`, до 15 минут после.

Выпуск кода — [опасное действие](wizard.ru.md) (TOTP).

### Команда для relay

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/<owner>/<repo>/<commit>/scripts/install.sh && echo '<sha256>  install.sh' | sha256sum -c --quiet - && printf '%s\n' '<code>' | sudo env INSTALL_REF=<commit> bash install.sh --relay
```

- `<commit>` — собственный `HEAD` основного сервера, `<sha256>` — хэш его собственного
  `scripts/install.sh`: relay ставит ровно тот код, что работает на основном сервере, а
  отличающийся файл отвергается до запуска. `<owner>/<repo>` — `origin` checkout на GitHub (форк
  добавляет `INSTALL_REPO=`).
- Код попадает в установщик через **stdin**, из встроенной команды shell `printf` — никогда не
  в argv. Ввод один: ни токена бота, ни Telegram ID.

### Что делает установщик на relay

`scripts/install.sh --relay` (или режим `2` интерактивно) на Ubuntu 24.04 от root — тот же
каркас, что у основного установщика: read-only preconditions, manifest, откат при любой ошибке
или сигнале, лог `/var/log/vpn-bot-install.<ts>.log` (кода и токена в нём нет).

1. **Preconditions** (при отказе ничего не меняется): код валиден и не истёк; root может войти по
   ключу — решает `sshd -T -C user=root,addr=<main>` (`PubkeyAuthentication`, `PermitRootLogin`
   не `no`, `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups`, `AuthorizedKeysFile`);
   **`sshd_config` никогда не меняется**. ufw не должен быть включён (его forward-цепочка с
   политикой DROP отбросит пересылаемый трафик — `ufw disable && systemctl mask ufw.service`);
   цель резолвится; ни один пересылаемый TCP-порт не занят sshd; хост — не основной сервер.
2. **Установка**: `nftables`, checkout `<commit>` в `/opt/vpn-service`, `.env` relay из
   `deploy/relay/relay.env.example` (`NODE_ROLE=relay`, `RELAY_UPSTREAM_HOST=<цель>`, порты,
   `RELAY_INPUT_FILTER=off`, `SSH_PORT` = порт, на котором sshd слушает сейчас, чтобы позднейший
   `redeploy.sh` не увёл ssh от бота), `/etc/vpn-relay/pairing.json` (sha256 токена, срок, `0600`),
   `vpn-relay-apply` и `vpn-relay-agent` в `/usr/local/sbin`, `vpn-relay.service`,
   `vpn-relay-resolve.service` + `.timer` и **одна** строка в `authorized_keys` root:

   ```
   restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 AAAA… vpn-relay-agent
   ```

   Все остальные строки остаются байт-в-байт; старая строка агента и любая другая строка с тем же
   ключом (неограниченная копия была бы root-shell'ом) удаляются.
3. **Запуск**: `vpn-relay.service` применяет `table ip vpnrelay` одним атомарным `nft -f` — DNAT
   tcp+udp 443 → адрес цели, masquerade, MSS clamp для SYN, forward-цепочка с политикой drop,
   пропускающая только DNAT-потоки, — и `net.ipv4.ip_forward=1` через
   `/etc/sysctl.d/90-vpn-relay.conf` (см. [Relay-хост](#relay-хост-node_rolerelay)). Уже работающий
   юнит **перезагружается** (`ExecReload` = тот же атомарный apply), а не перезапускается: restart
   сначала выполняет `ExecStop` и оставил бы момент без DNAT.
4. **Проверка**: `vpn-relay-apply check`; **ровно одно DNAT-правило на каждый пересылаемый порт
   во всём ruleset** (другая таблица, тоже DNAT'ящая 443, валит установку); таймер активен. То,
   что основной сервер не отвечает с relay (`check` exit 13/14), — предупреждение: бот проверит
   путь сам при подключении.
5. Установщик печатает адрес, который нужно отправить боту, — source-адрес из
   `ip -4 route get <цель>` и ssh-порт; за NAT он говорит отправить публичный.

Повторный запуск с новым кодом на relay, поставленном этим установщиком, — **re-pair**: тот же
checkout, новый `pairing.json`, строка ключа заменена, всё применено заново.

#### Adoption ручной установки

Relay, настроенный вручную — `/etc/vpn-relay.nft`, `vpn-relay.service`, который его грузит,
`table ip vpnrelay`, — или развёрнутый `redeploy.sh`, **принимается** (adoption), а не
накрывается сверху:

- всё, что у него было, сначала уходит в `/var/backups/vpn-relay/adopt-<ts>/`: живые таблицы так,
  как их печатает `nft list`, `/etc/vpn-relay.nft`, юнит, sysctl-файл, helper'ы, `.env`. Эта копия
  **остаётся** (и после commit, и после отката);
- `/etc/vpn-relay.nft` убирается, чтобы его больше ничто не загрузило;
- у таблицы то же имя, поэтому одна транзакция `nft -f` заменяет старую `table ip vpnrelay` новой —
  никогда двух DNAT, никогда момента без DNAT;
- **откат возвращает всё**: файлы из бэкапа, а живую таблицу — из её дампа одной транзакцией
  (`table …; delete table …; <дамп>`), а не перезапуском старого юнита (чей `nft -f` мог бы
  добавить свои правила поверх). CI проверяет это на настоящей VM (ниже).

### Завершение pairing

«🔌 Подключить» (TOTP) → отправьте адрес relay для SSH (`IP`, `IP:порт` или DNS-имя). Бот:

1. подключается как `root` своим ключом — **trust on first use**: ключ хоста relay запоминается
   сейчас и закрепляется в `relays.host_key`; каждый следующий вызов идёт с
   `StrictHostKeyChecking=yes` под `HostKeyAlias=vpn-relay-<id>`, и relay с другим ключом
   отклоняется («ключ хоста relay изменился»);
2. выполняет `hello <token>`; агент сравнивает sha256 за постоянное время, в пределах срока, и
   отмечает себя спаренным. Повторный `hello` с тем же токеном отвечает снова (бот может повторить
   проверки), любой другой токен отклоняется;
3. проверяет relay **снаружи**, оба раза через его DNAT до этого сервера: **TCP** — проверенный
   TLS-handshake с `XRAY_SNI` на `<relay>:XRAY_PUBLIC_PORT` ([health-проба](#монитор-доступности));
   **UDP** (если включён Hysteria2) — QUIC-пакет с зарезервированной версией на
   `<relay>:HYSTERIA2_PORT`, на который любой QUIC-сервер отвечает version negotiation. Провал
   любой из проверок ничего не меняет и предлагает «Подключить снова»;
4. **новый relay**: создаёт строку `relays` СРАЗУ с агентом, в одной транзакции с закрытием кода —
   включён, **не «в подписках»** (их он получит кнопкой «➕ Добавить в подписки»,
   [ниже](#в-подписках-действие-над-всеми-подписками)), «👁 в базовых», метка `relay` или имя, `host` = публичный хост для ссылок из кода,
   **source IPs** = адрес, по которому к нему приходят, плюс адрес-источник, который агент сообщает
   для upstream, если он публичный (их [исключает детектор аномалий](#ограничения)). Если публичный
   хост не указывает на этот relay, результат об этом говорит;
5. [монитор доступности](#монитор-доступности) следит за ним со следующего прохода и шлёт
   суперадминам алерт при смене состояния (`RELAY_HEALTH_INTERVAL`, по умолчанию 300 с; при `0`
   результат предупреждает, что алертов не будет).

### Подключение агента к существующему relay

Relay без агента (настроенный вручную — бывший legacy `ru1`) продолжает работать как есть. Его
страница показывает «⚠️ без агента» и предлагает **«🔗 Подключить агент (ключи не меняются)»**
(TOTP): pairing-код для ЭТОГО relay — имя не спрашивается — и одну строку для него. На relay
установщик [принимает](#adoption-ручной-установки) ручную установку (старые файлы и таблицы уходят
в `/var/backups/vpn-relay/`, пересылка не прерывается). Дальше «🔌 Подключить» с адресом relay для
SSH, как выше, но:

- **это должен быть тот же сервер**: адрес для SSH совпадает с хостом relay, входит в его source IPs
  или это адрес, в который резолвится хост relay, — иначе **«это другой сервер»**: к тому серверу
  бот даже не обращается, а код остаётся ждать правильного адреса;
- **в relay меняются только колонки агента**: имя, метка, хост для ссылок, вкл/выкл, «в подписках»
  и каждый ключ остаются байт-в-байт, поэтому ссылки и подписки не меняются. `source_ips` может
  только **расти** — на адреса из ответа агента, которых список ещё не покрывает; ничего не удаляется;
- **любой сбой оставляет relay ровно таким, каким он был**: колонки агента, source IPs и код
  записываются ОДНОЙ транзакцией, после проверок;
- второго агента у relay быть не может; уже ждущий код показывается снова, а не выпускается новый;
  удаление relay отменяет его ждущий код.

**«🔌 Отключить агент»** — обратное действие: колонки агента очищаются, relay и его ключи остаются —
это снова relay, настроенный вручную, без потерь (хост, метка, source IPs — как были). По выбору
«🧹 Отключить и снять с relay» сначала выполняет `uninstall` на relay; это снимает и пересылку, так что
ключи через relay перестанут работать, пока relay не настроят заново (экран об этом предупреждает).

### Агент (`vpn-relay-agent`)

`scripts/vpn-relay-agent` (stdlib Python). sshd запускает его для ключа бота, что бы ни просил
клиент; запрос приходит в `SSH_ORIGINAL_COMMAND` и должен **целиком** совпасть с одной из строк
(полные шаблоны, ASCII, не длиннее 4096 символов — самый длинный запрос это список `jump`); всё остальное — синтаксис shell, вторая строка,
лишние слова, argv, интерактивный вход — отклоняется с кодом 2 до того, как что-либо выполнится:

| Запрос | Что делает |
|---|---|
| `hello <token>` | Завершает pairing; отвечает фактами о relay. Единственный запрос до pairing. |
| `status` | Факты: цель, порты, текущая цель DNAT, во что имя резолвится сейчас, `ip_forward`, юниты (`vpn-relay.service` и каждый таймер набора ниже), ssh-порты, source-адрес исходящего трафика, checkout, последнее обновление, `vpn-relay-apply check`, `vpn-relay-apply input-status` (`input_status`), на hub — его строка jump (`jump`: какие relay она открывает, отпечаток ключа), и с агента 5 — `sshd_drift` (ключи входа, у которых `sshd -T` не равен значению репо; дёшево, на каждый вызов) и `sshd_overrides` / `host_check_at` (что назвал последний прогон проверки хоста — её `last.json`), [чужой sshd-override](#чужой-sshd-override). |
| `apply target=<dns-имя> tcp=<порты> udp=<порты>` | Сменить цель/порты: отказ для имени, которое не имя или не резолвится на relay, порта вне 1..65535, больше 8 портов, TCP-порта, на котором слушает sshd. Переписывает только `RELAY_UPSTREAM_HOST` / `RELAY_FORWARD_*`, применяет, проверяет; возвращает `.env` и применяет заново, если ruleset или проверка (таблица, sysctl, upstream не отвечает) не прошли. |
| `update` | В transient-юните (`systemd-run --wait`): забирает теги релизов, выбирает самый новый релиз ([то же правило, что у деплоя](#какую-ревизию-деплоит-relay)) — только вперёд, никогда назад или вбок — и запускает для него деплой relay: `scripts/redeploy.sh` с `DEPLOY_REF=<тег>` (`deploy.sh` этого тега в своём transient-юните, лог `/root/deploy-<ts>.log`): гейт pytest, helper'ы, юниты и файлы хоста, reload vpn-relay, проверки; откатывается `deploy.sh` сам. Сам агент ничего не checkout'ит. Итог (`running` / `noop` / `failed` / `succeeded`, `from_commit`, `to_commit`, `release`, `log`; для провала `reason`, `step`, `excerpt` — причина из [строки результата](deployment.ru.md#маркеры-шагов-и-результата) deploy.sh, её шаг и строки, которые её объясняют; для успеха `warnings`) — в `/var/lib/vpn-relay/update.json` и в `status`; проваленный `update` отвечает всем итогом, и бот показывает причину, шаг, эти строки и путь к логу вместо «relay отказал». Это минуты: агент ждёт до 45 минут. |
| `uninstall` | В transient-юните: юниты набора ниже остановлены и удалены (сначала таймеры, `vpn-relay.service` последним), обе таблицы удалены, sysctl-файл удалён и `ip_forward` возвращён к значению до установки, удалены helper'ы, `/etc/vpn-relay`, `/var/lib/vpn-relay`, checkout (если его создал установщик), строка ключа агента и строка jump. Бэкап adoption остаётся. Отказ на хосте без `/etc/vpn-relay/install.json` установщика. |
| `input-confirm` | Запускает `vpn-relay-apply input-confirm` прямым дочерним процессом — ssh-сессия бота (новая) среди его предков, а это и есть доказательство для той проверки ([dead-man](#как-не-потерять-доступ-dead-man-и-input-confirm)). Отвечает строками helper'а и новым `input-status`. Lock агента не берёт: фильтр ждёт подтверждения как раз пока `update` его держит. |
| `jump key=<blob ed25519> open=<host>:<port>[,…]` | Hub: записать ОДНУ строку jump-ключа бота в authorized_keys root (`restrict,port-forwarding,permitopen="<host>:<port>"[,…],command="/bin/false" ssh-ed25519 <blob> vpn-bot-relay-jump`) — [ниже](#управление-ru-relay-через-hub). DNS-имя или IPv4 (не loopback, link-local, multicast), порт 1..65535, без повторов, не больше 32; ключ, у которого в файле уже есть другая строка (сам ключ агента), — отказ; отказ и пока `sshd -T` разрешает удалённый проброс (не `allowtcpforwarding local`). Все остальные строки — байт-в-байт. Свой lock, поэтому `update` hub'а его не задерживает. |
| `jump-off` | Hub: убрать эту строку. |
| `ssh-port-finish port=<p> since=<s>` | Фаза 2 переезда SSH-порта — только из сессии, пришедшей на `<p>` (её `SSH_CONNECTION`): `vpn-bot-ssh-port confirm-session` пишет доказательство и закрывает старый порт ([host-state.ru.md](host-state.ru.md#переезд-relay-из-бота)). |
| `ssh-port-keep since=<s>` / `ssh-port-resume since=<s>` | Удержать фазу 1 (старый порт остаётся, никакое доказательство её не завершает) / продолжить переезд. |
| `ssh-port-set port=<p>` | `SSH_PORT=<p>` в `.env`, затем `vpn-bot-ssh-port begin --keep <порт этой сессии>`: оба порта слушают сразу, без деплоя; порт, по которому пришёл бот, не закрывается; при неудаче (в том числе входного фильтра) `.env` возвращается. Проброшенный порт — отказ. |
| `input-filter on` / `input-filter off` | Агент 4. `on`: фильтр применяется из **промежуточной** копии `.env` с `RELAY_INPUT_FILTER=on` (`/etc/vpn-relay/input-filter.env`, `RELAY_ENV=<копия> vpn-relay-apply apply`) — живой `.env` пока не трогается; неподтверждённый TCP-набор взводит [dead-man](#как-не-потерять-доступ-dead-man-и-input-confirm), проба main может подтвердить его в том же apply. Подтверждён (`input-status` OK / CONFIRMED) → в `.env` пишется `on` (`"committed": true`); всё ещё PENDING → бот делает `input-confirm` из НОВОЙ сессии и снова просит `on`, который фиксирует. Так и не подтверждён → dead-man снимает таблицу, а `.env` ни разу не говорил `on`. Неудачный apply → снова применяется живой `.env`, exit 4. `off`: `RELAY_INPUT_FILTER=off` и apply (таблица уходит, ждущий dead-man разоружается); неудачный apply возвращает `.env`. [Довести relay до нормы](#довести-relay-до-нормы). |
| `sshd-check` | Агент 5. Свежий прогон `vpn-bot-host-check` (только чтение; пишет лишь свой `last.json`): файлы в `sshd_config.d`, которые перебивают ключ входа репо (`sshd_overrides`: путь, ключи, тексты проверки, mtime), и `sshd_drift`. |
| `sshd-override-off path=<файл>` | Агент 5. Перенести ОДИН [чужой sshd-override](#чужой-sshd-override) в `/root/attic/<имя>.<epoch>` (не удалить), `sshd -t`, `systemctl try-reload-or-restart ssh`, `sshd -T`; откат при любом сбое. Путь — только файл прямо в `/etc/ssh/sshd_config.d/` (без glob, без `/`, не файл репо), и только тот, который называет СВЕЖИЙ прогон проверки хоста; без личного ключа в authorized_keys root — отказ. |
| `update-log` | Агент 5. Конец (96 КиБ) деплой-лога последнего (или идущего) обновления — файл `/root/deploy-<ts>.log`, который назвал redeploy.sh (`update.json`); только чтение. Кнопка «📄 Лог» под обновлением. |

**Юниты** в агенте не перечислены. Он берёт их из checkout по тому же правилу, что deploy.sh,
install.sh и проверка хоста (`relay_unit_names`): каждый `deploy/relay/*.service` и `*.timer` в
`/opt/vpn-service`, кроме `*.example.*`. Поэтому юнит, добавленный туда, `uninstall` останавливает,
отключает и удаляет, а `status` показывает, как только его установят deploy/install. `uninstall`
сначала останавливает таймеры, чтобы ни один не запустил свой oneshot посреди удаления. Затем идут
oneshot-юниты, а `vpn-relay.service` — последним, потому что его `ExecStop` удаляет таблицы. Если
checkout есть, затрагивается только его набор. Если его нет (удалён или стоит на ref без
`deploy/relay/`), `uninstall` берёт файлы `vpn-relay.service` / `vpn-relay-<имя>.service|.timer`,
которые лежат в `/etc/systemd/system`, плюс `vpn-relay.service`.

Коды выхода: `0` ok · `2` отклонено · `3` не разрешено (токен, не спарен, истёк) · `4` сбой (то,
что успело измениться, возвращено) · `5` занято (другой изменяющий вызов держит lock). Один
JSON-объект в stdout. Каждый вызов пишется через `logger -t vpn-relay-agent` — имя запроса, адрес
вызывающего, вердикт; токен — никогда. В строке ключа стоит `restrict`: ни pty, ни проброса портов,
агента или X11.

### DNS-имя как upstream

nftables резолвит имя только при **загрузке** ruleset, поэтому `dnat to <имя>` заморозил бы адрес
того момента. Поэтому relay никогда не кладёт имя в таблицу:

- `RELAY_UPSTREAM_HOST` (вместо `RELAY_UPSTREAM_IPV4`; ровно одна из двух) резолвится
  `vpn-relay-apply` при каждом рендере (`getent ahostsv4`); из нескольких A-записей сохраняется та,
  что уже стоит в живой таблице (round-robin не перезагружает таблицу), иначе — наименьшая.
- `vpn-relay-resolve.timer` запускает `vpn-relay-apply resolve` через 2 минуты после загрузки и
  дальше раз в 5 минут: если текущая цель DNAT больше не среди адресов имени — применяет (один
  атомарный `nft -f`), иначе пишет `unchanged` и ничего не делает.
- Каждый apply запоминает адрес в `/etc/vpn-relay/upstream.resolved`; имя, которое не резолвится
  (DNS не поднялся при загрузке), откатывается к нему — только для **того же** имени; иначе
  `apply` выходит с `20`, ничего не применив, а `resolve` оставляет живую таблицу как есть (exit
  `20`, следующий проход повторит).

### Управление со страницы relay

Relay с агентом показывает «агент vX», адрес для SSH, цель и порты и последний `status` агента
(текущая цель DNAT, юниты, `vpn-relay-apply check`, версия, последнее обновление). На его странице
добавляются: «⬆️ Обновить агент» (`update`), «⚙️ Порты / цель» (`apply` — отправьте
`vpn.example.com tcp=443 udp=443`), «🔌 Отключить агент», а «🗑 Удалить» выполняет `uninstall` на relay
до удаления строки (relay, который не отвечает, — «Удалить только запись»). Вызов агента, идущий
минутами (update, apply, uninstall), занимает только ЭТОТ relay — экраном можно пользоваться, а
другое изменение этого relay в это время отклоняется («relay занят»). Каждое изменение спрашивает
TOTP-код ([ниже](#управление-relay-в-админ-панели)) и пишется в аудит (сущность `relay`).
Когда экран фолбэка подключён, у relay, который не hub, есть ещё **«🛟 Через hub: вкл/выкл»**
([через hub](#управление-ru-relay-через-hub)), а на странице написано, когда к агенту бот ходит
через hub. Пока последний `status` агента показывает входной фильтр `PENDING CONFIRM`, кнопка
**«🛡 Подтвердить входной фильтр»** отправляет `input-confirm` (состояние фильтра — в строках статуса).
Пока relay не [доведён до нормы](#довести-relay-до-нормы), на странице строка-предупреждение и кнопка
**«🛡 Довести до нормы»**.

### Ограничения relay из установщика

- **Без входного фильтра, SSH там же, где был**: установщик ставит `RELAY_INPUT_FILTER=off` и
  `SSH_PORT=<порт, который sshd слушает сейчас>` — намеренно, чтобы первый деплой не отрезал бота.
  К норме бот доводит его потом, по «Довести» суперадмина ([ниже](#довести-relay-до-нормы)).
- `redeploy.sh` и `update` агента — один и тот же движок (`deploy.sh` в роли relay, по умолчанию
  самый новый релиз): relay из установщика можно в любой момент задеплоить вручную, а host-файлы
  приходят с каждым обновлением в обоих случаях. Агент из времени до этого (он вызывал
  `install.sh --relay-update`, который теперь только отказывает) получает новый ОДНИМ ручным
  `sudo bash /opt/vpn-service/scripts/redeploy.sh` на relay — с `DEPLOY_REF=main` на relay, который
  уже впереди самого нового релиза.
- `/etc/vpn-relay/install.json` хранит то, что нужно `uninstall`; его `ref` — коммит, который
  поставила **установка** (переустановка его перезаписывает), — актуальным не поддерживается:
  деплои и `update` двигают checkout, не трогая файл. Коммит, на котором работает relay, —
  `git -C /opt/vpn-service rev-parse HEAD` (`status`: `checkout.commit`).
- Только IPv4, как и весь relay.

### Довести relay до нормы

**Зачем.** `install.sh` (`relay_write_env`) пишет НОВОМУ relay `SSH_PORT=<порт, который sshd слушает
сейчас>` и `RELAY_INPUT_FILTER=off`, чтобы первый деплой не отрезал бота. Дальше их никто не
переводил: у he2 — hub, через который в режиме фолбэка идёт ВЕСЬ трафик, — так и остались
`SSH_PORT=22`, `RELAY_INPUT_FILTER=off`, sshd только на `:22`.

**Что осталось** — по последнему `status` агента (`hardening_of`, services/relays.py): *SSH на 22* —
`ssh_migration.ssh_port` (действующий SSH_PORT) равен 22 и переезд не идёт (у агента без плана —
`ssh_ports` равен `[22]`); *фильтр выключен* — `input_status` начинается с `off`. Нестандартный порт
(2222) не трогается.

**Уведомление.** Сразу после pairing (его `hello` — первый статус relay) и, для relay, который был
раньше, — по сохранённому статусу (цикл health, проверка) или при открытии его карточки суперадмины
получают ОДНО жирное сообщение — «⚠️ relay X: SSH на 22, входной фильтр выключен — довести до
нормы?» — с **«🛡 Довести до нормы»** и **«Позже»**. Один раз на pairing (`schema_meta`
`relay_hardening_told`, по relay и его `paired_at`: новый pairing — спросит снова); «Позже»
тоже запоминается (`relay_hardening_later`), и больше не пристаёт. Вернуться можно всегда:
строка-предупреждение и кнопка на карточке relay, «🔑 SSH-порт relay» мастера (экран relay) и
**«🛡 Входной фильтр relay»** (каждый relay с агентом, его `input-status`, «Довести» для каждого, кто
не в норме).

**«Довести»** (TOTP: `relay_harden`; агенту старше нужного — `input-filter` есть с агента 4,
`ssh-port-set` с 3 — «сначала обновите агент» с кнопкой «⬆️ Обновить агент», и ничего не
отправляется) показывает план (каждый шаг ⚪, «✅ Подтвердить»), затем выполняет его с
[прогрессом](#прогресс-обновить-агент) в том же сообщении (`RelayService.harden`):

0. **Чужой sshd-override** — всегда первым: `sshd-check` (свежая проверка хоста), затем
   `sshd-override-off` для каждого файла, который она назвала ([ниже](#чужой-sshd-override)).
   Агент старше 5 — шаг ⏭ (его статус override назвать не может).
1. **Входной фильтр** — `input-filter on` (apply из промежуточной копии, dead-man взведён); если
   проба main ещё не подтвердила — `input-confirm` из НОВОЙ ssh-сессии бота (для relay за hub —
   через jump hub'а, [ниже](#управление-ru-relay-через-hub)); затем снова `input-filter on`,
   который видит набор подтверждённым и фиксирует `.env`. **Откат**: `input-filter off`; relay,
   до которого бот не достаёт вовсе, откатывает dead-man за 5 минут (`.env` не говорил `on`).
2. **SSH с 22** — `ssh-port-set port=54321` (фаза 1: 22 и 54321; фильтр следует за слушающими
   портами, новый TCP-набор подтверждает проба main или новая сессия бота), затем
   `finish_ssh_port` — вызов бота ПО 54321 и есть доказательство, фаза 2 закрывает 22
   ([host-state.ru.md](host-state.ru.md#переезд-relay-из-бота)). **Откат**: 54321 не отвечает →
   `ssh-port-set port=22` отменяет фазу 1 (снова только 22).

Каждый шаг атомарный; неудавшийся откатывается, предыдущий остаётся сделанным. **Фильтр — раньше
порта** намеренно: это бо́льшая защита (на хосте, через который идёт трафик, закрыто всё, кроме
sshd) и шаг, который откатывается сам (dead-man), поэтому переезд порта, который не может
завершиться — провайдер режет 54321, — оставляет relay с фильтром на 22. Переезд затем идёт тем же
путём, что у любого relay по умолчанию (фильтр включён; проба main набора {22, 54321} — ещё и
доказательство для фазы 2). Цена — два лишних круга dead-man, оба подтверждает сам бот.

### Чужой sshd-override

**Что случилось на he2 (hub).** 2026-11-18 в `/etc/ssh/sshd_config.d/` появился
`00-password-login.conf` (не из репо; вероятно, панель хостера при сбросе пароля) с
`PasswordAuthentication yes` / `PermitRootLogin yes`. По порядку файлов (sshd берёт ПЕРВОЕ значение)
он побеждает `00-vpnrelay-keyonly.conf`: hub снова принимает пароли. `vpn-bot-host-check
--pre-install` видит это как BEATEN, и деплой relay останавливается в Phase 1 — правильно; но в боте
было видно только «2 fatal finding(s)», а исправить можно было только руками.

**Что видно теперь.** Итог обновления называет находки — ключ, файл:строка, что победило что
([прогресс](#прогресс-обновить-агент)), и шаг «проверки». Для находки класса «файл прямо в
`sshd_config.d`, которого нет в репо, перебивает ключ входа репо» (`passwordauthentication`,
`kbdinteractiveauthentication`, `permitrootlogin`, `permitemptypasswords`, `pubkeyauthentication`,
`authenticationmethods` — тот же список, что `HOST_CHECK_SSHD_AUTH_KEYS` deploy.sh) — кнопка
**«🧹 Убрать чужой override»**.

**Что делает кнопка** (TOTP `relay_sshd_override`, код в том же сообщении; агент 5,
`sshd-override-off path=<файл>`):

- путь — только файл прямо в `/etc/ssh/sshd_config.d/` (whitelist агента и бота, `_REQUEST` и
  `WHITELIST`, синхронно; без glob, без подкаталогов, не файл, который ставит репо);
- агент заново запускает проверку хоста и уберёт файл, только если она его называет (не путь,
  который сказал бот);
- в `authorized_keys` root должна быть хотя бы одна строка без `command=` — личный ключ оператора;
  иначе отказ «добавьте свой ключ, иначе потеряете вход» (со строками агента и jump вход только по
  ключу закрыл бы оператору дверь);
- файл **переносится** в `/root/attic/<имя>.<epoch>` (не удаляется), `sshd -t`, `systemctl
  try-reload-or-restart ssh`, `sshd -T` сверяется со значениями репо для каждого перебитого ключа
  (ключ, который всё ещё перебивает ДРУГОЙ чужой файл, — не откат: тот файл назван в ответе, уберите
  и его). Любой сбой — файл возвращается на место, `sshd -t` и reload снова.

**Агент старше 5** (he2 на v3.2.0): обновление, которое принесло бы новый агент, останавливается
именно на этом файле. Бот показывает однократное исправление руками (по ssh со своим ключом):

```bash
mkdir -m 700 -p /root/attic
mv /etc/ssh/sshd_config.d/00-password-login.conf /root/attic/
sshd -t && systemctl reload ssh
```

затем «⬆️ Обновить агент»; дальше бот убирает такой файл сам.

**Если файл появится снова.** `status` агента 5 несёт `sshd_drift` (ключи входа, у которых `sshd -T`
не равен репо — дёшево, каждый вызов цикла health) и `sshd_overrides` (что назвал последний прогон
проверки — `vpn-bot-host-check.timer`, ежедневно и через 5 минут после загрузки). Монитор
(services/relay_sshd_override.py) шлёт суперадминам сообщение с той же кнопкой — ОДИН раз на файл и
его mtime (`schema_meta`, рестарт не повторяет): повторный «сброс пароля» в панели хостера — новый
файл, новый mtime — снова уведомление. Только дрейф без названного файла — бот сам просит
`sshd-check`, не чаще раза в час на relay. Повторный «сброс пароля» не откроет вход по паролю на hub
молча. Эта же проверка — первый шаг [«Довести до нормы»](#довести-relay-до-нормы).

## Управление relay в админ-панели

Только SUPERADMIN. **🛡 Админ-панель → 🧩 Протоколы и маршрутизация → 🛰 Relay** — ОДИН экран для
всех relay; «🛰 Relay» мастера настройки открывает его же (своего списка у мастера нет). В списке у
каждого relay — метка, имя, хост для ссылок, вкл/выкл, «в подписках», «👁 в базовых», число
активных ключей, его [health](#монитор-доступности) (один значок, одна причина) и как им управляют —
«агент vX» или «⚠️ без агента»; затем коды, которые ещё ждут подключения. Над relay — строка
**основного сервера** (прямых ключей) с его «👁 в базовых», под ними — его переключатель
**«👁 Основной сервер в базовых: да/нет»** ([ниже](#в-базовых-видимость-сервера-в-базовых-подписках)):
своей страницы у основного сервера нет.

**Страница relay** — общие действия для любого relay:

- **«✏️ Хост ссылок»** — хост, на который указывают ссылки (DNS-имя или IPv4; IPv6 отклоняется).
  После смены страница говорит, что подписки уже указывают на новый адрес и сколько одиночных
  relay-ключей нужно переимпортировать; IPv4-хост получает предупреждение про сгоревший IP, а не
  покрытый source IPs — предлагается добавить в source IPs;
- **«✏️ Переименовать»** — метка: название relay в списках и его маркер в названии ключей,
  уникальна для relay, 1–16 символов одной строкой, эмодзи можно (`🇷🇺➜`), приклеивается к флагу без
  `_`. **Имя** (`^[a-z0-9][a-z0-9-]{0,31}$`, то, что ключи несут в `vpn_keys.relay`) не меняется
  никогда; имя, которое ещё носит хоть одна строка ключа — в любом статусе, — новому relay не дают;
- **«✏️ Source IPs»**, **«✏️ Заметка»**, **вкл/выкл** ([ниже](#выключение-relay)),
  **«➕ Добавить в подписки» / «➖ Убрать из подписок»**
  ([ниже](#в-подписках-действие-над-всеми-подписками)), **«👁 В базовых: да/нет»**
  ([ниже](#в-базовых-видимость-сервера-в-базовых-подписках)),
  **«🔍 Проверить сейчас»** (один проход health: трафик и агент; вердикт остаётся на странице),
  **«🗑 Удалить»** ([ниже](#удаление-relay));
- **блок агента**: «🔗 Подключить агент» у relay без агента или статус / обновление / порты и цель /
  отключение у relay с агентом ([выше](#управление-со-страницы-relay)).

**«➕ Добавить relay»** — единственный способ создать relay: через pairing-код, поэтому новый relay
всегда сразу с агентом ([выше](#установка-relay-одной-командой)). Формы, которая записывает relay
без агента, в панели нет.

**Каждое изменение — опасное действие**: при включённом TOTP кнопка сначала спрашивает код
([wizard.ru.md](wizard.ru.md#где-спрашивается)) — вкл/выкл, «➕ Добавить в подписки» / «➖ Убрать из
подписок» (код спрашивается на «✅ Выполнить» под планом), «👁 в базовых» у relay и у основного
сервера, каждая правка,
предложение source IP, удаление (с ключами и без, только запись), «Добавить relay», «Подключить
агент», «Подключить», обновление, порты/цель, отключение агента. Шаг, ждущий ввода текстом, перед
действием ещё раз проверяет подтверждение. Каждое изменение пишется в аудит (сущность `relay`) со
значениями до и после: `relay_updated`, `relay_deleted`, `relay_delete_incomplete`,
`relay_pairing_issued`, `relay_pairing_cancelled`, `relay_pairing_check_failed`, `relay_paired`,
`relay_attach_refused`, `relay_agent_attached`, `relay_agent_detached`, `relay_agent_update`,
`relay_agent_apply`, `relay_agent_uninstall`, `relay_main_basic_visibility_changed` (основной сервер
«в базовых»). Добавление и удаление участников relay в подписках пишется по каждой подписке
(сущность `key_bundle`): `key_bundle_relay_members_added` / `key_bundle_relay_members_removed`, при
сбое — `key_bundle_reconcile_rolled_back` / `key_bundle_reconcile_partial`; в деталях — `relay` и
`relay_action`.

Любое изменение **действует со следующей отрисованной ссылки**: бот держит в памяти снимок
таблицы, который каждая запись тут же заменяет (бот — единственный писатель); эндпоинт подписок
(`vpn-bot-subscription`) читает таблицу на **каждый запрос** через своё read-only соединение.

**Кнопки из прошлого** — сообщения в истории чата двух бывших разделов («🛰 Управлять relay» и
«Мастер настройки → Relay», `wrl:*`) и старого ручного «Добавить relay» ведут на этот экран: кнопка
relay — на его страницу, кнопка кода — к коду, всё остальное — в список; никогда не в ошибку, и
старая кнопка сама ничего не меняет. Бывший переключатель «Убрать из подписок / Вернуть в подписки»
открывает план того, что он значит теперь (добавить или убрать — по текущему состоянию relay), и
тоже ничего не меняет без подтверждения.

### «В подписках»: действие над всеми подписками

«В подписках» — это не флаг «для новых», а действие над **всеми** выданными подписками сразу:

- **Новый relay создаётся не «в подписках»** (`in_subscriptions=0` — и через код, и в
  `RelayService.create`). Существующие relay не меняются. Колонка в схеме сохраняет `DEFAULT 1`:
  SQLite не умеет менять default колонки без пересборки таблицы, а пересборка `relays` внутри
  транзакции bootstrap (где `PRAGMA foreign_keys` не выключить) сработала бы `ON DELETE SET NULL`
  у `relay_pairings.relay_id` и осиротила бы ждущие коды. Поэтому значение задаёт код: каждая
  вставка называет колонку явно, и default не используется никогда.
- **«➕ Добавить в подписки»** — dry-run по всем активным подпискам и экран плана («будут
  дополнены N, будет создано X ключей, пропущены …»); ничего не меняется до «✅ Выполнить». После
  подтверждения relay отмечается «в подписках» (новые подписки получат его сами), и в фоне в
  каждой активной подписке создаются **только участники этого relay**: базовая — 2 (VLESS (TCP),
  Hysteria2), расширенная — 5 (ещё три VLESS (HTTP)); протокол, выключенный сейчас, не создаётся,
  как и при создании подписки. Вид подписки, прямые ключи, VLESS (HTTP) и участники других relay
  не трогаются. Выключенный relay добавить нельзя — понятный отказ («сначала включите его»).
- **«➖ Убрать из подписок»** — то же с планом «будут затронуты N подписок, будет удалено Y
  ключей»; после подтверждения relay снимается с «в подписках», и каждый его участник удаляется
  из всех активных подписок тем же путём, что и удаление подписки (клиент Xray, трафик в архив,
  аудит). Подписка, у которой после этого не осталось бы ни одного активного ключа (остальные
  отозваны по одному), пропускается с причиной.
- Гарантии те же, что у массового приведения
  ([docs/subscription.ru.md](subscription.ru.md#приведение-существующих-подписок)): сначала
  создания, при сбое созданное в этой подписке откатывается; затем удаления, при сбое повторный
  запуск доделывает (кнопка «🔁 Повторить» под отчётом); новые ключи получают общий `expires_at`
  и fingerprint VLESS подписки; токен не меняется; необычная подписка (разные сроки, дубликат
  участника, неактивный участник, degraded backend) пропускается с причиной. Ребёнок этого relay,
  удаление которого раньше не завершилось (`delete_failed`), дочищается, а место заполняется
  заново.
- Прогон идёт фоном с прогрессом (не чаще раза в 3 с) и итоговым отчётом — на том же исполнителе,
  что и «🔗 All-in-One», поэтому одновременно идёт только один массовый прогон любого вида.
- При `SUBSCRIPTION_ENABLED=false` выданных подписок нет: кнопка только переключает флаг.

### «В базовых»: видимость сервера в базовых подписках

**«👁 В базовых: да/нет»** на странице relay (`relays.basic_visible`, по умолчанию да) и
**«👁 Основной сервер в базовых: да/нет»** в списке (ключ `basic_visible_main` в `schema_meta` —
рабочем хранилище настроек в БД, не `.env`; нет ключа — виден) решают, отдаёт ли **базовая**
подписка детей этого сервера:

- действует **только при отрисовке** и **только для базовых** подписок; расширенные не меняются.
  Ключи, клиенты Xray и строки подписок не трогаются, поэтому переключение мгновенное и
  обратимое: клиенты увидят изменение при следующем обновлении подписки;
- **базовая подписка никогда не пустая**: скрыть сервер (или убрать relay из подписок), после
  чего в базовых не останется видимого сервера — основного или relay, который включён, «в
  подписках» и «👁 в базовых», — нельзя, бот объясняет почему. Выключение и удаление relay не
  запрещаются (это экстренные действия); если из-за них видимых серверов не осталось, список
  relay предупреждает, а endpoint отдаёт базовую подписку **без фильтра** с `WARNING` в логе
  (fail-open) — лучше показать скрытый сервер, чем отдать пустую подписку.

### Выключение relay

- **выключен** (`enabled=0`): ссылки его ключей отклоняются (`RelayUnavailable`, бот
  показывает ошибку вместо ссылки), его участники пропускаются в подписках (с WARNING в
  логе; прямые участники отдаются как обычно), его не предлагают для новых ключей и
  подписок. Его source IPs **по-прежнему исключены** из детектора аномалий — клиенты
  ещё могут быть подключены. Обратное включение возвращает всё как было.
- **не в подписках** (`in_subscriptions=0`): ни новые, ни выданные all-in-one подписки не
  содержат участников через него — «➖ Убрать из подписок» удаляет их из выданных
  ([выше](#в-подписках-действие-над-всеми-подписками)); одиночные ключи через него выдавать
  можно, пока он включён.

### Удаление relay

- Relay **с агентом**: **сначала** на relay выполняется `uninstall` — чтобы не осталось DNAT на этот
  сервер, — и только потом удаляется строка. Relay отказал или не отвечает: ничего не удаляется, и
  экран предлагает **«Удалить только запись»** (сам relay продолжит пересылать, пока его не почистят
  вручную). После `uninstall` relay помечается, поэтому прерванное удаление продолжается без
  второго `uninstall`.
- Relay **без агента**: удаляется только запись; на самом relay ничего не делается.
- **Ключей нет** (вне статуса `deleted`): одно подтверждение.
- **Ключи есть**: экран говорит, сколько их (и сколько из них в скольких подписках), и
  предлагает:
  - **Удалить ключи и relay** — каждый ключ через relay удаляется **тем же путём, что
    и с экрана самого ключа** (клиент Xray удаляется, трафик архивируется, аудит).
    Ребёнок подписки уходит из неё; подписка остаётся с остальными участниками. Первый
    ключ, который не удалось удалить, останавливает операцию: relay остаётся, экран
    сообщает, сколько ключей удалено, какой не удалился и почему. Повторное удаление
    продолжит с оставшихся ключей.
  - **Отключить вместо удаления** — relay выключается, ничего не удаляется.
  - **Отмена**.

Строка relay удаляется, только если в этот самый момент ни один ключ его больше не
называет (один SQL-оператор), поэтому ключ, выданный во время удаления, не осиротеет;
ждущий код «Подключить агент» отменяется в той же транзакции.

## Устаревшие `RELAY_*` в `.env`

Раньше relay настраивался переменными `RELAY_ENABLED`, `RELAY_NAME`, `RELAY_HOST` и
`RELAY_SOURCE_IPS`; одна из прошлых версий один раз переносила описанный ими relay в таблицу (так
там появился `ru1`). Теперь они **не читаются — даже не разбираются**:

- значение, оставшееся в `.env`, не может остановить бота, корректное или нет;
- при старте бот пишет ОДИН `WARNING RELAY_* в .env устарели и не читаются … — удалите их: <имена>`;
- самопроверка мастера показывает то же жёлтым пунктом (`legacy_env`).

Удалите эти строки. `RELAY_HEALTH_INTERVAL` и `SERVER_FLAG_EMOJI` — живые настройки, они остаются.

## Что такое relay-ключ

Relay — **атрибут ключа** (`vpn_keys.relay`, `NULL` у прямого ключа, иначе `name`
relay), а не новый тип ключа или транспорт:

- он создаётся тем же путём, что и прямой ключ, и получает свои uuid / secret /
  метку с обычным префиксом (`xray_tcp_*`, `xray_http_<профиль>_*`, `hy2_*`), поэтому
  `hy2_auth`, reconcile Xray (`XRAY_MANAGED_LABEL_RE`), статистика трафика и схема
  email-меток не затронуты;
- его ссылка отличается от ссылки прямого ключа ровно в двух местах: **хост** (host
  relay вместо `XRAY_PUBLIC_HOST` / `HYSTERIA2_HOST`) и **название** (метка relay
  после метки ключа, вплотную к флагу/кружку: `<метка>_<метка relay><флаг|кружок>`,
  например `xray_tcp_ab12c_🇷🇺➜🇫🇮` для метки `🇷🇺➜`). Порт, REALITY `sni`/`pbk`/`sid`/`spx`/`fp`, `flow`,
  `path`/`mode`/`extra` XHTTP и `sni` Hysteria2 — те же: relay форвардит 1:1, и TLS
  по-прежнему терминируется на основном сервере его сертификатом / ключами REALITY;
- хост выбирается в одном месте (`services.relay.relay_link_host`) для всех путей —
  экран конфига, QR, мастер создания, кэш `public_payload.link`, подписка. Ключ, чей
  relay выключен, удалён или неизвестен, **отклоняется** (`RelayUnavailable`) и
  никогда не перенаправляется молча на основной хост: ссылка, которая тихо обходит
  выбранный пользователем relay, — ровно та ошибка, от которой это защищает.

Пользователь выбирает это в мастере создания: после шага протокола (и профиля XHTTP),
пока включён хотя бы один relay, бот спрашивает **«Как подключаться?»** с кнопкой
**«Напрямую»** и по одной кнопке **«Через <метка>»** на каждый включённый relay (в
пользовательском и админском мастерах одинаково; у AmneziaWG шага нет — он не на 443).
Шаг подтверждения перепроверяет relay, так что выключенный за это время relay
отклоняется до того, как что-либо записано.

### Несколько relay в подписках

Новая all-in-one получает копию каждого участника через **каждый** relay, который
включён и «в подписках», группами в порядке `id` relay: сначала все прямые участники,
затем участники через relay №1, затем через relay №2 и т. д. — внутри группы обычный
порядок участников (basic: 2 в группе, extended: 5). Участник через relay получает
кружок своего прямого близнеца. См. [docs/subscription.ru.md](subscription.ru.md).

## Настройки

Полный справочник: [Конфигурация → Relay](configuration.ru.md#relay).

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `RELAY_HEALTH_INTERVAL` | `300` | Период проб, секунды; `0` = выключено. |
| `SERVER_FLAG_EMOJI` | `🇫🇮` | Флаг в названии одиночных ключей и участников basic. |
| `RELAY_ENABLED`, `RELAY_NAME`, `RELAY_HOST`, `RELAY_SOURCE_IPS` | — | **Устаревшие.** Не читаются; один WARNING при старте и жёлтый пункт самопроверки, пока их не удалят ([выше](#устаревшие-relay_-в-env)). |

**Настройки порта relay нет**: порт в relay-ссылке — это публичный порт самого
протокола (`XRAY_PUBLIC_PORT`, `HYSTERIA2_PORT`), потому что relay форвардит 1:1.

## Режим фолбэка (hub)

**Зачем.** ТСПУ блокирует IP основного сервера на границе РФ **в обе стороны**: клиенты из РФ,
RU-relay и основной сервер друг до друга не достают, а выходной IP основного сервера менять
нельзя. Выход — **hub**: relay **вне РФ** с чистым IP, который основной сервер по-прежнему видит.
В режиме фолбэка только hub ходит на основной сервер, а все имена **failover-набора** указывают
на hub:

```
обычный режим:                          режим фолбэка:

клиент ─▶ RU-relay ─▶ main              клиент ─▶ RU-relay ─▶ hub ─▶ main
клиент ─────────────▶ main              клиент ─────────────▶ hub ─▶ main
          (A: anycastedge.net → main)             (A: anycastedge.net → hub)
                                         hub → origin.anycastedge.net → IPv4 main (всегда)
```

**RU-relay переключать не нужно** — и невозможно: в этот момент основной сервер до них не
достаёт. Они форвардят на DNS-имя (`RELAY_UPSTREAM_HOST`, [выше](#dns-имя-как-upstream)), и
`vpn-relay-resolve.timer` каждые 5 минут сам переводит DNAT на новый адрес A-записи. Подписки
(`HYSTERIA2_SNI:2096`) рендерятся на лету и тоже идут через hub, если имя подписки в наборе.

Экран: **🛰 Relay → 🛟 Режим фолбэка**. В списке relay — одна строка состояния (выключен /
ВКЛЮЧЁН / ⚠️ переключение не завершено).

### Требования к hub

- **вне РФ** и с **чистым** IP: его должны видеть и клиенты/RU-relay, и основной сервер;
- relay **с агентом** (бот переводит его форвард сам) и включённый;
- **задеплоенный** с только локальным пробросом (`00-vpnrelay-forwarding.conf`, его ставит каждый
  деплой relay), прежде чем бот сможет управлять через него RU-relay
  ([ниже](#управление-ru-relay-через-hub)), — «⬆️ Обновить агент» его деплоит;
- **conntrack и полоса**: через hub идёт **ВЕСЬ** трафик всех клиентов и всех RU-relay —
  `RELAY_CONNTRACK_MAX` ([conntrack](#conntrack)) и канал выбирайте с запасом на всю аудиторию;
- hub форвардит TCP `XRAY_PUBLIC_PORT` + `SUBSCRIPTION_PUBLIC_PORT` и UDP `HYSTERIA2_PORT`
  (бот выставляет это сам при назначении роли);
- сейчас поддерживается **один** включённый hub. Модель допускает несколько (`relays.role`),
  выбор идёт через `services.relay.select_hub` — место для будущего балансировщика.

### Origin-имя: почему без него петля

Hub форвардит на **origin** — отдельное имя (например, `origin.anycastedge.net`), которое
**всегда** указывает на IPv4 основного сервера и **никогда** не входит в failover-набор. Если бы
hub форвардил на имя из набора, то после переключения это имя указало бы на сам hub — hub делал
бы DNAT сам на себя, и **все** клиенты потеряли бы связь. Поэтому:

- **«🛟 Сделать hub»** на странице relay с агентом спрашивает origin (предлагает
  `origin.<зона HYSTERIA2_SNI>`), бот через DNS API создаёт/исправляет его A-запись
  (`proxied=false`, TTL 60) → ждёт, пока публичные резолверы (DoH) отдадут IPv4 основного
  сервера → агентом `apply target=<origin> tcp=443,2096 udp=443` (проверка агента — TCP до
  основного сервера на **каждом** порту; не прошла — откат на relay) → проверяет, что hub
  смотрит на основной сервер (`live_target`/`resolved` агента) → роль `hub`. Любой отказ
  оставляет роль как была;
- origin и host hub **нельзя** добавить в набор; имя из набора нельзя сделать origin;
- петля проверяется при назначении роли и **перед каждым включением** режима (preflight).

Снять роль можно, только когда ни одно имя набора не указывает на hub — режим выключен **и**
выключение доведено до конца (имя, которое бот перевёл на hub, а обратно записать не смог,
держит роль). Форвард hub при этом не меняется. Пока relay — hub, его нельзя удалить, снять с него
агент (в том числе с `uninstall`) или сменить его порты/цель со страницы relay: через hub идут все
клиенты, а его собственный счётчик ключей их не видит. Сначала — «🛟 Снять роль hub».

### Токен DNS API

DNS переключается через API Cloudflare. Нужен **API token** с правами
**«Zone · Zone · Read»** и **«Zone · DNS · Edit»** на зону failover-имён (зона ищется по имени, для
этого нужно Zone Read). Это **один** токен бота: DNS-01 сертификата (acme.sh
`dns_cf`) и собственные DNS-записи бота используют тот же файл и ту же проверку — до сохранения он
проверяется, зона должна быть видна и читаема, создаётся и удаляется TXT-запись
([certificate.ru.md](certificate.ru.md#токен-cloudflare-один-на-бота)). Токен, который не может
править зону, отклоняется и не сохраняется.

Токен вводится только в админке (**🔑 Токен DNS API**) — никаких `.env` и CLI. Сообщение с ним
**удаляется сразу** после чтения (если Telegram не дал удалить — бот попросит удалить вручную),
токен проверяется запросом к API и только потом сохраняется в
`/etc/vpn-bot/dns_failover/cloudflare_token` (0600, владелец — пользователь бота, без симлинков —
те же проверки, что у ключа relay и ключа TOTP). В логах и аудите токена нет: значение
маскируется по точному совпадению везде, где работает редактирование, а аудит пишет только
отпечаток (8 hex sha256). В helper-nonroot модели (`ProtectSystem=strict`) каталог создаётся заранее —
`install -d -m 0700 -o vpn-bot -g vpn-bot /etc/vpn-bot/dns_failover` — и разрешается на запись в
unit: `ReadWritePaths=-/etc/vpn-bot/dns_failover` (уже есть в `deploy/vpn-bot.nonroot.example.service`;
`-` — unit стартует и без каталога).

### Failover-набор

**📝 Имена** — имена, A-запись которых переключается: обычный режим — IPv4 основного сервера,
режим фолбэка — IPv4 hub. Хранятся в БД (`failover_names`). Бот предлагает кандидатов:
`HYSTERIA2_SNI` (домен подписки и сертификата hy2) и имена, на которые смотрят relay с агентом
(у RU-relay — их `target_host`). Адреса берутся сами: основной — `XRAY_PUBLIC_HOST`, иначе
`HYSTERIA2_HOST` (если это IPv4); hub — его host, иначе SSH-адрес, иначе единственный /32 из
source IPs. Оба можно переопределить кнопками «IPv4 main» / «IPv4 hub» (при выключенном режиме).

### Включение и выключение

**«🟥 Включить режим фолбэка»** (подтверждение + TOTP):

1. **preflight** — ровно один включённый hub с агентом; агент отвечает свежим `status`; hub
   форвардит нужные порты и **сам достаёт** основной сервер на TCP `XRAY_PUBLIC_PORT` и
   `SUBSCRIPTION_PUBLIC_PORT` (строки `vpn-relay-apply check` агента; код 16–18 принимается,
   только если **все** строки FAIL — про входной фильтр, а не про `ip_forward` и проброс); петли нет (origin вне
   набора, указывает на основной сервер — по DoH и по мнению самого hub, а имя upstream и порты,
   которые
  hub сообщает в свежем `status` **сейчас**, совпадают с origin и портами hub — hub, перенаправленный на имя из набора вручную,
  резолвится в main до переключения и замкнулся бы после); токен активен; у
   каждого имени **ровно одна** A-запись, **не проксируется** (серое облако) и указывает на
   основной сервер или на hub — чужой адрес бот молча не перезаписывает. AAAA — предупреждение
   (клиенты с IPv6 пойдут мимо hub), не блокер. Не прошёл — DNS не тронут, режим не включён;
2. каждая A-запись → IPv4 hub (`proxied=false`, TTL 60);
3. **проверка через DoH** (cloudflare-dns.com и dns.google — не системный резолвер): до 30 с
   ждём, пока резолверы отдадут новый адрес;
4. **отчёт** по каждому имени: ✅ записано и видно / ⏳ записано, резолверы ещё отдают старое
   (держат до прежнего TTL — это не ошибка) / ❌ не записано (причина).

**«🟩 Выключить»** — обратная запись IPv4 основного сервера (нужен только токен; hub может быть
уже выключен).

Желаемое состояние режима хранится в БД, а что сделала последняя запись — **по каждому имени**.
Если часть имён не обновилась, экран и список relay показывают «⚠️ переключение не завершено»
со списком имён, а **«🔁 Повторить»** доводит переключение до конца (имена, которые уже на месте,
не трогаются). Всё пишется в аудит (сущность `relay`): `relay_hub_assigned`, `relay_hub_cleared`,
`failover_name_added`/`_removed`, `failover_token_set`/`_deleted`/`_rejected`,
`failover_preflight_failed`, `failover_enabled`, `failover_disabled`, `failover_setting_changed`,
`failover_direct_host_changed`.

Переключение показывает **прогресс** в том же сообщении (bot/progress.py): сначала план — шаги ⚪
(preflight, jump-строка hub, A-записи, проверка резолверами) с «✅ Да», затем 🔄 / ✅ / ❌ по шагам,
«N/M» для записей, строка активности, не чаще одной правки в 3 с; итог закрывает сообщение.

### Экран, мастер настройки, «Включить» при пустом наборе

**Не настроено** (нет токена DNS API или нет hub): экран говорит, чего не хватает, и даёт ОДНУ
кнопку — **«⚙️ Настроить фолбэк»** — мастер (TOTP), каждый шаг пропускается, если уже сделан:

1. **токен** — бот сам просит его; сообщение удаляется сразу; проверяется API и **на зоне**
   `HYSTERIA2_SNI` тут же («Токен управляет зоной …» или почему нет);
2. **hub** — из relay с агентом **вне РФ** (по стране IPv4 из базы IP-to-ASN; relay с неизвестной
   страной предлагается с пометкой);
3. **origin** — подставлен `origin.<зона>`, одно нажатие подтверждает (или другое имя);
4. **набор имён** — бот сам подставляет кандидатов, **у каждого «зачем»** (HYSTERIA2_SNI —
   сертификат hy2; имя подписки; имена, на которые форвардят RU-relay, с этими relay; XRAY_PUBLIC_HOST,
   если это DNS-имя), **все отмечены**; снимите лишнее — одно подтверждение, без ручного ввода;
5. **preflight** — с кнопкой на каждую найденную проблему.

**Настроено**: состояние, hub, имена со статусами — и только **«Включить/Выключить режим»**,
**«Проверить»**, **«⚙️ Настройки»**, **«⬅️ Назад»** («🔁 Повторить» — только пока переключение не
дошло до всех имён). Имена, токен, IPv4 main/hub, host прямых ссылок, `fallback-url` и
«Автопереключение» — в «⚙️ Настройки». «Обновить» нет: экран перерисовывается при открытии и после
каждого действия.

**«Включить» при пустом наборе** не отказывает молча: открывается экран кандидатов (отмечены, у
каждого «зачем») с ОДНОЙ кнопкой **«🛟 Включить с этими именами»** — отмеченные имена добавляются в
набор, и ТО ЖЕ действие продолжает переключение, без возврата на главный экран. Любой отказ
«Включить» — пустой набор, preflight, петля, токен, нет hub — показывает **причину и кнопку, которая
её устраняет** («🔑 Задать токен DNS API», «🧭 Выбрать имена», «🛟 Выбрать hub», «🛰 Карточка hub»,
«🧭 Имена набора», IPv4), а не голый отказ.

### Автоматика

Health уже видит RU (edge) relay — напрямую и через hub. Когда **каждый** включённый edge-relay с
агентом в проходе **отрезан от main** — его собственный check говорит, что upstream не отвечает
(exit 13/14), или main не достаёт ни его порт трафика, ни агент — а hub с main виден, это проход
инцидента. **Стабильно** = 3 прохода подряд **и** не меньше 10 минут (`services/fallback_auto.py`:
`PASSES`, `MIN_SECONDS`). Тогда:

* **«Автопереключение» выключено** (по умолчанию): каждый суперадмин получает ОДНО сообщение с
  ОДНОЙ кнопкой **«🛟 Включить режим фолбэка»** (подтверждение экрана, за TOTP);
* **включено** (⚙️ Настройки): бот переключает сам (`_switch` без актора — полный preflight,
  статус hub спрашивается от имени бота; hub выбирает `select_hub` — шов для будущего
  балансировщика) и **всегда** сообщает суперадминам итог.

Одно сообщение на инцидент (он кончается, только когда проход увидит edge-relay снова доступным);
после любого переключения — вручную или автоматически — час ничего автоматического
(`COOLDOWN_SECONDS`): флаппинга нет. **Обратно — только вручную**: при включённом режиме RU-relay
форвардят на hub, и сигнал, по которому режим включился, больше не наблюдается (их check пробует
hub и проходит); «восстановление», прочитанное по нему, было бы ложным и вернуло бы всех клиентов
в заблокированный путь. Поздно выключенный режим стоит трафика hub, слишком рано выключенный —
того самого простоя.

### Что переезжает, а что нет

- **Подписки** рендерятся на каждый запрос: их URL (`HYSTERIA2_SNI`) и записи relay-детей
  следуют за DNS сами.
- **Прямые ссылки** (`XRAY_PUBLIC_HOST` / `HYSTERIA2_HOST`) в живом деплое — **IPv4**: DNS их не
  двигает. Опция **«🔗 Host прямых ссылок»** заменяет этот IPv4 DNS-именем во всех новых
  рендерах — у бота и у подписок (`schema_meta`, по умолчанию пусто = как раньше). Имя должно
  сейчас резолвиться в основной сервер. Если оно **в наборе** — в режиме фолбэка прямые записи
  подписок пойдут через hub; если нет — всегда напрямую. Существующие ключи не ломаются: REALITY и
  hy2 от адреса в ссылке не зависят (SNI прежний), а импортированная ссылка с IPv4 работает,
  пока работает основной сервер. **Одиночные** прямые ключи (VLESS/Hysteria2, не дети подписок),
  выданные до установки имени, импортированы с IPv4 и **не переезжают** — экран показывает,
  сколько их (верхняя оценка: пользователь мог переимпортировать).
- **`fallback-url` в подписке** (по умолчанию выкл): подписка отдаёт заголовок
  `fallback-url: https://<host hub>:<SUBSCRIPTION_PUBLIC_PORT>/sub/<token>`. Happ читает его
  **только** для подписки с Provider ID. Сертификат порта подписки должен покрывать host hub
  (host-IPv4 — предупреждение на экране). Основной механизм — DNS.

### Прокси через hub

**Зачем.** SOCKS5 (и MTProto, когда включён) выдаётся как `SOCKS5_HOST:SOCKS5_PORT` — сейчас это
IPv4 main и порт 31337. В режиме фолбэка IP main забанен на границе: прокси у пользователей из РФ
мёртв, а hub до main достаёт.

**Адрес — один источник.** Пока режим включён, модуль включён и hub пробрасывает его порт, раздел
«Прокси» и всё, что бот выдаёт — `Host`/`Port`, `socks5://…`, ссылка `https://t.me/socks?…`, ссылки
MTProto `https://t.me/proxy?…`, строки статистики, — рендерятся с **IPv4 hub** (тот же адрес, что
получают failover-имена), порт прежний. Режим выключен — снова `SOCKS5_HOST` / `MTPROTO_HOST`.
Источник один: `ProxyEndpoints.endpoint()` (services/proxy_endpoint.py); шаблоны `SOCKS5_HOST` сами
не читают, а сохранённый при выдаче payload переписывается адресом «сейчас» при каждом показе.
Логины, пароли и секреты MTProto не меняются: hub — L4-проброс, аутентифицирует danted / mtproxy на
main. Почему IPv4, а не host hub: имя может само быть в failover-наборе или переехать вместе с
режимом; имени нужен DNS на клиенте — то, что ненадёжно там, где прокси нужен; IPv4 — ровно то, что
переключение пишет в A-записи, поэтому прокси и VPN-имена переезжают вместе.

**Проброс на hub.** «Включить» добавляет `SOCKS5_PORT/tcp` (и `MTPROTO_PORT`, если модуль включён) в
TCP-набор hub — тем же `apply` агента, что 443/2096, ДО записи DNS; `apply` сам проверяет, что hub
достаёт main:<порт>, иначе откатывает проброс. «Выключить» снимает порт после возврата имён на main;
выключение модуля прокси при включённом режиме снимает его сразу (включение — добавляет). Выбрано
при включении режима, а не при назначении роли hub: вне режима danted через hub никому не нужен, а
каждый проброшенный порт проверяет собственный check hub (его health, verify его деплоя, `apply`
агента) — падение danted на main не должно выглядеть как мёртвый hub или откатывать его обновление,
пока прокси никому не нужен. Порт, который не удалось пробросить, **не блокирует** переключение: VPN
важнее, отчёт говорит, что стало с прокси, а пользователи остаются на прежнем адресе. Порт, равный
SSH-порту hub, бот не отправляет вовсе (агент всё равно отказал бы).

**Reconcile, а не только переключение.** Переключение — событие, и режим, включённый до того, как
бот научился пробрасывать прокси, его не видел: hub так и не получил SOCKS5_PORT, и прокси всё время
режима оставался на забаненном адресе main (прод: v3.3.0 поставлена после включения режима). Поэтому
бот сам доводит прокси-порты hub до того, что хочет режим, всякий раз, когда смотрит, —
`FallbackService.reconcile_proxies`:

- **когда**: при старте (сразу после `refresh_state()`), на каждом проходе health-loop фолбэка (pass
  listener общего health-loop relay, `FallbackAutoSwitch.observe`), при открытии экрана «🛟 Режим
  фолбэка» и по кнопке «🔁 Довести прокси до hub». Всё, кроме кнопки, — в фоне и по одному: `apply`
  агента (до его таймаута 300 с) не держит ни запуск бота, ни проход health-loop, который решает об
  автопереключении, а экран ждёт его не больше 10 с. Lock переключения держится только на план и на
  запись итога — никогда на время вызовов агента, — поэтому переключение (прежде всего
  автоматическое) не ждёт reconcile; план, устаревший из-за переключения, не отправляется, а ушедший,
  пока режим сменился, тут же планируется заново;
- **что**: режим включён, модуль прокси включён, а hub его порт не форвардит → порт добавляется (тот же
  `apply` агента: его check проверяет main:<порт> или откатывает), прокси показывает IPv4 hub, и
  появляется «📣 Разослать»; прокси-порт на hub, которого режим не хочет (режим выключен, модуль
  выключен), → снимается. Добавляются и снимаются только настроенные прокси-порты: остальной
  TCP-набор hub (443/2096 и всё прочее), его UDP-набор и upstream отправляются ровно такими, какие есть,
  а hub, в наборе которого нет VPN-порта, reconcile не трогает вовсе — это дело preflight (кнопка так и
  говорит). Перед `apply` бот спрашивает у hub живой проброс: если он не совпадает ни с копией бота, ни
  с уже нужным набором (поменяли на relay руками, другой upstream), он **не перезаписывается** — это
  неудача с такой причиной;
- **неудача**: порт не отправляется повторно час (`RECONCILE_BACKOFF_SECONDS`; кнопка не ждёт). Если
  check агента называет порт, до которого не достал, ждёт только он — другой прокси уходит на
  следующем проходе без него. Суперадминам — ОДНО сообщение на каждую пару (порт, ошибка), с текстом
  ошибки агента и кнопкой на экран режима; сообщение, возникшее до старта бота, доставляется на
  следующем проходе. Если ничего не отправлено — hub не ответил на `status`, отказ «relay занят»,
  устаревший план, — это не неудача: не откладывается и не сообщается, следующий проход спросит снова.

Никогда не чините это выключением/включением модуля SOCKS5: `disable_protocol` удаляет все
SOCKS5-доступы.

**Проверки.** «🔍 Проверить» показывает прокси отдельной строкой: режим выключен — ℹ️ «порт
добавится при включении, apply проверит main:<порт>»; включён — ✅/⚠️ «hub достаёт main:<порт>»
(своей проверкой hub). Недоступный main:SOCKS5_PORT — понятный отказ ПРОКСИ (⚠️ и текст ошибки), а
не VPN: проверка «hub достаёт main на 443/2096» прокси-порт не учитывает. Режим включён, а прокси всё
ещё выдаётся «напрямую» — ⚠️ «режим включён, но hub не форвардит SOCKS5:<порт>» (с ошибкой последнего
`apply`, если была) и под ней **«🔁 Довести прокси до hub»** (TOTP, `fallback_proxy_reconcile`; та же
кнопка — на экране режима, пока прокси идёт напрямую): reconcile сразу.

**danted видит hub.** Все подключения через hub приходят на main с IP hub. Проверено: в
`deploy/danted.conf.example` `client pass` и `socks pass` — `from: 0.0.0.0/0`, сетей, исключающих
hub, нет (на живом `/etc/danted.conf` держите так же — он ручной); бот не ограничивает и не считает
SOCKS5 по IP клиента (детектор аномалий читает только access-лог Xray, а source IPs relay, hub в их
числе, у него и так исключены); правило UFW модуля socks5 — `allow`, не `limit`. Если на main есть
свой fail2ban на danted — добавьте source IPs hub в `ignoreip`.

**Только TCP CONNECT.** UDP ASSOCIATE через L4-hub не работает: danted отдаёт клиенту для UDP свой
адрес (main), до которого клиент в режиме не достаёт. Telegram хватает TCP.

**Сохранённые ссылки** у пользователей содержат IP main и сами не переедут. После переключения,
которое сдвинуло адрес прокси, на экране режима появляется **«📣 Разослать пользователям с прокси
новую ссылку»** — по желанию, никогда автоматически: подтверждение с числом получателей (активный
доступ к сдвинутому прокси) и текстом, TOTP (`fallback_proxy_notice`), рассылка через обычные
рассылки (announcements, сегмент по протоколу, журнал доставки). В тексте — новый адрес (общий для
всех) и подсказка, что готовая ссылка — в разделе «Прокси».

### Через hub: лимит подписки, ssh-probe, health, детектор аномалий

- **Лимит подписки.** Через hub все клиенты приходят на основной сервер с одного IP, и корзина
  по peer была бы одна на всех. Запросы, чей peer входит в source IPs hub, лимитируются по
  **хэшу токена** (свой префикс: ни токен, ни его отпечаток из корзины не восстановить; в лог
  токен не пишется). 429 по-прежнему отдаётся **до** проверки существования токена. Список сетей
  hub кэшируется в процессе подписки на 30 с (истёкший кэш перечитывает один запрос, остальные
ждут его), чтобы лимитер не ходил в БД на каждый запрос.
  Остаточный риск: через hub перебор случайных токенов не упирается в лимит по peer —
  кривые токены до БД не доходят, валидные по форме стоят один индексный lookup.
- **`POST /relay/ssh-probe`** ([выше](#main-подтверждает-фильтр-post-relayssh-probe)) отвечает
  **404**, если IP вызывающего входит в source IPs **любого** hub (включённого или нет), даже
  если этот адрес покрывает и обычный relay. Hub маскарадит порт подписки: в режиме фолбэка
  probe RU-relay приходит с адреса hub, и main прозвонил бы SSH-порты hub, «подтвердив» чужой
  фильтр. Следствие: входной фильтр **самого hub** и RU-relay в режиме фолбэка подтверждается
  `input-confirm` из новой SSH-сессии — её бот открывает сам, через hub
  ([dead-man](#как-не-потерять-доступ-dead-man-и-input-confirm), [ниже](#управление-ru-relay-через-hub)).
- **Health.** В режиме фолбэка relay, который форвардит на имя из набора (или relay без агента),
  с упавшей hairpin-пробой получает уровень **🛟 «за hub, напрямую недоступен»**: переход в него
  и из него обратно в 🟢 **алертов не шлёт**. Агента при этом всё равно спрашивают — через hub, —
  так что его статус свежий, а ожидающий входной фильтр подтверждается. Выключили режим, а relay
  так и недоступен — обычный 🔴 с алертом.
- **Детектор аномалий** теряет IP-сигнал: весь трафик через hub приходит с IP hub, а его source
  IPs исключены, как у любого relay. Пока режим включён, IP-аномалии не видны.

Не сделано здесь: автопереключение по health.

### Управление RU-relay через hub

ТСПУ режет и SSH с основного сервера к RU-relay. Hub по-прежнему достаёт до обоих, поэтому бот
управляет ими **через hub**:

```
бот ──ssh (jump-ключ)──▶ sshd hub ──-W ru1:22──▶ sshd ru1 ──▶ vpn-relay-agent
     закреплённый ключ hub            закреплённый ключ ru1, ключ агента, forced command
```

- **Когда.** Через hub идёт relay, на странице которого **«🛟 Через hub: вкл»** (`relays.via_hub`,
  схема v47, — всегда), и **все relay, кроме hub, пока включён режим фолбэка** (автоматически, без
  флага). К hub бот всегда ходит напрямую. Relay за hub без hub (или hub без агента) — понятный
  отказ, а не таймаут. На странице relay написано, как бот достаёт агента: «SSH к агенту — через
  hub … (флаг «через hub» | режим фолбэка)».
- **ssh.** Один `ssh` с `ProxyCommand` — вторым, полностью закреплённым `ssh` (`-F /dev/null`, тот
  же набор опций, **jump-ключ**, свой `HostKeyAlias` и закреплённый ключ хоста hub,
  `StrictHostKeyChecking=yes` всегда), который делает только `-W <ssh_host relay>:<ssh_port>`. Не
  `-J`: ProxyJump запускает ssh прыжка с настройками по умолчанию (`~/.ssh`, любой ключ), их не
  закрепить. Прыжок к relay — ровно прямой вызов: ключ агента, свой alias и закреплённый ключ
  (TOFU при pairing). ProxyCommand выполняется в `/bin/sh` (свой `$SHELL` у бота — nologin).
  Прыжок до hub пишет лог на уровне `INFO`, поэтому отказ назван: «hub не пускает к …» (нет в его
  permitopen) или «hub не достучался до …».
- **Строка на hub.** Агент hub держит ОДНУ строку jump-ключа в authorized_keys root:

  ```
  restrict,port-forwarding,permitopen="<ssh_host>:<ssh_port>"[,permitopen="…"],command="/bin/false" ssh-ed25519 <jump-ключ> vpn-bot-relay-jump
  ```

  `restrict` (ни pty, ни проброса агента/X11), проброс портов обратно — но только к sshd
  перечисленных relay, — и `/bin/false` для сессии: shell нет. **`permitopen` ограничивает только
  локальный проброс**: с включённым пробросом ключ мог бы ещё и открывать listener на hub (`-R`:
  TCP-порт на loopback, Unix-сокет от root по новому пути), а запретить это опцией authorized_keys
  нельзя (`permitlisten` не покрывает Unix-сокеты и не знает `none`). Поэтому sshd каждого relay
  пробрасывает **только локальный TCP** (проброс Unix-сокетов выключен в обе стороны — `permitopen`
  и так отклоняет не перечисленные в нём пути сокетов, так что это подстраховка): `deploy.sh` ставит `/etc/ssh/sshd_config.d/00-vpnrelay-forwarding.conf`
  (`AllowTcpForwarding local`, `AllowStreamLocalForwarding no`; `-R` на relay выключен для всех),
  проверка хоста следит, что он действует, а агент hub отказывает в `jump`, пока `sshd -T` этого не
  показывает, — hub, установленный, но с тех пор не деплоившийся, строку jump не получит (сначала
  обновите его). В `permitopen` **ровно** relay с
  агентом, которые за hub. Бот переписывает строку (`jump key=… open=…` или `jump-off`, когда за
  hub никого) при каждом изменении этого набора — флаг, включение/выключение режима, выдача или
  снятие роли hub (строка уходит вместе с ролью), pairing, отключение агента, удаление — и перед
  первым вызовом через hub после перезапуска. Клиент отклоняет цель не из этого списка ещё до
  запуска процесса; hub, который всё равно отказал в пробросе (переустановлен, правлен руками),
  получает строку заново — один раз. Собственная строка агента —
  `restrict,command="vpn-relay-agent"` — не трогается: прыжком она не станет никогда.
- **Pairing во время бана** (режим фолбэка включён или агент подключается к relay «через hub»)
  делает `hello` через hub: строка hub на время pairing открывает этот адрес (и закрывает его
  обратно, если pairing не удался). Внешние проверки с основного сервера в этот момент пройти не
  могут, поэтому вместо них — собственная проверка relay `vpn-relay-apply check` (TCP до его
  upstream на каждый проброшенный порт, TLS), запрошенная через hub с ключом, который только что
  узнал hello (в результате — «relay's own check, via hub»).
- **Входной фильтр.** Сессия через hub — НОВАЯ ssh-сессия на relay. Когда `status` показывает
  `PENDING CONFIRM`, бот отправляет `input-confirm` (после обновления, в цикле health или по кнопке
  «🛡 Подтвердить входной фильтр») — проба main не нужна
  ([dead-man](#как-не-потерять-доступ-dead-man-и-input-confirm)).

## Монитор доступности

При `RELAY_HEALTH_INTERVAL > 0` бот запускает **один** фоновый цикл для всех relay по
образцу монитора WARP и держит **один вердикт на relay** — один значок и одну строку причины в
списке и на странице, одну защёлку, один алерт на смену состояния. Каждый проход читает relay из
БД (relay, добавленный или изменённый в панели, подхватывается без рестарта) и для каждого
**включённого** relay:

1. **трафик** — TCP-подключение к `<host relay>:XRAY_PUBLIC_PORT` и TLS-handshake с
   `server_hostname=XRAY_SNI` **с проверкой сертификата** (и UDP, ниже). Бот работает на основном
   сервере, поэтому проба уходит на relay и возвращается через его DNAT (hairpin); REALITY не
   узнаёт в ней клиента и отдаёт её decoy, сертификат которого действителен для `XRAY_SNI`.
   Поэтому прошедшая проба означает «TCP/443 через relay доходит до основного inbound целиком»
   (проверено вручную: HTTP 200, `verify=0`, TLS ≈ 0,29 с);
2. **агент**, если он есть, — `status` по SSH (сохраняется в строке relay и показывается на его
   странице). Не ответил или его `vpn-relay-apply check` завершился кодом, отличным от `0`/`13`/`14`
   (13/14 — relay сам не достучался до этого сервера — оценивает hairpin-проба): часть агента
   провалена.

Вердикт: 🔴 **недоступен** — трафик через relay не доходит до этого сервера (ключи не работают);
🟡 **предупреждение** — трафик проходит, агент нет (ключи работают, управление — нет); 🟢 **в
порядке** — и то и другое. Relay без агента оценивается только по трафику.

- **UDP** (при `HYSTERIA2_ENABLED=true`): QUIC-пакет с зарезервированной («greasing») версией,
  дополненный до 1200 байт, на `<relay host>:HYSTERIA2_PORT` — любой QUIC-сервер отвечает на
  неизвестную версию version negotiation (RFC 9000 §6), так что ответ доказывает UDP DNAT
  целиком, без всяких учётных данных. Сначала тот же пакет на `127.0.0.1` — контроль: если
  собственный hysteria-server этого хоста тоже не отвечает, UDP «не оценивается», а не «упал».
  Relay доступен, когда TCP проходит, а UDP не провалился.
- Одна проба длится не дольше 10 с и никогда не бросает исключение.
- Защёлка по времени — **своя у каждого relay** (`relays.id`) по трём уровням: relay переходит на
  уровень после одного интервала на нём (две пробы подряд). Каждый админ из `ADMIN_IDS` получает
  **ровно одно сообщение на смену состояния** — 🔴 / 🟡 / 🟢 с меткой, именем, host relay и одной
  строкой причины — никогда два на одно событие (трафик и агент упали вместе — ОДИН 🔴), никогда
  повтор, пока ничего не меняется. Новый relay стартует как доступный; у выключенного или
  удалённого relay защёлка сбрасывается; состояние одного relay не влияет на другой. Пока на relay
  идёт вызов агента (update, uninstall), цикл его агента не спрашивает.
- Последняя проба каждого relay (из цикла или «Проверить сейчас») показывается на его
  карточке; хранится только в памяти бота.
- Мёртвый relay **не** помечает Xray как degraded и не блокирует выдачу ключей.
- В [режиме фолбэка](#режим-фолбэка-hub) четвёртый уровень — 🛟 **за hub**: relay за hub с упавшей
  hairpin-пробой, без алертов и без SSH к агенту.
- Каждая проба оставляет в error-логе Xray одну строку вида
  `REALITY: processed invalid connection from <IP relay>`. Это ожидаемо — так проба
  уходит в decoy.

## Ограничения

- **Детектор аномалий слеп к IP трафика через relay — так задумано.** L4 без PROXY
  protocol означает, что у каждого подключения через relay адрес relay; у Hysteria2
  поверх UDP адреса клиента нет вообще. Поэтому source IPs **всех** relay — включая
  выключенные — не учитываются вовсе (ни IP, ни его сеть/ASN); список перечитывается
  из БД в начале каждого цикла детекции. Inbound общий, так что это лишает IP-сигнала
  **любой** ключ, которым пользуются через relay, — в том числе прямой ключ, ссылку
  которого пользователь перенаправил на relay. Счётчик подключений `/online`
  Hysteria2 не затронут.
- **UDP оценивается только относительно собственного сервера.** Если hysteria-server этого
  хоста не отвечает на контрольную пробу, UDP relay не оценивается (решает вердикт TCP).
- **Порты 1:1.** Relay должен форвардить на те же номера портов, что публикует
  основной сервер.
- **Inbound общий.** Отдельного inbound, тега или учётных данных у relay нет; relay
  виден только в ссылке, которую держит пользователь.
- **URL подписки остаётся на основном домене.** Sub-URL (`:2096` в живом деплое)
  запрашивается с домена основного сервера, а не через relay; на relay указывают
  только ссылки внутри. Что нужно, чтобы перенести его за relay:
  [Проброс порта подписки](#проброс-порта-подписки-2096-через-relay).
- **Выданные подписки меняются только кнопками «в подписках».** «➕ Добавить в подписки» /
  «➖ Убрать из подписок» на странице relay добавляют или удаляют его участников во всех
  активных подписках ([выше](#в-подписках-действие-над-всеми-подписками)); простое включение
  выключенного relay их не дополняет. Массовое приведение «🔗 All-in-One» по-прежнему есть —
  см. [docs/subscription.ru.md](subscription.ru.md#приведение-существующих-подписок).
