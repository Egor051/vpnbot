# Добавление inbound VLESS (HTTP) — `vless-xhttp-reality` (XHTTP fallback topology)

Этот runbook заводит второй транспорт VLESS (**XHTTP**), используемый типом ключа
**VLESS (HTTP)**. Это **разовая серверная** операция, выполняемая оператором на VDS — бот сам
никогда не редактирует топологию inbound; он только добавляет и удаляет *клиентов* в inbound,
указанном `XRAY_XHTTP_INBOUND_TAG`.

## XHTTP fallback topology

VLESS (HTTP) **не** получает собственный публичный порт. Он едет через REALITY публичного `:443`
у `vless-in` посредством **дефолтного catch-all fallback** на внутренний loopback-only
XHTTP-inbound:

```
client ──TLS / REALITY──▶  vless-in (:443, security: reality)
                               │  settings.fallbacks = [{ "dest": 8001, "xver": 0 }]
                               │      ↑ ДЕФОЛТНЫЙ catch-all — без поля "path"
                               ▼
                           vless-xhttp-reality (127.0.0.1:8001, security: none, network: xhttp)
                               путь /v1/messages/stream валидируется здесь, на inbound
```

- `vless-in` (`:443`): `vless`, `security: reality`, `serverNames: ["googletagmanager.com"]`, `shortIds: ["ff69b6f523de0d17"]`, с единственным **дефолтным catch-all** fallback `{ "dest": 8001, "xver": 0 }` (без `path`).
- `vless-xhttp-reality`: `listen: 127.0.0.1`, `port: 8001`, `vless`, `security: none`, `network: xhttp`, `xhttpSettings.path: /v1/messages/stream`, `mode: auto`. Пустые `clients`, **без своего REALITY** — он только держит http `clients[]`; бот добавляет/удаляет клиентов здесь по тегу, а ссылка VLESS (HTTP) переиспользует REALITY у `vless-in` (`pbk`/`sni`/`sid`/`fp`) и его публичный `:443`.

> ⚠️ **Подвох — НЕ используйте path-based fallback для XHTTP.** Path-based VLESS `fallback`
> (`{ "path": "/v1/messages/stream", "dest": 8001 }`) **не** матчит HTTP/2 XHTTP-запрос: под h2
> путь запроса лежит в HPACK-сжатом псевдо-заголовке `:path`, а не в request-line HTTP/1, который
> инспектирует matching `path` у VLESS fallback. Единственная рабочая схема — **дефолтный
> catch-all** fallback (`{ "dest": 8001, "xver": 0 }`, без `path`) на loopback XHTTP-inbound; путь
> валидируется ниже по потоку на `xhttpSettings.path` XHTTP-inbound. Оба клиентских режима
> `stream-one` и `packet-up` подтверждённо работают через этот fallback.

> ⚠️ Делайте это с **остановленным** ботом, чтобы он не гонялся за `ConfigFileLock`, и всегда
> держите timestamped-бэкап для отката.

## 1. Завести топологию (бот остановлен)

```bash
systemctl stop vpn-bot
cd /usr/local/etc/xray && cp -a config.json config.json.bak.$(date +%s)

jq '
  .inbounds |= (
    # 1) Добавить ДЕФОЛТНЫЙ catch-all fallback к vless-in (должен остаться последней/беспутевой
    #    записью, чтобы быть дефолтом; любые path-based fallbacks должны идти перед ним).
    map(
      if .tag == "vless-in"
      then .settings.fallbacks = ((.settings.fallbacks // []) + [{ "dest": 8001, "xver": 0 }])
      else .
      end
    )
    # 2) Добавить loopback XHTTP-inbound (fallback dest), security: none, пустые clients.
    + [
        {
          tag: "vless-xhttp-reality",
          listen: "127.0.0.1",
          port: 8001,
          protocol: "vless",
          settings: { clients: [], decryption: "none" },
          streamSettings: {
            security: "none",
            network: "xhttp",
            xhttpSettings: {
              path: "/v1/messages/stream",
              mode: "auto"
            }
          }
        }
      ]
  )
' config.json > /tmp/config.new.json

# Проверить, затем установить с тем же owner/mode, что и у live-конфига (root-owned,
# группа vpn-bot, 0640 — читается non-root ботом, никогда не world-readable).
xray run -test -config /tmp/config.new.json    # если флаг отвергнут: xray -test -config /tmp/config.new.json
install -o nobody -g vpn-bot -m 0640 /tmp/config.new.json /usr/local/etc/xray/config.json

# Новое правило firewall не нужно: XHTTP-inbound слушает только loopback, а трафик
# входит через уже открытый публичный :443.
systemctl restart xray && systemctl status xray --no-pager
# Оставьте vpn-bot остановленным, пока не задеплоен код с XRAY_XHTTP_ENABLED (шаг 2).
```

Sanity-check, что оба inbound существуют, новый — loopback + пустой, а `vless-in` несёт дефолтный
catch-all fallback:

```bash
jq '.inbounds[] | {
      tag,
      listen,
      port,
      security: .streamSettings.security,
      network: .streamSettings.network,
      fallbacks: (.settings.fallbacks // []),
      n: (.settings.clients | length)
    }' /usr/local/etc/xray/config.json
```

> **Опциональный серверный тюнинг.** XHTTP-inbound может нести блок `xhttpSettings.extra`
> (напр. `xPaddingBytes`, `scMaxEachPostBytes`, `keepAlivePeriod`, decoy `headers`). Это чисто
> серверная история и намеренно **не** попадает в сгенерированную клиентскую ссылку.

## 2. Включить фичу в боте

Добавьте в `.env` бота:

```
XRAY_XHTTP_ENABLED=true
XRAY_XHTTP_INBOUND_TAG=vless-xhttp-reality
XRAY_XHTTP_PATH=/v1/messages/stream
XRAY_XHTTP_MODE=stream-one
```

- `XRAY_XHTTP_PATH` должен совпадать с `xhttpSettings.path` на inbound выше (используется только для построения клиентской ссылки).
- `XRAY_XHTTP_MODE` — **клиентский** режим, записываемый в ссылку VLESS (HTTP). Дефолт `stream-one` чище всего для direct REALITY — одна full-duplex HTTP/2-сессия — и подтверждённо работает через catch-all fallback. Переключайтесь на `packet-up` для троттлинга запросов на долгих сессиях или при фронтинге через CDN (там xmux ротирует нижележащие соединения). `stream-up` (двух-запросный вариант) для сред без single-request full-duplex; на direct REALITY не нужен. Собственный `mode: auto` inbound принимает любой из них.
- `XRAY_XHTTP_PORT` больше **не** используется для построения ссылок — ссылка едет через публичный `:443` у `vless-in` (`XRAY_PUBLIC_PORT`); XHTTP-inbound слушает loopback как fallback dest. Настройка оставлена только для обратной совместимости.

Задеплойте новый код, примените DB-миграцию (автоматически при bootstrap; добавляет колонку
`transport`, заполняя каждый существующий ключ значением `tcp`), затем:

```bash
systemctl start vpn-bot
```

## 3. Проверка

- Создайте ключ **VLESS (HTTP)** из бота и убедитесь, что клиент попал **только** в XHTTP-inbound:

  ```bash
  jq '.inbounds[] | {tag, n: (.settings.clients|length)}' /usr/local/etc/xray/config.json
  ```

  Сгенерированная ссылка должна быть `type=xhttp`, порт `443` (публичный REALITY-порт, не 8001),
  нести параметры REALITY от `vless-in` и **не** нести `flow`.
- Создайте ключ **VLESS (TCP)** и убедитесь, что он попал **только** в `vless-in`.
- Удалите оба и убедитесь, что каждый исчезает из своего inbound.
- Убедитесь, что существующий (legacy) ключ всё ещё работает и помечен `VLESS (TCP)`.

## Откат

- **Код:** откатите деплой через git.
- **Конфиг Xray:** восстановите timestamped-бэкап и перезапустите Xray:

  ```bash
  cp -a /usr/local/etc/xray/config.json.bak.<ts> /usr/local/etc/xray/config.json
  systemctl restart xray
  ```

  (Правил firewall откатывать не нужно — XHTTP-inbound был loopback-only.)

- **Только фича (оставить inbound):** установите `XRAY_XHTTP_ENABLED=false` и перезапустите бота — опция **VLESS (HTTP)** исчезает, и бот игнорирует XHTTP-inbound. (Оставьте уже выданные HTTP-ключи/клиентов на месте или сначала удалите их из бота, прежде чем демонтировать inbound.)
- **DB:** колонка `transport` аддитивна и безвредна; восстанавливайте из DB-бэкапа только при необходимости полного отката.

> Catch-all fallback форвардит **весь** не-совпавший REALITY-трафик на loopback XHTTP-inbound.
> `vless-in` продолжает терминировать REALITY для VLESS (TCP) как раньше; только соединения,
> провалившиеся в fallback, доходят до XHTTP-inbound, где валидируется путь.
