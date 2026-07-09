# WARP: сокрытие исходящего IP

Опциональный серверный модуль, который скрывает исходящий IP сервера для выбранных
приложений-шпионов: направляет их трафик через AmneziaWG-туннель (`out-warp`), так что их
соединения выходят с endpoint туннеля, а не с реального IP сервера, и автоматически
переключается на прямой выход, когда туннель недоступен. **Выключен по умолчанию** и ничего не
делает, пока superadmin не загрузит конфиг и не включит модуль из админ-панели (📡 WARP-туннель).

Все переменные окружения WARP описаны в
[Конфигурация → WARP-сокрытие исходящего IP](configuration.ru.md#warp-сокрытие-исходящего-ip).

## Как это работает

1. `awg-quick up` поднимает интерфейс `out-warp` из `/etc/amnezia/out-warp.conf`.
2. Через `out-warp` добавляются системные маршруты `ip route` для CIDR из конфига.
3. Фоновая asyncio-задача пингует туннель каждые 10 с, учащая до 3 с, как только проба осталась без ответа. После **60 с** непрерывного отсутствия ответа маршруты снимаются (трафик → напрямую); после **60 с** непрерывного успеха — восстанавливаются.
4. Выключение модуля снимает маршруты и опускает интерфейс.

> **Шаги 1–4 описывают legacy-режим (не observer).** Продовый дефолт —
> **observer-режим** (см. ниже): интерфейсом и маршрутами владеет systemd, бот их не
> добавляет и не снимает.
>
> **Семантика отказа зависит от режима.** В legacy-режиме падение туннеля *снимает*
> маршруты, и маскируемый трафик уходит **напрямую с реальным IP сервера** —
> доступность важнее маскировки. Если нужно наоборот (fail-closed), включите
> **kill-switch** (⚙️ Настройки): при падении туннеля маршруты *сохраняются*, и
> маскируемый трафик блэкхолится на мёртвом интерфейсе, а не утекает с реальным IP.
> Kill-switch **по умолчанию выключен** и действует только в legacy-режиме — в
> observer-режиме маршрутами владеет systemd, и fail-closed обеспечивает
> `warp-failsafe`, а не бот.
>
> Независимо от маршрутов, детектор **деградации** следит за скользящим окном проб и
> предупреждает администраторов, когда туннель постоянно теряет пробы, но *не*
> проваливается непрерывно (то есть latch «down» не срабатывает). Это только
> предупреждение — маршруты не трогаются, а единичная потеря пробы его не поднимает.

Бот работает непривилегированно: каждое root-действие проходит через sudo-хелперы
`vpn-bot-warp-*`. Системный DNS-резолвер не трогается. Маршруты по умолчанию (`0.0.0.0/0`, `::/0`)
в `AllowedIPs` молча пропускаются routes-хелпером, чтобы не изолировать хост случайно — при
пропуске хелпер пишет предупреждение. Если нужен full-tunnel, настройте отдельную таблицу
маршрутизации и policy-правила вне бота, а не через `AllowedIPs`.

## Формат конфига

Загрузите клиентский конфиг **AmneziaWG** (не обычный WireGuard) как документ `.conf`. Он должен
содержать `[Interface]`/`[Peer]`, `PrivateKey`/`PublicKey`/`Endpoint`, поля обфускации AmneziaWG
(`Jc`, `S1`, `S2`, …) и непустой `AllowedIPs`. Модуль уводит в туннель **всех
AmneziaWG-клиентов** (`10.0.0.0/24`), так что исходящий IP клиентов — это endpoint WARP, а не
реальный IP сервера, при этом сам хост (SSH, бот, обновления) всегда остаётся на прямом пути.
Используйте full-tunnel `AllowedIPs = 0.0.0.0/0, ::/0`, чтобы `Table = auto` построил маршрут по
умолчанию туннеля. `AllowedIPs` никогда не изменяется: install-хелпер дословно извлекает его в
`/etc/amnezia/out-warp-routes.list` (один CIDR на строку, для счётчика маршрутов в админ-панели).

> **Примечание:** хост защищён по дизайну — `vpn-bot-warp-routes` снимает host-bypass awg-quick
> сразу после подъёма интерфейса и ставит одно узкое правило `from 10.0.0.0/24`, поэтому
> full-tunnel `AllowedIPs` никогда не утянет хост (или вашу SSH-сессию) в туннель. Хелпер делает
> самопроверку и откатывается к прямому выходу клиентов, если она не прошла.

При установке хелпер удаляет любую строку `DNS = …`, принудительно ставит `Table = auto` в
`[Interface]` (обязательно — это задаёт fwmark WG-сокета и динамическую таблицу маршрутизации;
прежний `Table = off` создавал петлю маршрутизации) и добавляет `PersistentKeepalive = 25` в
`[Peer]`, если их нет.

## Установка

`awg-quick`/`awg` (userspace-инструменты AmneziaWG) должны быть установлены в
`/usr/bin/awg-quick` / `/usr/bin/awg`. Установите хелперы и выдайте sudo (см.
[`../deploy/helpers/README.md`](../deploy/helpers/README.md) и `deploy/sudoers.d/vpn-bot.example`):

```bash
install -o root -g root -m 0755 scripts/vpn-bot-warp-install /usr/local/sbin/vpn-bot-warp-install
install -o root -g root -m 0755 scripts/vpn-bot-warp-iface   /usr/local/sbin/vpn-bot-warp-iface
install -o root -g root -m 0755 scripts/vpn-bot-warp-routes  /usr/local/sbin/vpn-bot-warp-routes
install -o root -g root -m 0755 scripts/vpn-bot-warp-status  /usr/local/sbin/vpn-bot-warp-status
install -o root -g root -m 0440 deploy/sudoers.d/vpn-bot.example /etc/sudoers.d/vpn-bot
visudo -cf /etc/sudoers.d/vpn-bot
```

Если `awg-quick` отсутствует, модуль отказывается стартовать и показывает понятную ошибку в
админ-панели.

## Владение интерфейсом и маршрутами (observer mode)

В режиме observer (по умолчанию) у интерфейса `out-warp` и его policy-маршрутов один владелец —
**systemd**. Интерфейс поднимает `awg-quick@out-warp.service`, а policy-правила/маршруты ставит
`warp-routes.service`; health-монитор бота — чистый наблюдатель: он сообщает о состоянии туннеля,
но никогда не запускает `awg-quick`, `ip route` или `ip rule`. Это убирает флаппинг, возникавший,
когда `warp-routes.service` (на загрузке) и монитор бота боролись за одни и те же записи
`ip rule`/`ip route`. Тумблер WARP в админ-панели теперь запускает/останавливает **только**
наблюдающий монитор — его выключение больше не роняет туннель и не стирает маршруты.

Разверните оба юнита (сначала интерфейс, затем маршруты поверх него):

```bash
# awg-quick резолвит имя "out-warp" в /etc/amnezia/amneziawg/out-warp.conf, а install-хелпер
# пишет канонический конфиг в /etc/amnezia/out-warp.conf — направьте имя на него симлинком:
mkdir -p /etc/amnezia/amneziawg
ln -sf /etc/amnezia/out-warp.conf /etc/amnezia/amneziawg/out-warp.conf
systemctl enable --now awg-quick@out-warp
systemctl enable --now warp-routes.service
```

## WARP proxy egress (маскировка исходящего IP прокси)

По умолчанию WARP заворачивает только **клиентскую** подсеть AmneziaWG (`10.0.0.0/24`).
Локальные egress-прокси — Dante SOCKS5, Xray VLESS, MTProto — продолжают выходить с реального IP
хоста. Включение **proxy egress** заворачивает в туннель и их, маскируя исходящий IP так же, как
у клиентов.

Локальный прокси нельзя матчить по source-подсети: его пакеты несут реальный IP хоста, а
`MASQUERADE -o out-warp` **не** переписывает locally-generated пакеты после fwmark-reroute (они
уходили бы в туннель с IP хоста, и WARP их дропал бы). Решение — сделать inner-src равным IP
туннеля (`[Interface] Address`, напр. `172.16.0.2`) двумя способами:

- **Source-bind демоны** (Dante, Xray) биндят source egress на IP туннеля; `vpn-bot-warp-routes` добавляет одно правило `ip rule from <tunnel-ip> lookup <T>` и **NAT не нужен** (src уже корректный):
  - **Xray** — управляется ботом. `config.json` перезаписывается ботом, поэтому ручная правка слетает; вместо неё ставьте `WARP_PROXY_EGRESS=true`, и генератор конфига эмитит `"sendThrough": "<tunnel-ip>"` на **freedom outbound** при каждой записи (трогается только outbound — гибридные REALITY/XHTTP inbound не задеты).
  - **Dante** — *не* управляется ботом (prerequisite). В `/etc/danted.conf` поставьте `external: 172.16.0.2` (IP туннеля) вместо WAN-устройства и установите drop-in `deploy/danted-warp.conf`, чтобы демон стартовал после подъёма туннеля.
- **MTProto / mtg** не умеет source-bind. `vpn-bot-warp-routes` помечает egress его юнита по cgroup (`fwmark 0x2`) и добавляет **явный SNAT** на IP туннеля, вставкой *перед* широким `out-warp` MASQUERADE. Так как матч `-m cgroup --path` требует существующего cgroup демона, drop-in `deploy/mtproxy-warp.conf` переприменяет правило из привилегированного `ExecStartPost` после старта mtg.

IP туннеля нигде не хардкодится — и `vpn-bot-warp-routes`, и генератор Xray читают его из
`[Interface] Address`. Рецепт `add`/`del` идемпотентен и безопасен при отсутствии демона.

> ⚠️ **Активация — это правка host-routing**: ошибка с разрывом SSH = reboot. Переключайтесь с
> ручной схемы `warp-clients.service` на схему бот/systemd осознанно, в нерабочее время и с
> доступом к консоли:
>
> 1. Сделайте бэкап рабочей конфигурации (снимок `.WORKING`).
> 2. `deploy/setup-nonroot-helper-mode.sh` — обновите хелперы в `/usr/local/sbin`.
> 3. Переустановите конфиг туннеля, чтобы в `[Interface]` был `Table = auto` (`vpn-bot-warp-install`).
> 4. Настройте source-bind прокси: `external: 172.16.0.2` в `danted.conf`; `WARP_PROXY_EGRESS=true` в `.env` (Xray `sendThrough` тогда эмитит бот).
> 5. Установите ordering drop-in'ы:
>    ```bash
>    install -m 700 -d /etc/systemd/system/danted.service.d
>    install -m 644 deploy/danted-warp.conf  /etc/systemd/system/danted.service.d/vpn-bot-warp.conf
>    install -m 700 -d /etc/systemd/system/mtproxy.service.d   # только если MTProto включён
>    install -m 644 deploy/mtproxy-warp.conf /etc/systemd/system/mtproxy.service.d/vpn-bot-warp.conf
>    systemctl daemon-reload
>    ```
> 6. `systemctl disable --now warp-clients.service` (старая схема), затем `systemctl enable --now awg-quick@out-warp warp-routes.service`.
> 7. **Reboot** (не live-restart — флип host-routing может разорвать SSH-окно), затем проверьте: хост сообщает `warp=off` и SSH жив, а AWG / Dante / Xray (и MTProto, если включён) сообщают `warp=on` (`curl -s https://www.cloudflare.com/cdn-cgi/trace`).
> 8. **Откат:** заново включите `warp-clients.service`, восстановите снимок `.WORKING` и перезагрузитесь.

## Активация WARP selective-split и boot-failsafe

Selective-split направляет через WARP только префиксы из `/etc/vpn-bot/warp-split.list`; остальной
трафик выходит напрямую через `eth0`. Boot-failsafe предотвращает блокировку SSH после
перезагрузки при неправильно настроенном туннеле.

Оба компонента — **аддитивный слой** поверх full-tunnel базы (`warp-routes.service`).
`AllowedIPs = 0.0.0.0/0` остаётся в `out-warp.conf` — split-маршрутизация работает полностью
через routing table, а не через WireGuard.

**Предусловие:** `awg-quick@out-warp` и `warp-routes.service` уже включены и протестированы
(full-tunnel работает).

### Runbook активации

1. **Базовый full-tunnel** — включите туннель, если ещё не запущен:

   ```bash
   sudo systemctl enable --now awg-quick@out-warp warp-routes.service
   ```

2. **Установка нового слоя** (запускать из корня репозитория от root):

   ```bash
   sudo bash deploy/setup-nonroot-helper-mode.sh
   ```

   Скрипт устанавливает `vpn-bot-warp-split`, `warp-failsafe`, их unit-файлы, перезагружает
   systemd и обновляет danted drop-in (удаляет устаревший `10-after-warp.conf`). Unit'ы **не**
   включаются автоматически.

3. *(Опционально)* **Включение selective-split:**

   ```bash
   sudo cp deploy/warp-split.list.example /etc/vpn-bot/warp-split.list
   # Отредактируйте список — добавьте/уберите CIDR. Широкие диапазоны предпочтительнее /32.
   sudo systemctl enable --now vpn-bot-warp-split
   ```

4. **Включение boot-failsafe** (рекомендуется всегда):

   ```bash
   sudo systemctl enable warp-failsafe
   ```

5. **Reboot** и проверка:

   ```bash
   # Исходящий egress хоста должен быть прямым (eth0), не через туннель
   ip route get 1.1.1.1          # → dev eth0

   # Таблица selective routing (T = decimal от `awg show out-warp fwmark`):
   T=$(printf '%d\n' "$(awg show out-warp fwmark)")
   ip route show table "$T"      # нет 'default dev out-warp'; видны префиксы

   # Клиентский трафик: listed-префикс → out-warp, не-listed → eth0
   ip route get 91.108.4.1  iif awg0   # → dev out-warp
   ip route get 8.8.8.8     iif awg0   # → dev eth0 (если 8.8.8.0/24 не в списке)

   # Прокси-сервисы работают
   sudo systemctl is-active danted
   ```

6. **Убедитесь в росте WARP transfer** на Telegram-фетче:

   ```bash
   awg show out-warp transfer
   # выполните любой запрос через Telegram; перепроверьте — счётчики rx/tx должны вырасти
   ```

### Откат

- **Только selective-split:** `sudo systemctl disable --now vpn-bot-warp-split` + reboot → возврат к full-tunnel (весь клиентский трафик идёт через WARP).
- **Полный откат WARP:** `sudo systemctl disable --now warp-routes awg-quick@out-warp` + reboot.

### Кнопки Вкл/Выкл/Перезапустить (управление РОУТАМИ split)

Кнопки **Включить / Выключить / Перезапустить** в панели «Сокрытие outbound IP» управляют именно
split-**маршрутами** в динамической таблице `T`, а НЕ туннелем: интерфейс `out-warp` и процесс
`awg-quick@out-warp` остаются под управлением systemd (observer-модель), бот их не трогает.

- **Выключить** — реконсайл таблицы `T` в пусто: снимаются все per-prefix маршруты `<prefix> dev out-warp`, весь клиентский/прокси-трафик идёт напрямую. Сохранённый список `/etc/vpn-bot/warp-split.list` **не стирается**, а анти-луп `162.159.195.1/32 via eth0-gw`, `ip rules` и NAT/FORWARD не трогаются.
- **Включить** — реконсайл таблицы `T` обратно в сохранённый список (selective).
- **Перезапустить** — флаш затем повторное применение списка (итог: включено).

Состояние **персистентно**: при «выключено» создаётся root-owned маркер
`/etc/vpn-bot/warp-split.disabled`, который `vpn-bot-warp-split` учитывает на каждом boot-apply —
поэтому «выключено» переживает перезагрузку. Все мутации таблицы `T` проходят через
`vpn-bot-warp-split-state` (sudo-грант строго на вербы `on|off|restart|status`, без wildcard).
Строки «Туннель» (observer) и «Маршруты» (намерение маркера + фактическая таблица `T`) в панели
берутся из `status()`; при рассинхроне отображается предупреждение, статус не падает ни в одном
состоянии. Когда фактическую таблицу `T` прочитать не удалось, строка «Маршруты» помечается
«(факт. таблица не прочитана)», а не выдаётся за подтверждённое совпадение.

### Kill-switch (fail-closed при падении туннеля)

В под-панели **⚙️ Настройки** есть тумблер **🛡 kill-switch**, сохраняемый в
`warp_settings.kill_switch`, **по умолчанию выключен**. Когда включён, падение туннеля в
legacy-режиме сохраняет маршруты, и маскируемый трафик блэкхолится на мёртвом интерфейсе, а не
уходит напрямую с реальным IP сервера. Это бот-контроль, поэтому он действует только в
legacy-режиме; в observer-режиме маршрутами владеет systemd, и fail-closed там обеспечивает
`warp-failsafe`.

### Управление split-листом из бота (суперадмин)

После активации `vpn-bot-warp-split` список префиксов можно вести прямо из Telegram, без SSH:

- **GUI:** под-панель **«Настройки WARP»** (⚙️ Настройки) содержит кнопку **🌐 Split-маршруты**, открывающую постраничную панель (≈8 префиксов на страницу, у каждого 🗑), плюс **➕ Добавить** (прислать один или несколько IPv4 CIDR через пробел/запятую/перенос строки), **🔄 Применить** (переприменить текущий список) и подтверждение Да/Нет перед каждым удалением. (Точка входа переехала сюда из главной WARP-панели; «Назад» возвращает в Настройки.)
- **Команды:** `/warp_split_list`, `/warp_split_add <cidr…>`, `/warp_split_del <cidr…>`, `/warp_split_reload`.

Оба пути — это только представление поверх `WarpSplitManager`: ввод только IPv4 с обязательной
маской, host-биты нормализуются, guard-диапазоны (`0.0.0.0/0`, клиентская подсеть AWG,
`172.16.0.0/12`, loopback/link-local/multicast, собственная подсеть `eth0` сервера) отклоняются,
дубли пропускаются, опустошение списка запрещено. Бот никогда не вызывает `ip`/`iptables` —
запись только через привилегированный хелпер.
