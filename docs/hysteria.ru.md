# Hysteria2 (apernet v2)

Опциональный третий тип VPN-ключей рядом с Xray VLESS Reality и AmneziaWG. Бот умеет выдавать,
отзывать и удалять Hysteria2-ключи **без перезапуска data plane**: отзыв вступает в силу на
следующем handshake. Hysteria2 **выключена по умолчанию** (`HYSTERIA2_ENABLED=false`) и работает
как **самостоятельный data plane**, независимо от процесса бота.

Эта страница — точка входа. Канонические справочники лежат там же, где и для остальных бэкендов:

- **Переменные окружения** → [Конфигурация → Hysteria2](configuration.ru.md#hysteria2)
  (все `HYSTERIA2_*` и `ANOMALY_HYSTERIA2_MAX_CONN`, дефолты, `HYSTERIA2_INSECURE`
  и Traffic Stats API).
- **Серверная установка** → [Развёртывание → Hysteria2 data plane](deployment.ru.md#hysteria2-data-plane-эндпоинт-hy2_auth).
- **Health, смысл degraded и восстановление** → [Эксплуатация → Health и восстановление Hysteria2](operations.ru.md#health-и-восстановление-hysteria2).

## Как это работает

Три части, и только одна из них — бот:

1. **Сервер `hysteria`** (apernet v2) — собственно data plane, настроенный с `auth: type: http`
   в `/etc/hysteria/config.yaml` (трекнутый источник: `deploy/hysteria/config.yaml`, устанавливается
   через `sudo bash deploy/hysteria/install-config.sh` — **никогда** не голым `cp`, т.к.
   `trafficStats.secret` в трекнутом файле — плейсхолдер, и именно установщик подставляет
   настоящий `HYSTERIA2_STATS_SECRET` из `.env`). Терминирует клиентские сессии на чистом QUIC —
   без salamander-обфускации — на публичном **UDP**-порту `HYSTERIA2_PORT` (дефолт `443`;
   сосуществует с Xray REALITY на TCP/443), предъявляя валидный сертификат Let's Encrypt для
   домена сервера (выпускается/продлевается `acme.sh` вне этого репозитория). Перед рестартом
   сервиса запускайте `deploy/hysteria/preflight-udp443.sh`. **Раскладка** продлённого
   сертификата — копирование новой цепочки в `/etc/hysteria/cert.pem`/`key.pem` с владельцем
   `hysteria` и рестарт сервиса — делается трекнутым хуком `deploy/vpn-bot-acme-reload.sh`,
   подключённым как `--reloadcmd` у acme.sh
   ([Подписка → TLS-терминация](subscription.ru.md#tls-терминация)).
2. **Эндпоинт `hy2_auth`** (`python -m hy2_auth`, `deploy/vpn-bot-hy2-auth.service`) — небольшой
   **отдельный** процесс, к которому сервер `hysteria` обращается по loopback на каждый handshake.
   Он открывает `vpn.db` **read-only** и проверяет персональный токен ключа в постоянное время
   (`hmac.compare_digest`), всегда отвечая HTTP 200 с `{"ok": <bool>, "id": "<label>"}` и
   отказывая **fail-closed**. Так как он читает **живую** базу, отзыв/удаление/истечение
   применяются на следующем handshake — без apply-шага и перезапуска. Он не импортирует
   `bot`/`aiogram` и продолжает работать, пока `vpn-bot.service` выключен.
   - Маршруты: `POST /auth` (авторизация handshake) и `GET /healthz` (`200 {"ok":true}`, когда БД
     читается, иначе `503` — годится для watchdog или `curl http://127.0.0.1:8444/healthz`).
3. **Traffic Stats API** (опционально) — loopback-HTTP-сервер, который поднимает сам
   `hysteria-server` (`trafficStats: {listen, secret}` в `config.yaml`). Бот только **читает** его
   (`GET /traffic`, `GET /online`) и POST-ит `/kick`. Он даёт per-key трафик, счётчик онлайна,
   детект аномалий по одновременным подключениям и **немедленный разрыв сессии при
   revoke/delete/expiry/block**. Гейтится `HYSTERIA2_STATS_SECRET`: без секрета вся эта
   поверхность инертна — hy2-ключи не показывают трафик/онлайн, а отзыв блокирует только новые
   handshake (живая сессия живёт до переподключения).

Сам бот не биндит ни один из этих портов; он лишь читает stats/health API (через
`adapters/hysteria_stats.py` / `adapters/hysteria_auth_health.py`) и пишет строки `vpn_keys`
(`key_type='hysteria2'`, персональный секрет в `payload_json`, stats-label `hy2_<rnd>`).

### Имя auth-юнита: репо против хоста (зафиксированное намеренное расхождение)

Трекнутый unit-файл — `deploy/vpn-bot-hy2-auth.service`, но на хосте, поднятом до переименования
`vpnbot-*` → `vpn-bot-*`, **установлен** юнит `vpnbot-hy2-auth.service`. Это legacy-имя оставлено
**намеренно** — как и `vpnbot-hy2-warp-mark`, это не техдолг, и «исправлять» его переименованием
нельзя; они двое — единственные наследники старого написания.

Мостом между ними служит `.env`: именно на `HYSTERIA2_AUTH_SERVICE_NAME` админ-диагностика бота
вызывает `systemctl is-active`, поэтому она следует за тем именем, которое использует хост. В
`.env.example` лежит дефолт **`vpn-bot-hy2-auth`**, так что хост с legacy-юнитом **обязан**
прописать legacy-имя в своём `.env` — иначе диагностика будет показывать auth-sidecar неактивным,
пока handshake'и продолжают успешно проходить.

Два следствия в Phase 1 `scripts/deploy.sh`, которые являются **ожидаемым выводом, а не ошибкой**:

- `UNIT_SET` собирает basename каждого поставляемого `deploy/*.service`, поэтому содержит
  `vpn-bot-hy2-auth.service`. На хосте с legacy-именем этот юнит `load=not-found`, и Phase 1
  сообщает о нём как о *не установленном / пропущенном*.
- Юнит, который реально обслуживает handshake'и, `vpnbot-hy2-auth.service`, попадает в `UNIT_SET`
  только через ветку, производную от `.env` — то есть **только потому, что его называет
  `HYSTERIA2_AUTH_SERVICE_NAME`**. Очистите этот ключ — и живой sidecar молча перестанет
  отслеживаться.

Посмотреть фактическое состояние своего хоста (только чтение):

```bash
systemctl list-units --all 'vpn*hy2-auth*'
grep -n '^HYSTERIA2_AUTH_SERVICE_NAME' /opt/vpn-service/.env
```

### Маскарад-decoy (статический файл)

`deploy/hysteria/config.yaml` включает файловый masquerade Hysteria2 (`masquerade.type: file`,
`masquerade.file.dir: /etc/hysteria/masq`): пробе, которая не завершает Hysteria2-handshake,
отдаётся статический сайт из этого каталога вместо разрыва соединения. *Контент*
`/etc/hysteria/masq` **не** трекается в этом репозитории и не может — см.
[Как decoy держится в синхроне](#как-decoy-держится-в-синхроне-vpn-bot-decoy-freshensh) ниже про
то, что его на самом деле наполняет и почему сам сайт остаётся за бортом; `install-config.sh` этот
каталог не трогает. `listenHTTP`/`listenHTTPS` не настроены, так как они
открыли бы отдельные plaintext TCP-листенеры `:80`/`:443`, а TCP/443 на этом хосте уже занят Xray
REALITY — decoy отдаётся по существующему UDP/443-пути.

### Как decoy держится в синхроне (`vpn-bot-decoy-freshen.sh`)

Два data plane на этом хосте отвечают пробе сайтом, а не разрывом, и отвечать они обязаны
**одним и тем же**:

| Плоскость | Порт | Откуда отдаёт decoy |
|---|---|---|
| Xray REALITY (self-steal `target`) | TCP/443 → loopback-vhost | docroot nginx, `DECOY_ROOT` |
| Hysteria2 (`masquerade.type: file`) | UDP/443 QUIC | `MASQ_DIR` = `/etc/hysteria/masq` |

Само по себе ничто эти два дерева в синхроне не держит, а Hysteria2 читает свою копию под
непривилегированным пользователем, которому нечего делать в docroot'е nginx.
`deploy/vpn-bot-decoy-freshen.sh` — трекнутая параметризованная форма этого зеркалирования:
`rsync -a --delete` из `DECOY_ROOT` в `MASQ_DIR`, затем `chown` в `MASQ_OWNER:MASQ_GROUP`. **Это и
есть ответ на вопрос «кто наполняет `/etc/hysteria/masq`» — руками его туда не кладут.**

Он же прогоняет пасс «свежести». Статический decoy, у которого «last updated» полугодовой
давности, — сам по себе tell, поэтому сайт несёт скользящие даты, и кто-то должен их продвигать.
Этот перезаписыватель **намеренно не трекается здесь и не может**: он неизбежно кодирует разметку
самого decoy — какие файлы, какие паттерны, какая вымышленная история инцидентов, — а этот контент
уникален для деплоя, и в нём весь смысл decoy. Он остаётся локальным для деплоя скриптом, который
этот хук лишь *вызывает*, через `DECOY_FRESHEN_HOOK`. Если переменная не задана — пасс свежести
пропускается, а зеркалирование всё равно идёт.

Установка — без шага копирования, запускается из чекаута, как `deploy/vpn-bot-acme-reload.sh`.
Намеренно **cron, а не systemd-юнит**: basename каждого `deploy/*.service` попадает в `UNIT_SET`
deploy.sh ([`deploy/managed-units.list`](../deploy/managed-units.list)), поэтому поставлять юнит
для работы, которую хост крутит из cron, значило бы заставить Phase 1 сообщать о нём как о
неустановленном на каждом деплое — то есть открыть новое расхождение репо↔хост вместо того, чтобы
закрыть старое.

```bash
sudo chmod 0755 /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh
# сначала проверка, только на чтение, не дожидаясь cron-окна
sudo DECOY_ROOT=/var/www/<DECOY_SITE> /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh --dry-run
sudo crontab -e
# минуту берите вне пиков; от точного времени ничего не зависит
7 3 * * * DECOY_ROOT=/var/www/<DECOY_SITE> /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh >/dev/null 2>&1
```

У `DECOY_ROOT` **намеренно нет дефолта**. `rsync --delete` деструктивен by design: направленный на
отсутствующий или пустой источник, он добросовестно опустошит `MASQ_DIR`, и Hysteria2 начнёт
отвечать пробам голым 404, пока nginx продолжает отдавать сайт. Расхождение между двумя
плоскостями — ровно тот tell, ради устранения которого весь механизм и существует, поэтому скрипт
fail-loud отказывается работать **до** того, как что-либо тронуто, если `DECOY_ROOT` не задан,
отсутствует или не содержит `INDEX_NAME`.

nginx здесь перезагружать не нужно — он отдаёт `DECOY_ROOT` с диска на каждый запрос (`try_files`),
так что перезаписанный файл виден сразу. Перезагрузка ему нужна после продления **сертификата**, и
это задача [`deploy/vpn-bot-acme-reload.sh`](../deploy/vpn-bot-acme-reload.sh), а не этого скрипта.


### Потолок полосы на клиента (Brutal)

`deploy/hysteria/config.yaml` объявляет потолок скорости:

```yaml
bandwidth:
  up: 95 mbps
  down: 95 mbps
```

Серверные значения — это лимит **на каждого клиента**, а не суммарный шейпер на машину: каждый
клиент держится в этих рамках, они не делят их между собой. Серверный `up` — это потолок
**download** у клиента, серверный `down` — потолок его **upload**; фактическая ставка в каждую
сторону равна `min(значение клиента, значение сервера)`. Ноль или отсутствующее значение с любой
стороны означает *без лимита* для этого направления, поэтому отсутствие блока было бы не
консервативным дефолтом, а полным отсутствием потолка. `ignoreClientBandwidth` намеренно **не**
задан: это взаимоисключающая альтернатива — он целиком игнорирует заявку клиента и включает
не-Brutal-контроллер, из-за чего значения выше теряют смысл. Как и любой другой ключ этого файла,
правка вступает в силу только после следующего `systemctl restart hysteria-server` — а рестарт
рвёт живые QUIC-сессии, так что делайте это в тихое окно.

**Как включить Brutal на стороне клиента.** Ссылки `hysteria2://`, которые выдаёт бот, не несут
параметров полосы, поэтому по умолчанию все клиенты идут на **BBR**, реагирующий на потери. Кому
нужен отправитель **Brutal** — добавляет секцию `bandwidth` в свой клиентский профиль (поля есть
в v2rayN / NekoBox / Happ), указывая **свои реальные скорости канала**, а не серверный потолок:

```yaml
bandwidth:
  up: 20 mbps     # ваш реальный upload
  down: 100 mbps  # ваш реальный download
```

Согласно официальной документации Hysteria 2, больше — **не** значит лучше: Brutal не измеряет
канал, а шлёт с той ставкой, которую ему назвали, и не снижает темп при потерях. Значение выше
того, что канал реально тянет, даёт обратный эффект — перегрузку и нестабильное соединение, а не
скорость. Сервер срежет всё, что выше `95 mbps`, но исправить завышенное значение ниже этой
планки он не может.

### Маркировка WARP-egress (`vpnbot-hy2-warp-mark`)

Когда развёрнут WARP split-tunnel, `vpnbot-hy2-warp-mark` fwmark-ит локально-порождённые
пакеты Hysteria2 (по owner-uid) в WARP policy-таблицу, чтобы hy2-egress подчинялся тому же
сплиту, что и остальной WARP. Это **tracked**-хелпер (`scripts/vpnbot-hy2-warp-mark`), который
**самоустанавливается** в Phase 2 `scripts/deploy.sh` (`install_out_of_repo_helpers`) — так же,
как WARP-хелперы: `sudo bash scripts/redeploy.sh` держит
`/usr/local/sbin/vpnbot-hy2-warp-mark` в синхроне с чекаутом, ручная установка после деплоя не
нужна. Его `iptables --sport`-исключение **выводится из `HYSTERIA2_PORT`** (единый источник
правды): порт резолвится из `.env` бота и проверяется на диапазон **до** первого касания сети
(fail-closed на отсутствующем/мусорном/вне-диапазона значении), поэтому порт маркировки не может
разъехаться с портом, который слушает `hysteria-server`. Так как порт живёт в `.env` (не в git),
деплой **переприменяет** `vpnbot-hy2-warp-mark.service`, если он был active до деплоя — чтобы
исключение следовало за текущим `HYSTERIA2_PORT` даже когда файл хелпера не менялся. См.
[deploy/helpers/README.md](../deploy/helpers/README.md#vpnbot-hy2-warp-mark--hysteria2-egress--warp-port-from-hysteria2_port).

## Паритет с Xray/AWG

При `HYSTERIA2_ENABLED=true` Hysteria2 достигает операционного паритета с Xray/AWG:

| Возможность | Требует | Примечания |
|---|---|---|
| Выдача / отзыв / удаление | `HYSTERIA2_HOST`, `HYSTERIA2_SNI` | Чистые записи в `vpn.db`; действуют на следующем handshake. |
| Админ-**диагностика** (`systemctl is-active`) | `HYSTERIA2_SERVICE_NAME`, `HYSTERIA2_AUTH_SERVICE_NAME` | Проверяет `hysteria-server` и `vpn-bot-hy2-auth`. |
| **Backend-health** `Hysteria2: OK/DEGRADED` | `HYSTERIA2_HEALTH_INTERVAL` (>0) | Только liveness data plane — **никогда не блокирует** выдачу/отзыв (в отличие от Xray/AWG). |
| Офсайтовый **бандл восстановления** | `OFFSITE_BACKUP_INCLUDE_CONFIGS=true` | Кладёт `HYSTERIA2_CONFIG_PATH` (`/etc/hysteria/config.yaml`). |
| Per-key **трафик**, счётчик **онлайна**, revoke-**/kick**, аномалия по одновременным конн. | `HYSTERIA2_STATS_SECRET` (+ `ANOMALY_HYSTERIA2_MAX_CONN` для аномалии) | Доступно только из Traffic Stats API; бот не может это синтезировать. |

> **Единственная асимметрия — намеренная:** отметка `Hysteria2: DEGRADED` **информационная** и не
> гейтит мутации, так как у Hysteria2 нет config-apply-шага — см.
> [Эксплуатация → Health и восстановление Hysteria2](operations.ru.md#health-и-восстановление-hysteria2).

## Клиентские приложения

Hysteria2-ключи выдаются как **ссылка** (без `.conf`-файла). Рекомендуемые GUI-клиенты:
NekoBox / Hiddify / Happ / sing-box. Пользовательские подсказки — в in-bot FAQ («Помощь»).
