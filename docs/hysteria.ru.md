# Hysteria2 (apernet v2)

Опциональный третий тип VPN-ключей рядом с Xray VLESS Reality и AmneziaWG. Бот умеет выдавать,
отзывать и удалять Hysteria2-ключи **без перезапуска data plane**: отзыв вступает в силу на
следующем handshake. Hysteria2 **выключена по умолчанию** (`HYSTERIA2_ENABLED=false`) и работает
как **самостоятельный data plane**, независимо от процесса бота.

Эта страница — точка входа. Канонические справочники лежат там же, где и для остальных бэкендов:

- **Переменные окружения** → [Конфигурация → Hysteria2](configuration.ru.md#hysteria2)
  (все `HYSTERIA2_*` и `ANOMALY_HYSTERIA2_MAX_CONN`, дефолты, MITM-tradeoff `HYSTERIA2_INSECURE`
  и Traffic Stats API).
- **Серверная установка** → [Развёртывание → Hysteria2 data plane](deployment.ru.md#hysteria2-data-plane-эндпоинт-hy2_auth).
- **Health, смысл degraded и восстановление** → [Эксплуатация → Health и восстановление Hysteria2](operations.ru.md#health-и-восстановление-hysteria2).

## Как это работает

Три части, и только одна из них — бот:

1. **Сервер `hysteria`** (apernet v2) — собственно data plane, настроенный с `auth: type: http`
   в `/etc/hysteria/config.yaml`. Терминирует клиентские QUIC/Salamander-сессии на публичном
   **UDP**-порту `HYSTERIA2_PORT` (дефолт `15650`).
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
(`key_type='hysteria2'`, персональный секрет в `payload_json`, stats-label `hy2_<hex>`).

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
| Выдача / отзыв / удаление | `HYSTERIA2_HOST`, `HYSTERIA2_SNI`, `HYSTERIA2_OBFS_PASSWORD` | Чистые записи в `vpn.db`; действуют на следующем handshake. |
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
