# Глубокий ревью слоя SQLite (репозитории + схема + модели)

Дата: 2026-07-03 · Область: только `repositories/*.py`, `db/database.py`,
`db/schema.sql`, `db/exceptions.py`, `db/migrations/*.sql`, `models/dto.py`,
`models/enums.py`, `models/access.py`. Правок в код не вносилось — только находки.

---

## 1. Резюме

### По серьёзности

| Серьёзность | Кол-во | ID |
|---|---|---|
| Critical | 0 | — |
| High | 1 | P2-001 |
| Medium | 3 | P2-002, P2-004, P2-006 |
| Low | 6 | P2-003, P2-005, P2-007, P2-009, P2-013, P2-015 |
| Info | 5 | P2-008, P2-010, P2-011, P2-012, P2-014 |

### По категориям

| Категория | ID |
|---|---|
| SQL-инъекция | **не найдено** (см. §2) |
| Дрейф схемы | P2-001, P2-004 |
| Несовместимость / логика | P2-002, P2-010, P2-011 |
| Потенциальный баг / гонка | P2-006, P2-009, P2-013 |
| Баг (латентный) | P2-003 |
| Несоответствие кода и документации | P2-004, P2-007, P2-008, P2-015 |
| Жаргон / нейминг | P2-005, P2-012 |
| Прочее | P2-014 |

**Общая оценка.** Слой доступа к БД написан аккуратно: все значения идут через
плейсхолдеры, транзакции сериализуются через `asyncio.Lock`, включён WAL,
`busy_timeout`, проверки ссылочной целостности и enum на бутстрапе. Критических
проблем и инъекций нет. Основные риски — точечный дрейф схемы (hysteria2 в
пробных заявках), расхождение аудитории рассылок и неполнота файлов миграций
027–029.

---

## 2. SQL-инъекции и дрейф схемы (приоритетный раздел)

### 2.1 SQL-инъекции — не найдено

Проверена каждая f-строка с SQL во всех репозиториях и в `db/database.py`.
Во ВСЕ f-строки подставляются исключительно:

- сгенерированные плейсхолдеры `?` (`",".join("?" for _ in ...)`) — `users`,
  `vpn_keys`, `proxy_accesses`, `audit_log`, `announcements`, `traffic_stats`;
- статические SQL-фрагменты-константы (`after_sql`, `exclude_sql`,
  `deleted_filter`, `action_sql`, `null_filter`, `_SANITIZED_STATS_SELECT`,
  `_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS`);
- имена таблиц/столбцов из внутренних констант в `db/database.py`
  (`_table_columns`, `_validate_*`) — не из пользовательского ввода.

Значения, производные от ввода (telegram id, username, note, фильтры,
LIMIT/OFFSET, threshold_days, login, fingerprint), везде передаются параметрами.
Пользовательских `ORDER BY`/`LIMIT`/имён столбцов из ввода нет.
`_build_segment_where` (`repositories/users.py:49`) — потенциально самое «опасное»
место: но роли/транспорты уходят через `?`, а ветки протоколов выбираются
сравнением с закрытым множеством enum (`VpnKeyType`/`ProxyAccessType`), строка
ввода в SQL не попадает. **Инъекций нет.**

### 2.2 Дрейф схемы — найдено

Ключевые находки — P2-001 (hysteria2 в `trial_key_requests`) и P2-004
(отсутствуют файлы миграций 027–029). Полная матрица — в §5.

---

## 3. Находки (High → Low → Info)

### P2-001 · Дрейф схемы / Потенциальный баг · High · Подтверждено (дрейф) / Вероятно (impact)
**Локация:** `db/schema.sql:86`, `db/database.py:681` (`_migrate_v13`),
`models/enums.py:28-31`, `models/dto.py:186-196`.

`trial_key_requests.key_type` ограничен `CHECK(key_type IN ('xray','awg'))` — и в
baseline-схеме, и в миграции v13. При этом:
- `VpnKeyType` содержит `HYSTERIA2 = "hysteria2"`;
- DTO `TrialKeyRequest.key_type: VpnKeyType`;
- `vpn_keys.key_type` был расширен до `hysteria2` в v29, а `trial_key_requests` —
  **нет** (миграции, аналогичной v29, для этой таблицы не существует).

**Сценарий.** Любая попытка `TrialKeyRequestRepository.create(key_type=HYSTERIA2)`
(`services/trial_access.py:83` пробрасывает `key_type` от вызывающего) приведёт к
`sqlite3.IntegrityError` (нарушение CHECK). Чтение асимметрично: `_row_to_request`
использует `enum_value(VpnKeyType, ...)`, который hysteria2 уже принимает, — то
есть на запись CHECK блокирует, на чтение — пропустил бы. Пока путь достижим лишь
если UI предлагает пробный hysteria2; но это «мина», которая сработает при первом
включении такой опции.

**Рекомендация.** Либо добавить миграцию, перестраивающую `trial_key_requests` с
`CHECK(... IN ('xray','awg','hysteria2'))` (как v29 для `vpn_keys`), либо явно
задокументировать и на уровне сервиса гарантировать, что пробные ключи —
только xray/awg. Заодно — добавить `trial_key_requests` в `_validate_enum_values`
(см. P2-011).

---

### P2-002 · Несовместимость / Потенциальный баг · Medium · Вероятно
**Локация:** `repositories/users.py:13-17` vs `models/dto.py:49-54`.

Аудитория рассылок определена в двух местах по-разному:
- «легаси»/несегментированный путь — `_ANNOUNCEMENT_ROLE_SQL_VALUES =
  (APPROVED_USER, SUPERADMIN)` (2 роли): `count_announcement_recipients`,
  `list_announcement_recipients_after`, `is_announcement_recipient`;
- сегментированный путь с пустым фильтром — `TARGETABLE_ROLES = (SUPERADMIN,
  MODERATOR, APPROVED_USER, PENDING_USER)` (4 роли): `_build_segment_where` при
  `recipient_filter.roles == ()`.

**Сценарий.** «Отправить всем» через сегментацию (пустой `RecipientFilter`,
`is_unfiltered()`) охватывает 4 роли, включая MODERATOR и PENDING_USER, а
«отправить всем» через старый путь — только 2. Итог: PENDING/MODERATOR получают
сегментные рассылки, но не «простые» — разное определение «всех» в одном фича-наборе.
При проверке получателя на этапе доставки (`is_announcement_recipient` vs
`is_segment_recipient`) используется тот же расходящийся критерий — что консистентно
внутри пути, но не между путями.

**Рекомендация.** Свести определение «кому можно слать» к единому источнику
правды (одна константа ролей), либо явно задокументировать, что легаси-«всем» и
сегмент-«всем» — намеренно разные аудитории.

---

### P2-004 · Дрейф схемы / Несоответствие кода и документации · Medium · Подтверждено
**Локация:** `db/migrations/` (только 020..026) vs `db/database.py:18`
(`CURRENT_SCHEMA_VERSION = 29`) и `_migrate_v27/28/29`.

Каталог `db/migrations/` содержит standalone-артефакты 020–026, но программные
миграции доходят до v29. Отсутствуют файлы:
- **027** — `announcement_batches.recipient_filter_json` (`_migrate_v27`);
- **028** — `vpn_keys.xhttp_profile` + переименование email-меток Xray
  (`_migrate_v28`, `_relabel_xray_emails_v28`);
- **029** — расширение CHECK `vpn_keys.key_type` до `hysteria2` + сид протокол-модуля
  `hysteria2` (`_migrate_v29`).

Каждый из файлов 020–026 в шапке обещает: «kept in sync with both `_migrate_vNN`
and `db/schema.sql`». Для 027–029 этого артефакта нет; в частности, засев
`hysteria2` в `protocol_modules` документирован только в `schema.sql:207` и v29 —
файл `021_add_protocol_modules.sql:15-18` сеет лишь 4 протокола.

**Рекомендация.** Либо добавить 027/028/029.sql, либо убрать обещание «kept in
sync» и пометить каталог как иллюстративный (источник правды — `db/database.py`).

---

### P2-006 · Потенциальный баг / Конфликт · Medium · Вероятно
**Локация:** `repositories/vpn_keys.py:453-457`, `repositories/proxy_accesses.py:381-385`.

В `mark_active` (и у ключей, и у proxy) при `cursor.rowcount == 0` (status-guarded
UPDATE не совпал — параллельная модификация) метод лишь пишет `logger.warning` и
**коммитит транзакцию без ошибки**. Вызывающий не может отличить «активировано» от
«пропущено». Это расходится с `set_status`, `mark_revoked`, `mark_deleted`,
`TrialKeyRequestRepository.approve/reject`, которые бросают
`ConcurrentModificationError`/`InvalidTransition`.

**Сценарий.** Параллельный revoke гонится с успешным apply: revoke переводит ключ
в `revoked`, затем `mark_active` не находит строку в `(pending_apply, apply_failed)`
→ тихий no-op. Ключ остаётся `revoked`, но код применения считает, что ключ
активирован (payload проигнорирован). Рассинхрон состояния БД и реального конфига.

**Рекомендация.** Сигнализировать пропуск вызывающему (raise или возврат bool),
чтобы он мог сверить/повторить.

---

### P2-003 · Баг (латентный) · Low · Подтверждено
**Локация:** `db/database.py:280-282`.

Блок `if version < 24:` вызывает `_migrate_v24()` и `_set_schema_version(24)`, но —
в отличие от всех остальных блоков — **не выполняет `version = 24`**. Локальная
переменная `version` остаётся 23. Сегодня безвредно: все последующие проверки
(`if version < 25/26/...`) — строгие `<`, и при `version == 23` они всё равно
истинны, так что миграции 25–29 отработают. Но инвариант «`version` = текущая
персистентная версия» нарушен и сломается, если будущий блок использует `==`/`>`
или будет опираться на точное значение.

**Рекомендация.** Добавить `version = 24` для единообразия и защиты инварианта.

---

### P2-005 · Жаргон / нейминг · Low · Подтверждено
**Локация:** `db/schema.sql:68`, `models/dto.py:176`, `db/database.py:23`
(`_V28_NEW_PREFIXES`).

Значение профиля `xhttp_profile == 'antisib'` — внутренний сленг
(анти-цензура / «анти-СИБ»). Оно попадает не только в служебные комментарии, но и в
реальные email-метки Xray (`xray_http_antisib_<rnd>`), то есть в хранимые
`payload_json`/`public_payload_json` и в live-конфиг Xray.

**Рекомендация.** Переименовать в нейтральное (`hardened`/`evasion`/`profile_b`)
через relabel-миграцию по образцу v28 (учтя, что переименование метки сбрасывает
накопленную per-label статистику Xray — тот же принятый компромисс, что в v28),
либо как минимум явно задокументировать смысл значения.

---

### P2-007 · Несоответствие кода и документации / нейминг · Low · Подтверждено
**Локация:** `repositories/vpn_keys.py:577-600`.

`find_active_awg_ips` (имя обещает «active») просто делегирует в
`get_occupied_awg_ips`, который возвращает IP по **шести** нетерминальным
статусам (`pending_apply, active, apply_failed, pending_revoke, pending_delete,
delete_failed`). Docstring у обоих методов **идентичен** («…reserved by
non-terminal AWG keys»), то есть противоречит имени `find_active_*`. Две публичные
функции делают ровно одно и то же.

**Рекомендация.** Убрать алиас или переименовать в отражающее суть
(`reserved/occupied`); привести docstring в соответствие имени.

---

### P2-009 · Прочее / Робастность миграций · Low · Предположительно
**Локация:** `db/database.py:791-850` (`_migrate_v17`).

`_migrate_v17` перестраивает таблицу `users` **безусловно** (в отличие от v16, где
есть guard `if "scheduled_at" in cols: return`). На свежей БД `schema.sql` уже
создаёт `users` со столбцами v26 (`language`, `expiry_notifications_enabled`), но
`users_new` в v17 объявлен лишь с 9 столбцами — эти два теряются при копировании,
а затем восстанавливаются v26 `ALTER TABLE ADD COLUMN`. Безопасно **только**
потому, что при бутстрапе `users` пуста (сид админов идёт после `bootstrap()`), а
на легаси-БД v17 выполняется лишь при апгрейде с версии <17 (когда этих столбцов
ещё нет). Любое переупорядочивание миграций или наличие данных в `users` на момент
v17 приведёт к тихой потере значений v26-столбцов.

**Рекомендация.** Сделать v17 идемпотентно-условным (как v16) или копировать все
фактически присутствующие столбцы.

---

### P2-013 · Потенциальный баг / гонка · Low · Предположительно
**Локация:** `db/database.py:1401-1451` (`_before_connection_execute`,
`_clear_implicit_write_owner`), проксирование в `_ConnectionProxy`.

Неявная запись захватывает `_transaction_lock` и ставит `_implicit_write_owner`,
освобождая их лишь в последующем `commit()`/`rollback()`. Если задача будет
отменена (CancelledError) в узком окне между возвратом из `execute(write)` и
входом в `commit()`, лок не освободится, и все прочие писатели/читатели-во-время-
записи зависнут до конца процесса. На практике окно крайне мало: сам `commit()`
защищён `try/finally`, а многошаговые операции идут через `transaction()`, чей
`except` освобождает лок. Но конструкция полагается на «нет `await` между
`execute` и `commit`».

**Рекомендация.** Гарантировать освобождение лока структурно (например, все записи
через `transaction()` или контекст-менеджер вокруг неявной записи).

---

### P2-015 · Несоответствие кода и документации / обработка ошибок · Low · Подтверждено
**Локация:** `repositories/users.py:281-289` vs `repositories/vpn_keys.py:555-561`,
`repositories/proxy_entries.py:93-99`.

Обновление заметки трактует «строка не найдена» по-разному:
`UserRepository.update_note/set_language/set_expiry_notifications_enabled` бросают
`NotFound` при `rowcount != 1`, а `VpnKeyRepository.update_note` и
`ProxyRepository.update_note` тихо ничего не делают, если строки нет.

**Рекомендация.** Привести к единому поведению (бросать или явно задокументировать
молчаливый no-op).

---

### P2-008 · Несоответствие кода и документации · Info · Подтверждено
**Локация:** `db/schema.sql:1-8`.

Шапка называет файл «version-1 BASELINE», но фактически он декларирует полное
состояние v29 (`language`, `expiry_notifications_enabled`, `transport`,
`xhttp_profile`, CHECK с `hysteria2`, `scheduled_at`, `recipient_filter_json`, все
settings-таблицы). Работает это потому, что каждая миграция идемпотентна и на
свежей v29-схеме отрабатывает как no-op. Формулировка «version-1» вводит в
заблуждение.

**Рекомендация.** Переформулировать: «снимок текущего состояния схемы,
переустанавливаемый перед миграциями».

---

### P2-010 · Несовместимость / нейминг · Info · Подтверждено
**Локация:** `db/schema.sql` (settings-таблицы) vs остальные таблицы; `models`.

Смешанные представления времени: большинство таблиц хранит TEXT ISO-8601 UTC
(`created_at`, `updated_at`, `requested_at`, `expires_at`, `decided_at`, …), а
`warp_settings`/`server_status_settings`/`maintenance_settings` — INTEGER unix-epoch
(`int(time.time())`); DTO `MaintenanceState.started_at: int`. Межтабличные
сравнения/сортировки по времени между этими группами некорректны, и два формата
легко перепутать.

**Рекомендация.** Явно задокументировать разделение или стандартизировать формат.

---

### P2-011 · Прочее / валидация · Info · Подтверждено
**Локация:** `db/database.py:582-646` (`_validate_enum_values`).

Валидатор enum на бутстрапе покрывает `users`, `access_requests`, `vpn_keys`,
`proxy_entries`, `proxy_accesses`, `announcement_*`, но **не** `trial_key_requests`
(`key_type`, `status`) и **не** `protocol_modules`. В связке с P2-001 некорректное
значение `key_type`/`status` в пробных заявках не будет замечено стартовой
проверкой (только CHECK на запись).

**Рекомендация.** Добавить `trial_key_requests` в набор enum-проверок.

---

### P2-012 · Жаргон / нейминг · Info · Подтверждено
**Локация:** `db/schema.sql:55,250` (`email_label`, `find_by_email_label`),
`db/schema.sql:212` (`config_path DEFAULT '/etc/amnezia/out-warp.conf'`,
`interface_name DEFAULT 'out-warp'`).

- `email_label` — это термин Xray для тега клиента, а не e-mail. Внешнему читателю
  это внутренний жаргон, вводящий в заблуждение (та же метка используется в
  `find_by_email_label`, `idx_vpn_keys_email_label`).
- `out-warp` и хардкод `/etc/amnezia/out-warp.conf` в DEFAULT столбца «зашивают»
  специфичное для деплоя имя в схему.

**Рекомендация.** Задокументировать, что `email_label` — идентификатор клиента
Xray; для WARP — вынести пути в конфиг/оставить комментарий о происхождении имени.

---

### P2-014 · Прочее / согласованность стиля · Info · Подтверждено
**Локация:** `repositories/warp_settings.py`, `server_status_settings.py`,
`maintenance_settings.py` (`self.db.conn.commit()`) vs остальные (`self.db.commit()`);
`repositories/vpn_keys.py:573` (`update_payload`).

- Точка входа коммита неоднородна: три settings-репозитория зовут
  `self.db.conn.commit()`, все прочие — `self.db.commit()` (функционально
  эквивалентно, но стилистически расходится).
- `update_payload` сериализует JSON без `separators=(",", ":")`, тогда как
  `create_pending`/`mark_active`/`update_payloads` используют компактные
  разделители — косметический дрейф в хранимом JSON.

**Рекомендация.** Выбрать один стиль.

---

## 4. Транзакции, конкурентность, WAL (оценка, без отдельных находок)

Смотрелось особо; серьёзных проблем сверх P2-006/P2-009/P2-013 не найдено:

- Единственное соединение aiosqlite; явные транзакции и неявные записи
  сериализованы `_transaction_lock`. Вложенные `transaction()` «сплющиваются»
  (join-семантика), внутренний `commit()` — no-op при открытой явной транзакции —
  корректно для композиции репозиторных записей в один атомарный блок.
- `BEGIN IMMEDIATE` по умолчанию — правильно для «прочитал-проверил-записал»
  (квоты триала, `mark_active`, `mark_expiry_notified`).
- WAL, `synchronous` (валидируется), `busy_timeout=5000`, checkpoint(TRUNCATE) при
  закрытии — best-effort, ошибки гасятся. Ок.
- ContextVar `_ACTIVE_TRANSACTION_DB` позволяет дочерним таскам читать
  «свои» незакоммиченные данные без дедлока и не пускает независимых читателей —
  логика покрыта тестами, замечаний нет.
- Многошаговые операции (`hard_delete_with_stats`, `create_batch`,
  `create_admin_placeholders`, `mark_active`, `mark_expiry_notified`) обёрнуты в
  `transaction()` — атомарность обеспечена.
- Целочисленные счётчики трафика: SQLite INTEGER 64-бит + Python bigint, `max(x,0)`
  на входе; практического переполнения нет.
- Секреты: DTO `VpnKey`/`ProxyAccess`/`ProxyEntry` переопределяют `__repr__` и
  маскируют `payload`/`password`; `_SANITIZED_STATS_SELECT` возвращает
  host/port/login/mode/fingerprint (не сырой секрет); логи не пишут сырые значения.
  Выборки клампятся (`_clamp_limit ≤ 500`). Замечаний нет.

---

## 5. Матрица «schema.sql ↔ миграции ↔ использование в репозиториях»

Отмечены только строки с расхождениями/примечаниями; остальные объекты совпадают.

| Объект | schema.sql | Миграция (db/database.py) | Файл в db/migrations/ | Использование в repo | Статус |
|---|---|---|---|---|---|
| `vpn_keys.key_type` CHECK | `xray,awg,hysteria2` (l.51) | v29 расширяет до hysteria2 | **нет 029.sql** | `vpn_keys`, `dashboard` (hysteria2) | ⚠ файл миграции 029 отсутствует (P2-004) |
| `trial_key_requests.key_type` CHECK | **`xray,awg`** (l.86) | v13, не расширялась | 013 отсутствует в области | DTO/enum допускают hysteria2 | ⚠ **дрейф** (P2-001) |
| `vpn_keys.transport` | `NOT NULL DEFAULT 'tcp'` (l.67) | v23 ADD COLUMN | 023 ✓ | `_build_segment_where`, `_row_to_vpn_key` | ✓ (валидируется в `_validate_enum_values`) |
| `vpn_keys.xhttp_profile` | `NOT NULL DEFAULT 'base'` (l.70) | v28 ADD COLUMN + relabel | **нет 028.sql** | `_row_to_vpn_key` | ⚠ файл 028 отсутствует; значение `antisib` (P2-004/P2-005); в `_validate_enum_values` не проверяется (нет CHECK — ок) |
| `announcement_batches.recipient_filter_json` | есть (l.184) | v27 ADD COLUMN | **нет 027.sql** | `announcements._row_to_batch` | ⚠ файл 027 отсутствует (P2-004) |
| `announcement_batches.status` CHECK | +`scheduled` (l.173) | v7 без scheduled → v16 rebuild | 016 вне области | `announcements` | ✓ (свежая БД: schema.sql уже со scheduled, v16 early-return) |
| `protocol_modules` сид | 5 протоколов вкл. hysteria2 (l.203-207) | v21 сеет 4, v29 добавляет hysteria2 | 021 сеет **4** (нет hysteria2) | `ProtocolModulesRepository`, `PROTOCOL_NAMES` (5) | ⚠ hysteria2-сид не документирован в migrations/ (P2-004) |
| `users.language`, `users.expiry_notifications_enabled` | есть (l.28,31) | v26 ADD COLUMN | 026 ✓ | `_row_to_user` (guard по наличию столбца) | ✓ (но v17 безусловно перестраивает users — P2-009) |
| `warp_settings`/`server_status_settings`/`maintenance_settings` | есть, время INTEGER | v20/v24/v25 | 020/024/025 ✓ | соответствующие repo (`int(time.time())`) | ⚠ формат времени INTEGER vs TEXT в прочих (P2-010) |
| `idx_vpn_keys_client_ip_reserved`, `idx_vpn_keys_expires_at`, `idx_access_requests_one_pending`, `idx_trial_requests_one_pending` | **нет** (комментарий l.272-282) | v5/v6, v13, v4, v18 | — | партиалы UNIQUE | ✓ migration-only, покрыто `test_schema_drift` |
| Роли рассылки | — | `_ANNOUNCEMENT_ROLE_SQL_VALUES` (2) vs `TARGETABLE_ROLES` (4) | — | `users.py` | ⚠ расхождение аудитории (P2-002) |
| Два пути инициализации | — | `init_db.py:13` и `bot/app.py:158` оба зовут один `Database.bootstrap()` | — | — | ✓ схема не разъезжается (общий код) |

Соответствие моделей строкам БД (`models/dto.py`/`enums.py` ↔ фактические столбцы):
проверено — поля, nullable и значения enum совпадают; enum-валидатор на бутстрапе
дублирует CHECK’и (кроме `trial_key_requests` — P2-011). Расхождение только по
`trial_key_requests.key_type` (P2-001).

---

## 6. Реестр жаргона (термин → где → нейтральная замена)

| Термин | Где | Комментарий | Нейтральная замена |
|---|---|---|---|
| `antisib` | `schema.sql:68`, `dto.py:176`, `database.py:23`; попадает в email-метки Xray | Внутренний сленг «анти-цензура/анти-СИБ» | `hardened` / `evasion` / `profile_b` (через relabel-миграцию) — P2-005 |
| `email_label` | `schema.sql:55,250`, `vpn_keys.find_by_email_label`, индекс | Термин Xray для тега клиента, не e-mail | документировать; опц. `client_tag` — P2-012 |
| `out-warp` / `/etc/amnezia/out-warp.conf` | `schema.sql:212`, DEFAULT столбца | Деплой-специфичное имя в DEFAULT схемы | вынести в конфиг / комментарий — P2-012 |
| `apply_generation`, `secret_fingerprint`, `last_shown_at` | `proxy_accesses` | Описательны, но узкоспециальны | оставить (замечаний нет) |
| `stuck` | `dashboard.KeysSummary.stuck` | Сленг для «застрявших» pending/failed статусов | опц. `problem`/`non_terminal` |
| `xray`,`awg`,`hysteria2`,`socks5`,`mtproto` | enums | Стандартные имена протоколов | оставить |

---

## 7. Несоответствия кода и документации (сводно)

- P2-004 — файлы миграций 027–029 отсутствуют, хотя 020–026 обещают «kept in sync».
- P2-007 — `find_active_awg_ips`: имя «active», docstring и поведение — «все
  нетерминальные».
- P2-008 — `schema.sql` называет себя «version-1 baseline», фактически это снимок v29.
- P2-015 — разное «not found» поведение у `update_note` в разных репозиториях.
- Комментарии в `schema.sql` («Mirrors _migrate_v23/v26/v27/v28») корректны;
  расхождений формулировок с кодом миграций не выявлено, кроме вышеуказанных.

---

## 8. Предположения и открытые вопросы

1. **P2-001/P2-002** помечены «Вероятно» по impact: достижимость hysteria2-триала и
   намеренность разной аудитории рассылок определяются слоем сервисов/хендлеров,
   который вне области ревью. Дрейф схемы и расхождение констант — подтверждены.
2. Предполагается, что все ISO-таймстемпы (`created_at` и пр.) генерируются
   `adapters/clock.py` в UTC с суффиксом `+00:00` (так утверждают комментарии в
   `audit_log`/`dashboard`); лексикографические сравнения дат корректны при этом
   допущении. `count_used_since_reset` использует дефолт `"1970-01-01T00:00:00"`
   **без** суффикса зоны — как «пол» работает (лексикографически меньше любой
   реальной даты), но формат неоднороден. Информационно.
3. Минимальная версия SQLite: используются оконные функции (`ROW_NUMBER()` в v4,
   ≥3.25), `UPDATE ... FROM` (`announcements.refresh_batch_counts`, ≥3.33), JSON1
   (`json_extract`). Предполагается современный SQLite; на старых сборках часть
   запросов не выполнится. Проверить требование к версии — вне области.

---

## 9. Что вне области ревью

- Слой сервисов/хендлеров/адаптеров (`services/*`, `handlers/*`, `bot/*`,
  `adapters/*`, `warp/*`) — смотрелся только точечно для оценки достижимости
  находок (P2-001, P2-006), но не ревьюился.
- Внешний процесс `hy2_auth` (собственное read-only соединение и параметризованный
  SELECT) — упомянут в `vpn_keys.list_active_hysteria2`, но код не в области.
- Тесты (`tests/*`) — не ревьюились (кроме сверки инвариантов `test_schema_drift`).
- Корректность бизнес-логики жизненного цикла ключей/прокси за пределами SQL.
