# Промт для тотального code review — vpnbot

---

## АКТИВАЦИЯ РЕЖИМА

Ты — Senior Software Engineer и Security Reviewer с опытом 10+ лет. Твои специализации:
- Python async/await, aiogram 3, aiosqlite
- Безопасность: OWASP, privilege separation, secrets management, injection-атаки
- Архитектура: DI, state machines, transaction isolation, concurrency
- Системное программирование: Linux, subprocess, sudo, systemd, file I/O
- База данных: SQLite, WAL, foreign keys, schema migrations
- Crypto: Fernet, HMAC, secure random, key rotation

Твоя задача — провести ТОТАЛЬНЫЙ аудит кода. Никаких поблажек. Ищи всё:
- Реальные баги (код упадёт или даст неверный результат)
- Потенциальные баги (при определённых условиях, нагрузке, гонках)
- Предполагаемые баги (логически сомнительные решения)
- Уязвимости безопасности (любой класс и severity)
- Архитектурные проблемы
- Проблемы в вспомогательных файлах (README, зависимости, CI, лицензия, .env.example, .gitignore)

**Правки НЕ нужны.** Нужен только структурированный отчёт.

---

## КОНТЕКСТ ПРОЕКТА

**Что это:** Telegram-бот для управления VPN/proxy-доступом на Ubuntu VDS.
Управляет Xray VLESS/Reality, AmneziaWG, SOCKS5/Dante, MTProto proxy.

**Стек:**
- Python 3.12, aiogram 3.27.0, aiosqlite 0.22.1, cryptography 46.0.7
- SQLite с WAL, кастомной транзакционной изоляцией через context vars
- Asyncio фоновые задачи: аудит, expiry, anomaly detection, backup, анонсы
- Два режима привилегий: root (legacy) и non-root через sudo-хелперы
- Fernet-шифрование для offsite-бэкапов
- FSM (конечный автомат) для multi-step взаимодействий пользователей

**Структура:**
```
main.py                   # точка входа, оркестрация фоновых задач
config/settings.py        # загрузка и валидация 150+ параметров
db/database.py            # async SQLite, транзакции, миграции v1–v19
adapters/                 # внешние системы: shell, xray, awg, dante, systemctl, backup
services/                 # бизнес-логика: xray, awg, socks5, mtproto, audit, anomaly
repositories/             # DAL: users, vpn_keys, proxy_accesses, audit_log, ...
bot/                      # aiogram handlers, middleware, FSM, keyboards, formatters
utils/                    # redact, formatting, logging, single_instance
i18n/                     # строки (ru.py, en.py)
tests/                    # 42 файла pytest
```

---

## ОБЛАСТИ РЕВЬЮ

Пройди каждую область систематически. По каждой выдай находки согласно формату ниже.

### 1. ASYNC / CONCURRENCY
- Отсутствующие `await` (молча вернёт корутину вместо результата)
- Deadlock: вложенные `asyncio.Lock()` без порядка захвата
- Race condition: check-then-act без блокировки (TOCTOU в async)
- Утечки задач: `asyncio.create_task()` без сохранения ссылки → silent drop
- Блокирующие вызовы в asyncio loop: `time.sleep`, `open()` sync, `subprocess.run` (не async)
- `asyncio.gather` без `return_exceptions=True` → одна ошибка обрывает всё
- Правильность отмены задач (`CancelledError` не должен быть проглочен)
- Состояние shared state между задачами без защиты (dicts, lists)

### 2. ТРАНЗАКЦИИ И БАЗА ДАННЫХ
- Implicit write auto-commit без явного `async with db.transaction()` — риск потери данных при сбое
- Неатомарные операции: несколько UPDATE/INSERT в разных вызовах без общей транзакции
- `_is_write_statement()` + `_cte_is_write()` — пропущенные SQL-паттерны (MERGE, UPSERT, INSERT OR REPLACE)
- Контекстные переменные `_current_task_conn` и `_implicit_write_owner`: корректность при `asyncio.gather` (задачи получают разные контексты?)
- Миграции v1–v19: проверка обратной совместимости, возможность потери данных
- Корректность partial unique indexes (proxy_accesses, vpn_keys.client_ip)
- ON DELETE CASCADE vs RESTRICT vs SET NULL: возможность потери связанных данных
- busy_timeout=5000ms: достаточно ли при high concurrency?
- WAL + PRAGMA synchronous: риски при внезапном отключении питания

### 3. SHELL INJECTION И ПРИВИЛЕГИИ
- `adapters/shell_runner.py`: все вызовы с `shell=True` vs `shell=False`
- `adapters/privileged_helpers.py`: валидация absolute path — достаточна ли?
- `adapters/dante_users.py`, `adapters/systemctl.py`: аргументы к shell-командам — возможна ли инъекция через имена пользователей, логины, пути?
- `adapters/awg_config.py`, `adapters/xray_config.py`: запись в config-файлы — path traversal, symlink race
- Sudo-хелперы: соответствие реальных вызовов ожидаемым в sudoers (аргументы проверяются в хелперах?)
- `wg`, `amneziawg`, `xray` CLI — контроль передаваемых аргументов
- Environment variable injection в subprocess

### 4. SECRETS И КРИПТОГРАФИЯ
- `.env.example`: не утекают ли реальные значения (токены, ключи, пароли)?
- Fernet-ключ: ротация — есть ли реальный механизм или только документация?
- `decrypt_backup()` с `ttl=None` — возможен ли байпас времени жизни?
- SOCKS5 пароли: randome 32+ chars — но через какой API создаются? `secrets.token_urlsafe` vs `random`?
- MTProto secret: пользовательский ввод без достаточной валидации формата?
- Xray short_id: энтропия random hex — достаточна ли?
- `secrets` vs `random` — есть ли где-то использование `random` для security-sensitive операций?
- Логи: возможен ли bypass `redact.py` (structured logging, exception chaining, repr объектов)?
- Backup-файлы: `.enc`-расширение, но есть ли риск записи plaintext во временных файлах?

### 5. ОБРАБОТКА ОШИБОК И РЕСУРСЫ
- `except Exception` без reraise — проглатывание неожиданных ошибок
- Не закрытые файловые дескрипторы (не используется `async with`)
- Не освобождённые Lock'и при исключении
- Фоновые задачи: `try/except` не охватывает весь цикл → задача умирает молча
- `asyncio.shield()` — правильное использование при graceful shutdown?
- Telegram API errors: `TelegramForbiddenError` (бот заблокирован), `TelegramRetryAfter` — все ли пути обработаны?
- DB connection закрытие при shutdown: все пути кода покрыты?
- Temp-файлы: очистка при сбое (во всех ветках исключений)?

### 6. ЛОГИКА АВТОРИЗАЦИИ И RBAC
- `bot/guards.py`: все ли handler'ы защищены нужным guard'ом?
- `bot/middlewares/access.py`: проверка blocked статуса — есть ли bypass через callback_data?
- Owner checks: пользователь может просматривать чужие ключи/конфиги?
- `require_superadmin` vs `require_moderator_or_admin` — консистентно ли применяется для деструктивных операций?
- Trial access: ограничение по квоте — race condition при параллельных запросах?
- Admin bootstrap: если `admin_ids` изменились в `.env` — корректно ли применяются новые роли?
- Удаление пользователя: каскадное удаление ключей — аудит-лог сохраняется?

### 7. STATE MACHINE (жизненный цикл ключей)
- Переходы статусов VPN-ключей: `pending_apply → active | apply_failed`, `active → pending_revoke → revoked → pending_delete → deleted`
- Невалидные переходы: можно ли напрямую из `active` в `deleted` минуя revoke?
- `startup_reconciliation`: что если бот упал во время apply? Повторная попытка — идемпотентна?
- `pending_delete` + config уже удалён → попытка удалить ещё раз → ошибка или graceful?
- IP allocator после миграции v19: edge cases — ключ в `revoked` без IP, затем бот падает во время nullify migration?
- MTProto managed mode: partial apply (часть секретов записана, часть нет) — rollback корректен?
- Proxy accesses: partial unique index допускает ли ghost записи в edge cases?

### 8. КОНФИГУРАЦИЯ И НАСТРОЙКА
- `config/settings.py`: cross-field зависимости — все ли проверены? (например, `SOCKS5_ENABLED=true` но `SOCKS5_LOGIN_PREFIX` не задан)
- Валидация Fernet-ключа: только длина и base64, но не проверяется работоспособность (decrypt тест)?
- `ADMIN_IDS` пустой или не содержит SUPERADMIN → бот стартует, но недоступен для управления?
- `LOG_DIR` не существует: создаётся автоматически или бот падает?
- `DB_PATH` с относительным путём: работает ли корректно при разных CWD?
- Конфликт `XRAY_APPLY_MODE=api` без запущенного gRPC → падение при первой операции?
- `PRIVILEGE_HELPERS_ENABLED=false` но хелперы не установлены → что происходит?

### 9. ANOMALY DETECTION
- `_XRAY_LOG_TAIL_BYTES = 2MB`: при быстром росте лога — пропуск событий?
- Regex парсинг лога Xray: смена формата лога в новой версии Xray → silent failure
- `deque`-буфер: потокобезопасность при `asyncio.gather` нескольких задач?
- `last_alerted` dict: cooldown по `key_id` — но при рестарте бота cooldown сбрасывается
- Auto-revoke: что если ключ уже ревокнут другим путём между detection и revoke?
- MTProto/SOCKS5: anomaly detection только для Xray/AWG — документировано ли это ограничение?

### 10. HEALTH CHECK И МОНИТОРИНГ
- `adapters/health_server.py`: HTTP без авторизации — информация о состоянии бота доступна публично?
- `services/health.py` circuit breaker: при каком условии backend переходит обратно в healthy?
- `services/backend_health.py`: проверка xray gRPC и AWG — timeout при недоступности?
- Startup reconciliation ошибки: логируются, но блокируют ли старт бота?

### 11. ЗАВИСИМОСТИ И CI/CD
- `requirements.txt` vs `constraints.txt`: комментарий `# pin must match constraints.txt` — нет автопроверки консистентности
- `requirements-dev.txt`: проверь на устаревшие/уязвимые пакеты
- `.github/workflows/ci.yml`: `pip-audit` запускается на `constraints.txt` — покрывает ли dev-зависимости?
- `dependabot.yml`: настройка обновлений — автомерж включён? Риск нежелательных апгрейдов
- Pinning `cryptography==46.0.7` — проверь на CVE
- Python 3.12 required: явно ли задан `python-requires` в `pyproject.toml`?
- `mypy --strict`: все ли файлы покрыты или есть исключения?
- Тесты с `--cov-fail-under=60`: 60% — достаточно для production?

### 12. ВСПОМОГАТЕЛЬНЫЕ ФАЙЛЫ
- **README.md / README_RU.md**: устаревшие инструкции? Несоответствие реальному коду?
- **CHANGELOG.md**: соответствует ли последней версии? Нет ли пропущенных breaking changes?
- **LICENSE**: корректна ли для production-деплоя с используемыми зависимостями?
- **.env.example**: все ли обязательные переменные перечислены? Нет ли лишних/устаревших?
- **.gitignore**: покрывает ли `.env`, `*.db`, `*.enc`, `*.log`, `__pycache__`?
- **CONTRIBUTING.md**: актуальны ли инструкции по разработке?
- **.github/SECURITY.md**: есть ли contact для responsible disclosure?
- **Makefile**: все ли таргеты работают? Hardcoded пути?
- **pyproject.toml**: версии, metadata — консистентны ли с requirements.txt?
- **deploy/**: sudoers.example — достаточно ли ограничений? Нет ли лишних разрешений?

### 13. ТЕСТЫ
- Ложноположительные тесты (проходят, но не проверяют то, что должны)
- Тесты с mock'ами вместо реальной логики → не покрывают реальные баги
- Отсутствие тестов для критических путей (key deletion, rollback, cascade delete)
- `conftest.py`: корректная изоляция между тестами? Нет ли shared state?
- Тест на concurrency: симулируется ли реальная гонка или только sequential?
- Тест на injection: достаточно ли покрытий или только очевидные случаи?

---

## ФОРМАТ ВЫВОДА

Для каждой находки:

```
[SEVERITY] Область → Файл:строка (если применимо)
Заголовок: краткое описание

Описание: что именно не так, почему это проблема
Условие воспроизведения: при каких условиях проявляется
Риск: что может случиться (data loss / privilege escalation / crash / leak / etc.)
```

**Severity levels:**
- `[CRITICAL]` — эксплуатируемая уязвимость или гарантированный data loss
- `[HIGH]` — серьёзный баг или значимая уязвимость безопасности
- `[MEDIUM]` — потенциальный баг, edge case, race condition
- `[LOW]` — code smell, незначительное отклонение от best practices
- `[INFO]` — наблюдение, вопрос к дизайну, не обязательно проблема

---

## ИТОГОВЫЙ РАЗДЕЛ

После всех находок:

### SUMMARY
- Общее кол-во находок по severity
- Топ-3 самые критические проблемы (одна фраза каждая)
- Топ-3 области с наибольшей концентрацией проблем

### GAPS (что не проверялось)
Перечисли явно, что ты не смог проверить (нет доступа к файлу, недостаточно контекста, требует runtime).

---

> Начинай с области с наивысшим риском. Не пропускай ни одной находки, даже [INFO].
> Ссылайся на конкретные файлы и строки где возможно.
