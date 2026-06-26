# Прокси-бэкенды (SOCKS5 / MTProto)

Бот не устанавливает Dante или MTProxy. Подготовьте их на VDS заранее, затем включите
соответствующие флаги в окружении (см. [Конфигурация](configuration.ru.md)).

## SOCKS5 / Dante

- Dante слушает на настроенном публичном host/порту, например `0.0.0.0:31337`.
- Аутентификация — через логин/пароль системного Linux-пользователя.
- В production процесс бота не вызывает инструменты управления аккаунтами напрямую. Он использует `sudo -n /usr/local/sbin/vpnbot-socks5-user ...`; только хелпер имеет право вызывать `getent`, `useradd`, `chpasswd`, `passwd -l` и `userdel`.
- Бот отказывается управлять Linux-пользователями, логин которых не начинается с `SOCKS5_LOGIN_PREFIX`.

## MTProto static mode

- Установите `MTPROTO_MODE=static` и задайте `MTPROTO_SECRET`.
- MTProxy управляется вне бота через собственный systemd unit.
- В static-режиме бот не редактирует файлы MTProxy.
- Вывод для пользователя всегда содержит обе Telegram-ссылки: сначала обычный секрет, затем вариант с random padding `dd`.
- Static-режим использует общий секрет; блокировка одного пользователя деактивирует только запись в боте и не отзывает доступ на уровне сервера.

## MTProto managed mode

- Установите `MTPROTO_MODE=managed`; не задавайте общий production-секрет в `MTPROTO_SECRET` для новых пользователей.
- MTProxy должен быть уже установлен и иметь рабочие файлы `proxy-secret` и `proxy-multi.conf`.
- Установите managed wrapper/drop-in один раз при деплое. Модель по умолчанию — **root-wrapper**:
  wrapper запускается от root. systemd запускает wrapper под root, wrapper читает managed
  env/секреты, доступные только root, и запускает `mtproto-proxy` с `-u mtproxy` из
  `MTPROTO_RUN_USER`, чтобы процесс прокси сбрасывал привилегии изнутри.
  ```bash
  sudo install -m 700 -d /opt/vpn-service/scripts
  sudo install -m 700 deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed
  sudo install -m 700 -d /etc/systemd/system/mtproxy.service.d
  sudo install -m 600 deploy/mtproxy-vpnbot-managed.conf /etc/systemd/system/mtproxy.service.d/vpnbot-managed.conf
  sudo install -m 700 -d /etc/mtproxy/vpnbot /etc/mtproxy/vpnbot/backups
  sudo chown root:root /opt/vpn-service/scripts/run-mtproxy-managed /etc/mtproxy/vpnbot /etc/mtproxy/vpnbot/backups
  sudo /opt/vpn-service/.venv/bin/python - <<'PY'
  import json, secrets
  from pathlib import Path
  managed = Path("/etc/mtproxy/vpnbot")
  placeholder = secrets.token_hex(16)
  (managed / "managed-secrets.json").write_text(json.dumps({
      "version": 1,
      "generation": 0,
      "managed_by": "vpn-bot",
      "secrets": [],
      "runtime_secrets": [{"secret": placeholder, "fingerprint": "empty-placeholder", "purpose": "empty-placeholder"}],
  }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
  (managed / "mtproxy.env").write_text(
      "MTPROTO_BINARY_PATH=/usr/local/bin/mtproto-proxy\n"
      "MTPROTO_RUN_USER=mtproxy\n"
      "MTPROTO_RUN_GROUP=mtproxy\n"
      "MTPROTO_PROXY_SECRET_PATH=/etc/mtproxy/proxy-secret\n"
      "MTPROTO_PROXY_MULTI_CONF_PATH=/etc/mtproxy/proxy-multi.conf\n"
      "MTPROTO_MANAGED_SECRETS_PATH=/etc/mtproxy/vpnbot/managed-secrets.json\n"
      "MTPROTO_PORT=8443\n"
      "MTPROTO_INTERNAL_STATS_PORT=8888\n"
      "MTPROTO_WORKERS=1\n",
      encoding="utf-8",
  )
  PY
  sudo chmod 600 /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
  sudo chown root:root /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
  sudo systemctl daemon-reload
  sudo systemctl restart mtproxy
  sudo systemctl status mtproxy --no-pager
  sudo ss -tlnp | grep 8443
  ```
- Drop-in очищает любые существующие `User=`/`Group=` из `mtproxy.service`; вывод `systemctl show mtproxy -p User -p Group -p ExecStart` должен показывать пустые `User`/`Group` и `ExecStart=/opt/vpn-service/scripts/run-mtproxy-managed`.
- Если `MTPROTO_MANAGED_WRAPPER_PATH` или `MTPROTO_MANAGED_ENV_PATH` отличаются от дефолтов, отредактируйте установленный wrapper/drop-in при деплое и вручную выполните `systemctl daemon-reload`.
- Не устанавливайте `MTPROTO_MODE=managed` в `vpn-bot`, пока baseline-конфигурация выше не перезапустится успешно и `mtproxy` не будет активен/слушает порт. Issue/revoke откажут, если `MTPROTO_MANAGED_SECRETS_PATH` или `MTPROTO_MANAGED_ENV_PATH` отсутствуют, поэтому первый apply хелпера всегда имеет known-good файлы для rollback.
- Во время работы бот размещает MTProxy-кандидаты в `/run/vpn-bot/mtproxy`. Хелпер `/usr/local/sbin/vpnbot-mtproxy-apply` валидирует эти файлы, записывает `MTPROTO_MANAGED_SECRETS_PATH`, записывает `MTPROTO_MANAGED_ENV_PATH`, поддерживает `MTPROTO_BACKUP_DIR/<backup-id>/`, перезапускает `mtproxy`, проверяет `systemctl is-active`, проверяет, что `MTPROTO_PORT` слушает, и восстанавливает предыдущие managed-файлы при ошибке apply.
- Обычные issue/revoke не пишут в `/etc/systemd/system` и не запускают `systemctl daemon-reload`; устанавливайте/обновляйте MTProxy unit/drop-in вручную при деплое.
- Managed mode обеспечивает реальный per-user revoke: удаляется только секрет конкретного пользователя из active MTProxy list. Секреты других остаются в managed-файле.
- Сырые MTProto-секреты не отображаются в статусе администратора, audit log, логах, README или `.env.example`; диагностика использует только счётчики и fingerprint'ы.
- Managed secrets и env-файлы: root:root `0600`; директории backup: root:root `0700`; файлы backup с секретами: root:root `0600`; wrapper: root:root `0700`; systemd drop-in без секретов, может быть root:root `0600`.

### Проверки видимости секретов в managed mode

- `systemctl cat mtproxy` и `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment` должны показывать только пути к wrapper/env, но не сырые секреты. В дефолтной root-wrapper модели `User` и `Group` пусты на уровне сервиса.
- `journalctl -u vpn-bot` и `journalctl -u mtproxy` не должны содержать сырых MTProto-секретов; бот маскирует данные audit/ошибок, а wrapper не выводит секреты. Если ваша сборка MTProxy логирует принятые секреты или сгенерированные ссылки, не используйте managed mode, пока логирование не отключено или бинарник не заменён.
- Официальный бинарник `mtproto-proxy` принимает клиентские секреты как аргументы `-S <secret>`. Это значит, что сырые секреты могут быть видны в argv процесса для root и для непривилегированных пользователей, если `/proc` не защищён. Ограничьте shell-доступ, рассмотрите монтирование `/proc` с `hidepid=2` и не включайте managed mode с этим бинарником, если требование — «сырые MTProto-секреты никогда не видны при инспекции процессов на уровне root».

### Ручной rollback для managed MTProto

1. Остановите `vpn-bot`.
2. Проверьте `MTPROTO_BACKUP_DIR`, по умолчанию `/etc/mtproxy/vpnbot/backups`.
3. Восстановите предыдущие managed secrets/env-файлы из последнего known-good backup, если автоматический rollback не сработал.
4. Выполните `sudo systemctl restart mtproxy`.
5. Проверьте `sudo systemctl status mtproxy --no-pager` и `sudo ss -tlnp | grep 8443`.

## Статистика прокси

Статистика прокси — это lifecycle/accounting-статистика из SQLite: выдано, активно,
отозвано/деактивировано, временные метки, статус, причина, ошибка. Бот не придумывает per-user
трафик для Dante или MTProxy. Без per-login accounting в Dante или надёжного агрегированного
stats endpoint для MTProxy трафик отображается как недоступный.
