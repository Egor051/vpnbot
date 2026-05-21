
STRINGS: dict[str, str] = {
    # ── misc ──────────────────────────────────────────────────────────────────
    "none": "нет",
    "no_data": "нет данных",
    "unavailable": "недоступно",
    "not_set": "не задан",
    "not_specified": "не указан",
    # ── role labels ───────────────────────────────────────────────────────────
    "role_superadmin": "superadmin",
    "role_approved": "одобрен",
    "role_pending": "ожидает",
    "role_blocked": "заблокирован",
    "role_moderator": "модератор",
    # ── VPN key status labels ─────────────────────────────────────────────────
    "key_status_pending_apply": "применяется",
    "key_status_active": "активен",
    "key_status_apply_failed": "ошибка применения",
    "key_status_pending_revoke": "отзывается",
    "key_status_revoked": "отозван",
    "key_status_pending_delete": "удаляется",
    "key_status_delete_failed": "ошибка удаления",
    "key_status_deleted": "удалён",
    "key_status_failed": "ошибка",
    # ── warnings / banners ────────────────────────────────────────────────────
    "one_key_one_device": "<b>⚠️ 1 КЛЮЧ = 1 УСТРОЙСТВО</b>",
    "note_create_warning": "<b>Рекомендуем не оставлять поле пустым, чтобы не запутаться в ключах.</b>",
    "server_restart_warning": (
        "<b>⚠️ Сервер перезагружается по чётным числам в 04:00 по МСК. "
        "Перезагрузка занимает несколько минут, в это время соединение может кратковременно прерваться.</b>"
    ),
    # ── common field labels ───────────────────────────────────────────────────
    "field_status": "Статус",
    "field_label": "Метка",
    "field_created": "Создан",
    "field_updated": "Обновлён",
    "field_expires": "Действует до",
    "field_note": "Заметка",
    "field_ip": "IP",
    "field_pubkey": "Публичный ключ",
    "field_owner": "Владелец",
    "field_type": "Тип",
    "field_downloaded": "Скачано",
    "field_uploaded": "Отправлено",
    "field_updated_at": "Обновлено",
    "field_reason": "Причина",
    "field_tg_id": "Telegram ID",
    "field_username": "Username",
    "field_role": "Роль",
    "field_name": "Имя",
    "field_current_role": "Текущая роль",
    "field_host": "Хост",
    "field_port": "Порт",
    "field_login": "Логин",
    "field_password": "Пароль",
    "field_description": "Описание",
    "field_issued": "Выдан",
    "field_activated": "Активирован",
    "field_last_shown": "Последний показ",
    "field_revoked": "Отозван",
    "field_deleted": "Удалён",
    # ── main menu ─────────────────────────────────────────────────────────────
    "main_menu_text": "Доброго времени суток, {name}!\n\n{warning}\n\nВыберите действие.",
    # ── keys page ─────────────────────────────────────────────────────────────
    "keys_user_title": "<b>Ключи пользователя</b>",
    "keys_my_title": "<b>Мои ключи</b>",
    "keys_page_empty": "На этой странице ключей нет.",
    "keys_page_title": "{title} · страница {page}",
    # ── key creation ──────────────────────────────────────────────────────────
    "create_confirm_title": "<b>Подтверждение создания ключа</b>",
    "field_expires_at": "Срок действия",
    # ── note confirm ─────────────────────────────────────────────────────────
    "note_confirm_title": "<b>Подтверждение заметки</b>",
    "note_confirm_key": "Ключ",
    "note_confirm_new_note": "Новая заметка",
    # ── config hints ─────────────────────────────────────────────────────────
    "xray_config_hint": "Добавьте ссылку в клиент с поддержкой VLESS/REALITY.",
    "awg_config_hint": "Добавьте ссылку в клиент AmneziaWG или используйте файл конфигурации.",
    # ── traffic stats ─────────────────────────────────────────────────────────
    "stats_title": "<b>Статистика {key_title}</b>",
    "stats_unavailable_now": "Статистика сейчас недоступна. Последний успешный снимок:",
    "stats_not_available_yet": "Статистика пока недоступна.",
    "stats_keys_title": "<b>Статистика ключей</b>",
    "stats_keys_empty": "<b>Статистика ключей</b>\n\nНа этой странице ключей нет.",
    "stats_last_prefix": "последнее",
    "stats_unavailable_short": "статистика пока недоступна",
    "stats_updated_fmt": " · обновлено {at}",
    "stats_attempt_fmt": " · попытка {at}",
    "stats_note": "Заметка",
    # ── access requests ───────────────────────────────────────────────────────
    "request_title": "<b>Заявка #{id}</b>",
    "requests_page_empty": "<b>Заявки на доступ</b>\n\nНовых заявок нет.",
    "requests_page_title": "<b>Заявки на доступ</b> · страница {page}",
    "decision_confirm_approve": "одобрить",
    "decision_confirm_reject": "отклонить",
    "decision_confirm_title": "<b>Подтвердите действие: {action}</b>",
    # ── user card ─────────────────────────────────────────────────────────────
    "user_card_title": "<b>Пользователь</b>",
    "user_keys_title": "<b>Ключи</b>",
    "user_no_keys": "Ключей нет.",
    "user_stats_unavailable": "статистика пока недоступна",
    # ── users page ────────────────────────────────────────────────────────────
    "users_title": "<b>Пользователи</b>",
    "users_empty": "На этой странице пользователей нет.",
    "users_page_title": "<b>Пользователи</b> · страница {page}",
    "users_key_count": "ключей",
    # ── block / unblock ───────────────────────────────────────────────────────
    "block_confirm_title": "<b>Подтвердите блокировку пользователя</b>",
    "block_keys_to_check": "Ключей к проверке/отзыву: {count}",
    "block_action_warning": (
        "Действие заблокирует доступ к боту и попытается отозвать VPN-ключи. "
        "Если часть VPN-ключей не получится отключить автоматически, потребуется ручная проверка на сервере."
    ),
    "unblock_confirm_title": "<b>Подтвердите разблокировку пользователя</b>",
    "unblock_manual_check": "<b>Требуется ручная проверка VPN</b>",
    "unblock_manual_check_desc": "Ранее могли остаться активные или проблемные VPN-ключи.",
    "unblock_warning_last_error": "Последняя ошибка блокировки: {at}",
    "unblock_no_auto_fix": "Разблокировка восстановит доступ к боту, но не исправит Xray/AWG runtime автоматически.",
    "unblock_confirm_success": "После подтверждения пользователь снова получит доступ к боту.",
    "unblock_success": "Пользователь разблокирован. FSM-состояние очищено, сценарии начнутся заново.",
    "unblock_vpn_check_warning": (
        "Внимание: перед разблокировкой были признаки неполного отзыва VPN-доступа. "
        "Проверьте Xray/AWG runtime и config вручную."
    ),
    # ── audit log ─────────────────────────────────────────────────────────────
    "audit_title": "<b>Логи действий</b>",
    "audit_empty": "На этой странице записей нет.",
    "audit_page_title": "<b>Логи действий</b> · страница {page}",
    "audit_system": "система",
    "audit_created_xray": " создал Xray-ключ {label}",
    "audit_created_xray_nolabel": " создал Xray-ключ",
    "audit_created_awg": " создал AWG-ключ {label}",
    "audit_created_awg_nolabel": " создал AWG-ключ",
    "audit_viewed_user_stats": " открыл статистику пользователя {user}",
    "audit_changed_role": " изменил роль пользователя",
    "audit_blocked_user": " заблокировал пользователя",
    "audit_unblocked_user": " разблокировал пользователя",
    "audit_access_request_repeat": " отправил повторную заявку на доступ",
    "audit_access_request": " отправил заявку на доступ",
    "audit_access_approved": " одобрил заявку на доступ",
    "audit_access_rejected": " отклонил заявку на доступ",
    "audit_action_generic": " выполнил действие {action}",
    "audit_owner_suffix": " для {owner}",
    # ── proxy texts ───────────────────────────────────────────────────────────
    "proxy_title": "<b>Прокси</b>",
    "proxy_not_configured": "Доступные прокси не настроены.",
    "proxy_no_accesses": "<b>Прокси</b>\n\nУ вас пока нет прокси-доступов.",
    "proxy_unavailable": "<b>Прокси</b>\n\nПрокси сейчас недоступны.",
    "mtproto_managed_note": (
        "Это индивидуальный MTProto-доступ. "
        "При блокировке пользователя этот MTProto secret будет отозван."
    ),
    "mtproto_static_note": (
        "Это общий MTProto-доступ. "
        "Индивидуальный серверный отзыв в static mode невозможен."
    ),
    "mtproto_variant1": "Вариант 1 — обычный, попробуйте сначала:",
    "mtproto_variant2": "Вариант 2 — с random padding dd, если первый не работает:",
    "mtproto_try_note": "Сначала попробуйте первый вариант. Если он не работает или плохо грузит медиа — попробуйте второй вариант с dd.",
    # ── proxy user stats ─────────────────────────────────────────────────────
    "proxy_user_stats_title": "<b>Статистика прокси</b>",
    "proxy_no_issued": "У вас пока нет выданных прокси.",
    "proxy_active_header": "<b>Активные прокси:</b>",
    "proxy_no_active": "Активных прокси нет.",
    "proxy_recent_errors_header": "<b>Последние ошибки выдачи:</b>",
    "proxy_hidden_old": "Старые неудачные попытки скрыты: {n}.",
    "proxy_traffic_header": "<b>Трафик:</b>",
    "proxy_traffic_unavailable": "Per-user traffic accounting для SOCKS5/MTProto сейчас недоступен и не фейкуется.",
    # ── proxy admin stats ─────────────────────────────────────────────────────
    "proxy_stats_no_users": "Пользователей с proxy_accesses нет.",
    "proxy_stats_hidden_users": "Ещё {n} пользователей скрыто.",
    "proxy_stats_traffic_note": "Traffic: per-user traffic accounting для SOCKS5/MTProto сейчас недоступен и не фейкуется.",
    "proxy_socks5_traffic_note": "Traffic: статистика трафика недоступна для этого типа прокси без per-login accounting Dante.",
    "proxy_runtime_unavailable": "Runtime status: недоступно",
    # ── proxy stat access lines ───────────────────────────────────────────────
    "proxy_stat_status": "Статус",
    "proxy_stat_issued": "Выдан",
    "proxy_stat_activated": "Активирован",
    "proxy_stat_last_shown": "Последний показ",
    "proxy_stat_revoked": "Отозван",
    "proxy_stat_deleted": "Удалён",
    "proxy_stat_type": "Тип",
    # ── announcement batches ─────────────────────────────────────────────────
    "announce_batches_title": "<b>Незавершённые объявления</b>",
    "announce_batches_empty": "<b>Незавершённые объявления</b>\n\nНезавершённых batch-записей нет.",
    # ── private chat guard ────────────────────────────────────────────────────
    "private_only_text": "Эта операция доступна только в личном чате с ботом.",
    "admin_private_only_text": "Админ-панель доступна только в личном чате с ботом.",
    # ── FAQ ───────────────────────────────────────────────────────────────────
    "faq_title": "<b>Часто задаваемые вопросы</b>",
    "faq_page_title": "<b>Часто задаваемые вопросы</b> · страница {page} из {total}",
    "faq_connect": (
        "После создания ключа бот выдаст конфигурацию. Скопируйте её в подходящее VPN-приложение "
        "или импортируйте файл, если он доступен. Для AWG обычно используется конфиг .conf, "
        "для Xray — ссылка/профиль. После импорта включите подключение в приложении."
    ),
    "faq_trouble": (
        "Проверьте интернет, правильность импортированного профиля, дату окончания доступа и не используется ли "
        "этот же ключ на другом устройстве. Также попробуйте выключить и включить VPN-приложение. Если и это не "
        "помогло, попробуйте включить и выключить \"режим самолета\" или перезагрузить устройство. Если проблема "
        "осталась — напишите в техподдержку."
    ),
    "faq_key_statuses": (
        "<b>Активен</b> — ключ работает.\n"
        "<b>Применяется / Отзывается / Удаляется</b> — идёт операция, подождите.\n"
        "<b>Отозван</b> — ключ отключён на сервере; статистика и заметка сохранены в боте.\n"
        "<b>Удалён</b> — ключ полностью удалён вместе со статистикой.\n"
        "<b>Ошибка</b> — что-то пошло не так; обратитесь в техподдержку."
    ),
    "faq_revoke_delete": (
        "<b>Отозвать</b> — необратимо отключает ключ на сервере. "
        "Статистика и заметка остаются в боте, ключ виден в списке со статусом «Отозван».\n\n"
        "<b>Удалить</b> — необратимо удаляет ключ вместе со статистикой и заметкой из бота."
    ),
    "faq_expired": (
        "Создайте новый ключ через «Создать ключ». "
        "Срок действия выбирается при создании: 7 дней, 30 дней, произвольный срок или бессрочный. "
        "Продление существующего ключа невозможно."
    ),
    "faq_device": (
        "Да. Один ключ рассчитан на одно устройство. Если использовать один и тот же ключ на нескольких "
        "устройствах, подключение может работать нестабильно, а статистика и управление доступом будут путаться."
    ),
    "faq_stats": (
        "Откройте «Мои ключи», выберите нужный ключ и нажмите «Статистика». "
        "Там отображается объём входящего и исходящего трафика. Данные обновляются автоматически."
    ),
    "faq_choice": "Если не знаете, что выбрать, начните с XRay.",
    "faq_mtu": (
        "MTU — максимальный размер сетевого пакета. Применяется только к AWG-ключам.\n\n"
        "В большинстве случаев подходит рекомендуемое значение 1360. "
        "Уменьшите его (например, до 1280), если наблюдаются обрывы соединения или медленная загрузка страниц."
    ),
    "faq_note_why": (
        "Заметка помогает понять, для какого устройства создан ключ — например, «Ноутбук» или «Телефон». "
        "Без заметки трудно разобраться в нескольких ключах."
    ),
    "faq_proxy": (
        "В разделе «Прокси» доступны два типа:\n"
        "<b>SOCKS5</b> — универсальный прокси для браузеров и приложений, требующих ручной настройки.\n"
        "<b>MTProto</b> — прокси специально для Telegram, если он недоступен без VPN.\n\n"
        "Прокси работают независимо от VPN-ключей."
    ),
    "faq_server_restart": (
        "Да, это штатное поведение. Сервер перезагружается по чётным числам в 04:00 по МСК. "
        "Перезагрузка занимает несколько минут — соединение кратковременно прерывается "
        "и восстанавливается автоматически."
    ),
    "faq_notes": "Нет. Ваши заметки никто не видит.",
    "faq_support": "Техподдержка: @ktotakmoje",
    "faq_not_found": "Ответ не найден.",
    # ── errors ────────────────────────────────────────────────────────────────
    "internal_error": "Произошла внутренняя ошибка. Попробуйте позже.",
    "cancel_done": "Операция отменена.",
    # ── start handler ─────────────────────────────────────────────────────────
    "blocked_no_request": "Повторная заявка пока не создана. Дождитесь решения администратора.",
    "blocked_request_created": "Повторная заявка на доступ создана. Дождитесь решения администратора.",
    "blocked_request_pending": "Ваша повторная заявка уже ожидает решения администратора.",
    "request_already_processed": "Заявка уже обработана. Дождитесь решения администратора.",
    "request_created": "Заявка на доступ создана. Дождитесь решения администратора.",
    "request_pending": "Ваша заявка уже ожидает решения администратора.",
    "trial_key_active": "У вас есть активный пробный ключ:\n\n{key_text}",
    "trial_offer": "Вы можете запросить пробный доступ на 7 дней. Администратор рассмотрит вашу заявку.",
    "notify_admin_new_request": (
        "<b>Новая заявка на доступ</b>\n"
        "Telegram ID: <code>{user_id}</code>\n"
        "Username: {username}\n"
        "Заявка: #{request_id}"
    ),
    # ── admin handler ─────────────────────────────────────────────────────────
    "admin_panel_title": "Админ-панель:",
    "moderator_panel_title": "Панель модератора:",
    "announce_prompt": "Отправьте сообщение объявления. Оно будет разослано одобренным пользователям без изменений после подтверждения.",
    "announce_confirm_prompt": "Разослать это объявление пользователям?\nПолучателей среди одобренных пользователей: {count}\nСообщение будет отправлено без дополнительных подписей.",
    "announce_sending": "Отправляю...",
    "announce_sent": "Объявление отправлено.\nПолучателей: {total}\nУспешно: {success}\nОшибок: {failed}",
    "announce_cancelled": "Отменено",
    "announce_stale": "Объявление уже отправлено или устарело.",
    "announce_schedule_prompt": "Введите дату и время отправки в формате ДД.ММ.ГГГГ ЧЧ:ММ (московское время):",
    "announce_invalid_time": "Неверный формат или время в прошлом.\nВведите дату и время в формате ДД.ММ.ГГГГ ЧЧ:ММ (московское время):",
    "announce_session_expired": "Сессия устарела, начните заново.",
    "announce_scheduled": "Объявление запланировано.\nBatch #{batch_id}\nПолучателей: {total}\nВремя отправки: {time} МСК",
    "announce_update_list": "Обновляю список...",
    "batch_cancelled": "Batch #{id} отменён.",
    "batch_already_cancelled": "Batch #{id} уже был отменён.",
    "batch_resume_sending": "Восстанавливаю отправку...",
    "batch_processed": "Batch #{id} обработан.\nПолучателей: {total}; успешно: {success}; ошибок: {failed}.",
    "request_already_processed_msg": "Заявка уже была обработана.",
    "request_approved_msg": "Заявка одобрена.",
    "request_rejected_msg": "Заявка отклонена.",
    "notify_approved": "Ваша заявка одобрена. Отправьте /start, чтобы открыть меню.",
    "notify_rejected": "Ваша заявка отклонена.",
    "user_approved_msg": "Пользователь одобрен.",
    "processing": "Обрабатываю...",
    "blocking": "Блокирую...",
    "unblocking": "Разблокирую...",
    "user_already_blocked": "Пользователь уже заблокирован.",
    "user_already_unblocked": "Пользователь уже не заблокирован.",
    "user_blocked_success": "Пользователь заблокирован.\nОтключено VPN-ключей: {keys}\nОтключено прокси-доступов: {proxies}\nОшибок: 0\nТеперь пользователю доступен только /start для повторной заявки.",
    "user_blocked_with_errors": "Пользователь заблокирован в боте, но не весь серверный доступ удалось отключить автоматически.\nОтключено VPN-ключей: {keys}\nОтключено прокси-доступов: {proxies}\nОшибок: {errors}\nПроверьте Xray/AWG/SOCKS5/MTProto runtime и config вручную.",
    "notify_user_blocked": "Ваш доступ был заблокирован администратором.",
    "choose_user_for_key": "Выберите пользователя для выдачи ключа:",
    "action_stale": "Действие устарело, начните выдачу заново",
    "action_stale_msg": "Действие устарело, начните выдачу заново.",
    "mtu_invalid": "Недопустимое значение MTU: 1–1500",
    "mtu_prompt": "Выберите MTU для ключа:",
    "mtu_custom_prompt": "Введите MTU (от 1 до 1500):",
    "mtu_enter_integer": "Введите целое число от 1 до 1500:",
    "expiry_invalid": "Недопустимый срок: 1–{max} дней",
    "expiry_prompt": "Выберите срок действия ключа:",
    "expiry_custom_prompt": "Введите количество дней (от 1 до 365):",
    "days_enter_integer": "Введите целое число дней (от 1 до 365):",
    "days_enter_range": "Введите число от 1 до {max}:",
    "key_note_prompt": "Введите заметку для ключа или отправьте <code>-</code>, чтобы оставить пустой.",
    "choose_key_type": "Выберите тип ключа:",
    "creating_key": "Создаю ключ...",
    "key_unknown_type": "Неизвестный тип ключа.",
    "admin_delivered_awg": "Администратор выдал вам AWG-ключ #{id}.\n\n{config_text}",
    "admin_delivered_xray": "Администратор выдал вам Xray-ключ #{id}.\n\n{config_text}",
    "trial_no_pending": "Нет ожидающих заявок на пробный доступ.",
    "trial_list_title": "<b>Заявки на пробный доступ:</b>",
    "trial_approved_msg": "Пробный ключ выдан. Конфиг отправлен пользователю.",
    "trial_rejected_msg": "Заявка на пробный доступ отклонена.",
    "trial_quota_resetting": "Сбрасываю квоту...",
    "trial_quota_reset": "Квота пробных доступов сброшена.",
    "updating_stats": "Обновляю статистику...",
    "updating_proxy_status": "Обновляю статус...",
    "updating_diagnostics": "Обновляю диагностику...",
    "updating_proxy_stats": "Обновляю статистику прокси...",
    "backup_disabled": "OFFSITE_BACKUP_ENCRYPTION_KEY не настроен — бэкап отключён.",
    "backup_creating": "Создаю бэкап...",
    "backup_sent": "Бэкап отправлен.\nУспешно: {success}\nОшибок: {failed}",
    "moderator_role_removed": "Роль модератора снята. Пользователь стал обычным одобренным пользователем.",
    "moderator_role_assigned": "Пользователь назначен модератором.",
    "admin_unote_current": " Текущая: <code>{note}</code>",
    "admin_unote_prompt": "Введите заметку для пользователя <code>{user_id}</code> или отправьте <code>-</code>, чтобы очистить.{current}",
    "cannot_issue_to_blocked": "Нельзя выдать ключ заблокированному пользователю",
    "issue_select_user": "Выберите пользователя для выдачи ключа:",
    # ── keys handler ──────────────────────────────────────────────────────────
    "revoke_prompt": "Отозвать ключ #{key_id}? Доступ по нему будет отключён.",
    "delete_prompt": (
        "Полностью удалить ключ #{key_id}? Доступ будет отключён на сервере, "
        "запись ключа и его статистика будут удалены из бота. Это действие нельзя отменить."
    ),
    "executing": "Выполняю...",
    "key_revoked": "Ключ отозван.",
    "key_deleted": "Ключ полностью удалён.",
    "key_deleted_with_list": "Ключ полностью удалён.\n\n{list}",
    "unknown_action": "Неизвестное действие",
    "edit_note_prompt": "Новая заметка для {type} #{id}. Отправьте <code>-</code>, чтобы очистить.",
    "saving": "Сохраняю...",
    "note_updated": "Заметка обновлена.",
    "trial_already_used": "Вы уже использовали свой пробный доступ.",
    "trial_choose_protocol": "Выберите протокол для пробного ключа (7 дней):",
    "trial_request_submitted": "Заявка на пробный доступ отправлена. Ожидайте решения администратора.",
    "trial_request_sent": "Заявка отправлена!",
    "trial_no_access": "Нет доступа к этому ключу.",
    "ensure_send_start": "Сначала отправьте /start, чтобы создать заявку на доступ",
    "access_not_approved": "Доступ ещё не одобрен. Дождитесь решения администратора.",
    "invalid_callback_btn": "Некорректная callback-кнопка",
    "revoke_context_stale": "Контекст отзыва устарел, откройте список ключей заново",
    "delete_context_stale": "Контекст удаления устарел, откройте список ключей заново",
    "trial_admin_notify": (
        "<b>Новая заявка на пробный ключ</b>\n"
        "Telegram ID: <code>{user_id}</code>\n"
        "Протокол: {protocol}\n"
        "Заявка: #{req_id}"
    ),
    # ── proxy handler ─────────────────────────────────────────────────────────
    "socks5_unavailable": "SOCKS5 сейчас недоступен",
    "mtproto_unavailable": "MTProto сейчас недоступен",
    "proxy_action_stale": "Действие устарело",
    "proxy_stale_retry": "Действие устарело. Вернитесь в раздел «Прокси» и попробуйте снова.",
    "executing_proxy": "Выполняю...",
    "proxy_unknown_type": "Неизвестный тип прокси.",
    "proxy_cancelled": "Отменено",
    "proxy_confirm_socks5": (
        "<b>Подтвердите выдачу SOCKS5</b>\n\n"
        "Будет создан персональный Linux-пользователь Dante и пароль для SOCKS5-доступа."
    ),
    "proxy_confirm_mtproto_managed": (
        "<b>Подтвердите выдачу MTProto</b>\n\n"
        "Будет создан индивидуальный MTProto secret. После применения MTProxy пользователь получит обычную ссылку "
        "и ссылку с random padding dd."
    ),
    "proxy_confirm_mtproto_static": (
        "<b>Подтвердите выдачу MTProto</b>\n\n"
        "Бот покажет статические ссылки Telegram MTProto Proxy. "
        "При общем secret индивидуальный серверный revoke для MTProto невозможен."
    ),
    # ── keyboard buttons (common) ─────────────────────────────────────────────
    "btn_my_keys": "Мои ключи",
    "btn_create_key": "Создать ключ",
    "btn_proxy": "Прокси",
    "btn_help": "Помощь",
    "btn_admin_panel": "Админ-панель",
    "btn_back_to_menu": "В меню",
    "btn_back_to_faq": "К вопросам",
    "btn_cancel": "Отмена",
    "btn_confirm": "Подтвердить",
    "btn_prev": "Назад",
    "btn_next": "Далее",
    "btn_faq_connect": "Как подключиться?",
    "btn_faq_trouble": "Почему не работает?",
    "btn_faq_key_statuses": "Что значат статусы ключа?",
    "btn_faq_revoke_delete": "Отозвать vs удалить ключ?",
    "btn_faq_expired": "Что делать, если ключ истёк?",
    "btn_faq_device": "1 ключ = 1 устройство?",
    "btn_faq_stats": "Как посмотреть статистику?",
    "btn_faq_choice": "Что выбрать: AWG или Xray?",
    "btn_faq_mtu": "Что такое MTU?",
    "btn_faq_note_why": "Зачем нужна заметка к ключу?",
    "btn_faq_proxy": "Что такое прокси?",
    "btn_faq_server_restart": "Сервер перезагружается — это нормально?",
    "btn_faq_notes": "Видит ли кто-нибудь мои заметки?",
    "btn_faq_support": "Техподдержка",
    "btn_keyboard_placeholder": "Выберите действие",
    # ── keyboard buttons (admin) ──────────────────────────────────────────────
    "btn_approve": "Одобрить",
    "btn_reject": "Отклонить",
    "btn_access_requests": "Заявки на доступ",
    "btn_users": "Пользователи",
    "btn_key_stats": "Статистика ключей",
    "btn_proxy_status": "Статус прокси",
    "btn_backend_diagnostics": "Диагностика backend",
    "btn_proxy_stats": "Статистика прокси",
    "btn_action_logs": "Логи действий",
    "btn_issue_key_to_user": "Выдать ключ пользователю",
    "btn_trial_accesses": "Пробные доступы",
    "btn_announcement": "Объявление",
    "btn_announcement_recovery": "Восстановление объявлений",
    "btn_db_backup": "Бэкап БД",
    "btn_send_now": "Отправить сейчас",
    "btn_schedule": "Запланировать",
    "btn_approve_user": "Одобрить пользователя",
    "btn_block": "Заблокировать",
    "btn_unblock": "Разблокировать",
    "btn_issue_key": "Выдать ключ",
    "btn_reset_trial": "Сбросить пробный доступ",
    "btn_user_keys": "Ключи пользователя",
    "btn_edit_note_user": "Редактировать заметку",
    "btn_set_moderator": "Назначить модератором",
    "btn_remove_moderator": "Снять роль модератора",
    "btn_to_users": "К пользователям",
    "btn_block_confirm": "Подтвердить блокировку",
    "btn_unblock_confirm": "Подтвердить разблокировку",
    "btn_refresh": "Обновить",
    # ── keyboard buttons (keys) ───────────────────────────────────────────────
    "btn_back": "Назад",
    "btn_config": "Конфиг",
    "btn_stats": "Статистика",
    "btn_revoke": "Отозвать",
    "btn_delete": "Удалить",
    "btn_note": "Заметка",
    "btn_show_config": "Показать конфиг",
    "btn_edit_note_key": "Редактировать заметку",
    "btn_to_list": "К списку",
    "btn_mtu_recommended": "1360 (рекомендуемый)",
    "btn_enter_manually": "Ввести вручную",
    "btn_open_key": "Открыть ключ",
    "btn_permanent": "Бессрочный",
    "btn_7_days": "7 дней",
    "btn_30_days": "30 дней",
    "btn_enter_days": "Ввести количество дней",
    "btn_get_config": "Получить конфиг",
    "btn_request_trial": "Запросить пробный доступ (7 дней)",
    # ── keyboard buttons (proxy) ──────────────────────────────────────────────
    "btn_get_socks5": "Получить SOCKS5",
    "btn_get_mtproto": "Получить MTProto",
    "btn_go_back": "Вернуться",
    "btn_back_to_proxy": "Вернуться в Прокси",
}
