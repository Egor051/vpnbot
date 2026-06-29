
STRINGS: dict[str, str] = {
    # ── misc ──────────────────────────────────────────────────────────────────
    "none": "none",
    "no_data": "no data",
    "unavailable": "unavailable",
    "not_set": "not set",
    "not_specified": "not specified",
    # ── slash command menu descriptions (Telegram set_my_commands) ────────────
    "cmd_desc_start": "Start and register",
    "cmd_desc_menu": "Main menu",
    "cmd_desc_settings": "Settings",
    "cmd_desc_help": "Help and FAQ",
    "cmd_desc_faq": "Frequently asked questions",
    "cmd_desc_cancel": "Cancel the current action",
    "cmd_desc_admin": "Admin panel",
    "cmd_desc_moderator": "Moderator panel",
    "cmd_desc_warp_split_list": "WARP split: list rules",
    "cmd_desc_warp_split_add": "WARP split: add a rule",
    "cmd_desc_warp_split_del": "WARP split: delete a rule",
    "cmd_desc_warp_split_reload": "WARP split: reload",
    # ── role labels ───────────────────────────────────────────────────────────
    "role_superadmin": "superadmin",
    "role_approved": "approved",
    "role_pending": "pending",
    "role_blocked": "blocked",
    "role_moderator": "moderator",
    # ── VPN key status labels ─────────────────────────────────────────────────
    "key_status_pending_apply": "applying",
    "key_status_active": "active",
    "key_status_apply_failed": "apply failed",
    "key_status_pending_revoke": "revoking",
    "key_status_revoked": "revoked",
    "key_status_pending_delete": "deleting",
    "key_status_delete_failed": "delete failed",
    "key_status_deleted": "deleted",
    "key_status_failed": "failed",
    # ── warnings / banners ────────────────────────────────────────────────────
    "one_key_one_device": "<b>⚠️ 1 KEY = 1 DEVICE</b>",
    "note_create_warning": "<b>We recommend filling in this field to avoid confusing your keys.</b>",
    "server_restart_warning": (
        "<b>⚠️ The server restarts on even-numbered dates at 04:00 MSK. "
        "The restart takes a few minutes; your connection may briefly drop during this time.</b>"
    ),
    # ── common field labels ───────────────────────────────────────────────────
    "field_status": "Status",
    "field_label": "Label",
    "field_created": "Created",
    "field_updated": "Updated",
    "field_expires": "Expires",
    "field_note": "Note",
    "field_ip": "IP",
    "field_pubkey": "Public key",
    "field_owner": "Owner",
    "field_type": "Type",
    "field_downloaded": "Downloaded",
    "field_uploaded": "Uploaded",
    "field_updated_at": "Updated at",
    "field_reason": "Reason",
    "field_tg_id": "Telegram ID",
    "field_username": "Username",
    "field_role": "Role",
    "field_name": "Name",
    "field_current_role": "Current role",
    "field_host": "Host",
    "field_port": "Port",
    "field_login": "Login",
    "field_password": "Password",
    "field_description": "Description",
    "field_issued": "Issued",
    "field_activated": "Activated",
    "field_last_shown": "Last shown",
    "field_revoked": "Revoked",
    "field_deleted": "Deleted",
    # ── main menu ─────────────────────────────────────────────────────────────
    "usage_rules": (
        "USAGE RULES:\n"
        "🚫🚫🚫 STRICTLY PROHIBITED: downloading or using the MAX messenger on the same device where VPN is used\n"
        "🚫🚫🚫 STRICTLY PROHIBITED: downloading torrent content through VPN"
    ),
    "main_menu_text": "Hello, {name}!\n\n{rules}\n\n{warning}\n\n✅ All systems operational.\n\nChoose an action.",
    # ── keys page ─────────────────────────────────────────────────────────────
    "keys_user_title": "<b>User's keys</b>",
    "keys_my_title": "<b>My keys</b>",
    "keys_page_empty": "No keys on this page.",
    "keys_page_title": "{title} · page {page}",
    # ── key creation ──────────────────────────────────────────────────────────
    "create_confirm_title": "<b>Confirm key creation</b>",
    "field_expires_at": "Valid until",
    # ── note confirm ─────────────────────────────────────────────────────────
    "note_confirm_title": "<b>Confirm note</b>",
    "note_confirm_key": "Key",
    "note_confirm_new_note": "New note",
    # ── config hints ─────────────────────────────────────────────────────────
    "xray_config_hint": "Add the link to a VLESS/REALITY-compatible client.",
    "awg_config_hint": "Add the link to an AmneziaVPN client or use the configuration file.",
    "hy2_config_hint": "Add the link to a Hysteria2-capable client (e.g. NekoBox or Hiddify).",
    # ── traffic stats ─────────────────────────────────────────────────────────
    "stats_title": "<b>Stats for {key_title}</b>",
    "stats_unavailable_now": "Stats are currently unavailable. Last successful snapshot:",
    "stats_not_available_yet": "Stats are not available yet.",
    "stats_keys_title": "<b>Key statistics</b>",
    "stats_keys_empty": "<b>Key statistics</b>\n\nNo keys on this page.",
    "stats_last_prefix": "last",
    "stats_unavailable_short": "stats not available yet",
    "stats_updated_fmt": " · updated {at}",
    "stats_attempt_fmt": " · attempt {at}",
    "stats_note": "Note",
    # ── access requests ───────────────────────────────────────────────────────
    "request_title": "<b>Request #{id}</b>",
    "requests_page_empty": "<b>Access requests</b>\n\nNo new requests.",
    "requests_page_title": "<b>Access requests</b> · page {page}",
    "decision_confirm_approve": "approve",
    "decision_confirm_reject": "reject",
    "decision_confirm_title": "<b>Confirm action: {action}</b>",
    # ── user card ─────────────────────────────────────────────────────────────
    "user_card_title": "<b>User</b>",
    "user_keys_title": "<b>Keys</b>",
    "user_no_keys": "No keys.",
    "user_stats_unavailable": "stats not available yet",
    # ── users page ────────────────────────────────────────────────────────────
    "users_title": "<b>Users</b>",
    "users_empty": "No users on this page.",
    "users_page_title": "<b>Users</b> · page {page}",
    "users_key_count": "keys",
    # ── block / unblock ───────────────────────────────────────────────────────
    "block_confirm_title": "<b>Confirm user block</b>",
    "block_keys_to_check": "Keys to check/revoke: {count}",
    "block_action_warning": (
        "This action will block bot access and attempt to revoke VPN keys. "
        "If some VPN keys cannot be disabled automatically, manual server-side verification will be required."
    ),
    "unblock_confirm_title": "<b>Confirm user unblock</b>",
    "unblock_manual_check": "<b>Manual VPN check required</b>",
    "unblock_manual_check_desc": "There may be previously active or problematic VPN keys.",
    "unblock_warning_last_error": "Last block error: {at}",
    "unblock_no_auto_fix": "Unblocking will restore bot access, but will not fix Xray/AWG runtime automatically.",
    "unblock_confirm_success": "After confirmation, the user will regain access to the bot.",
    "unblock_success": "User unblocked. FSM state cleared, flows will restart.",
    "unblock_vpn_check_warning": (
        "Warning: before unblocking, there were signs of incomplete VPN access revocation. "
        "Check Xray/AWG runtime and config manually."
    ),
    # ── audit log ─────────────────────────────────────────────────────────────
    "audit_title": "<b>Action logs</b>",
    "audit_empty": "No entries on this page.",
    "audit_page_title": "<b>Action logs</b> · page {page}",
    "audit_system": "system",
    "audit_created_xray": " created Xray key {label}",
    "audit_created_xray_nolabel": " created Xray key",
    "audit_created_awg": " created AWG key {label}",
    "audit_created_awg_nolabel": " created AWG key",
    "audit_viewed_user_stats": " viewed statistics for user {user}",
    "audit_changed_role": " changed user role",
    "audit_blocked_user": " blocked user",
    "audit_unblocked_user": " unblocked user",
    "audit_access_request_repeat": " submitted a repeat access request",
    "audit_access_request": " submitted an access request",
    "audit_access_approved": " approved access request",
    "audit_access_rejected": " rejected access request",
    "audit_action_generic": " performed action {action}",
    "audit_owner_suffix": " for {owner}",
    # ── proxy texts ───────────────────────────────────────────────────────────
    "proxy_title": "<b>Proxy</b>",
    "proxy_not_configured": "No proxies are configured.",
    "proxy_no_accesses": "<b>Proxy</b>\n\nYou don't have any proxy access yet.",
    "proxy_unavailable": "<b>Proxy</b>\n\nProxy services are currently unavailable.",
    "mtproto_managed_note": (
        "This is personal MTProto access. "
        "When the user is blocked, this MTProto secret will be revoked."
    ),
    "mtproto_static_note": (
        "This is shared MTProto access. "
        "Individual server-side revoke in static mode is not possible."
    ),
    "mtproto_variant1": "Option 1 — standard, try this first:",
    "mtproto_variant2": "Option 2 — with random padding dd, if option 1 doesn't work:",
    "mtproto_try_note": "Try option 1 first. If it doesn't work or media loads slowly, try option 2 with dd.",
    # ── proxy user stats ─────────────────────────────────────────────────────
    "proxy_user_stats_title": "<b>Proxy statistics</b>",
    "proxy_no_issued": "You don't have any issued proxies yet.",
    "proxy_active_header": "<b>Active proxies:</b>",
    "proxy_no_active": "No active proxies.",
    "proxy_recent_errors_header": "<b>Recent issuance errors:</b>",
    "proxy_hidden_old": "Older failed attempts hidden: {n}.",
    "proxy_traffic_header": "<b>Traffic:</b>",
    "proxy_traffic_unavailable": "Per-user traffic accounting for SOCKS5/MTProto is not available and is not faked.",
    # ── proxy admin stats ─────────────────────────────────────────────────────
    "proxy_stats_no_users": "No users with proxy accesses.",
    "proxy_stats_hidden_users": "{n} more users hidden.",
    "proxy_stats_traffic_note": "Traffic: per-user traffic accounting for SOCKS5/MTProto is not available and is not faked.",
    "proxy_socks5_traffic_note": "Traffic: stats unavailable for this proxy type without per-login Dante accounting.",
    "proxy_runtime_unavailable": "Runtime status: unavailable",
    # ── proxy stat access lines ───────────────────────────────────────────────
    "proxy_stat_status": "Status",
    "proxy_stat_issued": "Issued",
    "proxy_stat_activated": "Activated",
    "proxy_stat_last_shown": "Last shown",
    "proxy_stat_revoked": "Revoked",
    "proxy_stat_deleted": "Deleted",
    "proxy_stat_type": "Type",
    # ── announcement batches ─────────────────────────────────────────────────
    "announce_batches_title": "<b>Pending announcements</b>",
    "announce_batches_empty": "<b>Pending announcements</b>\n\nNo pending batch records.",
    # ── private chat guard ────────────────────────────────────────────────────
    "private_only_text": "This operation is available in private chat with the bot only.",
    "admin_private_only_text": "Admin panel is available in private chat with the bot only.",
    # ── FAQ ───────────────────────────────────────────────────────────────────
    "faq_page_title": "<b>Frequently Asked Questions</b> · page {page} of {total}",
    "faq_connect": (
        "After creating a key, the bot will provide the configuration. Copy it into a suitable VPN app "
        "or import the file if available. Depending on the client, both AWG and Xray keys can be added "
        "either via a link (profile) or via a config file. After importing, enable the connection in your app.\n\n"
        "<b>Recommended apps:</b> for AWG — the official AmneziaVPN client; "
        "for Xray — v2RayTun (or alternatives such as Hiddify or NekoBox).\n\n"
        "<b>Tip:</b> keep several different keys — with different protocols and/or transports "
        "(e.g. AWG and Xray TCP/XHTTP). If one of them starts to degrade due to blocking, you can "
        "switch to another and won't be left without a connection."
    ),
    "faq_trouble": (
        "Check your internet, the imported profile, the access expiry date, and whether the same key "
        "is being used on another device. Also try toggling the VPN app off and on. If that doesn't help, "
        "try enabling and disabling airplane mode or restarting the device.\n\n"
        "<b>AWG:</b> if the connection is unstable or won't connect, try lowering the MTU to 1280 "
        "(use the «Change MTU» button in the key settings).\n\n"
        "<b>Xray:</b> if the connection won't establish, try changing the fingerprint "
        "(use the «Change Fingerprint» button in the key settings). Good starting options: Firefox or Edge. "
        "If that doesn't help, try creating a new Xray key with a different transport (TCP / XHTTP) — "
        "the transport choice is offered during key creation.\n\n"
        "If the problem persists, contact support."
    ),
    "faq_key_statuses": (
        "<b>Active</b> — the key is working.\n"
        "<b>Applying / Revoking / Deleting</b> — an operation is in progress, please wait.\n"
        "<b>Revoked</b> — the key is disabled on the server; stats and note are kept in the bot.\n"
        "<b>Deleted</b> — the key is fully removed along with its statistics.\n"
        "<b>Failed</b> — something went wrong; contact support."
    ),
    "faq_revoke_delete": (
        "<b>Revoke</b> — irreversibly disables the key on the server. "
        "Stats and note are kept in the bot; the key remains visible in the list with the «Revoked» status.\n\n"
        "<b>Delete</b> — irreversibly removes the key along with its stats and note from the bot."
    ),
    "faq_expired": (
        "Create a new key via «Create key». "
        "The validity period is chosen at creation time: 7 days, 30 days, custom, or permanent. "
        "Extending an existing key is not possible."
    ),
    "faq_device": (
        "Yes. One key is meant strictly for one device. Using the same key on multiple devices "
        "will inevitably cause problems: connections become unstable (devices keep dropping each "
        "other), and statistics and access management get mixed up. Create a separate key for each device."
    ),
    "faq_stats": (
        "Open «My keys», select the key, and tap «Statistics». "
        "You'll see incoming and outgoing traffic volumes. Data is updated automatically."
    ),
    "faq_choice": (
        "<b>AWG (AmneziaWG)</b> — based on WireGuard: simpler and faster, with lower latency. "
        "A good pick when VPNs aren't blocked.\n\n"
        "<b>Xray (VLESS + REALITY)</b> — disguises traffic as ordinary HTTPS, better at bypassing "
        "blocks and DPI, but a bit more complex and sometimes slightly slower.\n\n"
        "If you're not sure what to choose, start with Xray — it's more reliable under blocking. "
        "If top speed matters and there's no blocking, go with AWG."
    ),
    "faq_fingerprint": (
        "A fingerprint is an imitation of the TLS stack of a popular browser or device. "
        "Xray pretends to be a regular browser so its traffic looks like ordinary HTTPS. "
        "This makes it harder to detect and block VPN traffic.\n\n"
        "<b>Firefox</b> and <b>Randomized</b> — a good choice for most cases. "
        "Note: Randomized is less stable than real fingerprints.\n"
        "<b>Chrome / Safari / iOS / Android / Edge / 360 / QQ</b> — alternatives if Firefox doesn't work.\n"
        "<b>Random</b> — a random fingerprint from the list is picked each time.\n"
        "<b>Randomized</b> — a random fingerprint with randomized TLS parameters; maximally obfuscates the pattern.\n\n"
        "The fingerprint applies only to Xray keys and has no effect on AWG."
    ),
    "faq_mtu": (
        "MTU is the maximum network packet size. It applies only to AWG keys.\n\n"
        "The recommended value of 1280 works in most cases. "
        "Increase it (e.g. to 1370 or 1420) if the connection is stable but speed seems low."
    ),
    "faq_note_why": (
        "A note helps you identify which device a key belongs to — for example, «Laptop» or «Phone». "
        "Without a note, it's easy to mix up multiple keys."
    ),
    "faq_proxy": (
        "The Proxy section offers two types:\n"
        "<b>SOCKS5</b> — a universal proxy for browsers and apps that support manual proxy settings.\n"
        "<b>MTProto</b> — a proxy specifically for Telegram when it's blocked without VPN.\n\n"
        "Proxies work independently from VPN keys."
    ),
    "faq_settings": (
        "The Settings section holds your personal preferences:\n\n"
        "👤 <b>Personal cabinet</b> — your profile and stats: role, registration date, number of "
        "active keys and proxy accesses, total traffic.\n\n"
        "🌐 <b>Language</b> — the bot interface language (Russian or English), for you only.\n\n"
        "🔔 <b>Expiry notifications</b> — reminders that a key is about to expire; you can turn them "
        "off. The message about an already-expired key being auto-revoked is sent regardless."
    ),
    "faq_server_restart": (
        "Yes, this is expected. The server restarts on even-numbered dates at 04:00 MSK. "
        "The restart takes a few minutes — the connection briefly drops and reconnects automatically."
    ),
    "faq_security": (
        "<b>We don't log your activity.</b> We don't record which sites you open, and we don't "
        "store the contents of your traffic — the tunnel is opaque to us.\n\n"
        "<b>Encryption.</b> The connection is protected by modern protocols (AmneziaWG / "
        "VLESS+REALITY), and the traffic can't be read from the outside.\n\n"
        "<b>Only you can see your key notes</b> — they just help you tell devices apart and are "
        "not shown to anyone.\n\n"
        "Still have privacy questions? Contact support."
    ),
    "faq_support": (
        "Support: @ktotakmoje\n\n"
        "To help you faster, please include up front:\n"
        "• the key type (AWG or Xray) and its number;\n"
        "• your device and app;\n"
        "• what you've already tried (see «Why doesn't it work?»).\n\n"
        "We usually reply within a day."
    ),
    "faq_not_found": "Answer not found.",
    # ── errors ────────────────────────────────────────────────────────────────
    "internal_error": "An internal error occurred. Please try again later.",
    "cancel_done": "Operation cancelled.",
    # ── start handler ─────────────────────────────────────────────────────────
    "blocked_no_request": "A new request has not been created yet. Wait for the admin's decision.",
    "blocked_request_created": "Your new access request has been submitted. Wait for the admin's decision.",
    "blocked_request_pending": "Your new request is already pending admin review.",
    "request_already_processed": "Request already processed. Wait for the admin's decision.",
    "request_created": "Access request submitted. Wait for the admin's decision.",
    "request_pending": "Your request is already pending admin review.",
    "trial_key_active": "You have an active trial key:\n\n{key_text}",
    "trial_offer": "You can request a 7-day trial access. An admin will review your request.",
    "notify_admin_new_request": (
        "<b>New access request</b>\n"
        "Telegram ID: <code>{user_id}</code>\n"
        "Username: {username}\n"
        "Request: #{request_id}"
    ),
    # ── admin handler ─────────────────────────────────────────────────────────
    "admin_panel_title": "Admin panel:",
    "moderator_panel_title": "Moderator panel:",
    "announce_prompt": "Send the announcement message. It will be delivered to approved users unchanged after confirmation.",
    "announce_confirm_prompt": "Send this announcement to users?\nRecipients among approved users: {count}\nThe message will be sent without any additional signature.",
    "announce_choose_roles": "Step 1/3. Choose recipient roles (multiple allowed), then \"Next\", or \"All roles\".",
    "announce_choose_protocols": "Step 2/3. Choose protocols (active access required), then \"Next\", or \"All protocols\".",
    "announce_choose_transports": "Step 3/3. Choose the VLESS transport, then \"Next\", or \"Any transport\".",
    "announce_confirm_prompt_segmented": "Send this announcement?\n{segment}\nRecipients: {count}\nThe message will be sent without any additional signature.",
    "seg_role_approved": "Approved",
    "seg_role_moderator": "Moderators",
    "seg_role_pending": "Pending",
    "seg_role_superadmin": "Superadmins",
    "seg_all": "all",
    "seg_select_one": "Select at least one option or tap \"All\".",
    "seg_summary_roles": "Roles: {value}",
    "seg_summary_protocols": "Protocols: {value}",
    "seg_summary_transports": "Transport: {value}",
    "btn_seg_all": "✅ All",
    "btn_seg_next": "Next ➡️",
    "announce_sending": "Sending...",
    "announce_sent": "Announcement sent.\nRecipients: {total}\nSuccessful: {success}\nFailed: {failed}",
    "announce_cancelled": "Cancelled",
    "announce_stale": "Announcement already sent or expired.",
    "announce_schedule_prompt": "Enter send date and time in DD.MM.YYYY HH:MM format (Moscow time):",
    "announce_invalid_time": "Invalid format or time in the past.\nEnter date and time in DD.MM.YYYY HH:MM format (Moscow time):",
    "announce_session_expired": "Session expired, please start over.",
    "announce_scheduled": "Announcement scheduled.\nBatch #{batch_id}\nRecipients: {total}\nSend time: {time} MSK",
    "announce_update_list": "Updating list...",
    "batch_cancelled": "Batch #{id} cancelled.",
    "batch_already_cancelled": "Batch #{id} was already cancelled.",
    "batch_resume_sending": "Resuming delivery...",
    "batch_processed": "Batch #{id} processed.\nRecipients: {total}; successful: {success}; failed: {failed}.",
    "request_already_processed_msg": "Request already processed.",
    "request_approved_msg": "Request approved.",
    "request_rejected_msg": "Request rejected.",
    "notify_approved": "Your request has been approved. Send /start to open the menu.",
    "notify_rejected": "Your request has been rejected.",
    "user_approved_msg": "User approved.",
    "processing": "Processing...",
    "blocking": "Blocking...",
    "unblocking": "Unblocking...",
    "user_already_blocked": "User is already blocked.",
    "user_already_unblocked": "User is not blocked.",
    "user_blocked_success": "User blocked.\nVPN keys disabled: {keys}\nProxy accesses disabled: {proxies}\nErrors: 0\nThe user can now only use /start to submit a new request.",
    "user_blocked_with_errors": "User blocked in the bot, but not all server access could be revoked automatically.\nVPN keys disabled: {keys}\nProxy accesses disabled: {proxies}\nErrors: {errors}\nCheck Xray/AWG/SOCKS5/MTProto runtime and config manually.",
    "static_mtproto_block_warning": "⚠️ MTProto is running in static mode: the shared secret remains active for all users. To revoke access rotate MTPROTO_SECRET and restart the proxy.",
    "notify_user_blocked": "Your access has been blocked by the admin.",
    "choose_user_for_key": "Choose a user to issue a key to:",
    "action_stale": "Action expired, please start over",
    "action_stale_msg": "Action expired, please start over.",
    "mtu_invalid": "Invalid MTU value: 1–1500",
    "mtu_prompt": "Choose MTU for the key:",
    "mtu_custom_prompt": "Enter MTU (1 to 1500):",
    "mtu_enter_integer": "Enter an integer between 1 and 1500:",
    "fp_prompt": "Choose fingerprint for the key:",
    "fp_change_prompt": "Select new fingerprint:",
    "fp_invalid": "Unsupported fingerprint value",
    "fp_updated": "Fingerprint updated.",
    "expiry_invalid": "Invalid period: 1–{max} days",
    "expiry_prompt": "Choose key validity period:",
    "expiry_custom_prompt": "Enter number of days (1 to 365):",
    "days_enter_integer": "Enter an integer number of days (1 to 365):",
    "days_enter_range": "Enter a number from 1 to {max}:",
    "key_note_prompt": "Enter a note for the key or send <code>-</code> to leave it empty.",
    "choose_key_type": "Choose protocol:",
    "choose_vless_transport": "Choose VLESS transport:",
    "vless_http_unavailable": "VLESS (HTTP) is temporarily unavailable.",
    "choose_xhttp_profile": "Choose the XHTTP transport profile:",
    "xhttp_profile_invalid": "Unknown transport profile.",
    "xhttp_profile_base_name": "🟢 Basic (recommended)",
    "xhttp_profile_base_desc": "Universal mode. The best balance of speed and stability, suitable for most users.",
    "xhttp_profile_antisib_name": "🛡 Anti-blocking",
    "xhttp_profile_antisib_desc": "Use if the connection drops at connect time because of TLS-handshake-count blocking. Single channel — may be slower on a weak network.",
    "xhttp_profile_multi_name": "🔀 Multi-connection",
    "xhttp_profile_multi_desc": "For resilient long sessions: splits traffic into short connections, helping against speed throttling on long-lived connections.",
    "creating_key": "Creating key...",
    "key_unknown_type": "Unknown key type.",
    "admin_delivered_awg": "Admin has issued you AWG key #{id}.\n\n{config_text}",
    "admin_delivered_xray": "Admin has issued you Xray key #{id}.\n\n{config_text}",
    "trial_no_pending": "No pending trial access requests.",
    "trial_list_title": "<b>Trial access requests:</b>",
    "trial_approved_msg": "Trial key issued. Config sent to user.",
    "trial_rejected_msg": "Trial access request rejected.",
    "trial_quota_resetting": "Resetting quota...",
    "trial_quota_reset": "Trial access quota reset.",
    "updating_stats": "Updating statistics...",
    "updating_proxy_status": "Updating status...",
    "updating_server_status": "Updating server status...",
    "updating_diagnostics": "Updating diagnostics...",
    "updating_proxy_stats": "Updating proxy statistics...",
    "backup_disabled": "OFFSITE_BACKUP_ENCRYPTION_KEY is not configured — backup disabled.",
    "backup_creating": "Creating backup...",
    "backup_sent": "Backup sent.\nSuccessful: {success}\nFailed: {failed}",
    "backup_sent_with_recovery": (
        "Backup sent.\nSuccessful: {success}\nFailed: {failed}\n"
        "Recovery bundle: {recovery_success} sent, {recovery_failed} failed"
    ),
    "moderator_role_removed": "Moderator role removed. User is now a regular approved user.",
    "moderator_role_assigned": "User set as moderator.",
    "admin_unote_current": " Current: <code>{note}</code>",
    "admin_unote_prompt": "Enter a note for user <code>{user_id}</code> or send <code>-</code> to clear it.{current}",
    "cannot_issue_to_blocked": "Cannot issue a key to a blocked user",
    "issue_select_user": "Choose a user to issue a key to:",
    # ── keys handler ──────────────────────────────────────────────────────────
    "revoke_prompt": "Revoke key #{key_id}? Access will be disabled.",
    "delete_prompt": (
        "Permanently delete key #{key_id}? Access will be disabled on the server, "
        "the key record and its statistics will be removed from the bot. This action cannot be undone."
    ),
    "executing": "Executing...",
    "config_already_sent": "The configuration file has already been sent.",
    "key_revoked": "Key revoked.",
    "key_deleted": "Key permanently deleted.",
    "key_deleted_with_list": "Key permanently deleted.\n\n{list}",
    "unknown_action": "Unknown action",
    "edit_note_prompt": "New note for {type} #{id}. Send <code>-</code> to clear it.",
    "saving": "Saving...",
    "note_updated": "Note updated.",
    "trial_already_used": "You have already used your trial access.",
    "trial_choose_protocol": "Choose protocol for the trial key (7 days):",
    "trial_request_submitted": "Trial access request submitted. Waiting for admin's decision.",
    "trial_request_sent": "Request submitted!",
    "trial_no_access": "No access to this key.",
    "ensure_send_start": "Send /start first to create an access request",
    "access_not_approved": "Access not yet approved. Wait for the admin's decision.",
    "invalid_callback_btn": "Invalid callback button",
    "revoke_context_stale": "Revoke context expired, please reopen the key list",
    "delete_context_stale": "Delete context expired, please reopen the key list",
    "trial_admin_notify": (
        "<b>New trial key request</b>\n"
        "Telegram ID: <code>{user_id}</code>\n"
        "Protocol: {protocol}\n"
        "Request: #{req_id}"
    ),
    # ── proxy handler ─────────────────────────────────────────────────────────
    "socks5_unavailable": "SOCKS5 is currently unavailable",
    "mtproto_unavailable": "MTProto is currently unavailable",
    "proxy_action_stale": "Action expired",
    "proxy_stale_retry": "Action expired. Go back to the Proxy section and try again.",
    "executing_proxy": "Executing...",
    "proxy_unknown_type": "Unknown proxy type.",
    "proxy_cancelled": "Cancelled",
    "proxy_confirm_socks5": (
        "<b>Confirm SOCKS5 issuance</b>\n\n"
        "A personal Dante Linux user and SOCKS5 password will be created."
    ),
    "proxy_confirm_mtproto_managed": (
        "<b>Confirm MTProto issuance</b>\n\n"
        "An individual MTProto secret will be created. After MTProxy applies it, the user will receive "
        "a standard link and a link with random padding dd."
    ),
    "proxy_confirm_mtproto_static": (
        "<b>Confirm MTProto issuance</b>\n\n"
        "The bot will show static Telegram MTProto Proxy links. "
        "With a shared secret, individual server-side revoke for MTProto is not possible."
    ),
    # ── keyboard buttons (common) ─────────────────────────────────────────────
    "btn_my_keys": "🔑 My keys",
    "btn_create_key": "➕ Create key",
    "btn_proxy": "🌐 Proxy",
    "btn_help": "❓ Help",
    "btn_admin_panel": "🛡 Admin panel",
    "btn_back_to_menu": "Main menu",
    "btn_back_to_faq": "Back to FAQ",
    "btn_cancel": "Cancel",
    "btn_confirm": "Confirm",
    "btn_prev": "Previous",
    "btn_next": "Next",
    "btn_faq_connect": "How to connect?",
    "btn_faq_trouble": "Why doesn't it work?",
    "btn_faq_key_statuses": "What do key statuses mean?",
    "btn_faq_revoke_delete": "Revoke vs delete a key?",
    "btn_faq_expired": "What if my key has expired?",
    "btn_faq_device": "1 key = 1 device?",
    "btn_faq_stats": "How to check traffic stats?",
    "btn_faq_choice": "What to choose: AWG or Xray?",
    "btn_faq_fingerprint": "What is a fingerprint?",
    "btn_faq_mtu": "What is MTU?",
    "btn_faq_note_why": "Why add a note to a key?",
    "btn_faq_proxy": "What is a proxy?",
    "btn_faq_settings": "What's in Settings?",
    "btn_faq_server_restart": "Server restarting — is that normal?",
    "btn_faq_security": "Security & privacy",
    "btn_faq_support": "Support",
    "btn_keyboard_placeholder": "Choose an action",
    # ── settings & personal cabinet ───────────────────────────────────────────
    "btn_settings": "⚙️ Settings",
    "btn_settings_cabinet": "👤 Personal cabinet",
    "btn_settings_language": "🌐 Language: {lang}",
    "btn_settings_notifications": "Expiry notifications",
    "btn_back_to_settings": "‹ Back to settings",
    "lang_name_ru": "Русский",
    "lang_name_en": "English",
    "settings_title": "<b>⚙️ Settings</b>",
    "settings_intro": (
        "Your personal settings live here. Below is what each button does:\n\n"
        "👤 <b>Personal cabinet</b> — your profile and personal statistics: role, "
        "registration date, number of active keys and proxy accesses, total traffic.\n\n"
        "🌐 <b>Language</b> — the bot's interface language. Switches all messages and "
        "buttons between Russian and English for you only.\n\n"
        "🔔 <b>Expiry notifications</b> — reminders that a key is about to expire. You can "
        "turn them off if you don't need them. The notice about an already-expired key being "
        "automatically revoked is always delivered."
    ),
    "cabinet_title": "<b>👤 Personal cabinet</b>",
    "field_registered": "Registered",
    "cabinet_active_keys": "Active keys: {total} (Xray: {xray}, AWG: {awg}, Hysteria2: {hysteria2})",
    "cabinet_traffic": "Traffic: ↓ {down} · ↑ {up}",
    "cabinet_proxy_count": "Proxy accesses: {count}",
    "settings_language_changed": "Language changed",
    "settings_notifications_on": "Expiry notifications enabled",
    "settings_notifications_off": "Expiry notifications disabled",
    "key_expiry_reminder": "Your {type} key #{id} expires in {days} {noun}.",
    "key_expired_revoked": "Your {type} key #{id} has expired — access was automatically revoked.",
    # ── keyboard buttons (admin) ──────────────────────────────────────────────
    "btn_approve": "Approve",
    "btn_reject": "Reject",
    "btn_server_status": "📊 Server status",
    "btn_access_requests": "📋 Access requests",
    "btn_users": "👥 Users",
    "btn_key_stats": "📊 Key statistics",
    "btn_proxy_status": "🌐 Proxy status",
    "btn_modules": "⚙️ Protocol modules",
    "btn_maintenance": "🛠 Maintenance mode",
    "btn_backend_diagnostics": "🔍 Backend diagnostics",
    "btn_action_logs": "📜 Action logs",
    "btn_issue_key_to_user": "🔑 Issue key to user",
    "btn_trial_accesses": "🧪 Trial accesses",
    "btn_announcement": "📢 Announcement",
    "btn_announcement_recovery": "🔄 Announcement recovery",
    "btn_db_backup": "💾 DB backup",
    "btn_send_now": "Send now",
    "btn_schedule": "Schedule",
    "btn_approve_user": "Approve user",
    "btn_block": "Block",
    "btn_unblock": "Unblock",
    "btn_issue_key": "Issue key",
    "btn_reset_trial": "Reset trial access",
    "btn_user_keys": "User's keys",
    "btn_edit_note_user": "Edit note",
    "btn_set_moderator": "Set as moderator",
    "btn_remove_moderator": "Remove moderator role",
    "btn_to_users": "To users",
    "btn_block_confirm": "Confirm block",
    "btn_unblock_confirm": "Confirm unblock",
    "btn_refresh": "Refresh",
    "btn_anomaly_dismiss": "✅ I've read it",
    "btn_warp_alert_dismiss": "✅ Got it",
    # ── server status panel ───────────────────────────────────────────────────
    "server_status_title": "REAL-TIME SERVER STATUS",
    "server_status_updated_at": "updated {time}",
    "server_status_cpu_hypervisor": "hypervisor",
    "server_status_disk_label": "Disk",
    "server_status_disk_value": "{used} GB used of {total} GB",
    "server_status_network_label": "Network activity",
    "server_status_net_in": "Inbound",
    "server_status_net_out": "Outbound",
    "server_status_swap_label": "Swap",
    "server_status_swap_off": "off",
    "server_status_online_label": "Online clients",
    "server_status_online_collecting": "collecting…",
    "server_status_loadavg_label": "Load average (1/5/15m)",
    "server_status_uptime_label": "Uptime",
    "server_status_net_avg": "avg",
    "server_status_net_peak": "peak",
    "btn_server_status_detailed_on": "🔬 Detailed metrics: ON",
    "btn_server_status_detailed_off": "🔬 Detailed metrics: OFF",
    # ── maintenance mode ──────────────────────────────────────────────────────
    "btn_maintenance_enable": "🛠 Enable maintenance mode",
    "btn_maintenance_disable": "✅ Finish works",
    "btn_maintenance_skip_text": "No text (default)",
    "maintenance_panel_title": "<b>🛠 Maintenance mode</b>",
    "maintenance_status_on": "Status: 🔴 ON",
    "maintenance_status_off": "Status: 🟢 off",
    "maintenance_started_at": "Enabled: {time}",
    "maintenance_current_banner": "Banner shown to users:\n{banner}",
    "maintenance_enable_prompt": (
        "Send the banner text users will see during the works, "
        "or tap \"No text\" to show the default message."
    ),
    "maintenance_default_banner": (
        "🛠 Maintenance is in progress. The bot is temporarily unavailable. "
        "Please try again later."
    ),
    "maintenance_enabling": "Enabling maintenance mode…",
    "maintenance_disabling": "Finishing works…",
    "maintenance_broadcast_on": "🛠 Dear users!\n\n{banner}",
    "maintenance_broadcast_off": "✅ Maintenance is finished. The bot is available again. Thanks for waiting!",
    "maintenance_enabled_ok": "Maintenance mode enabled. {count} users notified.",
    "maintenance_disabled_ok": "Maintenance mode disabled. {count} users notified.",
    # ── keyboard buttons (keys) ───────────────────────────────────────────────
    "btn_back": "Back",
    "btn_config": "Config",
    "btn_stats": "Statistics",
    "btn_revoke": "Revoke",
    "btn_delete": "Delete",
    "btn_note": "Note",
    "btn_show_config": "Show config",
    "btn_edit_note_key": "Edit note",
    "btn_to_list": "Back to list",
    "btn_mtu_recommended": "1280 (recommended)",
    "btn_enter_manually": "Enter manually",
    "btn_fp_firefox": "Firefox (recommended)",
    "btn_fp_random": "Random — random from list (not recommended)",
    "btn_fp_randomized": "Randomized — fully randomized params",
    "btn_change_fp": "Change Fingerprint",
    "btn_open_key": "Open key",
    "btn_permanent": "Permanent",
    "btn_7_days": "7 days",
    "btn_30_days": "30 days",
    "btn_enter_days": "Enter number of days",
    "btn_get_config": "Get config",
    "btn_request_trial": "Request trial access (7 days)",
    # ── keyboard buttons (proxy) ──────────────────────────────────────────────
    "btn_get_socks5": "Get SOCKS5",
    "btn_get_mtproto": "Get MTProto",
    "btn_go_back": "Back",
    "btn_back_to_proxy": "Back to Proxy",
    # ── Protocol modules panel ────────────────────────────────────────────────
    "btn_module_disable": "Disable",
    "btn_module_enable": "Enable",
    "btn_module_disable_step1": "Yes, disable →",
    "btn_module_disable_step2": "⚠️ CONFIRM DELETION",
    "btn_module_enable_confirm": "Enable protocol",
    "btn_modules_back": "← Back to modules",
    "modules_panel_title": (
        "<b>⚙️ Protocol modules</b>\n\n"
        "Disabling a protocol <b>permanently deletes</b> all related bot-side data (keys, proxy accesses, database records).\n"
        "Server-side accounts (AWG/Xray configs, Linux users, MTProto secrets) are NOT removed — clean them up manually.\n"
        "Once disabled, the protocol is completely hidden; only «Backend diagnostics» will show it was disabled.\n\n"
        "You can re-enable a protocol at any time."
    ),
    "module_disable_confirm1": (
        "<b>⚠️ Disable protocol {label}</b>\n\n"
        "This action will:\n"
        "• permanently hard-delete all keys / proxy accesses for this protocol from the bot database\n"
        "• remove all buttons and mentions of the protocol\n"
        "• NOT touch the server side (AWG/Xray configs etc.) — clean those up manually\n\n"
        "Continue?"
    ),
    "module_disable_confirm2": (
        "<b>🛑 FINAL CONFIRMATION — {label}</b>\n\n"
        "All data for this protocol will be <b>permanently destroyed</b>.\n"
        "Click the button below to confirm."
    ),
    "module_enable_confirm": (
        "<b>Enable protocol {label}?</b>\n\n"
        "The protocol will become available to users again. Old data will not be restored."
    ),
    "module_disabling": "Disabling protocol...",
    "module_enabling": "Enabling protocol...",
    "module_disabled_ok": "✅ Protocol <b>{label}</b> disabled. Records deleted: {deleted}.",
    "module_enabled_ok": "✅ Protocol <b>{label}</b> enabled.",
    # ── WARP routing module ───────────────────────────────────────────────────
    "btn_warp": "📡 WARP tunnel",
    "btn_warp_upload": "📤 Upload config",
    "btn_warp_replace": "📤 Replace config",
    "btn_warp_delete": "🗑 Delete config",
    "btn_warp_enable": "🟢 Enable",
    "btn_warp_disable": "🔴 Disable",
    "btn_warp_restart": "🔄 Restart",
    "btn_warp_settings": "⚙️ Settings",
    "btn_warp_split": "🌐 Split routes",
    "warp_title": "📡 <b>Outbound IP masking</b>",
    "warp_settings_title": "⚙️ <b>WARP Settings</b>",
    "warp_status_disabled": "Status: 🔴 Disabled",
    "warp_intro": (
        "Hides the server's outbound IP for spy apps:\n"
        "routes their traffic through an AmneziaWG tunnel.\n"
        "On connection loss it falls back to the direct path."
    ),
    "warp_no_config_hint": "Upload a config to enable the module.",
    "warp_label_module": "Module:",
    "warp_label_tunnel": "Tunnel:",
    "warp_label_routes": "Routes:",
    "warp_label_handshake": "Handshake:",
    "warp_label_fails": "Consecutive failures:",
    "warp_module_on": "✅ Enabled",
    "warp_module_off": "🔴 Disabled",
    "warp_tunnel_up": "🟢 Up",
    "warp_tunnel_down": "🔴 Unreachable",
    "warp_routes_active": "✅ Active ({count} CIDR)",
    "warp_routes_fallback": "⚠️ Fallback (traffic → direct)",
    "warp_routes_inactive": "⏸ Inactive",
    "warp_routes_off": "⚪ Disabled (all traffic direct)",
    "warp_routes_drift": "⚠️ Out of sync (marker: {marker}, in table: {table}, in list: {count})",
    "warp_routes_hint": (
        "ℹ️ The On/Off/Restart buttons control the split <b>routes</b> (table T), "
        "not the tunnel: the <code>out-warp</code> interface is owned by systemd."
    ),
    "warp_handshake_never": "no data",
    "warp_ago_seconds": "{n} sec ago",
    "warp_ago_minutes": "{n} min ago",
    "warp_ago_hours": "{n} h ago",
    "warp_ago_days": "{n} d ago",
    "warp_settings_config": "Config:",
    "warp_settings_iface": "Interface:",
    "warp_settings_routes": "Routes:",
    "warp_upload_prompt": (
        "Send the AmneziaWG configuration file (<code>.conf</code>) as a document.\n\n"
        "It must contain the AmneziaWG fields (Jc, S1, S2) and a non-empty AllowedIPs. "
        "Whose outbound IP to mask (the spy apps' addresses) is decided by your AllowedIPs."
    ),
    "warp_upload_not_document": "Please send the <code>.conf</code> file as a document.",
    "warp_upload_too_large": "The configuration file is too large.",
    "warp_upload_read_failed": "Could not read the file. Please try again.",
    "warp_config_invalid": "❌ Config rejected: {error}",
    "warp_config_installed": "✅ Config installed, routes: {count}",
    "warp_delete_confirm": "Delete the WARP config and disable the module?",
    "warp_deleted": "🗑 Config deleted, module disabled.",
    "warp_enabled_ok": "✅ WARP module enabled.",
    "warp_disabled_ok": "🔴 WARP module disabled.",
    "warp_restarted_ok": "🔄 WARP module restarted.",
    "warp_last_error": "⚠️ {error}",
    "warp_processing": "Working…",
}
