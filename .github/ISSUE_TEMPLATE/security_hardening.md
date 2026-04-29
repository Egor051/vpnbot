---
name: Security hardening
about: Propose defensive improvements without exposing live secrets
title: "[Security hardening]: "
labels: security
assignees: ""
---

## Security Notice

Do not disclose working secrets in this issue. Do not paste Telegram tokens, `.env` files, private keys, Xray Reality key pairs from active servers, AmneziaWG private keys, full VPN configs, SQLite database dumps, server credentials, or unredacted logs.

For vulnerabilities that expose secrets, access control bypasses, live configs, database contents, or server credentials, follow `SECURITY.md` and use responsible disclosure instead of a public issue.

## Security Area

- [ ] Telegram token/config handling
- [ ] Admin authorization
- [ ] User ownership checks
- [ ] Access approval
- [ ] Xray config writes/reload
- [ ] AmneziaWG config writes/runtime peers
- [ ] SQLite/database/migrations
- [ ] Audit logging/secret masking
- [ ] systemd/deployment permissions
- [ ] Backup/rollback behavior
- [ ] Documentation

## Description

<!-- What should be hardened? -->

## Impact

<!-- What could go wrong if this is not improved? Keep it high-level and redacted. -->

## Proposed Mitigation

<!-- What change would reduce the risk? -->

## Safe Reproduction

<!-- Use placeholders or a local test setup. Do not include live secrets, configs, or database content. -->

## Notes

<!-- Optional context, related files, or test ideas. -->
