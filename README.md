# OWASP A09:2025 - Security Logging and Monitoring Failures

> **WARNING: This repository contains INTENTIONALLY VULNERABLE code for security scanner testing. DO NOT deploy to production.**

## Vulnerabilities Included

- **Login Failures Never Logged** – `/login` returns 401 on bad credentials with zero audit trail; no logging call, no lockout, brute-force is invisible
- **Sensitive Data Logged in Plaintext** – `/api/checkout` writes full passwords, credit card numbers, and auth tokens directly into `app.log`
- **Log Injection / Log Forging** – `/api/log-action` writes user-supplied input into a log line via string concatenation, allowing CRLF injection to forge fake log entries
- **No Audit Log on Sensitive Admin Actions** – `/admin/delete-user/<id>` deletes a user with no audit log entry at all
- **No Alerting / Monitoring** – repeated failures from the same IP trigger no alert; see `/api/security-status` and comments in `app.py` for what proper monitoring would look like

## Stack
Python 3 / Flask / SQLite

## Setup
```bash
pip install -r requirements.txt
python db_setup.py
python app.py
```

## Attack Examples
```bash
# Login failures leave no trace - brute force freely, app.log stays empty
curl -X POST http://localhost:5009/login -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "wrong-guess-1"}'
curl -X POST http://localhost:5009/login -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "wrong-guess-2"}'
# ... repeat as many times as you like, no lockout, no log entry, no alert

# Sensitive data logged in plaintext - password, card, and token land in app.log
curl -X POST http://localhost:5009/api/checkout -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password1", "credit_card": "4222222222222222", "auth_token": "tok_alice_1a2b3c4d"}'

# Log injection - forge a fake log entry via CRLF
curl -X POST http://localhost:5009/api/log-action -H "Content-Type: application/json" \
  -d '{"username": "attacker", "action": "viewed profile\r\n2024-01-01 00:00:00 INFO User action: user=admin action=login succeeded (FORGED ENTRY)"}'

# Sensitive admin action with no audit trail
curl -X DELETE http://localhost:5009/admin/delete-user/2

# Confirm monitoring/alerting is absent
curl http://localhost:5009/api/security-status
```
