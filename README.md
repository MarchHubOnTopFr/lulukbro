# Synthia API v4

**Luarmor-alternative** — a self-hosted Lua script protection and key management system.

Store your Lua scripts server-side. Users are issued HWID-locked keys. Scripts are only served after successful key + HWID verification. Includes webhooks, an admin panel, full audit logging, and a Lua loader generator.

---

## Feature Comparison

| Feature                       | Synthia v4 | Luarmor |
|-------------------------------|:----------:|:-------:|
| HWID-locked key system        | ✅         | ✅      |
| Key expiry                    | ✅         | ✅      |
| Key enable/disable            | ✅         | ✅      |
| HWID reset (with cooldown)    | ✅         | ✅      |
| Server-side script storage    | ✅         | ✅      |
| Lua loader snippet generation | ✅         | ✅      |
| Per-script key assignment     | ✅         | ✅      |
| Script versioning             | ✅         | ✅      |
| Webhook callbacks             | ✅         | ✅      |
| Audit log                     | ✅         | ❌      |
| Self-hosted / open source     | ✅         | ❌      |
| Admin dashboard               | ✅         | ✅      |
| No monthly fees               | ✅         | ❌      |

---

## Quick Start

```bash
cp .env.example .env        # fill in DB creds + generate a JWT_SECRET
npm install
npm start                   # → http://localhost:18635

# Create your first admin account
node admin.js create-admin yourname yourpassword
```

---

## Environment Variables

| Variable                      | Default     | Description                                      |
|-------------------------------|-------------|--------------------------------------------------|
| `DB_USER`                     | postgres    | PostgreSQL user                                  |
| `DB_HOST`                     | localhost   | PostgreSQL host                                  |
| `DB_NAME`                     | synthia     | Database name                                    |
| `DB_PASSWORD`                 | —           | **Required.** Database password                  |
| `DB_PORT`                     | 5432        | PostgreSQL port                                  |
| `DB_POOL_MAX`                 | 20          | Max pool connections                             |
| `DB_POOL_MIN`                 | 2           | Min idle connections kept warm                   |
| `JWT_SECRET`                  | —           | **Required.** 48+ char random string             |
| `JWT_EXPIRY`                  | 7d          | Token expiry (e.g. 1d, 12h, 7d)                 |
| `PORT`                        | 18635       | HTTP listen port                                 |
| `NODE_ENV`                    | production  | `development` enables detailed error output      |
| `CORS_ORIGIN`                 | *           | Allowed CORS origin                              |
| `PUBLIC_URL`                  | auto        | Base URL used in loader snippet generation       |
| `MAX_KEYS_PER_USER`           | 10          | Max keys a user can own                          |
| `HWID_RESET_COOLDOWN_HOURS`   | 24          | Hours between user self-service HWID resets      |
| `MEMORY_THRESHOLD`            | 85          | System memory % before warning                   |
| `UPTIME_LIMIT_HOURS`          | 48          | Auto-restart after N hours (PM2 restarts)        |
| `MONITOR_INTERVAL_MS`         | 300000      | Health check interval                            |
| `AUDIT_LOG_RETENTION_DAYS`    | 90          | Auto-prune audit logs older than N days          |
| `CRON_INTERVAL_MS`            | 21600000    | How often the maintenance cron runs (6 h)        |

Generate a JWT_SECRET:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

---

## API Reference

### Auth

| Method | Path           | Auth | Description                     |
|--------|----------------|------|---------------------------------|
| POST   | `/auth/signup` | —    | Register new account            |
| POST   | `/auth/login`  | —    | Login, returns JWT              |
| GET    | `/auth/me`     | JWT  | Current user profile            |

Auth endpoints are rate-limited to **20 requests / 15 min per IP** to prevent brute-force.

```json
POST /auth/login
{ "username": "alice", "password": "secret123" }

→ { "success": true, "token": "eyJ...", "role": "user" }
```

All protected routes require: `Authorization: Bearer <token>`

---

### Keys (JWT required)

| Method | Path                | Description                              |
|--------|---------------------|------------------------------------------|
| POST   | `/keys/generate`    | Generate a new key                       |
| GET    | `/keys/list`        | List all your keys (includes `is_expired` flag) |
| GET    | `/keys/raw`         | Lua table of active key→HWID mappings    |
| PATCH  | `/keys/note`        | Update key note                          |
| PATCH  | `/keys/hwid`        | Manually bind an HWID                    |
| PATCH  | `/keys/hwid/reset`  | Reset HWID (24 h cooldown)               |
| PATCH  | `/keys/toggle`      | Enable ↔ disable key                    |
| DELETE | `/keys/delete`      | Delete key                               |

```json
POST /keys/generate
{ "note": "for alice", "expires_in": 30 }

→ { "success": true, "key": { "id": 1, "key": "uuid", "expires_at": "...", ... } }
```

---

### Public Verification

```
GET /verify?key=<uuid>&hwid=<string>
```

Always HTTP 200. Check the `valid` boolean.

```json
{ "valid": true }
{ "valid": false, "reason": "HWID mismatch" }
```

Reasons: `Invalid key` · `Key is disabled` · `Key has expired` · `HWID mismatch` · `Invalid parameters`

**First call** with an unbound key automatically binds the provided HWID.

**Lua example:**
```lua
local Http = game:GetService("HttpService")
local HWID = game:GetService("RbxAnalyticsService"):GetClientId()
local r    = Http:GetAsync("https://yourdomain.com/verify?key=YOUR_KEY&hwid=" .. HWID, true)
local data = Http:JSONDecode(r)
if not data.valid then
  game.Players.LocalPlayer:Kick(data.reason or "Unauthorized")
end
```

---

### Scripts (Luarmor alternative — JWT required)

Upload Lua source code server-side. Assign keys to scripts. Scripts are only served after key + HWID verification.

| Method | Path                        | Description                              |
|--------|-----------------------------|------------------------------------------|
| GET    | `/scripts/manage/list`      | List your scripts                        |
| GET    | `/scripts/manage/source`    | Fetch raw source (for editing)           |
| POST   | `/scripts/manage/create`    | Upload a new script                      |
| PATCH  | `/scripts/manage/update`    | Update source / version / enabled        |
| DELETE | `/scripts/manage/delete`    | Delete script                            |
| POST   | `/scripts/manage/assign`    | Assign a key to a script                 |
| DELETE | `/scripts/manage/unassign`  | Unassign a key from a script             |
| GET    | `/scripts/manage/loader`    | Get Lua loader snippet                   |

**Public loader endpoint (called by your Lua):**
```
GET /scripts/load?key=<uuid>&hwid=<string>&script=<name>
→ { "valid": true, "source": "-- your lua code..." }
```

**Workflow:**
1. `POST /scripts/manage/create` — upload your Lua source
2. `POST /scripts/manage/assign` — link one or more keys to the script
3. `GET /scripts/manage/loader?name=myscript` — copy the generated Lua loader
4. Paste the loader snippet into your executor — it handles everything automatically

---

### Webhooks (JWT required)

Receive HTTP POST callbacks when key events occur.

| Method | Path               | Description                            |
|--------|--------------------|----------------------------------------|
| GET    | `/webhooks/list`   | List registered webhooks               |
| POST   | `/webhooks/upsert` | Create or update webhook for an event  |
| DELETE | `/webhooks/delete` | Remove a webhook                       |
| POST   | `/webhooks/test`   | Send a test delivery                   |

**Events:** `VERIFY_OK` · `VERIFY_FAIL` · `VERIFY_BIND` · `LOAD_OK` · `LOAD_FAIL`

```json
POST /webhooks/upsert
{
  "event":  "VERIFY_OK",
  "url":    "https://discord.com/api/webhooks/...",
  "secret": "optional-signing-secret"
}
```

Each delivery includes an `X-Synthia-Signature: sha256=<hmac>` header (when secret is set) so you can verify authenticity. Payload:
```json
{
  "event":     "VERIFY_OK",
  "username":  "alice",
  "key_id":    42,
  "ip":        "1.2.3.4",
  "timestamp": "2025-01-01T00:00:00.000Z"
}
```

---

### Admin (admin JWT required)

| Method | Path                      | Description                              |
|--------|---------------------------|------------------------------------------|
| GET    | `/admin/stats`            | System-wide stats (single query)         |
| GET    | `/admin/users`            | Paginated user list with key counts      |
| DELETE | `/admin/users/delete`     | Delete user + cascade their keys         |
| PATCH  | `/admin/users/role`       | Promote / demote user                    |
| GET    | `/admin/keys`             | All keys, paginated + filterable         |
| POST   | `/admin/keys/create`      | Create key for any user                  |
| PATCH  | `/admin/keys/toggle`      | Toggle any key's status                  |
| PATCH  | `/admin/keys/hwid/reset`  | Reset HWID (no cooldown for admin)       |
| DELETE | `/admin/keys/delete`      | Delete any key                           |
| GET    | `/admin/logs`             | Audit logs, paginated + filterable       |

Pagination params: `?page=1&limit=50`
Log filter params: `?username=alice&action=VERIFY_FAIL`

---

### Health

```
GET /health
→ { "status": "ok", "version": "4.0.0", "uptime_s": 3600, "heap_used_mb": "45.2", ... }
```

No auth required. Safe to use as an uptime monitor target.

---

## Admin CLI

```bash
node admin.js create-admin <username> <password>   # seed first admin
node admin.js list-admins                           # list admin accounts
node admin.js promote <username>                    # promote existing user
node admin.js expire-keys                           # run expiry sweep manually
node admin.js stats                                 # print system stats
```

---

## Production Deployment (PM2)

```bash
cp .env.example .env
# fill in DB_PASSWORD, JWT_SECRET, PUBLIC_URL

npm install --omit=dev
npm install -g pm2

pm2 start ecosystem.config.js
pm2 save
pm2 startup     # enable auto-restart on reboot

# Logs
pm2 logs synthia-api
pm2 monit
```

---

## Security Notes

- **JWT tokens** are header-only (no query string leakage into server logs or browser history)
- **Passwords** are hashed with bcrypt (cost 12)
- **Login** uses constant-time bcrypt compare even for unknown usernames (no timing oracle)
- **HWID** is stored as `NULL` (proper SQL NULL, not the string `'Nil'`)
- **Webhook secrets** are HMAC-SHA256 signed so receivers can verify authenticity
- **Rate limits**: 300 req/min global · 20 req/15min on auth · 60 req/15min on key management · 120 req/min on verify · 200 req/min on script load
- **Statement timeout**: 10 s — runaway queries are automatically killed
- **SQL injection**: 100% parameterised queries throughout
- Set `CORS_ORIGIN` to your actual domain in production (not `*`)

---

## Database Schema

```
users          — username, password (bcrypt), role, created_at
user_keys      — key (UUID), hwid (NULL=unbound), status, expires_at, ...
scripts        — name, source (Lua), version, enabled, username
key_scripts    — many-to-many: key ↔ script
webhooks       — event, url, secret, delivery stats, username
audit_logs     — username, action, key_id, ip, metadata (JSONB), created_at
```

Key migrations are idempotent — safe to restart against an existing database.
Audit logs older than `AUDIT_LOG_RETENTION_DAYS` (default 90) are automatically pruned by the built-in cron.
# lulukbro
