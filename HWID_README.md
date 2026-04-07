# Synthia HWID System — Integration Guide

## New Files Added
| File | Purpose |
|------|---------|
| `hwid.js` | Core HWID engine: schema validation, Roblox API check, fingerprint scoring, anomaly detection |
| `routes/fingerprint.js` | `POST /fingerprint/verify` — multi-factor HWID verify + script delivery |
| `routes/getkey.js` | `POST /getkey/start|complete|redeem` — Roblox UI Get Key flow |
| `routes/admin_hwid.js` | `GET /admin/hwid/logs|stats|suspicious` — admin visibility into HWID activity |
| `SynthiaLoader.lua` | Drop into StarterPlayerScripts — full UI key system for Roblox |
| `.env.example` | Updated with all new env vars |

## Modified Files
- `server.js` — new requires + routes + initializeHWIDTables() call
- `cron.js` — fingerprint log pruning + pending token expiry tasks

## Quick Start
1. Copy all files into your Synthia project directory
2. Copy `.env.example` → `.env` and fill in `HWID_SECRET` (generate 40+ random chars)
3. Set `GETKEY_OWNER_USER` to the dashboard username that will own auto-generated keys
4. Restart: `pm2 restart all`
5. In Roblox Studio: drop `SynthiaLoader.lua` into StarterPlayerScripts,
   set `SERVER_URL` and `SCRIPT_NAME` at the top of the file.

## New DB Tables Created Automatically on Boot
- `fingerprint_logs` — every verify attempt with score + verdict
- `pending_keys` — single-use challenge tokens (auto-cleaned by cron)

## HWID Score Weights
| Component | Weight | Notes |
|-----------|--------|-------|
| UserId | 0.50 | Immutable anchor — hard fail if mismatched |
| ClientId (GetClientId) | 0.28 | Hamming tolerance via MAX_CLIENTID_DRIFT |
| Username | 0.10 | Soft — allows renames without lockout |
| AccountAge | 0.07 | ±10 day drift allowed |
| DeviceType | 0.05 | Broad category match |

Default pass threshold: **0.80** (configurable via `HWID_ACCEPT_THRESHOLD`)

## Roblox Lua Flow
```
Player clicks "Get Key"
  → POST /getkey/start   { userId, username }    ← Roblox identity verified
  ← { token, wait_seconds: 5 }
  [5-second countdown UI]
  → POST /getkey/complete { token, fingerprint }  ← fingerprint collected
  ← { key, expires_at }   (or existing key reissued)
Player inputs key + clicks Validate
  → POST /getkey/redeem  { key, fingerprint, script }
  ← { valid: true, source: "...lua..." }
  [loadstring(source)() executed]
```
