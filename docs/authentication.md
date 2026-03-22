# FiberHome HG6145F Authentication

## Overview

The router web interface uses AES-128-CBC encryption for the login password.
The encryption key is fetched dynamically from the router on page load.

## Login Flow

1. **Auth check** — `GET /cgi-bin/ajax?ajaxmethod=get_base_info`
   - If response contains `session_valid:1`, the session cookie is still alive. Done.
   - If `session_valid:0`, proceed with login.

2. **Fetch AES key** — `GET /cgi-bin/ajax?ajaxmethod=get_acs_random`
   - Unauthenticated endpoint, accessible before login.
   - Returns `{"acsRandom": "<29-char string>"}`.
   - Key and IV = `acsRandom[6:22]` (16 bytes).

3. **Get session ID** — `GET /cgi-bin/ajax?ajaxmethod=get_login_user`
   - Returns `{"sessionid":"XXXXXXXX","session_valid":1,"login_user":"..."}`
   - Note: `login_user:"1"` here reflects whoever else is logged in (e.g. browser), NOT whether our session is authenticated. Do not use this to skip login.
   - Save `sessionid` for use in the login POST.

4. **Login** — `POST /cgi-bin/ajax`
   - Body: `username=admin&loginpd=<encrypted>&port=0&sessionid=<sessionid>&ajaxmethod=do_login&_=<random>`
   - Success response: `{"session_valid":1,"login_result":0}`
   - `login_result:2` = account locked (3 failed attempts), wait ~1 minute.

5. **Confirm session** — `POST /cgi-bin/is_logined.cgi`
   - Body: empty
   - Success response: `{"result":"1","user":"1"}`

6. **Fetch data** — `GET /cgi-bin/ajax?ajaxmethod=get_base_info`
   - Now returns full router data with `session_valid:1`.

## Password Encryption

### Algorithm
AES-128-CBC, key = IV = `acs_random[6:22]` (16 bytes), PKCS7 padding, result as uppercase hex.

### acs_random
A 29-character string served by the router from an unauthenticated endpoint before login.
The exporter fetches it automatically — no configuration required.

- **Endpoint:** `GET /cgi-bin/ajax?ajaxmethod=get_acs_random`
- **Response:** `{"acsRandom": "<29-char string>"}`
- **Key / IV:** `acsRandom[6:22]` — a fixed 16-character slice (128-bit)

| Field      | Example (device-specific)       |
|------------|---------------------------------|
| acsRandom  | `xxxxxxx6HTTa1234567bLVLxxxxxx` |
| key / IV   | `6HTTa1234567bLVL` (chars 6–22) |

> **Note:** Characters 6–22 appear fixed across reboots and firmware updates. The surrounding characters (0–5 and 22–28) may vary per device.

### Python Implementation

```python
import requests
from Crypto.Cipher import AES

def fetch_acs_random(router_ip):
    resp = requests.get(f"{router_ip}/cgi-bin/ajax?ajaxmethod=get_acs_random", verify=False)
    return resp.json()["acsRandom"]

def pkcs7padding(data, block_size=16):
    pl = block_size - (len(data) % block_size)
    return data + bytearray([pl] * pl)

def fhencrypt(password, acs_random):
    key = acs_random[6:22].encode("utf8")  # 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, key)
    return cipher.encrypt(pkcs7padding(password.encode("utf8"))).hex().upper()
```

## Firmware History

| Firmware | AES Key Source              | Key Value          |
|----------|-----------------------------|--------------------|
| Pre-RP4552 | Fixed: `opqrstuvwxyz{|}~` | `opqrstuvwxyz{|}~` |
| RP4552+    | `acs_random[6:22]`        | `6HTTa1234567bLVL` |

## If Login Breaks After a Firmware Update

The exporter fetches `acs_random` live from the router on every login attempt, so a firmware change to the `acsRandom` value is handled automatically.

If login still fails, verify the slice is still `[6:22]`:
1. Open `http://192.168.1.1/` in Chrome → DevTools → Console
2. Type `acs_random` — note the full value
3. Type `random_acs()` — this is the 16-char key the router actually uses
4. If the key is no longer at chars 6–22, update the slice in `fhencrypt()` in `collector.py`

## Session Notes

- The router session expires after 300 seconds of inactivity (`SessionMaxTime`).
- Use a persistent `requests.Session()` across scrapes so the cookie survives.
- Only one admin session is active at a time. Logging in from Python will share/replace the browser session.
