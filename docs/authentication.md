# FiberHome HG6145F Authentication

## Overview

The router web interface uses AES-128-CBC encryption for the login password.
The encryption key is fetched dynamically from the router on page load.

## Login Flow

1. **Auth check** — `GET /cgi-bin/ajax?ajaxmethod=get_base_info`
   - If response contains `session_valid:1`, the session cookie is still alive. Done.
   - If `session_valid:0`, proceed with login.

2. **Get session ID** — `GET /cgi-bin/ajax?ajaxmethod=get_login_user`
   - Returns `{"sessionid":"XXXXXXXX","session_valid":1,"login_user":"..."}`
   - Note: `login_user:"1"` here reflects whoever else is logged in (e.g. browser), NOT whether our session is authenticated. Do not use this to skip login.
   - Save `sessionid` for use in the login POST.

3. **Login** — `POST /cgi-bin/ajax`
   - Body: `username=admin&loginpd=<encrypted>&port=0&sessionid=<sessionid>&ajaxmethod=do_login&_=<random>`
   - Success response: `{"session_valid":1,"login_result":0}`
   - `login_result:2` = account locked (3 failed attempts), wait ~1 minute.

4. **Verify login** — `GET /cgi-bin/ajax?ajaxmethod=get_login_user`
   - Confirm `session_valid:1` and `login_user:"1"`.

5. **Confirm session** — `POST /cgi-bin/is_logined.cgi`
   - Body: empty
   - Success response: `{"result":"1","user":"1"}`

6. **Fetch data** — `GET /cgi-bin/ajax?ajaxmethod=get_base_info`
   - Now returns full router data with `session_valid:1`.

## Password Encryption

### Algorithm
AES-128-CBC, key = IV = `acs_random[6:22]` (16 bytes), PKCS7 padding, result as uppercase hex.

### acs_random
A 29-character string fetched by the login page JS from the router on load.
Used as the source for the AES key.

> **Each router has its own `acs_random`. Do not use the example below — read yours from the browser console.**

| Field      | Example (yours will differ)     |
|------------|---------------------------------|
| acs_random | `xxxxxxx6HTTa1234567bLVLxxxxxx` |
| key / IV   | `6HTTa1234567bLVL` (chars 6–22) |

> **Note:** Characters 6–22 appear to be fixed across resets and firmware updates — this is the portion used as the AES key/IV. The surrounding characters (0–5 and 22–28) may vary per device.

**To get your `acs_random`:** Open `http://192.168.1.1/` in Chrome → DevTools → Console → type `acs_random`.

**To get your key slice:** type `random_acs()` in the same console — this is the actual AES key your router uses.

### Python Implementation

```python
from Crypto.Cipher import AES

ACS_RANDOM = "your_acs_random_here"  # read from browser console

def pkcs7padding(data, block_size=16):
    pl = block_size - (len(data) % block_size)
    return data + bytearray([pl] * pl)

def fhencrypt(password, acs_random):
    key = acs_random[6:22].encode("utf8")  # 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, key)
    return cipher.encrypt(pkcs7padding(password.encode("utf8"))).hex().upper()
```

### Verification
```
fhencrypt("your_password", "your_acs_random_here")
  -> <uppercase hex string>
```

## Firmware History

| Firmware | AES Key Source              | Key Value          |
|----------|-----------------------------|--------------------|
| Pre-RP4552 | Fixed: `opqrstuvwxyz{|}~` | `opqrstuvwxyz{|}~` |
| RP4552+    | `acs_random[6:22]`        | `6HTTa1234567bLVL` |

## If Login Breaks After a Firmware Update

1. Open `http://192.168.1.1/` in Chrome
2. Open DevTools → Console
3. Type `acs_random` and note the value
4. Type `random_acs()` and note the result (this is the actual key)
5. Update `ACS_RANDOM` in `collector.py` with the new `acs_random` value
6. Verify the `[6:22]` slice still equals what `random_acs()` returns — adjust if not

## Session Notes

- The router session expires after 300 seconds of inactivity (`SessionMaxTime`).
- Use a persistent `requests.Session()` across scrapes so the cookie survives.
- Only one admin session is active at a time. Logging in from Python will share/replace the browser session.
