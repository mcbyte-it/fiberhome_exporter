# How `acs_random` Is Extracted — FiberHome HG6145F Login Page

## Overview

The router login page (`login_jawwal.html`) loads `aes.js`, which on document ready
fetches a device-specific random string called `acs_random` from the router. This string
is later used as the source for the AES-128-CBC encryption key and IV when submitting
the login password.

---

## Obfuscated Code (as seen in aes.js)

```javascript
var $vhHTOB, acs_random;
$(document)[K_q]($veW29N(() => {
    XHR.get(o_q, null, $veW29N(b => {
        acs_random = b[P_q]
    }, 0x1))
}, 0x0));
```

### What each obfuscated name resolves to

The short constant names (`K_q`, `o_q`, `P_q`, ...) are defined inside a
base64-encoded, zlib-compressed JSON blob at the top of `aes.js` (lines 1–291).
The blob is decoded at runtime via `Object.assign(window, decodedObject)`.

Decoded from the blob (`aes_c_blob.md`):

| Obfuscated name | Actual value         | Role                                     |
|-----------------|----------------------|------------------------------------------|
| `K_q`           | `"ready"`            | jQuery document-ready event              |
| `o_q`           | `"get_acs_random"`   | CGI endpoint queried to fetch the value  |
| `P_q`           | `"acsRandom"`        | JSON response field containing the value |

### Deobfuscated equivalent

```javascript
var acs_random;
$(document).ready(function() {
    XHR.get("get_acs_random", null, function(response) {
        acs_random = response.acsRandom;
    });
});
```

The XHR helper (`xhr.js`) sends this as:

```
GET /cgi-bin/ajax?ajaxmethod=get_acs_random&_=<random>
```

This endpoint requires no authentication — it is accessible before login.

---

## How `acs_random` Is Used — `random_acs()` and `fhencrypt()`

```javascript
function random_acs() {
    var b = '';
    return b = acs_random[yuq](Cpq)[Voq](ZAq, -Yxq), b
}
```

Resolved constants:

| Obfuscated name | Actual value   | Role                              |
|-----------------|----------------|-----------------------------------|
| `yuq`           | `"substring"`  | String method: extract from index |
| `Cpq`           | `6`            | Start index                       |
| `Voq`           | `"slice"`      | String method: trim the end       |
| `ZAq`           | `0`            | Slice start                       |
| `Yxq`           | `7`            | Chars to remove from end          |

### Deobfuscated equivalent

```javascript
function random_acs() {
    return acs_random.substring(6).slice(0, -7);
    // equivalent to: acs_random.slice(6, 22)  — always 16 characters
}
```

This 16-character slice is used as **both the AES key and IV**:

```javascript
function fhencrypt(password) {
    var key = random_acs();       // 16 chars from acs_random[6:22]
    return encrypt(password, key, key);  // AES-128-CBC, key == IV
}
```

---

## Example

| Field        | Example value                          |
|--------------|----------------------------------------|
| `acs_random` | `xxxxxxx6HTTa1234567bLVLxxxxxx`       |
| `random_acs()` | `6HTTa1234567bLVL` (chars 6–22, 16 chars) |
| AES key / IV | `6HTTa1234567bLVL`                     |

> **Each router has its own `acs_random`.** The value above is a device-specific example.

---

## Python Equivalent

```python
from Crypto.Cipher import AES

def pkcs7padding(data, block_size=16):
    pl = block_size - (len(data) % block_size)
    return data + bytearray([pl] * pl)

def fhencrypt(password, acs_random):
    key = acs_random[6:22].encode("utf8")       # random_acs() equivalent
    cipher = AES.new(key, AES.MODE_CBC, key)    # key == IV
    return cipher.encrypt(pkcs7padding(password.encode("utf8"))).hex().upper()
```

---

## How to Read `acs_random` from a Live Router

1. Open `http://192.168.1.1/` in Chrome
2. Open DevTools → Console
3. Type `acs_random` → full 29-char string
4. Type `random_acs()` → 16-char AES key actually used

---

## Decoding the Constant Blob

The string constants are stored in `aes.js` as a base64-encoded, zlib-deflated JSON
object (line 2, the long `c` array). To decode:

```
base64_decode(blob) -> zlib_inflate -> JSON.parse -> constant map
```

The decoded map is in `aes_c_blob.md` in this repo.
