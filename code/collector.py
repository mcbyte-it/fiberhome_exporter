import logging
import os
import random
import sys
import traceback
import time

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE = os.getenv("LOG_FILE", "/logs/collector.log")

log = logging.getLogger("collector")
log.setLevel(logging.INFO)
log.propagate = False

_fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")

_sh = logging.StreamHandler(sys.stdout)
_sh.setFormatter(_fmt)
log.addHandler(_sh)

_fh = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
_fh.setFormatter(_fmt)
log.addHandler(_fh)

# ── Imports ───────────────────────────────────────────────────────────────────
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
from Crypto.Cipher import AES
from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily

# ── Configuration ─────────────────────────────────────────────────────────────
ROUTER_IP          = os.getenv("ROUTER_IP",         "http://192.168.1.1")
LOGIN_URL          = f"{ROUTER_IP}/cgi-bin/ajax"
STATUS_URL         = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_base_info&_="
GET_LOGIN_USER_URL = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_login_user"
IS_LOGINED_URL     = f"{ROUTER_IP}/cgi-bin/is_logined.cgi"
USERNAME           = os.getenv("ROUTER_USERNAME",   "admin")
PASSWORD           = os.getenv("ROUTER_PASSWORD",   "admin1234")
# ACS_RANDOM is fetched by the router login page and used as the AES key source.
# key = ACS_RANDOM[6:22]. See authentication.md for details.
ACS_RANDOM         = os.getenv("ROUTER_ACS_RANDOM", "")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Connection": "keep-alive",
}

# ── Crypto ────────────────────────────────────────────────────────────────────
def pkcs7padding(data, block_size=16):
    if not isinstance(data, (bytearray, bytes)):
        raise TypeError("Only support bytearray/bytes !")
    pl = block_size - (len(data) % block_size)
    return data + bytearray([pl] * pl)

def fhencrypt(data, acs_random):
    key = acs_random[6:22].encode("utf8")
    cipher = AES.new(key, AES.MODE_CBC, key)
    return cipher.encrypt(pkcs7padding(data.encode("utf8"))).hex().upper()

# ── Persistent HTTP session ───────────────────────────────────────────────────
_session = requests.Session()
_session.headers.update(HEADERS)
_session.verify = False

# ── Router data fetch ─────────────────────────────────────────────────────────
def _req(method, url, **kwargs):
    try:
        return _session.request(method, url, timeout=15, **kwargs)
    except Exception as e:
        log.error(f"Request failed: {method} {url} — {type(e).__name__}: {e}")
        raise

def get_router_data():
    # Check if existing session cookie is still valid
    resp = _req("GET", f"{STATUS_URL}{random.random()}",
                headers={"Referer": f"{ROUTER_IP}/html/stateOverview_inter.html"})
    if resp.status_code == 200:
        result = resp.json()
        if result.get("session_valid", 0):
            return result

    log.info("Session expired — re-authenticating")

    # Get session ID for login
    resp = _req("GET", f"{GET_LOGIN_USER_URL}&_={random.random()}")
    if resp.status_code != 200:
        log.error(f"get_login_user failed: HTTP {resp.status_code}")
        return None
    sessionid = resp.json().get("sessionid", "")

    # Login
    resp = _req("POST", LOGIN_URL,
                data={
                    "username":   USERNAME,
                    "loginpd":    fhencrypt(PASSWORD, ACS_RANDOM),
                    "port":       "0",
                    "sessionid":  sessionid,
                    "ajaxmethod": "do_login",
                    "_":          str(random.random()),
                },
                headers={
                    "Content-type": "application/x-www-form-urlencoded",
                    "Origin":       ROUTER_IP,
                    "Referer":      f"{ROUTER_IP}/html/login_jawwal.html",
                })
    if resp.json().get("login_result", -1) != 0:
        log.error(f"Login failed: {resp.text}")
        return None

    # Confirm session
    _req("POST", f"{IS_LOGINED_URL}?_={random.random()}", data="",
         headers={
             "Content-Length":   "0",
             "Origin":           ROUTER_IP,
             "Referer":          f"{ROUTER_IP}/html/main_inter.html",
             "X-Requested-With": "XMLHttpRequest",
         })

    # Fetch data
    resp = _req("GET", f"{STATUS_URL}{random.random()}",
                headers={"Referer": f"{ROUTER_IP}/html/stateOverview_inter.html"})
    if resp.status_code != 200:
        log.error(f"get_base_info failed: HTTP {resp.status_code}")
        return None

    result = resp.json()
    if not result.get("session_valid", 0):
        log.error("get_base_info returned session_valid=0 after login")
        return None

    log.info("Re-authentication successful")
    return result

# ── Custom Collector (called on every scrape) ─────────────────────────────────
class RouterCollector:
    def collect(self):
        try:
            data = get_router_data()
        except Exception:
            log.error(f"Exception fetching router data:\n{traceback.format_exc()}")
            return

        if not data:
            log.warning("No data returned — skipping scrape")
            return

        yield GaugeMetricFamily("router_uptime",                  "Router uptime in seconds",             value=float(data.get("uptime", 0)))
        yield GaugeMetricFamily("router_mem_total",               "Total memory in KB",                   value=float(data.get("mem_total", 0)))
        yield GaugeMetricFamily("router_mem_free",                "Free memory in KB",                    value=float(data.get("mem_free", 0)))
        yield GaugeMetricFamily("router_cpu_usage",               "CPU usage percentage",                 value=float(data.get("cpu_usage", 0)))
        yield CounterMetricFamily("router_pon_bytes_sent",         "PON bytes sent",                       value=float(data.get("ponBytesSent", 0)))
        yield CounterMetricFamily("router_pon_bytes_received",    "PON bytes received",                   value=float(data.get("ponBytesReceived", 0)))
        yield CounterMetricFamily("router_pon_packets_sent",      "PON packets sent",                     value=float(data.get("ponPacketsSent", 0)))
        yield CounterMetricFamily("router_pon_packets_received",  "PON packets received",                 value=float(data.get("ponPacketsReceived", 0)))
        yield GaugeMetricFamily("router_tx_power",                "TX power level",                       value=float(data.get("txpower", 0)))
        yield GaugeMetricFamily("router_rx_power",                "RX power level",                       value=float(data.get("rxpower", 0)))
        yield GaugeMetricFamily("router_transceiver_temperature", "Transceiver temperature in Celsius",   value=float(data.get("transceivertemperature", 0)))


if __name__ == "__main__":
    PORT = int(os.getenv("PORT", "6145"))
    REGISTRY.register(RouterCollector())
    start_http_server(PORT)
    log.info(f"FiberHome exporter listening on port {PORT} (router: {ROUTER_IP})")
    while True:
        time.sleep(3600)
