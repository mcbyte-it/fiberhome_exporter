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
ETHERNET_URL       = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=getEthernetPorts_info&_="
WAN_URL            = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_allwan_info&_="
LAN_URL            = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_lan_status&_="
USERNAME           = os.getenv("ROUTER_USERNAME",   "admin")
PASSWORD           = os.getenv("ROUTER_PASSWORD",   "admin1234")

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

ACS_RANDOM_URL = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_acs_random"

def _fix_ip(s):
    """Router encodes IPs as '192_point_168_point_1_point_1' — decode to normal."""
    return s.replace("_point_", ".")

def fetch_acs_random():
    resp = _req("GET", f"{ACS_RANDOM_URL}&_={random.random()}")
    if resp.status_code != 200:
        raise RuntimeError(f"get_acs_random failed: HTTP {resp.status_code}")
    acs_random = resp.json().get("acsRandom")
    if not acs_random:
        raise RuntimeError(f"get_acs_random response missing acsRandom field: {resp.text}")
    log.info(f"Fetched acs_random from router")
    return acs_random

def get_router_data():
    # Check if existing session cookie is still valid
    resp = _req("GET", f"{STATUS_URL}{random.random()}",
                headers={"Referer": f"{ROUTER_IP}/html/stateOverview_inter.html"})
    if resp.status_code == 200:
        result = resp.json()
        if result.get("session_valid", 0):
            return result

    log.info("Session expired — re-authenticating")

    # Fetch AES key source from router (unauthenticated endpoint)
    acs_random = fetch_acs_random()

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
                    "loginpd":    fhencrypt(PASSWORD, acs_random),
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

def fetch_ethernet_ports():
    """Return list of per-port dicts from getEthernetPorts_info, or []."""
    try:
        resp = _req("GET", f"{ETHERNET_URL}{random.random()}",
                    headers={"Referer": f"{ROUTER_IP}/html/stateOverview_inter.html"})
        if resp.status_code != 200:
            log.warning(f"getEthernetPorts_info failed: HTTP {resp.status_code}")
            return []
        return resp.json().get("ethernet_ports_info", {}).get("ethernet_ports_data", [])
    except Exception:
        log.error(f"Exception fetching ethernet ports:\n{traceback.format_exc()}")
        return []

def fetch_wan_info():
    """Return list of INTERNET WAN dicts from get_allwan_info, or []."""
    try:
        resp = _req("GET", f"{WAN_URL}{random.random()}",
                    headers={"Referer": f"{ROUTER_IP}/html/stateOverview_inter.html"})
        if resp.status_code != 200:
            log.warning(f"get_allwan_info failed: HTTP {resp.status_code}")
            return []
        wan_list = resp.json().get("wan", [])
        return [w for w in wan_list if "INTERNET" in w.get("ServiceList", "")]
    except Exception:
        log.error(f"Exception fetching WAN info:\n{traceback.format_exc()}")
        return []

def fetch_lan_clients():
    """Return count of active LAN clients from get_lan_status, or None."""
    try:
        resp = _req("GET", f"{LAN_URL}{random.random()}",
                    headers={"Referer": f"{ROUTER_IP}/html/stateOverview_inter.html"})
        if resp.status_code != 200:
            log.warning(f"get_lan_status failed: HTTP {resp.status_code}")
            return None
        clients = resp.json().get("lan_status", {}).get("data", [])
        return len(clients)
    except Exception:
        log.error(f"Exception fetching LAN status:\n{traceback.format_exc()}")
        return None

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

        # ── Existing base_info metrics ────────────────────────────────────────
        yield GaugeMetricFamily("router_uptime",                  "Router uptime in seconds",             value=float(data.get("uptime", 0)))
        yield GaugeMetricFamily("router_mem_total",               "Total memory in KB",                   value=float(data.get("mem_total", 0)))
        yield GaugeMetricFamily("router_mem_free",                "Free memory in KB",                    value=float(data.get("mem_free", 0)))
        yield GaugeMetricFamily("router_cpu_usage",               "CPU usage percentage",                 value=float(data.get("cpu_usage", 0)))
        yield CounterMetricFamily("router_pon_bytes_sent",        "PON bytes sent",                       value=float(data.get("ponBytesSent", 0)))
        yield CounterMetricFamily("router_pon_bytes_received",    "PON bytes received",                   value=float(data.get("ponBytesReceived", 0)))
        yield CounterMetricFamily("router_pon_packets_sent",      "PON packets sent",                     value=float(data.get("ponPacketsSent", 0)))
        yield CounterMetricFamily("router_pon_packets_received",  "PON packets received",                 value=float(data.get("ponPacketsReceived", 0)))
        yield GaugeMetricFamily("router_tx_power",                "TX power level in dBm",                value=float(data.get("txpower", 0)))
        yield GaugeMetricFamily("router_rx_power",                "RX power level in dBm",                value=float(data.get("rxpower", 0)))
        yield GaugeMetricFamily("router_transceiver_temperature", "Transceiver temperature in Celsius",   value=float(data.get("transceivertemperature", 0)))

        # ── New base_info metrics (no extra HTTP call) ────────────────────────
        yield GaugeMetricFamily("router_supply_voltage",          "SFP transceiver supply voltage in V",  value=float(data.get("supplyvottage", 0)))
        yield GaugeMetricFamily("router_bias_current",            "SFP laser bias current in mA",         value=float(data.get("biascurrent", 0)))
        yield GaugeMetricFamily("router_flash_usage",             "Flash storage usage percentage",       value=float(data.get("flash_usage", 0)))
        yield GaugeMetricFamily("router_pon_reg_state",           "PON registration state (5=registered)", value=float(data.get("pon_reg_state", 0)))

        info_metric = GaugeMetricFamily(
            "router_info", "Router device information",
            labels=["model", "firmware", "hardware", "serial", "manufacturer"],
        )
        info_metric.add_metric(
            [
                data.get("ModelName", ""),
                data.get("SoftwareVersion", ""),
                data.get("HardwareVersion", ""),
                data.get("SerialNumber", ""),
                data.get("Manufacturer", ""),
            ],
            1.0,
        )
        yield info_metric

        # ── Ethernet port metrics ─────────────────────────────────────────────
        port_up      = GaugeMetricFamily("router_ethernet_port_up",              "Ethernet port link state (1=Up)",         labels=["port"])
        port_uptime  = GaugeMetricFamily("router_ethernet_port_uptime_seconds",  "Ethernet port connection time in seconds", labels=["port"])
        eth_tx       = CounterMetricFamily("router_ethernet_bytes_sent",         "Ethernet port bytes sent",                labels=["port"])
        eth_rx       = CounterMetricFamily("router_ethernet_bytes_received",     "Ethernet port bytes received",            labels=["port"])
        eth_tx_pkts  = CounterMetricFamily("router_ethernet_packets_sent",       "Ethernet port packets sent",              labels=["port"])
        eth_rx_pkts  = CounterMetricFamily("router_ethernet_packets_received",   "Ethernet port packets received",          labels=["port"])
        eth_errors   = CounterMetricFamily("router_ethernet_errors_received",    "Ethernet port receive errors",            labels=["port"])

        for port in fetch_ethernet_ports():
            p = str(port.get("ethernet_ports_index", "?"))
            port_up.add_metric([p],     1.0 if port.get("Status") == "Up" else 0.0)
            port_uptime.add_metric([p], float(port.get("X_FH_ConnetTime", 0)))
            eth_tx.add_metric([p],      float(port.get("BytesSent", 0)))
            eth_rx.add_metric([p],      float(port.get("BytesReceived", 0)))
            eth_tx_pkts.add_metric([p], float(port.get("PacketsSent", 0)))
            eth_rx_pkts.add_metric([p], float(port.get("PacketsReceived", 0)))
            eth_errors.add_metric([p],  float(port.get("ErrorsReceived", 0)))

        yield port_up
        yield port_uptime
        yield eth_tx
        yield eth_rx
        yield eth_tx_pkts
        yield eth_rx_pkts
        yield eth_errors

        # ── WAN metrics ───────────────────────────────────────────────────────
        wan_connected = GaugeMetricFamily("router_wan_connected",       "WAN connection state (1=Connected)", labels=["wan_name"])
        wan_uptime    = GaugeMetricFamily("router_wan_uptime_seconds",  "WAN connection uptime in seconds",   labels=["wan_name"])

        for wan in fetch_wan_info():
            name = wan.get("Name", str(wan.get("wan_index", "?")))
            wan_connected.add_metric([name], 1.0 if wan.get("ConnectionStatus") == "Connected" else 0.0)
            wan_uptime.add_metric([name],    float(wan.get("Uptime", 0)))

        yield wan_connected
        yield wan_uptime

        # ── LAN client count ──────────────────────────────────────────────────
        client_count = fetch_lan_clients()
        if client_count is not None:
            yield GaugeMetricFamily("router_lan_connected_clients", "Number of active LAN clients", value=float(client_count))


if __name__ == "__main__":
    PORT = int(os.getenv("PORT", "6145"))
    REGISTRY.register(RouterCollector())
    start_http_server(PORT)
    log.info(f"FiberHome exporter listening on port {PORT} (router: {ROUTER_IP})")
    while True:
        time.sleep(3600)
