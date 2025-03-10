import os
import random

import requests
from Crypto.Cipher import AES
from flask import Flask, Response
from prometheus_client import Gauge, Counter, generate_latest

# Configuration
ROUTER_IP = os.getenv("ROUTER_IP", "http://192.168.1.1")
# AJAX_ENDPOINT = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod="
STATUS_URL = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_base_info&_="
SESSION_ID_URL = f"{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid"
LOGIN_URL = f"{ROUTER_IP}/cgi-bin/ajax"
USERNAME = os.getenv("ROUTER_USERNAME", "admin")
PASSWORD = os.getenv("ROUTER_PASSWORD", "admin1234")

def pkcs7padding(data, block_size=16):
    if type(data) != bytearray and type(data) != bytes:
        raise TypeError("Only support bytearray/bytes !")
    pl = block_size - (len(data) % block_size)
    return data + bytearray([pl for i in range(pl)])


def int_aes_iv():
    iv = ""
    for i in range(16):
        iv += chr(i + 111)
    return iv


def fhencrypt(data):
    iv = b'opqrstuvwxyz{|}~'
    key = iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    byte_data = pkcs7padding(data.encode("utf8"))
    encrypted_pass = cipher.encrypt(byte_data)
    return encrypted_pass.hex().upper()


def fhdecrypt(data):
    iv = b'opqrstuvwxyz{|}~'
    key = iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    byte_data = bytes.fromhex(data)
    decrypted_pass = cipher.decrypt(byte_data)
    return decrypted_pass.strip().decode('utf8')


# Prometheus metrics
uptime = Gauge("router_uptime", "Router uptime in seconds")
mem_total = Gauge("router_mem_total", "Total memory in KB")
mem_free = Gauge("router_mem_free", "Free memory in KB")
cpu_usage = Gauge("router_cpu_usage", "CPU usage percentage")
pon_bytes_sent = Counter("router_pon_bytes_sent", "PON bytes sent")
pon_bytes_received = Counter("router_pon_bytes_received", "PON bytes received")
pon_packets_sent = Counter("router_pon_packets_sent", "PON packets sent")
pon_packets_received = Counter("router_pon_packets_received", "PON packets received")
tx_power = Gauge("router_tx_power", "TX power level")
rx_power = Gauge("router_rx_power", "RX power level")
transceiver_temperature = Gauge("router_transceiver_temperature", "Transceiver temperature in Celsius")

# Flask app
app = Flask(__name__)

def get_router_data():
    response = requests.get(f"{STATUS_URL}{random.random()}")

    if response.status_code == 200:
        data = response.json()
        print(data)
        if not data.get("session_valid", False):  # Check session validity from JSON response
            session_id_response = requests.get(SESSION_ID_URL)
            print(session_id_response)
            if session_id_response.status_code != 200:
                print("Failed to retrieve session ID")
                return None
            session_id_data = session_id_response.json()
            new_sessionid = session_id_data.get("sessionid", "")

            login_payload = {"username": USERNAME,
                         "loginpd": fhencrypt(PASSWORD),
                         "port": "0",
                         "sessionid": new_sessionid,
                         "ajaxmethod": "do_login",
                         "_": f'{random.random()}'}
            print(login_payload)
            login_response = requests.post(LOGIN_URL, data=login_payload)
            if login_response.status_code != 200:
                print("Failed to log in to the router")
                return None
            login_data = login_response.json()
            print(login_data)
            if login_data.get("login_result") == 2:
                print("Error: Username or password is wrong 3 times, please retry 1 minute later! ")
                return None
            if login_data.get("login_result") != 0:
                print(f"Login failed with result code: {login_data.get('login_result')}")
                return None

            if not login_data.get("session_valid", False):  # Check session validity after login
                print("Session still not valid after login")
                return None
            response = requests.get(f"{STATUS_URL}{random.random()}")
            if response.status_code == 200:
                data = response.json()
            else:
                print("Failed to retrieve data after login")
                return None
        return data
    else:
        print("Failed to retrieve data")
        return None

def update_metrics():
    data = get_router_data()
    print(data)
    if data:
        #download_speed.set(data.get("download", 0))
        #upload_speed.set(data.get("upload", 0))
        uptime.set((data.get("uptime", 0)))
        mem_total.set((data.get("mem_total", 0)))
        mem_free.set((data.get("mem_free", 0)))
        cpu_usage.set((data.get("cpu_usage", 0)))
        pon_bytes_sent.inc(int(data.get("ponBytesSent", 0)))
        pon_bytes_received.inc(int(data.get("ponBytesReceived", 0)))
        pon_packets_sent.inc(int(data.get("ponPacketsSent", 0)))
        pon_packets_received.inc(int(data.get("ponPacketsReceived", 0)))
        tx_power.set((data.get("txpower", 0)))
        rx_power.set((data.get("rxpower", 0)))
        transceiver_temperature.set(data.get("transceivertemperature", 0))

def generate_metrics():
    update_metrics()
    return generate_latest()

@app.route("/metrics")
def metrics():
    return Response(generate_metrics(), mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6145)