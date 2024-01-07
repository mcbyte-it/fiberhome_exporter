import base64
import logging
import os
import time

import requests
from Crypto.Cipher import AES
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY, CounterMetricFamily

__version__ = "develop"

# username to access thw webui
USERNAME = ''
# username to access thw webui
PASSWORD = ''
# URL for the webUI including the port
HOSTNAME = 'http://192.168.1.1'

ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s %(levelname)8s %(name)s | %(message)s")
ch.setFormatter(formatter)

logger = logging.getLogger("fiberhome_logger")
logger.addHandler(ch)

log_level = "INFO"

loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
for log in loggers:
    log.setLevel(log_level)


class FiberHomeCollector(object):
    def __init__(self):
        pass

    def collect(self):
        base_url = HOSTNAME
        ajax_endpoint = base_url + "/cgi-bin/ajax?ajaxmethod="
        login_url = base_url + "/cgi-bin/ajax"

        resp = requests.get(url=ajax_endpoint + "get_base_info")
        data = resp.json()  # Check the JSON Response Content documentation below
        valid_session = data['session_valid']
        logger.info("valid session?")
        logger.info(valid_session)

        if valid_session:
            pass
            # logger.info("valid session")
        else:
            logger.info("Not logged in, need to pass data")

            resp = requests.get(url=ajax_endpoint + "get_refresh_sessionid")
            data = resp.json()  # Check the JSON Response Content documentation below

            new_sessionid = data['sessionid']
            logger.info("new sessionid: " + new_sessionid)

            post_data = {"username": USERNAME,
                         "loginpd": fhencrypt(PASSWORD),
                         "port": "0",
                         "sessionid": new_sessionid,
                         "ajaxmethod": "do_login"}

            resp = requests.post(url=login_url, data=post_data)
            # logger.info("post data: " + resp.text)

            data = resp.json()
            login_session_valid = data['session_valid']

            if login_session_valid:
                logger.info("We are now logged in")
                pass
            else:
                logger.error("Something went wrong, please check the credentials and try again")
                exit(1)

        resp = requests.get(url=ajax_endpoint + "get_base_info")
        data = resp.json()

        # logger.info("uptime: " + data['uptime'])

        # array starts at index 0
        base_metrics = [
            ['c', 'uptime_seconds_total', 'Uptime in seconds', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             'seconds', 'uptime'],
            ['g', 'memory_total_bytes', 'Total memory', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             'bytes', 'mem_total'],
            ['g', 'memory_free_bytes', 'Free memory', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             'bytes', 'mem_free'],
            ['g', 'cpu_usage', 'CPU usage', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             '', 'cpu_usage'],
            ['c', 'pon_bytes_total', 'PON bytes sent', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             'bytes', 'ponBytesSent', 'tx'],
            ['c', 'pon_bytes_total', 'PON  bytes received', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             'bytes', 'ponBytesReceived', 'rx'],
            ['c', 'pon_packets_total', 'PON packets sent', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             'packets', 'ponPacketsSent', 'tx'],
            ['c', 'pon_packets_total', 'PON  packets received', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             'packets', 'ponPacketsReceived', 'rx'],
            ['g', 'power', 'Power in transmission', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             '', 'txpower', 'tx'],
            ['g', 'power', 'Power in reception', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             '', 'rxpower', 'rx'],
            ['g', 'transceiver_temperature', 'Transceiver temperature', ['ModelName', 'SerialNumber', 'SoftwareVersion'],
             '', 'transceivertemperature'],
        ]

        prom_metrics = []
        idx = 0
        for metric in base_metrics:
            label_names = []
            for value in metric[3]:
                label_names.append(value.lower())
            try:
                if metric[6]:
                    label_names.append('direction')
            except IndexError:
                pass

            if metric[0] == "c":
                mtr = CounterMetricFamily("fiberhome_" + metric[1], metric[2], labels=label_names, unit=metric[4])
            elif metric[0] == "g":
                mtr = GaugeMetricFamily("fiberhome_" + metric[1], metric[2], labels=label_names, unit=metric[4])

            label_values = []
            for value in metric[3]:
                label_values.append(data[value])
            try:
                if metric[6]:
                    label_values.append(metric[6])
            except IndexError:
                pass
            mtr.add_metric(labels=label_values, value=data[metric[5]])
            yield mtr
            prom_metrics.append(mtr)

        # $base_info = curlGetJson("get_base_info"); // NEEDED - more status of above, used lan ports, serial, modem,
        # $wan_info = curlGetJson("get_allwan_info"); // WAN info,
        # $lan_info = curlGetJson("get_ipv4_lan_info"); // LAN ipv4 info,
        # $ethernet_info = curlGetJson("getEthernetPorts_info"); // LAN ports info, connected and total packets


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


if __name__ == '__main__':
    # get username from ENV, defaults to 'admin'
    USERNAME = os.getenv('USERNAME', 'admin')

    # get username from ENV
    PASSWORD = os.getenv('PASSWORD')

    # get hostname and port from ENV, defaults to http://192.168.1.1
    HOSTNAME = os.getenv('HOSTNAME', 'http://192.168.1.1')

    # logger.info("username: " + USERNAME)
    # logger.info("password: " + PASSWORD)
    # logger.info("hostname: " + HOSTNAME)

    if USERNAME is None or PASSWORD is None or HOSTNAME == "":
        logger.error("Credentials not found or not correct, please check the Environmental variables")
        logger.error("USERNAME=<username>")
        logger.error("PASSWORD=<password>")
        logger.error("HOSTNAME=<url of the router. OPTIONAL, defaults to http://192.168.1.1>")
        exit(1)

    logger.info("Starting collector on port 6145")
    start_http_server(6145)
    REGISTRY.register(FiberHomeCollector())
    while True:
        time.sleep(5)
