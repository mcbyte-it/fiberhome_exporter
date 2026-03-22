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

if __name__ == "__main__":
    router_ip = "http://192.168.1.1"
    password = "admin1234"
    acs_random = fetch_acs_random(router_ip)
    print(f"ACS Random: {acs_random}")
    
    encrypted_password = fhencrypt(password, acs_random)
    print(f"Original password: {password}")
    print(f"Encrypted password: {encrypted_password}")