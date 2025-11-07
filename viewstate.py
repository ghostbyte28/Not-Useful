#!/usr/bin/env python3
import base64
import hashlib
from binascii import unhexlify
from Crypto.Cipher import AES
import hmac
import sys

# === YOUR KEYS HERE ===
VALIDATION_KEY = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB"  # 64-byte hex
DECRYPTION_KEY = "0123456789ABCDEF0123456789ABCDEF"  # 16/24/32-byte hex
VALIDATION_ALG = "HMACSHA256"  # or "HMACSHA1"

validation_key = unhexlify(VALIDATION_KEY)
decryption_key = unhexlify(DECRYPTION_KEY)
if len(decryption_key) < 32:
    decryption_key = decryption_key.ljust(32, b'\x00')

def pkcs7_unpad(data):
    if not data: return None
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16: return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len: return None
    return data[:-pad_len]

def decrypt_viewstate(viewstate_b64):
    data = base64.b64decode(viewstate_b64)
    if len(data) < 16: raise ValueError("Invalid ViewState")
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pt_unpadded = pkcs7_unpad(pt)
    if pt_unpadded is None or pt_unpadded[0] != 0xFF:
        raise ValueError("Decryption failed or invalid ViewState")
    return pt_unpadded, iv

def encrypt_viewstate(pt_original, iv_original):
    # FIXED: Always pad — even if length % 16 == 0
    pad_len = 16 - (len(pt_original) % 16)
    pt_padded = pt_original + bytes([pad_len]) * pad_len
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv_original)
    ct = cipher.encrypt(pt_padded)
    return base64.b64encode(iv_original + ct).decode('ascii')

def generate_eventvalidation(viewstate_pt, page_url="/default.aspx"):
    mac_size = 32 if VALIDATION_ALG == "HMACSHA256" else 20
    if len(viewstate_pt) < mac_size + 2:
        raise ValueError("ViewState too short")
    mac = viewstate_pt[-mac_size:]
    payload = viewstate_pt[:-mac_size]
    expected = hmac.new(validation_key, payload, hashlib.sha256 if VALIDATION_ALG == "HMACSHA256" else hashlib.sha1).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("ViewState MAC failed! Wrong validationKey or corrupted data")
    to_hash = page_url.encode('utf-8') + b'|' + payload
    ev_mac = hmac.new(validation_key, to_hash, hashlib.sha256 if VALIDATION_ALG == "HMACSHA256" else hashlib.sha1).digest()
    return base64.b64encode(ev_mac).decode('ascii').rstrip('=')

def generate_valid_pair(viewstate_b64, page_url="/default.aspx"):
    pt, iv = decrypt_viewstate(viewstate_b64)
    new_vs = encrypt_viewstate(pt, iv)
    new_ev = generate_eventvalidation(pt, page_url)
    return new_vs, new_ev

# === RUN IT ===
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vs.py \"<VIEWSTATE>\" [page_url]")
        sys.exit(1)
    vs = sys.argv[1]
    url = sys.argv[2] if len(sys.argv) > 2 else "/"
    try:
        new_vs, new_ev = generate_valid_pair(vs, url)
        print("\nSUCCESS!\n")
        print(f"__VIEWSTATE={new_vs}")
        print(f"__EVENTVALIDATION={new_ev}")
    except Exception as e:
        print(f"[!] {e}")