#!/usr/bin/env python3
import base64
import sys
from binascii import unhexlify
from Crypto.Cipher import AES, DES3

def pkcs7_unpad(data):
    if not data:
        return None
    pad_len = data[-1]
    if isinstance(pad_len, str):  # py2 safety (shouldn't happen here)
        pad_len = ord(pad_len)
    if pad_len < 1 or pad_len > 16:
        return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return data[:-pad_len]

def try_aes(decryption_key, ciphertext):
    # AES uses 16-byte IV at start
    if len(ciphertext) <= 16:
        return None
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    # pad/trim key to 16/24/32 bytes — ASP.NET typically expects 256-bit AES key if configured
    # we'll try to use 32 bytes (AES-256) by right-padding with zeros if needed
    key = decryption_key
    if len(key) not in (16, 24, 32):
        if len(key) < 32:
            key = key.ljust(32, b'\x00')
        else:
            key = key[:32]
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt_unpadded = pkcs7_unpad(pt)
        if pt_unpadded and b'<' in pt_unpadded[:64]:
            return pt_unpadded
        # still return if unpad ok (even if no '<') to let user inspect
        if pt_unpadded:
            return pt_unpadded
    except Exception:
        return None
    return None

def try_3des(decryption_key, ciphertext):
    # 3DES uses 8-byte IV at start
    if len(ciphertext) <= 8:
        return None
    iv = ciphertext[:8]
    ct = ciphertext[8:]
    key = decryption_key
    # 3DES key must be 16 or 24 bytes; pad/truncate to 24 bytes
    if len(key) < 24:
        key = key.ljust(24, b'\x00')
    else:
        key = key[:24]
    try:
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt_unpadded = pkcs7_unpad(pt)
        if pt_unpadded and b'<' in pt_unpadded[:64]:
            return pt_unpadded
        if pt_unpadded:
            return pt_unpadded
    except Exception:
        return None
    return None

def main():
    print("ASP.NET ViewState decryption helper (AES vs 3DES detector)")
    viewstate_b64 = input("Enter ViewState (Base64): ").strip()
    decryption_key_hex = input("Enter decryptionKey (hex): ").strip()
    # validationKey isn't needed for detecting AES/3DES here, but ask for completeness
    validation_key_hex = input("Enter validationKey (hex) [optional]: ").strip()

    try:
        viewstate_bytes = base64.b64decode(viewstate_b64)
    except Exception as e:
        print("[-] Invalid Base64 ViewState:", e)
        sys.exit(1)

    try:
        decryption_key = unhexlify(decryption_key_hex)
    except Exception as e:
        print("[-] Invalid decryption key hex:", e)
        sys.exit(1)

    print("[*] ViewState length (bytes):", len(viewstate_bytes))
    # quick IV-length heuristic
    if len(viewstate_bytes) >= 16:
        print("[*] First 8 bytes (hex):", viewstate_bytes[:8].hex())
        print("[*] First 16 bytes (hex):", viewstate_bytes[:16].hex())

    # Try AES
    print("[*] Trying AES (16-byte IV) ...")
    aes_plain = try_aes(decryption_key, viewstate_bytes)
    if aes_plain:
        out = "decrypted_viewstate_AES.bin"
        with open(out, "wb") as f:
            f.write(aes_plain)
        print(f"[+] AES decryption appears successful — saved to {out}")
        # show a short textual preview if printable
        preview = aes_plain[:1024]
        try:
            print("[Preview (first 512 bytes)]:")
            print(preview.decode('utf-8', errors='replace')[:512])
        except Exception:
            pass
        return

    # Try 3DES
    print("[*] Trying 3DES (8-byte IV) ...")
    des_plain = try_3des(decryption_key, viewstate_bytes)
    if des_plain:
        out = "decrypted_viewstate_3DES.bin"
        with open(out, "wb") as f:
            f.write(des_plain)
        print(f"[+] 3DES decryption appears successful — saved to {out}")
        preview = des_plain[:1024]
        try:
            print("[Preview (first 512 bytes)]:")
            print(preview.decode('utf-8', errors='replace')[:512])
        except Exception:
            pass
        return

    print("[-] Neither AES nor 3DES produced a clearly valid plaintext with the provided decryption key.")
    print("    - Confirm the decryptionKey hex is correct.")
    print("    - Check for a 'decryption' attribute in web.config (decryption=\"AES\" or decryption=\"3DES\").")
    print("    - Check .NET/ASP.NET runtime version (defaults differ by version).")

if __name__ == '__main__':
    main()
