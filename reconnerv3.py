#!/usr/bin/env python3
"""
reconner.py - Passive Reconnaissance & Secret Discovery Toolkit
For authorized penetration testing only.
"""

import sys
import os
import re
import json
import time
import signal
import random
import string
import argparse
import subprocess
import shutil
import concurrent.futures
import urllib.parse
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    GRY = "\033[90m"
    BRED = "\033[1;91m"
    BGRN = "\033[1;92m"
    BYLW = "\033[1;93m"
    BBLU = "\033[1;94m"
    BMAG = "\033[1;95m"
    BCYN = "\033[1;96m"

BANNER = f"""{C.BCYN}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
  {C.GRY}v3.1 — Authorized Pentest Reconnaissance Toolkit{C.RST}
"""

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
VERBOSITY = 2
TIMEOUT = 10
THREADS = 20
RANDOM_AGENT = False
SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_BASE = Path(".")
SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log(msg, level=1, prefix="*", color=C.BLU):
    if level <= VERBOSITY:
        ts = f"{C.GRY}{datetime.now().strftime('%H:%M:%S')}{C.RST}" if VERBOSITY >= 4 else ""
        print(f"  {ts} {color}[{prefix}]{C.RST} {msg}")

def info(msg, level=1):  log(msg, level, "*", C.BLU)
def ok(msg, level=1):    log(msg, level, "+", C.GRN)
def warn(msg, level=1):  log(msg, level, "!", C.YLW)
def err(msg, level=0):   log(msg, level, "✗", C.RED)
def dbg(msg):            log(msg, 4, "~", C.GRY)
def trace(msg):          log(msg, 5, "…", C.GRY)

def section(title):
    print(f"\n  {C.BMAG}{'━'*60}")
    print(f"  ▸ {title}")
    print(f"  {'━'*60}{C.RST}\n")

def found(category, item, level=2):
    log(f"{C.CYN}{category:<18}{C.RST} {item}", level, "→", C.GRN)

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def get_ua():
    if RANDOM_AGENT:
        return random.choice(USER_AGENTS)
    return USER_AGENTS[0]

def get_headers():
    return {
        "User-Agent": get_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }

def clean_domain(d):
    d = d.strip().rstrip("/")
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0]
    return d.lower()

def ensure_schema(domain):
    if domain.startswith("http://") or domain.startswith("https://"):
        return domain
    return f"https://{domain}"

def write_list(filepath, items):
    items = sorted(set(items))
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text("\n".join(items) + "\n" if items else "")
    dbg(f"Wrote {len(items)} items → {filepath}")
    return items

def read_wordlist(name):
    p = SCRIPT_DIR / "wordlists" / name
    if not p.exists():
        p = SCRIPT_DIR / name
    if not p.exists():
        warn(f"Wordlist not found: {name}", 1)
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]

def load_json_safe(text):
    try:
        return json.loads(text)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

def make_session():
    if not HAS_REQUESTS:
        return None
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=THREADS, pool_maxsize=THREADS)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

SESSION = None

def http_get(url, timeout=None, allow_redirects=True, stream=False):
    global SESSION
    if SESSION is None:
        SESSION = make_session()
    timeout = timeout or TIMEOUT
    try:
        r = SESSION.get(url, headers=get_headers(), timeout=timeout,
                        allow_redirects=allow_redirects, stream=stream, verify=False)
        return r
    except Exception as e:
        trace(f"HTTP error {url}: {e}")
        return None

def http_head(url, timeout=None):
    global SESSION
    if SESSION is None:
        SESSION = make_session()
    timeout = timeout or TIMEOUT
    try:
        r = SESSION.head(url, headers=get_headers(), timeout=timeout,
                         allow_redirects=True, verify=False)
        return r
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Dependency checker / installer
# ---------------------------------------------------------------------------
TOOLS_CHECKED = False
PIP_DEPS = ["requests", "beautifulsoup4", "lxml"]

def check_deps():
    global TOOLS_CHECKED, HAS_REQUESTS, SESSION
    if TOOLS_CHECKED:
        return
    missing_pip = []
    for pkg in PIP_DEPS:
        import_name = pkg.replace("-", "_")
        if pkg == "beautifulsoup4":
            import_name = "bs4"
        try:
            __import__(import_name)
        except ImportError:
            missing_pip.append(pkg)

    if missing_pip:
        info(f"Installing: {', '.join(missing_pip)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q"] + missing_pip,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import importlib
        for pkg in missing_pip:
            if pkg == "beautifulsoup4":
                importlib.import_module("bs4")
            elif pkg == "requests":
                import requests as _r
                HAS_REQUESTS = True
                SESSION = make_session()
            else:
                importlib.import_module(pkg.replace("-", "_"))
    TOOLS_CHECKED = True

def check_tool_exists(name):
    return shutil.which(name) is not None

# ---------------------------------------------------------------------------
# Suppress SSL warnings
# ---------------------------------------------------------------------------
import warnings
warnings.filterwarnings("ignore")
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ---------------------------------------------------------------------------
# MODULE: Subdomain Enumeration
# ---------------------------------------------------------------------------
def extract_subs_crtsh(domain):
    subs = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = http_get(url, timeout=25)
    if r and r.status_code == 200:
        data = load_json_safe(r.text)
        if data:
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lower()
                    if line.endswith(f".{domain}") or line == domain:
                        line = re.sub(r'^\*\.', '', line)
                        subs.add(line)
    ok(f"crt.sh: {len(subs)} subdomains", 2)
    return subs

def extract_subs_hackertarget(domain):
    subs = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    r = http_get(url, timeout=15)
    if r and r.status_code == 200 and "error" not in r.text.lower():
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub)
    ok(f"hackertarget: {len(subs)} subdomains", 2)
    return subs

def extract_subs_rapiddns(domain):
    subs = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    r = http_get(url, timeout=15)
    if r and r.status_code == 200:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "lxml")
        for td in soup.find_all("td"):
            text = td.get_text(strip=True).lower()
            if text.endswith(f".{domain}") or text == domain:
                subs.add(text)
    ok(f"rapiddns: {len(subs)} subdomains", 2)
    return subs

def extract_subs_alienvault(domain):
    subs = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = http_get(url, timeout=15)
    if r and r.status_code == 200:
        data = load_json_safe(r.text)
        if data and "passive_dns" in data:
            for entry in data["passive_dns"]:
                hostname = entry.get("hostname", "").strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
    ok(f"alienvault: {len(subs)} subdomains", 2)
    return subs

def extract_subs_urlscan(domain):
    subs = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    r = http_get(url, timeout=15)
    if r and r.status_code == 200:
        data = load_json_safe(r.text)
        if data and "results" in data:
            for result in data["results"]:
                page = result.get("page", {})
                d = page.get("domain", "").strip().lower()
                if d.endswith(f".{domain}") or d == domain:
                    subs.add(d)
    ok(f"urlscan: {len(subs)} subdomains", 2)
    return subs

def extract_subs_certspotter(domain):
    subs = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    r = http_get(url, timeout=15)
    if r and r.status_code == 200:
        data = load_json_safe(r.text)
        if data and isinstance(data, list):
            for cert in data:
                for name in cert.get("dns_names", []):
                    name = name.strip().lower()
                    name = re.sub(r'^\*\.', '', name)
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name)
    ok(f"certspotter: {len(subs)} subdomains", 2)
    return subs

def extract_subs_shrewdeye(domain):
    subs = set()
    url = f"https://shrewdeye.app/domains/{domain}.txt"
    r = http_get(url, timeout=15)
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            line = line.strip().lower()
            if line and (line.endswith(f".{domain}") or line == domain):
                subs.add(line)
    ok(f"shrewdeye: {len(subs)} subdomains", 2)
    return subs

def extract_subs_webarchive(domain):
    subs = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=5000"
    r = http_get(url, timeout=30)
    if r and r.status_code == 200:
        data = load_json_safe(r.text)
        if data and isinstance(data, list):
            for row in data[1:]:
                if row:
                    parsed = urllib.parse.urlparse(row[0] if isinstance(row, list) else row)
                    host = parsed.hostname
                    if host and (host.endswith(f".{domain}") or host == domain):
                        subs.add(host.lower())
    ok(f"web.archive: {len(subs)} subdomains", 2)
    return subs

def enumerate_subdomains(domain):
    section(f"Subdomain Enumeration: {domain}")
    all_subs = set()
    extractors = [
        extract_subs_crtsh,
        extract_subs_hackertarget,
        extract_subs_rapiddns,
        extract_subs_alienvault,
        extract_subs_urlscan,
        extract_subs_certspotter,
        extract_subs_shrewdeye,
        extract_subs_webarchive,
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(extractors), 10)) as pool:
        futures = {pool.submit(fn, domain): fn.__name__ for fn in extractors}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                all_subs.update(result)
            except Exception as e:
                warn(f"{futures[future]}: {e}", 3)

    all_subs.add(domain)
    ok(f"Total unique subdomains: {C.BLD}{len(all_subs)}{C.RST}", 1)
    return all_subs

# ---------------------------------------------------------------------------
# MODULE: Alive checker
# ---------------------------------------------------------------------------
def check_alive(subdomain):
    for schema in ["https", "http"]:
        url = f"{schema}://{subdomain}"
        r = http_head(url, timeout=TIMEOUT)
        if r is not None:
            return url
    return None

def check_alive_bulk(subdomains, domain):
    section(f"Probing Alive Hosts: {domain}")
    alive = []
    total = len(subdomains)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(check_alive, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if VERBOSITY >= 3 and done % 50 == 0:
                info(f"Progress: {done}/{total}", 3)
            try:
                result = future.result()
                if result:
                    alive.append(result)
                    found("alive", result, 3)
            except Exception:
                pass
    ok(f"Alive hosts: {C.BLD}{len(alive)}{C.RST} / {total}", 1)
    return alive

# ---------------------------------------------------------------------------
# MODULE: Wayback Machine mining
# ---------------------------------------------------------------------------
def wayback_urls(domain):
    section(f"Wayback Machine Mining: {domain}")
    urls = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=10000"
    r = http_get(url, timeout=45)
    if r and r.status_code == 200:
        data = load_json_safe(r.text)
        if data and isinstance(data, list):
            for row in data[1:]:
                u = row[0] if isinstance(row, list) else row
                if u:
                    urls.add(u)
    ok(f"Wayback URLs: {len(urls)}", 1)
    return urls

def classify_urls(urls):
    patterns = {
        "xss": [r'[?&](q|search|query|s|keyword|term|input|text|value|data|msg|message|content|body|payload|comment|name|title|desc|url|redirect|return|next|callback|ref|page|view|action|file|path|src|href|img|image|link)='],
        "sqli": [r'[?&](id|page|report|dir|search|category|class|news|item|menu|lang|name|ref|title|view|topic|thread|type|date|cat|sort|order|process|row|tab|popup|download|file|url|img|path|folder)='],
        "ssrf": [r'[?&](dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open|file|document|folder|pg|php_path|style|doc|img|filename)='],
        "lfi": [r'[?&](cat|dir|action|board|date|detail|file|download|path|folder|prefix|include|inc|locate|show|doc|site|type|view|content|document|layout|mod|conf|pg|template|php_path|style|img|filename)='],
        "redirect": [r'[?&](next|url|target|rurl|dest|destination|redir|redirect_uri|redirect_url|redirect|out|view|to|image_url|go|return|returnTo|return_to|checkout_url|continue|return_path|link)='],
        "rce": [r'[?&](cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|function|req|feature|exe|module|payload|run|print|daemon|upload|log|jndi|env)='],
        "api_endpoints": [r'/api/', r'/v[0-9]+/', r'/graphql', r'/rest/', r'/json', r'/xml', r'/rpc'],
        "juicy_files": [r'\.(sql|bak|old|backup|zip|tar|gz|rar|7z|log|conf|config|cfg|ini|env|swp|swo|db|sqlite|mdb|key|pem|crt|cer|csr)(\?|$)'],
        "js_files": [r'\.js(\?|$)'],
        "php_files": [r'\.php(\?|$)'],
        "sensitive_paths": [r'/(admin|dashboard|panel|login|signin|console|debug|trace|actuator|swagger|graphiql|phpinfo|server-status|server-info|\.well-known)'],
    }
    classified = {k: set() for k in patterns}
    for url in urls:
        for category, pats in patterns.items():
            for pat in pats:
                if re.search(pat, url, re.IGNORECASE):
                    classified[category].add(url)
                    break
    return classified

# ---------------------------------------------------------------------------
# MODULE: urldedupe — deduplicate URLs by structure
# ---------------------------------------------------------------------------
def run_urldedupe(urls, outdir):
    """
    Deduplicate URLs using urldedupe if installed, otherwise fall back to
    a Python implementation that strips duplicate param-structure patterns.
    e.g. /page?id=1 and /page?id=2 collapse into one.
    """
    section("URL Deduplication")
    info(f"Input URLs: {len(urls)}", 1)

    infile = Path(outdir) / ".tmp_urls_raw.txt"
    outfile = Path(outdir) / ".tmp_urls_deduped.txt"
    infile.write_text("\n".join(urls) + "\n")

    deduped = set()

    if check_tool_exists("urldedupe"):
        info("Using urldedupe binary", 2)
        try:
            result = subprocess.run(
                ["urldedupe", "-u", str(infile), "-s"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line:
                        deduped.add(line)
            else:
                warn(f"urldedupe exited {result.returncode}, falling back to python dedup", 2)
                deduped = _python_urldedupe(urls)
        except Exception as e:
            warn(f"urldedupe failed: {e}, falling back to python dedup", 2)
            deduped = _python_urldedupe(urls)
    else:
        warn("urldedupe not found in PATH, using built-in python dedup", 2)
        info("Install: go install github.com/ameenmaali/urldedupe@latest", 2)
        deduped = _python_urldedupe(urls)

    # Cleanup temp files
    infile.unlink(missing_ok=True)
    outfile.unlink(missing_ok=True)

    ok(f"Deduped URLs: {C.BLD}{len(deduped)}{C.RST} (removed {len(urls) - len(deduped)} duplicates)", 1)
    return deduped

def _python_urldedupe(urls):
    """
    Python fallback: deduplicate by (path, sorted_param_names).
    /search?q=foo&lang=en and /search?q=bar&lang=uz → keep only one.
    Also dedupes by stripping trivial path variations like numeric IDs.
    """
    seen_patterns = set()
    deduped = set()

    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)

            # Normalize path: replace numeric segments with {N}
            path_parts = parsed.path.rstrip("/").split("/")
            norm_parts = []
            for part in path_parts:
                if re.match(r'^\d+$', part):
                    norm_parts.append("{N}")
                elif re.match(r'^[a-f0-9]{24,}$', part, re.IGNORECASE):
                    norm_parts.append("{HASH}")
                elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', part, re.IGNORECASE):
                    norm_parts.append("{UUID}")
                else:
                    norm_parts.append(part.lower())
            norm_path = "/".join(norm_parts)

            # Extract sorted param names (ignore values)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            param_key = tuple(sorted(params.keys()))

            # Build fingerprint
            fingerprint = (parsed.netloc.lower(), norm_path, param_key)

            if fingerprint not in seen_patterns:
                seen_patterns.add(fingerprint)
                deduped.add(url)
        except Exception:
            deduped.add(url)

    return deduped

# ---------------------------------------------------------------------------
# MODULE: JS analysis — deep scan from ALL sources
# ---------------------------------------------------------------------------
def extract_js_links_from_html(url, html):
    """Extract JS URLs from an HTML page."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "lxml")
    js_urls = set()
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            parsed = urllib.parse.urlparse(url)
            src = f"{parsed.scheme}://{parsed.netloc}{src}"
        elif not src.startswith("http"):
            src = urllib.parse.urljoin(url, src)
        js_urls.add(src)
    return js_urls

def extract_js_links_from_content(content, base_url):
    """Extract additional JS references from raw content (inline scripts, etc.)."""
    js_urls = set()
    # Match src= references
    for match in re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', content, re.IGNORECASE):
        if match.startswith("//"):
            match = "https:" + match
        elif match.startswith("/"):
            parsed = urllib.parse.urlparse(base_url)
            match = f"{parsed.scheme}://{parsed.netloc}{match}"
        elif not match.startswith("http"):
            match = urllib.parse.urljoin(base_url, match)
        js_urls.add(match)
    return js_urls

def analyze_js_content(js_url, content):
    """Extract API endpoints, URLs, and secrets from JS content."""
    results = {"api_endpoints": set(), "urls": set(), "secrets": set(), "nested_js": set()}

    # --- API endpoints ---
    api_patterns = [
        r'["\'](/api/[^\s"\'<>]+)["\']',
        r'["\'](/v[0-9]+/[^\s"\'<>]+)["\']',
        r'["\'](/graphql[^\s"\'<>]*)["\']',
        r'["\'](/rest/[^\s"\'<>]+)["\']',
        r'["\'](/oauth/[^\s"\'<>]+)["\']',
        r'["\'](/auth/[^\s"\'<>]+)["\']',
        r'["\'](/users?/[^\s"\'<>]*)["\']',
        r'["\'](/admin/[^\s"\'<>]+)["\']',
        r'["\'](/internal/[^\s"\'<>]+)["\']',
        r'["\'](/private/[^\s"\'<>]+)["\']',
        r'["\'](/ws/[^\s"\'<>]+)["\']',
        r'["\'](/socket[^\s"\'<>]*)["\']',
        r'["\'](/webhook[^\s"\'<>]*)["\']',
        r'["\'](https?://[^\s"\'<>]*?/api/[^\s"\'<>]+)["\']',
        r'["\'](https?://[^\s"\'<>]*?/v[0-9]+/[^\s"\'<>]+)["\']',
        r'["\'](https?://[^\s"\'<>]*?/graphql[^\s"\'<>]*)["\']',
        r'fetch\s*\(\s*["\']([^\s"\'<>]+)["\']',
        r'fetch\s*\(\s*`([^`]+)`',
        r'axios\.[a-z]+\s*\(\s*["\']([^\s"\'<>]+)["\']',
        r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^\s"\'<>]+)["\']',
        r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^\s"\'<>]+)["\']',
        r'XMLHttpRequest[^;]*open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^\s"\'<>]+)["\']',
        r'\.get\s*\(\s*["\']([/][^\s"\'<>]+)["\']',
        r'\.post\s*\(\s*["\']([/][^\s"\'<>]+)["\']',
        r'\.put\s*\(\s*["\']([/][^\s"\'<>]+)["\']',
        r'\.delete\s*\(\s*["\']([/][^\s"\'<>]+)["\']',
        r'\.patch\s*\(\s*["\']([/][^\s"\'<>]+)["\']',
        r'endpoint\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'baseURL\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'base_url\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'apiUrl\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'API_URL\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'API_BASE\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'API_ENDPOINT\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'SERVICE_URL\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'BACKEND_URL\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
        r'SERVER_URL\s*[:=]\s*["\']([^\s"\'<>]+)["\']',
    ]
    skip_ext = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                '.woff', '.woff2', '.ttf', '.eot', '.map')
    for pat in api_patterns:
        for match in re.findall(pat, content):
            match = match.strip()
            if len(match) > 3 and not match.lower().endswith(skip_ext):
                # Skip template literals that are unresolved
                if '${' in match or '{{' in match:
                    continue
                results["api_endpoints"].add(match)

    # --- Full URLs ---
    for match in re.findall(r'["\'](https?://[^\s"\'<>]{10,})["\']', content):
        results["urls"].add(match)

    # --- Nested JS files referenced inside this JS ---
    for match in re.findall(r'["\']((?:https?://)?[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?)["\']', content):
        if match.startswith("http"):
            results["nested_js"].add(match)

    # --- Secrets / tokens / keys ---
    secret_patterns = [
        (r'(?i)(api[_-]?key|apikey|api_secret|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key)\s*[:=]\s*["\']([a-zA-Z0-9_\-/.]{16,})["\']', "api_key"),
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "aws_key"),
        (r'(?i)(AKIA[A-Z0-9]{16})', "aws_access_key"),
        (r'(?i)(bearer\s+[a-zA-Z0-9_\-/.]{20,})', "bearer_token"),
        (r'(?i)(ghp_[a-zA-Z0-9]{36})', "github_token"),
        (r'(?i)(gho_[a-zA-Z0-9]{36})', "github_oauth"),
        (r'(?i)(glpat-[a-zA-Z0-9_\-]{20,})', "gitlab_token"),
        (r'(?i)(sk-[a-zA-Z0-9]{20,})', "secret_key"),
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{4,})["\']', "password"),
        (r'(?i)(mongodb(\+srv)?://[^\s"\'<>]+)', "mongodb_uri"),
        (r'(?i)(postgres(ql)?://[^\s"\'<>]+)', "postgres_uri"),
        (r'(?i)(mysql://[^\s"\'<>]+)', "mysql_uri"),
        (r'(?i)(redis://[^\s"\'<>]+)', "redis_uri"),
        (r'(?i)(amqp://[^\s"\'<>]+)', "rabbitmq_uri"),
        (r'(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})', "jwt_token"),
        (r'(?i)(xox[bpas]-[a-zA-Z0-9\-]+)', "slack_token"),
        (r'(?i)(sq0[a-z]{3}-[a-zA-Z0-9_\-]{22,})', "square_key"),
        (r'(?i)(sk_live_[a-zA-Z0-9]{24,})', "stripe_key"),
        (r'(?i)(pk_live_[a-zA-Z0-9]{24,})', "stripe_pub_key"),
        (r'(?i)(rk_live_[a-zA-Z0-9]{24,})', "stripe_restricted"),
        (r'(?i)(AIza[a-zA-Z0-9_\-]{35})', "google_api_key"),
        (r'(?i)(ya29\.[a-zA-Z0-9_\-]{20,})', "google_oauth"),
        (r'(?i)(GOCSPX-[a-zA-Z0-9_\-]{28,})', "google_client_secret"),
        (r'(?i)(SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,})', "sendgrid_key"),
        (r'(?i)(key-[a-zA-Z0-9]{32})', "mailgun_key"),
        (r'(?i)(AC[a-f0-9]{32})', "twilio_sid"),
    ]
    for pat, label in secret_patterns:
        for match in re.findall(pat, content):
            val = match if isinstance(match, str) else match[0]
            results["secrets"].add(f"[{label}] {val}  (src: {js_url})")
    return results

def collect_all_js_urls(alive_urls, wayback_js_urls):
    """
    Collect JS URLs from ALL sources:
    1. Alive host HTML pages (script tags)
    2. Wayback classified JS files
    3. Nested JS found inside other JS files
    Returns dict: {js_url: parent_url}
    """
    section("JS Collection (all sources)")
    js_map = {}  # js_url -> parent_url

    # Source 1: alive host pages
    info("Extracting JS from alive host HTML...", 2)

    def fetch_page_js(url):
        r = http_get(url, timeout=TIMEOUT)
        if r and r.status_code == 200:
            js_from_html = extract_js_links_from_html(url, r.text)
            js_from_content = extract_js_links_from_content(r.text, url)
            return url, js_from_html | js_from_content
        return url, set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(fetch_page_js, url): url for url in alive_urls}
        for future in concurrent.futures.as_completed(futures):
            try:
                parent_url, js_links = future.result()
                for js in js_links:
                    if js not in js_map:
                        js_map[js] = parent_url
            except Exception:
                pass

    alive_js_count = len(js_map)
    ok(f"From alive pages: {alive_js_count} JS files", 2)

    # Source 2: wayback JS files
    wb_added = 0
    for js_url in wayback_js_urls:
        if js_url not in js_map:
            js_map[js_url] = "wayback"
            wb_added += 1
    ok(f"From wayback: {wb_added} JS files added", 2)

    ok(f"Total unique JS to analyze: {C.BLD}{len(js_map)}{C.RST}", 1)
    return js_map

def deep_js_analysis(js_map):
    """
    Fetch and analyze ALL collected JS files.
    Also follows nested JS references (1 level deep).
    """
    section("JS Deep Analysis")
    all_results = {"api_endpoints": set(), "urls": set(), "secrets": set()}
    analyzed = set()
    nested_js_queue = {}  # new JS found inside JS

    def fetch_and_analyze(js_url, parent_url):
        if js_url in analyzed:
            return None
        r = http_get(js_url, timeout=TIMEOUT)
        if r and r.status_code == 200 and len(r.text) < 10_000_000:
            return js_url, parent_url, analyze_js_content(js_url, r.text)
        return None

    info(f"Analyzing {len(js_map)} JS files (pass 1)...", 2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(fetch_and_analyze, js_url, parent): (js_url, parent)
                   for js_url, parent in js_map.items()}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    js_url, parent_url, data = result
                    analyzed.add(js_url)
                    all_results["api_endpoints"].update(data["api_endpoints"])
                    all_results["urls"].update(data["urls"])
                    all_results["secrets"].update(data["secrets"])
                    # Collect nested JS for pass 2
                    for nested in data.get("nested_js", set()):
                        if nested not in analyzed and nested not in js_map:
                            nested_js_queue[nested] = js_url
            except Exception:
                pass

    # Pass 2: analyze nested JS discovered inside other JS
    if nested_js_queue:
        info(f"Analyzing {len(nested_js_queue)} nested JS files (pass 2)...", 2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
            futures = {pool.submit(fetch_and_analyze, js_url, parent): (js_url, parent)
                       for js_url, parent in nested_js_queue.items()}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        js_url, parent_url, data = result
                        analyzed.add(js_url)
                        all_results["api_endpoints"].update(data["api_endpoints"])
                        all_results["urls"].update(data["urls"])
                        all_results["secrets"].update(data["secrets"])
                except Exception:
                    pass

    ok(f"JS analysis complete: {C.BLD}{len(analyzed)}{C.RST} files analyzed", 1)
    ok(f"  API endpoints: {len(all_results['api_endpoints'])}", 2)
    ok(f"  URLs found:    {len(all_results['urls'])}", 2)
    ok(f"  Secrets found: {len(all_results['secrets'])}", 2)
    return all_results, analyzed

# ---------------------------------------------------------------------------
# MODULE: Secret files scanner (with false positive detection)
# ---------------------------------------------------------------------------
TARGET_TYPES = {
    "generic": "secrets_generic.txt",
    "wordpress": "secrets_wordpress.txt",
    "laravel": "secrets_laravel.txt",
    "django": "secrets_django.txt",
    "nodejs": "secrets_nodejs.txt",
    "spring": "secrets_spring.txt",
    "rails": "secrets_rails.txt",
    "aspnet": "secrets_aspnet.txt",
    "php": "secrets_php.txt",
    "vuejs": "secrets_vuejs.txt",
    "react": "secrets_react.txt",
    "angular": "secrets_angular.txt",
    "joomla": "secrets_joomla.txt",
    "drupal": "secrets_drupal.txt",
    "magento": "secrets_magento.txt",
    "strapi": "secrets_strapi.txt",
    "nextjs": "secrets_nextjs.txt",
    "nuxtjs": "secrets_nuxtjs.txt",
}

def detect_target_type(url, html=None):
    types = set()
    if html is None:
        r = http_get(url, timeout=TIMEOUT)
        if r and r.status_code == 200:
            html = r.text
        else:
            return {"generic"}

    hl = html.lower()
    checks = {
        "wordpress": ["/wp-content/", "/wp-includes/", "wp-json", "wordpress"],
        "laravel": ["laravel", "csrf-token", "laravel_session"],
        "django": ["csrfmiddlewaretoken", "django", "__admin__"],
        "nodejs": ["express", "x-powered-by"],
        "spring": ["spring", "actuator", "whitelabel error"],
        "rails": ["rails", "csrf-token", "turbolinks"],
        "aspnet": ["__viewstate", "__eventvalidation", "asp.net", "aspnet"],
        "php": [".php", "phpsessid"],
        "vuejs": ["__vue__", "vue.js", "vue.min.js", "nuxt", "vue-router"],
        "react": ["react", "_reactroot", "react-dom", "__next"],
        "angular": ["ng-version", "angular", "ng-app"],
        "joomla": ["joomla", "/components/com_", "/media/jui/"],
        "drupal": ["drupal", "sites/default", "drupal.settings"],
        "magento": ["magento", "mage/", "varien/"],
        "strapi": ["strapi", "/admin/", "content-type-builder"],
        "nextjs": ["__next", "_next/static", "next.js"],
        "nuxtjs": ["__nuxt", "_nuxt/", "nuxt.js"],
    }

    for tech, indicators in checks.items():
        for ind in indicators:
            if ind in hl:
                types.add(tech)
                break

    r = http_head(url, timeout=TIMEOUT)
    if r:
        headers_str = str(r.headers).lower()
        for tech, indicators in checks.items():
            for ind in indicators:
                if ind in headers_str:
                    types.add(tech)

    if not types:
        types.add("generic")
    return types

def check_secret_path(base_url, path):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    r = http_get(url, timeout=TIMEOUT)
    if r is None:
        return None

    if r.status_code == 200:
        ct = r.headers.get("content-type", "").lower()
        text = r.text[:2000]
        soft_404_indicators = ["not found", "page not found", "404", "does not exist",
                               "error 404", "the page you", "no such file"]
        if any(ind in text.lower() for ind in soft_404_indicators) and len(text) < 5000:
            return None
        if len(r.text.strip()) < 5:
            return None
        return {
            "url": url, "status": r.status_code, "size": len(r.text),
            "content_type": ct, "snippet": text[:300],
        }
    elif r.status_code == 403:
        return {
            "url": url, "status": 403, "size": 0,
            "content_type": "", "snippet": "[403 Forbidden - file exists but access denied]",
        }
    return None

def scan_secrets(alive_urls, target_type=None):
    section("Secret Files Discovery")
    findings = {}

    paths = set()
    generic = read_wordlist("secrets_generic.txt")
    paths.update(generic)
    info(f"Loaded {len(generic)} generic paths", 2)

    if target_type:
        for tt in target_type.split(","):
            tt = tt.strip().lower()
            if tt in TARGET_TYPES:
                specific = read_wordlist(TARGET_TYPES[tt])
                paths.update(specific)
                info(f"Loaded {len(specific)} {tt}-specific paths", 2)

    info(f"Total paths to check: {len(paths)}", 1)
    FP_THRESHOLD = 5

    for base_url in alive_urls:
        host_findings = []

        if not target_type:
            detected_types = detect_target_type(base_url)
            if detected_types != {"generic"}:
                info(f"{base_url} → detected: {', '.join(detected_types)}", 2)
                for dt in detected_types:
                    if dt in TARGET_TYPES and dt != "generic":
                        extra = read_wordlist(TARGET_TYPES[dt])
                        paths.update(extra)

        info(f"Scanning {base_url} with {len(paths)} paths...", 2)

        raw_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
            futures = {pool.submit(check_secret_path, base_url, p): p for p in paths}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        raw_results.append(result)
                except Exception:
                    pass

        size_counts = {}
        for r in raw_results:
            if r["status"] == 200:
                sz = r["size"]
                size_counts[sz] = size_counts.get(sz, 0) + 1

        fp_sizes = {sz for sz, count in size_counts.items() if count >= FP_THRESHOLD}
        if fp_sizes:
            warn(f"{base_url} → false positive sizes: {', '.join(f'{s}b ({size_counts[s]}x)' for s in sorted(fp_sizes))}", 2)

        for r in raw_results:
            if r["status"] == 200 and r["size"] in fp_sizes:
                dbg(f"FP filtered: {r['url']} ({r['size']}b)")
                continue
            host_findings.append(r)
            status_color = C.GRN if r["status"] == 200 else C.YLW
            found("secret", f"{status_color}[{r['status']}]{C.RST} {r['url']} ({r['size']}b)")

        if host_findings:
            findings[base_url] = host_findings

    total_found = sum(len(v) for v in findings.values())
    ok(f"Secret files: {C.BLD}{total_found}{C.RST} across {len(findings)} hosts", 1)
    return findings

def output_secret_findings(findings, outdir):
    outdir = Path(outdir)
    lines_200 = []
    lines_403 = []
    for host, items in findings.items():
        for item in items:
            entry = f"[{item['status']}] {item['url']} ({item['size']}b)"
            if item["status"] == 200:
                lines_200.append(entry)
            else:
                lines_403.append(entry)
    write_list(outdir / "secrets_found_200.txt", lines_200)
    write_list(outdir / "secrets_found_403.txt", lines_403)
    write_list(outdir / "secrets_found_all.txt", lines_200 + lines_403)

# ---------------------------------------------------------------------------
# MODULE: API Endpoint Enumeration
# ---------------------------------------------------------------------------
API_COMMON_PATHS = [
    "api", "api/", "api/v1", "api/v2", "api/v3", "api/v4",
    "api/v1/", "api/v2/", "api/v3/",
    "api/docs", "api/doc", "api/help", "api/schema",
    "api/swagger", "api/swagger.json", "api/swagger.yaml",
    "api/openapi", "api/openapi.json", "api/openapi.yaml",
    "api/api-docs", "api/redoc",
    "swagger.json", "swagger.yaml", "swagger/", "swagger-ui/", "swagger-ui.html",
    "openapi.json", "openapi.yaml",
    "v1/api-docs", "v2/api-docs", "v3/api-docs",
    "api-docs", "api-docs/", "redoc", "redoc/", "doc.html",
    "graphql", "graphiql", "playground", "api/graphql",
    "graphql/console", "graphql/schema", "__graphql", "v1/graphql",
    "api/health", "api/healthz", "api/status", "api/ping",
    "api/version", "api/info", "api/config", "api/debug",
    "health", "healthz", "health/live", "health/ready",
    "readyz", "livez", "status", "ping", "version", "info",
    "metrics", "prometheus/metrics", "server-status", "server-info",
    "api/auth", "api/auth/login", "api/auth/register",
    "api/auth/token", "api/auth/refresh",
    "api/login", "api/register", "api/signup",
    "api/token", "api/oauth/token",
    "oauth/token", "oauth/authorize",
    "auth/login", "auth/token", "auth/register",
    "connect/token", "connect/authorize",
    ".well-known/openid-configuration", ".well-known/jwks.json",
    "api/v1/auth/login", "api/v1/auth/register",
    "api/users", "api/user", "api/users/me", "api/me",
    "api/account", "api/accounts", "api/profile",
    "api/v1/users", "api/v1/user", "api/v1/users/me", "api/v2/users",
    "users", "user", "accounts",
    "api/items", "api/products", "api/orders", "api/posts",
    "api/comments", "api/categories", "api/tags",
    "api/files", "api/upload", "api/uploads", "api/download",
    "api/images", "api/media", "api/documents",
    "api/search", "api/query", "api/filter",
    "api/v1/items", "api/v1/products", "api/v1/orders",
    "api/v1/posts", "api/v1/search",
    "api/admin", "api/admin/users", "api/admin/config",
    "api/admin/settings", "api/admin/stats",
    "api/internal", "api/private", "api/management",
    "api/console", "api/dashboard",
    "api/test", "api/debug", "api/dev",
    "debug", "debug/vars", "debug/pprof", "debug/requests",
    "_debug", "_profiler", "trace",
    "actuator", "actuator/env", "actuator/health",
    "actuator/info", "actuator/beans", "actuator/mappings",
    "actuator/configprops", "actuator/metrics",
    "actuator/httptrace", "actuator/threaddump",
    "actuator/heapdump", "actuator/loggers",
    "actuator/prometheus", "actuator/sessions",
    "actuator/shutdown", "actuator/gateway/routes", "actuator/jolokia",
    "wp-json/", "wp-json/wp/v2/users", "wp-json/wp/v2/posts",
    "wp-json/wp/v2/pages", "wp-json/wp/v2/settings",
    "?rest_route=/wp/v2/users",
    "jsonapi/", "jsonapi/node/article", "rest/session/token",
    "api/auth/local", "api/users-permissions/roles",
    "api/content-type-builder/content-types",
    "api/upload/files", "_health",
    "rest/V1/store/storeViews", "rest/V1/store/storeConfigs",
    "rest/V1/directory/countries", "rest/V1/integration/admin/token",
    "_next/data/", "_nuxt/builds/latest.json",
    "api/auth/session", "api/auth/providers", "api/trpc/",
    "odata/", "odata/$metadata", "soap", "wsdl",
    "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", "security.txt",
    "_catalog", "__routes__", "routes", "endpoints",
    "api/routes", "api/endpoints",
]

def probe_api_endpoint(base_url, path):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        r = http_get(url, timeout=TIMEOUT)
        if r is None:
            return None
        if r.status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405):
            ct = r.headers.get("content-type", "").lower()
            size = len(r.text) if r.text else 0
            text = r.text[:2000] if r.text else ""

            if r.status_code == 200:
                soft_404 = ["not found", "page not found", "404", "does not exist", "error 404"]
                if any(ind in text.lower() for ind in soft_404) and size < 5000:
                    return None
                if size < 5:
                    return None

            is_api = any([
                "application/json" in ct, "application/xml" in ct,
                "text/xml" in ct, "application/yaml" in ct,
                "swagger" in text.lower()[:500], "openapi" in text.lower()[:500],
                '"version"' in text[:500], '"status"' in text[:500],
                '"data"' in text[:500], '"error"' in text[:500],
                '"message"' in text[:500], '"results"' in text[:500],
                '"paths"' in text[:500], "graphql" in text.lower()[:500],
                r.status_code in (401, 403, 405),
            ])
            if ct and "json" in ct:
                is_api = True

            if is_api:
                return {
                    "url": url, "status": r.status_code, "size": size,
                    "content_type": ct, "snippet": text[:300],
                }
    except Exception:
        pass
    return None

def enumerate_api_endpoints(alive_urls, js_api_endpoints=None):
    """
    Probe alive hosts with common API paths + any JS-discovered endpoints.
    """
    section("API Endpoint Enumeration")
    findings = {}

    # Build per-host path lists: common + JS-discovered
    js_paths_per_host = {}
    if js_api_endpoints:
        for ep in js_api_endpoints:
            ep = ep.strip()
            if ep.startswith("http"):
                parsed = urllib.parse.urlparse(ep)
                host_base = f"{parsed.scheme}://{parsed.netloc}"
                path = parsed.path
                if parsed.query:
                    path += f"?{parsed.query}"
                if host_base not in js_paths_per_host:
                    js_paths_per_host[host_base] = set()
                js_paths_per_host[host_base].add(path.lstrip("/"))
            elif ep.startswith("/"):
                # Relative path — add to all hosts
                for url in alive_urls:
                    if url not in js_paths_per_host:
                        js_paths_per_host[url] = set()
                    js_paths_per_host[url].add(ep.lstrip("/"))

    info(f"Probing {len(alive_urls)} hosts with ~{len(API_COMMON_PATHS)}+ API paths each", 1)

    FP_THRESHOLD = 5

    for base_url in alive_urls:
        host_findings = []
        paths_to_check = set(API_COMMON_PATHS)

        # Add JS-discovered paths for this host
        js_extra = js_paths_per_host.get(base_url, set())
        if js_extra:
            paths_to_check.update(js_extra)
            dbg(f"{base_url}: +{len(js_extra)} JS-discovered paths")

        raw_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
            futures = {pool.submit(probe_api_endpoint, base_url, p): p for p in paths_to_check}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        raw_results.append(result)
                except Exception:
                    pass

        size_counts = {}
        for r in raw_results:
            if r["status"] == 200:
                sz = r["size"]
                size_counts[sz] = size_counts.get(sz, 0) + 1

        fp_sizes = {sz for sz, count in size_counts.items() if count >= FP_THRESHOLD}
        if fp_sizes:
            warn(f"{base_url} → API FP sizes: {', '.join(f'{s}b ({size_counts[s]}x)' for s in sorted(fp_sizes))}", 2)

        for r in raw_results:
            if r["status"] == 200 and r["size"] in fp_sizes:
                dbg(f"API FP filtered: {r['url']} ({r['size']}b)")
                continue
            host_findings.append(r)
            if r["status"] == 200:
                sc = C.GRN
            elif r["status"] in (401, 403):
                sc = C.YLW
            elif r["status"] == 405:
                sc = C.CYN
            else:
                sc = C.GRY
            found("api-endpoint", f"{sc}[{r['status']}]{C.RST} {r['url']} ({r['size']}b) {C.GRY}{r['content_type']}{C.RST}")

        if host_findings:
            findings[base_url] = host_findings

    total = sum(len(v) for v in findings.values())
    ok(f"API endpoints: {C.BLD}{total}{C.RST} across {len(findings)} hosts", 1)
    return findings

def output_api_findings(findings, outdir):
    outdir = Path(outdir)
    lines_200 = []
    lines_auth = []
    lines_all = []

    for host, items in findings.items():
        for item in items:
            ct_short = item["content_type"].split(";")[0].strip() if item["content_type"] else "?"
            entry = f"[{item['status']}] {item['url']} ({item['size']}b) [{ct_short}]"
            lines_all.append(entry)
            if item["status"] == 200:
                lines_200.append(entry)
            elif item["status"] in (401, 403):
                lines_auth.append(entry)

    write_list(outdir / "api_endpoints_200.txt", lines_200)
    write_list(outdir / "api_endpoints_auth.txt", lines_auth)
    write_list(outdir / "api_endpoints_all.txt", lines_all)

    urls_only = []
    for host, items in findings.items():
        for item in items:
            urls_only.append(item["url"])
    write_list(outdir / "api_endpoints_urls.txt", urls_only)

# ---------------------------------------------------------------------------
# MODULE: Full extractor pipeline
# ---------------------------------------------------------------------------
def run_extractor(domain, outdir, target_type=None):
    section(f"EXTRACTOR PIPELINE: {domain}")
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # ── 1. Subdomain enumeration ──
    subdomains = enumerate_subdomains(domain)
    write_list(outdir / "allsubdomains.txt", list(subdomains))

    # ── 2. Alive check ──
    alive = check_alive_bulk(subdomains, domain)
    write_list(outdir / "alive.txt", alive)
    alive_nohttp = [re.sub(r'^https?://', '', u) for u in alive]
    write_list(outdir / "alive_nohttp.txt", alive_nohttp)

    # ── 3. Wayback mining ──
    wb_urls = wayback_urls(domain)
    write_list(outdir / "wayback_urls_raw.txt", list(wb_urls))

    # ── 4. Classify URLs ──
    classified = classify_urls(wb_urls)
    for category, items in classified.items():
        if items:
            write_list(outdir / f"wayback_{category}.txt", list(items))
            ok(f"  {category}: {len(items)} URLs", 2)

    # ── 5. Deduplicate ALL URLs ──
    all_urls_raw = set(wb_urls)
    # Add alive URLs to the pool
    all_urls_raw.update(alive)
    # Add any URLs from classifications
    for cat_urls in classified.values():
        all_urls_raw.update(cat_urls)

    deduped_urls = run_urldedupe(all_urls_raw, outdir)
    write_list(outdir / "urls_deduped.txt", list(deduped_urls))

    # Also dedupe per-category files
    for category, items in classified.items():
        if items:
            cat_deduped = _python_urldedupe(items)  # quick dedupe per category
            write_list(outdir / f"wayback_{category}.txt", list(cat_deduped))

    # ── 6. JS deep analysis — collect from ALL sources ──
    wayback_js = classified.get("js_files", set())
    js_map = collect_all_js_urls(alive, wayback_js)
    js_results, js_analyzed = deep_js_analysis(js_map)

    # Resolve relative JS endpoints to full URLs
    all_api_full = set()
    all_api_only = set()
    js_api_annotated = []

    for ep in js_results["api_endpoints"]:
        all_api_only.add(ep)
        if ep.startswith("http"):
            all_api_full.add(ep)
            js_api_annotated.append(ep)
        elif ep.startswith("/"):
            # Resolve against all alive hosts
            for alive_url in alive:
                parsed = urllib.parse.urlparse(alive_url)
                full = f"{parsed.scheme}://{parsed.netloc}{ep}"
                all_api_full.add(full)
            js_api_annotated.append(f"{ep}  # relative, resolved to all alive hosts")

    write_list(outdir / "js_api_endpoints_full.txt", list(all_api_full))
    write_list(outdir / "js_api_endpoints_only.txt", list(all_api_only))
    write_list(outdir / "js_api_annotated.txt", sorted(js_api_annotated))
    write_list(outdir / "js_urls.txt", sorted(js_results["urls"]))
    write_list(outdir / "js_secrets.txt", sorted(js_results["secrets"]))
    write_list(outdir / "js_files_analyzed.txt", sorted(js_analyzed))

    # ── 7. API endpoint enumeration (common paths + JS-discovered) ──
    api_findings = enumerate_api_endpoints(alive, js_api_endpoints=all_api_only)
    output_api_findings(api_findings, outdir)

    # ── 8. Secret files discovery ──
    secret_findings = scan_secrets(alive, target_type)
    output_secret_findings(secret_findings, outdir)

    # ── 9. Merge all secrets ──
    all_secrets = set()
    all_secrets.update(js_results["secrets"])
    for category in ["juicy_files", "sensitive_paths"]:
        all_secrets.update(classified.get(category, set()))
    for host, items in secret_findings.items():
        for item in items:
            all_secrets.add(f"[{item['status']}] {item['url']}")
    write_list(outdir / "secrets.txt", sorted(all_secrets))

    # ── Summary ──
    ok(f"Extractor complete → {outdir}/", 0)
    print(f"\n  {C.GRY}Files written:{C.RST}")
    for f in sorted(outdir.iterdir()):
        if f.name.startswith(".tmp"):
            continue
        lines = len(f.read_text().splitlines()) if f.stat().st_size > 0 else 0
        print(f"    {C.CYN}{f.name:<35}{C.RST} {lines:>6} lines")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description=f"{C.BCYN}reconner{C.RST} — Authorized Pentest Reconnaissance Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.BLD}Examples:{C.RST}
  reconner.py example.com
  reconner.py example.com example2.com
  reconner.py -f domains.txt
  reconner.py example.com -v3 --th 30 --ra
  reconner.py example.com -o /tmp/recon_output
  reconner.py example.com -tt wordpress,laravel
        """,
    )
    parser.add_argument("domains", nargs="*", help="Domain(s) to scan")
    parser.add_argument("-f", "--file", help="File containing domains (one per line)")
    parser.add_argument("-tt", "--target-type", default=None,
                        help=f"Target type hint: {', '.join(TARGET_TYPES.keys())}")
    parser.add_argument("--ra", action="store_true", help="Random User-Agent per request")
    parser.add_argument("--to", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--th", type=int, default=20, help="Thread count (default: 20)")
    parser.add_argument("-v", "--verbosity", type=int, default=2, choices=range(0, 6),
                        help="Verbosity 0-5 (default: 2)")
    parser.add_argument("-o", "--output", default=None, help="Output directory (default: ./recon_<domain>)")
    return parser.parse_args()

def main():
    global VERBOSITY, TIMEOUT, THREADS, RANDOM_AGENT

    args = parse_args()
    VERBOSITY = args.verbosity
    TIMEOUT = args.to
    THREADS = args.th
    RANDOM_AGENT = args.ra

    if VERBOSITY >= 1:
        print(BANNER)

    check_deps()

    domains = []
    if args.file:
        p = Path(args.file)
        if p.exists():
            domains = [clean_domain(l) for l in p.read_text().splitlines() if l.strip()]
        else:
            err(f"File not found: {args.file}")
            sys.exit(1)
    if args.domains:
        domains.extend([clean_domain(d) for d in args.domains])

    domains = list(dict.fromkeys(d for d in domains if d))

    if not domains:
        err("No domains specified. Use: reconner.py domain.com or reconner.py -f domains.txt")
        sys.exit(1)

    info(f"Targets: {', '.join(domains)}", 1)
    info(f"Threads: {THREADS} | Timeout: {TIMEOUT}s | Verbosity: v{VERBOSITY}", 1)
    if RANDOM_AGENT:
        info("Random User-Agent: enabled", 1)

    for domain in domains:
        outdir = Path(args.output) if args.output else Path(f"recon_{domain}")
        run_extractor(domain, outdir, args.target_type)

    section("COMPLETE")
    for domain in domains:
        outdir = Path(args.output) if args.output else Path(f"recon_{domain}")
        print(f"  {C.BGRN}✓{C.RST} {domain} → {C.CYN}{outdir}/{C.RST}")

if __name__ == "__main__":
    main()