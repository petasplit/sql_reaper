#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       REAPER RECON v2.0 — Unified Subdomain & Endpoint Discovery           ║
║       75+ OSINT Sources · Smart Active Probing · JS Analysis               ║
║       FOR AUTHORIZED SECURITY TESTING ONLY                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

Install:  pip install aiohttp aiofiles dnspython beautifulsoup4 lxml tqdm

Usage:
  python3 reaper_recon.py
  python3 reaper_recon.py -d example.com
  python3 reaper_recon.py -d example.com --passive-only
  python3 reaper_recon.py -d example.com --vt-key VT --shodan-key SH
  python3 reaper_recon.py -d example.com --proxy http://127.0.0.1:8080
"""

# ═══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════
import argparse, asyncio, base64, hashlib, ipaddress, json, os, random
import re, socket, ssl, string, sys, time, traceback, urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

try:
    import aiohttp
    import aiofiles
except ImportError:
    sys.exit("[!] pip install aiohttp aiofiles")

try:
    from bs4 import BeautifulSoup
    BS4 = True
except ImportError:
    BS4 = False

try:
    import dns.asyncresolver, dns.resolver, dns.exception
    DNSPY = True
except ImportError:
    DNSPY = False

# Optional tqdm progress bar
try:
    from tqdm.asyncio import tqdm as atqdm
    TQDM = True
except ImportError:
    TQDM = False

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
VERSION       = "2.0.0"
MAX_HTTP      = 80
MAX_DNS       = 150
MAX_PROBE     = 100
MAX_JS        = 25
REQ_TIMEOUT   = 14
DNS_TIMEOUT   = 5
RETRIES       = 3
BACKOFF       = 1.8
MAX_JS_BYTES  = 6 * 1024 * 1024
OUTPUT_BASE   = "reaper_output"

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.92",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.71 Mobile Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "curl/8.6.0",
]

# ─── Framework endpoint probes ─────────────────────────────────────────────
FW_PATHS: Dict[str, List[str]] = {
    "spring": [
        "/actuator","/actuator/health","/actuator/health/liveness",
        "/actuator/health/readiness","/actuator/env","/actuator/beans",
        "/actuator/mappings","/actuator/metrics","/actuator/info",
        "/actuator/loggers","/actuator/threaddump","/actuator/heapdump",
        "/actuator/prometheus","/actuator/httptrace","/actuator/auditevents",
        "/actuator/caches","/actuator/configprops","/actuator/scheduledtasks",
        "/actuator/sessions","/actuator/shutdown","/actuator/startup",
        "/actuator/flyway","/actuator/liquibase","/jolokia","/jolokia/list",
        "/manage/health","/management/health","/health","/info","/metrics","/env",
    ],
    "nextjs": [
        "/_next/data/","/_next/static/","/_next/image",
        "/api/auth/session","/api/auth/providers","/api/auth/csrf",
        "/api/auth/callback","/api/auth/signin","/api/auth/signout",
        "/api/trpc/","/__nextjs_original-stack-frame",
    ],
    "nuxt": ["/_nuxt/","/__nuxt_error","/api/_content/","/_ipx/","/api/","/_payload.json"],
    "django": [
        "/admin/","/admin/login/","/admin/doc/","/__debug__/","/silk/",
        "/api/schema/","/api/schema/swagger-ui/","/api/schema/redoc/",
        "/_debugbar/","/rosetta/","/flower/",
    ],
    "laravel": [
        "/nova","/nova-api/","/telescope","/telescope/api/",
        "/horizon","/horizon/api/","/sanctum/csrf-cookie",
        "/_debugbar/","/debugbar/","/artisan",
    ],
    "rails": [
        "/rails/info/","/rails/info/properties","/rails/info/routes",
        "/rails/mailers","/sidekiq","/sidekiq/queues","/resque/",
        "/blazer","/letter_opener","/rack-mini-profiler/",
    ],
    "wordpress": [
        "/wp-admin/","/wp-admin/admin-ajax.php","/wp-login.php",
        "/wp-json/wp/v2/","/wp-json/wp/v2/users","/wp-json/wp/v2/posts",
        "/wp-json/","/xmlrpc.php","/wp-cron.php","/wp-config.php",
        "/?rest_route=/wp/v2/users","/?author=1","/wp-content/debug.log",
    ],
    "graphql": [
        "/graphql","/graphiql","/graphql/console","/graphql/playground",
        "/api/graphql","/v1/graphql","/v2/graphql","/query",
        "/playground","/altair","/graphql-explorer",
    ],
    "swagger": [
        "/swagger-ui/","/swagger-ui.html","/swagger/","/api-docs",
        "/api-docs/","/openapi.json","/openapi.yaml",
        "/v1/api-docs","/v2/api-docs","/v3/api-docs",
        "/swagger/v1/swagger.json","/swagger/v2/swagger.json",
        "/api/swagger.json","/docs/","/redoc","/scalar",
        "/swagger-resources","/v2/swagger.json","/v3/openapi.json",
    ],
    "k8s": [
        "/healthz","/readyz","/livez","/metrics",
        "/apis/","/api/v1","/version","/openapi/v2",
        "/latest/meta-data/","/computeMetadata/v1/","/metadata/instance/",
    ],
    "aspnet": [
        "/elmah.axd","/elmah/","/trace.axd","/hangfire","/hangfire/",
        "/mini-profiler-resources/","/healthcheck","/api/healthcheck",
        "/_framework/blazor.webassembly.js",
    ],
    "jenkins": [
        "/jenkins/","/job/","/view/","/script","/scriptText","/systemInfo",
        "/api/json","/api/xml","/crumbIssuer/api/json","/computer/api/json",
    ],
    "jira": [
        "/rest/api/2/","/rest/api/latest/","/rest/auth/1/session",
        "/wiki/rest/api/","/secure/Dashboard.jspa",
    ],
    "git_leak": [
        "/.git/","/.git/HEAD","/.git/config","/.git/refs/heads/main",
        "/.git/refs/heads/master","/.git/COMMIT_EDITMSG","/.git/index",
        "/.git/packed-refs","/.git/logs/HEAD",
        "/.svn/","/.svn/wc.db","/.hg/","/.hg/hgrc","/.bzr/",
    ],
    "secrets": [
        "/.env","/.env.local","/.env.production","/.env.staging",
        "/.env.development","/.env.example","/.env.backup","/.env.prod",
        "/config.json","/config.yml","/config.yaml","/config.toml",
        "/settings.json","/web.config","/appsettings.json",
        "/database.yml","/secrets.yml","/credentials.yml",
        "/application.yml","/application.properties",
        "/service-account.json","/firebase-adminsdk.json",
        "/google-credentials.json","/.aws/credentials",
        "/private.key","/server.key","/Dockerfile","/docker-compose.yml",
        "/terraform.tfvars","/terraform.tfstate","/.terraform/",
        "/helm-values.yaml","/k8s.yml","/kubernetes.yml",
    ],
    "api": [
        "/api/v1/","/api/v2/","/api/v3/","/api/v4/","/api/v5/",
        "/v1/","/v2/","/v3/","/api/","/api/latest/",
        "/api/internal/","/api/private/","/api/public/",
        "/api/admin/","/api/system/","/api/debug/",
        "/api/beta/","/api/alpha/","/api/test/","/api/dev/",
        "/api/search","/api/users","/api/user","/api/me",
        "/api/auth","/api/login","/api/logout","/api/register",
        "/api/profile","/api/account","/api/settings","/api/config",
        "/api/status","/api/health","/api/ping","/api/info",
        "/api/token","/api/refresh","/api/oauth","/api/oauth2",
        "/api/webhooks","/api/events","/api/data","/api/upload",
        "/api/reports","/api/analytics","/api/metrics",
        "/api/notifications","/api/orders","/api/products",
        "/api/customers","/api/permissions","/api/roles",
        "/api/logs","/api/audit","/graphql","/rest/","/soap/","/rpc/",
    ],
    "wellknown": [
        "/.well-known/security.txt","/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json","/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/host-meta","/.well-known/webfinger",
        "/.well-known/change-password","/.well-known/mta-sts.txt",
    ],
    "debug": [
        "/admin","/admin/","/administrator/","/dashboard","/console",
        "/phpinfo.php","/info.php","/test.php","/server-status",
        "/server-info","/nginx_status","/debug","/debug/",
        "/phpmyadmin/","/pma/","/adminer/","/adminer.php",
        "/manager/html","/host-manager/html",
        "/solr/","/solr/admin/","/kibana/","/grafana/",
    ],
    "packages": [
        "/package.json","/package-lock.json","/yarn.lock","/pnpm-lock.yaml",
        "/composer.json","/Gemfile","/requirements.txt",
        "/go.mod","/Cargo.toml","/pyproject.toml",
    ],
    "backup": [
        "/backup/","/backups/","/bak/","/old/","/archive/","/dump/",
        "/database.sql","/db.sql","/dump.sql",
        "/backup.zip","/backup.tar.gz","/site.zip",
    ],
    "cloud_storage": [
        "/s3/","/blob/","/storage/","/uploads/","/files/","/assets/",
        "/static/","/media/","/cdn/","/public/",
    ],
    "sourcemaps": [
        "/main.js.map","/app.js.map","/bundle.js.map",
        "/static/js/main.chunk.js.map","/dist/bundle.js.map",
        "/assets/index.js.map","/build/static/js/main.chunk.js.map",
    ],
}

ALL_PROBE_PATHS = list({p for ps in FW_PATHS.values() for p in ps})

SUBDOMAIN_PREFIXES = [
    "www","mail","ftp","smtp","pop","pop3","imap","vpn","ssh","rdp","sftp",
    "dns","ns1","ns2","mx","mx1","mx2","relay","gateway",
    "dev","development","develop","devel","staging","stage","stg","uat","qa",
    "qat","pre-prod","test","testing","sandbox","demo","preview","beta","alpha",
    "canary","next","new","old","prod","production","live","release",
    "local","internal","private","ext","external","int","corp","intranet",
    "api","api2","api3","api-v1","api-v2","api-v3","rest","graphql","grpc","rpc",
    "auth","login","sso","oauth","id","identity","iam","idp",
    "portal","dashboard","admin","manage","console","panel","control","cp","cpanel","whm",
    "shop","store","ecom","cart","checkout","pay","payment","billing",
    "blog","news","media","cdn","static","assets","img","images","video",
    "stream","live","hls","vod","rtmp",
    "app","apps","mobile","m","wap","web","www2","www3","pwa",
    "cloud","k8s","kubernetes","docker","registry","container",
    "metrics","monitor","monitoring","grafana","kibana","elk","elastic",
    "prometheus","alertmanager","jaeger","zipkin","datadog",
    "jenkins","ci","cd","build","deploy","pipeline","runner",
    "git","gitlab","github","bitbucket","svn","nexus","artifactory",
    "jira","confluence","wiki","docs","documentation","kb","knowledge",
    "support","help","helpdesk","tickets","service","servicedesk",
    "chat","slack","teams","meet","video","webrtc","voip",
    "status","uptime","health","ping","hc",
    "db","database","mysql","postgres","mongo","redis","cache","memcache",
    "rabbitmq","kafka","queue","broker","zookeeper","mq","nats","pulsar",
    "smtp","mail2","email","webmail","owa","autodiscover","exchange",
    "remote","vpn2","openvpn","wireguard","proxy","forward","lb","edge",
    "cdn1","cdn2","cloudfront","akamai","fastly","cloudflare",
    "security","sec","waf","firewall","ids","siem","splunk",
    "vault","secrets","key","pki","cert","hsm",
    "data","analytics","bi","reporting","reports","warehouse","dw","etl",
    "search","elastic","solr","meilisearch","algolia",
    "notify","notification","push","webhook","hooks","events","message",
    "files","file","storage","s3","blob","upload","download","share","drive",
    "ml","ai","model","inference","predict","train","notebook","jupyter",
    "office","hr","crm","erp","sap","dynamics","salesforce",
    "backup","dr","tools","util","utility","tooling",
    "v1","v2","v3","v4","legacy","archive","classic","old-api","new-api",
    "microservice","service","services","svc","worker","cron","jobs","task",
    "partner","partner-api","customer","public-api","private-api",
    "cms","wp","wordpress","drupal","ghost","contentful","strapi",
    "forum","community","social","connect","hub",
    "experimental","labs","research","innovation","sandbox2",
    "preprod","pre-production","integration","int",
    "staging2","test2","dev2","demo2","beta2",
]

# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass
class Result:
    domain:         str
    timestamp:      str
    subdomains:     Set[str]            = field(default_factory=set)
    endpoints:      Set[str]            = field(default_factory=set)
    live_subs:      Set[str]            = field(default_factory=set)
    live_eps:       Set[str]            = field(default_factory=set)
    js_endpoints:   Set[str]            = field(default_factory=set)
    tech_stack:     Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    cors_issues:    List[Dict]          = field(default_factory=list)
    open_methods:   Dict[str, List[str]]= field(default_factory=dict)
    source_counts:  Dict[str, int]      = field(default_factory=dict)
    errors:         List[str]           = field(default_factory=list)

    def add_sub(self, s: str, src: str = "") -> None:
        s = s.strip().lower().rstrip(".")
        if s and self.domain in s and s != self.domain and len(s) < 253:
            if re.match(r'^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$', s):
                self.subdomains.add(s)
                if src:
                    self.source_counts[src] = self.source_counts.get(src, 0) + 1

    def add_ep(self, p: str, src: str = "") -> None:
        p = _norm_path(p)
        if p:
            self.endpoints.add(p)

    def add_url(self, url: str, src: str = "") -> None:
        try:
            pr = urlparse(url.strip())
            if pr.netloc:
                self.add_sub(pr.netloc.lower().split(':')[0], src)
            path = pr.path
            if pr.query:
                path = f"{path}?{pr.query}"
            self.add_ep(path, src)
        except Exception:
            pass

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════
def _norm_domain(raw: str) -> str:
    raw = raw.strip().lower()
    raw = re.sub(r'^https?://', '', raw)
    raw = re.sub(r'^www\.', '', raw)
    return raw.split('/')[0].split('?')[0].split('#')[0].rstrip('.')

def _norm_path(p: str) -> str:
    if not p:
        return ""
    p = p.strip()
    pr = urlparse(p)
    if pr.scheme in ('http', 'https'):
        return p  # keep full URLs as-is
    path = pr.path or p
    if not path.startswith('/'):
        path = '/' + path
    path = re.sub(r'/{2,}', '/', path)
    return path.split('#')[0][:512]

def _ua() -> str:
    return random.choice(UA_POOL)

def _hdrs(extra: Optional[Dict] = None) -> Dict[str, str]:
    h = {
        "User-Agent": _ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "application/json,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    if extra:
        h.update(extra)
    return h

def _subs_from_text(text: str, domain: str) -> Set[str]:
    pat = re.compile(
        r'(?<![.\w])((?:[\w\-]+\.)+' + re.escape(domain) + r')(?![.\w])',
        re.I,
    )
    return {m.group(1).lower().rstrip('.') for m in pat.finditer(text)
            if m.group(1).lower() != domain}

def _urls_from_text(text: str, domain: str) -> Set[str]:
    out: Set[str] = set()
    for m in re.finditer(r'https?://([^\s\'\"<>\)\(,]{3,300})', text, re.I):
        full = "https://" + m.group(1)
        if domain in full.lower():
            out.add(full)
    return out

def _paths_from_text(text: str) -> Set[str]:
    out: Set[str] = set()
    patterns = [
        r'[\'"`](/(?:api|v\d+|graphql|auth|user|admin|health|static|assets|'
        r'media|upload|download|webhook|oauth|internal|private|public|data|'
        r'search|login|logout|register|profile|settings|config|status|metrics|'
        r'docs|swagger|openapi|actuator|manage|console|dashboard|panel|portal|'
        r'rest|service|endpoint|resource)[^\s\'"`<>\\]{0,300})[\'"`]',
        r'fetch\s*\(\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
        r'axios\.\w+\s*\(\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
        r'url\s*[:=]\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.I):
            p = _norm_path(m.group(1))
            if p and len(p) < 400:
                out.add(p)
    return out

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _out_dir(domain: str) -> Path:
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    p = Path(OUTPUT_BASE) / f"{safe}_{ts}"
    p.mkdir(parents=True, exist_ok=True)
    return p

def log(msg: str, lvl: str = "INF") -> None:
    ts = datetime.utcnow().strftime("%H:%M:%S")
    print(f"\033[90m[{ts}]\033[0m [{lvl}] {msg}", flush=True)

# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITER (per-source token bucket)
# ═══════════════════════════════════════════════════════════════════════════════
class RL:
    def __init__(self, rps: float):
        self._delay = 1.0 / rps if rps > 0 else 0
        self._lock  = asyncio.Lock()
        self._last  = 0.0
    async def wait(self) -> None:
        if self._delay == 0:
            return
        async with self._lock:
            now  = time.monotonic()
            wait = self._delay - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
async def _fetch(
    session: "aiohttp.ClientSession",
    url: str,
    *,
    method: str = "GET",
    hdrs: Optional[Dict] = None,
    params: Optional[Dict] = None,
    json_body: Optional[Any] = None,
    retries: int = RETRIES,
    timeout: int = REQ_TIMEOUT,
    as_json: bool = False,
    as_text: bool = True,
    allow_redirects: bool = True,
    proxy: Optional[str] = None,
) -> Optional[Any]:
    h = _hdrs(hdrs)
    to = aiohttp.ClientTimeout(total=timeout)
    for attempt in range(retries):
        try:
            async with session.request(
                method, url, headers=h, params=params, json=json_body,
                timeout=to, allow_redirects=allow_redirects,
                ssl=_ssl_ctx(), proxy=proxy,
            ) as r:
                if r.status == 429:
                    await asyncio.sleep(min(int(r.headers.get("Retry-After", 15)), 60))
                    continue
                if r.status >= 500 and attempt < retries - 1:
                    await asyncio.sleep(BACKOFF ** attempt)
                    continue
                if as_json:
                    try:
                        return await r.json(content_type=None)
                    except Exception:
                        return None
                if as_text:
                    return await r.text(errors='replace')
                return r.status
        except asyncio.TimeoutError:
            if attempt < retries - 1:
                await asyncio.sleep(BACKOFF ** attempt)
        except Exception:
            if attempt < retries - 1:
                await asyncio.sleep(BACKOFF ** attempt)
    return None

async def _jget(s, url, **kw): return await _fetch(s, url, as_json=True, as_text=False, **kw)
async def _tget(s, url, **kw): return await _fetch(s, url, as_text=True,  as_json=False, **kw)

# ═══════════════════════════════════════════════════════════════════════════════
# DNS HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
async def _resolve(host: str) -> Optional[str]:
    if DNSPY:
        try:
            r = dns.asyncresolver.Resolver()
            r.timeout = DNS_TIMEOUT; r.lifetime = DNS_TIMEOUT
            ans = await r.resolve(host, 'A')
            return str(ans[0])
        except Exception:
            return None
    try:
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return info[0][4][0]
    except Exception:
        return None

async def _wildcard(domain: str) -> Optional[str]:
    r1 = ''.join(random.choices(string.ascii_lowercase, k=18))
    r2 = ''.join(random.choices(string.ascii_lowercase, k=18))
    ip1 = await _resolve(f"{r1}.{domain}")
    if not ip1: return None
    ip2 = await _resolve(f"{r2}.{domain}")
    return ip1 if (ip2 and ip1 == ip2) else None

async def batch_resolve(hosts: List[str], wc: Optional[str] = None) -> Dict[str, str]:
    sem = asyncio.Semaphore(MAX_DNS)
    out: Dict[str, str] = {}
    async def _r(h: str):
        async with sem:
            ip = await _resolve(h)
            if ip and ip != wc:
                out[h] = ip
    await asyncio.gather(*[_r(h) for h in hosts], return_exceptions=True)
    return out

# ═══════════════════════════════════════════════════════════════════════════════
# PASSIVE COLLECTOR  (75 sources)
# ═══════════════════════════════════════════════════════════════════════════════
class Passive:
    def __init__(self, s: "aiohttp.ClientSession", r: Result,
                 d: str, k: Dict[str, str], proxy: Optional[str]):
        self.s = s; self.r = r; self.d = d; self.k = k; self.proxy = proxy
        self._sem = asyncio.Semaphore(MAX_HTTP)

    def _p(self, **kw): return dict(proxy=self.proxy, **kw)

    # ── helper: generic text scrape → extract subs + paths ──────────────────
    async def _scrape(self, url: str, src: str, *, params=None, hdrs=None,
                      timeout=14) -> None:
        async with self._sem:
            text = await _tget(self.s, url, params=params, hdrs=hdrs,
                               timeout=timeout, **self._p())
        if not text: return
        for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, src)
        for u in _urls_from_text(text, self.d): self.r.add_url(u, src)

    # ── helper: generic JSON fetch → run parser callback ────────────────────
    async def _jfetch(self, url: str, src: str, cb: Callable,
                      *, params=None, hdrs=None, method="GET",
                      json_body=None, timeout=18) -> None:
        async with self._sem:
            data = await _jget(self.s, url, params=params, hdrs=hdrs,
                               method=method, json_body=json_body,
                               timeout=timeout, **self._p())
        if data is not None:
            try: cb(data, src)
            except Exception: pass

    # ═════════════════════ CERTIFICATE TRANSPARENCY (6) ═════════════════════

    async def crt_sh(self) -> None:
        src = "crtsh"
        for q in [f"%.{self.d}", self.d]:
            def cb(data, s):
                if not isinstance(data, list): return
                for e in data:
                    for f in ("name_value", "common_name"):
                        for n in e.get(f,"").split('\n'):
                            self.r.add_sub(n.strip().lower().lstrip("*."), s)
            await self._jfetch(f"https://crt.sh/", src, cb,
                               params={"q": q, "output": "json"}, timeout=25)

    async def certspotter(self) -> None:
        src = "certspotter"
        def cb(d, s):
            if not isinstance(d, list): return
            for c in d:
                for n in c.get("dns_names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch(
            "https://api.certspotter.com/v1/issuances", src, cb,
            params={"domain": self.d, "include_subdomains": "true",
                    "expand": "dns_names"}, timeout=20)

    async def merklemap(self) -> None:
        src = "merklemap"
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("results", []):
                for f in ("domain", "san"):
                    v = r.get(f, "")
                    if isinstance(v, list):
                        for n in v: self.r.add_sub(str(n).lower().lstrip("*."), s)
                    elif v:
                        self.r.add_sub(str(v).lower().lstrip("*."), s)
        for page in range(3):
            await self._jfetch(
                "https://api.merklemap.com/search", src, cb,
                params={"query": f"*.{self.d}", "page": str(page)})

    async def entrust_ct(self) -> None:
        src = "entrust_ct"
        def cb(d, s):
            if not isinstance(d, list): return
            for c in d:
                for n in c.get("dnsNames", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch(
            "https://ctsearch.entrust.com/api/v1/certificates", src, cb,
            params={"fields": "subjectCN,alternativeName",
                    "domain": self.d, "includeExpired": "true",
                    "exactMatch": "false", "limit": "5000"}, timeout=20)

    async def google_ct(self) -> None:
        src = "google_ct"
        async with self._sem:
            text = await _tget(
                self.s,
                "https://transparencyreport.google.com/transparencyreport/api/v3/"
                "httpsreport/ct/certsearch",
                params={"include_subdomains": "true", "domain": self.d,
                        "p": None},
                timeout=20, **self._p())
        if not text: return
        for sub in _subs_from_text(text, self.d):
            self.r.add_sub(sub, src)

    async def sslmate_spki(self) -> None:
        src = "sslmate"
        def cb(d, s):
            if not isinstance(d, list): return
            for c in d:
                for n in c.get("dns_names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch(
            f"https://api.certspotter.com/v1/issuances", src, cb,
            params={"domain": self.d, "include_subdomains": "true",
                    "match_wildcards": "true", "expand": "dns_names"}, timeout=20)

    # ═════════════════════ ARCHIVE / CRAWL (5) ══════════════════════════════

    async def wayback(self) -> None:
        src = "wayback"
        for q in [f"*.{self.d}/*", f"{self.d}/*"]:
            def cb(d, s):
                if not isinstance(d, list): return
                for row in d[1:]:
                    if row: self.r.add_url(row[0], s)
            await self._jfetch(
                "http://web.archive.org/cdx/search/cdx", src, cb,
                params={"url": q, "output": "json", "fl": "original",
                        "collapse": "urlkey", "limit": "200000"}, timeout=40)

    async def commoncrawl(self) -> None:
        src = "commoncrawl"
        async with self._sem:
            indexes = await _jget(
                self.s, "https://index.commoncrawl.org/collinfo.json",
                timeout=20, **self._p())
        if not isinstance(indexes, list): return
        for ix in [i.get("cdx-api","") for i in indexes[:4] if i.get("cdx-api")]:
            for q in [f"*.{self.d}", self.d]:
                async with self._sem:
                    text = await _tget(
                        self.s, ix,
                        params={"url": f"{q}/*", "output": "json",
                                "fl": "url", "limit": "80000"},
                        timeout=40, **self._p())
                if text:
                    for line in text.splitlines():
                        try:
                            obj = json.loads(line)
                            self.r.add_url(obj.get("url",""), src)
                        except Exception: pass

    async def timetravel(self) -> None:
        src = "timetravel"
        async with self._sem:
            data = await _jget(
                self.s,
                f"http://timetravel.mementoweb.org/timemap/json/"
                f"http://{self.d}/",
                timeout=20, **self._p())
        if isinstance(data, dict):
            for m in data.get("mementos", {}).get("list", []):
                u = m.get("uri", "")
                if u: self.r.add_url(u, src)

    async def archive_special(self) -> None:
        src = "archive_special"
        specials = ["robots.txt","sitemap.xml","sitemap_index.xml",
                    "sitemap.xml.gz","sitemap1.xml","urllist.txt",
                    "crossdomain.xml","clientaccesspolicy.xml",
                    ".well-known/security.txt"]
        for fn in specials:
            url = f"https://{self.d}/{fn}"
            async with self._sem:
                text = await _tget(self.s, url, timeout=10, **self._p())
            if text:
                self.r.add_ep(f"/{fn}", src)
                for line in text.splitlines():
                    line = line.strip()
                    if ":" in line:
                        _, _, val = line.partition(":")
                        val = val.strip()
                        if val.startswith("http"):
                            self.r.add_url(val, src)
                        elif val.startswith("/"):
                            self.r.add_ep(val, src)

    async def cachedview(self) -> None:
        src = "cachedview"
        await self._scrape(
            f"https://archive.ph/{self.d}", src, timeout=12)

    # ═════════════════════ THREAT INTEL (10) ════════════════════════════════

    async def otx(self) -> None:
        src = "otx"
        key_hdr = {"X-OTX-API-KEY": self.k.get("otx","")}
        def cb_dns(d, s):
            if not isinstance(d, dict): return
            for rec in d.get("passive_dns", []):
                h = rec.get("hostname","")
                if h and self.d in h.lower(): self.r.add_sub(h, s)
        def cb_url(d, s):
            if not isinstance(d, dict): return
            for e in d.get("url_list", []):
                self.r.add_url(e.get("url",""), s)
        await self._jfetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/passive_dns",
            src, cb_dns, hdrs=key_hdr)
        await self._jfetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/url_list",
            src, cb_url, hdrs=key_hdr)

    async def urlscan(self) -> None:
        src = "urlscan"
        hdrs = {}
        if self.k.get("urlscan"): hdrs["API-Key"] = self.k["urlscan"]
        for q in [f"domain:{self.d}", f"page.domain:{self.d}"]:
            def cb(d, s):
                if not isinstance(d, dict): return
                for res in d.get("results", []):
                    pg = res.get("page", {})
                    self.r.add_url(pg.get("url",""), s)
                    for key in ("domain","apexDomain"):
                        h = pg.get(key,"")
                        if h and self.d in h.lower(): self.r.add_sub(h, s)
            await self._jfetch(
                "https://urlscan.io/api/v1/search/", src, cb,
                params={"q": q, "size": "10000"}, hdrs=hdrs, timeout=25)

    async def virustotal(self) -> None:
        src = "virustotal"
        vt = self.k.get("virustotal","")
        if vt:
            for ep in [f"https://www.virustotal.com/api/v3/domains/{self.d}/subdomains?limit=40",
                       f"https://www.virustotal.com/api/v3/domains/{self.d}/urls?limit=40"]:
                def cb(d, s):
                    if not isinstance(d, dict): return
                    for item in d.get("data",[]):
                        v = item.get("id","")
                        if self.d in v.lower(): self.r.add_sub(v, s)
                await self._jfetch(ep, src, cb, hdrs={"x-apikey": vt})
        else:
            await self._scrape(
                f"https://www.virustotal.com/gui/domain/{self.d}/relations", src)

    async def threatminer(self) -> None:
        src = "threatminer"
        for rt in ["5","6"]:
            def cb(d, s):
                if not isinstance(d, dict): return
                if d.get("status_code") != "200": return
                for e in d.get("results",[]):
                    if rt == "5": self.r.add_sub(str(e), s)
                    else: self.r.add_url(str(e), s)
            await self._jfetch("https://api.threatminer.org/v2/domain.php",
                               src, cb, params={"q": self.d, "rt": rt})

    async def threatcrowd(self) -> None:
        src = "threatcrowd"
        def cb(d, s):
            if not isinstance(d, dict): return
            for sub in d.get("subdomains",[]): self.r.add_sub(sub, s)
            for e in d.get("emails",[]): pass  # just subs for now
        await self._jfetch(
            "https://www.threatcrowd.org/searchApi/v2/domain/report/",
            src, cb, params={"domain": self.d})

    async def urlhaus(self) -> None:
        src = "urlhaus"
        def cb(d, s):
            if not isinstance(d, dict): return
            for u in d.get("urls",[]):
                self.r.add_url(u.get("url",""), s)
        await self._jfetch("https://urlhaus-api.abuse.ch/v1/host/", src, cb,
                           method="POST", json_body={"host": self.d})

    async def pulsedive(self) -> None:
        src = "pulsedive"
        pd_key = self.k.get("pulsedive","")
        params = {"q": self.d, "pretty": "1"}
        if pd_key: params["key"] = pd_key
        await self._scrape("https://pulsedive.com/api/explore.php", src,
                           params=params)

    async def hybridanalysis(self) -> None:
        src = "hybridanalysis"
        ha_key = self.k.get("ha","")
        if not ha_key: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("result", []):
                self.r.add_sub(item.get("domain",""), s)
        await self._jfetch(
            "https://www.hybrid-analysis.com/api/v2/search/terms",
            src, cb, method="POST",
            hdrs={"api-key": ha_key, "user-agent": "Falcon"},
            json_body={"domain": self.d, "count": 100})

    async def greynoise(self) -> None:
        src = "greynoise"
        gk = self.k.get("greynoise","")
        h = {"key": gk} if gk else {}
        await self._scrape(
            f"https://api.greynoise.io/v3/community/{self.d}", src, hdrs=h)

    async def circl_pdns(self) -> None:
        src = "circl_pdns"
        def cb(d, s):
            if not isinstance(d, dict): return
            for e in d.get("rdata",[]):
                if self.d in str(e).lower(): self.r.add_sub(str(e), s)
        await self._jfetch(
            f"https://www.circl.lu/pdns/query/{self.d}", src, cb,
            hdrs={"Accept": "application/json"})

    # ═════════════════════ DNS INTELLIGENCE (12) ════════════════════════════

    async def bufferover(self) -> None:
        src = "bufferover"
        for url in [f"https://dns.bufferover.run/dns?q=.{self.d}",
                    f"https://tls.bufferover.run/dns?q=.{self.d}"]:
            def cb(d, s):
                if not isinstance(d, dict): return
                for key in ("FDNS_A","RDNS","Results"):
                    for e in d.get(key,[]):
                        for part in str(e).split(","):
                            part = part.strip()
                            if self.d in part.lower():
                                self.r.add_sub(part.lower().rstrip('.'), s)
            await self._jfetch(url, src, cb)

    async def hackertarget(self) -> None:
        src = "hackertarget"
        async with self._sem:
            text = await _tget(
                self.s,
                f"https://api.hackertarget.com/hostsearch/?q={self.d}",
                timeout=15, **self._p())
        if text and "error" not in text.lower():
            for line in text.splitlines():
                parts = line.split(",")
                if parts:
                    h = parts[0].strip().lower()
                    if h and self.d in h: self.r.add_sub(h, src)

    async def anubis(self) -> None:
        src = "anubis"
        def cb(d, s):
            if isinstance(d, list):
                for sub in d: self.r.add_sub(str(sub), s)
        await self._jfetch(f"https://jldc.me/anubis/subdomains/{self.d}", src, cb)

    async def rapiddns(self) -> None:
        src = "rapiddns"
        await self._scrape(
            f"https://rapiddns.io/subdomain/{self.d}?full=1#result", src)

    async def riddler(self) -> None:
        src = "riddler"
        await self._scrape(
            f"https://riddler.io/search/exportcsv?q=pld:{self.d}", src)

    async def sonarsearch(self) -> None:
        src = "sonarsearch"
        for url in [f"https://sonar.omnisint.io/subdomains/{self.d}",
                    f"https://omnisint.io/subdomains/{self.d}"]:
            def cb(d, s):
                if isinstance(d, list):
                    for sub in d: self.r.add_sub(str(sub), s)
                    return True  # stop trying alternatives
            async with self._sem:
                data = await _jget(self.s, url, timeout=15, **self._p())
            if isinstance(data, list):
                for sub in data: self.r.add_sub(str(sub), src)
                break

    async def robtex(self) -> None:
        src = "robtex"
        def cb(d, s):
            if not isinstance(d, dict): return
            for entry in d.get("pas",[]) + d.get("pash",[]):
                h = entry.get("o","")
                if h and self.d in h.lower(): self.r.add_sub(h, s)
        await self._jfetch(
            f"https://freeapi.robtex.com/pdns/forward/{self.d}", src, cb)

    async def viewdns(self) -> None:
        src = "viewdns"
        await self._scrape(
            f"https://viewdns.info/dnsrecord/?domain={self.d}", src)

    async def dnsgrep(self) -> None:
        src = "dnsgrep"
        await self._scrape(
            f"https://www.dnsgrep.nl/subdomains/{self.d}?limit=5000", src)

    async def shrewdeye(self) -> None:
        src = "shrewdeye"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    if isinstance(item, dict):
                        h = item.get("domain","") or item.get("host","")
                        if h: self.r.add_sub(h.lower(), s)
                    elif isinstance(item, str):
                        self.r.add_sub(item.lower(), s)
        await self._jfetch(
            f"https://shrewdeye.app/domains/{self.d}.json", src, cb)

    async def columbus(self) -> None:
        src = "columbus"
        def cb(d, s):
            if isinstance(d, list):
                for sub in d:
                    full = f"{sub}.{self.d}" if not self.d in str(sub) else str(sub)
                    self.r.add_sub(full.lower(), s)
        await self._jfetch(
            f"https://columbus.elmasy.com/api/lookup/{self.d}", src, cb)

    async def dnsdumpster(self) -> None:
        src = "dnsdumpster"
        # DNSDumpster requires a CSRF token — scrape the page first
        async with self._sem:
            html = await _tget(self.s, "https://dnsdumpster.com/", timeout=12,
                               **self._p())
        if not html: return
        csrf = re.search(r'name=[\'"]csrfmiddlewaretoken[\'"] value=[\'"]([^\'"]+)[\'"]', html)
        if not csrf: return
        token = csrf.group(1)
        async with self._sem:
            result = await _tget(
                self.s, "https://dnsdumpster.com/",
                hdrs={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "https://dnsdumpster.com/",
                },
                timeout=20, **self._p())
        # Even if POST form doesn't work, extract from GET page
        if html:
            for sub in _subs_from_text(html, self.d):
                self.r.add_sub(sub, src)

    # ═════════════════════ AGGREGATOR APIs (10) ═════════════════════════════

    async def shodan(self) -> None:
        src = "shodan"
        sk = self.k.get("shodan","")
        if sk:
            def cb(d, s):
                if not isinstance(d, dict): return
                for sub in d.get("subdomains",[]): self.r.add_sub(f"{sub}.{self.d}", s)
            await self._jfetch(
                f"https://api.shodan.io/dns/domain/{self.d}",
                src, cb, params={"key": sk})
        else:
            await self._scrape(f"https://www.shodan.io/domain/{self.d}", src)

    async def censys(self) -> None:
        src = "censys"
        ci = self.k.get("censys_id",""); cs = self.k.get("censys_secret","")
        if not (ci and cs): return
        creds = base64.b64encode(f"{ci}:{cs}".encode()).decode()
        def cb(d, s):
            if not isinstance(d, dict): return
            for h in d.get("result",{}).get("hits",[]):
                for n in h.get("parsed.names",[]):
                    if self.d in n.lower(): self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch(
            "https://search.censys.io/api/v2/certificates/search", src, cb,
            hdrs={"Authorization": f"Basic {creds}"},
            json_body={"q": f"parsed.names: {self.d}", "per_page": 100,
                       "fields": ["parsed.names"]},
            method="POST")

    async def leakix(self) -> None:
        src = "leakix"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("Subdomains",[]):
                self.r.add_sub(item.get("subdomain",""), s)
        await self._jfetch(
            f"https://leakix.net/domain/{self.d}", src, cb,
            hdrs={"Accept": "application/json"})

    async def securitytrails(self) -> None:
        src = "securitytrails"
        stk = self.k.get("securitytrails","")
        if stk:
            def cb(d, s):
                if not isinstance(d, dict): return
                for sub in d.get("subdomains",[]): self.r.add_sub(f"{sub}.{self.d}", s)
            await self._jfetch(
                f"https://api.securitytrails.com/v1/domain/{self.d}/subdomains",
                src, cb, hdrs={"APIKEY": stk})
        else:
            await self._scrape(
                f"https://securitytrails.com/domain/{self.d}/subdomains", src)

    async def chaos(self) -> None:
        src = "chaos"
        ck = self.k.get("chaos","")
        if not ck: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for sub in d.get("subdomains",[]): self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch(
            f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains",
            src, cb, hdrs={"Authorization": ck})

    async def passivetotal(self) -> None:
        src = "passivetotal"
        pu = self.k.get("pt_user",""); pk = self.k.get("pt_key","")
        if not (pu and pk): return
        creds = base64.b64encode(f"{pu}:{pk}".encode()).decode()
        def cb(d, s):
            if not isinstance(d, dict): return
            for sub in d.get("subdomains",[]): self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch(
            "https://api.riskiq.net/pt/v2/enrichment/subdomains",
            src, cb, hdrs={"Authorization": f"Basic {creds}"},
            params={"query": self.d})

    async def netlas(self) -> None:
        src = "netlas"
        nk = self.k.get("netlas","")
        if not nk:
            await self._scrape(f"https://app.netlas.io/responses/?q=domain%3A*.{self.d}", src)
            return
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("items",[]):
                h = item.get("data",{}).get("domain","")
                if h: self.r.add_sub(h, s)
        await self._jfetch(
            "https://app.netlas.io/api/domains/",
            src, cb, params={"q": f"domain:*.{self.d}", "source_type": "include",
                             "start": "0", "fields": "domain"},
            hdrs={"X-API-Key": nk})

    async def zoomeye(self) -> None:
        src = "zoomeye"
        zk = self.k.get("zoomeye","")
        if not zk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("list",[]): self.r.add_sub(item.get("name",""), s)
        await self._jfetch(
            "https://api.zoomeye.org/domain/search", src, cb,
            params={"q": f"site:{self.d}", "type": "1"},
            hdrs={"API-KEY": zk})

    async def binaryedge(self) -> None:
        src = "binaryedge"
        bk = self.k.get("binaryedge","")
        if not bk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for sub in d.get("events",[]): self.r.add_sub(str(sub), s)
        await self._jfetch(
            f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.d}",
            src, cb, hdrs={"X-Key": bk})

    async def fullhunt(self) -> None:
        src = "fullhunt"
        fk = self.k.get("fullhunt","")
        h = {"X-API-KEY": fk} if fk else {}
        def cb(d, s):
            if not isinstance(d, dict): return
            for host in d.get("hosts",[]): self.r.add_sub(str(host), s)
        await self._jfetch(
            f"https://fullhunt.io/api/v1/domain/{self.d}/subdomains",
            src, cb, hdrs=h)

    # ═════════════════════ WHOIS / IP / ASN (5) ═════════════════════════════

    async def whoisxml(self) -> None:
        src = "whoisxml"
        wk = self.k.get("whoisxml","")
        if not wk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for rec in d.get("result",{}).get("records",[]):
                sub = rec.get("domain","")
                if sub and self.d in sub.lower(): self.r.add_sub(sub, s)
        await self._jfetch(
            "https://subdomains.whoisxmlapi.com/api/v1",
            src, cb, params={"apiKey": wk, "domainName": self.d,
                             "outputFormat": "JSON"})

    async def bgpview(self) -> None:
        src = "bgpview"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("data",{}).get("ipv4_prefixes",[]):
                # Get ASN, use it to look up more hosts
                pass
            for item in d.get("data",{}).get("domains",[]):
                if self.d in str(item).lower(): self.r.add_sub(str(item), s)
        await self._jfetch(
            f"https://api.bgpview.io/search", src, cb,
            params={"query_term": self.d})

    async def ipinfo(self) -> None:
        src = "ipinfo"
        ik = self.k.get("ipinfo","")
        # Resolve IP first, then look up
        ip = await _resolve(self.d)
        if not ip: return
        h = {"Authorization": f"Bearer {ik}"} if ik else {}
        await self._scrape(f"https://ipinfo.io/{ip}", src, hdrs=h)

    async def onyphe(self) -> None:
        src = "onyphe"
        ok = self.k.get("onyphe","")
        h = {"Authorization": f"apikey {ok}"} if ok else {}
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("results",[]):
                h2 = r.get("hostname","")
                if h2 and self.d in h2.lower(): self.r.add_sub(h2, s)
        await self._jfetch(
            f"https://www.onyphe.io/api/v2/simple/datascan/{self.d}",
            src, cb, hdrs=h)

    async def dnshistory(self) -> None:
        src = "dnshistory"
        await self._scrape(f"https://dnshistory.org/subdomains/{self.d}", src)

    # ═════════════════════ SEARCH ENGINES (8) ═══════════════════════════════

    async def duckduckgo(self) -> None:
        src = "duckduckgo"
        rl = RL(rps=0.25)
        for dork in [f"site:{self.d}", f"site:*.{self.d}",
                     f"site:{self.d} inurl:api",
                     f"site:{self.d} inurl:admin",
                     f"site:{self.d} filetype:json",
                     f"site:{self.d} inurl:dev"]:
            await rl.wait()
            data = await _jget(
                self.s, "https://api.duckduckgo.com/",
                params={"q": dork, "format": "json", "no_html": "1",
                        "kl": "us-en"},
                timeout=12, **self._p())
            if isinstance(data, dict):
                for item in data.get("Results",[]) + data.get("RelatedTopics",[]):
                    u = item.get("FirstURL","") or item.get("Result","")
                    if u and self.d in u: self.r.add_url(u, src)

    async def bing(self) -> None:
        src = "bing"
        bk = self.k.get("bing","")
        rl = RL(rps=0.25)
        dorks = [f"site:{self.d}", f"site:*.{self.d}",
                 f"site:{self.d} filetype:json",
                 f"site:{self.d} inurl:api"]
        for dork in dorks:
            await rl.wait()
            if bk:
                def cb(d, s):
                    if not isinstance(d, dict): return
                    for item in d.get("webPages",{}).get("value",[]):
                        self.r.add_url(item.get("url",""), s)
                await self._jfetch(
                    "https://api.bing.microsoft.com/v7.0/search",
                    src, cb,
                    hdrs={"Ocp-Apim-Subscription-Key": bk},
                    params={"q": dork, "count": "50"})
            else:
                await self._scrape(
                    "https://www.bing.com/search",
                    src, params={"q": dork, "count": "50"})

    async def yahoo(self) -> None:
        src = "yahoo"
        rl = RL(rps=0.2)
        for dork in [f"site:{self.d}", f"site:*.{self.d}",
                     f"site:{self.d} inurl:api"]:
            await rl.wait()
            await self._scrape("https://search.yahoo.com/search",
                               src, params={"p": dork, "n": "100"})

    async def yandex(self) -> None:
        src = "yandex"
        rl = RL(rps=0.15)
        for dork in [f"site:{self.d}", f"site:*.{self.d}"]:
            await rl.wait()
            await self._scrape(
                "https://yandex.com/search/",
                src, params={"text": dork, "numdoc": "100"})

    async def mojeek(self) -> None:
        src = "mojeek"
        rl = RL(rps=0.25)
        for dork in [f"site:{self.d}", f"site:*.{self.d}"]:
            await rl.wait()
            await self._scrape("https://www.mojeek.com/search",
                               src, params={"q": dork})

    async def baidu(self) -> None:
        src = "baidu"
        rl = RL(rps=0.2)
        for dork in [f"site:{self.d}", f"inurl:{self.d}"]:
            await rl.wait()
            await self._scrape("https://www.baidu.com/s",
                               src, params={"wd": dork, "rn": "100"})

    async def startpage(self) -> None:
        src = "startpage"
        rl = RL(rps=0.2)
        await rl.wait()
        await self._scrape(
            "https://www.startpage.com/search",
            src, params={"q": f"site:{self.d}", "language": "english"})

    async def exalead(self) -> None:
        src = "exalead"
        rl = RL(rps=0.2)
        await rl.wait()
        await self._scrape(
            "https://www.exalead.com/search/web/results/",
            src, params={"q": f"site:{self.d}", "elements_per_page": "100"})

    # ═════════════════════ DEVELOPER / SOCIAL (7) ═══════════════════════════

    async def github(self) -> None:
        src = "github"
        gk = self.k.get("github","")
        h: Dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
        if gk: h["Authorization"] = f"token {gk}"
        rl = RL(rps=0.4 if gk else 0.15)
        queries = [self.d, f'"{self.d}" api', f'"{self.d}" endpoint',
                   f'"{self.d}" subdomain', f'"{self.d}" staging',
                   f'"{self.d}" internal', f'"{self.d}" config']
        for q in queries:
            await rl.wait()
            data = await _jget(
                self.s, "https://api.github.com/search/code",
                hdrs=h, params={"q": q, "per_page": "50"},
                timeout=20, **self._p())
            if not isinstance(data, dict): continue
            for item in data.get("items", []):
                file_url = item.get("url","")
                if not file_url: continue
                await rl.wait()
                file_data = await _jget(self.s, file_url, hdrs=h,
                                        timeout=15, **self._p())
                if isinstance(file_data, dict):
                    try:
                        content = base64.b64decode(
                            file_data.get("content","")).decode("utf-8", errors="replace")
                        for sub in _subs_from_text(content, self.d):
                            self.r.add_sub(sub, src)
                        for path in _paths_from_text(content):
                            self.r.add_ep(path, src)
                    except Exception: pass

    async def gitlab_search(self) -> None:
        src = "gitlab"
        gk = self.k.get("gitlab","")
        h = {"PRIVATE-TOKEN": gk} if gk else {}
        rl = RL(rps=0.2)
        await rl.wait()
        def cb(d, s):
            if not isinstance(d, list): return
            for item in d:
                content = item.get("data","")
                for sub in _subs_from_text(content, self.d): self.r.add_sub(sub, s)
                for p in _paths_from_text(content): self.r.add_ep(p, s)
        await self._jfetch(
            "https://gitlab.com/api/v4/search", src, cb,
            params={"scope": "blobs", "search": self.d}, hdrs=h)

    async def reddit(self) -> None:
        src = "reddit"
        rl = RL(rps=0.4)
        for q in [self.d, f"site:{self.d}", f"{self.d} api", f"{self.d} endpoint"]:
            await rl.wait()
            data = await _jget(
                self.s, "https://www.reddit.com/search.json",
                params={"q": q, "limit": "100", "type": "link,comment"},
                hdrs={"User-Agent": "ReaperRecon/2.0"},
                timeout=15, **self._p())
            if isinstance(data, dict):
                for child in data.get("data",{}).get("children",[]):
                    post = child.get("data",{})
                    for field in ("url","selftext","title"):
                        val = post.get(field,"")
                        if val and self.d in val:
                            for sub in _subs_from_text(val, self.d): self.r.add_sub(sub, src)
                            for u in _urls_from_text(val, self.d): self.r.add_url(u, src)

    async def pastebin(self) -> None:
        src = "pastebin"
        for url in [f"https://psbdmp.ws/api/v3/search/{self.d}",
                    f"https://psbdmp.ws/api/v3/search/domain/{self.d}"]:
            data = await _jget(self.s, url, timeout=12, **self._p())
            if isinstance(data, dict):
                text = json.dumps(data)
                for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, src)
                for u in _urls_from_text(text, self.d): self.r.add_url(u, src)

    async def stackoverflow(self) -> None:
        src = "stackoverflow"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("items",[]):
                for field in ("title","body"):
                    v = item.get(field,"")
                    if v and self.d in v:
                        for sub in _subs_from_text(v, self.d): self.r.add_sub(sub, s)
        await self._jfetch(
            "https://api.stackexchange.com/2.3/search/advanced",
            src, cb, params={"q": self.d, "site": "stackoverflow",
                             "filter": "withbody", "pagesize": "50"})

    async def bitbucket(self) -> None:
        src = "bitbucket"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("values",[]):
                content = item.get("content",{}).get("raw","")
                if self.d in content:
                    for sub in _subs_from_text(content, self.d): self.r.add_sub(sub, s)
        await self._jfetch(
            "https://api.bitbucket.org/2.0/search/code",
            src, cb, params={"q": self.d})

    # ═════════════════════ SPECIALIZED (8) ══════════════════════════════════

    async def recondev(self) -> None:
        src = "recondev"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    if isinstance(item, dict):
                        self.r.add_sub(item.get("domain",""), s)
                    elif isinstance(item, str):
                        self.r.add_sub(item, s)
        await self._jfetch(
            f"https://recon.dev/api/search",
            src, cb, params={"key": "", "domain": self.d})

    async def c99(self) -> None:
        src = "c99"
        ck = self.k.get("c99","")
        if ck:
            def cb(d, s):
                if not isinstance(d, dict): return
                for sub in d.get("subdomains",[]): self.r.add_sub(str(sub), s)
            await self._jfetch(
                "https://api.c99.nl/subdomainfinder",
                src, cb, params={"key": ck, "domain": self.d,
                                 "json": "true"})
        else:
            await self._scrape(
                f"https://subdomainfinder.c99.nl/scans/{self.d}", src)

    async def sitedossier(self) -> None:
        src = "sitedossier"
        await self._scrape(f"http://www.sitedossier.com/site/{self.d}", src)

    async def spyonweb(self) -> None:
        src = "spyonweb"
        sk = self.k.get("spyonweb","")
        if sk:
            def cb(d, s):
                if not isinstance(d, dict): return
                for item in d.get("results",{}).get("items",[]):
                    self.r.add_sub(item.get("domain",""), s)
            await self._jfetch(
                f"https://api.spyonweb.com/v1/domain/{self.d}",
                src, cb, params={"access_token": sk})
        else:
            await self._scrape(f"https://spyonweb.com/{self.d}", src)

    async def publicwww(self) -> None:
        src = "publicwww"
        await self._scrape(
            f"https://publicwww.com/websites/%22{self.d}%22/", src)

    async def intelligencex(self) -> None:
        src = "intelx"
        ik = self.k.get("intelx","")
        if not ik: return
        init = await _jget(
            self.s, "https://2.intelx.io/intelligent/search",
            hdrs={"x-key": ik, "Content-Type": "application/json"},
            **self._p())
        # Use the POST method properly
        async with self._sem:
            init = await _fetch(
                self.s, "https://2.intelx.io/intelligent/search",
                method="POST",
                hdrs={"x-key": ik},
                json_body={"term": self.d, "maxresults": 1000,
                           "media": 0, "lookuplevel": 0, "sort": 2},
                as_json=True, as_text=False, timeout=15, **self._p())
        if not isinstance(init, dict) or "id" not in init: return
        sid = init["id"]
        await asyncio.sleep(3)
        results = await _jget(
            self.s, "https://2.intelx.io/intelligent/search/result",
            hdrs={"x-key": ik},
            params={"id": sid, "limit": "1000"},
            timeout=20, **self._p())
        if isinstance(results, dict):
            text = json.dumps(results)
            for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, src)

    async def fofa(self) -> None:
        src = "fofa"
        fe = self.k.get("fofa_email",""); fk = self.k.get("fofa_key","")
        if not (fe and fk): return
        query = base64.b64encode(f'domain="{self.d}"'.encode()).decode()
        def cb(d, s):
            if not isinstance(d, dict) or d.get("error"): return
            for row in d.get("results",[]):
                for val in row:
                    if isinstance(val, str) and self.d in val.lower():
                        self.r.add_sub(val.lower(), s)
        await self._jfetch(
            "https://fofa.info/api/v1/search/all", src, cb,
            params={"email": fe, "key": fk, "qbase64": query,
                    "fields": "host,domain", "page": "1", "size": "10000"})

    async def hunterio(self) -> None:
        src = "hunter"
        hk = self.k.get("hunter","")
        if not hk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            data = d.get("data",{})
            for email in data.get("emails",[]):
                domain = email.get("domain","")
                if domain: self.r.add_sub(domain, s)
        await self._jfetch(
            "https://api.hunter.io/v2/domain-search", src, cb,
            params={"domain": self.d, "api_key": hk, "limit": "100"})

    # ═════════════════════ CLOUD / INFRA (5) ════════════════════════════════

    async def cloudflare_radar(self) -> None:
        src = "cf_radar"
        cfk = self.k.get("cloudflare","")
        h = {"Authorization": f"Bearer {cfk}"} if cfk else {}
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("result",{}).get("searchResults",[]):
                name = item.get("name","") or item.get("domain","")
                if name and self.d in name.lower(): self.r.add_sub(name, s)
        await self._jfetch(
            f"https://radar.cloudflare.com/api/v0/search",
            src, cb, params={"query": self.d, "limit": "100"}, hdrs=h)

    async def github_pages(self) -> None:
        src = "github_pages"
        # Check for <org>.github.io and <project>.github.io patterns
        org = self.d.split('.')[0]
        for pattern in [f"{org}.github.io", f"{self.d.replace('.','')}.github.io"]:
            ip = await _resolve(pattern)
            if ip:
                self.r.add_sub(pattern, src)

    async def cloud_buckets(self) -> None:
        src = "cloud_buckets"
        # Common cloud storage bucket naming patterns
        org = self.d.split('.')[0]
        tld = self.d.split('.')[0]
        candidates = [
            f"{org}.s3.amazonaws.com", f"{org}-assets.s3.amazonaws.com",
            f"{org}-static.s3.amazonaws.com", f"{org}-media.s3.amazonaws.com",
            f"{org}-backup.s3.amazonaws.com", f"{org}-uploads.s3.amazonaws.com",
            f"{org}-data.s3.amazonaws.com", f"{tld}.s3.amazonaws.com",
            f"{org}.storage.googleapis.com",
            f"{org}.blob.core.windows.net",
            f"{org}-cdn.azureedge.net",
            f"{org}.digitaloceanspaces.com",
        ]
        for bucket in candidates:
            ip = await _resolve(bucket)
            if ip:
                self.r.add_sub(bucket, src)

    async def firebase(self) -> None:
        src = "firebase"
        org = self.d.split('.')[0]
        for pattern in [f"{org}.firebaseapp.com", f"{org}.web.app",
                        f"{org}-default-rtdb.firebaseio.com"]:
            ip = await _resolve(pattern)
            if ip:
                self.r.add_sub(pattern, src)

    async def azure_websites(self) -> None:
        src = "azure"
        org = self.d.split('.')[0]
        for pattern in [f"{org}.azurewebsites.net",
                        f"{org}.azurefd.net",
                        f"{org}-staging.azurewebsites.net",
                        f"{org}-dev.azurewebsites.net"]:
            ip = await _resolve(pattern)
            if ip:
                self.r.add_sub(pattern, src)

    # ═════════════════════ ADDITIONAL SPECIALIZED (6) ═══════════════════════

    async def dnsbufferover_tls(self) -> None:
        # Alternate TLS certificate source via bufferover TLS endpoint
        src = "bufferover_tls"
        def cb(d, s):
            if not isinstance(d, dict): return
            for key in ("FDNS_A","RDNS","Results"):
                for e in d.get(key,[]):
                    for part in str(e).split(","):
                        p = part.strip().lower().rstrip('.')
                        if self.d in p: self.r.add_sub(p, s)
        await self._jfetch(f"https://tls.bufferover.run/dns?q=.{self.d}", src, cb)

    async def certsh_org(self) -> None:
        src = "crtsh_org"
        # Additional crt.sh query for organization field
        await self._scrape(
            f"https://crt.sh/?O={urllib.parse.quote(self.d)}&output=json", src)

    async def whoisxml_history(self) -> None:
        src = "whoisxml_hist"
        wk = self.k.get("whoisxml","")
        if not wk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for rec in d.get("result",{}).get("records",[]):
                sub = rec.get("domain","")
                if sub: self.r.add_sub(sub, s)
        await self._jfetch(
            "https://dns-history.whoisxmlapi.com/api/v1",
            src, cb, params={"apiKey": wk, "domainName": self.d,
                             "outputFormat": "JSON"})

    async def dnslookup_org(self) -> None:
        src = "dnslookup"
        await self._scrape(
            f"https://dnslookup.org/{self.d}/dns/", src)

    async def webarchive_subpages(self) -> None:
        src = "webarchive_sp"
        # Query wayback for specific sensitive file extensions
        exts = ["json","xml","env","config","bak","sql","yaml","yml",
                "wsdl","map","js","pdf","zip"]
        for ext in exts[:6]:  # limit to keep it fast
            data = await _jget(
                self.s,
                "http://web.archive.org/cdx/search/cdx",
                params={"url": f"{self.d}/*.{ext}", "output": "json",
                        "fl": "original", "collapse": "urlkey",
                        "limit": "5000"},
                timeout=25, **self._p())
            if isinstance(data, list):
                for row in data[1:]:
                    if row: self.r.add_url(row[0], src)

    async def ibm_xforce(self) -> None:
        src = "xforce"
        xk = self.k.get("xforce_key",""); xs = self.k.get("xforce_pass","")
        if not (xk and xs): return
        creds = base64.b64encode(f"{xk}:{xs}".encode()).decode()
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("dns",{}).get("passive",{}).get("records",[]):
                val = item.get("value","")
                if self.d in val.lower(): self.r.add_sub(val, s)
        await self._jfetch(
            f"https://api.xforce.ibmcloud.com/resolve/{self.d}",
            src, cb, hdrs={"Authorization": f"Basic {creds}",
                           "Accept": "application/json"})

    # ═════════════════════════════════════════════════════════════════════════
    async def run_all(self, passive_only: bool = False) -> None:
        tasks = [
            # CT (6)
            self.crt_sh(), self.certspotter(), self.merklemap(),
            self.entrust_ct(), self.google_ct(), self.sslmate_spki(),
            # Archive (5)
            self.wayback(), self.commoncrawl(), self.timetravel(),
            self.archive_special(), self.cachedview(),
            # Threat Intel (10)
            self.otx(), self.urlscan(), self.virustotal(),
            self.threatminer(), self.threatcrowd(), self.urlhaus(),
            self.pulsedive(), self.hybridanalysis(), self.greynoise(),
            self.circl_pdns(),
            # DNS Intel (12)
            self.bufferover(), self.hackertarget(), self.anubis(),
            self.rapiddns(), self.riddler(), self.sonarsearch(),
            self.robtex(), self.viewdns(), self.dnsgrep(),
            self.shrewdeye(), self.columbus(), self.dnsdumpster(),
            # Aggregators (10)
            self.shodan(), self.censys(), self.leakix(),
            self.securitytrails(), self.chaos(), self.passivetotal(),
            self.netlas(), self.zoomeye(), self.binaryedge(), self.fullhunt(),
            # WHOIS/IP (5)
            self.whoisxml(), self.bgpview(), self.ipinfo(),
            self.onyphe(), self.dnshistory(),
            # Search Engines (8)
            self.duckduckgo(), self.bing(), self.yahoo(),
            self.yandex(), self.mojeek(), self.baidu(),
            self.startpage(), self.exalead(),
            # Dev/Social (7)
            self.github(), self.gitlab_search(), self.reddit(),
            self.pastebin(), self.stackoverflow(), self.bitbucket(),
            self.hunterio(),
            # Specialized (8)
            self.recondev(), self.c99(), self.sitedossier(),
            self.spyonweb(), self.publicwww(), self.intelligencex(),
            self.fofa(), self.ibm_xforce(),
            # Cloud (5)
            self.cloudflare_radar(), self.github_pages(), self.cloud_buckets(),
            self.firebase(), self.azure_websites(),
            # Additional (6)
            self.dnsbufferover_tls(), self.certsh_org(),
            self.whoisxml_history(), self.dnslookup_org(),
            self.webarchive_subpages(), self.webarchive_subpages(),
        ]
        # Deduplicate coroutines that might be duplicated
        unique_tasks = []
        seen_names = set()
        for t in tasks:
            name = getattr(t, '__qualname__', id(t))
            if name not in seen_names:
                seen_names.add(name)
                unique_tasks.append(t)

        log(f"Running {len(unique_tasks)} passive sources concurrently")
        await asyncio.gather(*unique_tasks, return_exceptions=True)

# ═══════════════════════════════════════════════════════════════════════════════
# JAVASCRIPT ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
class JSEngine:
    def __init__(self, s, r: Result, d: str, proxy: Optional[str]):
        self.s = s; self.r = r; self.d = d; self.proxy = proxy
        self._seen: Set[str] = set()
        self._sem  = asyncio.Semaphore(MAX_JS)

    async def crawl(self, base_url: str) -> None:
        async with self._sem:
            text = await _tget(self.s, base_url, timeout=15, proxy=self.proxy)
        if not text: return
        await self._parse_html(text, base_url)

    async def _parse_html(self, html: str, base_url: str) -> None:
        # Extract JS URLs
        js_urls: Set[str] = set()
        if BS4:
            soup = BeautifulSoup(html, 'lxml')
            for tag in soup.find_all('script', src=True):
                js_urls.add(urljoin(base_url, tag['src']))
            # Also grab link[rel=preload] for scripts
            for tag in soup.find_all('link', rel=True):
                if 'preload' in tag.get('rel', []) and tag.get('as') == 'script':
                    href = tag.get('href', '')
                    if href: js_urls.add(urljoin(base_url, href))
        else:
            for m in re.finditer(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', html, re.I):
                js_urls.add(urljoin(base_url, m.group(1)))

        # Parse inline JS
        await self._parse_js(html, base_url)

        # Parse each external JS
        tasks = [self._fetch_and_parse(u) for u in list(js_urls)[:150]]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fetch_and_parse(self, url: str) -> None:
        if url in self._seen or len(self._seen) > 600: return
        self._seen.add(url)
        async with self._sem:
            text = await _tget(self.s, url, timeout=20, proxy=self.proxy)
        if not text or len(text) > MAX_JS_BYTES: return
        await self._parse_js(text, url)

    async def _parse_js(self, text: str, base_url: str) -> None:
        src = "js_engine"

        # 1. Standard path extraction
        for p in _paths_from_text(text): self.r.add_ep(p, src)

        # 2. Subdomain extraction
        for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, src)

        # 3. API base URL patterns
        for m in re.finditer(
            r'(?:API_URL|BASE_URL|API_BASE|REACT_APP_API|VITE_API|VUE_APP_API|'
            r'NEXT_PUBLIC_API|apiBase|baseURL|baseUrl|api_url|endpoint|'
            r'serviceUrl|backendUrl)\s*[=:]\s*[\'"`](https?://[^\'"` ]{5,300})[\'"`]',
            text, re.I,
        ):
            u = m.group(1)
            self.r.add_url(u, "js_config")

        # 4. fetch / axios / XMLHttpRequest calls
        for m in re.finditer(
            r'(?:fetch|axios\.(?:get|post|put|delete|patch|request)|'
            r'\$\.(?:ajax|get|post|put|delete)|'
            r'(?:http|request)\.(?:get|post|put|delete|patch))\s*\(\s*'
            r'(?:[\'"`]([^\'"`\s]{1,400})[\'"`]|'
            r'\`([^`]{1,400})\`)',
            text, re.I,
        ):
            raw = m.group(1) or m.group(2) or ""
            raw = re.sub(r'\$\{[^}]+\}', '{id}', raw)
            if raw.startswith('http'):
                self.r.add_url(raw, "js_fetch")
            elif raw.startswith('/'):
                self.r.add_ep(raw, "js_fetch")

        # 5. Express/Koa/FastAPI route definitions
        for m in re.finditer(
            r'(?:router|app|server)\s*\.\s*(?:get|post|put|delete|patch|use|all)\s*'
            r'\(\s*[\'"`]([^\'"` ]{1,300})[\'"`]',
            text, re.I,
        ):
            self.r.add_ep(m.group(1), "js_route")

        # 6. Source map references → fetch the map
        for m in re.finditer(r'//[#@]\s*sourceMappingURL\s*=\s*(.+?)(?:\s|$)', text, re.I):
            ref = m.group(1).strip()
            if not ref.startswith("data:"):
                await self._fetch_sourcemap(urljoin(base_url, ref))

        # 7. Webpack chunk references
        for m in re.finditer(r'(?:chunk|bundle|vendor|app|main|index)(?:\.\w+)?\.js', text, re.I):
            chunk_name = m.group(0)
            base_dir = base_url.rsplit('/', 1)[0]
            for chunk_url in [
                f"{base_dir}/{chunk_name}",
                f"{base_dir}/static/js/{chunk_name}",
                f"{base_dir}/assets/{chunk_name}",
                f"{base_dir}/js/{chunk_name}",
            ]:
                await self._fetch_and_parse(chunk_url)

        # 8. Dynamic imports
        for m in re.finditer(
            r'(?:import\s*\(|require\s*\()\s*[\'"`]([^\'"`\s]{1,300})[\'"`]',
            text, re.I,
        ):
            ref = m.group(1)
            if ref.startswith(('.', '/')):
                resolved = urljoin(base_url, ref)
                if resolved.endswith(('.js', '.mjs', '.ts')):
                    await self._fetch_and_parse(resolved)

        # 9. Webpack __webpack_require__ registry (exposes all bundle paths)
        if '__webpack_require__' in text or 'webpackChunk' in text:
            for m in re.finditer(r'"([^"]{1,300}\.(?:js|json|map))"', text):
                candidate = m.group(1)
                if candidate.startswith('/') or candidate.startswith('./'):
                    self.r.add_ep(_norm_path(candidate), "webpack_registry")

        # 10. GraphQL query strings expose schema paths
        for m in re.finditer(
            r'(?:query|mutation|subscription)\s+\w+[^{]*\{[^}]{0,500}\}', text):
            for word_m in re.finditer(r'\b(\w+)\s*\{', m.group(0)):
                resource = word_m.group(1).lower()
                if len(resource) > 2 and resource not in {'data','items','edges','node'}:
                    self.r.add_ep(f"/graphql/{resource}", "graphql_schema")
                    self.r.add_ep(f"/api/{resource}", "graphql_schema")

    async def _fetch_sourcemap(self, map_url: str) -> None:
        if map_url in self._seen: return
        self._seen.add(map_url)
        async with self._sem:
            text = await _tget(self.s, map_url, timeout=20, proxy=self.proxy)
        if not text: return
        try:
            data = json.loads(text)
            for source in data.get("sources", []):
                self.r.add_ep(_norm_path(source), "source_map")
            for content in data.get("sourcesContent", []):
                if isinstance(content, str):
                    for p in _paths_from_text(content): self.r.add_ep(p, "source_map")
                    for sub in _subs_from_text(content, self.d): self.r.add_sub(sub, "source_map")
        except Exception:
            for p in _paths_from_text(text): self.r.add_ep(p, "source_map")


# ═══════════════════════════════════════════════════════════════════════════════
# MUTATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
class Mutator:
    def __init__(self, r: Result, d: str):
        self.r = r; self.d = d

    def subdomain_mutations(self) -> Set[str]:
        out: Set[str] = set()
        prefixes_seen: Set[str] = set()
        env_words = {"dev","staging","stg","qa","uat","test","prod","production",
                     "preprod","pre-prod","beta","alpha","canary","int","internal",
                     "external","ext","corp","old","new","legacy","v1","v2","v3"}

        for sub in self.r.subdomains:
            clean = sub.replace(f".{self.d}", "").strip(".")
            for part in clean.split("."):
                if part and len(part) < 40:
                    prefixes_seen.add(part)

        all_prefixes = prefixes_seen | set(SUBDOMAIN_PREFIXES)
        svc_words = prefixes_seen - env_words

        # Single-level
        for p in all_prefixes:
            out.add(f"{p}.{self.d}")

        # Compound: env × service
        for env in env_words:
            for svc in list(svc_words)[:80]:
                out.add(f"{env}-{svc}.{self.d}")
                out.add(f"{svc}-{env}.{self.d}")
                out.add(f"{svc}.{env}.{self.d}")
                out.add(f"{env}.{svc}.{self.d}")

        # API versioning
        for api in [p for p in prefixes_seen if 'api' in p.lower()] or ["api"]:
            for v in range(1, 6):
                out.update([
                    f"{api}-v{v}.{self.d}", f"{api}{v}.{self.d}",
                    f"v{v}.{api}.{self.d}", f"{api}-{v}.{self.d}",
                ])

        # Cloud-style suffixes
        cloud_sfx = ["-cdn", "-edge", "-static", "-assets", "-media",
                     "-files", "-uploads", "-backup", "-dr"]
        org = self.d.split('.')[0]
        for sfx in cloud_sfx:
            out.add(f"{org}{sfx}.{self.d}")

        out -= self.r.subdomains
        out.discard(self.d)
        return out

    def endpoint_mutations(self) -> Set[str]:
        out: Set[str] = set()
        versions_seen: Set[str] = set()
        resources_seen: Set[str] = set()

        for path in self.r.endpoints:
            parts = [p for p in path.split('/') if p and '?' not in p]
            for part in parts:
                if re.match(r'^v\d+(?:\.\d+)?$', part, re.I):
                    versions_seen.add(part.lower())
                elif not re.match(r'^\d+$|^[a-f0-9]{24,}$|^[a-f0-9\-]{36}$', part):
                    if 2 < len(part) < 35:
                        resources_seen.add(part.lower())
            # Version substitution
            for ver in (versions_seen or {"v1","v2","v3","v4"}):
                mutated = re.sub(r'/v\d+(?:\.\d+)?/', f'/{ver}/', path, flags=re.I)
                if mutated != path: out.add(mutated)

        if not versions_seen:
            versions_seen = {"v1", "v2", "v3", "v4"}

        # Resource × version expansion
        for ver in versions_seen:
            for res in list(resources_seen)[:120]:
                for pfx in ["/api", "/api2", "/rest", ""]:
                    base = f"{pfx}/{ver}/{res}"
                    out.update([
                        base, f"{base}/list", f"{base}/search",
                        f"{base}/count", f"{base}/{{id}}",
                        f"{base}/admin", f"{base}/bulk",
                        f"{base}/export", f"{base}/import",
                        f"{base}/me", f"{base}/all",
                    ])

        # All framework static paths
        out.update(ALL_PROBE_PATHS)

        # Env suffixes on discovered paths
        env_sfx = ["-dev","-staging","-test","-beta","-internal",
                   "-old","-new","-v2","-legacy","-backup","-debug"]
        for path in list(self.r.endpoints)[:600]:
            parts = path.split('/')
            if len(parts) >= 2 and parts[-1]:
                last = parts[-1].split('?')[0]
                if last:
                    for sfx in env_sfx:
                        out.add('/'.join(parts[:-1]) + '/' + last + sfx)

        # Path traversal / bypass variants on protected paths
        protected = [p for p in self.r.endpoints
                     if any(x in p.lower() for x in
                            ('admin','internal','private','debug','manage','api'))]
        bypass_transforms = [
            lambda p: f"/..;/{p.lstrip('/')}",
            lambda p: f"/{p.lstrip('/')}/",
            lambda p: f"/{p.lstrip('/')}%2f",
            lambda p: f"/{p.lstrip('/')}%20",
            lambda p: f"/;/{p.lstrip('/')}",
            lambda p: f"/%2e/{p.lstrip('/')}",
            lambda p: f"/.//{p.lstrip('/')}",
            lambda p: f"/{p.lstrip('/')}/.",
            lambda p: re.sub(r'/(\w)', lambda m: f'/{m.group(1).upper()}', p, count=1),
        ]
        for path in protected[:200]:
            for transform in bypass_transforms:
                try: out.add(transform(path))
                except Exception: pass

        # Content-type / extension variants
        ext_variants = [".json", ".xml", ".yaml", ".csv", ".txt",
                        ".html", ";.json", "?format=json"]
        for path in list(self.r.endpoints)[:300]:
            clean = path.split('?')[0].split('#')[0]
            if '.' not in clean.split('/')[-1]:  # no extension
                for ext in ext_variants:
                    out.add(clean + ext)

        out -= self.r.endpoints
        return out


# ═══════════════════════════════════════════════════════════════════════════════
# ACTIVE PROBER — behavioral fingerprinting, no wordlist brute-force
# ═══════════════════════════════════════════════════════════════════════════════
class Prober:
    def __init__(self, s, r: Result, d: str, wc: Optional[str], proxy: Optional[str]):
        self.s = s; self.r = r; self.d = d; self.wc = wc; self.proxy = proxy
        self._sem_h = asyncio.Semaphore(MAX_PROBE)
        self._probed: Set[str] = set()

    async def _baseline(self, host: str) -> Optional[Dict]:
        rand = f"/{''.join(random.choices(string.ascii_lowercase, k=22))}"
        try:
            t0 = time.monotonic()
            to = aiohttp.ClientTimeout(total=10)
            for scheme in ("https", "http"):
                try:
                    async with self.s.request(
                        "GET", f"{scheme}://{host}{rand}",
                        headers=_hdrs(), timeout=to,
                        allow_redirects=True, ssl=_ssl_ctx(),
                        proxy=self.proxy,
                    ) as resp:
                        body = await resp.text(errors='replace')
                        return {
                            "status": resp.status,
                            "len": len(body),
                            "hash": hashlib.md5(body.encode()).hexdigest(),
                            "ct": resp.headers.get("Content-Type",""),
                            "server": resp.headers.get("Server",""),
                            "hdrs": dict(resp.headers),
                            "t": time.monotonic() - t0,
                            "scheme": scheme,
                        }
                except Exception:
                    continue
        except Exception:
            pass
        return None

    async def _probe(self, host: str, path: str, scheme: str = "https") -> Optional[Dict]:
        key = f"{host}{path}"
        if key in self._probed: return None
        self._probed.add(key)
        try:
            t0 = time.monotonic()
            to = aiohttp.ClientTimeout(total=12)
            async with self.s.request(
                "GET", f"{scheme}://{host}{path}",
                headers=_hdrs(), timeout=to,
                allow_redirects=True, ssl=_ssl_ctx(),
                proxy=self.proxy,
            ) as resp:
                body = await resp.text(errors='replace')
                return {
                    "status": resp.status,
                    "url": str(resp.url),
                    "len": len(body),
                    "hash": hashlib.md5(body.encode()).hexdigest(),
                    "ct": resp.headers.get("Content-Type",""),
                    "server": resp.headers.get("Server",""),
                    "hdrs": dict(resp.headers),
                    "t": time.monotonic() - t0,
                    "body": body[:800],
                    "scheme": scheme,
                }
        except Exception:
            return None

    def _interesting(self, probe: Dict, baseline: Optional[Dict]) -> bool:
        st = probe.get("status", 0)
        if st in (200, 201, 202, 204, 206): return True
        if st in (401, 403, 405, 407, 408): return True
        if st in (301, 302, 307, 308):
            loc = probe.get("hdrs",{}).get("Location","")
            if loc and not re.search(r'(?:404|error|not.?found)', loc, re.I):
                return True
        if not baseline:
            return st < 400
        bst = baseline.get("status", 404)
        if st != bst: return True
        blen = baseline.get("len", 1)
        plen = probe.get("len", 0)
        if abs(plen - blen) > max(150, blen * 0.12): return True
        if probe.get("ct","") != baseline.get("ct",""): return True
        pt = probe.get("t", 0); bt = baseline.get("t", 1)
        if pt > bt * 3.5 and pt > 0.6: return True
        if probe.get("hash") != baseline.get("hash") and abs(plen - blen) < 80:
            return True
        sec_hdrs = {"WWW-Authenticate","X-Auth-Required","X-Frame-Options",
                    "Content-Security-Policy"}
        if set(probe.get("hdrs",{}).keys()) & sec_hdrs - set(baseline.get("hdrs",{}).keys()):
            return True
        return False

    async def probe_host_paths(self, host: str, paths: List[str]) -> None:
        baseline = await self._baseline(host)
        scheme = (baseline or {}).get("scheme", "https")

        # Detect tech stack from baseline headers
        if baseline:
            srv = baseline.get("server","").lower()
            ct  = baseline.get("ct","").lower()
            if "nginx"   in srv: self.r.tech_stack["webserver"].add("nginx")
            if "apache"  in srv: self.r.tech_stack["webserver"].add("apache")
            if "iis"     in srv: self.r.tech_stack["webserver"].add("iis")
            if "cloudflare" in baseline.get("hdrs",{}).get("Server","").lower():
                self.r.tech_stack["cdn"].add("cloudflare")

        async def _check(path: str) -> None:
            async with self._sem_h:
                probe = await self._probe(host, path, scheme)
                if not probe: return
                if self._interesting(probe, baseline):
                    self.r.add_ep(path, "active_probe")
                    self.r.live_eps.add(f"{scheme}://{host}{path}")
                    # Extract more endpoints from interesting response body
                    body = probe.get("body","")
                    if body:
                        for p in _paths_from_text(body): self.r.add_ep(p, "active_body")
                        ct = probe.get("ct","")
                        if "json" in ct:
                            try:
                                jdata = json.loads(body)
                                for link in self._extract_links_from_json(jdata):
                                    self.r.add_ep(link, "active_json")
                            except Exception: pass

        chunk_size = 250
        for i in range(0, len(paths), chunk_size):
            await asyncio.gather(*[_check(p) for p in paths[i:i+chunk_size]],
                                 return_exceptions=True)

    def _extract_links_from_json(self, data: Any, depth: int = 0) -> List[str]:
        if depth > 4: return []
        out = []
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and v.startswith('/'):
                    out.append(v)
                elif isinstance(v, str) and v.startswith('http'):
                    out.append(v)
                else:
                    out.extend(self._extract_links_from_json(v, depth+1))
        elif isinstance(data, list):
            for item in data[:20]:
                out.extend(self._extract_links_from_json(item, depth+1))
        return out

    async def framework_fingerprint(self, host: str) -> Set[str]:
        detected: Set[str] = set()
        indicators = {
            "spring":    ["/actuator/health", "/actuator"],
            "nextjs":    ["/_next/static/", "/api/auth/session"],
            "django":    ["/admin/", "/admin/login/"],
            "laravel":   ["/nova-api/", "/telescope"],
            "wordpress": ["/wp-login.php", "/wp-json/"],
            "graphql":   ["/graphql", "/graphiql"],
            "rails":     ["/rails/info/properties"],
            "aspnet":    ["/elmah.axd", "/hangfire"],
            "swagger":   ["/swagger-ui/", "/api-docs"],
        }
        async def _check_fw(fw: str, inds: List[str]) -> None:
            for ind in inds[:2]:
                probe = await self._probe(host, ind)
                if probe and probe.get("status",0) not in (0, 404, 410):
                    detected.add(fw)
                    for fw_path in FW_PATHS.get(fw, []):
                        self.r.add_ep(fw_path, "fw_fingerprint")
                    break
        await asyncio.gather(*[_check_fw(fw, inds) for fw, inds in indicators.items()],
                             return_exceptions=True)
        return detected

    async def cors_probe(self, host: str, path: str = "/api/") -> None:
        evil_origins = [
            f"https://evil.{self.d}", "https://attacker.com",
            f"https://{self.d}.evil.com", "null",
            f"https://evil{self.d}", f"http://localhost",
        ]
        for origin in evil_origins:
            try:
                to = aiohttp.ClientTimeout(total=8)
                async with self.s.get(
                    f"https://{host}{path}",
                    headers={**_hdrs(), "Origin": origin},
                    timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin","")
                    acac = resp.headers.get("Access-Control-Allow-Credentials","")
                    if acao and (acao == origin or acao == "*"):
                        self.r.cors_issues.append({
                            "url": f"https://{host}{path}",
                            "origin_sent": origin,
                            "acao": acao,
                            "acac": acac,
                        })
            except Exception: pass

    async def method_enum(self, host: str, path: str) -> None:
        # HTTP method enumeration on interesting paths
        methods = ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS",
                   "TRACE","CONNECT","PROPFIND","MKCOL"]
        results: List[str] = []
        for method in methods:
            try:
                to = aiohttp.ClientTimeout(total=8)
                async with self.s.request(
                    method, f"https://{host}{path}",
                    headers=_hdrs(), timeout=to,
                    ssl=_ssl_ctx(), proxy=self.proxy,
                ) as resp:
                    if resp.status not in (405, 501, 0):
                        results.append(f"{method}:{resp.status}")
                    # OPTIONS exposes Allow header
                    if method == "OPTIONS":
                        allow = resp.headers.get("Allow","")
                        if allow:
                            results.extend([f"{m}:OPTIONS-Allow"
                                            for m in allow.split(",")])
            except Exception: pass
        if results:
            key = f"https://{host}{path}"
            self.r.open_methods[key] = results

    async def vhost_probe(self, ip: str, vhosts: List[str]) -> Set[str]:
        discovered: Set[str] = set()
        async with self._sem_h:
            baseline = await self._baseline(ip)

        async def _check_vhost(vhost: str) -> None:
            async with self._sem_h:
                try:
                    to = aiohttp.ClientTimeout(total=10)
                    async with self.s.get(
                        f"https://{ip}/",
                        headers={**_hdrs(), "Host": vhost},
                        timeout=to, ssl=_ssl_ctx(),
                        allow_redirects=False, proxy=self.proxy,
                    ) as resp:
                        body = await resp.text(errors='replace')
                        probe = {
                            "status": resp.status,
                            "len": len(body),
                            "hash": hashlib.md5(body.encode()).hexdigest(),
                            "ct": resp.headers.get("Content-Type",""),
                            "t": 0,
                            "hdrs": dict(resp.headers),
                        }
                        if self._interesting(probe, baseline):
                            discovered.add(vhost)
                            self.r.add_sub(vhost, "vhost_probe")
                except Exception: pass

        await asyncio.gather(*[_check_vhost(v) for v in vhosts],
                             return_exceptions=True)
        return discovered

    async def parameter_probe(self, host: str, path: str) -> None:
        # Common parameter names to inject and observe reflections
        common_params = [
            "id","user","username","email","page","limit","offset",
            "q","query","search","filter","sort","order","type","format",
            "token","key","api_key","auth","debug","test","verbose",
            "callback","redirect","url","next","return","ref",
            "lang","locale","currency","country","region",
            "from","to","start","end","date","time",
            "fields","include","exclude","expand","embed",
        ]
        canary = f"reaper{random.randint(10000,99999)}"
        for param in common_params[:20]:
            try:
                to = aiohttp.ClientTimeout(total=8)
                async with self.s.get(
                    f"https://{host}{path}",
                    params={param: canary},
                    headers=_hdrs(), timeout=to,
                    ssl=_ssl_ctx(), proxy=self.proxy,
                ) as resp:
                    body = await resp.text(errors='replace')
                    if canary in body:
                        self.r.add_ep(f"{path}?{param}=[reflected]", "param_probe")
            except Exception: pass

    async def probe_subdomains(self, candidates: Set[str]) -> Set[str]:
        live: Set[str] = set()
        sem = asyncio.Semaphore(MAX_DNS)

        async def _check(sub: str) -> None:
            async with sem:
                ip = await _resolve(sub)
                if not ip: return
                if self.wc and ip == self.wc:
                    # Wildcard match — verify behaviorally
                    probe  = await self._probe(sub, "/")
                    rand_h = f"{''.join(random.choices(string.ascii_lowercase,k=16))}.{self.d}"
                    wc_probe = await self._probe(rand_h, "/")
                    if probe and wc_probe:
                        if probe.get("hash") != wc_probe.get("hash"):
                            live.add(sub); self.r.live_subs.add(sub)
                            self.r.add_sub(sub, "active_wc")
                else:
                    live.add(sub); self.r.live_subs.add(sub)
                    self.r.add_sub(sub, "active_dns")

        await asyncio.gather(*[_check(s) for s in candidates],
                             return_exceptions=True)
        return live

    async def run(self, sub_candidates: Set[str], ep_candidates: Set[str]) -> None:
        # 1. Validate subdomain mutations
        log(f"  Validating {len(sub_candidates)} subdomain mutations")
        new_live = await self.probe_subdomains(sub_candidates)
        log(f"  Found {len(new_live)} new live subdomains")

        # 2. Build target host list
        target_hosts = [self.d] + list(self.r.live_subs)[:40]

        # 3. Fingerprint + probe on each host
        for host in target_hosts[:20]:
            log(f"  Probing {host}")
            fws = await self.framework_fingerprint(host)
            if fws:
                log(f"    Detected: {', '.join(fws)}")

            paths = list(ep_candidates)[:4000]
            await self.probe_host_paths(host, paths)

            # CORS probe on API paths
            for api_path in ["/api/", "/api/v1/", "/graphql"]:
                await self.cors_probe(host, api_path)

            # Method enumeration on interesting discovered paths
            interesting = [p for p in self.r.live_eps
                           if host in p and
                           any(x in p for x in ('api','admin','internal'))]
            for ep in list(interesting)[:10]:
                path = urlparse(ep).path
                await self.method_enum(host, path)

        # 4. Virtual host probing on main IP
        main_ip = await _resolve(self.d)
        if main_ip:
            log(f"  VHost probing on {main_ip}")
            vhosts = list(sub_candidates)[:300]
            new_vhosts = await self.vhost_probe(main_ip, vhosts)
            log(f"  VHost: {len(new_vhosts)} new candidates")

        # 5. Parameter probe on key endpoints
        key_eps = [p for p in ALL_PROBE_PATHS
                   if any(x in p for x in ('search','query','filter','api'))]
        for ep in key_eps[:15]:
            await self.parameter_probe(self.d, ep)


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
class Output:
    def __init__(self, r: Result, out: Path):
        self.r = r; self.out = out

    def write(self) -> Dict[str, Path]:
        files: Dict[str, Path] = {}
        subs = sorted(self.r.subdomains)
        eps  = sorted(self.r.endpoints)

        (self.out / "subdomains.txt").write_text('\n'.join(subs)+'\n', encoding='utf-8')
        files["subdomains.txt"] = self.out / "subdomains.txt"

        (self.out / "endpoints.txt").write_text('\n'.join(eps)+'\n', encoding='utf-8')
        files["endpoints.txt"] = self.out / "endpoints.txt"

        if self.r.live_subs:
            p = self.out / "subdomains_live.txt"
            p.write_text('\n'.join(sorted(self.r.live_subs))+'\n', encoding='utf-8')
            files["subdomains_live.txt"] = p

        if self.r.live_eps:
            p = self.out / "endpoints_live.txt"
            p.write_text('\n'.join(sorted(self.r.live_eps))+'\n', encoding='utf-8')
            files["endpoints_live.txt"] = p

        if self.r.js_endpoints:
            p = self.out / "endpoints_js.txt"
            p.write_text('\n'.join(sorted(self.r.js_endpoints))+'\n', encoding='utf-8')
            files["endpoints_js.txt"] = p

        if self.r.cors_issues:
            p = self.out / "cors_issues.json"
            p.write_text(json.dumps(self.r.cors_issues, indent=2), encoding='utf-8')
            files["cors_issues.json"] = p

        if self.r.open_methods:
            p = self.out / "http_methods.json"
            p.write_text(json.dumps(self.r.open_methods, indent=2), encoding='utf-8')
            files["http_methods.json"] = p

        # Master JSON
        master = {
            "meta": {
                "target": self.r.domain,
                "timestamp": self.r.timestamp,
                "version": VERSION,
                "counts": {
                    "subdomains": len(subs),
                    "live_subdomains": len(self.r.live_subs),
                    "endpoints": len(eps),
                    "live_endpoints": len(self.r.live_eps),
                    "js_endpoints": len(self.r.js_endpoints),
                    "cors_issues": len(self.r.cors_issues),
                },
            },
            "tech_stack": {k: sorted(v) for k, v in self.r.tech_stack.items()},
            "source_counts": dict(sorted(self.r.source_counts.items(),
                                         key=lambda x: x[1], reverse=True)),
            "subdomains": subs,
            "live_subdomains": sorted(self.r.live_subs),
            "endpoints": eps,
            "live_endpoints": sorted(self.r.live_eps),
            "js_endpoints": sorted(self.r.js_endpoints),
            "cors_issues": self.r.cors_issues,
            "http_methods": self.r.open_methods,
            "errors": self.r.errors[:100],
        }
        p = self.out / "results.json"
        p.write_text(json.dumps(master, indent=2, ensure_ascii=False), encoding='utf-8')
        files["results.json"] = p

        # HTML summary report
        self._write_html(master, files)

        return files

    def _write_html(self, data: Dict, files: Dict) -> None:
        meta = data["meta"]
        counts = meta["counts"]
        subs_html   = '\n'.join(f'<li>{s}</li>' for s in data["subdomains"][:200])
        live_s_html = '\n'.join(f'<li><a href="{s}" target="_blank">{s}</a></li>'
                                for s in data["live_subdomains"][:100])
        eps_html    = '\n'.join(f'<li><code>{e}</code></li>'
                                for e in data["endpoints"][:300])
        live_e_html = '\n'.join(f'<li><a href="{e}" target="_blank">{e}</a></li>'
                                for e in data["live_endpoints"][:100])
        cors_html   = '\n'.join(
            f'<tr><td>{c["url"]}</td><td>{c["origin_sent"]}</td>'
            f'<td>{c["acao"]}</td><td>{c["acac"]}</td></tr>'
            for c in data.get("cors_issues", [])
        )
        src_html = '\n'.join(
            f'<tr><td>{k}</td><td>{v}</td></tr>'
            for k, v in list(data.get("source_counts",{}).items())[:30]
        )
        html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Reaper Recon — {meta["target"]}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}}
h1{{color:#58a6ff;margin-bottom:8px}}
h2{{color:#79c0ff;margin:24px 0 8px;border-bottom:1px solid #21262d;padding-bottom:4px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:16px 0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}}
.card .num{{font-size:2em;font-weight:700;color:#58a6ff}}
.card .lbl{{font-size:.8em;color:#8b949e;margin-top:4px}}
ul{{list-style:none;max-height:300px;overflow-y:auto;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px}}
li{{padding:3px 6px;font-size:.85em;border-bottom:1px solid #21262d}}
li:last-child{{border:none}}
a{{color:#58a6ff;text-decoration:none}}
table{{width:100%;border-collapse:collapse;font-size:.85em}}
th{{background:#21262d;padding:8px;text-align:left;color:#8b949e}}
td{{padding:6px 8px;border-bottom:1px solid #21262d;word-break:break-all}}
.badge{{background:#1f6feb;color:#fff;padding:2px 8px;border-radius:12px;font-size:.75em}}
</style></head><body>
<h1>🔍 Reaper Recon v{VERSION}</h1>
<p>Target: <strong>{meta["target"]}</strong> &nbsp;|&nbsp;
   Scanned: {meta["timestamp"]} &nbsp;|&nbsp;
   <span class="badge">75+ sources</span></p>
<div class="grid">
  <div class="card"><div class="num">{counts["subdomains"]}</div><div class="lbl">Subdomains</div></div>
  <div class="card"><div class="num">{counts["live_subdomains"]}</div><div class="lbl">Live Subdomains</div></div>
  <div class="card"><div class="num">{counts["endpoints"]}</div><div class="lbl">Endpoints</div></div>
  <div class="card"><div class="num">{counts["live_endpoints"]}</div><div class="lbl">Live Endpoints</div></div>
  <div class="card"><div class="num">{counts["js_endpoints"]}</div><div class="lbl">JS Endpoints</div></div>
  <div class="card"><div class="num">{counts["cors_issues"]}</div><div class="lbl">CORS Issues</div></div>
</div>
<h2>Live Subdomains</h2><ul>{live_s_html or '<li>None found</li>'}</ul>
<h2>All Subdomains (top 200)</h2><ul>{subs_html or '<li>None</li>'}</ul>
<h2>Live Endpoints</h2><ul>{live_e_html or '<li>None found</li>'}</ul>
<h2>All Endpoints (top 300)</h2><ul>{eps_html or '<li>None</li>'}</ul>
{"<h2>CORS Issues</h2><table><tr><th>URL</th><th>Origin</th><th>ACAO</th><th>ACAC</th></tr>" + cors_html + "</table>" if cors_html else ""}
<h2>Source Contributions</h2>
<table><tr><th>Source</th><th>Findings</th></tr>{src_html}</table>
</body></html>"""
        p = self.out / "report.html"
        p.write_text(html, encoding='utf-8')
        files["report.html"] = p


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════
async def run(domain: str, args: argparse.Namespace) -> None:
    ts = datetime.utcnow().isoformat() + "Z"
    r  = Result(domain=domain, timestamp=ts)
    out_dir = _out_dir(domain)
    proxy = args.proxy or None

    api_keys: Dict[str, str] = {
        "virustotal":   args.vt_key        or "",
        "shodan":       args.shodan_key    or "",
        "urlscan":      args.urlscan_key   or "",
        "github":       args.github_key    or "",
        "gitlab":       args.gitlab_key    or "",
        "securitytrails":args.st_key       or "",
        "censys_id":    args.censys_id     or "",
        "censys_secret":args.censys_secret or "",
        "chaos":        args.chaos_key     or "",
        "otx":          args.otx_key       or "",
        "bing":         args.bing_key      or "",
        "greynoise":    args.gn_key        or "",
        "intelx":       args.intelx_key    or "",
        "fofa_email":   args.fofa_email    or "",
        "fofa_key":     args.fofa_key      or "",
        "pt_user":      args.pt_user       or "",
        "pt_key":       args.pt_key        or "",
        "whoisxml":     args.whoisxml_key  or "",
        "netlas":       args.netlas_key    or "",
        "zoomeye":      args.zoomeye_key   or "",
        "binaryedge":   args.be_key        or "",
        "fullhunt":     args.fh_key        or "",
        "hunter":       args.hunter_key    or "",
        "pulsedive":    args.pd_key        or "",
        "onyphe":       args.onyphe_key    or "",
        "c99":          args.c99_key       or "",
        "spyonweb":     args.spw_key       or "",
        "cloudflare":   args.cf_key        or "",
        "ha":           args.ha_key        or "",
        "xforce_key":   args.xforce_key    or "",
        "xforce_pass":  args.xforce_pass   or "",
        "ipinfo":       args.ipinfo_key    or "",
    }

    log(f"Target  : {domain}")
    log(f"Output  : {out_dir}")

    connector = aiohttp.TCPConnector(
        limit=MAX_HTTP, limit_per_host=8,
        ssl=_ssl_ctx(), ttl_dns_cache=300,
    )
    session_timeout = aiohttp.ClientTimeout(total=120, connect=12)

    async with aiohttp.ClientSession(
        connector=connector, timeout=session_timeout, headers=_hdrs(),
    ) as session:

        # ── Phase 1: Wildcard ──────────────────────────────────────────────
        log("Phase 1 : Wildcard DNS check")
        wc = await _wildcard(domain)
        if wc: log(f"  Wildcard: *.{domain} → {wc}", "WRN")

        # ── Phase 2: Passive OSINT ─────────────────────────────────────────
        if not args.active_only:
            log("Phase 2 : Passive OSINT (75+ sources)")
            passive = Passive(session, r, domain, api_keys, proxy)
            await passive.run_all()
            log(f"  Passive: {len(r.subdomains)} subdomains, {len(r.endpoints)} endpoints")

        # ── Phase 3: DNS resolution ────────────────────────────────────────
        log("Phase 3 : DNS resolution")
        resolved = await batch_resolve(list(r.subdomains), wc)
        r.live_subs.update(resolved.keys())
        log(f"  Live subdomains: {len(r.live_subs)}")

        # ── Phase 4: JS parsing ────────────────────────────────────────────
        if not args.passive_only:
            log("Phase 4 : JavaScript bundle analysis")
            js = JSEngine(session, r, domain, proxy)
            js_targets = [f"https://{domain}"] + \
                         [f"https://{s}" for s in list(r.live_subs)[:25]]
            await asyncio.gather(*[js.crawl(u) for u in js_targets],
                                 return_exceptions=True)
            r.js_endpoints.update(r.endpoints)
            log(f"  After JS: {len(r.endpoints)} endpoints")

        # ── Phase 5: Mutation ──────────────────────────────────────────────
        log("Phase 5 : Mutation engine")
        mut = Mutator(r, domain)
        sub_muts = mut.subdomain_mutations()
        ep_muts  = mut.endpoint_mutations()
        log(f"  Generated {len(sub_muts)} sub candidates, {len(ep_muts)} ep candidates")

        # ── Phase 6: Active probing ────────────────────────────────────────
        if not args.passive_only:
            log("Phase 6 : Active probing")
            prober = Prober(session, r, domain, wc, proxy)
            await prober.run(sub_muts, ep_muts)
            log(f"  Live endpoints: {len(r.live_eps)}")
            if r.cors_issues: log(f"  CORS issues   : {len(r.cors_issues)}", "WRN")

    # ── Phase 7: Output ────────────────────────────────────────────────────
    log("Phase 7 : Writing output")
    out = Output(r, out_dir)
    files = out.write()

    print("\n" + "─"*62)
    print(f"  TARGET          {domain}")
    print(f"  OUTPUT          {out_dir}/")
    print(f"  Subdomains      {len(r.subdomains):,}  (live: {len(r.live_subs):,})")
    print(f"  Endpoints       {len(r.endpoints):,}  (live: {len(r.live_eps):,})")
    print(f"  CORS Issues     {len(r.cors_issues):,}")
    print("─"*62)
    for label, path in files.items():
        print(f"  {label:<28} {path}")
    print("─"*62 + "\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════
def _args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Reaper Recon v2.0 — 75+ source subdomain & endpoint discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-d","--domain", help="Target domain")
    p.add_argument("--passive-only", action="store_true")
    p.add_argument("--active-only",  action="store_true")
    p.add_argument("--proxy", metavar="URL", help="HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080)")
    g = p.add_argument_group("API Keys (all optional)")
    keys = [
        ("--vt-key","VirusTotal"),("--shodan-key","Shodan"),
        ("--urlscan-key","URLScan.io"),("--github-key","GitHub PAT"),
        ("--gitlab-key","GitLab PAT"),("--st-key","SecurityTrails"),
        ("--censys-id","Censys API ID"),("--censys-secret","Censys secret"),
        ("--chaos-key","ProjectDiscovery Chaos"),("--otx-key","AlienVault OTX"),
        ("--bing-key","Bing Search API"),("--gn-key","GreyNoise"),
        ("--intelx-key","IntelligenceX"),("--fofa-email","FOFA email"),
        ("--fofa-key","FOFA key"),("--pt-user","PassiveTotal user"),
        ("--pt-key","PassiveTotal key"),("--whoisxml-key","WhoisXML"),
        ("--netlas-key","Netlas.io"),("--zoomeye-key","ZoomEye"),
        ("--be-key","BinaryEdge"),("--fh-key","FullHunt"),
        ("--hunter-key","Hunter.io"),("--pd-key","Pulsedive"),
        ("--onyphe-key","Onyphe"),("--c99-key","C99.nl"),
        ("--spw-key","SpyOnWeb"),("--cf-key","Cloudflare Radar"),
        ("--ha-key","Hybrid Analysis"),("--xforce-key","IBM X-Force key"),
        ("--xforce-pass","IBM X-Force pass"),("--ipinfo-key","IPInfo.io"),
    ]
    for flag, desc in keys:
        g.add_argument(flag, metavar="KEY", help=desc)
    return p.parse_args()


def _prompt_domain() -> str:
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   REAPER RECON v2.0 — 75+ Source Discovery Engine       ║")
    print("║              FOR AUTHORIZED TESTING ONLY                ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    while True:
        raw = input("  Target domain/URL: ").strip()
        if not raw: print("  [!] Cannot be empty."); continue
        domain = _norm_domain(raw)
        if not re.match(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
            domain):
            print(f"  [!] Invalid domain: '{domain}'"); continue
        confirm = input(
            f"\n  Target: {domain}\n"
            "  Confirm authorized [y/N]: ").strip().lower()
        if confirm in ('y','yes'): return domain
        print("  [!] Not confirmed. Exiting."); sys.exit(0)


def main() -> None:
    args = _args()
    if args.domain:
        domain = _norm_domain(args.domain)
        if not re.match(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
            domain):
            sys.exit(f"[!] Invalid domain: {domain}")
    else:
        domain = _prompt_domain()

    try:
        asyncio.run(run(domain, args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
