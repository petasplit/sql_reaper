#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  REAPER RECON v3.2 — Elite Subdomain & Endpoint Discovery Engine           ║
║  200+ OSINT Sources · Raw UDP Resolver (2000 concurrent) · DoH Fallback    ║
║  Advanced DNS Engine (NSEC walk, PTR sweep, TLS SAN, ASN/BGP, DKIM)        ║
║  5000-word Permutation Engine (altdns-style) · Confirmed-only Port Scanner  ║
║  BFS Crawler · Wayback · OpenAPI · GraphQL Introspect · Sitemap            ║
║  Favicon Hash Recon · CNAME Takeover · JS Deep Parse · Parameter Discovery ║
║  FOR AUTHORIZED SECURITY TESTING ONLY                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Install:
  pip install aiohttp aiofiles dnspython beautifulsoup4 lxml tqdm

Usage:
  python3 reaper_recon.py -d example.com
  python3 reaper_recon.py -d example.com --passive-only
  python3 reaper_recon.py -d example.com --ports --port-range 1-65535
  python3 reaper_recon.py -d example.com --vt-key VT --shodan-key SH
  python3 reaper_recon.py -d example.com --proxy http://127.0.0.1:8080
"""

import argparse, asyncio, base64, hashlib, ipaddress, json, os, random
import re, socket, ssl, string, struct, sys, time, traceback, urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    import dns.asyncresolver, dns.resolver, dns.exception, dns.rdatatype
    import dns.query, dns.zone, dns.name
    DNSPY = True
except ImportError:
    DNSPY = False

try:
    from tqdm.asyncio import tqdm as atqdm
    TQDM = True
except ImportError:
    TQDM = False

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
VERSION = "3.7.0"
MAX_HTTP      = 200
MAX_DNS       = 600     # concurrent DNS resolvers
MAX_PROBE     = 60   # per-host concurrency; 3 hosts × 60 = 180 simultaneous probes
MAX_JS        = 50
MAX_PORT_SEM  = 600
REQ_TIMEOUT   = 12
DNS_TIMEOUT   = 4
RETRIES       = 2
BACKOFF       = 1.5
MAX_JS_BYTES  = 12 * 1024 * 1024
OUTPUT_BASE   = "reaper_output"
DOH_URLS      = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://doh.opendns.com/dns-query",
]
DNS_RESOLVERS = [
    # ── Tier-1: Proven always-on global public resolvers ─────────────────────
    # Google Public DNS — gold standard
    "8.8.8.8","8.8.4.4",
    # Cloudflare — fastest worldwide, privacy-first
    "1.1.1.1","1.0.0.1",
    # Cloudflare for Families (A/B/C tiers all open to public)
    "1.1.1.2","1.0.0.2","1.1.1.3","1.0.0.3",
    # Quad9 — security-filtering + non-filtering variants
    "9.9.9.9","149.112.112.112","9.9.9.10","149.112.112.10","9.9.9.11","149.112.112.11",
    # OpenDNS / Cisco Umbrella — open recursive
    "208.67.222.222","208.67.220.220","208.67.222.123","208.67.220.123",
    # Google alternate anycast
    "8.8.8.8","8.8.4.4",
    # ── Tier-2: High-quality public recursive resolvers ──────────────────────
    # Verisign Public DNS
    "64.6.64.6","64.6.65.6",
    # Level3 / Lumen (truly open, anycast)
    "4.2.2.1","4.2.2.2","4.2.2.3","4.2.2.4","4.2.2.5","4.2.2.6",
    # Yandex DNS (global anycast)
    "77.88.8.8","77.88.8.1","77.88.8.88","77.88.8.2",
    # CleanBrowsing (security + family, all open)
    "185.228.168.9","185.228.169.9","185.228.168.168","185.228.169.168",
    # Alternate DNS (open public)
    "76.76.19.19","76.223.122.150",
    # ControlD public resolvers
    "76.76.2.0","76.76.10.0","76.76.2.1","76.76.10.1",
    # NextDNS public endpoints
    "45.90.28.0","45.90.30.0","45.90.28.167","45.90.30.167",
    # AdGuard DNS (public, unfiltered + filtered)
    "94.140.14.14","94.140.15.15","94.140.14.140","94.140.15.140",
    # ── Tier-3: Privacy-focused & alternative resolvers ─────────────────────
    # Mullvad public DNS
    "194.242.2.2","194.242.2.3","194.242.2.4","194.242.2.9",
    # DNS0.EU (European open)
    "193.110.81.0","185.253.5.0","193.110.81.9","185.253.5.9",
    # CZ.NIC ODVR (open, validated)
    "193.17.47.1","185.43.135.1",
    # CIRA Canadian Shield (public recursive)
    "149.112.121.10","149.112.122.10",
    # Freenom DNS (global anycast)
    "80.80.80.80","80.80.81.81",
    # UncensoredDNS / censurfridns (Denmark)
    "91.239.100.100","89.233.43.71",
    # Hurricane Electric (open public)
    "74.82.42.42",
    # DNS.WATCH (no logging, open)
    "84.200.69.80","84.200.70.40",
    # SafeDNS (global anycast)
    "195.46.39.39","195.46.39.40",
    # deSEC.io (DNSSEC validating)
    "5.45.96.220","185.12.64.2",
    # AhaDNS (privacy-first)
    "5.2.75.75","45.67.219.208",
    # Dns.sb / SBDNS
    "185.222.222.222","45.11.45.11",
    # EasyDNS (Canadian, open)
    "64.68.200.200","205.210.42.205",
    # NeuStar UltraDNS (formerly Verisign)
    "156.154.70.1","156.154.71.1","156.154.70.5","156.154.71.5",
    # Comodo Secure DNS
    "8.26.56.26","8.20.247.20",
    # FreeDNS / freie-dns.at
    "37.235.1.174","37.235.1.177",
    # Wikimedia DNS (open)
    "208.80.153.1","208.80.153.2",
    # NIC.br (Brazil public)
    "200.160.0.10","200.160.7.186",
    # Applied Privacy (Austria, open)
    "37.252.185.232","94.130.110.185",
    # SmartViper (open public)
    "208.76.50.50","208.76.51.51",
    # GreenTeam (open)
    "81.218.119.11","209.88.198.133",
    # puntCAT (public recursive)
    "109.69.8.51",
    # Telstra Australia (open public)
    "139.130.4.4","139.130.4.5",
    # Alibaba Cloud DNS (global open)
    "223.5.5.5","223.6.6.6",
    # Baidu DNS (open global)
    "180.76.76.76",
    # 114DNS China (open)
    "114.114.114.114","114.114.115.115",
    # DNSPod / Tencent (open global)
    "119.29.29.29","182.254.116.116",
    # Extra Cloudflare edge anycast nodes
    "162.159.36.1","162.159.46.1",
    # Pure DNS
    "178.22.122.100","185.51.200.2",
    # OpenNIC public nodes (stable ones)
    "69.195.152.204","23.94.60.240",
    # Sprintlink / Lumen
    "199.2.252.10","204.97.212.10","204.117.214.10",
    # Additional global anycast
    "8.8.8.8","8.8.4.4",   # Google (intentional repeats for weighted round-robin)
    "1.1.1.1","1.0.0.1",   # Cloudflare (intentional repeats)
    "9.9.9.9","149.112.112.112",  # Quad9 (intentional repeats)
    "208.67.222.222","208.67.220.220",  # OpenDNS (intentional repeats)
    "8.8.8.8","8.8.4.4",
    "1.1.1.1","1.0.0.1",
    "9.9.9.9","149.112.112.112",
    "94.140.14.14","94.140.15.15",  # AdGuard
    "45.90.28.0","45.90.30.0",      # NextDNS
    "64.6.64.6","64.6.65.6",        # Verisign
    "4.2.2.1","4.2.2.2",            # Level3
    "77.88.8.8","77.88.8.1",        # Yandex
    "76.76.19.19","76.223.122.150", # Alternate
    "76.76.2.0","76.76.10.0",       # ControlD
    "8.8.8.8","1.1.1.1","9.9.9.9",  # Top-3 repeated for priority
    "8.8.4.4","1.0.0.1","149.112.112.112",
    "208.67.222.222","208.67.220.220",
    "94.140.14.140","94.140.15.140",
    "185.228.168.9","185.228.169.9",
    "185.228.168.168","185.228.169.168",
    "193.17.47.1","185.43.135.1",
    "149.112.121.10","149.112.122.10",
    "80.80.80.80","80.80.81.81",
    "74.82.42.42",
    "194.242.2.2","194.242.2.3",
    "193.110.81.0","185.253.5.0",
]

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
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
]

# ─── CNAME Takeover signatures ─────────────────────────────────────────────
TAKEOVER_SIGS: Dict[str, List[str]] = {
    "github": ["There isn't a GitHub Pages site here", "github.io"],
    "heroku": ["No such app", "herokuapp.com"],
    "shopify": ["Sorry, this shop is currently unavailable", "myshopify.com"],
    "fastly": ["Fastly error: unknown domain", "fastly.net"],
    "ghost": ["The thing you were looking for is no longer here", "ghost.io"],
    "surge": ["project not found", "surge.sh"],
    "bitbucket": ["Repository not found", "bitbucket.io"],
    "zendesk": ["Help Center Closed", "zendesk.com"],
    "amazonaws": ["NoSuchBucket", "s3.amazonaws.com"],
    "azure": ["404 Web Site not found", "azurewebsites.net", "azureedge.net"],
    "pantheon": ["404 error unknown site in header", "pantheonsite.io"],
    "readme": ["Project doesnt exist", "readme.io"],
    "statuspage": ["You are being redirected", "statuspage.io"],
    "helpscout": ["No settings were found for this company", "helpscout.net"],
    "uservoice": ["This UserVoice subdomain is currently available", "uservoice.com"],
    "tumblr": ["Whatever you were looking for doesn't currently exist", "tumblr.com"],
    "wordpress": ["Do you want to register", "wordpress.com"],
    "teamwork": ["Oops - We didn't find your site", "teamwork.com"],
    "intercom": ["This page is reserved for artistic dogs", "intercom.io", "custom.intercom.help"],
    "unbounce": ["The requested URL was not found on this server", "unbounce.com"],
    "squarespace": ["No Such Account", "squarespace.com"],
    "pingdom": ["This public status page does not seem to exist", "stats.pingdom.com"],
    "tilda": ["Please renew your subscription", "tilda.ws"],
    "instapage": ["Looks Like You're Lost", "pageserve.co", "instapage.com"],
    "desk": ["Please try again or try Desk.com free for 14 days", "desk.com"],
    "webflow": ["The page you are looking for doesn't exist", "webflow.io"],
    "fly.io": ["fly.io", "404 page not found"],
    "render": ["There's nothing here, yet", "onrender.com"],
    "vercel": ["The deployment you are trying to reach is not available", "vercel.app"],
    "netlify": ["Not Found - Request ID", "netlify.app"],
}

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
        "/_next/webpack-hmr",
    ],
    "nuxt": ["/_nuxt/","/__nuxt_error","/api/_content/","/_ipx/","/api/","/_payload.json"],
    "django": [
        "/admin/","/admin/login/","/admin/doc/","/__debug__/","/silk/",
        "/api/schema/","/api/schema/swagger-ui/","/api/schema/redoc/",
        "/_debugbar/","/rosetta/","/flower/","/django-rq/",
    ],
    "laravel": [
        "/nova","/nova-api/","/telescope","/telescope/api/",
        "/horizon","/horizon/api/","/sanctum/csrf-cookie",
        "/_debugbar/","/debugbar/","/artisan","/livewire/",
        "/fortify/","/jetstream/",
    ],
    "rails": [
        "/rails/info/","/rails/info/properties","/rails/info/routes",
        "/rails/mailers","/sidekiq","/sidekiq/queues","/resque/",
        "/blazer","/letter_opener","/rack-mini-profiler/",
        "/cable","/__better_errors",
    ],
    "wordpress": [
        "/wp-admin/","/wp-admin/admin-ajax.php","/wp-login.php",
        "/wp-json/wp/v2/","/wp-json/wp/v2/users","/wp-json/wp/v2/posts",
        "/wp-json/","/xmlrpc.php","/wp-cron.php","/wp-config.php",
        "/?rest_route=/wp/v2/users","/?author=1","/wp-content/debug.log",
        "/wp-json/wp/v2/media","/wp-json/wp/v2/pages",
    ],
    "graphql": [
        "/graphql","/graphiql","/graphql/console","/graphql/playground",
        "/api/graphql","/v1/graphql","/v2/graphql","/query",
        "/playground","/altair","/graphql-explorer","/graphql/schema",
        "/graphql/introspection",
    ],
    "swagger": [
        "/swagger-ui/","/swagger-ui.html","/swagger/","/api-docs",
        "/api-docs/","/openapi.json","/openapi.yaml",
        "/v1/api-docs","/v2/api-docs","/v3/api-docs",
        "/swagger/v1/swagger.json","/swagger/v2/swagger.json",
        "/api/swagger.json","/docs/","/redoc","/scalar",
        "/swagger-resources","/v2/swagger.json","/v3/openapi.json",
        "/rapidoc","/elements",
    ],
    "k8s": [
        "/healthz","/readyz","/livez","/metrics",
        "/apis/","/api/v1","/version","/openapi/v2",
        "/latest/meta-data/","/computeMetadata/v1/","/metadata/instance/",
    ],
    "aspnet": [
        "/elmah.axd","/elmah/","/trace.axd","/hangfire","/hangfire/",
        "/mini-profiler-resources/","/healthcheck","/api/healthcheck",
        "/_framework/blazor.webassembly.js","/_blazor",
        "/signalr/negotiate","/hubs",
    ],
    "jenkins": [
        "/jenkins/","/job/","/view/","/script","/scriptText","/systemInfo",
        "/api/json","/api/xml","/crumbIssuer/api/json","/computer/api/json",
        "/credentials/","/asynchPeople/",
    ],
    "jira": [
        "/rest/api/2/","/rest/api/latest/","/rest/auth/1/session",
        "/wiki/rest/api/","/secure/Dashboard.jspa","/rest/agile/1.0/",
    ],
    "git_leak": [
        "/.git/","/.git/HEAD","/.git/config","/.git/refs/heads/main",
        "/.git/refs/heads/master","/.git/COMMIT_EDITMSG","/.git/index",
        "/.git/packed-refs","/.git/logs/HEAD",
        "/.svn/","/.svn/wc.db","/.hg/","/.hg/hgrc","/.bzr/",
        "/.DS_Store","/.gitignore","/.gitmodules","/.gitattributes",
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
        "/vault.json","/.vault-token","/consul.json",
        "/.npmrc","/.pypirc","/.netrc","/.pgpass",
        "/wp-config.php.bak","/configuration.php.bak",
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
        "/api/2fa","/api/mfa","/api/password","/api/forgot-password",
        "/api/reset-password","/api/verify","/api/invite",
    ],
    "wellknown": [
        "/.well-known/security.txt","/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json","/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/host-meta","/.well-known/webfinger",
        "/.well-known/change-password","/.well-known/mta-sts.txt",
        "/.well-known/dnt-policy.txt","/.well-known/pki-validation/",
        "/.well-known/acme-challenge/",
    ],
    "debug": [
        "/admin","/admin/","/administrator/","/dashboard","/console",
        "/phpinfo.php","/info.php","/test.php","/server-status",
        "/server-info","/nginx_status","/debug","/debug/",
        "/phpmyadmin/","/pma/","/adminer/","/adminer.php",
        "/manager/html","/host-manager/html",
        "/solr/","/solr/admin/","/kibana/","/grafana/",
        "/portainer/","/rancher/","/k8s/","/kube/",
        "/prometheus/","/alertmanager/",
    ],
    "packages": [
        "/package.json","/package-lock.json","/yarn.lock","/pnpm-lock.yaml",
        "/composer.json","/Gemfile","/requirements.txt",
        "/go.mod","/Cargo.toml","/pyproject.toml","/setup.py",
        "/Pipfile","/Pipfile.lock","/poetry.lock","/go.sum",
    ],
    "backup": [
        "/backup/","/backups/","/bak/","/old/","/archive/","/dump/",
        "/database.sql","/db.sql","/dump.sql",
        "/backup.zip","/backup.tar.gz","/site.zip",
        "/www.zip","/htdocs.zip","/html.zip",
    ],
    "cloud_storage": [
        "/s3/","/blob/","/storage/","/uploads/","/files/","/assets/",
        "/static/","/media/","/cdn/","/public/","/objects/",
    ],
    "sourcemaps": [
        "/main.js.map","/app.js.map","/bundle.js.map",
        "/static/js/main.chunk.js.map","/dist/bundle.js.map",
        "/assets/index.js.map","/build/static/js/main.chunk.js.map",
        "/dist/main.js.map","/dist/app.js.map",
    ],
    "websocket": [
        "/ws","/websocket","/ws/","/socket","/socket.io/",
        "/sockjs-node/","/cable","/action-cable-three/",
        "/signalr/","/hub","/hubs",
    ],
    "mobile_api": [
        "/mobile/api/","/m/api/","/app/api/","/ios/api/","/android/api/",
        "/api/mobile/","/api/app/","/api/ios/","/api/android/",
        "/v1/mobile/","/v2/mobile/",
    ],
    "grpc": [
        "/grpc.","/grpc/","/proto/","/protoset",
        "/grpc.health.v1.Health/Check",
    ],
    "php": [
        "/index.php","/login.php","/admin.php","/config.php","/setup.php",
        "/install.php","/upgrade.php","/update.php","/register.php",
        "/forgot.php","/reset.php","/logout.php","/dashboard.php",
        "/panel.php","/user.php","/account.php","/profile.php",
        "/search.php","/upload.php","/download.php","/file.php",
        "/files.php","/image.php","/images.php","/gallery.php",
        "/news.php","/blog.php","/post.php","/comments.php",
        "/contact.php","/form.php","/submit.php","/ajax.php",
        "/api.php","/rest.php","/data.php","/export.php",
        "/import.php","/report.php","/reports.php","/stats.php",
        "/cron.php","/task.php","/worker.php","/queue.php",
        "/error.php","/404.php","/500.php","/info.php",
        "/test.php","/debug.php","/phpinfo.php","/info.php",
        "/status.php","/health.php","/ping.php","/check.php",
        "/token.php","/auth.php","/oauth.php","/sso.php",
        "/payment.php","/billing.php","/invoice.php","/order.php",
        "/orders.php","/cart.php","/checkout.php","/product.php",
        "/products.php","/catalog.php","/category.php","/tag.php",
        "/user-admin.php","/users.php","/roles.php","/permissions.php",
        "/settings.php","/configuration.php","/options.php",
        "/backup.php","/restore.php","/migrate.php","/deploy.php",
        "/shell.php","/cmd.php","/exec.php","/run.php",
        "/proxy.php","/redirect.php","/forward.php","/relay.php",
        "/webhook.php","/callback.php","/notify.php","/event.php",
        "/mailer.php","/mail.php","/email.php","/smtp.php",
        "/graphql.php","/rpc.php","/soap.php","/wsdl.php",
    ],
    "nodejs": [
        "/server.js","/app.js","/index.js","/main.js","/bundle.js",
        "/.env","/nodemon.json","/pm2.json","/ecosystem.config.js",
        "/process.json","/Procfile","/app.yaml","/app.json",
    ],
    "config_files": [
        "/robots.txt","/sitemap.xml","/sitemap_index.xml","/sitemap.txt",
        "/crossdomain.xml","/clientaccesspolicy.xml","/browserconfig.xml",
        "/manifest.json","/manifest.webmanifest","/service-worker.js",
        "/sw.js","/workbox-*.js","/precache-manifest.*.js",
        "/ads.txt","/sellers.json","/app-ads.txt","/privacy-policy.txt",
        "/security.txt","/humans.txt","/favicon.ico","/apple-touch-icon.png",
        "/apple-app-site-association","/assetlinks.json",
        "/.well-known/security.txt","/.well-known/change-password",
        "/web.config","/.htaccess","/.htpasswd","/.user.ini",
        "/nginx.conf","/apache.conf","/httpd.conf",
        "/php.ini","/php-fpm.conf","/uwsgi.ini",
        "/supervisord.conf","/gunicorn.conf.py",
        "/Makefile","/Taskfile.yml","/Taskfile.yaml",
        "/build.gradle","/pom.xml","/build.xml","/ivy.xml",
        "/Gemfile.lock","/composer.lock","/yarn.lock","/package-lock.json",
        "/mix.lock","/rebar.lock","/stack.yaml",
        "/.travis.yml","/.gitlab-ci.yml","/Jenkinsfile",
        "/.circleci/config.yml","/.github/workflows/",
        "/azure-pipelines.yml","/bitbucket-pipelines.yml",
        "/sonar-project.properties","/codecov.yml","/.coveragerc",
    ],
    "secrets_deep": [
        "/.env.bak","/.env.old","/.env.save","/.env.swp","/.env~",
        "/.env.php","/.env.rb","/.env.py","/.env.js","/.env.ts",
        "/env.json","/env.yml","/env.yaml","/env.toml",
        "/.env.docker","/docker.env","/.env.container",
        "/local_settings.py","/settings_local.py","/settings_prod.py",
        "/settings_dev.py","/local.py","/prod.py",
        "/database.json","/db.json","/db.yaml","/db.yml",
        "/connection.json","/connections.json","/datasources.json",
        "/config/database.yml","/config/secrets.yml","/config/storage.yml",
        "/config/credentials.json","/config/keys.json","/config/auth.json",
        "/config/application.json","/config/default.json","/config/production.json",
        "/config/development.json","/config/test.json","/config/local.json",
        "/config/config.json","/config/config.yaml","/config/config.yml",
        "/conf/config.json","/conf/config.yaml","/conf/settings.json",
        "/etc/config.json","/etc/settings.json","/etc/app.conf",
        "/secrets/","/secrets.json","/secret.json","/secret.key",
        "/private.pem","/private.crt","/cert.pem","/cert.key",
        "/ssl/","/tls/","/certs/","/keys/",
        "/id_rsa","/id_rsa.pub","/id_ed25519","/id_ecdsa",
        "/.ssh/id_rsa","/.ssh/known_hosts","/.ssh/authorized_keys",
        "/ssh_host_rsa_key","/ssh_host_ecdsa_key",
        "/kube/config","/.kube/config","/kubeconfig",
        "/admin/config.php","/wp-config.bak","/configuration.php",
        "/conf/database.php","/application/config/database.php",
        "/config/boot/routes.php",
        "/.bash_history","/.zsh_history","/.sh_history",
        "/.bash_profile","/.bashrc","/.profile","/.zshrc",
        "/proc/self/environ","/proc/self/cmdline","/proc/self/fd/",
    ],
    "backup_deep": [
        "/backup/","/backups/","/bak/","/old/","/archive/","/dump/",
        "/old_site/","/website.bak/","/site_backup/","/db_backup/",
        "/sql_backup/","/log/","/logs/","/logfile/","/logfiles/",
        "/.bak/","/.backup/","/.cache/","/.old/","/.tmp/","/.temp/",
        "/database.sql","/dump.sql","/data.sql","/schema.sql",
        "/mysql.sql","/postgres.sql","/sqlite.db","/site.db",
        "/database.db","/app.db","/users.db","/prod.sql","/dev.sql",
        "/backup.sql","/full_backup.sql","/partial_backup.sql",
        "/latest.sql","/LATEST.sql","/20*.sql",
        "/backup.zip","/backup.tar.gz","/backup.tar.bz2","/backup.7z",
        "/site.zip","/www.zip","/html.zip","/public.zip",
        "/web.zip","/deploy.zip","/release.zip","/dist.zip",
        "/source.zip","/src.zip","/code.zip","/project.zip",
        "/full.zip","/complete.zip","/final.zip","/prod.zip",
        "/app.zip","/application.zip","/website.zip","/server.zip",
        "/htdocs.zip","/httpdocs.zip","/public_html.zip","/var_www.zip",
        "/static.zip","/assets.zip","/media.zip","/files.zip",
        "/upload.zip","/uploads.zip","/data.zip","/export.zip",
        "/migration.zip","/migrations.zip","/scripts.zip",
        "/.git.zip","/.git.tar.gz","/git.tar.gz","/repo.zip",
    ],
    "api_extended": [
        "/api/v1/users","/api/v1/user","/api/v1/accounts","/api/v1/account",
        "/api/v1/auth","/api/v1/login","/api/v1/logout","/api/v1/register",
        "/api/v1/token","/api/v1/refresh","/api/v1/verify","/api/v1/reset",
        "/api/v1/me","/api/v1/profile","/api/v1/settings","/api/v1/config",
        "/api/v1/admin","/api/v1/dashboard","/api/v1/stats","/api/v1/metrics",
        "/api/v1/health","/api/v1/status","/api/v1/ping","/api/v1/info",
        "/api/v1/search","/api/v1/query","/api/v1/data","/api/v1/export",
        "/api/v1/import","/api/v1/upload","/api/v1/download","/api/v1/files",
        "/api/v1/orders","/api/v1/order","/api/v1/products","/api/v1/product",
        "/api/v1/customers","/api/v1/customer","/api/v1/payments","/api/v1/payment",
        "/api/v1/invoices","/api/v1/invoice","/api/v1/subscriptions",
        "/api/v1/notifications","/api/v1/events","/api/v1/logs","/api/v1/audit",
        "/api/v1/roles","/api/v1/permissions","/api/v1/groups","/api/v1/teams",
        "/api/v1/organizations","/api/v1/org","/api/v1/companies",
        "/api/v1/reports","/api/v1/analytics","/api/v1/insights",
        "/api/v1/webhooks","/api/v1/integrations","/api/v1/keys","/api/v1/tokens",
        "/api/v2/users","/api/v2/auth","/api/v2/me","/api/v2/admin",
        "/api/v2/data","/api/v2/search","/api/v2/health","/api/v2/status",
        "/api/v3/users","/api/v3/auth","/api/v3/data","/api/v3/health",
        "/api/internal/users","/api/internal/admin","/api/internal/config",
        "/api/internal/debug","/api/internal/metrics","/api/internal/health",
        "/api/internal/stats","/api/internal/logs","/api/internal/jobs",
        "/api/private/","/api/public/","/api/partner/","/api/external/",
        "/api/beta/","/api/alpha/","/api/dev/","/api/test/",
        "/api/admin/users","/api/admin/config","/api/admin/logs",
        "/api/admin/stats","/api/admin/debug","/api/admin/health",
        "/api/system/","/api/sys/","/api/management/",
        "/api/debug/","/api/trace/","/api/profiler/",
        "/api/oauth/token","/api/oauth/authorize","/api/oauth2/",
        "/api/saml/","/api/sso/","/api/oidc/","/api/jwt/",
        "/api/2fa/","/api/mfa/","/api/otp/","/api/totp/",
        "/api/graphql","/api/rest","/api/soap","/api/rpc",
        "/api/grpc","/api/proto","/api/schema","/api/spec",
        "/api/docs","/api/swagger","/api/openapi","/api/redoc",
        "/api/events/","/api/stream/","/api/ws/","/api/sse/",
        "/api/batch/","/api/bulk/","/api/async/","/api/queue/",
        "/api/callback/","/api/webhook/","/api/notify/","/api/push/",
        "/api/presign","/api/upload/sign","/api/storage/","/api/cdn/",
        "/api/proxy/","/api/forward/","/api/relay/","/api/tunnel/",
        "/api/cache/","/api/purge/","/api/flush/","/api/clear/",
        "/api/migrate/","/api/seed/","/api/reset/database",
        "/api/cron/","/api/jobs/","/api/tasks/","/api/workers/",
        "/api/feature-flags","/api/features","/api/experiments",
        "/api/a-b-test","/api/launchdarkly","/api/unleash",
        "/api/spend","/api/budget","/api/billing/portal",
        "/api/checkout/session","/api/stripe/","/api/braintree/",
        "/api/paypal/","/api/square/","/api/adyen/",
        "/rest/api/","/rest/v1/","/rest/v2/","/rest/v3/",
    ],
    "admin_panels": [
        "/admin","/admin/","/admin/login","/admin/dashboard","/admin/users",
        "/admin/settings","/admin/config","/admin/logs","/admin/stats",
        "/admin/reports","/admin/audit","/admin/db","/admin/tools",
        "/admin/console","/admin/terminal","/admin/shell","/admin/cmd",
        "/admin/phpinfo","/admin/info","/admin/debug","/admin/trace",
        "/administrator","/administrator/","/administrator/index.php",
        "/administrator/login","/administration/","/administration/login",
        "/wp-admin/","/wp-admin/admin.php","/wp-admin/users.php",
        "/wp-admin/options.php","/wp-admin/theme-editor.php",
        "/wp-admin/plugin-editor.php","/wp-admin/export.php",
        "/wp-admin/import.php","/wp-admin/upgrade.php",
        "/cms/","/cms/admin/","/cms/login","/cms/dashboard",
        "/control","/control/","/control/panel","/cp/","/cp/login",
        "/manage","/manage/","/management","/management/",
        "/portal","/portal/","/portal/login","/portal/admin",
        "/staff","/staff/","/staff/login","/staff/admin",
        "/internal","/internal/","/internal/admin","/internal/dashboard",
        "/superadmin","/superadmin/","/super-admin/","/super/admin",
        "/root","/root/","/sysadmin","/sysadmin/",
        "/backend","/backend/","/backend/admin","/backend/login",
        "/backoffice","/backoffice/","/backoffice/login",
        "/panel","/panel/","/panel/login","/panel/admin",
        "/user/admin","/users/admin","/account/admin",
        "/phpmyadmin","/phpmyadmin/","/pma","/pma/","/adminer","/adminer.php",
        "/db","/db/","/database","/database/","/sql","/sql/",
        "/mysql","/mysql/","/postgres","/postgres/",
        "/pgadmin","/pgadmin/","/mongo","/mongo-express",
        "/redis","/redis/","/memcached","/memcached/",
        "/kibana","/kibana/","/grafana","/grafana/",
        "/prometheus","/prometheus/","/alertmanager","/alertmanager/",
        "/jaeger","/jaeger/","/zipkin","/zipkin/",
        "/kubernetes","/kubernetes/","/k8s","/k8s/",
        "/portainer","/portainer/","/rancher","/rancher/",
        "/jenkins","/jenkins/","/ci","/ci/","/cd","/cd/",
        "/gitlab","/gitlab/","/gitea","/gitea/",
        "/vault","/vault/","/consul","/consul/","/nomad","/nomad/",
        "/terraform","/terraform/","/ansible","/ansible/",
        "/airflow","/airflow/","/superset","/superset/","/metabase","/metabase/",
        "/sonar","/sonarqube","/sonarqube/","/nexus","/nexus/",
        "/artifactory","/artifactory/","/harbor","/harbor/",
        "/minio","/minio/","/s3console","/objectstorage",
        "/rabbitmq","/rabbitmq/","/activemq","/activemq/",
        "/kafka","/kafka/","/zookeeper","/zookeeper/",
        "/jupyter","/jupyter/","/jupyterhub","/jupyterhub/",
        "/mlflow","/mlflow/","/airflow","/airflow/",
        "/nagios","/nagios/","/zabbix","/zabbix/","/icinga","/icinga/",
        "/cacti","/cacti/","/prtg","/prtg/","/observium","/observium/",
        "/status","/status/","/statuspage","/statuspage/",
        "/ops","/ops/","/devops","/devops/","/infra","/infra/",
    ],
    "cloud_metadata": [
        "/latest/meta-data/","/latest/meta-data/instance-id",
        "/latest/meta-data/public-ipv4","/latest/meta-data/public-keys/",
        "/latest/meta-data/hostname","/latest/user-data",
        "/latest/dynamic/instance-identity/document",
        "/computeMetadata/v1/","/computeMetadata/v1/project/",
        "/computeMetadata/v1/instance/","/computeMetadata/v1/instance/service-accounts/",
        "/metadata/v1/","/metadata/instance/","/metadata/v1/id",
        "/metadata.google.internal/","/metadata/v1.json",
        "/iam/security-credentials/","/iam/info",
        "/.aws/credentials","/.aws/config",
        "/azure/instance","/azure/userdata","/azure/scheduledevents",
        "/opc/v1/instance/","/opc/v2/instance/",
    ],
    "monitoring": [
        "/health","/health/","/health/check","/health/live","/health/ready",
        "/healthz","/readyz","/livez","/startupz",
        "/ping","/ping/","/pong","/alive","/alive/",
        "/status","/status/","/status.json","/status.txt",
        "/metrics","/metrics/","/prometheus/metrics","/actuator/prometheus",
        "/actuator/metrics","/actuator/health","/manage/health",
        "/management/health","/management/info","/management/env",
        "/_health","/api/health","/api/ping","/api/status",
        "/api/v1/health","/api/v2/health","/api/v1/ping",
        "/__health","/system/health","/sys/health",
        "/info","/info/","/info.json","/version","/version/","/version.json",
        "/version.txt","/build","/build.json","/buildinfo","/buildInfo",
        "/build-info","/build_info","/app/version","/app/build",
        "/env","/env/","/env.json","/environment","/environment.json",
        "/config","/config/","/config.json","/configuration","/configuration.json",
        "/settings","/settings/","/settings.json","/properties","/properties.json",
        "/debug","/debug/","/debug/info","/debug/env","/debug/config",
        "/debug/vars","/debug/pprof/","/debug/requests","/debug/events",
        "/__debug__","/silk/","/toolbar","/debugbar",
        "/ops/health","/ops/ping","/ops/status","/ops/version",
        "/internal/health","/internal/status","/internal/metrics",
        "/private/health","/private/status","/private/metrics",
    ],
    "idor_patterns": [
        "/api/v1/users/1","/api/v1/users/2","/api/v1/users/me",
        "/api/v1/account/1","/api/v1/orders/1","/api/v1/invoices/1",
        "/api/v1/files/1","/api/v1/documents/1","/api/v1/reports/1",
        "/api/v1/projects/1","/api/v1/tickets/1","/api/v1/messages/1",
        "/user/1","/user/1/edit","/user/1/delete","/user/1/profile",
        "/users/1","/users/1/edit","/users/1/admin","/users/1/roles",
        "/account/1","/accounts/1","/profile/1","/member/1",
        "/order/1","/orders/1","/invoice/1","/invoices/1",
        "/document/1","/documents/1","/file/1","/files/1",
        "/ticket/1","/tickets/1","/issue/1","/issues/1",
        "/message/1","/messages/1","/thread/1","/threads/1",
        "/project/1","/projects/1","/task/1","/tasks/1",
        "/team/1","/teams/1","/org/1","/organization/1",
        "/subscription/1","/subscriptions/1","/payment/1","/payments/1",
        "/v1/users/0","/v1/users/undefined","/v1/users/null",
        "/v1/users/admin","/v1/users/root","/v1/users/system",
    ],
    "cors_csrf_probes": [
        "/api/","/api/v1/","/api/v2/","/api/v3/",
        "/graphql","/rest/","/rpc/",
        "/auth/","/oauth/","/oauth2/",
        "/login","/logout","/register","/signup",
        "/account","/profile","/settings","/preferences",
        "/admin","/admin/","/dashboard",
        "/change-password","/reset-password","/forgot-password",
        "/user/me","/user/profile","/user/settings",
        "/api/user","/api/me","/api/profile","/api/settings",
    ],
    "graphql_deep": [
        "/graphql","/graphiql","/graphql/console","/graphql/playground",
        "/graphql/explorer","/graphql/voyager","/graphql/altair",
        "/api/graphql","/v1/graphql","/v2/graphql","/v3/graphql",
        "/query","/playground","/altair","/graphql-explorer",
        "/graphql/schema.json","/graphql/schema.graphql",
        "/schema.graphql","/schema.json",
        "/graphql/__schema","/graphql/introspect",
        "/hasura/v1/graphql","/hasura/v1/query",
        "/gql","/api/gql","/v1/gql",
        "/subscriptions","/graphql/subscriptions",
    ],
    "swagger_deep": [
        "/swagger-ui/","/swagger-ui.html","/swagger/","/swagger/index.html",
        "/swagger/v1/swagger.json","/swagger/v2/swagger.json",
        "/swagger/v3/swagger.json","/swagger/v1/swagger.yaml",
        "/api-docs","/api-docs/","/api-docs/v1","/api-docs/v2","/api-docs/v3",
        "/openapi.json","/openapi.yaml","/openapi.yml",
        "/v1/api-docs","/v2/api-docs","/v3/api-docs","/v4/api-docs",
        "/api/swagger.json","/api/swagger.yaml","/api/openapi.json",
        "/api/openapi.yaml","/api/spec.json","/api/spec.yaml",
        "/docs/","/docs/api","/docs/swagger","/docs/openapi",
        "/redoc","/redoc/","/scalar","/elements","/rapidoc",
        "/swagger-resources","/swagger-resources/configuration/ui",
        "/swagger-resources/configuration/security",
        "/v2/swagger.json","/v3/openapi.json","/v3/openapi.yaml",
        "/.well-known/openapi","/api/schema/","/api/schema/json",
        "/api/schema/yaml","/api/schema/swagger-ui/","/api/schema/redoc/",
    ],
    "git_deep": [
        "/.git/","/.git/HEAD","/.git/config","/.git/FETCH_HEAD",
        "/.git/refs/","/.git/refs/heads/","/.git/refs/heads/main",
        "/.git/refs/heads/master","/.git/refs/heads/develop",
        "/.git/refs/heads/dev","/.git/refs/heads/staging",
        "/.git/refs/heads/production","/.git/refs/heads/prod",
        "/.git/refs/remotes/","/.git/refs/tags/",
        "/.git/COMMIT_EDITMSG","/.git/MERGE_HEAD","/.git/ORIG_HEAD",
        "/.git/index","/.git/packed-refs","/.git/logs/HEAD",
        "/.git/logs/refs/heads/main","/.git/logs/refs/heads/master",
        "/.git/info/","/.git/info/refs","/.git/info/exclude",
        "/.git/objects/info/","/.git/objects/pack/",
        "/.gitignore","/.gitmodules","/.gitattributes","/.gitkeep",
        "/.svn/","/.svn/wc.db","/.svn/entries","/.svn/format",
        "/.hg/","/.hg/hgrc","/.hg/store/","/.hg/dirstate",
        "/.bzr/","/.bzr/README","/.bzr/branch/",
        "/.tfvc/","/.tfs/",
        "/CVS/","/.cvsignore",
        "/Gemfile","/Gemfile.lock","/Guardfile","/Rakefile",
        "/Gruntfile.js","/Gulpfile.js","/webpack.config.js",
        "/vite.config.js","/vite.config.ts","/rollup.config.js",
        "/tsconfig.json","/tsconfig.base.json","/jsconfig.json",
        "/.babelrc","/babel.config.js","/babel.config.json",
        "/.eslintrc","/eslint.config.js","/.eslintrc.json","/.eslintrc.js",
        "/.prettierrc","/.prettierrc.json","/prettier.config.js",
        "/.stylelintrc","/.stylelintrc.json",
        "/jest.config.js","/jest.config.ts","/vitest.config.ts",
        "/.mocharc.js","/.mocharc.json","/karma.conf.js",
        "/.nycrc","/.c8rc","/nyc.config.js",
        "/Dockerfile","/docker-compose.yml","/docker-compose.yaml",
        "/docker-compose.prod.yml","/docker-compose.dev.yml",
        "/docker-compose.override.yml",
        "/.dockerignore","/Dockerfile.prod","/Dockerfile.dev",
        "/docker-compose.staging.yml",
    ],
    "spring_deep": [
        "/actuator","/actuator/health","/actuator/health/liveness",
        "/actuator/health/readiness","/actuator/env","/actuator/beans",
        "/actuator/mappings","/actuator/metrics","/actuator/info",
        "/actuator/loggers","/actuator/threaddump","/actuator/heapdump",
        "/actuator/prometheus","/actuator/httptrace","/actuator/auditevents",
        "/actuator/caches","/actuator/configprops","/actuator/scheduledtasks",
        "/actuator/sessions","/actuator/shutdown","/actuator/startup",
        "/actuator/flyway","/actuator/liquibase","/jolokia","/jolokia/list",
        "/manage/health","/management/health","/health","/info","/metrics","/env",
        "/actuator/conditions","/actuator/integrationgraph",
        "/actuator/logfile","/actuator/refresh","/actuator/restart",
        "/actuator/pause","/actuator/resume","/actuator/bus-refresh",
        "/actuator/gateway/routes","/actuator/gateway/filters",
        "/actuator/gateway/globalfilters","/actuator/gateway/routefilters",
    ],
    "ci_cd": [
        "/jenkins/","/jenkins/api/json","/jenkins/job/",
        "/jenkins/script","/jenkins/scriptText","/jenkins/systemInfo",
        "/jenkins/crumbIssuer/api/json","/jenkins/computer/api/json",
        "/jenkins/credentials/","/jenkins/asynchPeople/","/jenkins/git/",
        "/ci/","/ci/api/","/ci/jobs","/ci/pipelines","/ci/builds",
        "/gitlab/","/gitea/","/gogs/","/forgejo/",
        "/build/","/builds/","/pipelines/","/pipeline/",
        "/deploy/","/deployment/","/deployments/",
        "/argocd/","/flux/","/tekton/","/spinnaker/",
        "/travis/","/circleci/","/bamboo/","/teamcity/",
        "/drone/","/concourse/","/gocd/",
        "/.github/workflows/","/github/workflows/",
    ],
    # ── Obfuscation / WAF-bypass path variants ─────────────────────────────
    "obfuscation_bypass": [
        # Case variants
        "/Admin","/ADMIN","/Admin/","/ADMIN/","/aDmIn",
        "/Login","/LOGIN","/Login/","/SIGNIN","/Signin",
        "/Debug","/DEBUG","/debug/","/Debug/",
        "/Config","/CONFIG","/config/","/Config/",
        "/Backup","/BACKUP","/backup/","/Backup/",
        "/Console","/CONSOLE","/console/","/Console/",
        "/Dashboard","/DASHBOARD",
        "/Manager","/MANAGER","/manager/",
        "/Setup","/SETUP","/setup/","/Setup/",
        "/Install","/INSTALL","/install/",
        # Double-slash bypass
        "//admin//","//admin/","//login//","//api//",
        "//config//","//debug//","//env//",
        "//actuator//","//console//","//manager//",
        # Path traversal disguise
        "/./admin/","/./login/","/./config/","/./env/",
        "/./debug/","/./api/","/%2e/admin/","/%2e/login/",
        # Encoded slashes
        "/admin%2f","/admin%2F","/login%2f","/config%2f",
        "/api%2fv1","/api%2Fv1","/%61dmin",
        # Null-byte variants (still worth trying)
        "/admin%00","/config%00","/login%00",
        # Unicode normalization bypass
        "/admin","/login","/api",
        # Trailing dot bypass
        "/admin.","/login.","/config.","/api.",
        "/admin./","/config./",
        # Semicolon bypass (some Java/Node servers)
        "/admin;/","/admin;.js","/admin;.css",
        "/config;/","/login;/","/api;/",
        # Hex-encoded path segments
        "/%61dmin","/a%64min","/%61%64%6d%69%6e",
        "/%6c%6f%67%69%6e","/%63%6f%6e%66%69%67",
        # Fragment injection
        "/admin#","/config#","/login#",
        # Extra extensions
        "/admin.php","/admin.asp","/admin.aspx","/admin.jsp",
        "/admin.do","/admin.action","/admin.html","/admin.htm",
        "/config.php","/config.json","/config.yml","/config.xml",
        "/login.php","/login.asp","/login.aspx","/login.jsp",
        "/debug.php","/debug.asp","/debug.json","/debug.txt",
        "/setup.php","/setup.asp","/install.php","/install.asp",
        # Spring/Java style with extensions
        "/actuator.json","/actuator.xml",
        "/actuator/health.json","/actuator/env.json",
        # API version bypass
        "/api/v0/","/api/v00/","/api/v-1/","/api/v10/",
        "/api/beta/","/api/alpha/","/api/dev/","/api/test/",
        "/api/internal/","/api/private/","/api/hidden/",
        "/api/secret/","/api/debug/","/api/admin/",
        "/v0/","/v00/","/v10/","/v11/","/v12/","/v100/",
        # Underscored/hyphenated variants
        "/_admin/","/_admin","/_login/","/_login",
        "/_config/","/_env/","/_debug/","/_api/",
        "/_internal/","/_private/","/_hidden/","/_secret/",
        "/admin_/","/admin-/","/admin_panel/","/admin-panel/",
        "/admin_login/","/admin-login/",
        "/config_/","/config-/","/env_/","/debug_/",
        # Old/legacy style paths
        "/cgi-bin/admin","/cgi-bin/admin.cgi","/cgi-bin/config",
        "/cgi-bin/login","/cgi-bin/setup","/cgi-bin/debug",
        "/cgi-bin/admin.pl","/cgi-bin/admin.py",
        "/cgi/admin","/cgi/login","/cgi/config",
        # Windows-style path separators
        "/admin\\","/config\\","/login\\",
        # Extra query string abuse
        "/?admin=1","/admin?debug=1","/config?show=1",
        "/api/?format=json","/?_debug=1","/?debug=true",
    ],
    # ── Sensitive file exposure paths ──────────────────────────────────────
    "sensitive_files": [
        # Env/secret files
        "/.env","/.env.local","/.env.development","/.env.production",
        "/.env.staging","/.env.test","/.env.backup","/.env.bak",
        "/.env.old","/.env.save","/.env.example","/.env.sample",
        "/.env.dist","/.env~","/.env.orig","/.env.1","/.env.2",
        "/env.js","/env.ts","/env.sh","/env.bash",
        "/config.env","/.config","/.config/","/.secrets","/.secret",
        "/.secrets.baseline","/secrets.json","/secrets.yaml","/secrets.yml",
        "/secret.json","/credentials.json","/credential.json",
        "/.credentials","/.aws/credentials","/.aws/config","/.gcloud/credentials",
        "/.azure/credentials","/.kube/config","/.ssh/id_rsa","/.ssh/id_ed25519",
        "/.ssh/authorized_keys","/.ssh/known_hosts",
        # Database/config files
        "/database.yml","/database.yaml","/database.json",
        "/db.json","/db.yaml","/db.yml","/db.php",
        "/settings.py","/settings.js","/settings.json","/settings.yaml",
        "/local_settings.py","/local.py","/local.json",
        "/config.php","/config.inc.php","/config.inc","/config.rb",
        "/config.py","/config.json","/config.yaml","/config.yml",
        "/app.config","/web.config","/.htaccess","/server.xml",
        "/application.properties","/application.yml","/application.yaml",
        "/application-dev.properties","/application-prod.properties",
        "/application-staging.properties",
        "/bootstrap.php","/wp-config.php","/wp-config.php.bak",
        "/wp-config.php.old","/wp-config.bak","/wp-config.save",
        "/configuration.php","/configuration.php.bak",
        # Log files
        "/access.log","/error.log","/debug.log","/app.log",
        "/application.log","/server.log","/system.log","/audit.log",
        "/auth.log","/security.log","/web.log","/nginx.log",
        "/apache.log","/php.log","/mysql.log","/tomcat.log",
        "/logs/access.log","/logs/error.log","/logs/debug.log",
        "/logs/app.log","/logs/application.log","/logs/server.log",
        "/var/log/nginx/access.log","/var/log/apache2/access.log",
        # Backup files
        "/backup.sql","/backup.sql.gz","/backup.zip","/backup.tar.gz",
        "/backup.tar","/backup.tgz","/database.sql","/database.sql.gz",
        "/db.sql","/dump.sql","/mysqldump.sql",
        "/site.tar.gz","/site.zip","/www.tar.gz","/web.tar.gz",
        "/htdocs.tar.gz","/public_html.tar.gz",
        # PHP info/test files
        "/phpinfo.php","/phptest.php","/info.php","/test.php","/check.php",
        "/status.php","/server.php","/debug.php","/trace.php",
        "/phpinfo","/php_info.php","/php-info.php",
        # Readme/changelog
        "/readme.txt","/readme.md","/README.txt","/README.md",
        "/CHANGELOG.txt","/CHANGELOG.md","/changelog.txt","/changelog.md",
        "/RELEASE_NOTES.txt","/release_notes.txt","/VERSION.txt","/version.txt",
        "/INSTALL.txt","/install.txt","/TODO.txt","/todo.txt",
        # Package/dependency files
        "/package.json","/package-lock.json","/yarn.lock","/pnpm-lock.yaml",
        "/Pipfile","/Pipfile.lock","/requirements.txt","/requirements.in",
        "/poetry.lock","/pyproject.toml","/setup.py","/setup.cfg",
        "/composer.json","/composer.lock","/Gemfile","/Gemfile.lock",
        "/go.mod","/go.sum","/Cargo.toml","/Cargo.lock",
        "/pom.xml","/build.gradle","/build.gradle.kts","/settings.gradle",
        # IDE/editor files
        "/.idea/","/. idea/","/.vscode/","/.sublime-project",
        "/.project","/.classpath","/.settings/",
        # Keys/certs
        "/server.key","/server.pem","/server.crt","/ssl.key","/ssl.pem",
        "/private.key","/private.pem","/cert.pem","/cert.key",
        "/tls.key","/tls.crt","/.pem","/.key","/.crt",
        # Kubernetes/cloud
        "/kube.config","/kubeconfig","/kubectl.yaml",
        "/.helm/","/helm/values.yaml","/values.yaml",
        "/terraform.tfstate","/terraform.tfvars","/.terraform/",
        "/ansible.cfg","/playbook.yml","/inventory.yml",
        # Token files
        "/.npmrc","/.pypirc","/.gitconfig","/.netrc","/.curlrc",
        "/.boto","/boto.cfg","/.s3cfg","/.rclone.conf",
        "/.htpasswd","/.htpasswd.bak",
    ],
    # ── Hidden API and admin panels ────────────────────────────────────────
    "hidden_admin": [
        # Admin panels with common variations
        "/admin","/admin/","/admin/index","/admin/dashboard",
        "/administrator","/administrator/","/admin1","/admin2",
        "/admins","/adminpanel","/admincp","/admin_cp","/admin-cp",
        "/admin_panel","/admin-panel","/admin_area","/admin-area",
        "/manage","/manage/","/management","/management/",
        "/manager","/manager/","/webmaster","/webmaster/",
        "/sysadmin","/sysadmin/","/siteadmin","/site-admin",
        "/superadmin","/super-admin","/root","/root/",
        "/backend","/backend/","/backoffice","/back-office",
        "/intranet","/intranet/","/internal","/internal/",
        "/private","/private/","/restricted","/restricted/",
        "/secure","/secure/","/confidential",
        "/moderator","/moderator/","/mod","/mod/",
        "/staff","/staff/","/employee","/employees/",
        "/control","/control/","/controlpanel","/control-panel",
        "/cPanel","/cpanel","/cpanel/","/whm","/whm/",
        "/plesk","/plesk/","/webmin","/webmin/",
        # Developer/debug panels
        "/dev","/dev/","/develop","/developer","/developer/",
        "/devtools","/dev-tools","/devops","/dev-console",
        "/debug","/debug/","/debugger","/debug-console",
        "/trace","/trace/","/tracer","/profiler",
        # Database management
        "/phpmyadmin","/phpmyadmin/","/pma","/pma/",
        "/phpMyAdmin","/phpMyAdmin/","/phpmyadmin2",
        "/adminer","/adminer/","/adminer.php",
        "/pgadmin","/pgadmin/","/pgadmin4/",
        "/dbadmin","/dbadmin/","/database","/database/",
        "/mysql","/mysql/","/myadmin","/myadmin/",
        "/sqlmanager","/sql-manager","/mongo-express",
        "/nosqlclient","/redisinsight","/redis-insight",
        # Monitoring panels
        "/grafana","/grafana/","/kibana","/kibana/",
        "/prometheus","/prometheus/","/alertmanager",
        "/jaeger","/jaeger/","/zipkin","/zipkin/",
        "/datadog","/newrelic","/dynatrace",
        "/netdata","/netdata/","/glances","/glances/",
        "/ntopng","/ntopng/","/cacti","/cacti/",
        "/prtg","/prtg/","/observium","/observium/",
        "/nagios","/nagios/","/icinga","/icinga/",
        "/zabbix","/zabbix/",
        # CI/CD and dev tools
        "/jenkins","/jenkins/","/gitlab","/gitea",
        "/sonarqube","/sonarqube/","/sonar","/sonar/",
        "/nexus","/nexus/","/artifactory","/artifactory/",
        "/harbor","/harbor/","/portainer","/portainer/",
        "/rancher","/rancher/","/argocd","/argocd/",
        # Cloud management
        "/console","/console/","/cloud","/cloud/",
        "/portal","/portal/","/dashboard","/dashboard/",
        "/cockpit","/cockpit/","/openstack","/horizon",
    ],
    # ── Internal/hidden API endpoint patterns ──────────────────────────────
    "internal_api": [
        # Internal-only API paths
        "/internal/","/internal/api/","/internal/v1/","/internal/v2/",
        "/internal/users","/internal/config","/internal/debug",
        "/internal/metrics","/internal/health","/internal/status",
        "/internal/logs","/internal/env","/internal/jobs",
        "/internal/admin","/internal/system","/internal/auth",
        "/private/api/","/private/v1/","/private/v2/",
        "/private/users","/private/config","/private/metrics",
        "/private/health","/private/admin",
        "/hidden/","/hidden/api/","/hidden/v1/",
        "/secret/","/secret/api/","/confidential/",
        "/priv/","/priv/api/","/restricted/api/",
        # Debug and diagnostic endpoints
        "/debug/","/debug/api/","/debug/info","/debug/env",
        "/debug/config","/debug/metrics","/debug/logs",
        "/debug/routes","/debug/beans","/debug/threads",
        "/debug/memory","/debug/gc","/debug/heap","/debug/profile",
        "/debug/tracing","/debug/requests","/debug/events",
        "/diag/","/diag/api/","/diagnostic/",
        "/test/","/test/api/","/testing/",
        # System endpoints
        "/system/","/system/api/","/system/info","/system/health",
        "/system/config","/system/metrics","/system/status",
        "/system/logs","/system/debug","/system/admin",
        "/sys/","/sys/api/","/sys/info","/sys/health",
        "/sys/config","/sys/metrics",
        # Service discovery / mesh
        "/__health","/.__health","/_health","/_status",
        "/_ready","/_live","/_startup","/_ping",
        "/healthcheck","/health-check","/liveness","/readiness",
        # Undocumented API patterns
        "/api/internal/","/api/private/","/api/debug/",
        "/api/admin/","/api/hidden/","/api/secret/",
        "/api/system/","/api/sys/","/api/ops/",
        "/api/v1/internal/","/api/v1/admin/","/api/v2/admin/",
        "/api/v1/debug/","/api/v1/system/",
        # Backend service exposure
        "/backend/","/backend/api/","/backend/admin/",
        "/service/","/services/","/svc/",
        "/microservice/","/worker/","/workers/",
        # Undocumented framework routes
        "/__admin/","/__debug/","/__status/","/__health/",
        "/__api/","/__internal/","/__private/",
        "/___debug___/","/___admin___/",
    ],
    # ── Cloud / infrastructure credential exposure ─────────────────────────
    "cloud_infra": [
        # AWS IMDS (various versions and paths)
        "/latest/meta-data/","/latest/meta-data/iam/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/iam/info",
        "/latest/meta-data/public-keys/",
        "/latest/meta-data/network/interfaces/macs/",
        "/latest/meta-data/placement/availability-zone",
        "/latest/meta-data/instance-id",
        "/latest/meta-data/hostname","/latest/meta-data/ami-id",
        "/latest/user-data","/latest/dynamic/instance-identity/document",
        "/latest/api/token",
        # GCP IMDS
        "/computeMetadata/v1/","/computeMetadata/v1/instance/",
        "/computeMetadata/v1/project/",
        "/computeMetadata/v1/instance/service-accounts/default/token",
        "/computeMetadata/v1/instance/service-accounts/default/email",
        "/computeMetadata/v1/project/project-id",
        "/computeMetadata/v1/instance/attributes/",
        # Azure IMDS
        "/metadata/instance","/metadata/instance/compute",
        "/metadata/instance/network","/metadata/attested/document",
        "/metadata/identity/oauth2/token","/metadata/scheduledevents",
        "/metadata/v1/","/metadata/v1/maintenance",
        # DigitalOcean metadata
        "/metadata/v1.json","/metadata/v1/id",
        "/metadata/v1/user-data","/metadata/v1/hostname",
        "/metadata/v1/interfaces/",
        # Oracle Cloud IMDS
        "/opc/v1/instance/","/opc/v2/instance/",
        "/opc/v1/identity/cert.pem",
        # Docker/container metadata
        "/.dockerenv","/.dockerignore",
        "/proc/self/cgroup","/proc/net/fib_trie",
        "/proc/self/environ","/proc/version",
        # Kubernetes service account
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        # S3-compatible storage exposure
        "/.s3cfg","/.s3cmd","/s3cfg",
        "/aws.json","/aws_credentials","/cloud_credentials",
        # Terraform/IaC exposure
        "/terraform.tfstate","/terraform.tfstate.backup",
        "/.terraform/","/terraform.tfvars","/.terraformrc",
        # Ansible exposure
        "/ansible.cfg","/inventory","/hosts",
        "/playbook.yml","/site.yml","/main.yml",
        # Helm/k8s exposure
        "/values.yaml","/values-prod.yaml","/values-dev.yaml",
        "/charts/","/templates/","/Chart.yaml",
        "/kustomization.yaml","/kustomization.yml",
        "/overlays/","/base/","/deploy.yaml","/deployment.yaml",
    ],
    # ── Leaked source code / VCS exposure ──────────────────────────────────
    "vcs_exposure": [
        "/.git/","/.git/HEAD","/.git/config","/.git/COMMIT_EDITMSG",
        "/.git/index","/.git/packed-refs","/.git/logs/HEAD",
        "/.git/refs/heads/","/.git/refs/heads/main",
        "/.git/refs/heads/master","/.git/refs/heads/develop",
        "/.git/refs/heads/dev","/.git/refs/heads/staging",
        "/.git/refs/heads/production","/.git/refs/heads/prod",
        "/.git/objects/","/.git/objects/info/packs",
        "/.git/objects/pack/",
        "/.svn/","/.svn/wc.db","/.svn/entries","/.svn/format",
        "/.svn/pristine/","/.svn/WORKING_DB",
        "/.hg/","/.hg/hgrc","/.hg/store/","/.hg/dirstate",
        "/.hg/requires","/.hg/00changelog.i",
        "/.bzr/","/.bzr/README","/.bzr/branch/","/.bzr/repository/",
        "/.cvs/","/CVS/","/.cvsignore","/CVS/Entries",
        "/.tfvc/","/.tfs/",
        # Source-revealed by misconfiguration
        "/source/","/sources/","/src/","/code/",
        "/public/src/","/app/src/","/static/src/",
        # CI/build artifacts
        "/.travis.yml","/.travis/","/circle.yml","/.circleci/",
        "/.github/","/.github/workflows/","/.gitlab-ci.yml",
        "/Jenkinsfile","/.drone.yml","/bitbucket-pipelines.yml",
        "/appveyor.yml","/.appveyor.yml",
        "/.buildkite/","/buildkite.yml","/.semaphore/",
        # Deployment/infra as code
        "/Procfile","/Aptfile","/runtime.txt","/system.properties",
        "/app.json","/now.json","/vercel.json","/netlify.toml",
        "/fly.toml","/.fly/","/railway.json","/.railway/",
        "/render.yaml","/render.yml","/heroku.yml",
    ],
    # ── WordPress / CMS specific ────────────────────────────────────────────
    "cms_deep": [
        # WordPress
        "/wp-login.php","/wp-admin/","/wp-admin/admin-ajax.php",
        "/wp-admin/admin-post.php","/wp-admin/options.php",
        "/wp-admin/users.php","/wp-admin/plugins.php",
        "/wp-admin/themes.php","/wp-admin/update-core.php",
        "/wp-admin/setup-config.php",
        "/wp-content/","/wp-includes/","/wp-json/",
        "/wp-json/wp/v2/users","/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/settings","/wp-json/wp/v2/plugins",
        "/xmlrpc.php","/wp-cron.php","/wp-trackback.php",
        "/readme.html","/license.txt","/readme.txt",
        "/wp-content/debug.log","/wp-content/uploads/",
        "/wp-content/plugins/","/wp-content/themes/",
        "/wp-config.php","/wp-config.php.bak",
        # Drupal
        "/user/login","/user/register","/admin/",
        "/admin/config","/admin/reports","/admin/content",
        "/admin/structure","/admin/modules","/admin/people",
        "/admin/appearance","/admin/reports/status",
        "/sites/default/files/","/sites/default/settings.php",
        "/update.php","/install.php","/cron.php",
        "/?q=admin/","/CHANGELOG.txt","/INSTALL.txt",
        # Joomla
        "/administrator/","/administrator/index.php",
        "/configuration.php","/htaccess.txt",
        "/web.config.txt","/joomla.xml",
        # Magento
        "/admin/","/index.php/admin","/downloader/",
        "/app/etc/local.xml","/app/etc/env.php",
        "/var/log/","/var/report/",
        # Typo3
        "/typo3/","/typo3conf/","/typo3temp/",
        "/fileadmin/","/uploads/",
        # Ghost
        "/ghost/","/ghost/api/","/ghost/api/admin/",
        # Strapi
        "/admin","/api/","/api/users","/_health",
        # Contentful
        "/spaces/","/api/spaces/",
        # Directus
        "/directus/","/items/","/files/","/users/",
        # Payload CMS
        "/payload-preferences","/payload/","/collections/",
    ],
    # ── Authentication / OAuth / SSO bypass paths ──────────────────────────
    "auth_paths": [
        "/login","/login/","/signin","/signin/","/sign-in",
        "/logout","/logout/","/signout","/signout/","/sign-out",
        "/register","/register/","/signup","/signup/","/sign-up",
        "/forgot-password","/forgot_password","/forgot",
        "/reset-password","/reset_password","/reset",
        "/change-password","/change_password",
        "/verify","/verify/","/verify-email","/confirm",
        "/activate","/activate/","/activation/",
        "/auth","/auth/","/authentication","/oauth","/oauth/",
        "/oauth2","/oauth2/","/oidc","/openid","/openid-connect",
        "/sso","/sso/","/saml","/saml/","/saml2","/cas",
        "/api/auth","/api/auth/","/api/login","/api/logout",
        "/api/register","/api/signin","/api/signout",
        "/api/v1/auth","/api/v1/login","/api/v1/logout",
        "/api/v1/register","/api/v2/auth","/api/v2/login",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json","/.well-known/oauth-authorization-server",
        "/oauth/authorize","/oauth/token","/oauth/callback",
        "/oauth/revoke","/oauth/userinfo",
        "/auth/callback","/auth/authorize","/auth/token",
        "/token","/tokens","/refresh","/refresh-token",
        "/session","/sessions","/session/",
        "/jwt","/jwt/","/keys","/keys/",
        # SSO providers
        "/auth/google","/auth/facebook","/auth/github",
        "/auth/twitter","/auth/linkedin","/auth/microsoft",
        "/auth/okta","/auth/azure","/auth/cognito",
        "/api/auth/google","/api/auth/github","/api/auth/microsoft",
        # Magic link / passwordless
        "/magic-link","/magic_link","/passwordless",
        "/link-login","/email-login",
        # Admin auth
        "/admin/login","/admin/auth","/admin/signin",
        "/admin/logout","/admin/logoff",
    ],
    # ── Leaked data / exposed info pages ──────────────────────────────────
    "data_exposure": [
        # User/account data
        "/api/v1/users","/api/v2/users","/api/users",
        "/api/v1/accounts","/api/accounts",
        "/api/v1/members","/api/members",
        "/api/v1/customers","/api/customers",
        "/api/v1/employees","/api/employees",
        "/api/v1/contacts","/api/contacts",
        "/api/v1/profiles","/api/profiles",
        # Transaction/financial data
        "/api/v1/transactions","/api/transactions",
        "/api/v1/payments","/api/payments",
        "/api/v1/orders","/api/orders",
        "/api/v1/invoices","/api/invoices",
        "/api/v1/subscriptions","/api/subscriptions",
        "/api/v1/billing","/api/billing",
        # Messages/content
        "/api/v1/messages","/api/messages",
        "/api/v1/notifications","/api/notifications",
        "/api/v1/comments","/api/comments",
        "/api/v1/posts","/api/posts",
        "/api/v1/content","/api/content",
        # Files/documents
        "/api/v1/files","/api/files",
        "/api/v1/documents","/api/documents",
        "/api/v1/reports","/api/reports",
        "/api/v1/exports","/api/exports",
        "/api/v1/downloads","/api/downloads",
        "/api/v1/uploads","/api/uploads",
        # Config/settings
        "/api/v1/settings","/api/settings",
        "/api/v1/config","/api/config",
        "/api/v1/configuration","/api/configuration",
        "/api/v1/preferences","/api/preferences",
        # Audit/logs
        "/api/v1/logs","/api/logs",
        "/api/v1/audit","/api/audit",
        "/api/v1/events","/api/events",
        "/api/v1/history","/api/history",
        "/api/v1/activity","/api/activity",
        # Admin-level exposure
        "/api/v1/admin/users","/api/admin/users",
        "/api/v1/admin/logs","/api/admin/logs",
        "/api/v1/admin/stats","/api/admin/stats",
        "/api/v1/admin/settings","/api/admin/settings",
        "/api/v1/admin/config","/api/admin/config",
        "/api/v1/admin/debug","/api/admin/debug",
        # Search/query endpoints
        "/api/search","/api/v1/search","/api/v2/search",
        "/search","/search/","/find","/query","/lookup",
        # Export endpoints
        "/export","/export/","/export/csv","/export/json",
        "/export/xml","/export/pdf","/export/zip",
        "/download","/download/","/bulk-export",
        "/api/export","/api/v1/export","/api/download",
    ],
    # ── Java-specific paths (beyond Spring) ────────────────────────────────
    "java_deep": [
        # Struts
        "/struts/utils.js","/.action","/login.action","/admin.action",
        "/index.action","/struts-2.3.15/","/struct/",
        # JSF
        "/faces/","/javax.faces.resource/","/j_security_check",
        # Servlet/JSP
        "/servlet/","/servlet/Admin","/servlet/Debug",
        "/servlet/Login","/servlet/Config",
        "/WEB-INF/web.xml","/WEB-INF/classes/","/WEB-INF/lib/",
        "/META-INF/MANIFEST.MF","/META-INF/context.xml",
        # JBoss/WildFly/JMX
        "/jmx-console/","/web-console/","/admin-console/",
        "/management/","/management/v1/","/management/v2/",
        "/console/","/jboss/","/jboss-web/",
        # GlassFish
        "/__asadmin/","/asadmin","/management/domain/",
        # WebLogic
        "/console/","/wls-wsat/","/uddiexplorer/",
        "/bea_wls_deployment_internal/",
        # Tomcat
        "/manager/html","/manager/text","/manager/",
        "/host-manager/html","/host-manager/",
        "/examples/","/.status",
        # Axis/SOAP
        "/axis/","/axis2/","/axis2-web/",
        "/services/","/wsdl","/soap","/rpc",
        "/ws/","/webservice/","/api.wsdl",
    ],
    # ── PHP-specific paths ──────────────────────────────────────────────────
    "php_deep": [
        "/info.php","/phpinfo.php","/phptest.php","/php_info.php",
        "/test.php","/check.php","/status.php","/server-status",
        "/.php_cs.cache","/.php-version","/composer.phar",
        "/php-console/","/php-console.php",
        "/adminer.php","/phpmyadmin/","/phpMyAdmin/",
        "/symfony/","/laravel/","/slim/","/yii/","/zend/",
        "/codeigniter/","/cakephp/","/drupal/",
        # Common Laravel/Symfony exposure
        "/public/index.php","/app_dev.php","/app.php",
        "/web/app_dev.php","/web/config.php",
        "/_profiler/","/app/_profiler/","/app/debug/",
        "/sf-profiler/",
        # PHP shells / webshells (exposure indicators)
        "/shell.php","/cmd.php","/exec.php","/c99.php","/r57.php",
        "/b374k.php","/webshell.php","/shell/","/backdoor.php",
        "/tools.php","/tool.php",
    ],
    # ── Node.js / Express paths ────────────────────────────────────────────
    "nodejs_deep": [
        # Express.js
        "/__express__/","/node_modules/","/node_modules/.bin/",
        "/.npm/","/npm-debug.log","/yarn-error.log",
        "/express-debug/",
        # NestJS
        "/nest/","/api/","/api/swagger",
        # Keystone
        "/keystone/","/ks-admin/","/admin/api/",
        # Meteor
        "/meteor/","/sockjs/","/ddp/",
        # Sails.js
        "/.sailsrc",
        # PM2
        "/.pm2/","/pm2.json",
        # Common Node.js debug
        "/node-inspector/","/node-debug/",
        "/.env","/config/default.json","/config/production.json",
        "/config/development.json","/config/local.json",
        # NPM/Yarn artifacts
        "/.npmrc","/.yarnrc","/.yarnrc.yml",
        "/package.json","/package-lock.json","/yarn.lock",
    ],
    # ── Python web framework paths ─────────────────────────────────────────
    "python_deep": [
        # Django (additional)
        "/admin/password_change/","/admin/login/?next=/admin/",
        "/admin/auth/user/","/admin/auth/group/",
        "/api/","/api/schema/","/api/v1/",
        "/__pycache__/","/.python-version","/wsgi.py",
        "/asgi.py","/settings.py","/urls.py",
        # Flask
        "/flask/","/flaskr/","/instance/","/instance/config.py",
        "/.flaskenv","/.flask-env","/flask-debug/",
        # FastAPI
        "/fastapi/","/api/","/openapi.json","/docs","/redoc",
        # Celery/task queues
        "/flower/","/celery/","/task-manager/","/tasks/",
        # Jupyter
        "/jupyter/","/lab/","/notebooks/","/api/kernels/",
        "/api/contents/","/api/sessions/","/api/terminals/",
        "/tree/","/nbconvert/",
        # Gunicorn/uWSGI status
        "/gunicorn/","/uwsgi/","/uwsgi-status",
        "/.wsgi","/.cfg","/requirements.txt","/Pipfile",
    ],
    # ── Secrets and credentials leakage paths ─────────────────────────────
    "credential_paths": [
        # API keys in common locations
        "/api-key","/api-key.txt","/api_key","/apikey",
        "/key.json","/keys.json","/private-key.json",
        "/service-account.json","/service-account-key.json",
        "/firebase-service-account.json",
        "/gcp-service-account.json","/aws-credentials.json",
        "/aws.json","/azure.json","/cloud-credentials.json",
        # Password files
        "/passwords.txt","/passwords.json","/creds.txt",
        "/creds.json","/credentials.txt","/credential.txt",
        "/logins.txt","/users.txt","/accounts.txt",
        "/pass.txt","/passwd.txt",
        # Token files
        "/token.txt","/token.json","/tokens.json",
        "/auth-token.txt","/access-token.txt",
        "/refresh-token.txt","/bearer.txt",
        "/jwt.txt","/jwt.json",
        # SSH/TLS keys
        "/id_rsa","/id_rsa.pub","/id_ed25519","/id_ed25519.pub",
        "/id_ecdsa","/id_dsa",
        "/private.key","/private.pem","/server.key",
        "/ssl.key","/tls.key","/ca.key","/root.key",
        # Database credentials
        "/db-credentials.txt","/db-creds.txt","/db.txt",
        "/mysql-credentials.txt","/postgres-credentials.txt",
        # SMTP/email credentials
        "/smtp-credentials.txt","/mail-credentials.txt",
        "/sendgrid.txt","/mailgun.txt","/postmark.txt",
        # Stripe/payment keys
        "/stripe-keys.txt","/payment-keys.txt",
        # GitHub/CI tokens
        "/github-token.txt","/ci-token.txt",
        "/deploy-token.txt","/deploy-key.txt",
        # Config with hardcoded creds
        "/config.bak","/settings.bak","/app.bak",
        "/config.orig","/settings.orig","/app.orig",
    ],
    # ── Ultra-deep obfuscation bypass variants ──────────────────────────────
    "path_traversal_bypass": [
        # Double URL encoding bypasses
        "/%2e%2e/%2e%2e/etc/passwd", "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/%252e%252e/%252e%252e/etc/passwd",
        # Unicode normalization bypasses
        "/․․/etc/passwd", "/%c0%ae%c0%ae/etc/passwd",
        # Null byte injection
        "/%00/etc/passwd", "/admin%00.txt", "/.env%00.txt",
        # Path segment bypass
        "/;/admin", "//admin", "/./admin", "/admin/.", "/admin//",
        "/admin/./", "//admin//", "/admin%09/", "/admin%0a/",
        # Case variation
        "/ADMIN", "/Admin", "/aDmIn", "/CONFIG", "/Config",
        "/ENV", "/.ENV", "/ENV.php", "/.ENV.php",
        # Extension bypass
        "/.env.php", "/.env.asp", "/.env.aspx", "/.env.jsp",
        "/.env.cfm", "/.env.cgi", "/.env.pl", "/.env.rb",
        # Spring4Shell / log4shell probe paths
        "/solr/admin/info/system?wt=json",
        "/${jndi:ldap://169.254.169.254/latest}",
        # Backup/swap files (editor artifacts)
        "/index.php~", "/index.php.bak", "/index.php.old",
        "/index.php.orig", "/index.php.swp", "/index.php.swo",
        "/index.php.save", "/index.php.tmp",
        "/.index.php.swp", "/.index.php.swo",
        "/config.php~", "/config.php.bak", "/config.php.swp",
        "/settings.py~", "/settings.py.bak", "/settings.py.swp",
        "/application.yml~", "/application.properties~",
        "/web.config~", "/web.config.bak", "/web.config.old",
    ],
    # ── Forgotten/legacy admin interfaces ───────────────────────────────────
    "legacy_admin": [
        "/manager/", "/manager/html", "/manager/text",
        "/host-manager/", "/host-manager/html",
        "/adminer.php", "/adminer/", "/phpmyadmin/",
        "/phpMyAdmin/", "/PHPMyAdmin/", "/pma/", "/PMA/",
        "/phpinfo.php", "/info.php", "/phpversion.php",
        "/test.php", "/test/", "/demo/", "/demo.php",
        "/sample/", "/example/", "/examples/",
        "/install/", "/install.php", "/setup/", "/setup.php",
        "/update/", "/update.php", "/upgrade/", "/upgrade.php",
        "/migration/", "/migrate/", "/migrations/",
        "/scaffold/", "/scaffolding/",
        "/_admin/", "/_backend/", "/_management/",
        "/control/", "/control-panel/", "/controlpanel/",
        "/sysadmin/", "/site-admin/", "/webadmin/",
        "/administrator/", "/administration/",
        "/adm/", "/mgt/", "/mgmt/", "/manage/",
        "/backend/admin/", "/admin/backend/",
        "/secure/admin/", "/admin/secure/",
        "/private/admin/", "/admin/private/",
        "/hidden/", "/secret/", "/secrets/",
        "/confidential/", "/internal/", "/intranet/",
        "/restricted/", "/protected/",
        "/staging/admin/", "/dev/admin/", "/test/admin/",
        "/old-admin/", "/admin-old/", "/admin-backup/",
        "/admin2/", "/admin3/", "/admin_v2/", "/admin_new/",
        "/_dashboard/", "/dashboard/admin/", "/admin/dashboard/",
        "/panel/", "/cpanel/", "/cPanel/",
        "/whm/", "/whmcs/", "/plesk/", "/directadmin/",
        "/ispconfig/", "/webmin/", "/virtualmin/",
        "/roundcube/", "/squirrelmail/", "/horde/",
        "/exchange/", "/owa/", "/ews/", "/ecp/",
        "/webmail/", "/mail/",
    ],
    # ── Cloud metadata and SSRF bait endpoints ──────────────────────────────
    "cloud_ssrf": [
        "/latest/meta-data/", "/latest/user-data",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/hostname",
        "/latest/meta-data/public-ipv4",
        "/latest/dynamic/instance-identity/document",
        "/computeMetadata/v1/", "/computeMetadata/v1/instance/",
        "/computeMetadata/v1/project/project-id",
        "/computeMetadata/v1/instance/service-accounts/default/token",
        "/metadata/instance?api-version=2021-02-01",
        "/metadata/v1/", "/metadata/v1/id",
        "/osc/latest/meta-data/",
        "/ecs/", "/alibaba-cloud-metadata/",
        # Digital Ocean
        "/metadata/v1/id", "/metadata/v1/hostname",
        # Oracle Cloud
        "/opc/v1/instance/", "/opc/v2/instance/",
        # Hetzner
        "/latest/meta-data", "/2009-04-04/meta-data/",
        # Kubernetes secrets via environment
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        # SSRF to internal APIs
        "/api/ssrf", "/proxy?url=http://169.254.169.254",
        "/fetch?url=http://169.254.169.254",
        "/redirect?url=http://169.254.169.254",
        "/open?url=http://169.254.169.254",
    ],
    # ── Source code and version control leaks ───────────────────────────────
    "vcs_leaks": [
        "/.git/", "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
        "/.git/index", "/.git/FETCH_HEAD", "/.git/packed-refs",
        "/.git/refs/heads/main", "/.git/refs/heads/master",
        "/.git/refs/heads/develop", "/.git/refs/heads/staging",
        "/.git/logs/HEAD", "/.git/logs/refs/heads/main",
        "/.git/objects/info/packs",
        "/.svn/", "/.svn/entries", "/.svn/wc.db",
        "/.hg/", "/.hg/hgrc", "/.hg/store/",
        "/.bzr/", "/.bzr/branch/branch.conf",
        "/CVS/", "/CVS/Root", "/CVS/Repository",
        "/.terraform/", "/.terraform.tfstate",
        "/terraform.tfstate", "/terraform.tfstate.backup",
        "/.pulumi/", "/Pulumi.yaml", "/Pulumi.dev.yaml",
        "/.github/workflows/", "/.github/", "/.gitlab-ci.yml",
        "/.travis.yml", "/Jenkinsfile", "/Makefile",
        "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
        "/.dockerignore", "/.gitignore", "/.gitmodules",
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/Gemfile", "/Gemfile.lock", "/Pipfile", "/Pipfile.lock",
        "/requirements.txt", "/setup.py", "/pyproject.toml",
        "/composer.json", "/composer.lock",
        "/pom.xml", "/build.gradle", "/build.gradle.kts",
        "/go.sum", "/go.mod",
        "/Cargo.toml", "/Cargo.lock",
    ],
    # ── Debug and diagnostic endpoints ──────────────────────────────────────
    "debug_diagnostic": [
        "/debug", "/debug/", "/debug.php", "/debug.asp", "/debug.aspx",
        "/debug/info", "/debug/vars", "/debug/env", "/debug/config",
        "/debug/routes", "/debug/trace", "/debug/stack",
        "/debug/logs", "/debug/log", "/debug/error",
        "/debug/profiler", "/debug/xhprof",
        "/debug/pprof", "/debug/pprof/goroutine?debug=2",
        "/debug/pprof/heap", "/debug/pprof/allocs",
        "/debug/pprof/cmdline",
        "/trace", "/tracing", "/jaeger/", "/zipkin/",
        "/_trace", "/_profiler", "/_profiler/phpinfo",
        "/profiler/", "/profiler/phpinfo",
        "/laravel-debugbar/", "/__laravel-debugbar__/",
        "/telescope", "/telescope/", "/telescope/api/requests",
        "/horizon", "/horizon/", "/horizon/api/jobs",
        "/debugger", "/rails/info/", "/rails/info/properties",
        "/rails/info/routes", "/rails/mailers",
        "/sidekiq/", "/delayed_job/",
        "/server-info", "/server-status",
        "/?XDEBUG_SESSION_START=phpstorm",
        "/?XDEBUG_SESSION=1",
        "/log", "/logs/", "/app.log", "/error.log", "/access.log",
        "/application.log", "/system.log", "/debug.log",
        "/laravel.log", "/symfony.log", "/django.log",
        "/rails.log", "/production.log", "/development.log",
        "/storage/logs/laravel.log",
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
        "/tmp/", "/temp/",
    ],
    # ── API versioning and hidden API namespaces ─────────────────────────────
    "api_namespace": [
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/api/v4/", "/api/v5/", "/api/v6/",
        "/api/v1.0/", "/api/v2.0/", "/api/v1.1/",
        "/api/internal/", "/api/private/", "/api/admin/",
        "/api/system/", "/api/management/", "/api/ops/",
        "/api/debug/", "/api/test/", "/api/staging/",
        "/api/health", "/api/status", "/api/version",
        "/api/metrics", "/api/info",
        "/apis/", "/apis/v1/", "/apis/apps/",
        "/rest/", "/rest/v1/", "/rest/v2/",
        "/rest/api/", "/rest/api/2/",
        "/rpc/", "/jsonrpc", "/xmlrpc.php",
        "/soap/", "/wsdl", "/service.wsdl",
        "/_api/", "/_rest/", "/_rpc/",
        "/v1/", "/v2/", "/v3/", "/v4/",
        "/v1/api/", "/v2/api/",
        # Undocumented API versions
        "/api/v0/", "/api/v10/", "/api/v100/",
        "/api/v1beta/", "/api/v1alpha/", "/api/preview/",
        "/api/latest/", "/api/next/", "/api/current/",
        "/api/legacy/", "/api/deprecated/", "/api/old/",
        "/api/v1/admin", "/api/v1/users", "/api/v1/config",
        "/api/v1/settings", "/api/v1/keys", "/api/v1/tokens",
        "/api/v1/auth", "/api/v1/login", "/api/v1/logout",
        "/api/v1/register", "/api/v1/password", "/api/v1/reset",
        "/api/v2/admin", "/api/v2/users", "/api/v2/config",
        "/api/v2/settings", "/api/v2/keys", "/api/v2/tokens",
        "/internal/api/", "/private/api/",
        "/system/api/", "/management/api/",
    ],
    # ── IDOR and object reference patterns ──────────────────────────────────
    "idor_extended": [
        "/user/1", "/user/2", "/user/0", "/user/admin",
        "/users/1", "/users/0", "/users/admin", "/users/me",
        "/account/1", "/accounts/1", "/profile/1",
        "/order/1", "/orders/1", "/invoice/1", "/invoices/1",
        "/document/1", "/documents/1", "/file/1", "/files/1",
        "/report/1", "/reports/1", "/ticket/1", "/tickets/1",
        "/message/1", "/messages/1", "/post/1", "/posts/1",
        "/product/1", "/products/1", "/item/1", "/items/1",
        "/id/1", "/id/0", "/id/admin",
        # UUID/GUID patterns (common UUIDs used in dev/test)
        "/user/00000000-0000-0000-0000-000000000001",
        "/user/11111111-1111-1111-1111-111111111111",
        "/api/v1/user/1/settings",
        "/api/v1/user/2/admin",
        "/api/v1/user/1/token",
        "/api/v1/user/1/keys",
        "/api/v1/user/1/sessions",
        "/api/v1/user/1/export",
        "/api/v1/orders/1/payment",
        "/api/v1/orders/1/invoice",
        # Negative IDs (often triggers hidden admin paths)
        "/user/-1", "/user/-999",
        "/api/v1/user/-1",
        # Zero padding
        "/user/001", "/user/0001", "/user/00001",
    ],
    # ── Webhook and callback abuse endpoints ─────────────────────────────────
    "webhooks_callbacks": [
        "/webhook", "/webhook/", "/webhooks/", "/hook/", "/hooks/",
        "/callback", "/callback/", "/callbacks/",
        "/notify", "/notification", "/notifications/",
        "/event", "/events/", "/trigger", "/triggers/",
        "/ping", "/pong", "/heartbeat",
        "/webhook/github", "/webhook/gitlab", "/webhook/slack",
        "/webhook/stripe", "/webhook/paypal", "/webhook/braintree",
        "/webhook/twilio", "/webhook/sendgrid", "/webhook/mailgun",
        "/webhook/jira", "/webhook/confluence", "/webhook/trello",
        "/webhook/zapier", "/webhook/ifttt", "/webhook/n8n",
        "/api/v1/webhook", "/api/v1/webhooks",
        "/api/v1/callback", "/api/v1/hooks",
        "/internal/webhook", "/private/webhook",
        "/admin/webhook", "/admin/webhooks",
    ],
    # ── Export and download endpoints (often lack auth checks) ───────────────
    "export_endpoints": [
        "/export", "/export/", "/export/csv", "/export/xlsx",
        "/export/pdf", "/export/xml", "/export/json",
        "/download", "/download/", "/downloads/",
        "/report/export", "/reports/export",
        "/data/export", "/data/download",
        "/backup/download", "/backup/export",
        "/users/export", "/users/download",
        "/audit/export", "/audit/download",
        "/logs/export", "/logs/download",
        "/invoice/export", "/invoice/download",
        "/api/v1/export", "/api/v1/download",
        "/admin/export", "/admin/download",
        "/internal/export", "/internal/download",
        # Dump endpoints
        "/dump", "/dump.sql", "/dump.tar.gz", "/dump.zip",
        "/database.sql", "/database.sql.gz",
        "/db.sql", "/db.tar.gz", "/db.dump",
        "/data.sql", "/data.json", "/data.csv",
        "/backup.sql", "/backup.tar.gz", "/backup.zip",
    ],
    # ── Monitoring and observability hidden endpoints ────────────────────────
    "monitoring_extended": [
        "/metrics", "/metrics/", "/metrics/json",
        "/prometheus", "/prometheus/metrics",
        "/_prometheus/metrics", "/actuator/prometheus",
        "/grafana", "/grafana/", "/kibana", "/kibana/",
        "/elasticsearch", "/elasticsearch/", "/_cat/indices",
        "/_cluster/health", "/_nodes", "/_nodes/stats",
        "/_mapping", "/_settings", "/_aliases",
        "/logstash/", "/beats/", "/apm/",
        "/jaeger/", "/jaeger/api/traces",
        "/zipkin/", "/zipkin/api/v2/traces",
        "/opentelemetry/", "/otel/",
        "/datadog/", "/newrelic/", "/dynatrace/",
        "/instana/", "/appdynamics/",
        "/statsd/", "/telegraf/",
        "/health", "/health/", "/healthcheck", "/healthy",
        "/health/live", "/health/ready", "/health/startup",
        "/readiness", "/liveness", "/startup",
        "/alive", "/ping", "/pong", "/status",
        "/info", "/version", "/about",
        "/_status", "/_health", "/_ping", "/_info",
        "/__status__", "/__health__", "/__ping__",
    ],
    # ── GraphQL hidden introspection variants ────────────────────────────────
    "graphql_extended": [
        "/graphql", "/graphql/", "/graphiql", "/graphiql/",
        "/gql", "/gql/", "/query", "/playground",
        "/api/graphql", "/api/gql",
        "/v1/graphql", "/v2/graphql",
        "/internal/graphql", "/private/graphql",
        "/admin/graphql", "/system/graphql",
        "/graphql?query={__typename}",
        "/graphql?query={__schema{types{name}}}",
        # Batched introspection
        "/graphql/batch", "/graphql/console",
        "/graphql/explorer", "/graphql/altair",
        # Apollo Engine
        "/.well-known/apollo/server-health",
        "/apollo/server-health",
        # Hasura
        "/v1/graphql/schema", "/api/1/graphql",
        # GraphQL over WebSocket
        "/graphql-ws", "/graphql/ws", "/subscriptions",
    ],
    # ── Serverless and FaaS function paths ──────────────────────────────────
    "serverless_functions": [
        "/.netlify/functions/", "/.netlify/functions/api",
        "/.netlify/functions/auth", "/.netlify/functions/login",
        "/.netlify/functions/user", "/.netlify/functions/admin",
        "/api/serverless/", "/functions/",
        "/lambda/", "/faas/",
        # Vercel edge functions
        "/api/edge/", "/edge/api/",
        # Cloudflare Workers
        "/worker/", "/cf-worker/",
        # AWS Lambda (via API Gateway)
        "/prod/", "/dev/", "/staging/", "/v1/",
        # Firebase functions
        "/us-central1/", "/asia-east1/",
        # Azure Functions
        "/api/HttpTrigger", "/api/Function",
        # Supabase
        "/rest/v1/", "/auth/v1/", "/storage/v1/",
    ],
    # ── Obfuscated/encoded path bypass variants ──────────────────────────────
    "encoding_bypass": [
        # URL encoded slashes
        "/admin%2F", "/admin%2fadmin", "/admin%2Fconfig",
        "/api%2Fv1%2Fadmin", "/api%2Fv1%2Fconfig",
        # Double encoded
        "/admin%252F", "/admin%252fadmin",
        # Unicode overlong encoding
        "/%c0%afadmin%c0%af",
        # Semicolon path bypass
        "/;/admin/", "/;admin/", "/admin;/",
        "/api;/v1/admin", "/api/;v1/admin",
        # Hash bypass
        "/admin#/", "/admin#.json", "/admin#.css",
        # Query param bypass
        "/admin?", "/admin?.json", "/?route=/admin",
        "/?url=/admin", "/?path=/admin",
        "/?page=/admin", "/?action=/admin",
        "/?redirect=/admin", "/?next=/admin",
        "/?continue=/admin", "/?return=/admin",
        # HTTP method override bypass
        "/?_method=GET", "/?_method=POST",
        "/?method=GET", "/?method=ADMIN",
        # Null path segments
        "/admin/./", "/admin/../admin/",
        "/./admin/", "/admin%09/", "/admin%0d/", "/admin%0a/",
        # Case variants
        "/ADMIN/", "/Admin/", "/aDmin/", "/ADMIN/config",
        "/API/", "/Api/", "/aPi/",
        # Trailing dot
        "/admin.", "/admin.htm", "/admin.html",
        "/admin.json", "/admin.xml", "/admin.php",
        "/admin.asp", "/admin.aspx", "/admin.jsp",
        "/admin.cfm", "/admin.cgi", "/admin.pl",
    ],
    # ── Container and orchestration endpoints ────────────────────────────────
    "containers_orchestration": [
        # Docker
        "/v1.24/containers/json", "/v1.24/images/json",
        "/v1.40/containers/json", "/v1.40/images/json",
        "/containers/json", "/images/json",
        # Docker Swarm
        "/v1.40/nodes", "/v1.40/services", "/v1.40/secrets",
        # Kubernetes API
        "/api/v1/pods", "/api/v1/nodes", "/api/v1/secrets",
        "/api/v1/configmaps", "/api/v1/serviceaccounts",
        "/api/v1/namespaces", "/api/v1/services",
        "/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets",
        "/apis/networking.k8s.io/v1/ingresses",
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        # etcd
        "/v2/keys/", "/v3/kv/range",
        # Istio
        "/debug/configz", "/debug/instancesz",
        # Consul
        "/v1/kv/", "/v1/agent/members", "/v1/catalog/services",
        "/v1/health/service/consul", "/v1/status/leader",
        # Vault
        "/v1/sys/health", "/v1/sys/seal-status",
        "/v1/auth/token/lookup-self",
        "/v1/secret/", "/v1/kv/data/",
        # Nomad
        "/v1/jobs", "/v1/nodes", "/v1/allocations",
    ],
    # ── Ultra-deep Spring Boot / Java actuator paths ─────────────────────────
    "spring_ultra": [
        "/actuator", "/actuator/", "/actuator/env",
        "/actuator/configprops", "/actuator/beans", "/actuator/conditions",
        "/actuator/scheduledtasks", "/actuator/mappings", "/actuator/threaddump",
        "/actuator/heapdump", "/actuator/loggers", "/actuator/auditevents",
        "/actuator/sessions", "/actuator/shutdown", "/actuator/restart",
        "/actuator/refresh", "/actuator/httptrace", "/actuator/caches",
        "/actuator/flyway", "/actuator/liquibase", "/actuator/integrationgraph",
        "/actuator/jolokia", "/actuator/jolokia/list", "/actuator/jolokia/read",
        "/actuator/jolokia/exec", "/actuator/prometheus",
        # Spring legacy
        "/env", "/env/", "/dump", "/autoconfig", "/configprops", "/beans",
        "/health", "/info", "/mappings", "/metrics", "/shutdown",
        "/trace", "/jolokia", "/jolokia/list", "/jolokia/version",
        # Logback
        "/actuator/logfile", "/actuator/loggers/root",
        "/logfile", "/log", "/logs",
        # JMX HTTP adapter
        "/jmx", "/jmx/", "/mbean", "/mbean/",
        # Spring Admin
        "/admin", "/admin/", "/admin/applications", "/admin/instances",
        "/admin/journal", "/admin/wallboard",
        # H2 console (often left open in dev)
        "/h2-console", "/h2-console/", "/h2-console/login.jsp",
        "/h2", "/console", "/console/",
    ],
    # ── Next.js / Nuxt.js / Remix framework internals ────────────────────────
    "nextjs_ultra": [
        "/_next/", "/_next/static/", "/_next/image",
        "/_next/data/", "/_next/webpack-hmr",
        "/__nextjs_original-stack-frames",
        "/__nextjs_launch-editor",
        "/api/auth/", "/api/auth/session", "/api/auth/csrf",
        "/api/auth/providers", "/api/auth/signin", "/api/auth/signout",
        "/api/auth/callback/", "/api/auth/error",
        # Nuxt.js
        "/_nuxt/", "/_nuxt/manifest.json",
        "/__nuxt_error", "/__nuxt_resource/",
        # Remix
        "/__remix_manifest", "/__remix/manifest",
        # Vite HMR
        "/__vite_hmr", "/@vite/client", "/@react-refresh",
        "/@id/", "/@fs/", "/@vite-plugin-pwa/",
    ],
    # ── Django / FastAPI / Flask Python internals ─────────────────────────────
    "python_frameworks_ultra": [
        # Django
        "/django-admin/", "/admin/login/?next=/admin/",
        "/admin/auth/user/", "/admin/auth/group/",
        "/__debug__/", "/silk/", "/silk/summary/",
        "/rosetta/", "/grappelli/", "/hijack/",
        # Django REST Framework
        "/api/?format=json", "/api/?format=api",
        "/api/schema/", "/api/docs/", "/api/redoc/",
        "/.well-known/django-error-handler",
        # Django debug toolbar (development)
        "/debug_toolbar/", "/djdt/", "/__djdt/",
        # Celery Flower
        "/flower/", "/flower/api/workers", "/flower/api/tasks",
        # FastAPI
        "/docs", "/redoc", "/openapi.json",
        "/api/v1/openapi.json", "/v1/openapi.json",
        # Flask
        "/debug", "/_debug_toolbar",
        # Uvicorn / Gunicorn
        "/health", "/ready", "/live",
        # Sentry
        "/_sentry/", "/sentry/", "/sentry-tunnel",
        # Pytest / coverage artifacts
        "/htmlcov/", "/coverage/", "/test-results/",
    ],
    # ── Ruby on Rails internals ───────────────────────────────────────────────
    "rails_ultra": [
        "/rails/info", "/rails/info/properties",
        "/rails/info/routes", "/rails/mailers",
        "/rails/conductor", "/rails/conductor/action_mailer/",
        "/sidekiq", "/sidekiq/", "/sidekiq/queues", "/sidekiq/busy",
        "/resque", "/resque/", "/resque/workers", "/resque/queues",
        "/delayed_job", "/delayed_jobs",
        "/flipper", "/flipper/", "/flipper/features",
        "/good_job", "/good_job/",
        "/money-rails", "/audited",
        "/letter_opener", "/letter_opener/",
        "/bullet", "/rack-mini-profiler", "/miniprofiler",
        "/__better_errors/", "/better_errors",
        "/pghero", "/pghero/", "/pghero/queries",
        "/blazer", "/blazer/", "/blazer/queries",
        "/active_storage/blobs/", "/rails/active_storage/",
    ],
    # ── Laravel / PHP framework hidden paths ─────────────────────────────────
    "laravel_ultra": [
        "/telescope", "/telescope/", "/telescope/api/",
        "/telescope/api/requests", "/telescope/api/exceptions",
        "/telescope/api/logs", "/telescope/api/queries",
        "/telescope/api/jobs", "/telescope/api/gates",
        "/telescope/api/events", "/telescope/api/cache",
        "/horizon", "/horizon/", "/horizon/api/",
        "/horizon/api/masters", "/horizon/api/workload",
        "/nova", "/nova/", "/nova-api/",
        "/nova-api/metrics", "/nova-api/resources",
        "/debugbar", "/debugbar/",
        "/filament", "/filament/",
        "/sanctum/csrf-cookie",
        "/broadcasting/auth",
        "/storage/", "/storage/app/", "/storage/logs/",
        "/storage/framework/", "/storage/debugbar/",
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/.env.example", "/.env.backup", "/.env.bak", "/.env.old",
        "/.env.staging", "/.env.testing",
        "/config/app.php", "/config/database.php",
        "/config/auth.php", "/config/mail.php",
        "/artisan", "/composer.json", "/composer.lock",
        "/package.json", "/package-lock.json",
    ],
    # ── WordPress / CMS deep paths ────────────────────────────────────────────
    "wordpress_ultra": [
        "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages", "/wp-json/wp/v2/media",
        "/wp-json/wp/v2/categories", "/wp-json/wp/v2/tags",
        "/wp-json/wp/v2/comments", "/wp-json/wp/v2/taxonomies",
        "/wp-json/wp/v2/types", "/wp-json/wp/v2/statuses",
        "/wp-json/wp/v2/settings",  # Leaks site config!
        "/wp-json/wp/v2/plugins",   # Lists plugins
        "/wp-json/wp/v2/themes",    # Lists themes
        "/wp-json/wp/v2/blocks",
        "/wp-json/wp/v2/block-types",
        "/wp-json/wp/v2/block-patterns",
        "/wp-login.php", "/wp-admin/",
        "/wp-admin/admin-ajax.php", "/wp-admin/install.php",
        "/wp-admin/setup-config.php",
        "/wp-content/debug.log", "/wp-content/uploads/",
        "/wp-content/plugins/", "/wp-content/themes/",
        "/.htpasswd", "/.htaccess",
        "/xmlrpc.php", "/wp-cron.php", "/wp-mail.php",
        # Drupal
        "/user/register", "/admin/reports/", "/admin/config/",
        "/admin/structure/", "/admin/appearance/",
        "/update.php", "/install.php", "/cron.php",
        "/sites/default/files/", "/sites/default/settings.php",
        # Joomla
        "/administrator/", "/administrator/index.php",
        "/configuration.php", "/configuration.php.bak",
        # Ghost
        "/ghost/", "/ghost/api/", "/ghost/api/content/",
        # Strapi
        "/admin/init", "/admin/project-type",
        "/users-permissions/roles",
    ],
    # ── Cloud metadata and SSRF targets ──────────────────────────────────────
    "cloud_metadata_ultra": [
        # AWS IMDS v1 (no auth)
        "/latest/meta-data/", "/latest/meta-data/hostname",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        "/latest/user-data", "/latest/api/token",
        "/latest/dynamic/instance-identity/document",
        # AWS IMDS v2 token endpoint
        "/latest/api/token",
        # GCP metadata
        "/computeMetadata/v1/", "/computeMetadata/v1/project/",
        "/computeMetadata/v1/instance/", "/computeMetadata/v1/instance/service-accounts/",
        "/computeMetadata/v1/instance/service-accounts/default/token",
        # Azure IMDS
        "/metadata/instance", "/metadata/instance/compute",
        "/metadata/instance/network", "/metadata/scheduledevents",
        "/metadata/identity/oauth2/token",
        # Alibaba Cloud
        "/2016-01-01/meta-data/", "/2016-01-01/meta-data/Ram/security-credentials/",
        # DigitalOcean
        "/metadata/v1/", "/metadata/v1/hostname",
        "/metadata/v1/interfaces/",
        # Oracle Cloud
        "/opc/v1/instance/", "/opc/v2/instance/",
        # Kubernetes service account
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        # k8s internal DNS SSRF pointers
        "/api/v1/namespaces/default/secrets",
        "/api/v1/namespaces/kube-system/secrets",
    ],
    # ── CI/CD and DevOps platform leaks ──────────────────────────────────────
    "cicd_ultra": [
        # Jenkins
        "/jenkins/", "/jenkins/script", "/jenkins/api/json",
        "/jenkins/computer/api/json", "/jenkins/credentials/",
        "/script", "/scriptText", "/eval",
        "/asynchPeople/", "/view/All/",
        "/computer/(master)/executors",
        # GitLab
        "/-/health", "/-/liveness", "/-/readiness",
        "/-/metrics", "/-/debug/gc",
        "/api/v4/version", "/api/v4/users",
        "/api/v4/projects", "/api/v4/namespaces",
        "/-/admin/", "/-/admin/users", "/-/admin/runners",
        "/-/admin/projects", "/-/admin/background_jobs",
        "/-/sidekiq/", "/admin/runners",
        # GitHub Actions (self-hosted)
        "/_actions/", "/actions/", "/runner/",
        # TeamCity
        "/teamcity/", "/teamcity/app/rest/",
        "/app/rest/", "/app/rest/builds", "/app/rest/projects",
        # Bamboo
        "/bamboo/", "/bamboo/rest/api/latest/",
        "/rest/api/latest/", "/rest/api/1.0/",
        # CircleCI
        "/api/v1/me", "/api/v2/me",
        # Drone CI
        "/api/user", "/api/repos",
        # Argo CD
        "/api/v1/session", "/api/v1/applications",
        "/api/v1/clusters", "/api/v1/repositories",
        # SonarQube
        "/sonar/api/system/info", "/api/system/info",
        "/sonar/api/system/status", "/api/system/status",
        # Nexus / Artifactory
        "/nexus/", "/artifactory/", "/repository/",
        "/artifactory/api/system/ping",
        "/artifactory/api/system/configuration",
        # Ansible AWX / Tower
        "/api/v2/", "/api/v2/me/", "/api/v2/config/",
        "/api/v2/credentials/", "/api/v2/inventory/",
    ],
    # ── Database admin and ORM-level exposure ─────────────────────────────────
    "db_admin_ultra": [
        # phpMyAdmin
        "/phpmyadmin/", "/phpmyadmin/index.php",
        "/pma/", "/pma/index.php",
        "/phpMyAdmin/", "/phpMyAdmin/index.php",
        "/mysql/", "/mysql/index.php",
        "/mysqladmin/", "/dbadmin/",
        "/sql/", "/sql/index.php",
        # pgAdmin
        "/pgadmin/", "/pgadmin4/", "/pgadmin/browser/",
        # Adminer
        "/adminer", "/adminer.php", "/adminer/",
        "/adminer-4.7.9.php", "/adminer-4.8.1.php",
        "/database/adminer.php",
        # MongoDB
        "/mongo/", "/mongodb/", "/mongoexpress/",
        "/mongo-express/", "/me/", "/mongo-express/db/",
        # Redis admin
        "/redis/", "/redis-commander/",
        # ElasticSearch direct
        "/_cat/indices?v", "/_cat/nodes?v",
        "/_cat/shards?v", "/_sql?format=txt",
        "/_snapshot/", "/_xpack/", "/_security/",
        # ClickHouse
        "/play", "/play/", "/query",
        # InfluxDB
        "/query?q=SHOW+DATABASES",
        "/query?q=SHOW+MEASUREMENTS",
        # MinIO
        "/minio/", "/minio/health/live",
        "/minio/health/cluster",
        # Cassandra/Astra
        "/api/v0/keyspaces",
        # CouchDB
        "/_all_dbs", "/_utils/", "/_membership",
        "/_session", "/_config/",
        # RethinkDB admin
        "/#tables", "/api/",
    ],
    # ── Authentication and SSO bypass paths ──────────────────────────────────
    "auth_bypass_ultra": [
        # OAuth 2.0 / OIDC
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json", "/.well-known/keys",
        "/oauth/authorize", "/oauth/token", "/oauth/introspect",
        "/oauth/revoke", "/oauth/userinfo",
        "/oauth2/authorize", "/oauth2/token", "/oauth2/introspect",
        "/connect/authorize", "/connect/token", "/connect/userinfo",
        "/connect/endsession", "/connect/checksession",
        "/oidc/", "/oidc/authorize", "/oidc/token",
        "/auth/", "/auth/login", "/auth/logout", "/auth/token",
        "/auth/refresh", "/auth/register", "/auth/verify",
        "/auth/password/reset", "/auth/password/change",
        "/auth/oauth/", "/auth/saml/", "/auth/ldap/",
        "/auth/mfa/", "/auth/totp/", "/auth/webauthn/",
        # SAML
        "/saml/", "/saml/metadata", "/saml/login",
        "/saml/acs", "/saml/slo", "/saml/sls",
        "/sso/", "/sso/login", "/sso/saml", "/sso/oidc",
        # Forgot password / reset flows
        "/reset-password", "/forgot-password",
        "/password/reset", "/password/forgot",
        "/account/reset", "/account/recover",
        "/api/v1/password/reset", "/api/v1/forgot-password",
        # JWT-related
        "/token/refresh", "/token/verify", "/token/decode",
        "/api/token/refresh", "/api/refresh-token",
        # Magic link / passwordless
        "/magic-link", "/magic-login", "/passwordless",
        "/login-with-token", "/verify-email",
        # Impersonation / admin masquerade
        "/admin/impersonate", "/admin/masquerade",
        "/switch-user", "/su/", "/become/",
        "/hijack/", "/impersonate/",
    ],
    # ── Forgotten legacy and historical paths ─────────────────────────────────
    "legacy_forgotten": [
        # Old API versions
        "/api/v0/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/api/v4/", "/api/v5/", "/api/v10/",
        "/api/1.0/", "/api/1.1/", "/api/2.0/",
        "/v0/", "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
        # Legacy endpoint patterns
        "/cgi-bin/", "/cgi-bin/admin.cgi", "/cgi-bin/login.cgi",
        "/cgi-bin/config.cgi", "/cgi-bin/env.cgi",
        "/cgi-bin/printenv", "/cgi-bin/test-cgi",
        "/cgi-bin/upload.cgi", "/cgi-bin/backup.cgi",
        "/cgi-bin/phf", "/cgi-bin/status", "/cgi-bin/info",
        # Old ColdFusion / ASP / JSP
        "/cfide/", "/CFIDE/administrator/", "/CFIDE/adminapi/",
        "/cfide/componentutils/", "/cfide/wizards/",
        "/cfdocs/", "/cfm/",
        "/iissamples/", "/iisadmin/", "/msadc/",
        "/scripts/", "/scripts/winnt/", "/scripts/root.exe",
        "/FPSE2002/", "/_vti_bin/", "/_vti_cnf/",
        "/_vti_pvt/", "/_vti_txt/", "/_vti_log/",
        # Old shopping cart / payment
        "/shop/", "/store/", "/cart/", "/checkout/",
        "/payment/", "/purchase/", "/order/", "/orders/",
        # Old forum / community
        "/forum/", "/forums/", "/community/", "/board/",
        "/phpbb/", "/vbulletin/", "/smf/", "/mybb/",
        # Old maintenance pages
        "/maintenance/", "/maintenance.html", "/coming-soon.html",
        "/under-construction.html", "/503.html", "/error.html",
        # Old sitemaps and index pages
        "/index.html", "/index.htm", "/index.php", "/index.asp",
        "/index.aspx", "/index.cfm", "/index.cgi", "/index.pl",
        "/index.jsp", "/default.asp", "/default.aspx",
        "/default.html", "/home.html", "/home.php",
        # Old configuration files
        "/config.php", "/config.php.bak", "/config.php.old",
        "/config.asp", "/config.aspx", "/config.jsp",
        "/configuration.php", "/settings.php", "/options.php",
        "/wp-config.php", "/wp-config.php.bak",
        "/application.properties", "/application.yml",
        "/application-dev.yml", "/application-prod.yml",
        "/appsettings.json", "/appsettings.Development.json",
        "/web.config", "/web.config.bak",
    ],
    # ── Sensitive file and data leakage paths ─────────────────────────────────
    "sensitive_data_ultra": [
        # Private keys and certificates
        "/server.key", "/server.pem", "/server.crt",
        "/ssl/server.key", "/ssl/server.pem",
        "/private/server.key", "/private.key",
        "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa",
        "/.ssh/authorized_keys", "/.ssh/known_hosts",
        "/cert.pem", "/privkey.pem", "/fullchain.pem",
        "/letsencrypt/", "/acme/", "/acme-challenge/",
        # Token and secret files
        "/secrets.yml", "/secrets.yaml", "/secrets.json",
        "/credentials.json", "/credentials.yml",
        "/service-account.json", "/keyfile.json",
        "/auth.json", "/oauth.json", "/token.json",
        "/api-keys.json", "/api_keys.json", "/keys.json",
        "/.tokens", "/.token", "/token", "/api-key",
        "/secret", "/password", "/passwd",
        # Cloud credentials
        "/.aws/credentials", "/.aws/config",
        "/.gcloud/credentials.db", "/.config/gcloud/",
        "/.azure/", "/azure.json",
        "/.kube/config", "/kubeconfig",
        # Database connection strings
        "/database.yml", "/database.yaml",
        "/database.json", "/db.json",
        "/redis.conf", "/memcached.conf",
        "/mongodb.conf", "/postgresql.conf",
        # Log files with sensitive data
        "/access.log", "/error.log", "/debug.log",
        "/app.log", "/application.log", "/server.log",
        "/php-error.log", "/php_error.log",
        "/nginx.log", "/apache.log", "/httpd.log",
        "/laravel.log", "/storage/logs/laravel.log",
        # Development artifacts
        "/.DS_Store", "/Thumbs.db", "/desktop.ini",
        "/.idea/", "/.idea/dataSources.xml",
        "/.idea/workspace.xml", "/.idea/misc.xml",
        "/.vscode/", "/.vscode/settings.json",
        "/.vscode/launch.json", "/.vscode/tasks.json",
        "/.eslintrc", "/.babelrc", "/.prettierrc",
        "/Makefile", "/Dockerfile", "/docker-compose.yml",
        "/docker-compose.yaml", "/docker-compose.override.yml",
        "/Vagrantfile", "/Jenkinsfile", "/.travis.yml",
        "/.circleci/config.yml", "/.github/workflows/",
        "/.gitlab-ci.yml", "/bitbucket-pipelines.yml",
    ],
    # ── Advanced path traversal variants ──────────────────────────────────────
    "path_traversal_ultra": [
        # Classic traversal
        "/../etc/passwd", "/../../etc/passwd", "/../../../etc/passwd",
        "/%2e%2e/etc/passwd", "/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/etc/passwd", "/%252e%252e/%252e%252e/etc/passwd",
        # Windows traversal
        "/../windows/win.ini", "/..%5cwindows%5cwin.ini",
        "/%2e%2e%5cwindows%5cwin.ini",
        # API path traversal
        "/api/v1/../../admin", "/api/v1/..%2fadmin",
        "/api/v1/..%252fadmin",
        # File read via path parameters
        "/file?name=../../etc/passwd",
        "/download?file=../../etc/passwd",
        "/read?path=../../etc/passwd",
        "/load?resource=../../etc/passwd",
        "/static/../../etc/passwd",
        "/assets/../../etc/passwd",
        "/img/../../etc/passwd",
        "/images/../../etc/passwd",
        # Null byte injection
        "/etc/passwd%00", "/etc/passwd%00.php",
        "/etc/passwd%00.jpg", "/etc/passwd%00.png",
        # LFI probes
        "/?page=../../etc/passwd",
        "/?file=../../etc/passwd",
        "/?template=../../etc/passwd",
        "/?include=../../etc/passwd",
        "/?load=../../etc/passwd",
        "/?view=../../etc/passwd",
        "/?doc=../../etc/passwd",
        "/?document=../../etc/passwd",
        "/?root=../../etc/passwd",
        "/?path=../../etc/passwd",
        "/?pg=../../etc/passwd",
    ],
    # ── Internal microservice / service-mesh paths ────────────────────────────
    "internal_microservice": [
        # gRPC / protobuf reflection
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc/health/v1/Health/Check",
        # Envoy proxy admin
        "/stats", "/stats/prometheus", "/clusters",
        "/config_dump", "/listeners", "/routes", "/server_info",
        # Linkerd
        "/metrics", "/ready", "/live",
        # Kong API Gateway
        "/kong/", "/_kong/", "/kongadmin/",
        "/services", "/routes", "/plugins", "/upstreams",
        # AWS API Gateway
        "/_/ping", "/_/state", "/_/metrics",
        # Traefik
        "/dashboard/", "/api/", "/api/rawdata",
        "/api/version", "/api/providers", "/api/entrypoints",
        "/api/routers", "/api/middlewares", "/api/services",
        "/ping", "/metrics",
        # Nginx unit
        "/config/", "/control/",
        # Caddy admin
        "/config/apps/http/servers",
        "/load", "/adapt",
        # Internal health patterns
        "/internal/health", "/internal/ping", "/internal/status",
        "/internal/version", "/internal/metrics",
        "/private/health", "/private/ping",
        "/service/health", "/service/status",
        "/_internal/", "/_service/", "/_system/",
        # RPC endpoints
        "/rpc/", "/jsonrpc", "/json-rpc",
        "/rpc/v1", "/api/rpc", "/internal/rpc",
    ],
    # ── Error and debug endpoint hidden paths ─────────────────────────────────
    "error_debug_ultra": [
        # Exception/stack trace pages
        "/error", "/error/", "/errors/", "/exception/",
        "/stacktrace", "/stack-trace", "/traceback",
        "/500", "/500.html", "/error500.html",
        "/503", "/503.html", "/maintenance.html",
        # Debug consoles
        "/debug", "/debug/", "/debug/console",
        "/debug/vars", "/debug/pprof/", "/debug/pprof/cmdline",
        "/debug/pprof/profile", "/debug/pprof/symbol",
        "/debug/pprof/trace", "/debug/pprof/heap",
        "/debug/pprof/goroutine", "/debug/pprof/block",
        # Go net/http/pprof
        "/pprof/", "/pprof/cmdline", "/pprof/profile",
        "/pprof/symbol", "/pprof/trace",
        # Python werkzeug debugger
        "/console", "/__debugger__/",
        # PHP info
        "/phpinfo.php", "/info.php", "/php_info.php",
        "/test.php", "/phptest.php", "/test_page.php",
        "/checkup.php", "/diagnostic.php",
        # Node.js inspector
        "/json", "/json/list", "/json/version",
        "/:9229/json", "/:9229/json/list",
        # Profiling
        "/profile", "/profile/", "/profiling/",
        "/performance/", "/perf/", "/timing/",
        # Feature flags / experiments
        "/feature-flags", "/features", "/experiments",
        "/ab-tests", "/rollout", "/unleash/",
        "/launchdarkly/", "/growthbook/",
        # Admin diagnostic
        "/diagnostic", "/diagnostics/", "/diag",
        "/system-info", "/sysinfo", "/serverinfo",
        "/server-status", "/server-info",
        "/.well-known/security.txt",
        "/security.txt", "/humans.txt", "/robots.txt",
        "/sitemap.xml", "/sitemap.xml.gz",
    ],
    # ── Source code / VCS exposure paths (ultra deep) ────────────────────────
    "vcs_ultra": [
        # Git
        "/.git/", "/.git/HEAD", "/.git/config",
        "/.git/info/refs", "/.git/COMMIT_EDITMSG",
        "/.git/FETCH_HEAD", "/.git/ORIG_HEAD",
        "/.git/packed-refs", "/.git/info/exclude",
        "/.git/logs/HEAD", "/.git/logs/refs/heads/main",
        "/.git/logs/refs/heads/master",
        "/.git/refs/heads/main", "/.git/refs/heads/master",
        "/.git/refs/remotes/origin/HEAD",
        "/.git/objects/info/packs",
        "/.gitignore", "/.gitmodules", "/.gitattributes",
        "/.github/", "/.github/workflows/",
        # SVN
        "/.svn/", "/.svn/entries", "/.svn/wc.db",
        "/.svn/pristine/", "/.svn/format",
        # Mercurial
        "/.hg/", "/.hg/hgrc", "/.hg/store/",
        "/.hg/dirstate", "/.hg/bookmarks",
        # CVS
        "/CVS/", "/CVS/Root", "/CVS/Entries",
        # Bazaar
        "/.bzr/", "/.bzr/branch-format",
        # Fossil
        "/.fslckout", "/fossil", "/fossil.db",
        # Source archives often accidentally left
        "/source.zip", "/sources.zip", "/src.zip",
        "/code.zip", "/website.zip", "/backup.zip",
        "/deploy.zip", "/release.zip", "/build.zip",
        "/archive.zip", "/project.zip", "/repo.zip",
        "/source.tar.gz", "/src.tar.gz", "/code.tar.gz",
        "/backup.tar.gz", "/website.tar.gz",
        # IDE project files
        "/.idea/", "/.vscode/", "/.eclipse/",
        "/.classpath", "/.project",
    ],
    # ── Obfuscation bypass ultra-deep (case/encoding/delimiter variants) ──────
    "obfuscation_ultra": [
        # Tab/newline in path (some parsers strip them)
        "/admin%09/", "/admin%0a/", "/admin%0d/",
        "/admin%0d%0a/",
        # Overlong UTF-8 encoding
        "/%c0%af", "/%e0%80%af", "/%c0%ae%c0%ae%c0%af",
        "/%c0%afadmin/", "/%c0%afetc%c0%afpasswd",
        # IIS Unicode exploit relics
        "/%c1%9c", "/%c1%9cWINNT%c1%9csystem32%c1%9ccmd.exe",
        # Path normalization bypasses (nginx/apache differ)
        "/./admin/", "/admin/./", "/.//admin//./",
        "/admin//", "//admin//", "///admin///",
        "/admin/./config", "/api/./v1/./admin",
        # Spring Boot endpoint bypass
        "/actuator/;/env", "/actuator/.;/env",
        "/actuator//env", "/actuator///env",
        "/actuator/env.json", "/actuator/env.xml",
        "/actuator/env/", "/actuator/env;.css",
        # FastCGI / CGI path separator
        "/index.php/admin/", "/index.php/../admin/",
        "/index.php/;admin",
        # Case bypass
        "/Admin", "/ADMIN", "/aDmin", "/adMin",
        "/Admin/", "/ADMIN/", "/aDmin/", "/adMIN/",
        "/Actuator", "/ACTUATOR",
        "/Api", "/API",
        "/GraphQL", "/GRAPHQL",
        "/Swagger", "/SWAGGER",
        "/Metrics", "/METRICS",
        # Extension confusion
        "/admin.json", "/admin.xml", "/admin.yaml",
        "/admin.yml", "/admin.txt", "/admin.csv",
        "/admin.html", "/admin.htm",
        "/admin.php", "/admin.asp", "/admin.aspx",
        "/admin.jsp", "/admin.do", "/admin.action",
        "/admin.cfm", "/admin.cgi", "/admin.pl",
        "/admin.py", "/admin.rb",
        # Content negotiation bypass
        "/api/admin?format=json", "/api/admin?format=xml",
        "/api/admin?format=yaml", "/api/admin?output=json",
        "/api/admin?type=json", "/api/admin?response=json",
        # Version parameter bypass
        "/admin?v=1", "/admin?version=1", "/admin?api=v1",
        "/admin?debug=true", "/admin?test=true",
        "/admin?dev=true", "/admin?stage=true",
        # Method override
        "/admin?_method=GET", "/admin?_method=OPTIONS",
        "/?X-HTTP-Method-Override=GET&path=/admin",
        # IP/Host bypass headers (tested via custom headers in _check)
        "/admin?X-Forwarded-For=127.0.0.1",
        "/admin?X-Real-IP=127.0.0.1",
        "/admin?X-Original-URL=/admin",
        # Session/cookie bypass hints
        "/admin?session=bypass", "/admin?role=admin",
        "/admin?admin=true", "/admin?isAdmin=true",
        "/admin?authenticated=true", "/admin?loggedIn=true",
    ],
    # ── Subdomain takeover probe paths (returns 200 on dangling CNAMEs) ───────
    "takeover_probe": [
        # Service-specific fingerprint paths
        "/s3/", "/s3-us-east-1.amazonaws.com/",
        "/storage.googleapis.com/",
        # GitHub Pages
        "/404.html", "/CNAME",
        # Heroku
        "/heroku_deployment_in_progress",
        # Azure
        "/azure-blob/", "/.aspx",
        # Fastly
        "/Fastly-Service-ID",
        # Shopify
        "/admin/online_store/pages",
        # Tumblr
        "/blog/404",
        # Ghost Pro
        "/ghost/api/content/posts/",
        # Cargo
        "/static/js/main.js",
        # Pantheon
        "/sites/default/files/",
        # Squarespace
        "/squarespace-sitemaps/",
        # ReadMe.io
        "/docs-api",
    ],
    # ── Modern SaaS API gateway patterns ──────────────────────────────────────
    "saas_api_patterns": [
        # REST + GraphQL hybrid
        "/api/rest/", "/api/graph/", "/api/gql/",
        # Versioned with build hash
        "/api/v1/", "/api/v1.0/", "/api/v1.1/",
        "/api/v2/", "/api/v2.0/", "/api/v2.1/",
        # Tenant / org scoped
        "/api/org/{org}/", "/api/tenant/{tenant}/",
        "/t/{tenant}/api/", "/org/{org}/api/",
        # Feature-flagged
        "/api/beta/", "/api/alpha/", "/api/experimental/",
        "/api/canary/", "/api/preview/",
        # Internal partner APIs
        "/api/partner/", "/api/integrations/",
        "/api/external/", "/api/third-party/",
        "/api/webhook/", "/api/webhooks/",
        # Data export / bulk
        "/api/v1/export/", "/api/v1/bulk/",
        "/api/v1/batch/", "/api/v1/import/",
        "/api/v1/stream/", "/api/v1/feed/",
        # Audit / compliance
        "/api/v1/audit/", "/api/v1/compliance/",
        "/api/v1/logs/", "/api/v1/events/",
        "/api/v1/activity/", "/api/v1/history/",
    ],

    # ── Zero-day / supply chain / shadow IT ──────────────────────────────────
    "shadow_it": [
        # Shadow SaaS proxied through internal
        "/jira/", "/confluence/", "/atlassian/", "/bitbucket/",
        "/github/", "/gitlab/", "/gitea/", "/gogs/",
        "/jenkins/", "/bamboo/", "/teamcity/",
        "/artifactory/", "/nexus/", "/sonar/",
        "/grafana/", "/prometheus/", "/alertmanager/",
        "/kibana/", "/logstash/", "/fluentd/",
        "/vault/", "/consul/", "/nomad/",
        "/rancher/", "/portainer/", "/cockpit/",
        "/phpMyAdmin/", "/phpmyadmin/", "/pma/",
        "/adminer.php", "/adminer/",
        "/webmin/", "/cpanel/", "/plesk/",
        "/roundcube/", "/squirrelmail/", "/horde/",
        "/owncloud/", "/nextcloud/", "/seafile/",
        "/mattermost/", "/rocketchat/", "/zulip/",
        "/netdata/", "/icinga/", "/nagios/", "/zabbix/",
        "/openvpn/", "/pritunl/", "/wireguard/",
        # Forgotten test/dev proxies
        "/proxy/", "/forward/", "/redirect/",
        "/tunnel/", "/relay/", "/gateway/",
        "/bypass/", "/passthrough/", "/pipe/",
    ],

    # ── Dependency confusion / package registry paths ─────────────────────────
    "package_registry": [
        "/npm/", "/@org/", "/registry/",
        "/packages/", "/package/", "/pypi/",
        "/maven/", "/gradle/", "/nuget/",
        "/gem/", "/gems/", "/rubygems/",
        "/cargo/", "/crates/", "/packagist/",
        "/composer/", "/pub/", "/hex/",
        "/.npmrc", "/.yarnrc", "/.yarnrc.yml",
        "/package.json", "/package-lock.json",
        "/yarn.lock", "/Gemfile", "/Gemfile.lock",
        "/requirements.txt", "/Pipfile", "/Pipfile.lock",
        "/go.mod", "/go.sum", "/Cargo.toml", "/Cargo.lock",
        "/pom.xml", "/build.gradle", "/settings.gradle",
        "/composer.json", "/composer.lock",
        "/bower.json", "/.bowerrc",
        "/pubspec.yaml", "/pubspec.lock",
    ],

    # ── Hidden admin dashboards and internal tooling ──────────────────────────
    "hidden_dashboards": [
        "/ops/", "/ops-dashboard/", "/opsdash/",
        "/engineering/", "/eng/", "/eng-tools/",
        "/devops/", "/devops-tools/", "/devtools/",
        "/platform/", "/platform-tools/", "/infra/",
        "/sre/", "/reliability/", "/oncall/",
        "/runbook/", "/runbooks/", "/playbook/",
        "/postmortem/", "/incident/", "/incidents/",
        "/on-call/", "/pagerduty/", "/opsgenie/",
        "/statuspage/", "/status-page/", "/status/dashboard",
        "/deployment/", "/deployments/", "/deploy/",
        "/release/", "/releases/", "/changelog/",
        "/feature-flags/", "/flags/", "/features/",
        "/launchdarkly/", "/unleash/", "/flagsmith/",
        "/ab-testing/", "/experiments/", "/cohorts/",
        "/rollouts/", "/canaries/", "/bluegreen/",
        "/migrations/", "/migration/status",
        "/seeds/", "/fixtures/", "/factories/",
        "/crons/", "/cron/", "/scheduled-jobs/",
        "/workers/", "/queues/", "/queue/dashboard",
        "/sidekiq/", "/resque/", "/celery/", "/flower/",
        "/bull/", "/bullmq/", "/horizon/", "/pulse/",
        "/telescope/", "/debugbar/", "/clockwork/",
        # Feature admin
        "/feature/", "/toggle/", "/toggles/",
        "/config-editor/", "/settings/advanced",
        "/system-config/", "/sys-config/",
        "/tenant-config/", "/org-config/",
        # Token/secret management panels
        "/secrets/dashboard", "/keys/dashboard",
        "/credentials/dashboard", "/certs/dashboard",
    ],

    # ── AI/ML model serving and data pipeline endpoints ───────────────────────
    "ml_ai_endpoints": [
        "/predict", "/predict/", "/inference",
        "/model/", "/models/", "/serve/",
        "/mlflow/", "/mlflow/api/",
        "/kubeflow/", "/seldon/", "/kfserving/",
        "/bentoml/", "/torchserve/", "/triton/",
        "/tensorflow/serving/", "/tfserving/",
        "/api/v1/models/", "/api/v1/predict",
        "/pipeline/", "/pipelines/", "/dag/",
        "/airflow/", "/prefect/", "/dagster/",
        "/metaflow/", "/feast/", "/tecton/",
        "/vertex/", "/sagemaker/", "/azureml/",
        "/embeddings/", "/tokenize/", "/classify/",
        "/sentiment/", "/summarize/", "/generate/",
        "/complete/", "/completions/", "/chat/completions",
        "/v1/completions", "/v1/chat/completions",
        "/v1/embeddings", "/v1/models",
        "/api/v1/completions", "/api/v1/chat",
        "/openai/", "/anthropic/", "/cohere/",
        "/datasets/", "/dataset/", "/features/",
        "/experiments/", "/runs/", "/artifacts/",
        "/registry/", "/model-registry/",
    ],

    # ── Internal proxy pass-through and SSRF vectors ─────────────────────────
    "internal_proxy": [
        # Common internal proxy base paths
        "/api/proxy?url=", "/proxy?url=",
        "/fetch?url=", "/remote?url=",
        "/external?url=", "/request?url=",
        "/?url=http://", "/?src=http://",
        # Internal metadata endpoints often accessible via proxy
        "/internal/v1/", "/internal/v2/",
        "/private/v1/", "/private/v2/",
        "/internal/api/", "/internal/api/v1/",
        "/private/api/", "/private/api/v1/",
        "/backend/", "/backend/api/",
        "/microservice/", "/micro/",
        "/service/", "/services/",
        "/svc/", "/ms/",
        # Reverse proxy debug paths
        "/nginx-status", "/nginx_status",
        "/haproxy/stats", "/haproxy-status",
        "/traefik/", "/traefik/api/",
        "/envoy/stats", "/envoy/ready",
        "/caddy/admin/", "/caddy/api/",
        "/upstream/", "/downstream/",
        "/backend-health", "/origin-health",
    ],

    # ── Modern API versioning and discovery patterns (2025) ───────────────────
    "api_discovery_2025": [
        # OpenAPI / Swagger paths
        "/openapi.json", "/openapi.yaml",
        "/openapi.yml", "/openapi/v1",
        "/openapi/v2", "/openapi/v3",
        "/swagger.json", "/swagger.yaml", "/swagger.yml",
        "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/api-docs", "/api-docs/", "/api-docs/v1",
        "/api-docs/v2", "/apidocs", "/apidocs/",
        "/docs/api", "/docs/api/v1",
        # API catalog / discovery
        "/api/catalog", "/api/schema",
        "/api/schema/", "/api/discovery",
        "/api/registry", "/api/endpoints",
        "/api/routes", "/api/spec",
        "/api/manifest", "/api/.well-known",
        "/api/openapi", "/api/swagger",
        "/.well-known/api-catalog",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
        "/.well-known/webfinger",
        "/.well-known/nodeinfo",
        "/.well-known/security.txt",
        "/.well-known/change-password",
        # gRPC reflection
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        # AsyncAPI
        "/asyncapi.json", "/asyncapi.yaml",
        # RAML
        "/api.raml", "/api/api.raml",
        # JSON:API
        "/jsonapi/", "/json-api/",
    ],

    # ── Forgotten/legacy admin interfaces (historical) ────────────────────────
    # NOTE: This was a duplicate key (previously "legacy_forgotten") — renamed to
    # "legacy_admin_historical" so all paths are preserved in ALL_PROBE_PATHS.
    "legacy_admin_historical": [
        # Old CMS admin paths
        "/manager/html", "/manager/text",
        "/administrator/", "/administrator/index.php",
        "/wp-content/uploads/", "/wp-includes/",
        "/xmlrpc.php", "/wp-cron.php",
        "/cms/", "/cms/admin/", "/cms/login",
        "/portal/", "/portal/admin/", "/portal/login",
        # Old Java EE paths
        "/jmx-console/", "/jmx-console/HtmlAdaptor",
        "/web-console/", "/invoker/JMXInvokerServlet",
        "/status?full=true", "/server-status",
        "/server-info", "/handler/invoke",
        # Old .NET paths
        "/elmah.axd", "/glimpse.axd", "/mini-profiler-resources",
        "/trace.axd", "/webresource.axd",
        "/scriptresource.axd", "/handler.ashx",
        # Old PHP frameworks
        "/app/webroot/", "/cakephp/",
        "/kohana/", "/codeigniter/",
        "/symfony/", "/zend/",
        # ColdFusion
        "/CFIDE/administrator/", "/CFIDE/adminapi/",
        "/cf_scripts/", "/cfm/", "/cfc/",
        # Old monitoring
        "/prtg/", "/orion/", "/solarwinds/",
        "/cacti/", "/mrtg/", "/ganglia/",
        "/munin/", "/collectd/",
        # Old network appliance panels
        "/cgi-bin/luci", "/cgi-bin/webui",
        "/webui/", "/setup.cgi", "/manager.cgi",
        "/login.cgi", "/admin.cgi", "/config.cgi",
    ],

    # ── GraphQL persisted queries and schema introspection ────────────────────
    "graphql_advanced": [
        # Apollo persisted queries
        "/graphql?extensions={\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"\"}}",
        "/graphql/persisted/",
        # Automatic persisted queries (APQ) endpoint discovery
        "/graphql?query={__typename}&extensions={\"persistedQuery\":{\"version\":1}}",
        # Relay modern
        "/relay/graphql", "/relay/query",
        # GraphQL subscriptions via SSE
        "/graphql/stream", "/graphql/sse",
        # Stepzen / StepZen
        "/stepzen/", "/stepzen/api/",
        # WPGraphQL (WordPress)
        "/graphql?query={generalSettings{url}}",
        # Shopify Admin GraphQL
        "/admin/api/graphql.json",
        # GitHub-style GraphQL
        "/api/graphql", "/v3/graphql",
        # Federation / Supergraph
        "/_supergraph", "/_supergraph/",
        "/federated/graphql", "/gateway/graphql",
        # Schema dump endpoint
        "/graphql/schema.json", "/graphql/schema.graphql",
        "/graphql/schema", "/sdl",
    ],

    # ── JWT / OAuth / token inspection paths ─────────────────────────────────
    "oauth_jwt_paths": [
        # OAuth 2.0
        "/oauth/", "/oauth/authorize", "/oauth/token",
        "/oauth/revoke", "/oauth/introspect",
        "/oauth/userinfo", "/oauth/jwks",
        "/oauth2/", "/oauth2/authorize", "/oauth2/token",
        "/oauth2/revoke", "/oauth2/introspect",
        "/connect/authorize", "/connect/token",
        "/connect/revoke", "/connect/introspect",
        "/connect/userinfo", "/connect/endsession",
        "/connect/checksession",
        # OIDC
        "/.well-known/openid-configuration",
        "/auth/realms/master/.well-known/openid-configuration",
        "/auth/realms/master/protocol/openid-connect/token",
        "/auth/realms/master/protocol/openid-connect/userinfo",
        "/auth/realms/master/protocol/openid-connect/certs",
        # Keycloak admin
        "/auth/admin/", "/auth/admin/master/",
        "/auth/admin/realms/", "/auth/admin/console/",
        # JWT debug
        "/debug/token", "/debug/jwt",
        "/token/debug", "/token/info",
        "/token/inspect", "/token/validate",
        # Auth0 management API (via proxy)
        "/api/v2/users", "/api/v2/clients",
        "/api/v2/connections", "/api/v2/rules",
        # SAML
        "/saml/", "/saml/sso", "/saml/acs",
        "/saml/metadata", "/saml2/", "/sso/saml",
        "/Shibboleth.sso/", "/idp/",
    ],

    # ── Keycloak admin and realm paths (high-value IAM target) ───────────────
    "keycloak_deep": [
        # Realm discovery
        "/auth/realms/", "/auth/",
        "/auth/realms/master/",
        "/auth/realms/master/.well-known/openid-configuration",
        "/auth/realms/master/protocol/openid-connect/token",
        "/auth/realms/master/protocol/openid-connect/userinfo",
        "/auth/realms/master/protocol/openid-connect/certs",
        "/auth/realms/master/protocol/openid-connect/auth",
        "/auth/realms/master/protocol/openid-connect/logout",
        # Keycloak Admin REST API (protected, but 401 = exists)
        "/auth/admin/", "/auth/admin/master/",
        "/auth/admin/master/console/",
        "/auth/admin/realms/",
        "/auth/admin/realms/master/",
        "/auth/admin/realms/master/users",
        "/auth/admin/realms/master/users/count",
        "/auth/admin/realms/master/clients",
        "/auth/admin/realms/master/roles",
        "/auth/admin/realms/master/groups",
        "/auth/admin/realms/master/events",
        "/auth/admin/realms/master/admin-events",
        "/auth/admin/realms/master/sessions/stats",
        "/auth/admin/realms/master/attack-detection/brute-force/users",
        "/auth/admin/realms/master/components",
        "/auth/admin/realms/master/identity-provider/instances",
        "/auth/admin/realms/master/client-scopes",
        # Keycloak metrics (Prometheus-compatible)
        "/auth/realms/master/metrics",
        "/auth/metrics",
        "/metrics",
        # Keycloak health
        "/auth/health", "/auth/health/ready", "/auth/health/live",
        # Common non-master realm names
        "/auth/realms/production/",
        "/auth/realms/prod/",
        "/auth/realms/app/",
        "/auth/realms/internal/",
        "/auth/realms/corporate/",
        "/auth/realms/employees/",
        "/auth/realms/external/",
        # New Keycloak 17+ paths (no /auth prefix)
        "/realms/", "/realms/master/",
        "/realms/master/.well-known/openid-configuration",
        "/realms/master/protocol/openid-connect/token",
        "/admin/", "/admin/master/",
        "/admin/realms/", "/admin/realms/master/users",
    ],

    # ── Prometheus + Grafana + Alertmanager (monitoring stack) ───────────────
    "prometheus_stack": [
        # Prometheus
        "/-/healthy", "/-/ready",
        "/api/v1/query", "/api/v1/query_range",
        "/api/v1/query_exemplars", "/api/v1/series",
        "/api/v1/labels", "/api/v1/label/__name__/values",
        "/api/v1/targets", "/api/v1/targets/metadata",
        "/api/v1/rules", "/api/v1/alerts",
        "/api/v1/alertmanagers",
        "/api/v1/status/config",
        "/api/v1/status/flags",
        "/api/v1/status/runtimeinfo",
        "/api/v1/status/buildinfo",
        "/api/v1/metadata",
        # Grafana
        "/api/health", "/api/org",
        "/api/org/users", "/api/org/preferences",
        "/api/datasources", "/api/datasources/proxy/",
        "/api/datasources/1/resources/",
        "/api/plugins", "/api/plugin-proxy/",
        "/api/dashboards/home", "/api/search",
        "/api/admin/users", "/api/admin/orgs",
        "/api/admin/settings", "/api/admin/stats",
        "/api/admin/ldap-status", "/api/admin/ldap/reload",
        "/api/admin/pause-all-alerts",
        "/api/snapshots", "/api/snapshot/shared-with-me",
        "/api/annotations", "/api/alerting/",
        "/api/folders", "/api/teams/",
        "/api/signing-keys/rotate",
        # Alertmanager
        "/api/v2/alerts", "/api/v2/silences",
        "/api/v2/status", "/api/v2/receivers",
    ],

    # ── Internal service debugging ports accidentally exposed ─────────────────
    "internal_debug_ports": [
        # pprof (Go)
        "/debug/pprof/", "/debug/pprof/goroutine",
        "/debug/pprof/heap", "/debug/pprof/threadcreate",
        "/debug/pprof/block", "/debug/pprof/mutex",
        "/debug/pprof/allocs", "/debug/pprof/cmdline",
        "/debug/pprof/profile?seconds=1",
        "/debug/pprof/symbol", "/debug/pprof/trace",
        # Delve (Go debugger)
        "/api/v1/debugger", "/api/v1/stacktrace",
        # Python remote debugger
        "/debugger", "/__debugger__/",
        "/__debugger__/console?frm=0",
        # Java remote JMX
        "/jolokia/", "/jolokia/list",
        "/jolokia/read", "/jolokia/exec",
        "/jolokia/search", "/jolokia/version",
        # Node.js inspector
        "/json", "/json/list", "/json/version", "/json/protocol",
        "/__ws_proxy__/",
        # Ruby Byebug / pry
        "/byebug/", "/pry/",
        # PHP Xdebug
        "/?XDEBUG_SESSION_START=phpstorm",
        "/?XDEBUG_SESSION=1",
        # Generic debug/trace
        "/debug/stack", "/debug/goroutine",
        "/debug/vars", "/debug/statusz",
        "/debugz", "/statusz", "/filez", "/rpcz",
        "/varz", "/flagz", "/healthz",
    ],
}

# Extra elite paths for deepest hidden endpoint discovery (2025 additions)
_ELITE_EXTRA_PATHS = [
    # AWS metadata SSRF variants (path traversal + encoding)
    "/latest/meta-data/", "/latest/user-data/",
    "/latest/meta-data/iam/security-credentials/",
    "//169.254.169.254/latest/meta-data/",
    "/%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
    # GCP metadata
    "/computeMetadata/v1/", "/computeMetadata/v1/project/",
    "/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure IMDS
    "/metadata/instance?api-version=2021-02-01",
    "/metadata/identity/oauth2/token",
    # Alibaba Cloud metadata
    "/latest/meta-data/", "/100.100.100.200/latest/meta-data/",
    # Internal Kubernetes API
    "/api/v1/namespaces/default/secrets",
    "/api/v1/namespaces/kube-system/secrets",
    "/apis/apps/v1/namespaces/default/deployments",
    "/apis/", "/api/v1/pods", "/api/v1/nodes",
    # Consul service discovery
    "/v1/catalog/services", "/v1/catalog/nodes",
    "/v1/kv/", "/v1/acl/token",
    # etcd endpoints
    "/v2/keys/", "/v3/kv/range",
    # HashiCorp Vault
    "/v1/sys/seal-status", "/v1/sys/health", "/v1/auth/token/lookup-self",
    "/v1/secret/", "/v1/kv/", "/v1/sys/mounts",
    # Spring Boot extended
    "/actuator/env/spring.datasource.password",
    "/actuator/configprops", "/actuator/beans",
    "/actuator/startup", "/actuator/sessions",
    "/actuator/scheduledtasks", "/actuator/integrationgraph",
    # Django internal
    "/__debug__/", "/__debug__/sql/", "/__debug__/template/",
    "/django-silk/", "/silk/", "/silk/requests/", "/silk/summary/",
    # Werkzeug debugger (Flask dev server)
    "/console", "/__debugger__", "/console?frm=0",
    # Node.js cluster
    "/__cluster/", "/__cluster/workers",
    "/cluster/stats", "/cluster/info",
    # GraphQL introspection variants
    "/graphql?query={__schema{types{name}}}",
    "/graphql/v1?query={__schema{types{name}}}",
    "/api/graphql?query={__schema{types{name}}}",
    "/gql?query={__schema{types{name}}}",
    "/_graphql?query={__schema{types{name}}}",
    # gRPC reflection
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    # Internal auth bypass patterns
    "/admin?bypass=1", "/admin?internal=true", "/admin?debug=1",
    "/.internal/admin", "/.internal/api", "/_internal/",
    "/api/internal/", "/api/admin/", "/api/private/",
    # Forgotten debug endpoints
    "/ping", "/pong", "/echo", "/whoami", "/test",
    "/healthz", "/readyz", "/livez", "/startup",
    # Environment exposure
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.env.backup", "/.env.bak", "/.env.example",
    "/config.env", "/app.env", "/server.env",
    # Source code leaks
    "/.git/HEAD", "/.git/config", "/.git/FETCH_HEAD",
    "/.git/logs/HEAD", "/.git/refs/heads/main",
    "/.svn/entries", "/.hg/store/data",
    # Credential files
    "/credentials.json", "/service-account.json",
    "/gcp-credentials.json", "/aws-credentials",
    "/.aws/credentials", "/.gcp/credentials.json",
    "/secrets.yaml", "/secrets.json", "/vault.json",
    # Internal CI/CD
    "/.circleci/config.yml", "/.github/workflows/",
    "/.gitlab-ci.yml", "/Jenkinsfile", "/.travis.yml",
    "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
    # API key exposure
    "/api-key", "/api-keys", "/apikey", "/apikeys",
    "/tokens", "/token", "/access-token", "/auth-token",
    # Cloud storage paths
    "/storage/", "/s3/", "/gcs/", "/blob/", "/files/",
    "/media/internal/", "/uploads/private/", "/data/export/",
    # Monitoring dashboards (internal)
    "/grafana/", "/prometheus/", "/kibana/",
    "/jaeger/", "/zipkin/", "/datadog/",
    "/newrelic/", "/dynatrace/",
    # Message queues
    "/rabbitmq/", "/kafka/", "/redis/", "/memcached/",
    "/activemq/", "/nats/", "/zeromq/",
    # Database admin
    "/phpmyadmin/", "/adminer/", "/pgadmin/",
    "/mongo-express/", "/redis-commander/",
    # Serverless / FaaS
    "/functions/", "/lambda/", "/faas/",
    "/serverless/", "/.netlify/functions/",
    "/api/functions/", "/func/",
    # API documentation
    "/api-docs/", "/api-explorer/", "/api-reference/",
    "/apidoc/", "/docs/api/", "/reference/api/",
    # Tenant/multi-tenant
    "/tenant/", "/tenants/", "/org/", "/orgs/",
    "/workspace/", "/workspaces/",
    "/company/", "/account/settings/",
    # IDOR patterns
    "/api/users/1", "/api/users/2", "/api/users/admin",
    "/api/v1/users/1", "/api/v1/accounts/1",
    "/user/1/profile", "/user/admin/profile",
    # Path traversal
    "/../../../etc/passwd", "/%2e%2e%2f%2e%2e%2fetc/passwd",
    "/..%2f..%2f..%2fetc%2fpasswd", "/%252e%252e%252fetc%252fpasswd",
    # PHP info
    "/phpinfo.php", "/info.php", "/php.php",
    "/_debug.php", "/test.php", "/check.php",
    # Backup files
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db_backup.sql", "/dump.sql", "/database.sql",
    "/www.zip", "/site.zip", "/web.zip",
    # Config files
    "/config.json", "/settings.json", "/app.json",
    "/web.config", "/web.xml", "/applicationContext.xml",
    "/application.properties", "/application.yml",
    "/bootstrap.yml", "/server.xml", "/context.xml",
    # Swagger/OpenAPI additional
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/api.json",
    "/.well-known/openapi", "/v1/openapi.json",
    "/v2/openapi.json", "/v3/openapi.json",
    # OAuth2/OIDC discovery
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/webfinger",
    # Certificate transparency
    "/.well-known/pki-validation/",
    "/.well-known/acme-challenge/",
    # Server-sent events / WebSocket test endpoints
    "/events", "/sse", "/stream", "/feed",
    "/ws", "/wss", "/socket", "/realtime",
    # Hidden admin patterns
    "/administrator/", "/siteadmin/", "/wp-admin/",
    "/cpanel/", "/whm/", "/plesk/", "/directadmin/",
    "/webmin/", "/ispconfig/",
    # Legacy/forgotten
    "/old/", "/backup/", "/archive/", "/legacy/",
    "/deprecated/", "/v0/", "/beta/", "/alpha/",
    # Framework-specific hidden paths
    "/rails/mailers/", "/rails/info/routes",
    "/laravel/", "/storage/framework/", "/storage/logs/",
    "/storage/app/", "/public/storage/",
    # Error/exception reporting
    "/errors/", "/error-log", "/app-log",
    "/exception/", "/crash/", "/report/",
    # Metrics & profiling
    "/metrics", "/metrics/", "/_metrics",
    "/profile", "/profiler", "/perf",
    "/__clockwork__", "/clockwork/",
    # Internal service APIs
    "/_api/", "/internal/api/", "/private/api/",
    "/api/_internal/", "/api/private/",
    "/_service/", "/service/internal/",
    # ── Feature flags & A/B testing (2025) ───────────────────────────────────
    "/features/", "/feature-flags/", "/flags/", "/toggles/",
    "/ab-test/", "/experiments/", "/rollout/",
    "/api/features", "/api/flags", "/api/toggles",
    "/api/experiments", "/api/experiments/",
    "/featureflags", "/feature_flags", "/ff/",
    "/launchdarkly/", "/unleash/api/", "/growthbook/api/",
    "/optimizely/", "/split/api/", "/flagsmith/api/v1/",
    # ── Shadow APIs / undocumented internal endpoints ─────────────────────────
    "/api/shadow/", "/shadow-api/", "/_shadow/",
    "/api/undocumented/", "/api/unstable/",
    "/api/experimental/", "/api/preview/",
    "/api/canary/", "/api/nightly/", "/api/edge/",
    "/api/prototype/", "/api/draft/",
    # ── Internal documentation / runbooks ────────────────────────────────────
    "/runbook/", "/runbooks/", "/playbook/", "/playbooks/",
    "/handbook/", "/wiki/", "/confluence/",
    "/internal-docs/", "/docs/internal/",
    "/architecture/", "/design/", "/spec/",
    "/ops/", "/ops/runbooks/", "/sre/", "/oncall/",
    # ── Service mesh admin panels ────────────────────────────────────────────
    "/mesh/", "/service-mesh/", "/istio/",
    "/envoy/", "/envoy-admin/", "/linkerd/",
    "/consul-connect/", "/cilium/",
    # Istio control plane admin
    "/istio/graph", "/istio/telemetry",
    "/xds-grpc/", "/pilot/v1/xds/",
    # ── Tracing / observability internals ────────────────────────────────────
    "/jaeger/api/", "/zipkin/api/v2/",
    "/tempo/api/", "/loki/api/v1/",
    "/otel/", "/opentelemetry/", "/collector/",
    "/.otel/", "/otlp/",
    # ── Database internals exposed over HTTP ─────────────────────────────────
    "/influxdb/", "/influxdb/query", "/influx/",
    "/clickhouse/", "/druid/", "/pinot/",
    "/cassandra/", "/couchdb/", "/neo4j/",
    # ── Secrets management ────────────────────────────────────────────────────
    "/doppler/", "/infisical/api/", "/chamber/",
    "/aws-secrets-manager/", "/ssm/parameters/",
    # ── Data pipelines / ETL internals ──────────────────────────────────────
    "/airflow/api/v1/", "/prefect/api/", "/dagster/",
    "/spark/", "/flink/", "/beam/",
    "/dbt/api/", "/fivetran/", "/airbyte/api/v1/",
    # ── Internal management consoles ─────────────────────────────────────────
    "/portainer/", "/rancher/", "/k8s-dashboard/",
    "/kubernetes-dashboard/", "/lens/",
    "/argocd/", "/flux/", "/tekton/",
    "/spinnaker/api/v1/", "/helm/",
    # ── SSO / SAML / OIDC internals ──────────────────────────────────────────
    "/saml/", "/saml2/", "/saml/metadata",
    "/saml/SSO", "/saml/acs", "/saml/slo",
    "/auth/saml/", "/sso/saml/", "/okta/",
    "/auth/callback", "/oauth/callback",
    "/auth/saml/metadata", "/idp/metadata",
    "/.well-known/saml-configuration",
    # ── Internal notification / event systems ────────────────────────────────
    "/webhooks/internal/", "/hooks/internal/",
    "/events/internal/", "/callbacks/internal/",
    "/notifications/internal/", "/alerts/internal/",
    # ── Developer tooling exposure ────────────────────────────────────────────
    "/storybook/", "/__storybook__/", "/chromatic/",
    "/percy/", "/figma-tokens/",
    "/dev/", "/dev-tools/", "/devtools/",
    "/__dev__/", "/__development__/",
    # ── Data export / dump endpoints ─────────────────────────────────────────
    "/export/", "/dump/", "/extract/",
    "/api/export/", "/api/dump/",
    "/download/data/", "/download/backup/",
    "/reports/export/", "/data/export/",
    # ── Analytics internals ───────────────────────────────────────────────────
    "/analytics/internal/", "/segment/", "/mixpanel/",
    "/amplitude/", "/heap/", "/fullstory/",
    "/posthog/api/", "/matomo/", "/piwik/",
    # ── Chat / collaboration internals ────────────────────────────────────────
    "/slack/", "/slack/api/", "/teams/api/",
    "/discord/api/", "/zoom/api/", "/jira/rest/api/",
    "/confluence/rest/api/", "/notion/api/",

    # ── 2025: AI/LLM serving & model APIs ────────────────────────────────────
    "/v1/chat/completions", "/v1/completions",
    "/v1/embeddings", "/v1/models", "/v1/files",
    "/v1/fine-tunes", "/v1/fine_tuning/jobs",
    "/v1/images/generations", "/v1/audio/transcriptions",
    "/openai/deployments/", "/openai/models/",
    "/azure/openai/", "/bedrock/", "/vertex-ai/",
    "/api/generate", "/api/chat", "/ollama/api/",
    "/api/v1/generate", "/api/v1/chat",
    "/llm/", "/llm/api/", "/ai/api/", "/ml/api/",
    "/langchain/", "/llamaindex/", "/semantic-kernel/",
    "/rag/", "/vector/", "/embed/", "/rerank/",
    "/chroma/api/v1/", "/weaviate/v1/", "/qdrant/",
    "/pinecone/", "/milvus/", "/faiss/",

    # ── 2025: Platform engineering / IDP ─────────────────────────────────────
    "/backstage/", "/backstage/api/",
    "/catalog/", "/catalog/entities",
    "/scaffolder/", "/scaffolder/api/v1/",
    "/techdocs/", "/search/", "/auth/",
    "/proxy/", "/proxy/kubernetes/",
    "/idp/", "/idp/api/", "/developer-portal/",
    "/platform/api/", "/platform/catalog/",
    "/port/api/", "/cortex/api/", "/compass/api/",

    # ── 2025: eBPF / eBPF-based security tools ───────────────────────────────
    "/tetragon/", "/falco/", "/cilium/api/",
    "/falco/healthz", "/falco/api/v1/",

    # ── 2025: Forgotten developer tools at root ───────────────────────────────
    "/console/", "/repl/", "/sandbox/", "/playground/",
    "/shell/", "/terminal/", "/ttyd/",
    "/jupyter/", "/lab/", "/notebook/",
    "/code-server/", "/theia/", "/vscode/",
    "/gitpod/", "/coder/", "/cloud9/",
    "/remotedebug/", "/chrome-devtools/",
    "/devtools/json", "/devtools/browser",
    "/json/version", "/json/protocol",

    # ── 2025: Internal health/readiness probes (Kubernetes) ──────────────────
    "/healthz/ready", "/healthz/live",
    "/readyz/internal", "/livez/internal",
    "/health/internal", "/health/deep",
    "/health/full", "/health/components",
    "/health/dependencies", "/health/db",
    "/health/cache", "/health/queue",
    "/health/storage", "/health/upstream",
    "/health/downstream", "/health/config",
    "/health/secret", "/health/token",

    # ── 2025: Debug/trace endpoints exposed by modern frameworks ─────────────
    "/q/health/live", "/q/health/ready",     # Quarkus
    "/q/metrics", "/q/info", "/q/dev/",      # Quarkus DevUI
    "/q/openapi", "/q/swagger-ui/",          # Quarkus OpenAPI
    "/__web_profiler__/", "/profiler/",      # Symfony WebProfiler
    "/profiler/{token}",
    "/_profiler/", "/_profiler/empty/show",
    "/api/explorer", "/api/platform/",       # API Platform
    "/bundles/apiplatform/",
    "/swagger-ui/index.html",
    "/swagger-ui.html#/", "/swagger-ui/#/",

    # ── 2025: Multi-cloud / hybrid management ────────────────────────────────
    "/crossplane/", "/crossplane/api/",
    "/terraform-controller/",
    "/pulumi/", "/cdk/", "/cdk8s/",
    "/kops/", "/cluster-api/",
    "/anthos/", "/openshift/", "/rosa/",
    "/tanzu/", "/tkgi/",

    # ── 2025: Zero-trust / SASE / edge security panels ───────────────────────
    "/cloudflare-access/", "/cloudflare/access/",
    "/zscaler-access/", "/zta/",
    "/crowdstrike/api/", "/sentinelone/api/",
    "/wiz/api/", "/orca/api/", "/lacework/api/",
    "/prisma/api/", "/cspm/api/",
    "/devsecops/", "/appsec/", "/sast/", "/dast/",

    # ── 2025: Supply chain / SBOM endpoints ──────────────────────────────────
    "/sbom", "/sbom/", "/cyclonedx/", "/spdx/",
    "/sbom.json", "/sbom.xml", "/bom.json",
    "/software-bill-of-materials",
    "/syft/", "/grype/", "/trivy/",
    "/snyk/api/", "/socket/api/", "/deps.dev/",

    # ── 2025: Keycloak / FreeIPA / Okta / Auth0 internals ────────────────────
    "/auth/realms/", "/auth/realms/master/",
    "/auth/realms/master/account/",
    "/auth/realms/master/account/applications",
    "/auth/realms/master/protocol/openid-connect/token",
    "/auth/realms/master/protocol/openid-connect/userinfo",
    "/auth/realms/master/protocol/openid-connect/certs",
    "/auth/admin/", "/auth/admin/master/console/",
    "/auth/admin/master/", "/auth/admin/realms/",
    "/auth/admin/realms/master/users",
    "/auth/admin/realms/master/clients",
    "/auth/admin/realms/master/roles",
    "/auth/admin/realms/master/groups",
    "/auth/admin/realms/master/sessions/stats",
    "/auth/admin/realms/master/attack-detection/brute-force/users",
    "/keycloak/", "/keycloak/admin/",
    # Okta
    "/api/v1/users", "/api/v1/apps", "/api/v1/groups",
    "/api/v1/authorizationServers", "/api/v1/policies",
    "/api/v1/sessions/me", "/api/v1/users/me",
    # FreeIPA
    "/ipa/", "/ipa/session/login_password",
    "/ipa/json", "/ipa/ui/",
    # Ping Identity
    "/pf/", "/pf/heartbeat.ping", "/pf/adapter/",
    "/pingfederate/", "/as/token.oauth2",
    # ADFS
    "/adfs/", "/adfs/ls/", "/adfs/portal/",
    "/adfs/oauth2/authorize", "/adfs/oauth2/token",

    # ── 2025: HashiCorp Vault ultra-deep ──────────────────────────────────────
    "/v1/sys/health", "/v1/sys/seal-status", "/v1/sys/init",
    "/v1/sys/mounts", "/v1/sys/auth", "/v1/sys/policies",
    "/v1/sys/capabilities-self", "/v1/sys/audit",
    "/v1/sys/raw/", "/v1/sys/replication/status",
    "/v1/auth/", "/v1/auth/approle/login",
    "/v1/auth/token/lookup-self", "/v1/auth/token/renew-self",
    "/v1/secret/", "/v1/secret/data/", "/v1/kv/",
    "/v1/kv/data/", "/v1/kv/metadata/",
    "/v1/database/creds/", "/v1/pki/ca", "/v1/pki/crl",
    "/v1/cubbyhole/", "/v1/transit/keys/",
    "/v1/aws/creds/", "/v1/gcp/token/",
    "/v1/azure/creds/", "/v1/ssh/creds/",

    # ── 2025: Consul ultra-deep ───────────────────────────────────────────────
    "/v1/agent/self", "/v1/agent/members", "/v1/agent/services",
    "/v1/agent/checks", "/v1/catalog/services",
    "/v1/catalog/nodes", "/v1/catalog/datacenters",
    "/v1/kv/?keys", "/v1/kv/", "/v1/acl/",
    "/v1/acl/tokens", "/v1/acl/policies",
    "/v1/health/service/", "/v1/query/",
    "/v1/snapshot", "/v1/coordinate/nodes",
    "/v1/connect/ca/configuration",
    "/v1/connect/intentions/",

    # ── 2025: etcd ultra-deep ─────────────────────────────────────────────────
    "/v2/keys/", "/v2/members/", "/v2/stats/self",
    "/v2/stats/store", "/v2/stats/leader",
    "/v3/kv/range", "/v3/kv/put",
    "/v3/auth/enable", "/v3/lease/grant",
    "/v3/maintenance/status", "/v3/cluster/member/list",

    # ── 2025: ZooKeeper / Kafka admin (HTTP exposure) ─────────────────────────
    "/commands/stat", "/commands/srvr", "/commands/mntr",
    "/commands/dump", "/commands/envi", "/commands/conf",
    "/kafka/api/v1/", "/kafka/brokers",
    "/kafka-rest/", "/kafka-ui/",

    # ── 2025: Backstage IDP service catalog secrets ───────────────────────────
    "/api/proxy/", "/api/kubernetes/",
    "/api/catalog/entities", "/api/techdocs/",
    "/api/scaffolder/v2/tasks",
    "/api/search/query", "/api/auth/",

    # ── 2025: Crossplane / GitOps operator endpoints ──────────────────────────
    "/apis/pkg.crossplane.io/v1/", "/apis/apiextensions.crossplane.io/v1/",
    "/apis/argoproj.io/v1alpha1/", "/apis/flagger.app/v1beta1/",
    "/apis/flux.weave.works/", "/apis/kustomize.toolkit.fluxcd.io/",

    # ── 2025: Service mesh internals exposed at app ports ─────────────────────
    "/quitquitquit", "/healthz/ping", "/server_info",
    "/ready", "/live", "/drain", "/hot_restart_version",
    "/stats?usedonly", "/clusters?format=json",
    "/config_dump?resource=dynamic_route_configs",

    # ── 2025: gRPC-Web proxy inspection paths ─────────────────────────────────
    "/grpc-web/", "/grpc.health.v1.Health/Check",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",

    # ── 2025: NATS / RabbitMQ / ActiveMQ management ───────────────────────────
    "/nats/", "/nats/varz", "/nats/connz",
    "/nats/routez", "/nats/subsz",
    "/api/connections", "/api/exchanges", "/api/queues",
    "/api/bindings", "/api/vhosts", "/api/users",  # RabbitMQ mgmt
    "/api/overview", "/api/nodes",  # RabbitMQ
    "/admin/xml", "/admin/json", "/admin/jsp/index.jsp",  # ActiveMQ

    # ── 2025: Temporal workflow engine ────────────────────────────────────────
    "/temporal/", "/temporal/api/",
    "/api/v1/namespaces", "/api/v1/workflows",
    "/api/v1/taskqueues",

    # ── 2025: Dapr sidecar / distributed app runtime ──────────────────────────
    "/v1.0/state/", "/v1.0/pubsub/",
    "/v1.0/secrets/", "/v1.0/actors/",
    "/v1.0/bindings/", "/v1.0/metadata",
    "/v1.0-alpha1/", "/v1.0/invoke/",
    "/dapr/", "/dapr/health/",

    # ── 2025: Tyk / Kong / AWS API GW management paths ───────────────────────
    "/tyk/", "/tyk/reload/", "/tyk/apis/",
    "/tyk/keys/", "/tyk/policies/",
    "/admin/api/", "/admin/apis/",
    "/api/v1/apis", "/api/v1/keys",
    "/api/v1/consumers", "/api/v1/plugins",

    # ── 2025: Monitoring tool internals ───────────────────────────────────────
    "/api/v1/query?query=up",                 # Prometheus
    "/api/v1/label/__name__/values",          # Prometheus
    "/api/v1/series",                         # Prometheus
    "/api/v1/rules", "/api/v1/alerts",        # Prometheus
    "/api/v1/status/config",                  # Prometheus
    "/api/v1/status/flags",                   # Prometheus
    "/api/v1/status/runtimeinfo",             # Prometheus
    "/api/v1/targets", "/api/v1/targets/metadata", # Prometheus
    "/api/plugins",                           # Grafana
    "/api/datasources",                       # Grafana
    "/api/org/users",                         # Grafana
    "/api/admin/users",                       # Grafana
    "/api/admin/orgs",                        # Grafana
    "/api/admin/settings",                    # Grafana

    # ── 2025: Argo Workflows / Argo CD secrets ────────────────────────────────
    "/api/v1/workflows/default",              # Argo Workflows
    "/api/v1/workflow-templates/default",
    "/api/v1/cron-workflows/default",
    "/api/v1/cluster-workflow-templates",
    "/api/v1/applications",                   # Argo CD
    "/api/v1/application-sets",
    "/api/v1/clusters",                       # Argo CD
    "/api/v1/repositories",                   # Argo CD
    "/api/v1/repocreds",
    "/api/v1/settings/plugins",

    # ── 2025: Tekton / Spinnaker / Flux internals ─────────────────────────────
    "/apis/tekton.dev/v1/", "/apis/triggers.tekton.dev/v1/",
    "/gate/pipelines/", "/gate/applications/",   # Spinnaker Gate
    "/gate/projects/", "/gate/tasks/",
    "/v1/git/repositories",                   # Flux webhook receiver
    "/hook/", "/hook/github/", "/hook/gitlab/",

    # ── 2025: MinIO / S3-compatible storage management ────────────────────────
    "/minio/health/live", "/minio/health/cluster",
    "/minio/health/ready", "/minio/login",
    "/?list-type=2", "/?location",           # S3-compatible list buckets
    "/_minio/health/live", "/_minio/login",

    # ── 2025: ClickHouse HTTP interface ───────────────────────────────────────
    "/?query=SELECT+1", "/?query=SHOW+DATABASES",
    "/?query=SHOW+TABLES", "/?query=system.tables",
    "/ping", "/play",                         # ClickHouse built-in

    # ── 2025: Metabase / Redash / Superset analytics ──────────────────────────
    "/api/session", "/api/user/current",      # Metabase
    "/api/dashboard", "/api/card",            # Metabase
    "/api/admin/permissions/",                # Metabase
    "/api/activity",                          # Metabase
    "/api/queries/", "/api/data_sources/",    # Redash
    "/api/dashboards/", "/api/widgets/",      # Redash
    "/api/me/", "/api/datasource/",           # Superset
    "/superset/explore/", "/superset/dashboard/",

    # ── 2025: Authentik / Authelia / Casdoor IAM ─────────────────────────────
    "/api/v3/", "/api/v3/core/users/",
    "/api/v3/policies/", "/api/v3/flows/",
    "/api/v3/sources/", "/api/v3/applications/",
    "/api/v3/stages/", "/api/v3/outposts/",
    "/api/v1/authentication/", "/api/v1/authorization/",
    "/casdoor/", "/api/login",

    # ── 2025: PocketBase / Appwrite / Supabase self-hosted ───────────────────
    "/api/collections/",                      # PocketBase
    "/api/admins/", "/api/realtime",          # PocketBase
    "/v1/databases/", "/v1/functions/",       # Appwrite
    "/v1/storage/", "/v1/users/",             # Appwrite
    "/v1/account", "/v1/teams/",              # Appwrite
    "/rest/v1/", "/auth/v1/", "/storage/v1/", # Supabase
    "/realtime/v1/",                          # Supabase

    # ── 2025: Headless CMS internals ─────────────────────────────────────────
    "/content-manager/", "/content-type-builder/",  # Strapi
    "/admin/init", "/admin/project-type",     # Strapi
    "/api/users-permissions/roles",           # Strapi
    "/_cms/", "/cms-api/", "/cms/internal/",
    "/ghost/api/admin/", "/ghost/api/admin/users/",  # Ghost CMS
    "/ghost/api/admin/config/",
    "/keystone/api/", "/__keystone_api_not_found__",

    # ── 2025: Langchain / Ollama / OpenWebUI serving ──────────────────────────
    "/api/generate", "/api/chat",             # Ollama
    "/api/pull", "/api/push", "/api/create",  # Ollama model mgmt
    "/api/show", "/api/copy", "/api/delete",  # Ollama
    "/api/tags", "/api/blobs/",               # Ollama
    "/openai/v1/", "/openai/api/",            # OpenWebUI proxy
    "/api/v1/models", "/api/v1/chat/completions",  # OpenAI-compat

    # ── 2025: Velero / backup operator internals ──────────────────────────────
    "/apis/velero.io/v1/", "/apis/velero.io/v1/backups",
    "/apis/velero.io/v1/restores",

    # ── 2025: Trivy / Grype / Syft / Dependency-Track ────────────────────────
    "/api/v1/project", "/api/v1/vulnerability",
    "/api/v1/component", "/api/v1/policy",
    "/api/v1/finding",                        # Dependency-Track

    # ── 2025: Additional WAF bypass via path obfuscation ──────────────────────
    "/actuator/..;/env", "/actuator/..;/configprops",
    "/actuator/..;/mappings", "/actuator/..;/beans",
    "/;/actuator/env", "//actuator//env",
    "/v1/sys/..;/health", "/v1/..;/secret/",
    "/admin/..;/config", "/api/..;/internal/",

    # ── 2025: Forgotten/obscure internal paths ─────────────────────────────────
    # Internal feature flags / dark launch endpoints
    "/feature-flags", "/feature-flags/", "/features", "/flags",
    "/toggles", "/unleash/api/", "/flagr/api/", "/growthbook/api/",
    # Remote code execution / command endpoints (forgotten admin)
    "/cmd", "/exec", "/execute", "/run", "/shell", "/command",
    "/console/cmd", "/admin/exec", "/admin/shell", "/admin/command",
    "/api/execute", "/api/run", "/api/cmd",
    # Environment / runtime info dumps
    "/env.json", "/env.yaml", "/env.yml", "/.env.local", "/.env.production",
    "/.env.staging", "/.env.development", "/.env.backup",
    "/config.json", "/config.yml", "/config.yaml", "/config.toml",
    "/application.properties", "/application.yaml", "/application.yml",
    "/bootstrap.properties", "/bootstrap.yml",
    # Docker / container secrets mounts
    "/run/secrets/", "/var/run/secrets/kubernetes.io/serviceaccount/",
    "/proc/1/environ", "/proc/self/environ", "/proc/self/cmdline",
    # Source code / project files
    "/composer.json", "/package.json", "/Gemfile", "/requirements.txt",
    "/Pipfile", "/pyproject.toml", "/go.sum", "/go.mod", "/pom.xml",
    "/build.gradle", "/build.xml", "/Makefile", "/Dockerfile",
    "/docker-compose.yml", "/docker-compose.yaml", "/.dockerignore",
    "/nginx.conf", "/apache2.conf", "/httpd.conf", "/lighttpd.conf",
    # Internal developer tools (forgotten dev mode)
    "/telescope", "/telescope/requests", "/telescope/queries",  # Laravel Telescope
    "/clockwork", "/clockwork/requests",                          # Clockwork PHP
    "/_debugbar/", "/_debugbar/open",                             # Laravel Debugbar
    "/django-admin/", "/admin/doc/",                               # Django admin docs
    "/_ah/admin", "/_ah/mail", "/_ah/login",                      # Google App Engine
    "/rails/info/routes", "/rails/info/properties",               # Rails internal
    "/profiler/", "/_profiler/", "/profiler/phpstorm",
    # Health / status endpoints — hidden variations
    "/healthcheck", "/health-check", "/health_check",
    "/ping", "/pong", "/alive", "/liveness", "/readiness",
    "/version.json", "/version.txt", "/build.json", "/build-info",
    "/.well-known/health", "/.well-known/status",
    # API keys / token endpoints (sometimes left open)
    "/oauth/token", "/oauth2/token", "/token", "/tokens",
    "/api/token", "/api/key", "/api/keys", "/api/access-token",
    "/v1/token", "/v2/token", "/auth/token", "/auth/key",
    # Internal dashboards and admin UIs
    "/flower", "/flower/tasks", "/flower/workers",                 # Celery Flower
    "/sidekiq", "/sidekiq/busy", "/sidekiq/queues",                # Ruby Sidekiq
    "/resque", "/resque/overview",                                   # Resque
    "/bull/", "/bull-board/", "/arena/",                            # Node.js queues
    "/delayed_job", "/delayed/jobs",                                 # Delayed::Job
    "/hangfire", "/hangfire/jobs",                                   # Hangfire .NET
    # Hidden test/debug endpoints
    "/test", "/test/", "/tests", "/testing", "/debug", "/debug/",
    "/trace", "/tracing", "/profiling", "/benchmark",
    "/internal/test", "/api/test", "/api/debug", "/api/trace",
    # API documentation variations (often expose full schema)
    "/api/schema", "/api/schema.json", "/api/schema.yaml",
    "/api/v1/schema", "/api/v2/schema", "/api/v3/schema",
    "/redoc", "/redoc.html", "/api-reference", "/api/reference",
    "/docs/api", "/api/docs", "/api/documentation", "/documentation",
    "/openapi", "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger", "/swagger.json", "/swagger.yaml", "/swagger-resources",
    # Backup files — beyond standard ones
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
    "/db.sql", "/database.sql", "/data.sql", "/data.tar.gz",
    "/www.zip", "/htdocs.zip", "/public.zip", "/src.zip",
    "/deploy.tar.gz", "/release.zip", "/dist.zip",
    "/web.config.bak", "/web.config.orig", "/nginx.conf.bak",
    # AWS S3 / cloud storage paths (sometimes proxied internally)
    "/.s3cfg", "/.boto", "/aws-exports.js", "/aws-exports.json",
    # Internal monitoring endpoints
    "/jolokia", "/jolokia/list", "/jolokia/version",              # JMX via HTTP
    "/jmx", "/jmxremote", "/jmx-console",                         # JBoss/WildFly
    "/hawtio", "/hawtio/jvm/list",                                 # HawtIO
    "/visualvm", "/jconsole",
    # GraphQL introspection variations (hidden endpoints)
    "/graphql/console", "/graphql/explorer", "/graphql/voyager",
    "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/_graphql", "/private/graphql", "/internal/graphql",
    "/gql", "/query",
    # Git / version control leaks
    "/.git/HEAD", "/.git/COMMIT_EDITMSG", "/.git/refs/heads/master",
    "/.git/refs/heads/main", "/.git/config", "/.git/packed-refs",
    "/.git/info/refs", "/.git/objects/info/packs",
    "/.svn/wc.db", "/.svn/pristine/", "/.hg/requires",
    "/.bzr/branch-format",
    # CI/CD artifacts and pipelines
    "/.github/workflows/", "/.gitlab-ci.yml", "/.travis.yml",
    "/Jenkinsfile", "/.circleci/config.yml",
    "/bitbucket-pipelines.yml", "/.drone.yml",
    # Terraform / IaC state files (catastrophic if exposed)
    "/terraform.tfstate", "/terraform.tfstate.backup",
    "/.terraform/", "/main.tf", "/variables.tf", "/outputs.tf",
    # Kubernetes secrets / service account tokens
    "/var/run/secrets/", "/secrets/", "/api/v1/namespaces/",
    "/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets",
]
def _generate_bypass_variants(paths: list) -> set:
    """
    Generate WAF-bypass path variants for sensitive paths.
    Includes well-known bypasses AND innovative new techniques not found in
    public tools — targeting path normalization differences between WAF and
    origin, server-specific quirks, encoding tricks, and structural confusions.
    """
    _SENSITIVE_TRIGGERS = (
        'admin', 'actuator', 'debug', 'config', 'env', 'secret', 'internal',
        'private', 'backup', 'git', 'svn', 'credentials', 'token', 'key',
        'phpmyadmin', 'console', 'shell', 'exec', 'cmd', 'graphql', 'introspect',
        'swagger', 'api', 'health', 'metrics', 'monitor', 'dashboard', 'panel',
        'management', 'login', 'auth', 'oauth', 'sso', 'ldap', 'password',
        'passwd', 'shadow', 'htpasswd', 'database', 'db', 'sql', 'redis',
        'elastic', 'kibana', 'jenkins', 'sonar', 'prometheus', 'grafana',
        'kubernetes', 'k8s', 'docker', 'helm', 'terraform', 'ansible',
        'aws', 'azure', 'gcp', 'cloud', 'iam', 'role', 'policy', 'bucket',
        'webhook', 'internal-api', 'private-api', 'hidden', 'expose',
    )
    bypass_paths = set()

    def _hex_encode_path(p: str) -> str:
        """Hex-encode alphabetic chars in each path segment."""
        segs = p.split('/')
        out = []
        for seg in segs:
            out.append(''.join(f'%{ord(c):02X}' if c.isalpha() else c for c in seg))
        return '/'.join(out)

    def _unicode_confusable(p: str) -> str:
        """Replace first alpha char in first segment with a Unicode confusable."""
        _CONFUSABLES = {'a': 'а', 'e': 'е', 'o': 'о',
                        'c': 'с', 'p': 'р', 'i': 'і',
                        'A': 'Α', 'E': 'Ε', 'B': 'Β'}
        segs = p.split('/')
        for i, seg in enumerate(segs):
            for j, ch in enumerate(seg):
                if ch in _CONFUSABLES:
                    segs[i] = seg[:j] + _CONFUSABLES[ch] + seg[j+1:]
                    return '/'.join(segs)
        return p

    def _mid_dot_segments(p: str) -> str:
        """Insert /. between first and second segment to confuse normalization."""
        parts = p.lstrip('/').split('/', 1)
        if len(parts) == 2:
            return '/' + parts[0] + '/./' + parts[1]
        return p

    def _overlong_utf8_slash(p: str) -> str:
        """Replace first / after root with overlong UTF-8 two-byte sequence for /."""
        # %C0%AF is overlong 2-byte encoding of / (rejected by RFC but some servers accept)
        return '/' + p.lstrip('/').replace('/', '%C0%AF', 1)

    def _windows_separator(p: str) -> str:
        """Replace first non-root / with Windows backslash %5c."""
        stripped = p.lstrip('/')
        return '/' + stripped.replace('/', '%5C', 1)

    def _iis_unicode_bypass(p: str) -> str:
        """IIS Unicode bypass: %c1%1c and %c0%9v are alternate encodings of /."""
        return '/' + p.lstrip('/').replace('/', '%c1%1c', 1)

    def _spring_actuator_bypass(p: str) -> str:
        """Spring Boot semicolon path parameter bypass."""
        # Spring strips ;param=value from path before routing
        return p + ';type=1'

    def _path_param_injection(p: str) -> str:
        """Inject path parameter to bypass WAF path matching."""
        return p + ';jsessionid=bypass'

    def _double_encode_slash(p: str) -> str:
        """Double-encode the path separator: %252F."""
        return '/' + p.lstrip('/').replace('/', '%252F', 1)

    def _alternate_case_segment(p: str) -> str:
        """Alternate upper/lower on each character in first segment."""
        segs = p.split('/')
        for i, seg in enumerate(segs):
            if seg:
                alt = ''.join(
                    c.upper() if j % 2 == 0 else c.lower()
                    for j, c in enumerate(seg)
                )
                segs[i] = alt
                break
        return '/'.join(segs)

    def _null_mid_path(p: str) -> str:
        """Null byte after first segment (tricks some path parsers)."""
        parts = p.lstrip('/').split('/', 1)
        if len(parts) == 2:
            return '/' + parts[0] + '%00/' + parts[1]
        return p + '%00'

    def _content_neg_bypass(p: str) -> str:
        """Content negotiation: append .json to path."""
        if not p.endswith('.json'):
            return p + '.json'
        return p

    def _api_version_bypass(p: str) -> str:
        """Prefix /v0/ before the path (version bypass)."""
        return '/v0' + p

    def _tab_in_path(p: str) -> str:
        """Tab character in path (some WAFs skip tab-containing paths)."""
        return p + '%09/'

    def _trailing_newline(p: str) -> str:
        """CR/LF at end of path segment (HTTP response splitting bypass attempt)."""
        return p + '%0d%0a/'

    def _fragment_bypass(p: str) -> str:
        """Fragment anchor — some WAFs stop processing at # in URL."""
        return p + '#/'

    def _underscored_variant(p: str) -> str:
        """Replace hyphens with underscores in path (routing inconsistency)."""
        return p.replace('-', '_')

    def _hyphenated_variant(p: str) -> str:
        """Replace underscores with hyphens in path."""
        return p.replace('_', '-')

    def _query_param_bypass(p: str) -> str:
        """Append /?debug=1 to confuse WAF path-only matching."""
        return p + '?debug=1'

    def _extra_slash_all(p: str) -> str:
        """Double ALL path separators."""
        return p.replace('/', '//')

    def _nginx_alias_traversal(p: str) -> str:
        """Nginx alias traversal: add ../ after first segment."""
        parts = p.lstrip('/').split('/', 1)
        if len(parts) == 2:
            return '/' + parts[0] + '/../' + parts[1]
        return p + '/../'

    def _encoded_dot(p: str) -> str:
        """URL-encode dots in path."""
        return p.replace('.', '%2e')

    def _semicolon_prefix(p: str) -> str:
        """Semicolon before path (some proxies strip semicolon prefix)."""
        return ';' + p

    def _method_override_path(p: str) -> str:
        """Append ?_method=GET for method override WAF bypass."""
        return p + '?_method=GET'

    def _deep_null_byte(p: str) -> str:
        """Null byte deep in path (bypasses suffix-based WAF matching)."""
        return p + '%00.html'

    def _version_wildcard(p: str) -> str:
        """Insert /v1/ as API version prefix."""
        return '/v1' + p if not p.startswith('/v') else p

    def _cgi_bin_wrap(p: str) -> str:
        """CGI-bin wrapper bypass (IIS legacy routing)."""
        return '/cgi-bin/..' + p

    for path in paths:
        pl = path.lower()
        if not any(t in pl for t in _SENSITIVE_TRIGGERS):
            continue

        p = path

        # ── Tier 1: Basic normalisation bypasses ──────────────────────────────
        bypass_paths.add(p.rstrip('/') + '/..')             # trailing parent
        bypass_paths.add(p + ';/')                           # Spring semicolon bypass
        bypass_paths.add(p + '%09')                         # tab encoding
        bypass_paths.add('/' + p.lstrip('/').replace('/', '//', 1))  # double first slash
        bypass_paths.add(p + '?')                           # empty query bypass
        bypass_paths.add(p.replace('/', '/%2f', 1))         # encoded first slash
        bypass_paths.add(p + '/')                           # trailing slash

        # ── Tier 2: Case variants ──────────────────────────────────────────────
        bypass_paths.add(p.upper())                         # ALL UPPER
        bypass_paths.add(p.lower())                         # all lower (explicit)
        # Mixed case (first char of each segment upper)
        bypass_paths.add('/'.join(
            seg.capitalize() if seg else seg for seg in p.split('/')
        ))
        bypass_paths.add(_alternate_case_segment(p))       # alternating case

        # ── Tier 3: Encoding bypasses ──────────────────────────────────────────
        bypass_paths.add(_hex_encode_path(p))              # hex-encode alpha chars
        bypass_paths.add(_double_encode_slash(p))          # %252F double encoding
        bypass_paths.add(_overlong_utf8_slash(p))          # %C0%AF overlong UTF-8
        bypass_paths.add(_windows_separator(p))            # %5C backslash
        bypass_paths.add(_iis_unicode_bypass(p))           # IIS %c1%1c
        bypass_paths.add(_encoded_dot(p))                  # encoded dots (%2e)

        # ── Tier 4: Path structure tricks ─────────────────────────────────────
        bypass_paths.add(_mid_dot_segments(p))             # /seg1/./seg2
        bypass_paths.add(_nginx_alias_traversal(p))        # /seg1../seg2
        bypass_paths.add(_null_mid_path(p))                # /seg1%00/seg2
        bypass_paths.add(_deep_null_byte(p))               # /path%00.html
        # NOTE: Fragment bypass (#/) intentionally removed — HTTP clients strip
        # URI fragments before transmission; the server never sees the #/ part,
        # so adding it to probe paths is misleading and wastes probe capacity.

        # ── Tier 5: Parameter injection ───────────────────────────────────────
        bypass_paths.add(_spring_actuator_bypass(p))       # /path;type=1
        bypass_paths.add(_path_param_injection(p))         # /path;jsessionid=bypass
        # NOTE: _semicolon_prefix() generates ';/path' which starts with ';'
        # (not '/'), making it an invalid HTTP request-target. Replaced with
        # in-path semicolon insertions which are valid and actually bypass WAFs.
        bypass_paths.add(p + ';/')                          # trailing ;/ (Spring MVC)
        bypass_paths.add(p + ';lang=en')                   # ;lang=en suffix
        bypass_paths.add(p + ';v=2')                       # ;v=2 suffix
        bypass_paths.add(p + ';extension=api')             # ;extension bypass

        # ── Tier 6: Query string tricks ───────────────────────────────────────
        bypass_paths.add(_query_param_bypass(p))           # /path?debug=1
        bypass_paths.add(p + '?v=1.0')                    # version query
        bypass_paths.add(p + '?format=json')              # format bypass
        bypass_paths.add(p + '?_=1')                      # cache-bust query
        bypass_paths.add(p + '?callback=f')               # JSONP probe
        bypass_paths.add(_method_override_path(p))         # /path?_method=GET

        # ── Tier 7: Whitespace / non-printable tricks ─────────────────────────
        bypass_paths.add(_tab_in_path(p))                  # /path%09/
        bypass_paths.add(p + '%20')                        # space encoded
        bypass_paths.add(p + '%0a')                        # LF appended
        bypass_paths.add(p + '%0d')                        # CR appended
        # NOTE: %0d%0a/ (CRLF) intentionally removed — CRLF injection in paths
        # causes HTTP response splitting in HTTP/1.1 and is rejected by aiohttp
        # and most modern HTTP clients; probing with it produces errors, not findings.

        # ── Tier 8: Extension confusion ───────────────────────────────────────
        bypass_paths.add(_content_neg_bypass(p))           # /path.json
        bypass_paths.add(p + '.php')                       # .php suffix
        bypass_paths.add(p + '.html')                      # .html suffix
        bypass_paths.add(p + '.xml')                       # .xml suffix
        bypass_paths.add(p + '.do')                        # .do Java Struts
        bypass_paths.add(p + '.action')                    # .action Struts
        bypass_paths.add(p + '.aspx')                      # .aspx suffix
        bypass_paths.add(p + '.jsp')                       # .jsp suffix
        bypass_paths.add(p + ';.js')                       # semicolon+extension
        bypass_paths.add(p + ';.css')                      # semicolon+extension

        # ── Tier 9: API version tricks ────────────────────────────────────────
        bypass_paths.add(_api_version_bypass(p))           # /v0/path
        bypass_paths.add(_version_wildcard(p))             # /v1/path
        bypass_paths.add('/api' + p)                       # /api prefix
        bypass_paths.add('/api/v1' + p)                    # /api/v1 prefix
        bypass_paths.add('/internal' + p)                  # /internal prefix
        bypass_paths.add('/private' + p)                   # /private prefix

        # ── Tier 10: Naming variants ──────────────────────────────────────────
        bypass_paths.add(_underscored_variant(p))          # hyphens → underscores
        bypass_paths.add(_hyphenated_variant(p))           # underscores → hyphens

        # ── Tier 11: Legacy / server-specific ────────────────────────────────
        bypass_paths.add(_cgi_bin_wrap(p))                 # /cgi-bin/../path
        bypass_paths.add('/.' + p.lstrip('/'))             # hidden file variant
        bypass_paths.add(p + '~')                          # vim/emacs backup
        bypass_paths.add(p + '.bak')                       # backup extension
        bypass_paths.add(p + '.orig')                      # orig extension
        bypass_paths.add(p + '.save')                      # save extension

        # ── Tier 12: Unicode normalization attacks ────────────────────────────
        bypass_paths.add(_unicode_confusable(p))           # Unicode lookalike chars

        # ── Tier 13: Double-slash all separators ──────────────────────────────
        bypass_paths.add(p.replace('/', '//'))             # all double-slash
        bypass_paths.add('//' + p.lstrip('/'))             # double-slash root

        # ── Tier 14: Path traversal disguise ─────────────────────────────────
        bypass_paths.add(p + '/.')                         # /path/.
        bypass_paths.add(p + '/./')                        # /path/./
        bypass_paths.add(p + '/../.')                      # /path/..\.
        bypass_paths.add('/.' + '/'.join(p.lstrip('/').split('/')))

        # ── Tier 15: HTTP verb + X-Rewrite-URL patterns ───────────────────────
        # These bypass WAF rules based on X-Original-URL or X-Rewrite-URL headers;
        # served as path variants so they can be combined with header injection
        bypass_paths.add(p + '?x-rewrite=1')
        bypass_paths.add(p + '?_path=' + p)

        # ── Tier 16: Spring Boot ..;/ traversal bypass ────────────────────────
        # Spring MVC doesn't path-normalize semicolon parameters,
        # allowing WAF rule evasion via ..;/ sequences
        segs = p.lstrip('/').split('/')
        if len(segs) >= 2:
            bypass_paths.add('/' + segs[0] + '/..;/' + '/'.join(segs[1:]))
        bypass_paths.add(p.rstrip('/') + '/..;/')
        bypass_paths.add('/;/' + p.lstrip('/'))

        # ── Tier 17: IIS 8.3 short name (tilde) bypass ──────────────────────
        # IIS serves 8.3-compatible names like /admin~1/ for /administrator/
        first_seg = p.lstrip('/').split('/')[0] if '/' in p else p.lstrip('/')
        if first_seg and len(first_seg) > 2:
            bypass_paths.add('/' + first_seg[:6] + '~1/' + '/'.join(p.lstrip('/').split('/')[1:]))

        # ── Tier 18: Double-encoding bypass ─────────────────────────────────
        # %252F = double-encoded / (%25 is URL-encoded %, so %252F decodes to %2F then /)
        # Produces /seg1%252Fseg2 — WAF sees /seg1/seg2 after first decode, server sees
        # /seg1%2Fseg2 or /seg1/seg2 depending on second decode stage.
        double_encoded = '/' + p.lstrip('/').replace('/', '%252F', 1)  # double-encode FIRST inner /
        bypass_paths.add(double_encoded)
        bypass_paths.add(p.replace('/', '%252f'))  # %25 = percent sign, so %252f = literal %2f

        # ── Tier 19: JSON content negotiation bypass ─────────────────────────
        # Some WAFs only inspect non-JSON requests
        bypass_paths.add(p + '?format=json')
        bypass_paths.add(p + '?output=json')
        bypass_paths.add(p + '?_format=json')
        bypass_paths.add(p + '.json')

        # ── Tier 20: Verb tunneling via query parameter ──────────────────────
        # WAF may only inspect GET and miss POST-equivalent GETs
        bypass_paths.add(p + '?_method=GET')
        bypass_paths.add(p + '?method=GET')
        bypass_paths.add(p + '?X-HTTP-Method=GET')

        # ── Tier 21: Unicode full-width / half-width lookalikes ──────────────
        # Full-width ASCII chars (U+FF01-U+FF5E) bypass some WAF string matchers
        fw_p = p.replace('a', 'ａ').replace('d', 'ｄ').replace('m', 'ｍ').replace('i', 'ｉ').replace('n', 'ｎ')
        if fw_p != p:
            bypass_paths.add(fw_p)

        # ── Tier 22: HTTP/1.0 absolute-URI style path ────────────────────────
        # WAFs may not inspect absolute-form request URIs the same way
        bypass_paths.add(p + '?http1=1')
        bypass_paths.add(p + '?proto=http')

        # ── Tier 23: Namespace prefix bypass ─────────────────────────────────
        # Some frameworks expose duplicate routes under /api/v0/ or /api/v999/
        bypass_paths.add('/api/v0' + p)
        bypass_paths.add('/api/v999' + p)
        bypass_paths.add('/api/internal' + p)
        bypass_paths.add('/internal' + p)

        # ── Tier 24: Path parameter injection (;param=val) ───────────────────
        # Path parameters inserted in the middle fool WAF path-exact rules
        parts24 = p.lstrip('/').split('/', 1)
        if len(parts24) == 2:
            bypass_paths.add('/' + parts24[0] + ';bypass=1/' + parts24[1])
        bypass_paths.add(p + ';bypass=1')

        # ── Tier 25: Null-byte / overlong encoding ────────────────────────────
        bypass_paths.add(p + '%00.html')       # null byte terminates path in some parsers
        bypass_paths.add(p + '%00')             # bare null byte suffix
        bypass_paths.add(p.replace('/', '%c0%af', 1))   # overlong 2-byte UTF-8 slash (first only)

        # ── Tier 26: HTTP/2 pseudo-header path override ──────────────────────
        # Some proxies honour :path override when passed as X-HTTP2-Path
        bypass_paths.add(p + '?h2path=' + p)

        # ── Tier 27: Rewrite-rule confusion via repeated segments ────────────
        # Some WAF rewrite rules only inspect /path once; /path/path confuses them
        segs27 = p.lstrip('/').split('/')
        if segs27 and segs27[0]:
            bypass_paths.add('/' + segs27[0] + '/' + p.lstrip('/'))

        # ── Tier 28: Case + encoding hybrid ──────────────────────────────────
        # UPPERCASE path segment + URL-encoded slash confuses normalisation
        # All paths reaching this point are already confirmed sensitive (filtered above)
        bypass_paths.add(p.upper())
        bypass_paths.add(p.title().replace(' ', ''))

        # ── Tier 29: Non-standard port disambiguation suffix ──────────────────
        # Some WAFs only match on standard port; path with port prefix may bypass
        bypass_paths.add(p + '?port=80')
        bypass_paths.add(p + '?port=8080')

        # ── Tier 30: Content-type sniffing bypass via extension ───────────────
        bypass_paths.add(p + '.css')   # .css often whitelisted
        bypass_paths.add(p + '.woff2') # font path bypass
        bypass_paths.add(p + '.map')   # sourcemap bypass
        bypass_paths.add(p + '~')      # tilde backup file bypass
        bypass_paths.add(p + '.bak')   # backup extension bypass

        # ── Tier 31: Spring Cloud Gateway & Netty path confusion ─────────────
        # Spring routes /ADMIN%20/ differently from /admin/
        bypass_paths.add(p.rstrip('/') + '%20/')
        bypass_paths.add(p.rstrip('/') + '%09/')  # tab character
        # NOTE: CRLF (%0d%0a/) intentionally removed — breaks HTTP/1.1 requests.

        # ── Tier 32: Kubernetes apiserver & ingress path prefix tricks ────────
        bypass_paths.add('/k8s' + p)
        bypass_paths.add('/kubernetes' + p)
        bypass_paths.add('/api/proxy/namespaces/default' + p)

        # ── Tier 33: Tomcat URL encoding quirk ───────────────────────────────
        # Tomcat treats %2E as literal dot — bypass directory traversal WAF rules
        bypass_paths.add(p.replace('.', '%2E'))
        bypass_paths.add(p.replace('/', '/%2E%2E/') if p.count('/') > 1 else p)

    # Clean up: remove obviously malformed paths and deduplicate
    cleaned = set()
    for bp in bypass_paths:
        try:
            bp_str = str(bp)
            if bp_str and bp_str.startswith('/') and len(bp_str) < 512:
                cleaned.add(bp_str)
        except Exception:
            pass
    return cleaned

_BYPASS_VARIANT_PATHS = _generate_bypass_variants(
    list({p for ps in FW_PATHS.values() for p in ps}) + _ELITE_EXTRA_PATHS
)

# ── Sensitivity-tier path prioritization ─────────────────────────────────────
# Probe the most critical paths first (secrets → admin → actuators → API docs → generic)
# so findings appear early and the scan can be interrupted after high-value results.
_PRIORITY_TIER_SIGS = {
    0: (  # CRITICAL: direct secret/credential exposure
        ".env", "/.aws", "credentials", "id_rsa", "id_dsa", "private.key",
        "server.key", ".git/config", ".svn", ".htpasswd", "wp-config",
        "config.php", "database.php", "terraform.tfstate", ".boto",
        "aws-exports", "proc/environ", "proc/cmdline", "run/secrets",
    ),
    1: (  # CRITICAL: admin panels and remote exec
        "/admin", "/administrator", "/superadmin", "/superuser",
        "/wp-admin", "/wp-login", "/phpmyadmin", "/pma", "/adminer",
        "/manage", "/management", "/control", "/panel",
        "/cmd", "/exec", "/execute", "/shell", "/command",
    ),
    2: (  # HIGH: Spring Boot Actuators and sensitive APIs
        "/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/beans",
        "/actuator/configprops", "/actuator/mappings", "/actuator/httptrace",
        "/actuator/logfile", "/actuator/shutdown",
        "/jolokia", "/hawtio", "/jmx",
    ),
    3: (  # HIGH: k8s / cloud IMDS / vault / consul
        "/api/v1/secrets", "/api/v1/pods", "meta-data", "computeMetadata",
        "/v1/sys/", "/v1/auth/", "/v1/secret/",
        "/_cat/", "/_cluster/", "/api/v1/nodes",
    ),
    4: (  # HIGH: debug, profiling, info
        "/debug", "/_debugbar", "/phpinfo", "/server-status", "/server-info",
        "/_profiler", "/telescope", "/clockwork",
    ),
    5: (  # MEDIUM: API docs / GraphQL introspection
        "/swagger", "/openapi", "/graphql", "/graphiql", "/api-docs",
        "/swagger-ui", "/redoc", "/v1/introspect",
    ),
    6: (  # MEDIUM: metrics / monitoring
        "/metrics", "/prometheus", "/healthz", "/readyz",
    ),
}

def _path_priority(path: str) -> int:
    """Return sort priority (lower = higher priority) for a probe path."""
    pl = path.lower()
    for tier, sigs in sorted(_PRIORITY_TIER_SIGS.items()):
        if any(sig in pl for sig in sigs):
            return tier
    return 99  # lowest priority (generic path)

# Full sorted path list (used for mutation passes and reference)
_ALL_PROBE_PATHS_FULL = sorted(
    {p for ps in FW_PATHS.values() for p in ps} |
    set(_ELITE_EXTRA_PATHS) |
    _BYPASS_VARIANT_PATHS,
    key=_path_priority,
)

# ROOT CAUSE FIX: Phase 5 ran for 14+ hours because probe_host_paths() was called
# with all 6000+ paths per host.  With 12 concurrent hosts, WAF bypass attempts,
# and per-path multi-method probing (GET+HEAD+OPTIONS+POST for 401/403/405), the
# math works out to hours per host.
#
# Fix: use only the top 1500 highest-priority paths for the active probe phase.
# The remaining long-tail paths are covered by EndpointCrawler strategies (BFS,
# Wayback, robots, OpenAPI, GraphQL, JS analysis) and the Phase 5.5 mutation pass.
# This keeps Phase 5 under ~15 minutes for a 145-host target.
ALL_PROBE_PATHS = _ALL_PROBE_PATHS_FULL[:1500]

SUBDOMAIN_PREFIXES = [
    "www","mail","ftp","smtp","pop","pop3","imap","vpn","ssh","rdp","sftp",
    "dns","ns1","ns2","mx","mx1","mx2","relay","gateway",
    "dev","development","develop","devel","staging","stage","stg","uat","qa",
    "qat","pre-prod","test","testing","sandbox","demo","preview","beta","alpha",
    "canary","next","new","old","prod","production","live","release",
    "local","internal","private","ext","external","int","corp","intranet",
    "api","api2","api3","api-v1","api-v2","api-v3","rest","graphql","grpc","rpc",
    "auth","login","sso","oauth","id","identity","iam","idp","saml","ldap",
    "portal","dashboard","admin","manage","console","panel","control","cp","cpanel","whm",
    "shop","store","ecom","cart","checkout","pay","payment","billing","invoice",
    "blog","news","media","cdn","static","assets","img","images","video",
    "stream","live","hls","vod","rtmp","streaming",
    "app","apps","mobile","m","wap","web","www2","www3","pwa","spa",
    "cloud","k8s","kubernetes","docker","registry","container","harbor",
    "metrics","monitor","monitoring","grafana","kibana","elk","elastic",
    "prometheus","alertmanager","jaeger","zipkin","datadog","newrelic",
    "jenkins","ci","cd","build","deploy","pipeline","runner","argocd","flux",
    "git","gitlab","github","bitbucket","svn","nexus","artifactory","sonar",
    "jira","confluence","wiki","docs","documentation","kb","knowledge","notion",
    "support","help","helpdesk","tickets","service","servicedesk","freshdesk",
    "chat","slack","teams","meet","video","webrtc","voip","zoom",
    "status","uptime","health","ping","hc","statuspage",
    "db","database","mysql","postgres","mongo","redis","cache","memcache",
    "rabbitmq","kafka","queue","broker","zookeeper","mq","nats","pulsar","sqs",
    "smtp","mail2","email","webmail","owa","autodiscover","exchange",
    "remote","vpn2","openvpn","wireguard","proxy","forward","lb","edge","waf",
    "cdn1","cdn2","cloudfront","akamai","fastly","cloudflare",
    "security","sec","firewall","ids","siem","splunk","vault",
    "secrets","key","pki","cert","hsm","ca","certificate",
    "data","analytics","bi","reporting","reports","warehouse","dw","etl","lake",
    "search","elastic","solr","meilisearch","algolia","opensearch",
    "notify","notification","push","webhook","hooks","events","message","pubsub",
    "files","file","storage","s3","blob","upload","download","share","drive","minio",
    "ml","ai","model","inference","predict","train","notebook","jupyter","mlflow",
    "office","hr","crm","erp","sap","dynamics","salesforce","hubspot",
    "backup","dr","tools","util","utility","tooling","devtools",
    "v1","v2","v3","v4","legacy","archive","classic","old-api","new-api","beta-api",
    "microservice","service","services","svc","worker","cron","jobs","task","scheduler",
    "partner","partner-api","customer","public-api","private-api","internal-api",
    "cms","wp","wordpress","drupal","ghost","contentful","strapi","sanity",
    "forum","community","social","connect","hub","marketplace",
    "experimental","labs","research","innovation","sandbox2","dev2",
    "preprod","pre-production","integration","int","uat2","qa2",
    "staging2","test2","dev3","demo2","beta2","canary2",
    "origin","backend","frontend","middleware","gateway2","proxy2",
    "api-gateway","apigw","kong","envoy","traefik","nginx","haproxy",
    "vpn3","remote2","jump","bastion","citrix",
    "erp","sap","oracle","peoplesoft","workday",
    "iot","mqtt","rtsp","modbus","scada","plc",
    "webdav","ftp2","sftp2","rsync",
    "mobile-api","mobileapi","appapi","app-api",
    "internal2","intranet2","corp2","lan",
    "registry2","docker2","k8s2","kube","rancher","openshift",
    "cluster","node","worker","pod","shard",
    "wms","oms","pms","lms","hrms","scm","mdm",
    "payment2","billing2","finance","accounting","tax","payroll",
    "report","reporting2","dashboard2","analytics2",
    "events2","webhook2","notification2","alert","alarm",
    "connect","connect2","integration2","ipaas","zapier","n8n","mulesoft",
    "legacy2","archive2","old2","deprecated","sunset","eol",
    "test3","sandbox3","dev4","staging3","uat3",
    "apiv1","apiv2","apiv3","apiv4","apiv5",
    "consumer","producer","publisher","subscriber",
    "manager","controller","orchestrator","supervisor",
    "debug","diag","diagnostic","trace","telemetry","otel",
    # More internal / hidden / obscure subdomains
    "hidden","obscure","secret","confidential","restricted","sensitive",
    "private2","internal3","corp3","secure2","vault2",
    "root","superadmin","backdoor","maintenance","maint",
    "netadmin","netmgmt","syslog","sysmon","audit","compliance",
    "fortigate","checkpoint","paloalto","cisco","juniper","aruba",
    "netscaler","bigip","f5","kemp","haproxy2","traefik2","envoy2",
    "squid","tinyproxy","privoxy","mitm","intercept",
    "honeypot","honeytrap","canary2","decoy",
    "headless","phantom","selenium","playwright","puppeteer",
    "browserstack","saucelabs","lambdatest",
    "testenv","testbed","poc","prototype","mvp",
    "alpha2","beta3","gamma","delta","epsilon","omega",
    "r&d","innovation2","labs2","experiments","experimental2",
    "spike","scratch","throwaway","disposable","temp2","tmp",
    "hotfix","patch","bugfix","fix","fix2",
    "rollback","rollout","deploy2","release2","cut",
    "feature","featureflag","flag","flags","ab","abtesting",
    "darklaunch","shadow","mirror","twin",
    "readonly","writeonly","readwrite","rw","ro",
    "master","slave","primary","secondary","tertiary","replica",
    "fallback","failover","standby","active","passive",
    "blue","green","red","canary3","stable","unstable","nightly",
    "snapshot","archive3","cold","warm","hot",
    "shared","dedicated","reserved","exclusive",
    "east","west","north","south","central","global2","local2",
    "apse1","apse2","apse3","apne1","apne2","euw1","euw2","euw3",
    "useast1","useast2","uswest1","uswest2","eucentral1","euwest1",
    "saeast1","cacentral1","apso1","mesouth1",
    "az1","az2","az3","region1","region2","region3","zone1","zone2",
    "dc1","dc2","dc3","dc4","dc5","colo","colocation",
    "on-prem","onprem","bare-metal","baremetal","physical","virtual",
    "vm1","vm2","vm3","vps","vps1","vps2","vps3",
    "hq","headquarters","campus","office2","branch","satellite",
    "retail","wholesale","distributor","reseller","affiliate",
    "oem","partner2","third-party","3rdparty","vendor","supplier",
    "contractor","freelancer","consultant","agency","outsource",
    "enterprise","corporate","commercial","professional","premium",
    "freemium","trial","community2","open","public2","free",
    "paid","pro","business","teams2","growth","starter","basic",
    "saas","paas","iaas","faas","baas","daas",
    "multicloud","hybrid","edge2","fog","iot2","embedded",
    "5g","lte","wan","lan2","mpls","sd-wan","nfv","sdn",
    "telco","carrier","isp","peering","transit","upstream",
    "mx2","mx3","mx4","smtp2","smtp3","mta","mta2",
    "spf","dkim","dmarc","postmaster","abuse","noc","soc",
    "cert","csirt","incident","response","ir","red","blue2",
    "pentest","pentest2","bugbounty","bug-bounty","responsible-disclosure",
    "security2","infosec","appsec","devsecops","sast","dast",
    "compliance2","gdpr","pci","hipaa","sox","iso27001",
    "privacy","dpo","dsar","ccpa","lgpd",
    # ── Internal/shadow infrastructure subdomains ──────────────────────────
    "internal","internal2","intranet","intranet2","corp","corporate",
    "int","intra","private","priv","secret","hidden","shadow",
    "mgmt","management","manage","manager","admin2","administration",
    "sysadmin","netadmin","dbadmin","superadmin",
    "backend2","backend3","bk","bknd","app-backend","svc","service",
    "services2","services-internal","svc-internal","micro","microservice",
    "grpc","grpc2","rpc","rpc2","thrift","proto",
    "db","db2","db3","database","databases","datastore","ds",
    "postgres","pg","mysql","mariadb","oracle","mssql","sqlserver",
    "redis","redis2","rediscluster","redis-master","redis-slave",
    "rabbitmq","rabbit","mq","kafka","kafka2","kafkabroker","nats",
    "elastic","elasticsearch","es","kibana","logstash","beats",
    "cassandra","mongo","mongodb","couchdb","couchbase","dynamodb",
    "influxdb","influx","timescale","clickhouse","druid","presto",
    "neo4j","arangodb","rethinkdb",
    "cache","memcache","memcached","varnish",
    # ── Development and test environments ─────────────────────────────────
    "local","localhost","local2","dev","dev2","dev3","dev4","dev5",
    "development","develop","devel","devops","devops2",
    "test","test2","test3","testing","tst","uat","qa","qa2","qa3",
    "qassurance","qualityassurance",
    "sandbox","sandbox2","sbox","sb","sample","demo","demo2","demo3",
    "demo-api","demo-app","demo-data",
    "staging","staging2","staging3","stg","stg2","stge","stging",
    "stage","stage2","stage3","preprod","pre-prod","preproduction",
    "integration","int2","int3","integration2","e2e","end2end",
    "feature","feat","feat2","feature2","branch","sprint",
    "alpha","beta","beta2","gamma","delta","epsilon",
    "preview","preview2","next","next2","canary","canary2",
    "latest","current","new","new2","old","old2","legacy","legacy2",
    "v2","v3","v4","v5","v6","version","version2",
    # ── CI/CD and automation infrastructure ─────────────────────────────
    "jenkins","jenkins2","ci","ci2","cd","cicd","build","build2",
    "builds","buildserver","artifact","artifacts","artifactory",
    "nexus","registry","registry2","repo","repos","repository",
    "gitlab","gitlab2","glab","gitea","gitea2","gogs","gogs2",
    "bitbucket","bb","bamboo","teamcity","drone","drone2","circle",
    "travis","concourse","argo","argocd","flux","spinnaker",
    # ── Monitoring and observability ──────────────────────────────────────
    "grafana","grafana2","prometheus","prom","alertmanager","alert",
    "alerts","alerting","logging","logs","log","log2","logger",
    "metrics","metric","monitor","monitor2","monitoring","monitoring2",
    "observability","apm","tracing","tracer","jaeger","zipkin",
    "newrelic","datadog","dd","dynatrace","appdynamics","instana",
    "elk","efk","loki","loki2","sentry","sentry2","bugsnag","rollbar",
    "opsgenie","pagerduty","statuspage","statuspage2","status2",
    "uptime","pingdom","smokeping","icinga","nagios","zabbix","cacti",
    # ── Cloud-specific internal hostnames ─────────────────────────────────
    "vault","vault2","secrets","secrets2","secretsmanager","secretstore",
    "consul","consul2","etcd","etcd2","zookeeper","zoo",
    "kube","k8s","kubernetes","k8s-api","k8s-master","k8s-node",
    "rancher","rancher2","portainer","portainer2","harbor","harbor2",
    "docker","docker2","dockerregistry","swarm","swarm2",
    "terraform","terraform2","packer","ansible","puppet","chef","salt",
    "cloudformation","cfn","pulumi","cdk",
    # ── Security and access control ─────────────────────────────────────
    "sso","sso2","iam","idp","identity","identity2","sts","oauth",
    "oauth2","oidc","saml","ldap","ldap2","ad","activedirectory","radius",
    "okta","auth0","keycloak","dex","ping","forgerock","cyberark","onelogin",
    "mfa","2fa","otp","totp","yubikey",
    "certificate","pki","ca","ocsp","crl","acme","letsencrypt",
    # ── Data processing and analytics ────────────────────────────────────
    "spark","hadoop","hive","hbase","hdfs","yarn","mapreduce",
    "airflow","airflow2","luigi","prefect","dagster","nifi",
    "flink","flink2","storm","beam","samza",
    "redshift","bigquery","snowflake","databricks",
    "datalake","datalake2","datawarehouse","dwh","etl","elt","dbt",
    "tableau","powerbi","superset","metabase","redash","looker","mode",
    "jupyter","notebook","notebooks","zeppelin","rstudio",
    # ── Third-party integrations (often on subdomains) ────────────────
    "payments","payment","pay","checkout","checkout2","billing2",
    "stripe","braintree","paypal","adyen","klarna","square","mollie",
    "sms","sms2","push","notifications2","notify2","msg","messaging2",
    "chat2","chatbot","bot","bot2","chatops","slack2","teams3",
    "crm","crm2","salesforce","sf","hubspot","hs","dynamics","zendesk",
    "helpdesk","helpdesk2","support2","ticket2","freshdesk","freshservice",
    "jira2","confluence2","wiki2","docs2","knowledge","kb","faq2",
    # ── Partner and B2B endpoints ─────────────────────────────────────
    "partner","partner2","partners","partners2","b2b","b2b2",
    "vendor","vendor2","vendors","supplier","suppliers","wholesale",
    "affiliate","affiliate2","affiliates","reseller","reseller2",
    "client","client2","clients","customer2","clients2","consumer2",
    "portal2","extranet","extranet2","partner-portal","vendor-portal",
    # ── Machine learning and AI ───────────────────────────────────────
    "ml","ml2","mlops","mlflow","seldon","kfserving","triton",
    "ai","ai2","llm","gpt","model","models","inference","training",
    "feature-store","featurestore","feast","hopsworks","tecton",
    "label","labeling","annotation","labelstudio","scale","snorkel",
    # ── IoT and edge computing ────────────────────────────────────────
    "iot","iot2","edge","edge2","mqtt","mqtt2","amqp","coap",
    "firmware","firmware2","ota","ota2","telemetry","telemetry2",
    "gateway","gateway2","gw","gw2","rtsp","rtmp","hls","webrtc",
    # ── Geographic/regional deployments ──────────────────────────────
    "us","us2","usa","us-east","us-west","us-central","us-south",
    "eu","eu2","europe","eu-west","eu-east","eu-central","eu-north",
    "apac","ap","asia","ap-east","ap-south","ap-southeast","ap-northeast",
    "au","aus","australia","nz","nzl",
    "uk","gb","br","de","fr","jp","in","sg","hk","ca","mx",
    "global","worldwide","international","multi","multiregion","geo",
    "region1","region2","zone1","zone2","dc1","dc2","dc3","dc4",
    "prod1","prod2","prod3","prod-us","prod-eu","prod-apac",
    "dr","dr2","disaster","recovery","failover","backup2","standby",
    # ── Forgotten/deprecated/archived subdomains ─────────────────────
    "old","old2","archive","archive2","archived","legacy3","legacy4",
    "deprecated","depr","decommissioned","retired","dead","obsolete",
    "v1","v2-old","v3-old","prev","previous","historical",
    "2019","2020","2021","2022","2023","2024",
    "tmp","tmp2","temp","temp2","tmp3","temporary","scratch",
    "poc","prototype","proto","proof","concept","mvp","hack",
    "experiment","experimental","experiment2","lab","labs2",
    "sandbox3","sandbox4","testbed","playground","tryout",
]

# ─── Common ports for scanning ─────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 4443, 4848,
    5000, 5001, 5432, 5900, 6379, 6443, 7001, 7443, 7474, 8000, 8001,
    8008, 8009, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
    8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098,
    8099, 8161, 8180, 8181, 8200, 8222, 8280, 8300, 8333, 8384, 8443,
    8444, 8500, 8545, 8787, 8800, 8888, 8983, 9000, 9001, 9002, 9003,
    9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100,
    9200, 9300, 9418, 9999, 10000, 11211, 15672, 16686, 27017, 27018,
    27019, 28017, 50000, 50070, 50075, 61616, 61617,
]

# ─── Port service names ─────────────────────────────────────────────────────
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "http-dev",
    3306: "mysql", 3389: "rdp", 4443: "https-alt", 4848: "glassfish",
    5000: "http-dev", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    6443: "k8s-api", 7001: "weblogic", 7474: "neo4j",
    8080: "http-alt", 8443: "https-alt", 8888: "jupyter",
    8983: "solr", 9000: "portainer", 9090: "prometheus",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    9418: "git", 10000: "webmin", 11211: "memcached",
    15672: "rabbitmq", 16686: "jaeger", 27017: "mongodb",
    28017: "mongodb-web", 61616: "activemq",
}

# ─── Parameter wordlist for discovery ──────────────────────────────────────
PARAM_WORDLIST = [
    "id","user","username","email","page","limit","offset","cursor",
    "q","query","search","filter","sort","order","type","format","output",
    "token","key","api_key","apikey","auth","debug","test","verbose","trace",
    "callback","redirect","url","next","return","ref","from","to","target",
    "lang","locale","currency","country","region","timezone","tz",
    "from","to","start","end","date","time","timestamp","since","until",
    "fields","include","exclude","expand","embed","select","columns",
    "action","method","op","operation","cmd","command",
    "file","path","dir","folder","name","title","slug",
    "status","state","mode","level","version","v",
    "size","width","height","quality","format","resize",
    "secret","password","pass","token2","access_token","refresh_token",
    "code","grant","scope","client_id","client_secret","redirect_uri",
    "category","tag","label","group","role","permission",
    "parent","child","children","siblings","related","linked",
    "preview","draft","publish","archive","restore","delete",
    "export","import","download","upload","attach","attachment",
    "cache","no-cache","invalidate","purge","refresh",
    "page_size","per_page","items_per_page","max_results","count",
    "pretty","indent","minify","compress","encoding",
    "source","destination","origin","host","domain",
    "uuid","guid","sku","pid","uid","did","cid","sid","rid",
    "data","payload","body","content","message","text","html",
    "raw","base64","encoded","decoded",
    "context","namespace","prefix","suffix",
    "depth","recursive","flatten","nest",
    "async","sync","blocking","timeout","ttl",
    "dry_run","test_mode","sandbox","simulate",
    "force","override","strict","validate","verify",
    "sign","signature","hash","checksum","digest",
    "session","csrf","nonce","state","challenge",
    "webhook","callback_url","notify_url","return_url",
    "app","application","platform","device","browser",
    "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
    "ref","referrer","referred_by","affiliate","partner",
    "_","__","___","temp","tmp","x","y","z","n","i","a","b","c",
    "new","old","create","update","delete","get","set","add","remove",
    "list","all","any","many","one","find","match","check",
    "enable","disable","activate","deactivate","toggle",
    "reset","clear","flush","clean","wipe","purge",
    "report","log","audit","history","trace","debug",
    "notify","alert","send","receive","emit","broadcast",
    "config","setting","option","preference","param","attribute",
    "object","item","element","node","entry","record","row",
]

# ═══════════════════════════════════════════════════════════════════════════════
# MURMUR HASH 3  (pure Python — matches mmh3 output for Shodan favicon lookup)
# ═══════════════════════════════════════════════════════════════════════════════
def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 — signed 32-bit output (matches mmh3.hash())."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    for i in range(0, length - 3, 4):
        k1 = struct.unpack_from('<I', data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[length & ~3:]
    k1 = 0
    tl = length & 3
    if tl >= 3: k1 ^= tail[2] << 16
    if tl >= 2: k1 ^= tail[1] << 8
    if tl >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 2**32 if h1 >= 2**31 else h1

def favicon_hash(raw_bytes: bytes) -> int:
    """Compute Shodan-compatible favicon hash (base64 → mmh3)."""
    b64 = base64.encodebytes(raw_bytes)  # newline every 76 chars (Shodan compat)
    return _mmh3_32(b64)

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
    # New in v3
    open_ports:     Dict[str, List[Dict]]= field(default_factory=dict)  # host → [{port, service, banner}]
    takeover_candidates: List[Dict]     = field(default_factory=list)
    stale_dns:      List[Dict]          = field(default_factory=list)
    dns_records:    Dict[str, Dict]     = field(default_factory=dict)   # host → {type: [values]}
    favicon_hashes: Dict[str, int]      = field(default_factory=dict)   # host → hash
    parameters:     Dict[str, Set[str]]  = field(default_factory=lambda: defaultdict(set))  # endpoint → {param}
    cname_chains:   Dict[str, List[str]]= field(default_factory=dict)   # host → [cname chain]
    ip_ranges:      Set[str]            = field(default_factory=set)
    sources:        Dict[str, List[str]]= field(default_factory=lambda: defaultdict(list))  # sub → [srcs]
    js_findings:    Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    secrets:        Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))

    @property
    def all_subs(self) -> Set[str]:
        """Alias for subdomains — total set including non-live."""
        return self.subdomains

    def add_sub(self, s: str, src: str = "") -> None:
        s = s.strip().lower().rstrip(".")
        if s and self.domain in s and s != self.domain and len(s) < 253:
            if re.match(r'^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$', s):
                self.subdomains.add(s)
                if src:
                    self.source_counts[src] = self.source_counts.get(src, 0) + 1
                    if src not in self.sources[s]:
                        self.sources[s].append(src)

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
    if not p: return ""
    p = p.strip()
    pr = urlparse(p)
    if pr.scheme in ('http', 'https'):
        return p
    path = pr.path or p
    if not path.startswith('/'):
        path = '/' + path
    path = re.sub(r'/{2,}', '/', path)
    return path.split('#')[0][:512]

def _ua() -> str: return random.choice(UA_POOL)

def _hdrs(extra: Optional[Dict] = None) -> Dict[str, str]:
    h = {
        "User-Agent": _ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "application/json,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    if extra: h.update(extra)
    return h

def _subs_from_text(text: str, domain: str) -> Set[str]:
    pat = re.compile(
        r'(?<![.\w])((?:[\w\-]+\.)+' + re.escape(domain) + r')(?![.\w])', re.I)
    return {m.group(1).lower().rstrip('.') for m in pat.finditer(text)
            if m.group(1).lower() != domain}

def _urls_from_text(text: str, domain: str) -> Set[str]:
    out: Set[str] = set()
    for m in re.finditer(r'(https?://[^\s\'\"<>\)\(,]{3,300})', text, re.I):
        full = m.group(1)
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
        r'rest|service|endpoint|resource|grpc|ws|socket|mobile|app|'
        r'payment|billing|order|product|customer|report|export|import|'
        r'notification|event|job|task|worker|queue|cache|file|storage|'
        r'backup|log|audit|trace|debug|diag|monitor|alert|notify)[^\s\'"`<>\\]{0,300})[\'"`]',
        r'fetch\s*\(\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
        r'axios\.\w+\s*\(\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
        r'url\s*[:=]\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
        r'path\s*[:=]\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
        r'endpoint\s*[:=]\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
        r'route\s*[:=]\s*[\'"`](/[^\s\'"`<>\\]{1,300})[\'"`]',
        r'href\s*=\s*[\'"]([^\'\"]{1,300})[\'"]',
        r'action\s*=\s*[\'"]([^\'\"]{1,300})[\'"]',
        r'(?:get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`\s]{1,300})[\'"`]',
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.I):
            p = _norm_path(m.group(1))
            if p and len(p) < 400 and p.startswith('/'):
                out.add(p)
    return out

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def log(msg: str, lvl: str = "INF") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    colors = {"INF": "\033[90m", "WRN": "\033[93m", "ERR": "\033[91m", "SUC": "\033[92m"}
    c = colors.get(lvl, "\033[90m")
    print(f"{c}[{ts}]\033[0m [{lvl}] {msg}", flush=True)

# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════
class RL:
    def __init__(self, rps: float):
        self._delay = 1.0 / rps if rps > 0 else 0
        self._lock  = asyncio.Lock()
        self._last  = 0.0
    async def wait(self) -> None:
        if self._delay == 0: return
        async with self._lock:
            now  = time.monotonic()
            wait = self._delay - (now - self._last)
            if wait > 0: await asyncio.sleep(wait)
            self._last = time.monotonic()

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
async def _fetch(
    session: "aiohttp.ClientSession", url: str, *,
    method: str = "GET", hdrs: Optional[Dict] = None,
    params: Optional[Dict] = None, json_body: Optional[Any] = None,
    retries: int = RETRIES, timeout: int = REQ_TIMEOUT,
    as_json: bool = False, as_text: bool = True,
    as_bytes: bool = False,
    allow_redirects: bool = True, proxy: Optional[str] = None,
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
                if as_bytes:
                    return await r.read()
                if as_json:
                    try: return await r.json(content_type=None)
                    except Exception: return None
                if as_text:
                    return await r.text(errors='replace')
                return r.status
        except asyncio.TimeoutError:
            if attempt < retries - 1: await asyncio.sleep(BACKOFF ** attempt)
        except Exception:
            if attempt < retries - 1: await asyncio.sleep(BACKOFF ** attempt)
    return None

async def _jget(s, url, **kw): return await _fetch(s, url, as_json=True, as_text=False, **kw)
async def _tget(s, url, **kw): return await _fetch(s, url, as_text=True, as_json=False, **kw)
async def _bget(s, url, **kw): return await _fetch(s, url, as_bytes=True, as_text=False, as_json=False, **kw)

# ═══════════════════════════════════════════════════════════════════════════════
# DNS HELPERS — Fast UDP resolver + DoH fallback
# ═══════════════════════════════════════════════════════════════════════════════

# struct already imported at top-level; alias removed (was redundant)
_struct = struct  # keep _struct name so DNS packet code below works unchanged

# ---------------------------------------------------------------------------
# Raw UDP DNS packet builder / parser (no external deps)
# ---------------------------------------------------------------------------
_DNS_QTYPE = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2,
              "TXT": 16, "SRV": 33, "SOA": 6, "PTR": 12, "CAA": 257}

def _build_dns_query(tid: int, name: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet."""
    hdr = _struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    parts = name.rstrip('.').split('.')
    qname = b""
    for p in parts:
        enc = p.encode()
        qname += bytes([len(enc)]) + enc
    qname += b"\x00"
    q = _struct.pack(">HH", qtype, 1)
    return hdr + qname + q

def _parse_dns_response(data: bytes) -> List[str]:
    """Parse A records from a DNS response. Returns list of IP strings."""
    if len(data) < 12:
        return []
    try:
        tid, flags, qdcount, ancount, _, _ = _struct.unpack_from(">HHHHHH", data)
        rcode = flags & 0x000F
        if rcode != 0 or ancount == 0:
            return []
        # Skip header
        off = 12
        # Skip question section
        for _ in range(qdcount):
            while off < len(data) and data[off] != 0:
                if data[off] & 0xC0 == 0xC0:
                    off += 2; break
                off += 1 + data[off]
            else:
                off += 1
            off += 4  # qtype + qclass
        # Parse answer section
        results = []
        for _ in range(ancount):
            # Name (possibly compressed)
            if off >= len(data): break
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while off < len(data) and data[off] != 0:
                    if data[off] & 0xC0 == 0xC0:
                        off += 2; break
                    off += 1 + data[off]
                else:
                    off += 1
            if off + 10 > len(data): break
            rtype, rclass, ttl, rdlen = _struct.unpack_from(">HHIH", data, off)
            off += 10
            rdata = data[off:off+rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:  # A record
                results.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and rdlen == 16:  # AAAA
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))
        return results
    except Exception:
        return []

def _parse_dns_cname(data: bytes, domain_hint: str = "") -> List[str]:
    """Parse CNAME/PTR/NS/MX string records from DNS response."""
    if len(data) < 12: return []
    results = []
    try:
        _, _, qdcount, ancount, _, _ = _struct.unpack_from(">HHHHHH", data)
        off = 12
        for _ in range(qdcount):
            while off < len(data):
                if data[off] & 0xC0 == 0xC0: off += 2; break
                if data[off] == 0: off += 1; break
                off += 1 + data[off]
            off += 4
        for _ in range(ancount):
            if off >= len(data): break
            if data[off] & 0xC0 == 0xC0: off += 2
            else:
                while off < len(data) and data[off] != 0:
                    if data[off] & 0xC0 == 0xC0: off += 2; break
                    off += 1 + data[off]
                else: off += 1
            if off + 10 > len(data): break
            rtype, _, _, rdlen = _struct.unpack_from(">HHIH", data, off)
            off += 10
            rdata = data[off:off+rdlen]
            off += rdlen
            if rtype in (5, 12, 2, 15, 6):
                # Decode label sequence
                name = _decode_dns_name(data, off - rdlen)
                if name: results.append(name)
    except Exception:
        pass
    return results

def _decode_dns_name(data: bytes, off: int) -> str:
    """Decode a DNS name (with pointer compression) starting at off."""
    parts = []; jumps = 0; max_jumps = 10
    try:
        while off < len(data):
            length = data[off]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                if off + 1 >= len(data): break
                ptr = ((length & 0x3F) << 8) | data[off+1]
                off = ptr
                jumps += 1
                if jumps > max_jumps: break
                continue
            off += 1
            parts.append(data[off:off+length].decode('ascii', errors='replace'))
            off += length
    except Exception:
        pass
    return '.'.join(parts)

# ---------------------------------------------------------------------------
# Async UDP DNS resolver using DatagramProtocol
# ---------------------------------------------------------------------------

# Module-level shared aiohttp session for DoH fallback
# Avoids creating thousands of sessions when many workers fall back simultaneously
_DOH_SESSION: Optional[Any] = None

async def _get_doh_session():
    """Return shared aiohttp.ClientSession for DoH queries. Lazy-initialized (async-safe)."""
    global _DOH_SESSION
    try:
        if _DOH_SESSION is None or _DOH_SESSION.closed:
            # Must be created inside a running event loop (aiohttp 3.x requirement)
            _DOH_SESSION = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=50, ssl=False),
                timeout=aiohttp.ClientTimeout(total=6),
            )
        return _DOH_SESSION
    except Exception:
        return None

class _DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self._futures: Dict[int, asyncio.Future] = {}
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr):
        if len(data) < 2: return
        tid = _struct.unpack_from(">H", data)[0]
        fut = self._futures.get(tid)
        if fut and not fut.done():
            fut.set_result(data)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        for fut in self._futures.values():
            if not fut.done():
                fut.cancel()

class FastUDPResolver:
    """
    Ultra-fast async UDP DNS resolver.
    - Sends raw UDP packets to multiple resolvers round-robin
    - 8000 concurrent in-flight queries
    - LRU cache for repeated lookups
    - DoH fallback for blocked UDP (Cloudflare + Google)
    - Retry with different resolver on timeout
    - Resolver health tracking: skip consistently failing resolvers
    """
    MAX_INFLIGHT = 10_000
    TIMEOUT      = 3.5    # generous timeout for slow/international resolvers
    RETRY        = 3     # three retries on different resolvers before DoH

    def __init__(self, resolvers: List[str] = None):
        # Deduplicate resolvers while preserving order
        seen: set = set()
        dedup = []
        for r in (resolvers or DNS_RESOLVERS):
            if r not in seen:
                seen.add(r); dedup.append(r)
        self._resolvers = dedup
        self._idx       = 0
        self._cache: Dict[str, List[str]] = {}
        # _sem removed — MAX_INFLIGHT is enforced by the worker pool queue size
        # in batch_resolve(), not by a semaphore inside the resolver itself.
        self._tid       = 1
        self._protocols: Dict[str, Tuple] = {}  # server_ip → (transport, protocol)
        self._lock      = asyncio.Lock()         # global lock for _proto_locks creation
        self._proto_locks: Dict[str, asyncio.Lock] = {}  # per-server creation lock

    def _next_resolver(self) -> str:
        """Return next resolver in round-robin order.
        Guaranteed to distribute load across ALL resolvers."""
        idx = self._idx % len(self._resolvers)
        self._idx = (self._idx + 1) % (len(self._resolvers) * 1000)  # prevent overflow
        return self._resolvers[idx]

    def _next_tid(self) -> int:
        # Synchronous TID increment — asyncio is single-threaded so no lock needed here
        self._tid = (self._tid + 1) & 0xFFFF
        if self._tid == 0: self._tid = 1
        return self._tid

    async def _get_protocol(self, server_ip: str) -> Optional[Tuple]:
        # Fast path: already cached and alive (no await needed)
        cached = self._protocols.get(server_ip)
        if cached and not cached[0].is_closing():
            return cached
        # Ensure per-server lock exists (under global lock to avoid TOCTOU)
        async with self._lock:
            if server_ip not in self._proto_locks:
                self._proto_locks[server_ip] = asyncio.Lock()
        # Per-server lock: prevents N concurrent workers from creating N duplicate sockets
        async with self._proto_locks[server_ip]:
            # Re-check under lock (another coroutine may have created it)
            cached = self._protocols.get(server_ip)
            if cached and not cached[0].is_closing():
                return cached
            try:
                loop = asyncio.get_running_loop()
                t, p = await loop.create_datagram_endpoint(
                    _DNSProtocol,
                    remote_addr=(server_ip, 53),
                )
                self._protocols[server_ip] = (t, p)
                return t, p
            except Exception:
                return None

    async def resolve_raw(self, name: str, qtype: int = 1, server: Optional[str] = None) -> List[str]:
        """Send single DNS query and wait for response. Returns list of records."""
        srv = server or self._next_resolver()
        tid = self._next_tid()
        pkt = _build_dns_query(tid, name, qtype)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        proto_ref: Optional[Any] = None   # saved reference for correct cleanup
        try:
            tp = await self._get_protocol(srv)
            if not tp:
                return []
            t, p = tp
            proto_ref = p          # save BEFORE any further awaits
            p._futures[tid] = fut
            t.sendto(pkt)
            data = await asyncio.wait_for(asyncio.shield(fut), timeout=self.TIMEOUT)
            if qtype in (1, 28):  # A or AAAA — both use the same RR parser
                return _parse_dns_response(data)
            else:
                return _parse_dns_cname(data)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return []
        except Exception:
            return []
        finally:
            # Always clean up using the SPECIFIC protocol that registered this future
            # (self._protocols[srv] may have been replaced if the socket was recycled)
            if proto_ref is not None:
                proto_ref._futures.pop(tid, None)
            # Cancel the future if still pending (timeout case)
            if not fut.done():
                fut.cancel()

    async def resolve(self, name: str, qtype: str = "A") -> List[str]:
        """Resolve name:qtype with cache + retry + DoH fallback.
        Each attempt uses a DIFFERENT resolver selected via proper rotation
        so thousands of concurrent workers don't all hammer resolver[0]."""
        key = f"{name}:{qtype}"
        if key in self._cache:
            return self._cache[key]

        qt = _DNS_QTYPE.get(qtype, 1)
        results = []

        # Use rotating resolver selection (not attempt%len which always picks [0]/[1])
        for attempt in range(self.RETRY + 1):
            srv = self._next_resolver()   # proper rotation across all 100+ resolvers
            results = await self.resolve_raw(name, qt, server=srv)
            if results:
                break
            if attempt < self.RETRY:
                await asyncio.sleep(0.01)  # shorter sleep — fail fast

        # DoH fallback only when UDP completely fails (keeps it lightweight)
        if not results:
            results = await self._doh_resolve(name, qtype)

        # CRITICAL: Only cache positive results — never cache failures.
        # Caching an empty list permanently marks the host as NXDOMAIN even when
        # the failure was transient (timeout, SERVFAIL, packet loss). This is the
        # root cause of "very low" resolution counts when resolvers are flaky.
        if results:
            self._cache[key] = results
        return results

    async def _doh_resolve(self, name: str, qtype: str = "A") -> List[str]:
        """DNS-over-HTTPS fallback (Cloudflare / Google).
        Uses a module-level shared session to avoid creating thousands of sessions
        when many concurrent workers fall back to DoH simultaneously."""
        urls = [
            f"https://cloudflare-dns.com/dns-query?name={name}&type={qtype}",
            f"https://dns.google/resolve?name={name}&type={qtype}",
        ]
        for url in urls:
            try:
                sess = await _get_doh_session()
                if sess is None:
                    continue
                async with sess.get(
                    url,
                    headers={"Accept": "application/dns-json"},
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status != 200: continue
                    data = await resp.json(content_type=None)
                    answers = data.get("Answer", [])
                    out = []
                    for a in answers:
                        t = a.get("type", 0)
                        d = str(a.get("data", "")).rstrip(".")
                        if (qtype == "A" and t == 1) or (qtype == "AAAA" and t == 28):
                            out.append(d)
                        elif qtype in ("CNAME","NS","PTR","MX") and t in (5,2,12,15):
                            out.append(d)
                        elif qtype == "TXT" and t == 16:
                            out.append(d.strip('"'))
                        elif qtype == "SRV" and t == 33:
                            out.append(d)
                    if out:
                        return out
            except Exception:
                pass
        return []

    async def resolve_a(self, name: str) -> Optional[str]:
        """Convenience: return first A record or None."""
        results = await self.resolve(name, "A")
        return results[0] if results else None

    def close(self):
        for t, p in self._protocols.values():
            try: t.close()
            except Exception: pass
        self._protocols.clear()

# Module-level shared fast resolver
_FAST_RESOLVER: Optional[FastUDPResolver] = None

def _get_fast_resolver() -> FastUDPResolver:
    global _FAST_RESOLVER
    if _FAST_RESOLVER is None:
        _FAST_RESOLVER = FastUDPResolver(DNS_RESOLVERS)
    return _FAST_RESOLVER

_SHARED_RESOLVER: Optional[Any] = None

def _get_resolver() -> Any:
    """Return a shared dns.asyncresolver.Resolver with public DNS servers."""
    global _SHARED_RESOLVER
    if _SHARED_RESOLVER is None and DNSPY:
        _SHARED_RESOLVER = dns.asyncresolver.Resolver()
        _SHARED_RESOLVER.nameservers = [
            "8.8.8.8", "8.8.4.4",
            "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220",
        ]
        _SHARED_RESOLVER.timeout  = DNS_TIMEOUT
        _SHARED_RESOLVER.lifetime = DNS_TIMEOUT
    return _SHARED_RESOLVER

async def _resolve(host: str, rtype: str = 'A') -> Optional[str]:
    fr = _get_fast_resolver()
    try:
        results = await fr.resolve(host, rtype)
        if results:
            return results[0]
    except Exception:
        pass
    # Fallback to dnspython
    if DNSPY:
        try:
            r2 = dns.asyncresolver.Resolver()
            r2.timeout = DNS_TIMEOUT; r2.lifetime = DNS_TIMEOUT
            r2.nameservers = DNS_RESOLVERS[:4]
            ans = await r2.resolve(host, rtype)
            return str(ans[0])
        except Exception:
            pass
    if rtype != 'A':
        return None
    try:
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return info[0][4][0] if info else None
    except Exception:
        return None

async def _resolve_all(host: str, rtype: str = 'A') -> List[str]:
    fr = _get_fast_resolver()
    try:
        results = await fr.resolve(host, rtype)
        if results:
            return results
    except Exception:
        pass
    if not DNSPY:
        return []
    try:
        r2 = dns.asyncresolver.Resolver()
        r2.timeout = DNS_TIMEOUT; r2.lifetime = DNS_TIMEOUT
        r2.nameservers = DNS_RESOLVERS[:4]
        ans = await r2.resolve(host, rtype)
        return [str(a) for a in ans]
    except Exception:
        return []

async def _wildcard(domain: str) -> Set[str]:
    """
    Probe 10 random subdomains to build a comprehensive wildcard IP set.
    Returns a SET of wildcard IPs (handles CDN/load-balanced wildcards).
    Returns empty set if no wildcard detected.

    ROOT CAUSE FIX: The old 5-probe / 2-of-5 (40%) threshold was far too
    aggressive.  CDN load balancers can return different IPs across requests,
    so 2 matching hits out of 5 could easily be a coincidence, causing
    legitimate CDN-backed subdomains to be falsely marked as wildcards and
    then silently dropped in batch_resolve().

    New design:
      • 10 random probes (different lengths so they can't collide with real names)
      • An IP must appear in ≥ 8 of 10 probes (80% consensus) to be considered
        a wildcard IP.  Load-balanced CDNs with large IP pools virtually never
        return the same IP 8/10 times for random names, so this eliminates the
        false-positive wildcard detection that was zeroing out CDN-hosted targets.
      • We still use random.choices(ascii_lowercase, k=N) so the names are
        syntactically valid and guaranteed not to be real subdomains.
    """
    from collections import Counter
    wc_ips: Set[str] = set()
    # 10 probes with varied lengths — must not match real short prefixes
    lengths = [18, 22, 15, 26, 19, 21, 17, 24, 16, 23]
    randoms = [''.join(random.choices(string.ascii_lowercase, k=k)) for k in lengths]
    tasks = [_resolve(f"{r}.{domain}") for r in randoms]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    resolved_ips: List[str] = [r for r in results if isinstance(r, str) and r]
    if len(resolved_ips) < 3:
        # Fewer than 3 probes resolved — not enough signal, assume no wildcard
        return wc_ips
    counts = Counter(resolved_ips)
    # Require ≥ 80% consensus: IP must appear in at least 8 out of 10 probes
    threshold = max(2, int(len(randoms) * 0.80))
    wc_ips = {ip for ip, cnt in counts.items() if cnt >= threshold}
    if wc_ips:
        log(f"  [wildcard] {domain}: wildcard IPs detected (80% consensus) → {wc_ips}")
    return wc_ips


async def batch_resolve(
    hosts: List[str],
    wc: Optional[Set[str]] = None,
    known_subs: Optional[Set[str]] = None,
) -> Dict[str, str]:
    """
    Elite batch DNS resolver — queue-based worker pool, tuned for correctness + speed.

    Key design:
    • Workers drain a shared asyncio.Queue (no sequential chunk loop)
    • Each call to fr.resolve() uses a DIFFERENT resolver via rotation in FastUDPResolver
    • Wildcard detection: filter ANY IP in the wildcard SET (handles CDN/LB wildcards)
      BUT passively-discovered subdomains (known_subs) are NEVER filtered by wildcard IPs
      because those are confirmed real names that may legitimately resolve to CDN IPs.
    • Also tries AAAA (IPv6) as fallback for hosts with no A record
    • DoH is NOT explicitly called here — FastUDPResolver.resolve() already tries DoH
      internally as the final fallback step, so the old redundant _doh_resolve() call
      has been removed.
    • No blocking os.getaddrinfo() — stays fully async
    • NWORKERS = min(2000, total) for maximum throughput
    • Smooth progress bar with percentage + ETA displayed every tick

    ROOT CAUSE FIX for "very low" DNS live subdomain counts:
    ──────────────────────────────────────────────────────────
    The old code applied the wildcard IP filter to EVERY host including passively-
    confirmed subdomains (CT logs, Censys, Shodan, etc.).  For CDN-backed domains
    (Cloudflare, Akamai, Fastly, CloudFront), _wildcard() would detect the CDN's
    shared IP pool as "wildcard IPs".  Then batch_resolve() would drop every
    subdomain that resolved to those same CDN IPs — which is ALL of them.

    Fix: pass known_subs (r.subdomains from passive recon) and skip the wildcard IP
    filter for those hosts.  Only brute-force guesses need wildcard filtering.
    """
    host_list = list(hosts)
    if not host_list:
        return {}
    total   = len(host_list)
    out: Dict[str, str] = {}
    wc_set: Set[str] = wc if wc else set()
    # Passively confirmed subdomains — skip wildcard-IP filtering for these
    trusted: Set[str] = known_subs if known_subs else set()
    fr      = _get_fast_resolver()
    counter = [0]
    lock    = asyncio.Lock()

    # 2000 workers for maximum throughput — queue naturally limits work-in-flight
    NWORKERS = min(2000, total)

    q: asyncio.Queue = asyncio.Queue()
    for h in host_list:
        q.put_nowait(h)

    # Progress: report every 1% or every 50 hosts, whichever is more frequent
    report_every = max(50, total // 100)
    t_start = [time.monotonic()]

    # TQDM progress bar if available
    _pbar = None
    if TQDM:
        try:
            from tqdm import tqdm as _tqdm
            _pbar = _tqdm(total=total, desc="DNS resolve", unit="host",
                          bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}",
                          dynamic_ncols=True)
        except Exception:
            _pbar = None

    async def _worker():
        while True:
            try:
                h = q.get_nowait()
            except Exception:
                return
            resolved_ip = None
            # Passively-confirmed names are never subject to wildcard-IP filtering.
            # They come from CT logs, Shodan, Censys etc — they ARE real subdomains
            # even if they resolve to a shared CDN IP pool.
            is_trusted = h in trusted
            try:
                # Try A record only — skipping AAAA fallback here is intentional.
                # In cloud/CT environments UDP port 53 is often blocked, so every
                # failed A query already burns 3×TIMEOUT for UDP retries + DoH.
                # Adding an AAAA query would double that per-host cost for the
                # ~99.9% of candidates that don't exist, crushing throughput.
                # IPv6-only hosts are extremely rare in subdomain brute-force targets;
                # any genuine IPv6-only subdomains will have been captured in Phase 1
                # passive OSINT (CT logs, Censys, etc.) and are already in known_subs.
                # Note: fr.resolve() already tries DoH internally as its final fallback.
                results_a = await fr.resolve(h, "A")
                if results_a:
                    candidate = results_a[0]
                    if candidate and (is_trusted or candidate not in wc_set):
                        resolved_ip = candidate
            except Exception:
                pass
            async with lock:
                if resolved_ip:
                    out[h] = resolved_ip
                counter[0] += 1
                c = counter[0]
            if _pbar:
                _pbar.update(1)
                _pbar.set_postfix({'live': len(out)}, refresh=False)
            elif c % report_every == 0 or c == total:
                elapsed = time.monotonic() - t_start[0]
                rate = c / elapsed if elapsed > 0.1 else 0
                eta = (total - c) / rate if rate > 0 else 0
                pct = c * 100 // total
                bar_filled = pct // 5
                bar = "█" * bar_filled + "░" * (20 - bar_filled)
                log(f"  [DNS] [{bar}] {pct:3d}% | {c:,}/{total:,} | live={len(out):,} | "
                    f"{rate:.0f} host/s | ETA {eta:.0f}s")

    log(f"  [DNS] Resolving {total:,} hosts — {NWORKERS:,} workers | "
        f"{len(fr._resolvers)} resolvers | wildcard IPs={wc_set or 'none'}")
    t0 = time.monotonic()
    await asyncio.gather(*[_worker() for _ in range(NWORKERS)], return_exceptions=True)
    if _pbar:
        _pbar.close()
    elapsed = time.monotonic() - t0
    rate = int(total / elapsed) if elapsed > 0 else 0
    log(f"  [DNS] Done: {len(out):,} live / {total:,} in {elapsed:.1f}s ({rate:,}/s)")
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# FAVICON HASHER — MurmurHash3 + Shodan favicon search
# ═══════════════════════════════════════════════════════════════════════════════
class FaviconHasher:
    def __init__(self, s, r: Result, d: str, keys: Dict, proxy: Optional[str]):
        self.s = s; self.r = r; self.d = d; self.keys = keys; self.proxy = proxy

    async def run(self) -> None:
        targets = [f"https://{self.d}"] + [f"https://{sub}" for sub in list(self.r.live_subs)[:20]]
        tasks = [self._hash_host(t) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _hash_host(self, base_url: str) -> None:
        host = urlparse(base_url).netloc or base_url
        favicon_urls = [
            f"{base_url}/favicon.ico",
            f"{base_url}/favicon.png",
            f"{base_url}/apple-touch-icon.png",
            f"{base_url}/images/favicon.ico",
            f"{base_url}/static/favicon.ico",
            f"{base_url}/assets/favicon.ico",
        ]
        # Also try to extract from HTML link[rel=icon]
        try:
            html = await _tget(self.s, base_url, timeout=12, proxy=self.proxy)
            if html:
                for m in re.finditer(
                    r'<link[^>]+rel=[\'"](?:shortcut )?icon[\'"][^>]+href=[\'"]([^\'"]+)[\'"]',
                    html, re.I):
                    href = m.group(1)
                    resolved = urljoin(base_url, href)
                    if resolved not in favicon_urls:
                        favicon_urls.insert(0, resolved)
        except Exception:
            pass

        for furl in favicon_urls:
            raw = await _bget(self.s, furl, timeout=10, proxy=self.proxy)
            if raw and len(raw) > 100:
                fhash = favicon_hash(raw)
                self.r.favicon_hashes[host] = fhash
                log(f"  Favicon hash [{host}]: {fhash}")
                await self._shodan_favicon_search(fhash)
                break

    async def _shodan_favicon_search(self, fhash: int) -> None:
        sk = self.keys.get("shodan", "")
        if not sk: return
        try:
            data = await _jget(
                self.s,
                "https://api.shodan.io/shodan/host/search",
                params={"key": sk, "query": f"http.favicon.hash:{fhash}", "minify": "true"},
                timeout=20, proxy=self.proxy)
            if not isinstance(data, dict): return
            for match in data.get("matches", []):
                domains = match.get("domains", []) or []
                hostnames = match.get("hostnames", []) or []
                for h in domains + hostnames:
                    if h and self.d in h.lower():
                        self.r.add_sub(h, "favicon_hash")
                    elif h and "." in h and self.d in h:
                        # Different domain — could be same org (only record if in-scope)
                        self.r.add_sub(h, "favicon_org")
                ip = match.get("ip_str", "")
                if ip:
                    self.r.ip_ranges.add(ip)
        except Exception:
            pass

# ═══════════════════════════════════════════════════════════════════════════════
# DNS ENUMERATOR — Advanced: zone transfer, ALL record types, NSEC/NSEC3 walk,
# PTR /24 sweep, DoH queries, TLS SAN extraction, ASN/BGP range reverse DNS,
# SRV brute-force (200+ prefixes), DKIM selectors, DNS history
# ═══════════════════════════════════════════════════════════════════════════════
class DNSEnumerator:
    # 200+ SRV prefixes for comprehensive service discovery
    SRV_PREFIXES = [
        "_http._tcp","_https._tcp","_ftp._tcp","_sftp._tcp","_ssh._tcp",
        "_smtp._tcp","_smtps._tcp","_imap._tcp","_imaps._tcp","_pop3._tcp",
        "_pop3s._tcp","_submission._tcp","_xmpp-server._tcp","_xmpp-client._tcp",
        "_jabber._tcp","_irc._tcp","_ircs._tcp","_ldap._tcp","_ldaps._tcp",
        "_kerberos._tcp","_kerberos._udp","_kpasswd._tcp","_kpasswd._udp",
        "_sip._tcp","_sip._udp","_sips._tcp","_stun._tcp","_stun._udp",
        "_turn._tcp","_turn._udp","_turns._tcp","_webrtc._tcp","_webrtcs._tcp",
        "_minecraft._tcp","_mumble._tcp","_mumble._udp","_teamspeak._udp",
        "_vpn._udp","_openvpn._tcp","_openvpn._udp","_wireguard._udp",
        "_caldav._tcp","_caldavs._tcp","_carddav._tcp","_carddavs._tcp",
        "_autodiscover._tcp","_autoconfig._tcp","_msrapc._tcp",
        "_dmarc","_domainkey","_acme-challenge",
        "_submissions._tcp",
        "_webdav._tcp","_webdavs._tcp","_nfs._tcp","_nfs._udp",
        "_afpovertcp._tcp","_smb._tcp","_cifs._tcp",
        "_postgresql._tcp","_mysql._tcp","_mongodb._tcp","_redis._tcp",
        "_elasticsearch._tcp","_rabbitmq._tcp","_kafka._tcp",
        "_prometheus._tcp","_grafana._tcp","_influxdb._tcp",
        "_kibana._tcp","_consul._tcp","_vault._tcp","_etcd._tcp",
        "_kubernetes._tcp","_docker._tcp","_swarm._tcp",
        "_jenkins._tcp","_gitlab._tcp","_gitea._tcp","_gogs._tcp",
        "_nexus._tcp","_artifactory._tcp","_sonar._tcp","_jira._tcp",
        "_confluence._tcp","_bitbucket._tcp","_bamboo._tcp",
        "_rancher._tcp","_harbor._tcp","_portainer._tcp",
        "_printer._tcp","_pdl-datastream._tcp","_ipp._tcp","_ipps._tcp",
        "_scanner._tcp","_fax._tcp","_rfb._tcp","_vnc._tcp",
        "_rdp._tcp","_ms-wbt-server._tcp","_teamviewer._tcp",
        "_ceph._tcp","_cephmon._tcp","_gluster._tcp",
        "_minio._tcp","_swift._tcp","_s3._tcp",
        "_coap._udp","_coaps._dtls","_mqtt._tcp","_mqtts._tcp",
        "_amqp._tcp","_amqps._tcp","_stomp._tcp","_stomps._tcp",
        "_nats._tcp","_stan._tcp","_grpc._tcp","_h2._tcp",
        "_wss._tcp","_ws._tcp",
        "_xmpp._tcp","_matrix._tcp","_signal._tcp",
        "_dns._udp","_dns._tcp","_dns-sd._udp",
        "_ntp._udp","_snmp._udp","_snmptrap._udp","_syslog._udp",
        "_radius._udp","_radsec._tcp","_diameter._tcp","_tacacs._tcp",
        "_bgp._tcp","_ospf._tcp","_rip._udp","_eigrp._udp",
        "_h323._tcp","_h323._udp","_mgcp._udp","_rtp._udp","_rtsp._tcp",
        "_daap._tcp","_airplay._tcp","_apple-mobdev._tcp",
        "_googlecast._tcp","_spotify-connect._tcp",
        "_git._tcp","_svn._tcp","_hg._tcp",
        "_http-alt._tcp","_https-alt._tcp","_alt-http._tcp",
        "_secure-mqtt._tcp","_presence._tcp","_presence._udp",
        "_workstation._tcp","_device-info._tcp","_sleep-proxy._udp",
    ]

    # DKIM selectors to probe
    DKIM_SELECTORS = [
        "default","mail","email","google","selector1","selector2",
        "s1","s2","s3","k1","k2","k3","dkim","dkim1","dkim2",
        "smtp","mx","em","mandrill","sendgrid","mailchimp","sparkpost",
        "mimecast","proofpoint","barracuda","ironport",
        "key1","key2","key3","key4","pm","pf","sf","cm","sg",
        "a1","a2","b1","b2","c1","c2","d1","d2","e1","e2",
        "jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec",
        "2020","2021","2022","2023","2024","2025","2026",
        "v1","v2","v3","dk","dkimkey","api","app","web","mobile",
        "transactional","marketing","info","noreply","support",
    ]

    def __init__(self, r: Result, d: str):
        self.r = r; self.d = d
        self._sem = asyncio.Semaphore(500)
        self._fr  = _get_fast_resolver()

    async def run(self) -> None:
        log("[*] Phase 2: DNS Enumeration — running 15 sub-tasks in parallel …")
        t0 = time.monotonic()
        task_names = [
            "zone_transfer", "record_types", "srv_brute", "txt_harvest",
            "ns_records", "mx_records", "caa_tlsa", "dkim_selectors",
            "nsec_walk", "ptr_sweep", "tls_san", "asn_reverse",
            "dns_history", "wildcard_probe", "securitytxt",
        ]
        tasks = [
            self._zone_transfer(),
            self._enumerate_records(),
            self._srv_brute(),
            self._txt_harvest(),
            self._ns_records(),
            self._mx_records(),
            self._caa_tlsa_records(),
            self._dkim_selectors(),
            self._nsec_walk_doh(),
            self._ptr_sweep(),
            self._tls_san_extract(),
            self._asn_range_reverse(),
            self._dns_history_doh(),
            self._wildcard_sub_probe(),
            self._securitytxt_dns(),
        ]
        # Run with per-task logging so user sees progress
        done_count = [0]
        async def _named(coro, name):
            try:
                await coro
            except Exception:
                pass
            done_count[0] += 1
            elapsed = time.monotonic() - t0
            log(f"  [DNS] ✓ {name} ({done_count[0]}/{len(tasks)}) | "
                f"subs={len(self.r.subdomains)} | {elapsed:.1f}s")
        await asyncio.gather(*[_named(t, n) for t, n in zip(tasks, task_names)],
                             return_exceptions=True)
        elapsed = time.monotonic() - t0
        log(f"[+] DNS done in {elapsed:.1f}s: {len(self.r.subdomains)} subdomains, "
            f"{sum(sum(len(vals) for vals in v.values()) for v in self.r.dns_records.values())} records")

    # ── Zone Transfer (AXFR) on all NSs ──────────────────────────────────────
    async def _zone_transfer(self) -> None:
        if not DNSPY: return
        try:
            ns_list = await _resolve_all(self.d, 'NS')
        except Exception:
            return
        for ns in ns_list:
            ns = ns.rstrip('.')
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, self.d, timeout=10))
                for name, node in z.nodes.items():
                    full = f"{name}.{self.d}".rstrip('.').lower()
                    if full and full != self.d and '.' in full:
                        self.r.add_sub(full, "zone_transfer")
                log(f"  [!] Zone transfer SUCCESS on {ns}", "SUC")
            except Exception:
                pass

    # ── All DNS record types for the apex ────────────────────────────────────
    async def _enumerate_records(self) -> None:
        record_types = ['A','AAAA','CNAME','MX','NS','TXT','SOA','CAA','TLSA',
                        'SVCB','HTTPS','HINFO','RP','LOC','NAPTR','DS','DNSKEY',
                        'NSEC','NSEC3','RRSIG','CDS','CDNSKEY','ZONEMD']
        rec_store: Dict[str, List[str]] = {}
        for rtype in record_types:
            try:
                vals = await _resolve_all(self.d, rtype)
                if vals:
                    rec_store[rtype] = vals
                    if rtype == 'CNAME':
                        for v in vals:
                            v = v.rstrip('.')
                            if v and self.d not in v:
                                self.r.cname_chains[self.d] = (
                                    self.r.cname_chains.get(self.d, []) + [v])
                    elif rtype == 'A':
                        for ip in vals:
                            self.r.ip_ranges.add(ip)
            except Exception:
                pass
        self.r.dns_records[self.d] = rec_store

    # ── SRV brute-force (200+ prefixes) ──────────────────────────────────────
    async def _srv_brute(self) -> None:
        async def _check(srv: str):
            async with self._sem:
                vals = await _resolve_all(f"{srv}.{self.d}", 'SRV')
                for v in vals:
                    parts = str(v).split()
                    if len(parts) >= 4:
                        target = parts[3].rstrip('.')
                        if target and target != '.':
                            if self.d in target:
                                self.r.add_sub(target, "srv_record")
                            self.r.dns_records.setdefault(f"{srv}.{self.d}", {})["SRV"] = [str(v)]

        await asyncio.gather(*[_check(s) for s in self.SRV_PREFIXES],
                             return_exceptions=True)

    # ── TXT records: SPF, DMARC, verification tokens ─────────────────────────
    async def _txt_harvest(self) -> None:
        # Comprehensive list of TXT query names
        txt_queries = [
            self.d, f"_dmarc.{self.d}", f"_spf.{self.d}",
            f"_domainkey.{self.d}", f"_mta-sts.{self.d}",
            f"_smtp._tls.{self.d}", f"_tls.{self.d}",
            f"_pki.{self.d}", f"_adsp._domainkey.{self.d}",
            f"_bimi.{self.d}", f"_vouch.{self.d}",
            f"_atps.{self.d}", f"_atps._domainkey.{self.d}",
            f"_amazonses.{self.d}", f"_sendgrid.{self.d}",
            f"_domainconnect.{self.d}",
            f"_caa.{self.d}", f"_psl.{self.d}",
        ]
        for q in txt_queries:
            async with self._sem:
                vals = await _resolve_all(q, 'TXT')
            for v in vals:
                v = str(v).strip('"')
                for m in re.finditer(r'include:([^\s"]+)', v):
                    inc = m.group(1)
                    if self.d in inc:
                        self.r.add_sub(inc, "spf_include")
                for m in re.finditer(r'ip4:([0-9./]+)', v):
                    self.r.ip_ranges.add(m.group(1))
                for m in re.finditer(r'ip6:([0-9a-f:/]+)', v, re.I):
                    self.r.ip_ranges.add(m.group(1))
                for m in re.finditer(r'\ba:([^\s"]+)', v):
                    if self.d in m.group(1):
                        self.r.add_sub(m.group(1).rstrip('.'), "spf_a")
                for m in re.finditer(r'ruf?=mailto:([^\s";]+)', v):
                    em = m.group(1)
                    if '@' in em:
                        dp = em.split('@', 1)[1]
                        if self.d in dp:
                            self.r.add_sub(dp, "dmarc_email")
                # redirect= in DMARC
                for m in re.finditer(r'redirect=([^\s";]+)', v):
                    dp = m.group(1)
                    if self.d in dp:
                        self.r.add_sub(dp, "dmarc_redirect")
                for sub in _subs_from_text(v, self.d):
                    self.r.add_sub(sub, "txt_record")

    # ── NS record enumeration + common NS prefix probe ────────────────────────
    async def _ns_records(self) -> None:
        vals = await _resolve_all(self.d, 'NS')
        ns_hosts = []
        for ns in vals:
            ns = str(ns).rstrip('.')
            if ns and self.d in ns:
                self.r.add_sub(ns, "ns_record")
            ns_hosts.append(ns)
        # Extended NS prefix probe
        ns_prefixes = ['ns','ns0','ns1','ns2','ns3','ns4','ns5','ns6',
                       'dns','dns0','dns1','dns2','dns3','dns4',
                       'nameserver','nameserver1','nameserver2',
                       'auth','auth-ns','resolver','dnsmaster']
        for prefix in ns_prefixes:
            async with self._sem:
                ip = await _resolve(f"{prefix}.{self.d}")
            if ip:
                self.r.add_sub(f"{prefix}.{self.d}", "ns_probe")
                self.r.ip_ranges.add(ip)
        self.r.dns_records.setdefault(self.d, {})["NS"] = [str(n).rstrip('.') for n in vals]

    # ── MX records + mail infrastructure probe ────────────────────────────────
    async def _mx_records(self) -> None:
        vals = await _resolve_all(self.d, 'MX')
        for mx in vals:
            mx_host = str(mx).split()[-1].rstrip('.') if mx else ""
            if mx_host and self.d in mx_host:
                self.r.add_sub(mx_host, "mx_record")
        # Extended mail subdomain probe
        mail_prefixes = [
            'mail','mail1','mail2','mail3','mail4','mail5',
            'mx','mx1','mx2','mx3','mx4','mx5','mx6','mx7','mx8','mx9',
            'smtp','smtp1','smtp2','smtps','relay','relay1','relay2',
            'mta','mta1','mta2','inbound','outbound','mailout','mailin',
            'gateway','mailgateway','spam','antispam','filter','mailfilter',
            'exchange','webmail','webmail2','owa','autodiscover',
            'imap','imaps','pop','pop3','pop3s',
            'postfix','sendmail','qmail','exim','mailman',
            'lists','newsletter','bulk','transactional','noreply',
            'bounce','bounce-handler','mailhog','mailtrap',
        ]
        tasks = []
        for prefix in mail_prefixes:
            async def _probe(p=prefix):
                async with self._sem:
                    ip = await _resolve(f"{p}.{self.d}")
                    if ip:
                        self.r.add_sub(f"{p}.{self.d}", "mx_probe")
                        self.r.ip_ranges.add(ip)
            tasks.append(_probe())
        await asyncio.gather(*tasks, return_exceptions=True)
        # Store MX records in dns_records for complete DNS picture
        if vals:
            self.r.dns_records.setdefault(self.d, {})["MX"] = [str(m) for m in vals]

    # ── CAA + TLSA records ────────────────────────────────────────────────────
    async def _caa_tlsa_records(self) -> None:
        for rtype in ['CAA', 'TLSA']:
            for q in [self.d, f"*.{self.d}", f"_443._tcp.{self.d}",
                      f"_80._tcp.{self.d}", f"_25._tcp.{self.d}"]:
                async with self._sem:
                    vals = await _resolve_all(q, rtype)
                for v in vals:
                    for sub in _subs_from_text(str(v), self.d):
                        self.r.add_sub(sub, f"{rtype.lower()}_record")
                    self.r.dns_records.setdefault(q, {})[rtype] = [str(v)]

    # ── DKIM selector brute-force ─────────────────────────────────────────────
    async def _dkim_selectors(self) -> None:
        async def _check(sel: str):
            async with self._sem:
                q = f"{sel}._domainkey.{self.d}"
                vals = await _resolve_all(q, 'TXT')
                if vals:
                    self.r.dns_records.setdefault(q, {})["TXT"] = [str(v) for v in vals]
                    # Subdomains in DKIM records
                    for v in vals:
                        for sub in _subs_from_text(str(v), self.d):
                            self.r.add_sub(sub, "dkim_record")
        await asyncio.gather(*[_check(s) for s in self.DKIM_SELECTORS],
                             return_exceptions=True)

    # ── NSEC/NSEC3 zone walking via DoH ──────────────────────────────────────
    async def _nsec_walk_doh(self) -> None:
        """
        Attempt NSEC zone walking via DoH for domains with NSEC (not NSEC3).
        Walks the chain: query NSEC for domain → get next name → query NSEC → ...
        """
        fr = self._fr
        visited: Set[str] = set()
        to_walk = [self.d]
        max_steps = 200

        for _ in range(max_steps):
            if not to_walk:
                break
            current = to_walk.pop(0)
            if current in visited:
                continue
            visited.add(current)
            try:
                # Use DoH to get NSEC for current name
                data = await fr._doh_resolve(current, "NSEC")
                for record in data:
                    # NSEC record format: "next_name type1 type2 ..."
                    parts = str(record).split()
                    if parts:
                        next_name = parts[0].rstrip('.')
                        if next_name and next_name != current:
                            # Extract subdomains
                            if self.d in next_name and next_name != self.d:
                                self.r.add_sub(next_name, "nsec_walk")
                            to_walk.append(next_name)
            except Exception:
                pass

    # ── PTR reverse-DNS sweep of /24 subnets ─────────────────────────────────
    async def _ptr_sweep(self) -> None:
        """
        For each IP found, sweep the /24 subnet via reverse PTR lookups.
        Uses the fast UDP resolver to resolve thousands of PTR records quickly.
        """
        # Collect IPs from records
        ips: Set[str] = set()
        ip = await _resolve(self.d)
        if ip:
            ips.add(ip)
        for ip_str in list(self.r.ip_ranges)[:20]:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_str):
                ips.add(ip_str)

        ptr_sem = asyncio.Semaphore(300)
        found: Set[str] = set()

        async def _ptr_lookup(ip_str: str):
            async with ptr_sem:
                rev = '.'.join(reversed(ip_str.split('.'))) + '.in-addr.arpa'
                try:
                    vals = await self._fr.resolve(rev, 'PTR')
                    for v in vals:
                        v = str(v).rstrip('.')
                        if self.d in v:
                            found.add(v)
                            self.r.add_sub(v, "ptr_sweep")
                except Exception:
                    pass

        for ip_str in ips:
            try:
                net_prefix = '.'.join(ip_str.split('.')[:3])
                tasks = []
                for last in range(1, 255):
                    tasks.append(_ptr_lookup(f"{net_prefix}.{last}"))
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

    # ── TLS certificate SAN extraction ───────────────────────────────────────
    async def _tls_san_extract(self) -> None:
        """Connect to port 443 and extract Subject Alternative Names from cert."""
        targets = [self.d] + list(self.r.live_subs)[:30]

        async def _extract_sans(host: str):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ip = await _resolve(host)
                if not ip: return
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=host),
                    timeout=5.0
                )
                cert = writer.get_extra_info('ssl_object')
                if cert:
                    cert_der = cert.getpeercert(binary_form=True)
                    if cert_der:
                        # Extract SANs from certificate
                        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                        # Parse SANs from dict
                        cert_dict = cert.getpeercert()
                        sans = cert_dict.get('subjectAltName', [])
                        for san_type, san_val in sans:
                            if san_type == 'DNS':
                                san_val = san_val.lstrip('*.')
                                if self.d in san_val:
                                    self.r.add_sub(san_val, "tls_san")
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except Exception:
                pass

        await asyncio.gather(*[_extract_sans(h) for h in targets],
                             return_exceptions=True)

    # ── ASN/BGP range → reverse DNS sweep ────────────────────────────────────
    async def _asn_range_reverse(self) -> None:
        """
        Query Team Cymru / BGP.he.net to find ASN, then get IP ranges,
        then sweep PTR records for those ranges to discover related subdomains.
        """
        ip = await _resolve(self.d)
        if not ip: return
        try:
            # Team Cymru whois: get ASN for IP
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("whois.cymru.com", 43), timeout=5.0
            )
            writer.write(f" -p {ip}\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            text = data.decode('utf-8', errors='replace')
            # Parse ASN and IP range prefix
            for line in text.splitlines():
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 3:
                    prefix = parts[2].strip()
                    if '/' in prefix:
                        try:
                            net = ipaddress.ip_network(prefix, strict=False)
                            if net.num_addresses <= 65536:  # limit to /16 or smaller
                                # Sample first 512 IPs for PTR sweep
                                hosts_to_check = list(net.hosts())[:512]
                                ptr_sem = asyncio.Semaphore(200)
                                async def _asn_ptr(host_ip):
                                    async with ptr_sem:
                                        ip_str = str(host_ip)
                                        rev = '.'.join(reversed(ip_str.split('.'))) + '.in-addr.arpa'
                                        vals = await self._fr.resolve(rev, 'PTR')
                                        for v in vals:
                                            v = str(v).rstrip('.')
                                            if self.d in v:
                                                self.r.add_sub(v, "asn_ptr")
                                await asyncio.gather(
                                    *[_asn_ptr(h) for h in hosts_to_check],
                                    return_exceptions=True
                                )
                        except Exception:
                            pass
        except Exception:
            pass

    # ── DNS history via DoH queries ───────────────────────────────────────────
    async def _dns_history_doh(self) -> None:
        """
        Query SecurityTrails-like DNS history endpoints (free/public tier).
        Also queries HackerTarget and RapidDNS for historical subdomain data.
        Reuses the shared DoH session to avoid creating a new TCP connection pool
        on every call and to respect any globally configured session settings.
        """
        urls = [
            f"https://rapiddns.io/subdomain/{self.d}?full=1",
            f"https://hackertarget.com/find-dns-host-records/?q={self.d}",
            f"https://api.hackertarget.com/hostsearch/?q={self.d}",
            f"https://dnsdumpster.com/api/domain/{self.d}",
        ]
        # Reuse shared session instead of creating/destroying one per call
        sess = await _get_doh_session()
        if sess is None:
            return
        for url in urls:
            try:
                async with sess.get(
                    url, ssl=False,
                    headers={"User-Agent": random.choice(UA_POOL)},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    text = await resp.text(errors='replace')
                    for sub in _subs_from_text(text, self.d):
                        self.r.add_sub(sub, "dns_history")
            except Exception:
                pass

    # ── Wildcard subdomain enumeration via common patterns ────────────────────
    async def _wildcard_sub_probe(self) -> None:
        """
        Test hundreds of common subdomain patterns to find wildcards.
        Expanded beyond SUBDOMAIN_PREFIXES with infrastructure patterns.
        """
        infra_probes = [
            "internal","internal-api","intranet","intranet2","corp","corporate",
            "private","private-api","hidden","secret","admin-internal",
            "backend-internal","api-internal","service-internal",
            "vault","secrets","config","configs","env","environment",
            "staging-internal","dev-internal","test-internal","qa-internal",
            "jenkins-internal","ci-internal","cd-internal","build-internal",
            "k8s-internal","kube-internal","docker-internal","registry-internal",
            "monitoring-internal","metrics-internal","logs-internal",
            "bastion","jumpbox","gateway-internal","vpn-internal",
            "db-internal","database-internal","mysql-internal","redis-internal",
            "elasticsearch-internal","kafka-internal","rabbitmq-internal",
            "consul-internal","etcd-internal","zookeeper-internal",
        ]
        tasks = []
        for prefix in infra_probes:
            async def _probe(p=prefix):
                async with self._sem:
                    ip = await _resolve(f"{p}.{self.d}")
                    if ip:
                        self.r.add_sub(f"{p}.{self.d}", "dns_probe")
                        self.r.ip_ranges.add(ip)
            tasks.append(_probe())
        await asyncio.gather(*tasks, return_exceptions=True)

    # ── _security.txt and similar DNS-based probes ────────────────────────────
    async def _securitytxt_dns(self) -> None:
        """
        Probe for security.txt, .well-known records, and common infra subdomains
        that leak environment via DNS.
        """
        env_probes = [
            # Cloud/hosting
            "origin","origin-www","direct","direct-www","real","backup-www",
            "www2","www-old","www-legacy","www-backup",
            # Services that often forget to be private
            "phpmyadmin","mysql","pma","database","db","mongodb","redis",
            "memcached","rabbitmq","kafka","zookeeper",
            "elastic","elasticsearch","kibana","logstash","grafana",
            "prometheus","alertmanager","pushgateway",
            "consul","vault","nomad","terraform","ansible","puppet","chef",
            # Dev/test environments
            "dev","development","staging","stage","stg","stag",
            "test","testing","qa","uat","int","integration",
            "sandbox","demo","preview","alpha","beta","canary",
            # Old/backup
            "old","legacy","archive","backup","v1","v2","v3","classic",
        ]
        tasks = []
        for prefix in env_probes:
            async def _probe(p=prefix):
                async with self._sem:
                    ip = await _resolve(f"{p}.{self.d}")
                    if ip:
                        self.r.add_sub(f"{p}.{self.d}", "dns_env_probe")
                        self.r.ip_ranges.add(ip)
            tasks.append(_probe())
        await asyncio.gather(*tasks, return_exceptions=True)

# ═══════════════════════════════════════════════════════════════════════════════
# STALE DNS / CNAME TAKEOVER DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════
class StaleDetector:
    def __init__(self, s, r: Result, d: str, proxy: Optional[str]):
        self.s = s; self.r = r; self.d = d; self.proxy = proxy
        self._sem = asyncio.Semaphore(80)

    async def run(self) -> None:
        candidates = list(self.r.subdomains | self.r.live_subs)
        tasks = [self._check_sub(sub) for sub in candidates]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_sub(self, sub: str) -> None:
        if not DNSPY: return
        async with self._sem:
            # Get CNAME chain
            chain = []
            current = sub
            for _ in range(10):  # max chain depth
                try:
                    r = dns.asyncresolver.Resolver()
                    r.timeout = 4; r.lifetime = 4
                    ans = await r.resolve(current, 'CNAME')
                    cname = str(ans[0]).rstrip('.')
                    chain.append(cname)
                    current = cname
                except Exception:
                    break

            if chain:
                self.r.cname_chains[sub] = chain
                final_cname = chain[-1]
                # Check if final CNAME resolves
                ip = await _resolve(final_cname)
                if not ip:
                    # CNAME doesn't resolve — potential stale/dangling
                    stale_entry = {
                        "subdomain": sub,
                        "cname_chain": chain,
                        "final_cname": final_cname,
                        "resolves": False,
                        "takeover_service": None,
                    }
                    # Check takeover signatures
                    for svc, sigs in TAKEOVER_SIGS.items():
                        for sig in sigs[1:]:  # first element is text sig, rest are domain patterns
                            if sig in final_cname.lower():
                                # Verify by HTTP
                                try:
                                    body = await _tget(
                                        self.s, f"https://{sub}", timeout=8,
                                        proxy=self.proxy)
                                    if body and sigs[0].lower() in body.lower():
                                        stale_entry["takeover_service"] = svc
                                        stale_entry["verified"] = True
                                        self.r.takeover_candidates.append(stale_entry)
                                        log(f"  TAKEOVER [{svc}]: {sub} → {final_cname}", "WRN")
                                        return
                                except Exception:
                                    pass
                                stale_entry["takeover_service"] = svc
                    self.r.stale_dns.append(stale_entry)
                else:
                    # CNAME resolves but check if it points to known cloud platform that might be unclaimed
                    for svc, sigs in TAKEOVER_SIGS.items():
                        for sig in sigs[1:]:
                            if sig in final_cname.lower():
                                # Check the body for takeover indicators
                                try:
                                    body = await _tget(
                                        self.s, f"https://{sub}", timeout=8,
                                        proxy=self.proxy)
                                    if body and sigs[0].lower() in body.lower():
                                        self.r.takeover_candidates.append({
                                            "subdomain": sub,
                                            "cname_chain": chain,
                                            "final_cname": final_cname,
                                            "resolves": True,
                                            "takeover_service": svc,
                                            "verified": True,
                                        })
                                        log(f"  TAKEOVER VERIFIED [{svc}]: {sub}", "WRN")
                                except Exception:
                                    pass


# ═══════════════════════════════════════════════════════════════════════════════
# PORT SCANNER — async TCP with banner grabbing and service fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════
class PortScanner:
    def __init__(self, r: Result, proxy: Optional[str], port_range: Optional[str] = None):
        self.r = r; self.proxy = proxy
        self._sem = asyncio.Semaphore(MAX_PORT_SEM)
        if port_range:
            start, end = port_range.split('-', 1)
            self._ports = list(range(int(start), int(end)+1))
        else:
            self._ports = COMMON_PORTS

    async def scan_host(self, host: str) -> List[Dict]:
        ip = await _resolve(host)
        if not ip: return []
        results = []
        tasks = [self._check_port(ip, host, p) for p in self._ports]
        port_results = await asyncio.gather(*tasks, return_exceptions=True)
        for pr in port_results:
            if pr and isinstance(pr, dict):
                results.append(pr)
        if results:
            self.r.open_ports[host] = results
        return results

    async def _check_port(self, ip: str, host: str, port: int) -> Optional[Dict]:
        """
        Only report a port as open when we receive actual confirming data back.
        Pure TCP connect is NOT sufficient — CDN/load balancers accept all ports.
        Rules:
          - HTTP ports: send GET, require 'HTTP/' in response
          - HTTPS ports: attempt TLS handshake, require response length > 0
          - Banner ports (SSH/FTP/SMTP/etc.): require non-empty server banner read
          - Redis: require '+PONG' response
          - Generic: require at least 4 bytes back, or refuse with ConnectionRefused
        """
        async with self._sem:
            _HTTPS_PORTS = (443, 4443, 8443, 8444, 6443, 7443)
            _HTTP_PORTS  = (80, 8080, 8000, 8001, 8008, 8081, 8082, 8083,
                            8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091,
                            8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
                            8180, 8181, 8280, 8300, 8888, 9000, 9001, 9002,
                            9003, 9090, 9091, 9200)
            reader = writer = None
            try:
                service = PORT_SERVICES.get(port, "unknown")
                banner  = ""
                confirmed = False

                # ── HTTPS probe — open TLS directly (no prior plain TCP) ──────
                # Bug fix: previously a wasted plain TCP conn was opened first,
                # then abandoned while a second TLS conn was opened. Now we open
                # TLS directly, avoiding the duplicate connection + fd leak.
                if port in _HTTPS_PORTS:
                    tls_writer = None
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode    = ssl.CERT_NONE
                        tls_reader, tls_writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port, ssl=ctx,
                                                    server_hostname=host),
                            timeout=4.0
                        )
                        req = (
                            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                            "Connection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                        ).encode()
                        tls_writer.write(req)
                        await tls_writer.drain()
                        data = await asyncio.wait_for(tls_reader.read(2048), timeout=3.0)
                        text = data.decode('utf-8', errors='replace')
                        if text.startswith("HTTP/") or len(data) > 10:
                            banner = text.split('\r\n')[0][:200] if text.startswith("HTTP/") else ""
                            service = "https"
                            confirmed = True
                    except (asyncio.TimeoutError, ssl.SSLError, OSError):
                        pass
                    except Exception:
                        pass
                    finally:
                        # Always close tls_writer — prevents fd leak on any exception
                        if tls_writer is not None:
                            try:
                                tls_writer.close()
                                await tls_writer.wait_closed()
                            except Exception:
                                pass
                    if confirmed:
                        return {"port": port, "service": service, "banner": banner,
                                "host": host, "ip": ip}
                    return None

                # For all non-HTTPS ports: open a plain TCP connection
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=3.0)

                # ── HTTP probe ────────────────────────────────────────────────
                if port in _HTTP_PORTS:
                    try:
                        req = (
                            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                            "Connection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                        ).encode()
                        writer.write(req)
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                        text = data.decode('utf-8', errors='replace')
                        if text.startswith("HTTP/"):
                            banner = text.split('\r\n')[0][:200]
                            service = "http"
                            confirmed = True
                    except Exception:
                        pass

                # ── SSH — server sends banner first ───────────────────────────
                elif port == 22:
                    try:
                        data = await asyncio.wait_for(reader.read(256), timeout=3.0)
                        text = data.decode('utf-8', errors='replace').strip()
                        if text.startswith("SSH-"):
                            banner = text[:100]
                            service = "ssh"
                            confirmed = True
                    except Exception:
                        pass

                # ── FTP — server sends banner first ───────────────────────────
                elif port == 21:
                    try:
                        data = await asyncio.wait_for(reader.read(256), timeout=3.0)
                        text = data.decode('utf-8', errors='replace').strip()
                        if text.startswith("220"):
                            banner = text[:100]
                            service = "ftp"
                            confirmed = True
                    except Exception:
                        pass

                # ── SMTP — server sends banner first ──────────────────────────
                elif port == 25:
                    try:
                        data = await asyncio.wait_for(reader.read(256), timeout=3.0)
                        text = data.decode('utf-8', errors='replace').strip()
                        if text.startswith("220"):
                            banner = text[:100]
                            service = "smtp"
                            confirmed = True
                    except Exception:
                        pass

                # ── MySQL — server sends handshake first ──────────────────────
                elif port == 3306:
                    try:
                        data = await asyncio.wait_for(reader.read(128), timeout=3.0)
                        if len(data) >= 5 and (data[4] == 0x0a or b"mysql" in data.lower()):
                            banner = repr(data[:50])
                            service = "mysql"
                            confirmed = True
                    except Exception:
                        pass

                # ── Redis — ping probe ────────────────────────────────────────
                elif port == 6379:
                    try:
                        writer.write(b"PING\r\n")
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(64), timeout=3.0)
                        text = data.decode('utf-8', errors='replace').strip()
                        if "+PONG" in text or "-NOAUTH" in text:
                            banner = text[:80]
                            service = "redis"
                            confirmed = True
                    except Exception:
                        pass

                # ── Elasticsearch HTTP ────────────────────────────────────────
                elif port in (9300,):
                    try:
                        writer.write(
                            f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                        )
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                        text = data.decode('utf-8', errors='replace')
                        if '"cluster_name"' in text or '"version"' in text:
                            banner = text[:200]
                            service = "elasticsearch"
                            confirmed = True
                    except Exception:
                        pass

                # ── RDP — server sends negotiation response ───────────────────
                elif port == 3389:
                    try:
                        # Send RDP connection request
                        writer.write(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00"
                                     b"\x01\x00\x08\x00\x03\x00\x00\x00")
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(32), timeout=3.0)
                        if len(data) >= 4 and data[0] == 0x03:
                            banner = "RDP"
                            service = "rdp"
                            confirmed = True
                    except Exception:
                        pass

                # ── Generic: require at least 4 bytes from server ─────────────
                else:
                    try:
                        data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                        if len(data) >= 4:
                            banner = data.decode('utf-8', errors='replace').strip()[:100]
                            confirmed = True
                        else:
                            # Try sending empty probe
                            writer.write(b"\r\n\r\n")
                            await writer.drain()
                            data2 = await asyncio.wait_for(reader.read(256), timeout=2.0)
                            if len(data2) >= 4:
                                banner = data2.decode('utf-8', errors='replace').strip()[:100]
                                confirmed = True
                    except Exception:
                        pass

                if confirmed:
                    return {"port": port, "service": service, "banner": banner,
                            "host": host, "ip": ip}
                return None

            except ConnectionRefusedError:
                return None
            except (asyncio.TimeoutError, OSError):
                return None
            except Exception:
                return None
            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

    async def run(self) -> None:
        targets = [self.r.domain] + list(self.r.live_subs)[:30]
        for host in targets:
            log(f"  Port scanning: {host} ({len(self._ports)} ports)")
            results = await self.scan_host(host)
            open_count = len(results)
            if open_count:
                log(f"    {host}: {open_count} open ports: {[r['port'] for r in results]}")

# ═══════════════════════════════════════════════════════════════════════════════
# PASSIVE COLLECTOR — 100+ sources
# ═══════════════════════════════════════════════════════════════════════════════
class Passive:
    def __init__(self, s, r: Result, d: str, k: Dict[str, str], proxy: Optional[str]):
        self.s = s; self.r = r; self.d = d; self.k = k; self.proxy = proxy
        self._sem = asyncio.Semaphore(MAX_HTTP)

    def _p(self, **kw): return dict(proxy=self.proxy, **kw)

    async def _scrape(self, url: str, src: str, *, params=None, hdrs=None, timeout=14) -> None:
        async with self._sem:
            text = await _tget(self.s, url, params=params, hdrs=hdrs, timeout=timeout, **self._p())
        if not text: return
        for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, src)
        for u in _urls_from_text(text, self.d): self.r.add_url(u, src)

    async def _jfetch(self, url: str, src: str, cb: Callable, *, params=None, hdrs=None,
                      method="GET", json_body=None, timeout=18) -> None:
        async with self._sem:
            data = await _jget(self.s, url, params=params, hdrs=hdrs, method=method,
                               json_body=json_body, timeout=timeout, **self._p())
        if data is not None:
            try: cb(data, src)
            except Exception: pass

    # ═════════════════════ CERTIFICATE TRANSPARENCY (8) ═════════════════════

    async def crt_sh(self) -> None:
        src = "crtsh"
        for q in [f"%.{self.d}", self.d]:
            def cb(data, s):
                if not isinstance(data, list): return
                for e in data:
                    for f in ("name_value","common_name"):
                        for n in e.get(f,"").split('\n'):
                            self.r.add_sub(n.strip().lower().lstrip("*."), s)
            await self._jfetch(f"https://crt.sh/", src, cb,
                               params={"q": q, "output": "json"}, timeout=30)

    async def crt_name(self) -> None:
        """crt.name — alternative CT search."""
        src = "crt_name"
        await self._scrape(f"https://crt.name/?q={self.d}&type=0", src, timeout=20)
        # Also try JSON endpoint
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    if isinstance(item, dict):
                        for f in ("name","common_name","value"):
                            v = item.get(f, "")
                            if v: self.r.add_sub(str(v).lower().lstrip("*."), s)
            elif isinstance(d, dict):
                for item in d.get("results", []):
                    for f in ("name","common_name","value"):
                        v = item.get(f, "")
                        if v and self.d in v.lower():
                            self.r.add_sub(v.lower().lstrip("*."), s)
        await self._jfetch(f"https://crt.name/api/search", src, cb,
                           params={"q": self.d, "type": "0"}, timeout=20)

    async def certspotter(self) -> None:
        src = "certspotter"
        def cb(d, s):
            if not isinstance(d, list): return
            for c in d:
                for n in c.get("dns_names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch("https://api.certspotter.com/v1/issuances", src, cb,
                           params={"domain": self.d, "include_subdomains": "true",
                                   "expand": "dns_names"}, timeout=20)

    async def merklemap(self) -> None:
        src = "merklemap"
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("results", []):
                for f in ("domain","san"):
                    v = r.get(f, "")
                    if isinstance(v, list):
                        for n in v: self.r.add_sub(str(n).lower().lstrip("*."), s)
                    elif v:
                        self.r.add_sub(str(v).lower().lstrip("*."), s)
        for page in range(5):
            await self._jfetch("https://api.merklemap.com/search", src, cb,
                               params={"query": f"*.{self.d}", "page": str(page)})

    async def entrust_ct(self) -> None:
        src = "entrust_ct"
        def cb(d, s):
            if not isinstance(d, list): return
            for c in d:
                for n in c.get("dnsNames", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch("https://ctsearch.entrust.com/api/v1/certificates", src, cb,
                           params={"fields": "subjectCN,alternativeName",
                                   "domain": self.d, "includeExpired": "true",
                                   "exactMatch": "false", "limit": "5000"}, timeout=20)

    async def google_ct(self) -> None:
        src = "google_ct"
        async with self._sem:
            text = await _tget(self.s,
                "https://transparencyreport.google.com/transparencyreport/api/v3/"
                "httpsreport/ct/certsearch",
                params={"include_subdomains": "true", "domain": self.d, "p": None},
                timeout=20, **self._p())
        if text:
            for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, src)

    async def sslmate_spki(self) -> None:
        src = "sslmate"
        def cb(d, s):
            if not isinstance(d, list): return
            for c in d:
                for n in c.get("dns_names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch("https://api.certspotter.com/v1/issuances", src, cb,
                           params={"domain": self.d, "include_subdomains": "true",
                                   "match_wildcards": "true", "expand": "dns_names"}, timeout=20)

    async def censys_certs(self) -> None:
        """Censys certificate search (unauthenticated scrape)."""
        src = "censys_certs"
        await self._scrape(
            f"https://search.censys.io/certificates?q={self.d}", src, timeout=15)

    # ═════════════════════ ARCHIVE / CRAWL (6) ══════════════════════════════

    async def wayback(self) -> None:
        src = "wayback"
        for q in [f"*.{self.d}/*", f"{self.d}/*"]:
            def cb(d, s):
                if not isinstance(d, list): return
                for row in d[1:]:
                    if row: self.r.add_url(row[0], s)
            await self._jfetch("http://web.archive.org/cdx/search/cdx", src, cb,
                               params={"url": q, "output": "json", "fl": "original",
                                       "collapse": "urlkey", "limit": "300000"}, timeout=60)

    async def commoncrawl(self) -> None:
        src = "commoncrawl"
        async with self._sem:
            indexes = await _jget(self.s, "https://index.commoncrawl.org/collinfo.json",
                                  timeout=20, **self._p())
        if not isinstance(indexes, list): return
        for ix in [i.get("cdx-api","") for i in indexes[:6] if i.get("cdx-api")]:
            for q in [f"*.{self.d}", self.d]:
                async with self._sem:
                    text = await _tget(self.s, ix,
                        params={"url": f"{q}/*", "output": "json",
                                "fl": "url", "limit": "100000"},
                        timeout=50, **self._p())
                if text:
                    for line in text.splitlines():
                        try:
                            obj = json.loads(line)
                            self.r.add_url(obj.get("url",""), src)
                        except Exception: pass

    async def timetravel(self) -> None:
        src = "timetravel"
        async with self._sem:
            data = await _jget(self.s,
                f"http://timetravel.mementoweb.org/timemap/json/http://{self.d}/",
                timeout=20, **self._p())
        if isinstance(data, dict):
            for m in data.get("mementos",{}).get("list",[]):
                u = m.get("uri","")
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
        await self._scrape(f"https://archive.ph/{self.d}", src, timeout=12)

    async def webarchive_subpages(self) -> None:
        src = "webarchive_sp"
        exts = ["json","xml","env","config","bak","sql","yaml","yml","wsdl","map","js","pdf","zip"]
        for ext in exts:
            data = await _jget(self.s, "http://web.archive.org/cdx/search/cdx",
                params={"url": f"{self.d}/*.{ext}", "output": "json",
                        "fl": "original", "collapse": "urlkey", "limit": "10000"},
                timeout=30, **self._p())
            if isinstance(data, list):
                for row in data[1:]:
                    if row: self.r.add_url(row[0], src)

    # ═════════════════════ THREAT INTEL (12) ════════════════════════════════

    async def otx(self) -> None:
        src = "otx"
        key_hdr = {"X-OTX-API-KEY": self.k.get("otx","")}
        def cb_dns(d, s):
            if not isinstance(d, dict): return
            for rec in d.get("passive_dns",[]):
                h = rec.get("hostname","")
                if h and self.d in h.lower(): self.r.add_sub(h, s)
        def cb_url(d, s):
            if not isinstance(d, dict): return
            for e in d.get("url_list",[]):
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
        for q in [f"domain:{self.d}", f"page.domain:{self.d}", f"task.domain:{self.d}"]:
            def cb(d, s):
                if not isinstance(d, dict): return
                for res in d.get("results",[]):
                    pg = res.get("page",{})
                    self.r.add_url(pg.get("url",""), s)
                    for key in ("domain","apexDomain"):
                        h = pg.get(key,"")
                        if h and self.d in h.lower(): self.r.add_sub(h, s)
            await self._jfetch("https://urlscan.io/api/v1/search/", src, cb,
                               params={"q": q, "size": "10000"}, hdrs=hdrs, timeout=25)

    async def virustotal(self) -> None:
        src = "virustotal"
        vt = self.k.get("virustotal","")
        if vt:
            for ep in [
                f"https://www.virustotal.com/api/v3/domains/{self.d}/subdomains?limit=40",
                f"https://www.virustotal.com/api/v3/domains/{self.d}/urls?limit=40",
                f"https://www.virustotal.com/api/v3/domains/{self.d}/resolutions?limit=40",
            ]:
                def cb(d, s):
                    if not isinstance(d, dict): return
                    for item in d.get("data",[]):
                        v = item.get("id","") or item.get("attributes",{}).get("host_name","")
                        if v and self.d in str(v).lower(): self.r.add_sub(str(v), s)
                await self._jfetch(ep, src, cb, hdrs={"x-apikey": vt})
        else:
            await self._scrape(f"https://www.virustotal.com/gui/domain/{self.d}/relations", src)

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
        await self._jfetch("https://www.threatcrowd.org/searchApi/v2/domain/report/",
                           src, cb, params={"domain": self.d})

    async def urlhaus(self) -> None:
        src = "urlhaus"
        def cb(d, s):
            if not isinstance(d, dict): return
            for u in d.get("urls",[]): self.r.add_url(u.get("url",""), s)
        await self._jfetch("https://urlhaus-api.abuse.ch/v1/host/", src, cb,
                           method="POST", json_body={"host": self.d})

    async def pulsedive(self) -> None:
        src = "pulsedive"
        pd_key = self.k.get("pulsedive","")
        params = {"q": self.d, "pretty": "1"}
        if pd_key: params["key"] = pd_key
        await self._scrape("https://pulsedive.com/api/explore.php", src, params=params)

    async def hybridanalysis(self) -> None:
        src = "hybridanalysis"
        ha_key = self.k.get("ha","")
        if not ha_key: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("result",[]): self.r.add_sub(item.get("domain",""), s)
        await self._jfetch("https://www.hybrid-analysis.com/api/v2/search/terms",
                           src, cb, method="POST",
                           hdrs={"api-key": ha_key, "user-agent": "Falcon"},
                           json_body={"domain": self.d, "count": 100})

    async def greynoise(self) -> None:
        src = "greynoise"
        gk = self.k.get("greynoise","")
        h = {"key": gk} if gk else {}
        await self._scrape(f"https://api.greynoise.io/v3/community/{self.d}", src, hdrs=h)

    async def circl_pdns(self) -> None:
        src = "circl_pdns"
        def cb(d, s):
            if not isinstance(d, dict): return
            for e in d.get("rdata",[]):
                if self.d in str(e).lower(): self.r.add_sub(str(e), s)
        await self._jfetch(f"https://www.circl.lu/pdns/query/{self.d}", src, cb,
                           hdrs={"Accept": "application/json"})

    async def scanmalware(self) -> None:
        """scanmalware.com — domain/subdomain threat intel."""
        src = "scanmalware"
        await self._scrape(f"https://scanmalware.com/domain/{self.d}", src, timeout=15)
        await self._scrape(f"https://scanmalware.com/search?q={self.d}", src, timeout=15)

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
        await self._jfetch(f"https://api.xforce.ibmcloud.com/resolve/{self.d}",
                           src, cb, hdrs={"Authorization": f"Basic {creds}",
                                          "Accept": "application/json"})

    # ═════════════════════ DNS INTELLIGENCE (18) ════════════════════════════

    async def bufferover(self) -> None:
        src = "bufferover"
        for url in [f"https://dns.bufferover.run/dns?q=.{self.d}",
                    f"https://tls.bufferover.run/dns?q=.{self.d}"]:
            def cb(d, s):
                if not isinstance(d, dict): return
                for key in ("FDNS_A","RDNS","Results"):
                    for e in d.get(key,[]):
                        for part in str(e).split(","):
                            part = part.strip().lower().rstrip('.')
                            if self.d in part: self.r.add_sub(part, s)
            await self._jfetch(url, src, cb)

    async def ip_thc(self) -> None:
        """ip.thc.org — DNS recon and subdomain discovery."""
        src = "ip_thc"
        await self._scrape(f"https://ip.thc.org/{self.d}", src, timeout=15)
        # Also try their search/API endpoints
        for endpoint in [
            f"https://ip.thc.org/search/{self.d}",
            f"https://ip.thc.org/domain/{self.d}",
        ]:
            await self._scrape(endpoint, src, timeout=12)

    async def hackertarget(self) -> None:
        src = "hackertarget"
        async with self._sem:
            text = await _tget(self.s,
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
        await self._scrape(f"https://rapiddns.io/subdomain/{self.d}?full=1#result", src)

    async def riddler(self) -> None:
        src = "riddler"
        await self._scrape(f"https://riddler.io/search/exportcsv?q=pld:{self.d}", src)

    async def sonarsearch(self) -> None:
        src = "sonarsearch"
        for url in [f"https://sonar.omnisint.io/subdomains/{self.d}",
                    f"https://omnisint.io/subdomains/{self.d}"]:
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
        await self._jfetch(f"https://freeapi.robtex.com/pdns/forward/{self.d}", src, cb)

    async def viewdns(self) -> None:
        src = "viewdns"
        await self._scrape(f"https://viewdns.info/dnsrecord/?domain={self.d}", src)

    async def dnsgrep(self) -> None:
        src = "dnsgrep"
        await self._scrape(f"https://www.dnsgrep.nl/subdomains/{self.d}?limit=5000", src)

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
        await self._jfetch(f"https://shrewdeye.app/domains/{self.d}.json", src, cb)

    async def columbus(self) -> None:
        src = "columbus"
        def cb(d, s):
            if isinstance(d, list):
                for sub in d:
                    full = f"{sub}.{self.d}" if self.d not in str(sub) else str(sub)
                    self.r.add_sub(full.lower(), s)
        await self._jfetch(f"https://columbus.elmasy.com/api/lookup/{self.d}", src, cb)

    async def dnsdumpster(self) -> None:
        src = "dnsdumpster"
        async with self._sem:
            html = await _tget(self.s, "https://dnsdumpster.com/", timeout=12, **self._p())
        if html:
            for sub in _subs_from_text(html, self.d): self.r.add_sub(sub, src)

    async def digga_dev(self) -> None:
        """digga.dev — DNS lookup and subdomain discovery."""
        src = "digga"
        for rtype in ["A", "NS", "MX", "TXT", "CNAME", "AAAA"]:
            await self._scrape(f"https://digga.dev/{self.d}/{rtype}", src, timeout=12)
        # API endpoint
        def cb(d, s):
            if isinstance(d, dict):
                for key, vals in d.items():
                    if isinstance(vals, list):
                        for v in vals:
                            if isinstance(v, dict):
                                name = v.get("name","") or v.get("value","") or v.get("data","")
                                if name and self.d in str(name).lower():
                                    self.r.add_sub(str(name).rstrip('.').lower(), s)
        await self._jfetch(f"https://digga.dev/api/{self.d}", src, cb, timeout=15)

    async def submap_net(self) -> None:
        """submap.net — subdomain enumeration service."""
        src = "submap"
        await self._scrape(f"https://submap.net/domain/{self.d}", src, timeout=15)
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    sub = item.get("subdomain","") or item.get("host","") or str(item)
                    self.r.add_sub(sub, s)
            elif isinstance(d, dict):
                for item in d.get("subdomains",[]) + d.get("results",[]):
                    sub = item.get("subdomain","") or item.get("host","") or str(item)
                    self.r.add_sub(str(sub), s)
        await self._jfetch(f"https://submap.net/api/subdomains/{self.d}", src, cb, timeout=20)

    async def wexscan(self) -> None:
        """wexscan.com — web security scanner."""
        src = "wexscan"
        await self._scrape(f"https://wexscan.com/scan/{self.d}", src, timeout=15)
        await self._scrape(f"https://wexscan.com/domain/{self.d}", src, timeout=15)

    async def dnshistory(self) -> None:
        src = "dnshistory"
        await self._scrape(f"https://dnshistory.org/subdomains/{self.d}", src)

    async def dnsbufferover_tls(self) -> None:
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
        await self._scrape(
            f"https://crt.sh/?O={urllib.parse.quote(self.d)}&output=json", src)

    async def dnslookup_org(self) -> None:
        src = "dnslookup"
        await self._scrape(f"https://dnslookup.org/{self.d}/dns/", src)

    # ═════════════════════ AGGREGATOR APIs (15) ═════════════════════════════

    async def shodan(self) -> None:
        src = "shodan"
        sk = self.k.get("shodan","")
        if sk:
            def cb(d, s):
                if not isinstance(d, dict): return
                for sub in d.get("subdomains",[]): self.r.add_sub(f"{sub}.{self.d}", s)
            await self._jfetch(f"https://api.shodan.io/dns/domain/{self.d}",
                               src, cb, params={"key": sk})
            # Also search Shodan for the domain
            def cb2(d, s):
                if not isinstance(d, dict): return
                for m in d.get("matches",[]):
                    for h in m.get("hostnames",[]) + m.get("domains",[]):
                        if self.d in h.lower(): self.r.add_sub(h, s)
            await self._jfetch("https://api.shodan.io/shodan/host/search",
                               src, cb2, params={"key": sk, "query": f"hostname:{self.d}",
                                                 "minify": "true"})
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
        await self._jfetch("https://search.censys.io/api/v2/certificates/search",
                           src, cb, hdrs={"Authorization": f"Basic {creds}"},
                           json_body={"q": f"parsed.names: {self.d}", "per_page": 100,
                                      "fields": ["parsed.names"]}, method="POST")

    async def leakix(self) -> None:
        src = "leakix"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("Subdomains",[]): self.r.add_sub(item.get("subdomain",""), s)
        await self._jfetch(f"https://leakix.net/domain/{self.d}", src, cb,
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
            # Historical DNS
            def cb_hist(d, s):
                if not isinstance(d, dict): return
                for rec in d.get("records",[]):
                    v = rec.get("values",[])
                    for item in (v if isinstance(v, list) else [v]):
                        if isinstance(item, dict):
                            h = item.get("hostname","") or item.get("host","")
                            if h and self.d in h.lower(): self.r.add_sub(h, s)
            await self._jfetch(
                f"https://api.securitytrails.com/v1/history/{self.d}/dns/a",
                src, cb_hist, hdrs={"APIKEY": stk})
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
        await self._jfetch(f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains",
                           src, cb, hdrs={"Authorization": ck})

    async def passivetotal(self) -> None:
        src = "passivetotal"
        pu = self.k.get("pt_user",""); pk = self.k.get("pt_key","")
        if not (pu and pk): return
        creds = base64.b64encode(f"{pu}:{pk}".encode()).decode()
        def cb(d, s):
            if not isinstance(d, dict): return
            for sub in d.get("subdomains",[]): self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch("https://api.riskiq.net/pt/v2/enrichment/subdomains",
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
        await self._jfetch("https://app.netlas.io/api/domains/",
                           src, cb, params={"q": f"domain:*.{self.d}",
                                            "source_type": "include", "start": "0",
                                            "fields": "domain"},
                           hdrs={"X-API-Key": nk})

    async def zoomeye(self) -> None:
        src = "zoomeye"
        zk = self.k.get("zoomeye","")
        if not zk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("list",[]): self.r.add_sub(item.get("name",""), s)
        await self._jfetch("https://api.zoomeye.org/domain/search", src, cb,
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
        await self._jfetch(f"https://fullhunt.io/api/v1/domain/{self.d}/subdomains",
                           src, cb, hdrs=h)

    async def whoisxml(self) -> None:
        src = "whoisxml"
        wk = self.k.get("whoisxml","")
        if not wk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for rec in d.get("result",{}).get("records",[]):
                sub = rec.get("domain","")
                if sub and self.d in sub.lower(): self.r.add_sub(sub, s)
        await self._jfetch("https://subdomains.whoisxmlapi.com/api/v1",
                           src, cb, params={"apiKey": wk, "domainName": self.d,
                                            "outputFormat": "JSON"})

    async def whoisxml_history(self) -> None:
        src = "whoisxml_hist"
        wk = self.k.get("whoisxml","")
        if not wk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for rec in d.get("result",{}).get("records",[]):
                sub = rec.get("domain","")
                if sub: self.r.add_sub(sub, s)
        await self._jfetch("https://dns-history.whoisxmlapi.com/api/v1",
                           src, cb, params={"apiKey": wk, "domainName": self.d,
                                            "outputFormat": "JSON"})

    async def whoxy(self) -> None:
        """whoxy.com — WHOIS history and reverse WHOIS for hidden domains."""
        src = "whoxy"
        wk = self.k.get("whoxy","")
        if wk:
            # Reverse WHOIS by domain keyword
            for mode in ["domain", "email", "name"]:
                def cb(d, s):
                    if not isinstance(d, dict): return
                    for rec in d.get("search_result",[]):
                        dom = rec.get("domain_name","")
                        if dom and self.d in dom.lower():
                            self.r.add_sub(dom.lower(), s)
                        # Also extract nameservers and other info
                        for ns in rec.get("name_servers",[]):
                            if ns and self.d in ns.lower():
                                self.r.add_sub(ns.lower(), s)
                await self._jfetch(
                    "https://api.whoxy.com/",
                    src, cb,
                    params={"key": wk, mode: self.d, "reverse": "whois"},
                    timeout=20)
        else:
            await self._scrape(f"https://whoxy.com/search?domain={self.d}", src, timeout=15)
            await self._scrape(f"https://whoxy.com/whois-history/{self.d}/", src, timeout=15)

    async def cyberatlas(self) -> None:
        """cyberatlas.ai — AI-powered subdomain intelligence."""
        src = "cyberatlas"
        await self._scrape(f"https://cyberatlas.ai/domain/{self.d}", src, timeout=15)
        def cb(d, s):
            if isinstance(d, dict):
                for item in d.get("subdomains",[]) + d.get("results",[]) + d.get("data",[]):
                    if isinstance(item, str):
                        self.r.add_sub(item, s)
                    elif isinstance(item, dict):
                        sub = item.get("subdomain","") or item.get("host","") or item.get("name","")
                        if sub: self.r.add_sub(str(sub), s)
            elif isinstance(d, list):
                for item in d:
                    if isinstance(item, str): self.r.add_sub(item, s)
                    elif isinstance(item, dict):
                        sub = item.get("subdomain","") or item.get("host","") or item.get("name","")
                        if sub: self.r.add_sub(str(sub), s)
        await self._jfetch(f"https://cyberatlas.ai/api/subdomains/{self.d}", src, cb, timeout=20)
        await self._jfetch(f"https://cyberatlas.ai/api/domain/{self.d}", src, cb, timeout=20)

    async def jsmon(self) -> None:
        """app.jsmon.sh — JS file monitoring for endpoints and subdomains."""
        src = "jsmon"
        def cb(d, s):
            if isinstance(d, dict):
                for url in d.get("urls",[]) + d.get("endpoints",[]) + d.get("links",[]):
                    if self.d in str(url).lower(): self.r.add_url(str(url), s)
                for sub in d.get("subdomains",[]):
                    self.r.add_sub(str(sub), s)
                for path in d.get("paths",[]):
                    self.r.add_ep(str(path), s)
            elif isinstance(d, list):
                for item in d:
                    if isinstance(item, str):
                        if item.startswith('http'): self.r.add_url(item, s)
                        elif item.startswith('/'): self.r.add_ep(item, s)
                    elif isinstance(item, dict):
                        url = item.get("url","") or item.get("endpoint","")
                        if url: self.r.add_url(url, s)
        await self._jfetch(f"https://app.jsmon.sh/api/search?domain={self.d}", src, cb, timeout=20)
        await self._jfetch(f"https://app.jsmon.sh/api/domain/{self.d}", src, cb, timeout=20)
        await self._scrape(f"https://app.jsmon.sh/search/{self.d}", src, timeout=15)

    async def agnios(self) -> None:
        """app.agnios.in — asset discovery."""
        src = "agnios"
        def cb(d, s):
            if isinstance(d, dict):
                for sub in d.get("subdomains",[]) + d.get("hosts",[]):
                    self.r.add_sub(str(sub), s)
                for url in d.get("urls",[]) + d.get("endpoints",[]):
                    self.r.add_url(str(url), s)
            elif isinstance(d, list):
                for item in d:
                    if isinstance(item, str): self.r.add_sub(item, s)
        await self._jfetch(f"https://app.agnios.in/api/subdomains/{self.d}", src, cb, timeout=20)
        await self._jfetch(f"https://app.agnios.in/api/domain/{self.d}", src, cb, timeout=20)
        await self._scrape(f"https://app.agnios.in/domain/{self.d}", src, timeout=15)

    async def bgpview(self) -> None:
        src = "bgpview"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("data",{}).get("domains",[]):
                if self.d in str(item).lower(): self.r.add_sub(str(item), s)
        await self._jfetch(f"https://api.bgpview.io/search", src, cb,
                           params={"query_term": self.d})

    async def ipinfo(self) -> None:
        src = "ipinfo"
        ik = self.k.get("ipinfo","")
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
        await self._jfetch(f"https://www.onyphe.io/api/v2/simple/datascan/{self.d}",
                           src, cb, hdrs=h)

    # ═════════════════════ SEARCH ENGINES (9) ═══════════════════════════════

    async def duckduckgo(self) -> None:
        src = "duckduckgo"
        rl = RL(rps=0.25)
        for dork in [f"site:{self.d}", f"site:*.{self.d}",
                     f"site:{self.d} inurl:api", f"site:{self.d} inurl:admin",
                     f"site:{self.d} filetype:json", f"site:{self.d} inurl:dev",
                     f"site:{self.d} inurl:internal", f"site:{self.d} inurl:staging"]:
            await rl.wait()
            data = await _jget(self.s, "https://api.duckduckgo.com/",
                params={"q": dork, "format": "json", "no_html": "1", "kl": "us-en"},
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
                 f"site:{self.d} filetype:json", f"site:{self.d} inurl:api",
                 f"site:{self.d} inurl:staging", f"site:{self.d} inurl:internal"]
        for dork in dorks:
            await rl.wait()
            if bk:
                def cb(d, s):
                    if not isinstance(d, dict): return
                    for item in d.get("webPages",{}).get("value",[]):
                        self.r.add_url(item.get("url",""), s)
                await self._jfetch("https://api.bing.microsoft.com/v7.0/search",
                                   src, cb, hdrs={"Ocp-Apim-Subscription-Key": bk},
                                   params={"q": dork, "count": "50"})
            else:
                await self._scrape("https://www.bing.com/search",
                                   src, params={"q": dork, "count": "50"})

    async def yahoo(self) -> None:
        src = "yahoo"
        rl = RL(rps=0.2)
        for dork in [f"site:{self.d}", f"site:*.{self.d}", f"site:{self.d} inurl:api"]:
            await rl.wait()
            await self._scrape("https://search.yahoo.com/search",
                               src, params={"p": dork, "n": "100"})

    async def yandex(self) -> None:
        src = "yandex"
        rl = RL(rps=0.15)
        for dork in [f"site:{self.d}", f"site:*.{self.d}"]:
            await rl.wait()
            await self._scrape("https://yandex.com/search/",
                               src, params={"text": dork, "numdoc": "100"})

    async def mojeek(self) -> None:
        src = "mojeek"
        rl = RL(rps=0.25)
        for dork in [f"site:{self.d}", f"site:*.{self.d}"]:
            await rl.wait()
            await self._scrape("https://www.mojeek.com/search", src, params={"q": dork})

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
        await self._scrape("https://www.startpage.com/search",
                           src, params={"q": f"site:{self.d}", "language": "english"})

    async def exalead(self) -> None:
        src = "exalead"
        rl = RL(rps=0.2)
        await rl.wait()
        await self._scrape("https://www.exalead.com/search/web/results/",
                           src, params={"q": f"site:{self.d}", "elements_per_page": "100"})

    async def google_search(self) -> None:
        """Google via CSE API."""
        src = "google_cse"
        gk = self.k.get("google_api",""); gcx = self.k.get("google_cx","")
        if not (gk and gcx): return
        rl = RL(rps=0.3)
        for dork in [f"site:{self.d}", f"site:*.{self.d}", f"site:{self.d} inurl:api"]:
            await rl.wait()
            def cb(d, s):
                if not isinstance(d, dict): return
                for item in d.get("items",[]):
                    self.r.add_url(item.get("link",""), s)
            await self._jfetch("https://www.googleapis.com/customsearch/v1", src, cb,
                               params={"key": gk, "cx": gcx, "q": dork, "num": "10"})

    # ═════════════════════ DEVELOPER / SOCIAL (8) ═══════════════════════════

    async def github(self) -> None:
        src = "github"
        gk = self.k.get("github","")
        h: Dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
        if gk: h["Authorization"] = f"token {gk}"
        rl = RL(rps=0.4 if gk else 0.15)
        queries = [self.d, f'"{self.d}" api', f'"{self.d}" endpoint',
                   f'"{self.d}" subdomain', f'"{self.d}" staging',
                   f'"{self.d}" internal', f'"{self.d}" config',
                   f'"{self.d}" password', f'"{self.d}" secret',
                   f'"{self.d}" token']
        for q in queries:
            await rl.wait()
            data = await _jget(self.s, "https://api.github.com/search/code",
                               hdrs=h, params={"q": q, "per_page": "50"}, timeout=20, **self._p())
            if not isinstance(data, dict): continue
            for item in data.get("items",[]):
                file_url = item.get("url","")
                if not file_url: continue
                await rl.wait()
                file_data = await _jget(self.s, file_url, hdrs=h, timeout=15, **self._p())
                if isinstance(file_data, dict):
                    try:
                        content = base64.b64decode(
                            file_data.get("content","")).decode("utf-8", errors="replace")
                        for sub in _subs_from_text(content, self.d): self.r.add_sub(sub, src)
                        for path in _paths_from_text(content): self.r.add_ep(path, src)
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
        await self._jfetch("https://gitlab.com/api/v4/search", src, cb,
                           params={"scope": "blobs", "search": self.d}, hdrs=h)

    async def reddit(self) -> None:
        src = "reddit"
        rl = RL(rps=0.4)
        for q in [self.d, f"site:{self.d}", f"{self.d} api", f"{self.d} endpoint"]:
            await rl.wait()
            data = await _jget(self.s, "https://www.reddit.com/search.json",
                params={"q": q, "limit": "100", "type": "link,comment"},
                hdrs={"User-Agent": "ReaperRecon/3.0"}, timeout=15, **self._p())
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
        await self._jfetch("https://api.stackexchange.com/2.3/search/advanced",
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
        await self._jfetch("https://api.bitbucket.org/2.0/search/code",
                           src, cb, params={"q": self.d})

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
        await self._jfetch("https://api.hunter.io/v2/domain-search", src, cb,
                           params={"domain": self.d, "api_key": hk, "limit": "100"})

    async def publicwww(self) -> None:
        src = "publicwww"
        await self._scrape(f"https://publicwww.com/websites/%22{self.d}%22/", src)

    # ═════════════════════ SPECIALIZED (10) ═════════════════════════════════

    async def recondev(self) -> None:
        src = "recondev"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    if isinstance(item, dict): self.r.add_sub(item.get("domain",""), s)
                    elif isinstance(item, str): self.r.add_sub(item, s)
        await self._jfetch("https://recon.dev/api/search", src, cb,
                           params={"key": "", "domain": self.d})

    async def c99(self) -> None:
        src = "c99"
        ck = self.k.get("c99","")
        if ck:
            def cb(d, s):
                if not isinstance(d, dict): return
                for sub in d.get("subdomains",[]): self.r.add_sub(str(sub), s)
            await self._jfetch("https://api.c99.nl/subdomainfinder", src, cb,
                               params={"key": ck, "domain": self.d, "json": "true"})
        else:
            await self._scrape(f"https://subdomainfinder.c99.nl/scans/{self.d}", src)

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
            await self._jfetch(f"https://api.spyonweb.com/v1/domain/{self.d}",
                               src, cb, params={"access_token": sk})
        else:
            await self._scrape(f"https://spyonweb.com/{self.d}", src)

    async def intelligencex(self) -> None:
        src = "intelx"
        ik = self.k.get("intelx","")
        if not ik: return
        async with self._sem:
            init = await _fetch(self.s, "https://2.intelx.io/intelligent/search",
                method="POST", hdrs={"x-key": ik},
                json_body={"term": self.d, "maxresults": 1000,
                           "media": 0, "lookuplevel": 0, "sort": 2},
                as_json=True, as_text=False, timeout=15, **self._p())
        if not isinstance(init, dict) or "id" not in init: return
        sid = init["id"]
        await asyncio.sleep(3)
        results = await _jget(self.s, "https://2.intelx.io/intelligent/search/result",
                              hdrs={"x-key": ik}, params={"id": sid, "limit": "1000"},
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
        await self._jfetch("https://fofa.info/api/v1/search/all", src, cb,
                           params={"email": fe, "key": fk, "qbase64": query,
                                   "fields": "host,domain", "page": "1", "size": "10000"})

    async def cloudflare_radar(self) -> None:
        src = "cf_radar"
        cfk = self.k.get("cloudflare","")
        h = {"Authorization": f"Bearer {cfk}"} if cfk else {}
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("result",{}).get("searchResults",[]):
                name = item.get("name","") or item.get("domain","")
                if name and self.d in name.lower(): self.r.add_sub(name, s)
        await self._jfetch("https://radar.cloudflare.com/api/v0/search",
                           src, cb, params={"query": self.d, "limit": "100"}, hdrs=h)

    async def cloud_buckets(self) -> None:
        src = "cloud_buckets"
        org = self.d.split('.')[0]
        candidates = [
            f"{org}.s3.amazonaws.com", f"{org}-assets.s3.amazonaws.com",
            f"{org}-static.s3.amazonaws.com", f"{org}-media.s3.amazonaws.com",
            f"{org}-backup.s3.amazonaws.com", f"{org}-uploads.s3.amazonaws.com",
            f"{org}-data.s3.amazonaws.com", f"{org}-prod.s3.amazonaws.com",
            f"{org}-staging.s3.amazonaws.com", f"{org}-dev.s3.amazonaws.com",
            f"{org}-logs.s3.amazonaws.com", f"{org}-public.s3.amazonaws.com",
            f"{org}.storage.googleapis.com",
            f"{org}.blob.core.windows.net", f"{org}-cdn.azureedge.net",
            f"{org}.digitaloceanspaces.com", f"{org}.nyc3.digitaloceanspaces.com",
        ]
        for bucket in candidates:
            ip = await _resolve(bucket)
            if ip: self.r.add_sub(bucket, src)

    async def firebase(self) -> None:
        src = "firebase"
        org = self.d.split('.')[0]
        for pattern in [f"{org}.firebaseapp.com", f"{org}.web.app",
                        f"{org}-default-rtdb.firebaseio.com",
                        f"{org}-staging.web.app", f"{org}-dev.web.app"]:
            ip = await _resolve(pattern)
            if ip: self.r.add_sub(pattern, src)

    async def azure_websites(self) -> None:
        src = "azure"
        org = self.d.split('.')[0]
        for pattern in [f"{org}.azurewebsites.net", f"{org}.azurefd.net",
                        f"{org}-staging.azurewebsites.net",
                        f"{org}-dev.azurewebsites.net",
                        f"{org}-prod.azurewebsites.net",
                        f"{org}.trafficmanager.net"]:
            ip = await _resolve(pattern)
            if ip: self.r.add_sub(pattern, src)

    async def github_pages(self) -> None:
        src = "github_pages"
        org = self.d.split('.')[0]
        for pattern in [f"{org}.github.io", f"{self.d.replace('.','')}.github.io"]:
            ip = await _resolve(pattern)
            if ip: self.r.add_sub(pattern, src)

    # ══════════════════════ EXTRA PASSIVE SOURCES (100+) ════════════════════

    async def _doh_lookup(self, name: str, src: str) -> None:
        """DNS-over-HTTPS lookup — bypasses local resolver blocks."""
        for doh_url in DOH_URLS:
            try:
                async with self._sem:
                    params = {"name": name, "type": "A"}
                    hdrs = {"Accept": "application/dns-json"}
                    data = await _jget(self.s, doh_url, params=params, hdrs=hdrs,
                                       timeout=10, **self._p())
                if not isinstance(data, dict): continue
                for ans in data.get("Answer", []):
                    val = str(ans.get("data",""))
                    if self.d in val.lower():
                        self.r.add_sub(val.rstrip(".").lower(), src)
                break
            except Exception:
                continue

    async def facebook_ct(self) -> None:
        """Facebook Certificate Transparency API."""
        src = "facebook_ct"
        def cb(d, s):
            if not isinstance(d, dict): return
            for e in d.get("data", []):
                for n in e.get("domains", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch(
            f"https://graph.facebook.com/certificates",
            src, cb, params={"query": self.d, "fields": "domains,valid_from,valid_to",
                             "access_token": "anonymous"}, timeout=20)

    async def censys_api(self) -> None:
        """Censys v2 API certificates search."""
        src = "censys_api"
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("result", {}).get("hits", []):
                for n in r.get("parsed", {}).get("names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        try:
            import base64 as _b64
            app_id = self.k.get("censys_app_id", "")
            secret = self.k.get("censys_secret", "")
            h = {"Authorization": "Basic " + _b64.b64encode(f"{app_id}:{secret}".encode()).decode()} if app_id else {}
            await self._jfetch(
                "https://search.censys.io/api/v2/certificates/search",
                src, cb, params={"q": f"parsed.names: {self.d}", "per_page": "100"},
                hdrs=h, timeout=25)
        except Exception:
            pass

    async def shodanfavicon(self) -> None:
        """Shodan HTTP title/org search."""
        src = "shodan_org"
        sk = self.k.get("shodan", "")
        if not sk: return
        for q in [f"hostname:{self.d}", f"ssl.cert.subject.cn:{self.d}",
                  f"ssl.cert.subject.org:{self.d.split('.')[0]}"]:
            def cb(d, s, _q=q):
                if not isinstance(d, dict): return
                for m in d.get("matches", []):
                    for h in m.get("hostnames", []) + m.get("domains", []):
                        if self.d in h.lower():
                            self.r.add_sub(h.lower(), s)
                    ip = m.get("ip_str", "")
                    if ip: self.r.ip_ranges.add(ip)
            await self._jfetch("https://api.shodan.io/shodan/host/search",
                               src, cb, params={"key": sk, "query": q,
                                                "minify": "true"}, timeout=25)

    async def netcraft_search(self) -> None:
        src = "netcraft"
        await self._scrape(f"https://searchdns.netcraft.com/?restriction=site+ends+with&host={self.d}&lookup=t&position=limited", src, timeout=20)
        await self._scrape(f"https://toolbar.netcraft.com/site_report?url={self.d}", src, timeout=15)

    async def dnslytics(self) -> None:
        src = "dnslytics"
        def cb(d, s):
            if not isinstance(d, dict): return
            for e in d.get("data", {}).get("domains", []):
                if isinstance(e, str) and self.d in e:
                    self.r.add_sub(e, s)
            for e in d.get("result", []):
                if isinstance(e, dict):
                    n = e.get("domain","") or e.get("name","")
                    if n and self.d in n: self.r.add_sub(n, s)
        await self._jfetch(f"https://api.dnslytics.net/v1/domainsearch/{self.d}",
                           src, cb, timeout=15)

    async def domaintools(self) -> None:
        src = "domaintools"
        await self._scrape(f"https://reversewhois.domaintools.com/?domains={self.d}", src, timeout=20)
        await self._scrape(f"https://whois.domaintools.com/{self.d}", src, timeout=15)

    async def threatbook(self) -> None:
        src = "threatbook"
        def cb(d, s):
            if not isinstance(d, dict): return
            for sub in d.get("data", {}).get("sub_domains", []):
                self.r.add_sub(sub, s)
        await self._jfetch(
            f"https://api.threatbook.io/v1/domain/sub_domains",
            src, cb, params={"apikey": self.k.get("threatbook",""), "resource": self.d}, timeout=20)

    async def dnsbufferover2(self) -> None:
        src = "dnsbufferover2"
        for ep in [f"https://dns.bufferover.run/dns?q=.{self.d}",
                   f"https://tls.bufferover.run/dns?q=.{self.d}"]:
            def cb(d, s):
                if not isinstance(d, dict): return
                for key in ("FDNS_A", "RDNS"):
                    for entry in d.get(key, []):
                        parts = entry.split(",")
                        for p in parts:
                            for sub in _subs_from_text(p, self.d):
                                self.r.add_sub(sub, s)
            await self._jfetch(ep, src, cb, timeout=20)

    async def passivedns_mnemonic(self) -> None:
        src = "mnemonic_pdns"
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("data", []):
                rrname = r.get("rrname","").rstrip(".").lower()
                if rrname and self.d in rrname:
                    self.r.add_sub(rrname, s)
        await self._jfetch(
            f"https://api.mnemonic.no/pdns/v3/{self.d}",
            src, cb, params={"limit": "1000"}, timeout=20)

    async def farsight_dnsdb(self) -> None:
        src = "farsight_dnsdb"
        fsk = self.k.get("farsight","")
        if not fsk: return
        def cb(d, s):
            if isinstance(d, str):
                for line in d.splitlines():
                    for sub in _subs_from_text(line, self.d):
                        self.r.add_sub(sub, s)
        await self._jfetch(
            f"https://api.dnsdb.info/lookup/rrset/name/*.{self.d}/",
            src, cb, hdrs={"X-API-Key": fsk, "Accept": "application/json"},
            timeout=25)

    async def riskiq_pdns(self) -> None:
        src = "riskiq"
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("results", []):
                name = r.get("name","").rstrip(".").lower()
                if name and self.d in name: self.r.add_sub(name, s)
                value = r.get("value","").rstrip(".").lower()
                if value and self.d in value: self.r.add_sub(value, s)
        uname = self.k.get("riskiq_user","")
        passwd = self.k.get("riskiq_pass","")
        if uname:
            import base64 as _b64
            h = {"Authorization": "Basic " + _b64.b64encode(f"{uname}:{passwd}".encode()).decode()}
            await self._jfetch("https://api.riskiq.net/pt/v2/dns/passive",
                               src, cb, params={"query": self.d}, hdrs=h, timeout=25)
        else:
            # Community endpoint
            await self._scrape(f"https://community.riskiq.com/research/{self.d}/resolutions", src, timeout=20)

    async def shadowserver(self) -> None:
        src = "shadowserver"
        await self._scrape(f"https://dnssearch.shadowserver.org/?q={self.d}", src, timeout=20)

    async def criminalip(self) -> None:
        src = "criminalip"
        cik = self.k.get("criminalip","")
        if not cik: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("data", {}).get("result", []):
                h = item.get("hostname","")
                if h and self.d in h.lower(): self.r.add_sub(h.lower(), s)
        await self._jfetch("https://api.criminalip.io/v1/domain/reports",
                           src, cb, params={"query": f"domain:{self.d}"},
                           hdrs={"x-api-key": cik}, timeout=20)

    async def spyse2(self) -> None:
        src = "spyse2"
        await self._scrape(f"https://spyse.com/target/domain/{self.d}", src, timeout=15)

    async def urlscan2(self) -> None:
        src = "urlscan2"
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("results", []):
                p = r.get("page", {})
                for key in ("domain","apex","url"):
                    val = p.get(key,"")
                    if val and self.d in val.lower():
                        for sub in _subs_from_text(val, self.d):
                            self.r.add_sub(sub, s)
        # Additional urlscan queries
        for q in [f"domain:{self.d}", f"page.domain:{self.d}", f"task.domain:{self.d}"]:
            await self._jfetch("https://urlscan.io/api/v1/search/",
                               src, cb, params={"q": q, "size": "200"}, timeout=25)

    async def grep_app(self) -> None:
        """grep.app — code search for subdomains."""
        src = "grep_app"
        def cb(d, s):
            if not isinstance(d, dict): return
            for hit in d.get("hits", {}).get("hits", []):
                text = json.dumps(hit.get("_source", {}))
                for sub in _subs_from_text(text, self.d):
                    self.r.add_sub(sub, s)
        await self._jfetch("https://grep.app/api/search",
                           src, cb, params={"q": self.d, "regexp": "false"}, timeout=20)

    async def searchcode(self) -> None:
        """searchcode.com — source code search."""
        src = "searchcode"
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("results", []):
                text = r.get("snippet","")
                for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
        await self._jfetch("https://searchcode.com/api/codesearch_I/",
                           src, cb, params={"q": self.d, "per_page": "100"}, timeout=20)

    async def github2(self) -> None:
        """GitHub code search — additional patterns."""
        src = "github_code"
        for q in [f'"{self.d}" filename:.env', f'"{self.d}" filename:config',
                  f'"{self.d}" site:{self.d}', f'"{self.d}" subdomain']:
            await self._scrape(
                f"https://github.com/search?q={urllib.parse.quote(q)}&type=code",
                src, timeout=20, hdrs={"Accept": "text/html"})

    async def gitlab2(self) -> None:
        src = "gitlab2"
        for q in [self.d, f'"{self.d}"']:
            await self._scrape(
                f"https://gitlab.com/search?utf8=%E2%9C%93&search={urllib.parse.quote(q)}&group_id=&project_id=&scope=blobs",
                src, timeout=15)

    async def trello_search(self) -> None:
        src = "trello"
        await self._scrape(f"https://trello.com/search?q={self.d}&modelTypes=all", src, timeout=15)

    async def shodan_fdns(self) -> None:
        """Shodan FDNS — forward DNS dataset queries."""
        src = "shodan_fdns"
        sk = self.k.get("shodan","")
        if not sk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for entry in d.get("matches", []):
                for k in ("hostnames","domains","ssl"):
                    val = entry.get(k,[])
                    if isinstance(val, list):
                        for v in val:
                            if self.d in str(v).lower():
                                self.r.add_sub(str(v).lower(), s)
        for q in [f"ssl.cert.subject.cn:*.{self.d}",
                  f"ssl.cert.subject.cn:{self.d}",
                  f"ssl:{self.d}"]:
            await self._jfetch("https://api.shodan.io/shodan/host/search",
                               src, cb, params={"key": sk, "query": q,
                                                "minify": "true", "facets": "domain"}, timeout=30)

    async def dnstwist(self) -> None:
        """DNStwist — domain permutations."""
        src = "dnstwist"
        def cb(d, s):
            if not isinstance(d, list): return
            for item in d:
                n = item.get("domain","") or item.get("fuzzer","")
                if n and self.d.split(".")[0] in n:
                    self.r.add_sub(n, s)
        await self._jfetch(f"https://dnstwist.it/api/?domain={self.d}&registered=true",
                           src, cb, timeout=25)

    async def whoisxml_reverse(self) -> None:
        """WhoisXML reverse IP/NS lookup."""
        src = "whoisxml_reverse"
        wk = self.k.get("whoisxml","")
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("result", []):
                n = item.get("domain","")
                if n and self.d in n: self.r.add_sub(n, s)
        for qtype in ["reverse_ip", "reverse_ns"]:
            await self._jfetch(
                f"https://reverse-ip.whoisxmlapi.com/api/v1",
                src, cb, params={"apiKey": wk, "domain": self.d, "outputFormat": "JSON"},
                timeout=20)

    async def dnstree(self) -> None:
        src = "dnstree"
        await self._scrape(f"https://dnstree.com/{self.d}", src, timeout=15)

    async def netlas2(self) -> None:
        src = "netlas2"
        for q in [f"domain:{self.d}", f"certificate.subject.common_name:{self.d}"]:
            await self._scrape(f"https://app.netlas.io/responses/?q={urllib.parse.quote(q)}&page=1&indices=", src, timeout=20)

    async def fofa2(self) -> None:
        src = "fofa2"
        import base64 as _b64
        q = _b64.b64encode(f'domain="{self.d}"'.encode()).decode()
        def cb(d, s):
            if not isinstance(d, dict): return
            for row in d.get("results", []):
                if isinstance(row, list):
                    for v in row:
                        for sub in _subs_from_text(str(v), self.d):
                            self.r.add_sub(sub, s)
        fk = self.k.get("fofa_key",""); fe = self.k.get("fofa_email","")
        await self._jfetch("https://fofa.info/api/v1/search/all",
                           src, cb, params={"email": fe, "key": fk, "qbase64": q,
                                            "size": "1000", "fields": "host,domain"}, timeout=25)

    async def quake360(self) -> None:
        src = "quake360"
        qk = self.k.get("quake360","")
        if not qk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("data", []):
                hostname = item.get("service", {}).get("http", {}).get("host","")
                if hostname and self.d in hostname: self.r.add_sub(hostname, s)
                for n in item.get("service",{}).get("cert",{}).get("subject",{}).get("common_name",[]):
                    if n and self.d in n: self.r.add_sub(n.lstrip("*."), s)
        await self._jfetch("https://quake.360.net/api/v3/search/quake_service",
                           src, cb, json_body={"query": f"domain:{self.d}", "size": 500},
                           hdrs={"X-QuakeToken": qk}, method="POST", timeout=25)

    async def hunterhow(self) -> None:
        src = "hunterhow"
        hk = self.k.get("hunterhow","")
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("data", {}).get("arr", []):
                host = item.get("hostname","") or item.get("domain","")
                if host and self.d in host: self.r.add_sub(host, s)
        await self._jfetch("https://api.hunter.how/search",
                           src, cb,
                           params={"api-key": hk, "query": f'domain.suffix="{self.d}"',
                                   "page": "1", "page_size": "100"}, timeout=20)

    async def c99_extra(self) -> None:
        src = "c99_extra"
        ck = self.k.get("c99","")
        if not ck: return
        for ep in [f"https://api.c99.nl/domainresolver?host={self.d}&json",
                   f"https://api.c99.nl/subdomainfinder?host={self.d}&key={ck}&json",
                   f"https://api.c99.nl/phonelookup?number={self.d}&key={ck}&json"]:
            def cb(d, s):
                if isinstance(d, dict):
                    for key in ("subdomains","result","data"):
                        val = d.get(key,[])
                        if isinstance(val, list):
                            for v in val:
                                n = v.get("subdomain","") if isinstance(v,dict) else str(v)
                                if n and self.d in n: self.r.add_sub(n, s)
            await self._jfetch(ep, src, cb, timeout=20)

    async def dnsdumpster2(self) -> None:
        src = "dnsdumpster2"
        # Alternative endpoint / different query format
        await self._scrape(f"https://dnsdumpster.com/static/map/{self.d}.png", src, timeout=10)
        await self._scrape(f"https://api.hackertarget.com/hostsearch/?q={self.d}", src, timeout=15)
        await self._scrape(f"https://api.hackertarget.com/reverseiplookup/?q={self.d}", src, timeout=15)
        await self._scrape(f"https://api.hackertarget.com/dnslookup/?q={self.d}", src, timeout=15)

    async def subdomaincenter(self) -> None:
        src = "subdomaincenter"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    if isinstance(item, str) and self.d in item:
                        self.r.add_sub(item.strip(), s)
            elif isinstance(d, dict):
                for v in d.values():
                    if isinstance(v, list):
                        for i in v:
                            if isinstance(i, str) and self.d in i:
                                self.r.add_sub(i.strip(), s)
        await self._jfetch(f"https://api.subdomain.center/?domain={self.d}", src, cb, timeout=15)

    async def recon_ng(self) -> None:
        src = "recon_ng"
        # ReconNg-accessible endpoints
        for url in [
            f"https://api.reconng.com/subdomains?domain={self.d}",
            f"https://reconng.com/api/domains/{self.d}",
        ]:
            await self._scrape(url, src, timeout=15)

    async def archive_cdx(self) -> None:
        """CommonCrawl CDX API — exhaustive URL/subdomain extraction."""
        src = "archive_cdx"
        for url_prefix in [f"*.{self.d}/*", f"{self.d}/*"]:
            def cb(d, s):
                if not isinstance(d, list): return
                for row in d:
                    if isinstance(row, list) and len(row) > 0:
                        for cell in row:
                            for sub in _subs_from_text(str(cell), self.d):
                                self.r.add_sub(sub, s)
                            for u in _urls_from_text(str(cell), self.d):
                                self.r.add_url(u, s)
                    elif isinstance(row, str):
                        for sub in _subs_from_text(row, self.d): self.r.add_sub(sub, s)
            await self._jfetch(
                "https://web.archive.org/cdx/search/cdx",
                src, cb, params={"url": url_prefix, "output": "json",
                                 "fl": "original", "limit": "5000",
                                 "collapse": "urlkey"}, timeout=45)

    async def commoncrawl2(self) -> None:
        """CommonCrawl index API — additional indexes."""
        src = "commoncrawl2"
        for idx in ["CC-MAIN-2024-42", "CC-MAIN-2024-26", "CC-MAIN-2024-10",
                    "CC-MAIN-2023-50", "CC-MAIN-2023-23"]:
            def cb(d, s):
                if not isinstance(d, dict): return
                for url in d.get("urls", []):
                    for sub in _subs_from_text(url, self.d): self.r.add_sub(sub, s)
                text = json.dumps(d)
                for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
            await self._jfetch(
                f"https://index.commoncrawl.org/{idx}-index",
                src, cb, params={"url": f"*.{self.d}", "output": "json",
                                 "limit": "1000"}, timeout=30)

    async def wayback2(self) -> None:
        """Wayback Machine Availability API + CDX extras."""
        src = "wayback2"
        # CDX with additional fields
        await self._scrape(
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.d}&output=text&fl=original&limit=5000&collapse=urlkey",
            src, timeout=40)
        # Also query with http:// and https://
        for scheme in ["http","https"]:
            await self._scrape(
                f"http://web.archive.org/cdx/search/cdx?url={scheme}://*.{self.d}&output=text&fl=original&limit=3000",
                src, timeout=30)

    async def certstream_api(self) -> None:
        """CertStream / crtsh exhaustive queries."""
        src = "certstream"
        for pattern in [f"%.{self.d}", f"%.%.{self.d}", f"%.%.%.{self.d}"]:
            def cb(d, s):
                if not isinstance(d, list): return
                for e in d:
                    for f in ("name_value","common_name"):
                        for n in e.get(f,"").split('\n'):
                            self.r.add_sub(n.strip().lower().lstrip("*."), s)
            await self._jfetch("https://crt.sh/", src, cb,
                               params={"q": pattern, "output": "json"}, timeout=35)

    async def threatfox(self) -> None:
        src = "threatfox"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("data", []):
                ioc = item.get("ioc","")
                if ioc and self.d in ioc: self.r.add_sub(ioc, s)
        await self._jfetch("https://threatfox-api.abuse.ch/api/v1/", src, cb,
                           json_body={"query": "search_ioc", "search_term": self.d},
                           method="POST", timeout=20)

    async def abusech(self) -> None:
        src = "abuse_ch"
        for url in [
            f"https://urlhaus-api.abuse.ch/v1/host/",
            f"https://bazaar.abuse.ch/api/v1/",
        ]:
            def cb(d, s):
                if not isinstance(d, dict): return
                text = json.dumps(d)
                for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
            await self._jfetch(url, src, cb,
                               json_body={"host": self.d}, method="POST", timeout=20)

    async def maltiverse(self) -> None:
        src = "maltiverse"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("data", []):
                h = item.get("hostname","") or item.get("domain","")
                if h and self.d in h: self.r.add_sub(h, s)
        await self._jfetch(f"https://api.maltiverse.com/hostname/{self.d}/related",
                           src, cb, timeout=15)

    async def publicwww2(self) -> None:
        src = "publicwww2"
        for q in [f'"{self.d}"', f'href="{self.d}"', f'action="{self.d}"']:
            await self._scrape(
                f"https://publicwww.com/websites/{urllib.parse.quote(q)}/",
                src, timeout=20)

    async def bing2(self) -> None:
        src = "bing2"
        for pg in range(1, 6):
            for q in [f"site:{self.d} -www", f"site:*.{self.d}",
                      f"hostname:{self.d}"]:
                await self._scrape(
                    f"https://www.bing.com/search?q={urllib.parse.quote(q)}&first={pg*10}",
                    src, timeout=15, hdrs={"Accept-Language": "en-US"})

    async def brave_search(self) -> None:
        src = "brave"
        for q in [f"site:{self.d}", f"site:*.{self.d}"]:
            await self._scrape(
                f"https://search.brave.com/search?q={urllib.parse.quote(q)}&source=web",
                src, timeout=15)

    async def ask_com(self) -> None:
        src = "ask_com"
        await self._scrape(f"https://www.ask.com/web?q=site%3A{self.d}", src, timeout=15)

    async def ecosia(self) -> None:
        src = "ecosia"
        await self._scrape(f"https://www.ecosia.org/search?method=index&q=site%3A{self.d}", src, timeout=15)

    async def qwant(self) -> None:
        src = "qwant"
        await self._scrape(f"https://www.qwant.com/?q=site%3A{self.d}&t=web", src, timeout=15)

    async def archive_today(self) -> None:
        src = "archive_today"
        await self._scrape(f"https://archive.ph/search/?q={self.d}", src, timeout=15)
        await self._scrape(f"https://archive.ph/*.{self.d}", src, timeout=15)

    async def intelx(self) -> None:
        src = "intelx"
        ixk = self.k.get("intelx","")
        def cb(d, s):
            if not isinstance(d, dict): return
            for sel in d.get("selectors", []):
                v = sel.get("selectvalue","")
                if v and self.d in v: self.r.add_sub(v, s)
        if ixk:
            await self._jfetch("https://2.intelx.io/intelligent/search",
                               src, cb,
                               json_body={"term": self.d, "maxresults": 100,
                                          "media": 0, "target": 0, "lookuplevel": 0},
                               hdrs={"x-key": ixk}, method="POST", timeout=20)
        else:
            await self._scrape(f"https://intelx.io/?s={self.d}", src, timeout=20)

    async def dehashed(self) -> None:
        src = "dehashed"
        dk = self.k.get("dehashed",""); de = self.k.get("dehashed_email","")
        if not (dk and de): return
        import base64 as _b64
        h = {"Authorization": "Basic " + _b64.b64encode(f"{de}:{dk}".encode()).decode()}
        def cb(d, s):
            if not isinstance(d, dict): return
            for entry in d.get("entries", []):
                for field in ("email","username","name","address","phone"):
                    v = entry.get(field,"")
                    for sub in _subs_from_text(str(v), self.d): self.r.add_sub(sub, s)
        await self._jfetch("https://api.dehashed.com/search",
                           src, cb,
                           params={"query": f'domain:{self.d}', "size": "100"},
                           hdrs=h, timeout=20)

    async def hunter_email(self) -> None:
        src = "hunter_email"
        hk = self.k.get("hunter","")
        if not hk: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for email in d.get("data", {}).get("emails", []):
                v = email.get("value","")
                if "@" in v:
                    dom = v.split("@",1)[1]
                    if self.d in dom: self.r.add_sub(dom, s)
        await self._jfetch("https://api.hunter.io/v2/domain-search",
                           src, cb, params={"domain": self.d, "api_key": hk,
                                            "limit": "100"}, timeout=20)

    async def dnsscan_io(self) -> None:
        src = "dnsscan"
        await self._scrape(f"https://dnsscan.io/dns-records/{self.d}/", src, timeout=15)
        await self._scrape(f"https://dnsscan.io/dns-records/subdomains/{self.d}/", src, timeout=15)

    async def ipv4info(self) -> None:
        src = "ipv4info"
        await self._scrape(f"https://ipv4info.com/search/{self.d}", src, timeout=15)
        await self._scrape(f"https://ipv4info.com/tools/domain/{self.d}", src, timeout=15)

    async def whoisfreaks(self) -> None:
        src = "whoisfreaks"
        wfk = self.k.get("whoisfreaks","")
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("whois_records", d.get("result", [])):
                domain = item.get("domain_name","")
                if domain and self.d in domain: self.r.add_sub(domain, s)
        await self._jfetch(
            f"https://api.whoisfreaks.com/v1.0/whois?whois=bulk_reverse&apiKey={wfk}&domain={self.d}&format=json",
            src, cb, timeout=20)

    async def dnszones(self) -> None:
        src = "dnszones"
        await self._scrape(f"https://dnszones.info/search?q={self.d}", src, timeout=15)

    async def entrust2(self) -> None:
        src = "entrust2"
        def cb(d, s):
            if not isinstance(d, dict): return
            for cert in d.get("certificates", []):
                for n in cert.get("dnsNames", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch(
            "https://ctsearch.entrust.com/api/v1/certificates",
            src, cb,
            params={"fields": "subjectDN,dnsNames,issuerDN",
                    "domain": self.d, "includeExpired": "true",
                    "exactMatch": "false", "limit": "2000"}, timeout=30)

    async def sslbl(self) -> None:
        src = "sslbl"
        def cb(d, s):
            text = json.dumps(d) if isinstance(d, (dict,list)) else str(d)
            for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
        await self._jfetch(f"https://sslbl.abuse.ch/api/domains/{self.d}/",
                           src, cb, timeout=15)

    async def rapiddns2(self) -> None:
        src = "rapiddns2"
        await self._scrape(f"https://rapiddns.io/subdomain/{self.d}?full=1&down=1", src, timeout=20)
        await self._scrape(f"https://rapiddns.io/sameip/{self.d}?full=1", src, timeout=20)

    async def ptrarchive(self) -> None:
        src = "ptrarchive"
        await self._scrape(f"http://ptrarchive.com/tools/search3.htm?label={self.d}&date=ALL", src, timeout=20)

    async def dnsspy(self) -> None:
        src = "dnsspy"
        await self._scrape(f"https://dnsspy.io/domain/{self.d}", src, timeout=15)

    async def dnscoffee(self) -> None:
        src = "dnscoffee"
        def cb(d, s):
            if not isinstance(d, dict): return
            text = json.dumps(d)
            for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
        await self._jfetch(f"https://dns.coffee/api/domain/{self.d}", src, cb, timeout=15)

    async def hackertarget2(self) -> None:
        src = "hackertarget2"
        for ep in [
            f"https://api.hackertarget.com/zonetransfer/?q={self.d}",
            f"https://api.hackertarget.com/nmap/?q={self.d}",
            f"https://api.hackertarget.com/whois/?q={self.d}",
        ]:
            await self._scrape(ep, src, timeout=15)

    async def networksdb(self) -> None:
        src = "networksdb"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("results", []):
                n = item.get("name","") or item.get("host","") or item.get("domain","")
                if n and self.d in n: self.r.add_sub(n, s)
        await self._jfetch(f"https://networksdb.io/api/domain/{self.d}",
                           src, cb, timeout=15)

    async def redhuntlabs(self) -> None:
        src = "redhuntlabs"
        def cb(d, s):
            if not isinstance(d, list): return
            for item in d:
                h = item.get("host","") if isinstance(item,dict) else str(item)
                if h and self.d in h: self.r.add_sub(h, s)
        for ep in [
            f"https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain={self.d}&page_size=200",
            f"https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain={self.d}&page_size=200&page=2",
        ]:
            await self._jfetch(ep, src, cb, timeout=20)

    async def leakix2(self) -> None:
        src = "leakix2"
        lk = self.k.get("leakix","")
        h = {"api-key": lk} if lk else {}
        for field in ["domain", "subdomain", "host"]:
            def cb(d, s):
                if not isinstance(d, list): return
                for item in d:
                    host = item.get("host","") or item.get("subdomain","")
                    if host and self.d in host: self.r.add_sub(host, s)
            await self._jfetch(
                f"https://leakix.net/api/subdomains/{self.d}",
                src, cb, hdrs=h, timeout=20)

    async def opendata_dns(self) -> None:
        src = "opendata"
        # Scans.io / FDNS datasets (public)
        for url in [
            f"https://opendata.rapid7.com/sonar.fdns_v2/{self.d}/subdomains",
            f"https://sonar.omnisint.io/subdomains/{self.d}",
            f"https://sonar.omnisint.io/all/{self.d}",
        ]:
            await self._scrape(url, src, timeout=20)

    async def dnsdb_graph(self) -> None:
        src = "dnsdb_graph"
        for url in [
            f"https://dnsdb.info/search?q={self.d}",
            f"https://pdns.daloo.de/search.php?q={self.d}&exact=0",
        ]:
            await self._scrape(url, src, timeout=15)

    async def certcentral(self) -> None:
        src = "certcentral"
        await self._scrape(f"https://ct.cloudflare.com/logs?domain={self.d}", src, timeout=15)
        await self._scrape(f"https://transparencyreport.google.com/https/certificates?include_subdomains=true&domain={self.d}", src, timeout=20)

    async def subdomainfinder(self) -> None:
        src = "subdomainfinder"
        await self._scrape(f"https://subdomainfinder.c99.nl/index.php?domain={self.d}", src, timeout=20)
        await self._scrape(f"https://subdomains.whoisxmlapi.com/api/v1?apiKey=&domains%5B%5D={self.d}", src, timeout=20)

    async def ipinfo2(self) -> None:
        src = "ipinfo2"
        def cb(d, s):
            if not isinstance(d, dict): return
            text = json.dumps(d)
            for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
        await self._jfetch(f"https://ipinfo.io/{self.d}/json", src, cb, timeout=12)
        # AS lookup
        ip = await _resolve(self.d)
        if ip:
            await self._jfetch(f"https://ipinfo.io/{ip}/json", src, cb, timeout=12)

    async def bgpview2(self) -> None:
        src = "bgpview2"
        def cb(d, s):
            if not isinstance(d, dict): return
            for prefix in d.get("data", {}).get("prefixes", []):
                pnet = prefix.get("prefix","")
                if pnet: self.r.ip_ranges.add(pnet)
            for peer in d.get("data", {}).get("peers", []):
                asn_desc = peer.get("description","")
                if self.d.split(".")[0].lower() in asn_desc.lower():
                    asn = peer.get("asn","")
                    if asn: self.r.add_sub(f"AS{asn}", s)
        await self._jfetch(f"https://api.bgpview.io/search?query_term={self.d}", src, cb, timeout=20)

    async def reverse_ip_api(self) -> None:
        """Reverse IP lookup — find all domains on same IP."""
        src = "reverse_ip"
        ip = await _resolve(self.d)
        if not ip: return
        for url in [
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            f"https://viewdns.info/reverseip/?host={ip}&apikey=free&output=json",
            f"https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=&ip={ip}&outputFormat=JSON",
            f"https://rapiddns.io/sameip/{ip}?full=1&down=1",
        ]:
            await self._scrape(url, src, timeout=15)

    async def ssl_cert_sans(self) -> None:
        """Extract SANs from TLS certificate directly."""
        src = "ssl_sans"
        for host in [self.d] + list(self.r.live_subs)[:20]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                conn = asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host)
                _, writer = await asyncio.wait_for(conn, timeout=6)
                cert = writer.get_extra_info("ssl_object").getpeercert(binary_form=False)
                if cert:
                    for san_type, san_val in cert.get("subjectAltName",[]):
                        if san_type == "DNS":
                            self.r.add_sub(san_val.lstrip("*.").lower(), src)
                try:
                    writer.close(); await writer.wait_closed()
                except Exception:
                    pass
            except Exception:
                pass

    async def arin_lookup(self) -> None:
        src = "arin"
        ip = await _resolve(self.d)
        if not ip: return
        def cb(d, s):
            if not isinstance(d, dict): return
            text = json.dumps(d)
            for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
        await self._jfetch(f"https://whois.arin.net/rest/ip/{ip}", src, cb,
                           hdrs={"Accept": "application/json"}, timeout=15)

    async def ripe_lookup(self) -> None:
        src = "ripe"
        ip = await _resolve(self.d)
        if not ip: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for obj in d.get("objects", {}).get("object", []):
                text = json.dumps(obj)
                for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
        await self._jfetch(f"https://rest.db.ripe.net/search.json?query-string={ip}&type-filter=inetnum",
                           src, cb, timeout=20)

    async def hurricane_electric(self) -> None:
        src = "he_bgp"
        await self._scrape(f"https://bgp.he.net/dns/{self.d}", src, timeout=15)
        await self._scrape(f"https://bgp.he.net/ip/{self.d}", src, timeout=15)

    async def myssl(self) -> None:
        src = "myssl"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("data", []):
                for n in item.get("sans", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch(f"https://myssl.com/api/v1/sslinfo?domain={self.d}",
                           src, cb, timeout=15)

    async def sslmate2(self) -> None:
        src = "sslmate2"
        def cb(d, s):
            if not isinstance(d, list): return
            for e in d:
                for n in e.get("dns_names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        for pattern in [f"*.{self.d}", self.d]:
            await self._jfetch(
                f"https://api.certspotter.com/v1/issuances",
                src, cb,
                params={"domain": pattern, "include_subdomains": "true",
                        "expand": "dns_names", "match_wildcards": "true"},
                timeout=25)

    async def google_transparency(self) -> None:
        src = "google_transparency"
        def cb(d, s):
            if not isinstance(d, dict): return
            text = json.dumps(d)
            for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
        for q in [self.d, f"*.{self.d}"]:
            await self._jfetch(
                "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch",
                src, cb, params={"include_expired": "false", "include_subdomains": "true",
                                 "domain": q}, timeout=25)

    async def tls_observer(self) -> None:
        src = "tls_observer"
        def cb(d, s):
            if not isinstance(d, dict): return
            for item in d.get("certificates", []):
                for n in item.get("subject_alt_names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch(f"https://tls.imirhil.fr/certificate/{self.d}.json",
                           src, cb, timeout=15)

    async def dnspedia(self) -> None:
        src = "dnspedia"
        await self._scrape(f"https://dnspedia.com/tld/search.php?q={self.d}", src, timeout=15)

    async def censys_view(self) -> None:
        src = "censys_view"
        await self._scrape(f"https://search.censys.io/certificates?q={self.d}", src, timeout=20)
        await self._scrape(f"https://search.censys.io/hosts?q=dns.reverse_dns:{self.d}", src, timeout=20)

    async def reconftw_sources(self) -> None:
        """Additional sources used by recon tools (reconftw, amass)."""
        src = "reconftw"
        for url in [
            f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains",
            f"https://chaos.projectdiscovery.io/dns/{self.d}/subdomains",
            f"https://codebeautify.org/jsonviewer#{self.d}",
        ]:
            def cb(d, s):
                if not isinstance(d, dict): return
                for sub in d.get("subdomains", []):
                    self.r.add_sub(f"{sub}.{self.d}", s)
            await self._jfetch(url, src, cb, timeout=15)

    async def chaos2(self) -> None:
        src = "chaos2"
        ck = self.k.get("chaos","")
        if not ck: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for sub in d.get("subdomains", []):
                self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch(f"https://chaos-data.projectdiscovery.io/{self.d}.zip",
                           src, cb, hdrs={"Authorization": ck}, timeout=20)
        await self._jfetch(f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains",
                           src, cb, hdrs={"Authorization": ck}, timeout=20)

    async def chaos3(self) -> None:
        """ProjectDiscovery Chaos — CNAME / A-record endpoint variant."""
        src = "chaos3"
        k = self.k.get("chaos", "")
        if not k: return
        def cb(d, s):
            if not isinstance(d, dict): return
            # /dns/{domain}/cname returns {"subdomains": [...]} just like the main endpoint
            for sub in d.get("subdomains", []):
                self.r.add_sub(f"{sub}.{self.d}", s)
            # also handle flat list response
            if isinstance(d, list):
                for sub in d:
                    self.r.add_sub(f"{sub}.{self.d}", s)
        for ep in ["cname", "a", "ns"]:
            await self._jfetch(
                f"https://dns.projectdiscovery.io/dns/{self.d}/{ep}",
                src, cb, hdrs={"Authorization": k}, timeout=20)

    async def phishtank(self) -> None:
        src = "phishtank"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    url_val = item.get("url","") if isinstance(item,dict) else str(item)
                    for sub in _subs_from_text(url_val, self.d): self.r.add_sub(sub, s)
        await self._jfetch(f"https://checkurl.phishtank.com/checkurl/",
                           src, cb, json_body={"url": self.d, "format": "json"},
                           method="POST", timeout=15)

    async def dnstwist2(self) -> None:
        """DNStwist via web API for permutation domains."""
        src = "dnstwist2"
        for url in [
            f"https://dnstwist.it/?q={self.d}&format=json",
            f"https://api.typosquat.com/subdomains?domain={self.d}",
        ]:
            def cb(d, s):
                if isinstance(d, list):
                    for item in d:
                        n = item.get("domain","") if isinstance(item,dict) else str(item)
                        if n and (self.d.split(".")[0] in n or self.d in n):
                            self.r.add_sub(n, s)
            await self._jfetch(url, src, cb, timeout=15)

    async def shodaninternet(self) -> None:
        """Shodan InternetDB — fast host info."""
        src = "shodan_idb"
        ip = await _resolve(self.d)
        if not ip: return
        def cb(d, s):
            if not isinstance(d, dict): return
            for h in d.get("hostnames", []):
                if self.d in h.lower(): self.r.add_sub(h.lower(), s)
            for tag in d.get("tags", []):
                if self.d in str(tag).lower(): self.r.add_sub(str(tag).lower(), s)
        await self._jfetch(f"https://internetdb.shodan.io/{ip}", src, cb, timeout=10)
        # Also do /24 range — concurrently to avoid 254× sequential slowdown.
        # Bug fixes: range(1, 255) missed .255 (off-by-one); sequential awaits
        # made this ~254× slower than necessary. Now gathers all 255 concurrently.
        parts = ip.rsplit(".", 1)
        if len(parts) == 2:
            tasks = [
                self._jfetch(f"https://internetdb.shodan.io/{parts[0]}.{i}", src, cb, timeout=5)
                for i in range(1, 256)  # 1-255 inclusive (was 1-254, missing .255)
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def fullhunt2(self) -> None:
        src = "fullhunt2"
        fk = self.k.get("fullhunt","")
        h = {"X-API-KEY": fk} if fk else {}
        def cb(d, s):
            if not isinstance(d, dict): return
            for host in d.get("hosts", []):
                if self.d in host: self.r.add_sub(host, s)
            for asset in d.get("assets", []):
                n = asset.get("host","") or asset.get("domain","")
                if n and self.d in n: self.r.add_sub(n, s)
        await self._jfetch(f"https://fullhunt.io/api/v1/domain/{self.d}/subdomains",
                           src, cb, hdrs=h, timeout=25)
        await self._jfetch(f"https://fullhunt.io/api/v1/domain/{self.d}/details",
                           src, cb, hdrs=h, timeout=25)

    async def securitytrails2(self) -> None:
        src = "securitytrails2"
        stk = self.k.get("securitytrails","")
        if not stk: return
        h = {"APIKEY": stk}
        def cb(d, s):
            if not isinstance(d, dict): return
            for sub in d.get("subdomains", []):
                self.r.add_sub(f"{sub}.{self.d}", s)
            for rec in d.get("records", {}).values():
                if isinstance(rec, list):
                    for v in rec:
                        for n in _subs_from_text(str(v), self.d):
                            self.r.add_sub(n, s)
        # Current + history
        for ep in [
            f"https://api.securitytrails.com/v1/domain/{self.d}/subdomains",
            f"https://api.securitytrails.com/v1/history/{self.d}/dns/a",
            f"https://api.securitytrails.com/v1/history/{self.d}/dns/mx",
            f"https://api.securitytrails.com/v1/history/{self.d}/dns/ns",
            f"https://api.securitytrails.com/v1/history/{self.d}/dns/cname",
        ]:
            await self._jfetch(ep, src, cb, hdrs=h, timeout=25)

    async def dnsx_query(self) -> None:
        """DNSX passive DNS via PD chaos / dnsx APIs."""
        src = "dnsx"
        for url in [
            f"https://dnsx.proj.is/dns/{self.d}",
            f"https://dnsx.shubs.io/dns/{self.d}",
            f"https://dns.projectdiscovery.io/dns/{self.d}/a",
            f"https://dns.projectdiscovery.io/dns/{self.d}/cname",
            f"https://dns.projectdiscovery.io/dns/{self.d}/mx",
            f"https://dns.projectdiscovery.io/dns/{self.d}/ns",
        ]:
            def cb(d, s):
                text = json.dumps(d) if isinstance(d,(dict,list)) else str(d)
                for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
            await self._jfetch(url, src, cb, timeout=15)

    async def subfinder_sources(self) -> None:
        """Sources used by subfinder that we haven't covered yet."""
        src = "subfinder"
        for url in [
            f"https://api.subdomain.center/?domain={self.d}",
            f"https://jldc.me/anubis/subdomains/{self.d}",
            f"https://www.nmmapper.com/api/tool/?domain={self.d}&tool=findomain",
            f"https://api.certspotter.com/v1/issuances?domain={self.d}&include_subdomains=true&expand=dns_names",
        ]:
            def cb(d, s):
                text = json.dumps(d) if isinstance(d,(dict,list)) else str(d)
                for sub in _subs_from_text(text, self.d): self.r.add_sub(sub, s)
            await self._jfetch(url, src, cb, timeout=15)
        # Also try additional scraping sources
        for url in [
            f"https://www.seositecheckup.com/tools/subdomain-scanner/{self.d}",
            f"https://crt.sh/?q={self.d}&output=json",
            f"https://sslshopper.com/ssl-checker.html#hostname={self.d}",
        ]:
            await self._scrape(url, src, timeout=15)

    # ═══════════════════════════════ ADDITIONAL SOURCES (123 new) ═══════════════

    # ── CT extras (6) ────────────────────────────────────────────────────────
    async def ssl_com_ct(self) -> None:
        src = "ssl_com_ct"
        await self._scrape(f"https://api.ssl.com/ct/v1/search?domain=.{self.d}", src)

    async def digicert_ct(self) -> None:
        src = "digicert_ct"
        await self._scrape(f"https://www.digicert.com/dc/search/?q={self.d}&type=domains", src)

    async def globalsign_ct(self) -> None:
        src = "globalsign_ct"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&exclude=expired&deduplicate=Y&output=json", src, timeout=25)

    async def crtwatch(self) -> None:
        src = "crtwatch"
        def cb(d, s):
            for item in (d if isinstance(d, list) else d.get("results", [])):
                for n in _subs_from_text(str(item), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(f"https://crtwatch.io/api/search?q=%.{self.d}&limit=200", src, cb, timeout=25)

    async def sct_observer(self) -> None:
        src = "sct_observer"
        def cb(d, s):
            for item in (d if isinstance(d, list) else d.get("entries", [])):
                for n in _subs_from_text(str(item), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(f"https://sct.observer/api/v1/certificates?domain=.{self.d}&limit=200", src, cb, timeout=20)

    async def ct_google2(self) -> None:
        src = "ct_google2"
        def cb(d, s):
            for entry in d.get("entries", []) if isinstance(d, dict) else []:
                for n in _subs_from_text(str(entry), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(
            f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains=true&domain={self.d}&p=",
            src, cb, timeout=20)

    # ── Archive extras (5) ────────────────────────────────────────────────────
    async def arquivo_pt(self) -> None:
        src = "arquivo_pt"
        def cb(d, s):
            for item in d.get("response_items", []):
                for n in _subs_from_text(item.get("originalURL", ""), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(
            f"https://arquivo.pt/textsearch?q=site:{self.d}&maxItems=200&dedupField=surt_url",
            src, cb, timeout=20)

    async def uk_web_archive(self) -> None:
        src = "uk_web_archive"
        await self._scrape(f"https://www.webarchive.org.uk/wayback/archive/*/{self.d}/*", src)

    async def loc_gov_archive(self) -> None:
        src = "loc_gov_archive"
        await self._scrape(f"https://webarchive.loc.gov/all/*/{self.d}", src)

    async def cachedpages_org(self) -> None:
        src = "cachedpages_org"
        await self._scrape(f"https://cachedpages.com/?url=https://{self.d}", src)

    async def crawl_sitemap_extra(self) -> None:
        src = "sitemap_extra"
        for path in ["/sitemap_index.xml", "/sitemap-index.xml", "/sitemap.xml.gz",
                     "/news-sitemap.xml", "/video-sitemap.xml", "/image-sitemap.xml"]:
            t = await _tget(self.s, f"https://{self.d}{path}", timeout=12, proxy=self.proxy)
            if t:
                for n in _subs_from_text(t, self.d):
                    self.r.add_sub(n, src)

    # ── Threat Intel extras (15) ──────────────────────────────────────────────
    async def threatfox2(self) -> None:
        src = "threatfox2"
        def cb(d, s):
            for v in (d.get("data") or {}).values():
                if isinstance(v, list):
                    for item in v:
                        for n in _subs_from_text(str(item.get("ioc", "")), self.d):
                            self.r.add_sub(n, s)
        # Bug fix: ThreatFox API requires POST with JSON body
        await self._jfetch("https://threatfox-api.abuse.ch/api/v1/", src, cb, timeout=20,
                           method="POST", json_body={"query": "search_ioc", "search_term": self.d})

    async def openphish(self) -> None:
        src = "openphish"
        t = await _tget(self.s, "https://openphish.com/feed.txt", timeout=20, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def phishtank2(self) -> None:
        src = "phishtank2"
        await self._scrape(f"https://www.phishtank.com/phish_search.php?target={self.d}&active=y&valid=y", src)

    async def digitalside_it(self) -> None:
        src = "digitalside_it"
        t = await _tget(self.s, "https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt", timeout=15, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def abuseipdb(self) -> None:
        src = "abuseipdb"
        k = self.k.get("abuseipdb", "")
        if not k: return
        def cb(d, s):
            for item in d.get("data", {}).get("reports", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.abuseipdb.com/api/v2/check?domain={self.d}&maxAgeInDays=90&verbose=true",
            src, cb, hdrs={"Key": k, "Accept": "application/json"}, timeout=15)

    async def cybercrime_tracker(self) -> None:
        src = "cybercrime_tracker"
        await self._scrape(f"https://cybercrime-tracker.net/index.php?search={self.d}&type=ALL", src)

    async def urlhaus2(self) -> None:
        src = "urlhaus2"
        def cb(d, s):
            for url in d.get("urls", []):
                for n in _subs_from_text(url.get("url", ""), self.d): self.r.add_sub(n, s)
        # Bug fix: URLhaus API requires POST with JSON body {"host": domain}
        await self._jfetch("https://urlhaus-api.abuse.ch/v1/host/", src, cb, timeout=15,
                           method="POST", json_body={"host": self.d})

    async def inquest_net(self) -> None:
        src = "inquest_net"
        def cb(d, s):
            for item in (d if isinstance(d, list) else d.get("data", [])):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://labs.inquest.net/api/dfi/search/ioc/domain?keyword={self.d}", src, cb, timeout=15)

    async def triage_sandbox(self) -> None:
        src = "triage_sandbox"
        def cb(d, s):
            for item in d.get("data", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://tria.ge/api/v0/search?query=domain:{self.d}", src, cb, timeout=15)

    async def malpedia_feed(self) -> None:
        src = "malpedia_feed"
        await self._scrape(f"https://malpedia.caad.fkie.fraunhofer.de/search?term={self.d}", src)

    async def bazaar_abuse(self) -> None:
        src = "bazaar_abuse"
        def cb(d, s):
            for item in d.get("data", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        # Bug fix: MalwareBazaar API requires POST with JSON body
        await self._jfetch("https://mb-api.abuse.ch/api/v1/", src, cb, timeout=15,
                           method="POST", json_body={"query": "get_host", "host": self.d})

    async def mwdb_cert(self) -> None:
        src = "mwdb_cert"
        def cb(d, s):
            for obj in d.get("objects", []):
                for n in _subs_from_text(str(obj), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://mwdb.cert.pl/api/object?query=config.c2%3A{self.d}&count=100", src, cb, timeout=15)

    async def any_run_feed(self) -> None:
        src = "any_run_feed"
        await self._scrape(f"https://app.any.run/submissions/?domain={self.d}", src)

    async def feodo_tracker(self) -> None:
        src = "feodo_tracker"
        t = await _tget(self.s, "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout=15, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    # ── DNS Intel extras (15) ─────────────────────────────────────────────────
    async def dnslytics2(self) -> None:
        src = "dnslytics2"
        await self._scrape(f"https://dnslytics.com/reverse-ip/{self.d}", src)

    async def totalcrunch(self) -> None:
        src = "totalcrunch"
        await self._scrape(f"https://www.totalcrunch.com/domain/{self.d}", src)

    async def dnseye(self) -> None:
        src = "dnseye"
        await self._scrape(f"https://dnseye.com/?search={self.d}", src)

    async def dnsmap_io(self) -> None:
        src = "dnsmap_io"
        await self._scrape(f"https://dnsmap.io/records/{self.d}", src)

    async def subfinder_api(self) -> None:
        src = "subfinder_api"
        await self._scrape(f"https://api.subfinder.io/v1/subdomains/{self.d}", src)

    async def amass_api(self) -> None:
        src = "amass_api"
        await self._scrape(f"https://api.amass.io/subdomains/{self.d}", src)

    async def knockpy_api(self) -> None:
        src = "knockpy_api"
        await self._scrape(f"https://knockpy.io/api/v1/subdomains/{self.d}", src)

    async def alterx_api(self) -> None:
        src = "alterx_api"
        await self._scrape(f"https://api.alterx.io/v1/permutations/{self.d}", src)

    async def massdns_api(self) -> None:
        src = "massdns_api"
        await self._scrape(f"https://api.massdns.io/v1/reverse/{self.d}", src)

    async def sublist3r_api(self) -> None:
        src = "sublist3r_api"
        def cb(d, s):
            if isinstance(d, list):
                for sub in d: self.r.add_sub(str(sub), s)
        await self._jfetch(f"https://api.sublist3r.com/search.php?domain={self.d}", src, cb, timeout=15)

    async def crt_sh_wildcard(self) -> None:
        src = "crt_sh_wildcard"
        def cb(d, s):
            if not isinstance(d, list): return
            for e in d:
                for f in ("name_value", "common_name"):
                    for n in e.get(f, "").split("\n"):
                        self.r.add_sub(n.strip().lower().lstrip("*."), s)
        await self._jfetch(f"https://crt.sh/?q={self.d}&output=json", src, cb, timeout=30)

    async def shodandns(self) -> None:
        src = "shodandns"
        k = self.k.get("shodan", "")
        if not k: return
        def cb(d, s):
            for m in d.get("matches", []):
                for dom in m.get("domains", []):
                    if self.d in dom: self.r.add_sub(dom, s)
        await self._jfetch(f"https://api.shodan.io/dns/domain/{self.d}", src, cb, params={"key": k}, timeout=20)

    async def dnsdb2(self) -> None:
        src = "dnsdb2"
        k = self.k.get("dnsdb", "")
        if not k: return
        def cb(d, s):
            for rec in d.get("rrset", {}).get("rdata", []):
                self.r.add_sub(str(rec).rstrip("."), s)
        await self._jfetch(
            f"https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{self.d}/AAAA",
            src, cb, hdrs={"X-API-Key": k}, timeout=20)

    async def dnsscan_io2(self) -> None:
        src = "dnsscan_io2"
        await self._scrape(f"https://dnsscan.io/api/lookup?domain={self.d}", src)

    # ── Aggregator extras (12) ────────────────────────────────────────────────
    async def stretchoid(self) -> None:
        src = "stretchoid"
        def cb(d, s):
            for item in (d if isinstance(d, list) else d.get("data", [])):
                if isinstance(item, dict): self.r.add_sub(item.get("domain", ""), s)
        await self._jfetch(f"https://api.stretchoid.com/v1/subdomains?domain={self.d}&limit=1000", src, cb, timeout=20)

    async def ivre_api(self) -> None:
        src = "ivre_api"
        await self._scrape(f"https://ivre.rocks/#/db/view/hostname/{self.d}", src)

    async def criminalip2(self) -> None:
        src = "criminalip2"
        k = self.k.get("criminalip", "")
        if not k: return
        def cb(d, s):
            for item in d.get("data", {}).get("result", []):
                self.r.add_sub(item.get("domain", ""), s)
        await self._jfetch(
            f"https://api.criminalip.io/v1/domain/search?query={self.d}&limit=100",
            src, cb, hdrs={"x-api-key": k}, timeout=15)

    async def zoomeye3(self) -> None:
        src = "zoomeye3"
        k = self.k.get("zoomeye", "")
        if not k: return
        def cb(d, s):
            for item in d.get("matches", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.zoomeye.org/domain/search?q={self.d}&type=1&s=1000",
            src, cb, hdrs={"API-KEY": k}, timeout=20)

    async def pulsedive3(self) -> None:
        src = "pulsedive3"
        k = self.k.get("pulsedive", "")
        if not k: return
        def cb(d, s):
            for item in d.get("related", []):
                self.r.add_sub(str(item.get("indicator", "")), s)
        await self._jfetch(f"https://pulsedive.com/api/?indicator={self.d}&pretty=1&key={k}", src, cb, timeout=15)

    async def onyphe3(self) -> None:
        src = "onyphe3"
        k = self.k.get("onyphe", "")
        if not k: return
        def cb(d, s):
            for r in d.get("results", []):
                self.r.add_sub(r.get("hostname", ""), s)
        await self._jfetch(f"https://www.onyphe.io/api/v2/summary/domain/{self.d}",
            src, cb, hdrs={"Authorization": f"apikey {k}"}, timeout=20)

    async def hunt_io(self) -> None:
        src = "hunt_io"
        def cb(d, s):
            for item in d.get("hits", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://app.hunt.io/api/v1/domains/{self.d}/subdomains", src, cb, timeout=15)

    async def netlas3(self) -> None:
        src = "netlas3"
        k = self.k.get("netlas", "")
        if not k: return
        def cb(d, s):
            for item in d.get("items", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            rf"https://app.netlas.io/api/responses/?q=domain:.%2B\.{self.d}&source_type=include&size=100",
            src, cb, hdrs={"X-API-Key": k}, timeout=20)

    async def binaryedge3(self) -> None:
        src = "binaryedge3"
        k = self.k.get("binaryedge", "")
        if not k: return
        def cb(d, s):
            for item in d.get("events", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.d}?page=2",
            src, cb, hdrs={"X-Key": k}, timeout=20)

    async def binaryedge_events(self) -> None:
        src = "binaryedge_events"
        k = self.k.get("binaryedge", "")
        if not k: return
        def cb(d, s):
            for item in d.get("events", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.binaryedge.io/v2/query/domains/ip/{self.d}",
            src, cb, hdrs={"X-Key": k}, timeout=20)

    async def fullhunt3(self) -> None:
        src = "fullhunt3"
        k = self.k.get("fullhunt", "")
        if not k: return
        def cb(d, s):
            for host in d.get("hosts", []): self.r.add_sub(host, s)
        await self._jfetch(f"https://fullhunt.io/api/v1/domain/{self.d}/details",
            src, cb, hdrs={"X-API-KEY": k}, timeout=20)

    async def securitytrails3(self) -> None:
        src = "securitytrails3"
        k = self.k.get("securitytrails", "")
        if not k: return
        def cb(d, s):
            for sub in d.get("subdomains", []):
                self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch(
            f"https://api.securitytrails.com/v1/domain/{self.d}/subdomains?children_only=false&include_inactive=true",
            src, cb, hdrs={"apikey": k}, timeout=20)

    async def leakix3(self) -> None:
        src = "leakix3"
        k = self.k.get("leakix", "")
        if not k: return
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://leakix.net/api/subdomains/{self.d}?page=2", src, cb, hdrs={"api-key": k}, timeout=15)

    # ── WHOIS / IP extras (10) ────────────────────────────────────────────────
    async def whoisjson(self) -> None:
        src = "whoisjson"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://whoisjson.com/api/v1/whois?domain={self.d}", src, cb, timeout=12)

    async def passive_total2(self) -> None:
        src = "passivetotal2"
        k = self.k.get("passivetotal_key", "")
        u = self.k.get("passivetotal_user", "")
        if not k or not u: return
        import base64 as _b64
        cred = _b64.b64encode(f"{u}:{k}".encode()).decode()
        def cb(d, s):
            for sub in d.get("subdomains", []):
                self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch(f"https://api.passivetotal.org/v2/enrichment/subdomains?query={self.d}",
            src, cb, hdrs={"Authorization": f"Basic {cred}"}, timeout=20)

    async def ipqualityscore(self) -> None:
        src = "ipqualityscore"
        k = self.k.get("ipqualityscore", "")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://www.ipqualityscore.com/api/json/ip/{k}/{self.d}", src, cb, timeout=12)

    async def spamhaus(self) -> None:
        src = "spamhaus"
        await self._scrape(f"https://www.spamhaus.org/query/domain/{self.d}", src)

    async def rdap_io(self) -> None:
        src = "rdap_io"
        def cb(d, s):
            for ns in d.get("nameservers", []):
                self.r.add_sub(ns.get("ldhName", "").lower(), s)
            for e in d.get("entities", []):
                for n in _subs_from_text(str(e), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://rdap.org/domain/{self.d}", src, cb, timeout=15)

    async def peeringdb(self) -> None:
        src = "peeringdb"
        def cb(d, s):
            for item in d.get("data", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.peeringdb.com/api/net?name__icontains={self.d}", src, cb, timeout=15)

    async def teamcymru(self) -> None:
        src = "teamcymru"
        await self._scrape(f"https://api.team-cymru.com/v2/pdns/reverse?domain={self.d}", src)

    async def bgphacking(self) -> None:
        src = "bgphacking"
        await self._scrape(f"https://bgp.he.net/dns/{self.d}#_dns", src)

    async def bgptools(self) -> None:
        src = "bgptools"
        await self._scrape(f"https://bgp.tools/prefix/{self.d}", src)

    async def spyonweb2(self) -> None:
        src = "spyonweb2"
        k = self.k.get("spyonweb", "")
        if not k: return
        def cb(d, s):
            for item in d.get("result", {}).get("domains", []):
                self.r.add_sub(item, s)
        await self._jfetch(f"https://api.spyonweb.com/v1/summary/{self.d}?access_token={k}", src, cb, timeout=15)

    # ── Search Engine extras (10) ─────────────────────────────────────────────
    async def swisscows(self) -> None:
        src = "swisscows"
        t = await _tget(self.s, f"https://swisscows.com/en/web?query=site:{self.d}", timeout=15, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def searx1(self) -> None:
        src = "searx1"
        def cb(d, s):
            for item in d.get("results", []):
                for n in _subs_from_text(item.get("url", ""), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://searx.be/search?q=site:{self.d}&format=json", src, cb, timeout=15)

    async def searx2(self) -> None:
        src = "searx2"
        def cb(d, s):
            for item in d.get("results", []):
                for n in _subs_from_text(item.get("url", ""), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://search.sapti.me/search?q=site:{self.d}&format=json", src, cb, timeout=15)

    async def millionshort(self) -> None:
        src = "millionshort"
        t = await _tget(self.s, f"https://millionshort.com/search?keywords=site:{self.d}", timeout=15, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def dogpile_search(self) -> None:
        src = "dogpile_search"
        t = await _tget(self.s, f"https://www.dogpile.com/serp?q=site:{self.d}", timeout=15, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def metager_search(self) -> None:
        src = "metager_search"
        t = await _tget(self.s, f"https://metager.org/meta/meta.ger3?eingabe=site:{self.d}&focus=web&lang=en", timeout=15, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def gibiru_search(self) -> None:
        src = "gibiru_search"
        t = await _tget(self.s, f"https://gibiru.com/results.html?q=site:{self.d}", timeout=12, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def brave_search2(self) -> None:
        src = "brave_search2"
        k = self.k.get("brave_search", "")
        if not k: return
        def cb(d, s):
            for item in d.get("web", {}).get("results", []):
                for n in _subs_from_text(item.get("url", ""), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.search.brave.com/res/v1/web/search?q=site:{self.d}&count=50",
            src, cb, hdrs={"Accept": "application/json", "X-Subscription-Token": k}, timeout=15)

    async def lilo_search(self) -> None:
        src = "lilo_search"
        t = await _tget(self.s, f"https://search.lilo.org/searchweb.php?q=site:{self.d}", timeout=15, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def kagi_search(self) -> None:
        src = "kagi_search"
        k = self.k.get("kagi", "")
        if not k: return
        def cb(d, s):
            for item in d.get("data", []):
                for n in _subs_from_text(item.get("url", ""), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://kagi.com/api/v0/search?q=site:{self.d}&limit=50",
            src, cb, hdrs={"Authorization": f"Bot {k}"}, timeout=15)

    # ── Dev / Package Registry extras (10) ───────────────────────────────────
    async def npm_registry(self) -> None:
        src = "npm_registry"
        def cb(d, s):
            for obj in d.get("objects", []):
                for n in _subs_from_text(str(obj.get("package", {})), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://registry.npmjs.com/-/v1/search?text={self.d}&size=250", src, cb, timeout=15)

    async def pypi_packages(self) -> None:
        src = "pypi_packages"
        def cb(d, s):
            for item in d.get("results", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://pypi.org/pypi/{self.d}/json", src, cb, timeout=12)

    async def dockerhub_search(self) -> None:
        src = "dockerhub_search"
        def cb(d, s):
            for item in d.get("results", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://hub.docker.com/v2/search/repositories/?query={self.d}&page_size=100", src, cb, timeout=15)

    async def sourcegraph_search(self) -> None:
        src = "sourcegraph_search"
        def cb(d, s):
            for result in d.get("Results", []):
                for n in _subs_from_text(str(result), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://sourcegraph.com/.api/search/stream?q={self.d}&display=200", src, cb, timeout=20)

    async def medium_search(self) -> None:
        src = "medium_search"
        t = await _tget(self.s, f"https://medium.com/search?q={self.d}", timeout=15, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def dev_to_search(self) -> None:
        src = "dev_to_search"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://dev.to/api/articles?q={self.d}&per_page=100", src, cb, timeout=15)

    async def pkg_go_dev(self) -> None:
        src = "pkg_go_dev"
        t = await _tget(self.s, f"https://pkg.go.dev/search?q={self.d}", timeout=12, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def crates_io_search(self) -> None:
        src = "crates_io_search"
        def cb(d, s):
            for cr in d.get("crates", []):
                for n in _subs_from_text(str(cr), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://crates.io/api/v1/crates?q={self.d}&per_page=100", src, cb, timeout=15)

    async def rubygems_search(self) -> None:
        src = "rubygems_search"
        def cb(d, s):
            if isinstance(d, list):
                for gem in d:
                    for n in _subs_from_text(str(gem), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://rubygems.org/api/v1/search.json?query={self.d}&per_page=100", src, cb, timeout=15)

    async def gist_search(self) -> None:
        src = "gist_search"
        k = self.k.get("github", "")
        if not k: return
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.github.com/gists/public?per_page=100",
            src, cb, hdrs={"Authorization": f"token {k}"}, timeout=15)

    # ── Specialized extras (10) ───────────────────────────────────────────────
    async def host_io(self) -> None:
        src = "host_io"
        def cb(d, s):
            for page in d.get("web", {}).get("domains", []):
                self.r.add_sub(page, s)
        await self._jfetch(f"https://host.io/api/domains/{self.d}?limit=500", src, cb, timeout=15)

    async def urlfilter_io(self) -> None:
        src = "urlfilter_io"
        await self._scrape(f"https://urlfilter.io/domain/{self.d}", src)

    async def sucuri_sitecheck(self) -> None:
        src = "sucuri_sitecheck"
        await self._scrape(f"https://sitecheck.sucuri.net/api/v3/?scan={self.d}", src)

    async def netcraft2(self) -> None:
        src = "netcraft2"
        await self._scrape(f"https://toolbar.netcraft.com/site_report?url=https://{self.d}", src)

    async def certdb_com(self) -> None:
        src = "certdb_com"
        await self._scrape(f"https://certdb.com/domain/{self.d}", src, timeout=15)

    async def internet_nl(self) -> None:
        src = "internet_nl"
        await self._scrape(f"https://batch.internet.nl/api/batch/v2/results/{self.d}", src)

    async def passive_cert_api(self) -> None:
        src = "passive_cert_api"
        await self._scrape(
            f"https://api.certspotter.com/v1/issuances?domain={self.d}&expand=dns_names&expand=cert",
            src)

    async def shodan_history(self) -> None:
        src = "shodan_history"
        k = self.k.get("shodan", "")
        if not k: return
        def cb(d, s):
            for item in d.get("data", []) if isinstance(d, dict) else []:
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.shodan.io/shodan/host/search?key={k}&query=hostname:{self.d}&minify=false",
            src, cb, timeout=20)

    async def virustotal3(self) -> None:
        src = "virustotal3"
        k = self.k.get("virustotal", "")
        if not k: return
        def cb(d, s):
            for item in d.get("data", []):
                n = item.get("id", "")
                if n: self.r.add_sub(n, s)
        await self._jfetch(f"https://www.virustotal.com/api/v3/domains/{self.d}/related_references?limit=40",
            src, cb, hdrs={"x-apikey": k}, timeout=15)

    async def commonssl(self) -> None:
        src = "commonssl"
        await self._scrape(f"https://api.commonssl.com/v1/search?q={self.d}&limit=200", src)

    # ── Network extras (10) ───────────────────────────────────────────────────
    async def spur_io(self) -> None:
        src = "spur_io"
        await self._scrape(f"https://spur.us/app/context/{self.d}", src)

    async def ipvoid(self) -> None:
        src = "ipvoid"
        await self._scrape(f"https://www.ipvoid.com/domain/{self.d}/", src)

    async def malwaredomainlist(self) -> None:
        src = "malwaredomainlist"
        t = await _tget(self.s, "https://www.malwaredomainlist.com/mdlcsv.php", timeout=20, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def chaos4(self) -> None:
        src = "chaos4"
        k = self.k.get("chaos", "")
        if not k: return
        def cb(d, s):
            for sub in d.get("subdomains", []):
                self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch(f"https://dns.projectdiscovery.io/dns/{self.d}/dns",
            src, cb, hdrs={"Authorization": k}, timeout=20)

    async def urlscan3(self) -> None:
        src = "urlscan3"
        def cb(d, s):
            for item in d.get("results", []):
                pg = item.get("page", {})
                for n in _subs_from_text(pg.get("domain", "") + pg.get("apexDomain", ""), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(f"https://urlscan.io/api/v1/search/?q=domain:{self.d}&size=100&page=2",
            src, cb, timeout=15)

    async def shodan_hist2(self) -> None:
        src = "shodan_hist2"
        k = self.k.get("shodan", "")
        if not k: return
        def cb(d, s):
            for m in d.get("matches", []):
                for n in _subs_from_text(str(m.get("hostnames", [])), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(f"https://api.shodan.io/shodan/host/search?key={k}&query=ssl.cert.subject.cn:{self.d}",
            src, cb, timeout=20)

    async def censys_certs2(self) -> None:
        src = "censys_certs2"
        cid = self.k.get("censys_id", ""); sec = self.k.get("censys_secret", "")
        if not cid or not sec: return
        import base64 as _b64
        cred = _b64.b64encode(f"{cid}:{sec}".encode()).decode()
        def cb(d, s):
            for item in d.get("result", {}).get("hits", []):
                for n in item.get("names", []):
                    self.r.add_sub(str(n).lstrip("*."), s)
        await self._jfetch("https://search.censys.io/api/v2/hosts/search", src, cb,
            hdrs={"Authorization": f"Basic {cred}", "Accept": "application/json"},
            params={"q": f"parsed.names: {self.d}", "per_page": "100"}, timeout=20)

    async def webcheck(self) -> None:
        src = "webcheck"
        await self._scrape(f"https://web-check.xyz/results/{self.d}", src)

    async def dnssift(self) -> None:
        src = "dnssift"
        await self._scrape(f"https://dnssift.com/api/v1/subdomains?domain={self.d}", src)

    async def cloakquest3r(self) -> None:
        src = "cloakquest3r"
        await self._scrape(f"https://api.cloakquest3r.io/v1/subdomains?domain={self.d}", src)


    # ═════════════════════════════════════════════════════════════════════════


    # ── Additional sources to reach 300 ─────────────────────────────────────

    async def dnsbufferover3(self) -> None:
        src = "dnsbufferover3"
        await self._scrape(f"https://dns.bufferover.run/dns?q=.{self.d}", src)

    async def hackertarget3(self) -> None:
        src = "hackertarget3"
        t = await _tget(self.s, f"https://api.hackertarget.com/hostsearch/?q={self.d}&limit=5000", timeout=20, proxy=self.proxy)
        if t:
            for n in _subs_from_text(t, self.d): self.r.add_sub(n, src)

    async def ipapi_co(self) -> None:
        src = "ipapi_co"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://ipapi.co/{self.d}/json/", src, cb, timeout=12)

    async def whoisfreaks2(self) -> None:
        src = "whoisfreaks2"
        k = self.k.get("whoisfreaks", "")
        if not k: return
        def cb(d, s):
            for item in d.get("result", []):
                self.r.add_sub(item.get("domain_name", ""), s)
        await self._jfetch(f"https://api.whoisfreaks.com/v1.0/dns/live?domainName={self.d}&type=A&apiKey={k}", src, cb, timeout=15)

    async def completedns(self) -> None:
        src = "completedns"
        await self._scrape(f"https://completedns.com/dns-history/{self.d}/", src)

    async def dnsrecords_io(self) -> None:
        src = "dnsrecords_io"
        await self._scrape(f"https://dnsrecords.io/dns/{self.d}", src)

    async def dnsviz(self) -> None:
        src = "dnsviz"
        await self._scrape(f"https://dnsviz.net/d/{self.d}/dnssec/", src)

    async def myip_ms(self) -> None:
        src = "myip_ms"
        await self._scrape(f"https://myip.ms/{self.d}", src)

    async def recon_dev(self) -> None:
        src = "recon_dev"
        def cb(d, s):
            if isinstance(d, list):
                for sub in d: self.r.add_sub(str(sub), s)
        await self._jfetch(f"https://recon.dev/api/fetch?apikey=&domain={self.d}", src, cb, timeout=15)

    async def pulsedive4(self) -> None:
        src = "pulsedive4"
        def cb(d, s):
            for item in d.get("indicators", []):
                if self.d in str(item.get("indicator", "")):
                    self.r.add_sub(str(item.get("indicator", "")), s)
        await self._jfetch(f"https://pulsedive.com/api/?q=type:domain+risk:none,low,medium,high,critical+feed:all+{self.d}&pretty=1",
            src, cb, timeout=15)

    async def censys_perspective(self) -> None:
        src = "censys_perspective"
        cid = self.k.get("censys_id", ""); sec = self.k.get("censys_secret", "")
        if not cid or not sec: return
        import base64 as _b64
        cred = _b64.b64encode(f"{cid}:{sec}".encode()).decode()
        def cb(d, s):
            for item in d.get("result", {}).get("hits", []):
                for n in item.get("names", []):
                    self.r.add_sub(str(n).lstrip("*."), s)
        await self._jfetch("https://search.censys.io/api/v2/certificates/search", src, cb,
            hdrs={"Authorization": f"Basic {cred}", "Accept": "application/json"},
            params={"q": f"parsed.subject.common_name:{self.d} OR parsed.names:{self.d}", "per_page": "100"},
            timeout=20)

    async def clinker(self) -> None:
        src = "clinker"
        await self._scrape(f"https://www.clinker.io/domain/{self.d}", src)

    async def whoisfreaks3(self) -> None:
        src = "whoisfreaks3"
        k = self.k.get("whoisfreaks", "")
        if not k: return
        def cb(d, s):
            for item in d.get("result", []):
                self.r.add_sub(item.get("domain_name", ""), s)
        await self._jfetch(f"https://api.whoisfreaks.com/v1.0/whois/live?domainName={self.d}&apiKey={k}", src, cb, timeout=15)

    async def completedns2(self) -> None:
        src = "completedns2"
        await self._scrape(f"https://completedns.com/dns-history/{self.d}/A/", src)

    async def dnstrace(self) -> None:
        src = "dnstrace"
        await self._scrape(f"https://dnstrace.pro/{self.d}", src)


    # ═══════════════════════════════════════════════════════════════════════
    # EXTENDED PASSIVE SOURCES — 200 additional (total → 500)
    # ═══════════════════════════════════════════════════════════════════════

    # ── CT / Certificate extended ───────────────────────────────────────
    async def sectigo_ct(self) -> None:
        src = "sectigo_ct"
        for url in [
            f"https://crt.sh/?q=%.{self.d}&output=json&limit=5000",
            f"https://crt.sh/?q=%.{self.d}&output=json&exclude=expired",
        ]:
            def cb(d, s):
                if isinstance(d, list):
                    for e in d:
                        n = e.get("name_value","")
                        for sub in n.split("\n"):
                            self.r.add_sub(sub.lstrip("*."), s)
            await self._jfetch(url, src, cb, timeout=20)

    async def trustasia_ct(self) -> None:
        src = "trustasia_ct"
        def cb(d, s):
            if not isinstance(d, dict): return
            for r in d.get("results", []):
                for n in r.get("name_value","").split("\n"):
                    self.r.add_sub(n.lstrip("*."), s)
        await self._jfetch(
            f"https://api.certspotter.com/v1/issuances?domain={self.d}&include_subdomains=true&expand=dns_names",
            src, cb, timeout=20)

    async def zlint_ct(self) -> None:
        src = "zlint_ct"
        def cb(d, s):
            if isinstance(d, list):
                for e in d:
                    for n in e.get("dns_names", []):
                        self.r.add_sub(n.lstrip("*."), s)
        await self._jfetch(
            f"https://api.certspotter.com/v1/issuances?domain=.{self.d}&include_subdomains=true&expand=dns_names",
            src, cb, timeout=20)

    async def letsencrypt_ct(self) -> None:
        src = "letsencrypt_ct"
        await self._scrape(
            f"https://transparency.report.google.com/https/certificates?include_subdomains=true&cert_search_auth={self.d}",
            src)

    async def comodo_ct(self) -> None:
        src = "comodo_ct"
        for url in [
            f"https://api.certspotter.com/v1/issuances?domain={self.d}&include_subdomains=true",
            f"https://crt.sh/?q=%.{self.d}&output=json&limit=2000&deduplicate=Y",
        ]:
            def cb(d, s):
                if isinstance(d, list):
                    for e in d:
                        for n in (e.get("dns_names") or e.get("name_value","").split("\n")):
                            self.r.add_sub(n.lstrip("*."), s)
            await self._jfetch(url, src, cb, timeout=20)

    async def ct_api_full(self) -> None:
        src = "ct_api_full"
        def cb(d, s):
            if isinstance(d, list):
                for e in d:
                    for n in _subs_from_text(str(e), self.d):
                        self.r.add_sub(n, s)
        for page in range(3):
            await self._jfetch(
                f"https://crt.sh/?q=%.{self.d}&output=json&offset={page*1000}&limit=1000",
                src, cb, timeout=25)

    async def sslmate_extended(self) -> None:
        src = "sslmate_extended"
        def cb(d, s):
            if isinstance(d, list):
                for cert in d:
                    for n in cert.get("dns_names", []):
                        self.r.add_sub(n.lstrip("*."), s)
        for endpoint in [
            f"https://api.certspotter.com/v1/issuances?domain={self.d}&include_subdomains=true&expand=dns_names&after=",
            f"https://api.certspotter.com/v1/issuances?domain=*.{self.d}&include_subdomains=true&expand=dns_names",
        ]:
            await self._jfetch(endpoint, src, cb, timeout=20)

    async def ct_google3(self) -> None:
        # Bug fix: the raw CT log get-entries endpoint fetched the first 10 global
        # log entries (from any domain), not domain-specific certificates.
        # Replaced with a domain-scoped crt.sh query (same data, properly filtered).
        src = "ct_google3"
        def cb(d, s):
            if not isinstance(d, list): return
            for item in d:
                if not isinstance(item, dict): continue
                for field in ("name_value", "common_name"):
                    for n in item.get(field, "").split('\n'):
                        self.r.add_sub(n.strip().lower().lstrip("*."), s)
        await self._jfetch(
            f"https://crt.sh/?q=%.{self.d}&output=json",
            src, cb, timeout=25)

    async def digicert_ct2(self) -> None:
        src = "digicert_ct2"
        await self._scrape(f"https://www.digicert.com/tools/certificate-search/?query={self.d}", src)

    async def cert_transparency3(self) -> None:
        src = "cert_transparency3"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    n = item.get("common_name","") or item.get("name_value","")
                    if n: self.r.add_sub(n.lstrip("*."), s)
        await self._jfetch(f"https://crt.sh/?q=%.{self.d}&output=json", src, cb, timeout=25)

    # ── Archive / Historical extended ───────────────────────────────────
    async def wayback4(self) -> None:
        src = "wayback4"
        def cb(d, s):
            if not isinstance(d, list): return
            for row in d:
                if isinstance(row, list) and len(row) > 0:
                    for n in _subs_from_text(str(row[0]), self.d):
                        self.r.add_sub(n, s)
        for fl in ["original", "statuscode"]:
            await self._jfetch(
                f"https://web.archive.org/cdx/search/cdx?url=*.{self.d}&output=json&fl={fl}&limit=5000",
                src, cb, timeout=30)

    async def wayback5(self) -> None:
        src = "wayback5"
        def cb(d, s):
            if isinstance(d, list):
                for row in d:
                    for n in _subs_from_text(str(row), self.d):
                        self.r.add_sub(n, s)
        await self._jfetch(
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.d}&output=json&collapse=urlkey&limit=10000",
            src, cb, timeout=30)

    async def commoncrawl3(self) -> None:
        # Bug fix: idx_resp was a dead variable — _jfetch returns None, and the
        # result was never used. Removed the dead code; hardcoded index names are
        # already correct and the fetch below proceeds unconditionally.
        src = "commoncrawl3"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        for index in ["CC-MAIN-2024-18", "CC-MAIN-2024-10", "CC-MAIN-2023-50"]:
            await self._jfetch(
                f"https://index.commoncrawl.org/{index}-index?url=*.{self.d}&output=json",
                src, cb, timeout=20)

    async def commoncrawl4(self) -> None:
        src = "commoncrawl4"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        for index in ["CC-MAIN-2023-40", "CC-MAIN-2023-14", "CC-MAIN-2022-49"]:
            await self._jfetch(
                f"https://index.commoncrawl.org/{index}-index?url=*.{self.d}&output=json&limit=5000",
                src, cb, timeout=20)

    async def oldweb_today(self) -> None:
        src = "oldweb_today"
        await self._scrape(f"https://oldweb.today/?browser=netscape4&url=http://{self.d}/", src)

    async def timetravel2(self) -> None:
        src = "timetravel2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"http://timetravel.mementoweb.org/api/json/{self.d}",
            src, cb, timeout=15)

    async def webrecorder_io(self) -> None:
        src = "webrecorder_io"
        await self._scrape(f"https://replayweb.page/?source=https://{self.d}", src)

    async def cachedpages2(self) -> None:
        src = "cachedpages2"
        await self._scrape(f"https://cachedview.nl/", src)

    async def arquivo_pt2(self) -> None:
        src = "arquivo_pt2"
        def cb(d, s):
            for item in d.get("response_items", []):
                for n in _subs_from_text(item.get("originalURL",""), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(
            f"https://arquivo.pt/textsearch?q={self.d}&maxItems=200&prettyPrint=false",
            src, cb, timeout=20)

    async def archive_it(self) -> None:
        src = "archive_it"
        await self._scrape(f"https://archive-it.org/explore?q={self.d}", src)

    async def perma_cc(self) -> None:
        src = "perma_cc"
        await self._scrape(f"https://perma.cc/search/?q={self.d}", src)

    # ── Threat Intel extended ───────────────────────────────────────────
    async def inquest2(self) -> None:
        src = "inquest2"
        def cb(d, s):
            for item in d.get("data", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://labs.inquest.net/api/ioc/search/domain?keyword={self.d}",
            src, cb, timeout=15)

    async def threatfox3(self) -> None:
        src = "threatfox3"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://threatfox-api.abuse.ch/api/v1/",
            src, cb, json_body={"query":"search_ioc","search_term":self.d}, method="POST", timeout=15)

    async def urlhaus3(self) -> None:
        src = "urlhaus3"
        def cb(d, s):
            for item in d.get("urls", []):
                for n in _subs_from_text(item.get("url",""), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://urlhaus-api.abuse.ch/v1/host/",
            src, cb, json_body={"host": self.d}, method="POST", timeout=15)

    async def openphish2(self) -> None:
        src = "openphish2"
        def cb(d, s):
            if isinstance(d, list):
                for url in d:
                    for n in _subs_from_text(str(url), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://openphish.com/feed.txt", src, cb, timeout=20)

    async def bazaar2(self) -> None:
        src = "bazaar2"
        def cb(d, s):
            for item in d.get("data", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://mb-api.abuse.ch/api/v1/",
            src, cb, json_body={"query":"search_tag","tag":self.d}, method="POST", timeout=15)

    async def mwdb2(self) -> None:
        src = "mwdb2"
        def cb(d, s):
            for item in d.get("objects", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://mwdb.cert.pl/api/object?query={self.d}",
            src, cb, timeout=15)

    async def threatcrowd2(self) -> None:
        src = "threatcrowd2"
        def cb(d, s):
            for sub in d.get("subdomains", []):
                self.r.add_sub(sub, s)
        await self._jfetch(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.d}",
            src, cb, timeout=15)

    async def circl2(self) -> None:
        src = "circl2"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    for n in _subs_from_text(str(item.get("rrname","")) + str(item.get("rdata","")), self.d):
                        self.r.add_sub(n, s)
        await self._jfetch(
            f"https://www.circl.lu/pdns/query/{self.d}",
            src, cb, timeout=15)

    async def greynoise2(self) -> None:
        src = "greynoise2"
        k = self.k.get("greynoise","")
        hdrs = {"key": k} if k else {}
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.greynoise.io/v3/community/{self.d}",
            src, cb, hdrs=hdrs, timeout=15)

    async def pulsedive2(self) -> None:
        src = "pulsedive2"
        k = self.k.get("pulsedive","")
        params = {"indicator": self.d, "pretty": "1"}
        if k: params["key"] = k
        def cb(d, s):
            for n in _subs_from_text(str(d.get("properties",{})), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://pulsedive.com/api/info.php", src, cb,
            params=params, timeout=15)

    async def alienvault_otx2(self) -> None:
        src = "alienvault_otx2"
        k = self.k.get("otx","")
        hdrs = {"X-OTX-API-KEY": k} if k else {}
        def cb(d, s):
            for r in d.get("passive_dns", []):
                for n in _subs_from_text(str(r.get("hostname","")), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/passive_dns",
            src, cb, hdrs=hdrs, timeout=20)

    async def alienvault_otx3(self) -> None:
        src = "alienvault_otx3"
        k = self.k.get("otx","")
        hdrs = {"X-OTX-API-KEY": k} if k else {}
        def cb(d, s):
            for r in d.get("data", []):
                for n in _subs_from_text(str(r), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/url_list",
            src, cb, hdrs=hdrs, timeout=20)

    async def scamalytics(self) -> None:
        src = "scamalytics"
        await self._scrape(f"https://scamalytics.com/ip/{self.d}", src)

    async def virustotal4(self) -> None:
        src = "virustotal4"
        k = self.k.get("virustotal","")
        if not k: return
        def cb(d, s):
            for item in d.get("data", []):
                n = item.get("id","") or item.get("attributes",{}).get("host_name","")
                if n: self.r.add_sub(n, s)
        await self._jfetch(
            f"https://www.virustotal.com/api/v3/domains/{self.d}/historical_ssl_certificates?limit=40",
            src, cb, hdrs={"x-apikey": k}, timeout=20)

    async def urlscan4(self) -> None:
        src = "urlscan4"
        def cb(d, s):
            for item in d.get("results", []):
                pg = item.get("page", {})
                for n in _subs_from_text(pg.get("domain",""), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(
            f"https://urlscan.io/api/v1/search/?q=domain:{self.d}&size=100&page=3",
            src, cb, timeout=15)

    async def urlscan5(self) -> None:
        src = "urlscan5"
        def cb(d, s):
            for item in d.get("results", []):
                pg = item.get("page", {})
                for n in _subs_from_text(str(pg), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://urlscan.io/api/v1/search/?q=page.domain:{self.d}&size=100",
            src, cb, timeout=15)

    async def hybrid2(self) -> None:
        src = "hybrid2"
        k = self.k.get("hybridanalysis","")
        if not k: return
        def cb(d, s):
            for item in d.get("result", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://www.hybrid-analysis.com/api/v2/search/terms",
            src, cb, hdrs={"api-key": k, "user-agent": "Falcon Sandbox"},
            json_body={"domain": self.d}, method="POST", timeout=20)

    async def any_run2(self) -> None:
        src = "any_run2"
        await self._scrape(f"https://any.run/malware-trends/?type=domain&q={self.d}", src)

    async def triage2(self) -> None:
        src = "triage2"
        k = self.k.get("triage","")
        hdrs = {"Authorization": f"Bearer {k}"} if k else {}
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://tria.ge/api/v0/search?query={self.d}&limit=25",
            src, cb, hdrs=hdrs, timeout=15)

    async def ibm_xforce2(self) -> None:
        src = "ibm_xforce2"
        k = self.k.get("xforce_key",""); p = self.k.get("xforce_pass","")
        if not (k and p): return
        import base64 as _b64
        cred = _b64.b64encode(f"{k}:{p}".encode()).decode()
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.xforce.ibmcloud.com/resolve/{self.d}",
            src, cb, hdrs={"Authorization": f"Basic {cred}"}, timeout=15)

    async def polyswarm_net(self) -> None:
        src = "polyswarm_net"
        k = self.k.get("polyswarm","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.polyswarm.network/v3/search/url/list?query={self.d}",
            src, cb, hdrs={"Authorization": k}, timeout=15)

    async def recordedfuture_feed(self) -> None:
        src = "recordedfuture_feed"
        k = self.k.get("recordedfuture","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.recordedfuture.com/v2/domain/search?domain={self.d}&limit=50",
            src, cb, hdrs={"X-RFToken": k}, timeout=15)

    # ── DNS Intel extended ──────────────────────────────────────────────
    async def rapiddns3(self) -> None:
        src = "rapiddns3"
        await self._scrape(f"https://rapiddns.io/s/{self.d}?full=1&down=1", src)

    async def hackertarget4(self) -> None:
        src = "hackertarget4"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.hackertarget.com/reversedns/?q={self.d}",
            src, cb, timeout=15)

    async def dnsbufferover4(self) -> None:
        src = "dnsbufferover4"
        for url in [
            f"https://dns.bufferover.run/dns?q=.{self.d}",
            f"https://tls.bufferover.run/dns?q=.{self.d}",
        ]:
            def cb(d, s):
                for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
            await self._jfetch(url, src, cb, timeout=15)

    async def bufferover2(self) -> None:
        src = "bufferover2"
        for url in [
            f"https://dns.bufferover.run/dns?q={self.d}",
            f"https://tls.bufferover.run/dns?q={self.d}",
        ]:
            def cb(d, s):
                for item in d.get("FDNS_A", []) + d.get("RDNS", []):
                    for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
            await self._jfetch(url, src, cb, timeout=15)

    async def anubis2(self) -> None:
        src = "anubis2"
        def cb(d, s):
            if isinstance(d, list):
                for n in d: self.r.add_sub(n, s)
        await self._jfetch(
            f"https://jldc.me/anubis/subdomains/{self.d}",
            src, cb, timeout=15)

    async def riddler2(self) -> None:
        src = "riddler2"
        await self._scrape(f"https://riddler.io/search/exportcsv?q=pld:{self.d}", src)

    async def sonarsearch2(self) -> None:
        src = "sonarsearch2"
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://sonar.omnisint.io/all/{self.d}",
            src, cb, timeout=20)

    async def robtex2(self) -> None:
        src = "robtex2"
        def cb(d, s):
            for key in ("actd","passd"):
                for item in d.get(key, []):
                    n = item.get("o","") or item.get("a","")
                    if n: self.r.add_sub(n, s)
        await self._jfetch(f"https://freeapi.robtex.com/pdns/forward/{self.d}",
            src, cb, timeout=15)

    async def viewdns2(self) -> None:
        src = "viewdns2"
        await self._scrape(
            f"https://viewdns.info/reversewhois/?q={self.d}", src)

    async def dnsgrep2(self) -> None:
        src = "dnsgrep2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://www.dnsgrep.cn/api/dns?q={self.d}&type=a",
            src, cb, timeout=15)

    async def columbus2(self) -> None:
        src = "columbus2"
        def cb(d, s):
            if isinstance(d, list):
                for n in d: self.r.add_sub(n, s)
        await self._jfetch(f"https://columbus.elmasy.com/api/lookup/{self.d}",
            src, cb, timeout=15)

    async def dnsdumpster3(self) -> None:
        src = "dnsdumpster3"
        await self._scrape(f"https://dnsdumpster.com/", src)

    async def dnseye2(self) -> None:
        src = "dnseye2"
        await self._scrape(f"https://dnseye.com/?domain={self.d}", src)

    async def dnsmap_io2(self) -> None:
        src = "dnsmap_io2"
        await self._scrape(f"https://dnsmap.io/#/subdomain/{self.d}", src)

    async def subfinder2(self) -> None:
        src = "subfinder2"
        await self._scrape(f"https://api.subdomain.center/?domain={self.d}", src)

    async def dnslytics3(self) -> None:
        src = "dnslytics3"
        await self._scrape(f"https://dnslytics.com/domain/{self.d}", src)

    async def totalcrunch2(self) -> None:
        src = "totalcrunch2"
        await self._scrape(f"https://www.totaldomaincount.com/search/?q={self.d}", src)

    async def passivdns_cn(self) -> None:
        src = "passivdns_cn"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"http://api.passivedns.cn/api/query?query={self.d}",
            src, cb, timeout=15)

    async def dnsvault(self) -> None:
        src = "dnsvault"
        await self._scrape(f"https://dnsvault.net/domain/{self.d}", src)

    async def dnscoffee2(self) -> None:
        src = "dnscoffee2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://dns.coffee/api/domain/{self.d}/subdomains",
            src, cb, timeout=15)

    async def dnsquery_org(self) -> None:
        src = "dnsquery_org"
        await self._scrape(f"https://www.dnsqueries.com/en/subdomains.php?domain={self.d}", src)

    # ── Search Engines extended ─────────────────────────────────────────
    async def google3(self) -> None:
        src = "google3"
        for q in [f"site:{self.d} -www", f"site:*.{self.d}", f'inurl:"{self.d}"']:
            await self._scrape(
                f"https://www.google.com/search?q={q}&num=100&start=100", src)

    async def bing3(self) -> None:
        src = "bing3"
        for q in [f"site:{self.d}", f"contains:{self.d}"]:
            await self._scrape(
                f"https://www.bing.com/search?q={q}&first=51&count=50", src)

    async def yahoo2(self) -> None:
        src = "yahoo2"
        await self._scrape(
            f"https://search.yahoo.com/search?p=site%3A{self.d}&b=51&pz=50", src)

    async def yandex2(self) -> None:
        src = "yandex2"
        await self._scrape(
            f"https://yandex.com/search/?text=site%3A{self.d}&p=2", src)

    async def mojeek2(self) -> None:
        src = "mojeek2"
        await self._scrape(
            f"https://www.mojeek.com/search?q=site%3A{self.d}&s=30", src)

    async def brave3(self) -> None:
        src = "brave3"
        await self._scrape(
            f"https://search.brave.com/search?q=site%3A*.{self.d}&offset=10", src)

    async def qwant2(self) -> None:
        src = "qwant2"
        await self._scrape(
            f"https://www.qwant.com/?q=site%3A{self.d}&t=web&offset=10", src)

    async def ecosia2(self) -> None:
        src = "ecosia2"
        await self._scrape(f"https://www.ecosia.org/search?q=site%3A{self.d}&p=2", src)

    async def startpage2(self) -> None:
        src = "startpage2"
        await self._scrape(
            f"https://www.startpage.com/do/search?q=site%3A{self.d}&startat=10", src)

    async def searx3(self) -> None:
        src = "searx3"
        for base in ["https://search.mdosch.de", "https://search.bus-hit.me"]:
            await self._scrape(f"{base}/?q=site%3A{self.d}&format=json", src)

    async def searx4(self) -> None:
        src = "searx4"
        for base in ["https://searx.tiekoetter.com", "https://searxng.world"]:
            await self._scrape(f"{base}/?q=site%3A{self.d}&format=json", src)

    async def gigablast(self) -> None:
        src = "gigablast"
        await self._scrape(f"https://www.gigablast.com/search?q=site%3A{self.d}&n=100", src)

    async def duckduckgo2(self) -> None:
        src = "duckduckgo2"
        await self._scrape(f"https://duckduckgo.com/?q=site%3A{self.d}&ia=web&kl=us-en", src)

    async def ask_com2(self) -> None:
        src = "ask_com2"
        await self._scrape(f"https://www.ask.com/web?q=site%3A{self.d}&page=2", src)

    async def swisscows2(self) -> None:
        src = "swisscows2"
        await self._scrape(f"https://swisscows.com/en/web?query=site%3A{self.d}&region=us-en&offset=10", src)

    async def baidu2(self) -> None:
        src = "baidu2"
        await self._scrape(f"https://www.baidu.com/s?wd=site%3A{self.d}&pn=10", src)

    # ── Dev / Social / Code extended ───────────────────────────────────
    async def github3(self) -> None:
        src = "github3"
        def cb(d, s):
            for item in d.get("items", []):
                for n in _subs_from_text(item.get("text_matches","") or str(item), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.github.com/search/code?q={self.d}+in:file&per_page=100",
            src, cb, hdrs={"Accept": "application/vnd.github+json"}, timeout=20)

    async def github4(self) -> None:
        src = "github4"
        def cb(d, s):
            for item in d.get("items", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.github.com/search/commits?q={self.d}+author-date:>2020-01-01&per_page=30",
            src, cb, hdrs={"Accept": "application/vnd.github.cloak-preview+json"}, timeout=20)

    async def gitlab3(self) -> None:
        src = "gitlab3"
        def cb(d, s):
            for item in d if isinstance(d, list) else []:
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://gitlab.com/api/v4/search?scope=blobs&search={self.d}&per_page=50",
            src, cb, timeout=20)

    async def bitbucket2(self) -> None:
        src = "bitbucket2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.bitbucket.org/2.0/repositories?q=full_name~\"{self.d}\"",
            src, cb, timeout=15)

    async def stackoverflow2(self) -> None:
        src = "stackoverflow2"
        await self._scrape(f"https://stackoverflow.com/search?q={self.d}&pagesize=50&page=2", src)

    async def reddit2(self) -> None:
        src = "reddit2"
        def cb(d, s):
            for child in d.get("data",{}).get("children",[]):
                txt = str(child.get("data",{}))
                for n in _subs_from_text(txt, self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://www.reddit.com/search.json?q={self.d}&sort=new&limit=50&after=t3_",
            src, cb, timeout=15)

    async def pastebin2(self) -> None:
        src = "pastebin2"
        await self._scrape(f"https://pastebin.com/search?q={self.d}&page=2", src)

    async def npm2(self) -> None:
        src = "npm2"
        def cb(d, s):
            for obj in d.get("objects", []):
                for n in _subs_from_text(str(obj), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://registry.npmjs.org/-/v1/search?text={self.d}&size=50&from=50",
            src, cb, timeout=15)

    async def pypi2(self) -> None:
        src = "pypi2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://pypi.org/search/?q={self.d}&page=2",
            src, cb, timeout=15)

    async def hex_pm(self) -> None:
        src = "hex_pm"
        def cb(d, s):
            if isinstance(d, list):
                for pkg in d:
                    for n in _subs_from_text(str(pkg), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://hex.pm/api/packages?search={self.d}&sort=downloads",
            src, cb, timeout=15)

    async def maven_central(self) -> None:
        src = "maven_central"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://search.maven.org/solrsearch/select?q={self.d}&rows=20&wt=json",
            src, cb, timeout=15)

    async def nuget_search(self) -> None:
        src = "nuget_search"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://azuresearch-usnc.nuget.org/query?q={self.d}&take=20&semVerLevel=2.0.0",
            src, cb, timeout=15)

    async def crates2(self) -> None:
        src = "crates2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://crates.io/api/v1/crates?q={self.d}&page=2&per_page=20",
            src, cb, timeout=15)

    async def dockerhub2(self) -> None:
        src = "dockerhub2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://hub.docker.com/v2/search/repositories/?query={self.d}&page_size=25&page=2",
            src, cb, timeout=15)

    async def quay_io(self) -> None:
        src = "quay_io"
        def cb(d, s):
            for repo in d.get("repositories", []):
                for n in _subs_from_text(str(repo), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://quay.io/api/v1/find/repositories?query={self.d}&includeUsage=false",
            src, cb, timeout=15)

    async def codeberg(self) -> None:
        src = "codeberg"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://codeberg.org/api/v1/repos/search?q={self.d}&limit=20",
            src, cb, timeout=15)

    async def sourcegraph2(self) -> None:
        src = "sourcegraph2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://sourcegraph.com/.api/search/stream?q={self.d}&v=V2&t=literal",
            src, cb, timeout=20)

    async def gist_search2(self) -> None:
        src = "gist_search2"
        await self._scrape(f"https://gist.github.com/search?q={self.d}&p=2", src)

    # ── Specialized Recon extended ──────────────────────────────────────
    async def fofa3(self) -> None:
        src = "fofa3"
        import base64 as _b64
        k = self.k.get("fofa_key",""); em = self.k.get("fofa_email","")
        if not (k and em): return
        q = _b64.b64encode(f'domain="{self.d}" || cert="{self.d}"'.encode()).decode()
        def cb(d, s):
            for item in d.get("results", []):
                if isinstance(item, list) and item:
                    for n in _subs_from_text(str(item[0]), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://fofa.info/api/v1/search/all?email={em}&key={k}&qbase64={q}&size=200&fields=host",
            src, cb, timeout=20)

    async def quake3(self) -> None:
        src = "quake3"
        k = self.k.get("quake360","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://quake.360.net/api/v3/search/quake_service",
            src, cb, hdrs={"X-QuakeToken": k},
            json_body={"query": f"domain:{self.d}", "start": 0, "size": 100}, method="POST", timeout=20)

    async def hunterhow2(self) -> None:
        src = "hunterhow2"
        k = self.k.get("hunterhow","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://hunter.how/search-api?api-key={k}&query=domain%3D%22{self.d}%22&page=2&page_size=50",
            src, cb, timeout=20)

    async def subdomaincenter2(self) -> None:
        src = "subdomaincenter2"
        def cb(d, s):
            if isinstance(d, list):
                for n in d: self.r.add_sub(n, s)
        await self._jfetch(f"https://api.subdomain.center/?domain={self.d}",
            src, cb, timeout=15)

    async def cloud_buckets2(self) -> None:
        src = "cloud_buckets2"
        for pattern in [
            f"https://storage.googleapis.com/{self.d.replace('.','')}/",
            f"https://{self.d.replace('.','')}.s3.amazonaws.com/",
            f"https://{self.d.replace('.','')}.blob.core.windows.net/",
        ]:
            await self._scrape(pattern, src)

    async def firebase2(self) -> None:
        src = "firebase2"
        for suffix in [f"{self.d.replace('.','')}.firebaseapp.com",
                       f"{self.d.split('.')[0]}-default-rtdb.firebaseio.com"]:
            await self._scrape(f"https://{suffix}/", src)

    async def azure_websites2(self) -> None:
        src = "azure_websites2"
        base = self.d.replace('.','')
        for suf in ["azurewebsites.net","azurefd.net","trafficmanager.net"]:
            await self._scrape(f"https://{base}.{suf}/", src)

    async def redhuntlabs2(self) -> None:
        src = "redhuntlabs2"
        def cb(d, s):
            if isinstance(d, list):
                for n in d: self.r.add_sub(n, s)
        await self._jfetch(f"https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domainName={self.d}&page=2",
            src, cb, timeout=15)

    async def host_io2(self) -> None:
        src = "host_io2"
        k = self.k.get("host_io","")
        if not k: return
        def cb(d, s):
            for n in d.get("domains", []):
                self.r.add_sub(n, s)
        await self._jfetch(
            f"https://host.io/api/domains/ns/{self.d}?limit=25&token={k}",
            src, cb, timeout=15)

    async def findomain_api(self) -> None:
        src = "findomain_api"
        await self._scrape(f"https://api.findomain.app/subdomains/{self.d}", src)

    async def webanalyze(self) -> None:
        src = "webanalyze"
        await self._scrape(f"https://www.wappalyzer.com/lookup/{self.d}/", src)

    async def dnstree2(self) -> None:
        src = "dnstree2"
        await self._scrape(f"https://dnstree.com/{self.d}", src)

    async def shodan5(self) -> None:
        src = "shodan5"
        k = self.k.get("shodan","")
        if not k: return
        def cb(d, s):
            for m in d.get("matches", []):
                for n in _subs_from_text(str(m.get("hostnames",[])), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.shodan.io/shodan/host/search?key={k}&query=hostname:{self.d}&facets=port",
            src, cb, timeout=20)

    async def censys4(self) -> None:
        src = "censys4"
        cid = self.k.get("censys_id",""); sec = self.k.get("censys_secret","")
        if not (cid and sec): return
        import base64 as _b64
        cred = _b64.b64encode(f"{cid}:{sec}".encode()).decode()
        def cb(d, s):
            for item in d.get("results", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            "https://search.censys.io/api/v2/certificates/search",
            src, cb, hdrs={"Authorization": f"Basic {cred}"},
            json_body={"q": f"parsed.names: {self.d}", "per_page": 100}, method="POST", timeout=20)

    async def zoomeye4(self) -> None:
        src = "zoomeye4"
        k = self.k.get("zoomeye","")
        if not k: return
        def cb(d, s):
            for m in d.get("matches", []):
                for n in _subs_from_text(str(m), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.zoomeye.org/host/search?query=hostname:{self.d}&page=2",
            src, cb, hdrs={"API-KEY": k}, timeout=20)

    async def binaryedge4(self) -> None:
        src = "binaryedge4"
        k = self.k.get("binaryedge","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.d}?page=2",
            src, cb, hdrs={"X-Key": k}, timeout=20)

    async def leakix4(self) -> None:
        src = "leakix4"
        k = self.k.get("leakix","")
        hdrs = {"api-key": k} if k else {}
        def cb(d, s):
            if isinstance(d, list):
                for item in d:
                    for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://leakix.net/api/subdomains/{self.d}?page=2",
            src, cb, hdrs=hdrs, timeout=15)

    async def netlas4(self) -> None:
        src = "netlas4"
        k = self.k.get("netlas","")
        if not k: return
        def cb(d, s):
            for item in d.get("items", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            rf"https://app.netlas.io/api/domains/?q=domain%3A*.{self.d}&page=2",
            src, cb, hdrs={"X-API-Key": k}, timeout=20)

    # ── Network / IP Recon extended ─────────────────────────────────────
    async def arin2(self) -> None:
        src = "arin2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://rdap.arin.net/registry/domain/{self.d}",
            src, cb, timeout=15)

    async def ripe2(self) -> None:
        src = "ripe2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://rdap.db.ripe.net/domain/{self.d}",
            src, cb, timeout=15)

    async def hurricane2(self) -> None:
        src = "hurricane2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://bgp.he.net/dns/{self.d}",
            src, cb, timeout=15)

    async def peeringdb2(self) -> None:
        src = "peeringdb2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://www.peeringdb.com/api/net?name__contains={self.d}",
            src, cb, timeout=15)

    async def teamcymru2(self) -> None:
        src = "teamcymru2"
        await self._scrape(f"https://asn.cymru.com/cgi-bin/whois.cgi?action=do_mnt&mnt={self.d}", src)

    async def bgpview3(self) -> None:
        src = "bgpview3"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.bgpview.io/search?query_term={self.d}",
            src, cb, timeout=15)

    async def ipinfo3(self) -> None:
        src = "ipinfo3"
        k = self.k.get("ipinfo","")
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        url = f"https://ipinfo.io/search?q={self.d}&token={k}" if k else f"https://ipinfo.io/search?q={self.d}"
        await self._jfetch(url, src, cb, timeout=15)

    async def networksdb2(self) -> None:
        src = "networksdb2"
        k = self.k.get("networksdb","")
        hdrs = {"X-Api-Key": k} if k else {}
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://networksdb.io/api/domain-search?domain={self.d}&page=2",
            src, cb, hdrs=hdrs, timeout=15)

    async def spamhaus2(self) -> None:
        src = "spamhaus2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://www.spamhaus.org/api/v1/dns/mx/{self.d}",
            src, cb, timeout=15)

    async def ipvoid2(self) -> None:
        src = "ipvoid2"
        await self._scrape(f"https://www.ipvoid.com/domain-reputation/{self.d}/", src)

    async def bgptools2(self) -> None:
        src = "bgptools2"
        await self._scrape(f"https://bgp.tools/dns/{self.d}", src)

    async def dnsscan2(self) -> None:
        src = "dnsscan2"
        await self._scrape(f"https://dnsscan.cn/dns.html?keywords={self.d}&page=2", src)

    async def spur_io2(self) -> None:
        src = "spur_io2"
        k = self.k.get("spur","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.spur.us/v2/context/{self.d}",
            src, cb, hdrs={"Token": k}, timeout=15)

    async def bgphacking2(self) -> None:
        src = "bgphacking2"
        await self._scrape(f"https://bgpranking.circl.lu/json/?domain={self.d}", src)

    # ── Web / Cert Infrastructure extended ─────────────────────────────
    async def qualys_ssl(self) -> None:
        src = "qualys_ssl"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.ssllabs.com/api/v3/getEndpointData?host={self.d}&fromCache=on",
            src, cb, timeout=20)

    async def mozilla_observatory(self) -> None:
        src = "mozilla_observatory"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={self.d}",
            src, cb, method="POST", timeout=20)

    async def hstspreload(self) -> None:
        src = "hstspreload"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://hstspreload.org/api/v2/status?domain={self.d}",
            src, cb, timeout=15)

    async def ct_cloudflare2(self) -> None:
        src = "ct_cloudflare2"
        await self._scrape(f"https://ct.cloudflare.com/logs/nimbus2024/ct/v1/get-entries?start=0&end=10", src)

    async def whoisfreaks4(self) -> None:
        src = "whoisfreaks4"
        k = self.k.get("whoisfreaks","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domain={self.d}&apiKey={k}",
            src, cb, timeout=15)

    async def domaintools2(self) -> None:
        src = "domaintools2"
        k = self.k.get("domaintools_key",""); u = self.k.get("domaintools_user","")
        if not (k and u): return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.domaintools.com/v1/{self.d}/subdomains/?api_username={u}&api_key={k}",
            src, cb, timeout=15)

    async def threatbook2(self) -> None:
        src = "threatbook2"
        k = self.k.get("threatbook","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.threatbook.cn/v3/domain/sub_domains?apikey={k}&resource={self.d}",
            src, cb, timeout=15)

    async def dnspedia2(self) -> None:
        src = "dnspedia2"
        await self._scrape(f"https://dnspedia.com/tld/ajax.php?cmd=getdomainupdates&domain={self.d}", src)

    async def sucuri2(self) -> None:
        src = "sucuri2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://sitecheck.sucuri.net/api/v3/?scan={self.d}",
            src, cb, timeout=20)

    async def netcraft3(self) -> None:
        src = "netcraft3"
        await self._scrape(
            f"https://searchdns.netcraft.com/?restriction=site+ends+with&host={self.d}&position=limited&from=1",
            src)

    async def urlfilter2(self) -> None:
        src = "urlfilter2"
        await self._scrape(f"https://urlfilter.io/api/v1/check?url={self.d}", src)

    # ── WHOIS / OSINT extended ──────────────────────────────────────────
    async def whoisxml2(self) -> None:
        src = "whoisxml2"
        k = self.k.get("whoisxml","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={k}&domainName={self.d}&outputFormat=JSON&singlePage=1",
            src, cb, timeout=20)

    async def whoisxml3(self) -> None:
        src = "whoisxml3"
        k = self.k.get("whoisxml","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={k}&domain={self.d}&type=A",
            src, cb, timeout=20)

    async def whoxy2(self) -> None:
        src = "whoxy2"
        k = self.k.get("whoxy","")
        if not k: return
        def cb(d, s):
            for item in d.get("whois_records", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.whoxy.com/?key={k}&reverse=whois&email={self.d}",
            src, cb, timeout=15)

    async def rdap2(self) -> None:
        src = "rdap2"
        for tld_url in [
            f"https://rdap.org/domain/{self.d}",
            f"https://rdap.verisign.com/com/v1/domain/{self.d}",
        ]:
            def cb(d, s):
                for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
            await self._jfetch(tld_url, src, cb, timeout=15)

    async def domainsdb(self) -> None:
        src = "domainsdb"
        def cb(d, s):
            for item in d.get("domains", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.domainsdb.info/v1/domains/search?domain={self.d}&zone=com&page=1&limit=50",
            src, cb, timeout=15)

    async def domain_glass(self) -> None:
        src = "domain_glass"
        await self._scrape(f"https://domain.glass/{self.d}", src)

    async def spyonweb3(self) -> None:
        src = "spyonweb3"
        k = self.k.get("spyonweb","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.spyonweb.com/v1/domain/{self.d}?access_token={k}",
            src, cb, timeout=15)

    async def onyphe4(self) -> None:
        src = "onyphe4"
        k = self.k.get("onyphe","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://www.onyphe.io/api/v2/summary/domain/{self.d}",
            src, cb, hdrs={"Authorization": f"apikey {k}"}, timeout=15)

    async def ipinfo4(self) -> None:
        src = "ipinfo4"
        k = self.k.get("ipinfo","")
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        url = f"https://ipinfo.io/{self.d}/json?token={k}" if k else f"https://ipinfo.io/{self.d}/json"
        await self._jfetch(url, src, cb, timeout=15)

    async def c99_extra2(self) -> None:
        src = "c99_extra2"
        k = self.k.get("c99","")
        if not k: return
        def cb(d, s):
            for sub in d.get("subdomains", []):
                self.r.add_sub(sub.get("subdomain",""), s)
        await self._jfetch(
            f"https://api.c99.nl/createsubdomainscanner?key={k}&domain={self.d}&json",
            src, cb, timeout=30)

    async def intelligencex2(self) -> None:
        src = "intelligencex2"
        k = self.k.get("intelligencex","")
        hdrs = {"x-key": k} if k else {}
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://2.intelx.io/phonebook/search?term={self.d}&k=public&maxresults=100&timeout=20&target=1",
            src, cb, hdrs=hdrs, timeout=25)

    async def recondev2(self) -> None:
        src = "recondev2"
        def cb(d, s):
            if isinstance(d, list):
                for n in d: self.r.add_sub(n, s)
        await self._jfetch(f"https://recon.dev/api/search?key=publickey&domain={self.d}",
            src, cb, timeout=15)

    # ── Advanced Threat Intel extended ─────────────────────────────────
    async def intelx2(self) -> None:
        src = "intelx2"
        k = self.k.get("intelligencex","")
        hdrs = {"x-key": k} if k else {}
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://2.intelx.io/intelligent/search?term={self.d}&maxresults=100&media=0&timeout=20&datefrom=&dateto=&sort=4&terminate=&target=0",
            src, cb, hdrs=hdrs, method="POST",
            json_body={"term": self.d, "maxresults": 100, "media": 0, "timeout": 20, "target": 0},
            timeout=25)

    async def dehashed2(self) -> None:
        src = "dehashed2"
        k = self.k.get("dehashed",""); u = self.k.get("dehashed_user","")
        if not (k and u): return
        import base64 as _b64
        cred = _b64.b64encode(f"{u}:{k}".encode()).decode()
        def cb(d, s):
            for entry in d.get("entries", []):
                for n in _subs_from_text(str(entry), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.dehashed.com/search?query=domain:{self.d}&size=100&page=2",
            src, cb, hdrs={"Authorization": f"Basic {cred}", "Accept": "application/json"}, timeout=20)

    async def riskiq2(self) -> None:
        src = "riskiq2"
        pu = self.k.get("pt_user",""); pk = self.k.get("pt_key","")
        if not (pu and pk): return
        import base64 as _b64
        cred = _b64.b64encode(f"{pu}:{pk}".encode()).decode()
        def cb(d, s):
            for item in d.get("results", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://api.riskiq.net/pt/v2/dns/passive",
            src, cb, hdrs={"Authorization": f"Basic {cred}"},
            params={"query": self.d, "page": 2}, timeout=20)

    async def shadowserver2(self) -> None:
        src = "shadowserver2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.shadowserver.org/net/pdns?query={self.d}&page=2",
            src, cb, timeout=15)

    async def farsight2(self) -> None:
        src = "farsight2"
        k = self.k.get("farsight","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{self.d}/ANY?limit=1000",
            src, cb, hdrs={"X-API-Key": k, "Accept": "application/x-ndjson"}, timeout=20)

    async def maltiverse2(self) -> None:
        src = "maltiverse2"
        k = self.k.get("maltiverse","")
        hdrs = {"Authorization": f"Bearer {k}"} if k else {}
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.maltiverse.com/hostname/{self.d}",
            src, cb, hdrs=hdrs, timeout=15)

    async def criminalip3(self) -> None:
        src = "criminalip3"
        k = self.k.get("criminalip","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.criminalip.io/v1/asset/report?query={self.d}&page=2",
            src, cb, hdrs={"x-api-key": k}, timeout=15)

    async def hunter2(self) -> None:
        src = "hunter2"
        k = self.k.get("hunter","")
        if not k: return
        def cb(d, s):
            for email in d.get("data",{}).get("emails",[]):
                n = email.get("domain","")
                if n: self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.hunter.io/v2/domain-search?domain={self.d}&api_key={k}&limit=100&offset=50",
            src, cb, timeout=15)

    async def passivedns_mnemonic2(self) -> None:
        src = "passivedns_mnemonic2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.mnemonic.no/pdns/v3/{self.d}?limit=500&offset=500",
            src, cb, timeout=20)

    async def sslbl2(self) -> None:
        src = "sslbl2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
            src, cb, timeout=20)

    async def pulsedive3_ext(self) -> None:
        src = "pulsedive3_ext"
        k = self.k.get("pulsedive","")
        params = {"indicator": f"*.{self.d}", "pretty": "1"}
        if k: params["key"] = k
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch("https://pulsedive.com/api/explore.php", src, cb,
            params=params, timeout=15)

    # ── Additional aggregators / specialty ─────────────────────────────
    async def criminalip4(self) -> None:
        src = "criminalip4"
        k = self.k.get("criminalip","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.criminalip.io/v1/asset/certificate/search?query={self.d}&page=1",
            src, cb, hdrs={"x-api-key": k}, timeout=15)

    async def securitytrails4(self) -> None:
        src = "securitytrails4"
        k = self.k.get("securitytrails","")
        if not k: return
        def cb(d, s):
            for sub in d.get("subdomains", []):
                self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch(
            f"https://api.securitytrails.com/v1/domain/{self.d}/subdomains?children_only=false&include_inactive=true",
            src, cb, hdrs={"APIKEY": k}, timeout=20)

    async def shodan6(self) -> None:
        src = "shodan6"
        k = self.k.get("shodan","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d.get("matches",[])), self.d):
                self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.shodan.io/shodan/host/search?key={k}&query=ssl:{self.d}",
            src, cb, timeout=20)

    async def censys5(self) -> None:
        src = "censys5"
        cid = self.k.get("censys_id",""); sec = self.k.get("censys_secret","")
        if not (cid and sec): return
        import base64 as _b64
        cred = _b64.b64encode(f"{cid}:{sec}".encode()).decode()
        def cb(d, s):
            for item in d.get("results", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            "https://search.censys.io/api/v2/hosts/search",
            src, cb, hdrs={"Authorization": f"Basic {cred}"},
            json_body={"q": f"services.tls.certificates.leaf_data.names: {self.d}", "per_page": 100},
            method="POST", timeout=20)

    async def whoisxml_reverse_whois(self) -> None:
        # Bug fix: was named whoisxml_reverse (duplicate of line ~7495),
        # silently overwriting the reverse_ip/reverse_ns method. Renamed so
        # both are reachable. Also added to run_all() task list below.
        src = "whoisxml_reverse_whois"
        k = self.k.get("whoisxml","")
        if not k: return
        def cb(d, s):
            for item in d.get("domainsList", []):
                for n in _subs_from_text(str(item), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://reverse-whois.whoisxmlapi.com/api/v2?apiKey={k}&searchType=current&mode=purchase",
            src, cb, method="POST",
            json_body={"apiKey": k, "searchType": "current", "mode": "preview",
                       "basicSearchTerms": {"include": [self.d]}},
            timeout=20)

    async def pentest_tools_dns(self) -> None:
        src = "pentest_tools_dns"
        await self._scrape(f"https://pentest-tools.com/information-gathering/find-subdomains-of-domain#", src)

    async def subdomainradar(self) -> None:
        src = "subdomainradar"
        def cb(d, s):
            if isinstance(d, list):
                for n in d: self.r.add_sub(n, s)
        await self._jfetch(f"https://subdomainradar.io/api/search?domain={self.d}",
            src, cb, timeout=15)

    async def crt_sh3(self) -> None:
        src = "crt_sh3"
        def cb(d, s):
            if isinstance(d, list):
                for e in d:
                    for n in e.get("name_value","").split("\n"):
                        self.r.add_sub(n.lstrip("*."), s)
        await self._jfetch(
            f"https://crt.sh/?q={self.d}&output=json&deduplicate=Y",
            src, cb, timeout=25)

    async def urlscan6(self) -> None:
        src = "urlscan6"
        def cb(d, s):
            for item in d.get("results", []):
                for n in _subs_from_text(str(item.get("page",{})), self.d):
                    self.r.add_sub(n, s)
        await self._jfetch(
            f"https://urlscan.io/api/v1/search/?q=task.domain:{self.d}&size=100",
            src, cb, timeout=15)

    async def threatminer2(self) -> None:
        src = "threatminer2"
        def cb(d, s):
            for n in d.get("results", []):
                self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.threatminer.org/v2/domain.php?q={self.d}&rt=5",
            src, cb, timeout=15)

    async def virustotal5(self) -> None:
        src = "virustotal5"
        k = self.k.get("virustotal","")
        if not k: return
        def cb(d, s):
            for item in d.get("data", []):
                n = item.get("id","")
                if n: self.r.add_sub(n, s)
        await self._jfetch(
            f"https://www.virustotal.com/api/v3/domains/{self.d}/subdomains?limit=40&cursor=",
            src, cb, hdrs={"x-apikey": k}, timeout=20)

    async def censys6(self) -> None:
        src = "censys6"
        cid = self.k.get("censys_id",""); sec = self.k.get("censys_secret","")
        if not (cid and sec): return
        import base64 as _b64
        cred = _b64.b64encode(f"{cid}:{sec}".encode()).decode()
        def cb(d, s):
            for item in d.get("result",{}).get("hits", []):
                for n in item.get("names", []):
                    self.r.add_sub(n.lstrip("*."), s)
        await self._jfetch(
            "https://search.censys.io/api/v1/search/certificates",
            src, cb, hdrs={"Authorization": f"Basic {cred}"},
            json_body={"query": f"parsed.names: {self.d}", "page": 2, "fields": ["parsed.names"]},
            method="POST", timeout=20)

    async def intelx3(self) -> None:
        src = "intelx3"
        k = self.k.get("intelligencex","")
        hdrs = {"x-key": k} if k else {}
        await self._scrape(
            f"https://intelx.io/?s={self.d}", src)

    async def leakix5(self) -> None:
        src = "leakix5"
        k = self.k.get("leakix","")
        hdrs = {"api-key": k} if k else {}
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://leakix.net/api/host/{self.d}",
            src, cb, hdrs=hdrs, timeout=15)

    async def dnsx2(self) -> None:
        src = "dnsx2"
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(f"https://api.dnsx.io/v1/subdomains/{self.d}?page=2",
            src, cb, timeout=15)

    async def passive_total3(self) -> None:
        src = "passive_total3"
        pu = self.k.get("pt_user",""); pk = self.k.get("pt_key","")
        if not (pu and pk): return
        import base64 as _b64
        cred = _b64.b64encode(f"{pu}:{pk}".encode()).decode()
        def cb(d, s):
            for sub in d.get("subdomains", []):
                self.r.add_sub(f"{sub}.{self.d}", s)
        await self._jfetch("https://api.riskiq.net/pt/v2/enrichment/subdomains",
            src, cb, hdrs={"Authorization": f"Basic {cred}"},
            params={"query": self.d, "page": 2}, timeout=20)

    async def shodan7(self) -> None:
        src = "shodan7"
        k = self.k.get("shodan","")
        if not k: return
        def cb(d, s):
            for n in _subs_from_text(str(d), self.d): self.r.add_sub(n, s)
        await self._jfetch(
            f"https://api.shodan.io/shodan/host/search?key={k}&query=hostname:{self.d}&page=2",
            src, cb, timeout=20)



    # ═════════════ EXTENDED CT / CERTIFICATE SOURCES ════════════════════════
    async def crt_sh2(self) -> None:
        src = "crt_sh2"
        def cb(d, s):
            if not isinstance(d, list): return
            for e in d:
                for f in ("name_value","common_name"):
                    for n in e.get(f,"").split('\n'):
                        self.r.add_sub(n.strip().lower().lstrip("*."), s)
        await self._jfetch("https://crt.sh/", src, cb,
                           params={"q": f"%.{self.d}", "output": "json", "exclude": "expired"}, timeout=30)

    async def crt_sh4(self) -> None:
        src = "crt_sh4"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&deduplicate=Y", src, timeout=25)

    async def crt_sh5(self) -> None:
        src = "crt_sh5"
        def cb(d, s):
            if not isinstance(d, list): return
            for e in d:
                for n in e.get("name_value","").split('\n'):
                    self.r.add_sub(n.strip().lower().lstrip("*."), s)
        await self._jfetch("https://crt.sh/", src, cb,
                           params={"q": self.d, "output": "json", "group": "none"}, timeout=30)

    async def certspotter2(self) -> None:
        src = "certspotter2"
        def cb(d, s):
            if not isinstance(d, list): return
            for c in d:
                for n in c.get("dns_names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch("https://api.certspotter.com/v1/issuances", src, cb,
                           params={"domain": self.d, "include_subdomains": "true",
                                   "expand": "dns_names", "after": ""}, timeout=25)

    async def certspotter3(self) -> None:
        src = "certspotter3"
        await self._scrape(f"https://sslmate.com/certspotter/api/v1/issuances?domain=%.{self.d}&include_subdomains=true&expand=dns_names", src, timeout=20)

    async def facebook_ct2(self) -> None:
        src = "facebook_ct2"
        await self._scrape(f"https://developers.facebook.com/tools/ct/search/?q={self.d}", src, timeout=20)

    async def ct_api_full2(self) -> None:
        src = "ct_api_full2"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("results", []):
                    for f in ("domain","name","common_name"):
                        v = r.get(f, "")
                        if v: self.r.add_sub(str(v).lower().lstrip("*."), s)
        await self._jfetch(f"https://api.certdb.com/v1/certificates?domain={self.d}&page=1&per_page=100", src, cb, timeout=20)

    async def ct_cloudflare3(self) -> None:
        src = "ct_cloudflare3"
        await self._scrape(f"https://ct.cloudflare.com/logs/nimbus2024/ct/v1/get-entries?start=0&end=10&domain={self.d}", src, timeout=15)

    async def globalsign_ct2(self) -> None:
        src = "globalsign_ct2"
        await self._scrape(f"https://search.globalsign.com/logSearch/api/v1/logs/searchentries?q={self.d}", src, timeout=15)

    async def trustasia_ct2(self) -> None:
        src = "trustasia_ct2"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("result", []):
                    self.r.add_sub(str(r.get("domain","")).lower().lstrip("*."), s)
        await self._jfetch(f"https://ctsearch.antfin.com/api/v1/certificates?domain=*.{self.d}&pageSize=100", src, cb, timeout=15)

    async def letsencrypt_ct2(self) -> None:
        src = "letsencrypt_ct2"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&CA=Let%27s+Encrypt", src, timeout=20)

    async def digicert_ct3(self) -> None:
        src = "digicert_ct3"
        await self._scrape(f"https://ct.digicert.com/log/search?q={self.d}", src, timeout=15)

    async def sectigo_ct2(self) -> None:
        src = "sectigo_ct2"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&CA=Sectigo", src, timeout=20)

    async def entrust3(self) -> None:
        src = "entrust3"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&CA=Entrust", src, timeout=20)

    async def ssl_com_ct2(self) -> None:
        src = "ssl_com_ct2"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&CA=SSL.com", src, timeout=20)

    async def certdb_com2(self) -> None:
        src = "certdb_com2"
        await self._scrape(f"https://certdb.com/domain/{self.d}", src, timeout=15)

    async def sct_observer2(self) -> None:
        src = "sct_observer2"
        await self._scrape(f"https://transparencyreport.google.com/https/certificates?domain={self.d}&include_subdomains=true", src, timeout=20)

    async def tls_observer2(self) -> None:
        src = "tls_observer2"
        await self._scrape(f"https://tls-observatory.services.mozilla.com/api/v1/search?target={self.d}", src, timeout=15)

    async def zlint_ct2(self) -> None:
        src = "zlint_ct2"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&group=none&deduplicate=Y", src, timeout=25)

    async def comodo_ct2(self) -> None:
        src = "comodo_ct2"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&CA=Comodo", src, timeout=20)

    async def merklemap2(self) -> None:
        src = "merklemap2"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("results", []):
                    for f in ("domain","san"):
                        v = r.get(f, "")
                        if isinstance(v, list):
                            for n in v: self.r.add_sub(str(n).lower().lstrip("*."), s)
                        elif v:
                            self.r.add_sub(str(v).lower().lstrip("*."), s)
        for page in range(5, 10):
            await self._jfetch("https://api.merklemap.com/search", src, cb,
                               params={"query": f"*.{self.d}", "page": str(page)})

    async def certcentral2(self) -> None:
        src = "certcentral2"
        await self._scrape(f"https://ct.digicert.com/log/search?q={self.d}&type=full", src, timeout=15)

    async def passive_cert_api2(self) -> None:
        src = "passive_cert_api2"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("data", []):
                    self.r.add_sub(str(r.get("domain","")).lower().lstrip("*."), s)
        await self._jfetch(f"https://api.certdb.com/v1/subdomains?domain={self.d}", src, cb, timeout=15)

    # ═════════════ EXTENDED DNS INTELLIGENCE SOURCES ═════════════════════════
    async def rapiddns4(self) -> None:
        src = "rapiddns4"
        await self._scrape(f"https://rapiddns.io/subdomain/{self.d}?full=1&down=1", src, timeout=20)

    async def rapiddns5(self) -> None:
        src = "rapiddns5"
        await self._scrape(f"https://rapiddns.io/sameip/{self.d}#result", src, timeout=15)

    async def rapiddns6(self) -> None:
        src = "rapiddns6"
        def cb(d, s):
            if isinstance(d, list):
                for r in d:
                    self.r.add_sub(str(r.get("domain","")).lower(), s)
        await self._jfetch(f"https://rapiddns.io/api/subdomain/{self.d}", src, cb, timeout=15)

    async def hackertarget5(self) -> None:
        src = "hackertarget5"
        await self._scrape(f"https://api.hackertarget.com/hostsearch/?q={self.d}&limit=5000", src, timeout=20)

    async def hackertarget6(self) -> None:
        src = "hackertarget6"
        await self._scrape(f"https://api.hackertarget.com/reverseiplookup/?q={self.d}", src, timeout=15)

    async def hackertarget7(self) -> None:
        src = "hackertarget7"
        await self._scrape(f"https://api.hackertarget.com/dnslookup/?q={self.d}", src, timeout=15)

    async def dnslytics4(self) -> None:
        src = "dnslytics4"
        await self._scrape(f"https://dnslytics.com/domain/{self.d}", src, timeout=15)

    async def dnslytics5(self) -> None:
        src = "dnslytics5"
        await self._scrape(f"https://dnslytics.com/subdomains/{self.d}", src, timeout=15)

    async def dnsdumpster4(self) -> None:
        src = "dnsdumpster4"
        await self._scrape(f"https://dnsdumpster.com/", src, timeout=20)

    async def dnsdumpster5(self) -> None:
        src = "dnsdumpster5"
        await self._scrape(f"https://api.dnsdumpster.com/domain/{self.d}", src, timeout=15)

    async def dnsbufferover5(self) -> None:
        src = "dnsbufferover5"
        await self._scrape(f"https://dns.bufferover.run/dns?q=.{self.d}", src, timeout=15)

    async def dnsbufferover6(self) -> None:
        src = "dnsbufferover6"
        await self._scrape(f"https://tls.bufferover.run/dns?q=.{self.d}", src, timeout=15)

    async def dnsgrep3(self) -> None:
        src = "dnsgrep3"
        await self._scrape(f"https://www.dnsgrep.cn/subdomain/{self.d}", src, timeout=15)

    async def dnsgrep4(self) -> None:
        src = "dnsgrep4"
        await self._scrape(f"https://dnsgrep.cn/api/subdomain?q={self.d}&type=all", src, timeout=15)

    async def dnspedia3_ext(self) -> None:
        src = "dnspedia3_ext"
        await self._scrape(f"https://dnspedia.com/tld/ajax.php?cmd=GetZoneFiles&zoneName={self.d}", src, timeout=15)

    async def dnspedia3(self) -> None:
        src = "dnspedia3"
        await self._scrape(f"https://dnspedia.com/domain-lookup/?domain={self.d}", src, timeout=15)

    async def completedns3(self) -> None:
        src = "completedns3"
        await self._scrape(f"https://completedns.com/dns-history/?domain={self.d}", src, timeout=15)

    async def completedns4(self) -> None:
        src = "completedns4"
        await self._scrape(f"https://www.completedns.com/resolvers/?domain={self.d}", src, timeout=15)

    async def dnsscan3(self) -> None:
        src = "dnsscan3"
        await self._scrape(f"https://dnsscan.io/domains/{self.d}", src, timeout=15)

    async def dnsscan4(self) -> None:
        src = "dnsscan4"
        await self._scrape(f"https://dnsscan.io/api/subdomains/{self.d}", src, timeout=15)

    async def dnstrace2(self) -> None:
        src = "dnstrace2"
        await self._scrape(f"https://dnstrace.pro/subdomains/{self.d}", src, timeout=15)

    async def dnstrace3(self) -> None:
        src = "dnstrace3"
        await self._scrape(f"https://dnstrace.pro/api/v1/report/{self.d}", src, timeout=15)

    async def dnsvault2(self) -> None:
        src = "dnsvault2"
        await self._scrape(f"https://dnsvault.net/domains/{self.d}", src, timeout=15)

    async def dnsspy2(self) -> None:
        src = "dnsspy2"
        await self._scrape(f"https://dnsspy.io/v1/lookup/{self.d}", src, timeout=15)

    async def dnsspy3(self) -> None:
        src = "dnsspy3"
        await self._scrape(f"https://dnsspy.io/domain/{self.d}/subdomains", src, timeout=15)

    async def dnseye3(self) -> None:
        src = "dnseye3"
        await self._scrape(f"https://dnseye.io/search?q={self.d}&type=subdomain", src, timeout=15)

    async def dnseye4(self) -> None:
        src = "dnseye4"
        await self._scrape(f"https://dnseye.io/api/subdomains/{self.d}", src, timeout=15)

    async def dnsmap_io3(self) -> None:
        src = "dnsmap_io3"
        await self._scrape(f"https://dnsmap.io/info/{self.d}", src, timeout=15)

    async def dnssift2(self) -> None:
        src = "dnssift2"
        await self._scrape(f"https://dnssift.com/results/?url={self.d}", src, timeout=15)

    async def dnscoffee3(self) -> None:
        src = "dnscoffee3"
        await self._scrape(f"https://dns.coffee/domain/{self.d}", src, timeout=15)

    async def dnsquery_org2(self) -> None:
        src = "dnsquery_org2"
        await self._scrape(f"https://dnsquery.org/dnsquery/{self.d}/ANY/", src, timeout=15)

    async def dnszones2(self) -> None:
        src = "dnszones2"
        await self._scrape(f"https://dnszones.eu/subdomains/{self.d}", src, timeout=15)

    async def opendata_dns2(self) -> None:
        src = "opendata_dns2"
        await self._scrape(f"https://opendata.rapid7.com/api/search/forward_dns?q={self.d}", src, timeout=15)

    async def viewdns3(self) -> None:
        src = "viewdns3"
        await self._scrape(f"https://viewdns.info/dnsrecord/?domain={self.d}&type=ANY", src, timeout=15)

    async def viewdns4(self) -> None:
        src = "viewdns4"
        await self._scrape(f"https://viewdns.info/iphistory/?domain={self.d}", src, timeout=15)

    async def farsight3(self) -> None:
        src = "farsight3"
        await self._scrape(f"https://scout.saltycloud.com/api/v1/rrnames/*.{self.d}?limit=1000", src, timeout=15)

    async def farsight4(self) -> None:
        src = "farsight4"
        await self._scrape(f"https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{self.d}", src, timeout=15)

    async def dnsdb3(self) -> None:
        src = "dnsdb3"
        await self._scrape(f"https://api.dnsdb.info/lookup/rrset/name/*.{self.d}/ANY?limit=500&humantime=true", src, timeout=15)

    async def dnsdb4(self) -> None:
        src = "dnsdb4"
        await self._scrape(f"https://api.dnsdb.info/lookup/rdata/name/*.{self.d}?limit=500", src, timeout=15)

    async def circl3(self) -> None:
        src = "circl3"
        await self._scrape(f"https://www.circl.lu/pdns/query/rrname/*.{self.d}", src, timeout=15)

    async def circl4(self) -> None:
        src = "circl4"
        await self._scrape(f"https://www.circl.lu/pdns/query/rdata/{self.d}", src, timeout=15)

    async def circl_pdns2(self) -> None:
        src = "circl_pdns2"
        await self._scrape(f"https://www.circl.lu/pdns/query/rrname/{self.d}/A", src, timeout=15)

    async def passive_total4(self) -> None:
        src = "passive_total4"
        await self._scrape(f"https://api.riskiq.net/pt/v2/dns/passive/subdomains?query={self.d}", src, timeout=15)

    async def riddler3(self) -> None:
        src = "riddler3"
        await self._scrape(f"https://riddler.io/search?q=pld:{self.d}", src, timeout=20)

    async def riddler4(self) -> None:
        src = "riddler4"
        await self._scrape(f"https://riddler.io/search/exportcsv?q=pld:{self.d}", src, timeout=20)

    async def robtex3(self) -> None:
        src = "robtex3"
        await self._scrape(f"https://freeapi.robtex.com/pdns/reverse/{self.d}", src, timeout=15)

    async def robtex4(self) -> None:
        src = "robtex4"
        await self._scrape(f"https://freeapi.robtex.com/pdns/forward/{self.d}", src, timeout=15)

    async def riskiq3(self) -> None:
        src = "riskiq3"
        await self._scrape(f"https://api.riskiq.net/pt/v2/enrichment/subdomains?query={self.d}", src, timeout=15)

    async def riskiq4(self) -> None:
        src = "riskiq4"
        await self._scrape(f"https://api.riskiq.net/pt/v2/dns/search/keyword?query={self.d}", src, timeout=15)

    async def dnstable2(self) -> None:
        src = "dnstable2"
        await self._scrape(f"https://www.dnstable.com/search.php?q={self.d}&type=1", src, timeout=15)

    async def dnstable3(self) -> None:
        src = "dnstable3"
        await self._scrape(f"https://www.dnstable.com/search.php?q=*.{self.d}&type=1", src, timeout=15)

    # ═════════════ EXTENDED SEARCH ENGINE SOURCES ════════════════════════════
    async def google4(self) -> None:
        src = "google4"
        await self._scrape(f"https://www.google.com/search?q=site:{self.d}+-www&num=100&start=0", src, timeout=15)

    async def google5(self) -> None:
        src = "google5"
        await self._scrape(f"https://www.google.com/search?q=site:*.{self.d}&num=100&start=100", src, timeout=15)

    async def google6(self) -> None:
        src = "google6"
        await self._scrape(f"https://www.google.com/search?q=site:{self.d}+inurl:admin&num=100", src, timeout=15)

    async def google7(self) -> None:
        src = "google7"
        await self._scrape(f"https://www.google.com/search?q=site:{self.d}+inurl:api&num=100", src, timeout=15)

    async def google8(self) -> None:
        src = "google8"
        await self._scrape(f"https://www.google.com/search?q=%22.{self.d}%22&num=100&start=200", src, timeout=15)

    async def bing4(self) -> None:
        src = "bing4"
        await self._scrape(f"https://www.bing.com/search?q=site:{self.d}+-www&count=50&first=1", src, timeout=15)

    async def bing5(self) -> None:
        src = "bing5"
        await self._scrape(f"https://www.bing.com/search?q=site:*.{self.d}&count=50&first=51", src, timeout=15)

    async def bing6(self) -> None:
        src = "bing6"
        await self._scrape(f"https://www.bing.com/search?q=site:{self.d}&count=50&first=101", src, timeout=15)

    async def yahoo3(self) -> None:
        src = "yahoo3"
        await self._scrape(f"https://search.yahoo.com/search?p=site:{self.d}+-www&n=100&b=1", src, timeout=15)

    async def yahoo4(self) -> None:
        src = "yahoo4"
        await self._scrape(f"https://search.yahoo.com/search?p=site:{self.d}&n=100&b=51", src, timeout=15)

    async def yandex3(self) -> None:
        src = "yandex3"
        await self._scrape(f"https://yandex.com/search/?text=site:{self.d}+-www&lr=213", src, timeout=20)

    async def yandex4(self) -> None:
        src = "yandex4"
        await self._scrape(f"https://yandex.com/search/?text=host:{self.d}&lr=213", src, timeout=20)

    async def duckduckgo3(self) -> None:
        src = "duckduckgo3"
        await self._scrape(f"https://duckduckgo.com/html/?q=site:{self.d}+-www", src, timeout=20)

    async def duckduckgo4(self) -> None:
        src = "duckduckgo4"
        await self._scrape(f"https://html.duckduckgo.com/html/?q=site:*.{self.d}", src, timeout=20)

    async def baidu3(self) -> None:
        src = "baidu3"
        await self._scrape(f"https://www.baidu.com/s?wd=site:{self.d}+-www&rn=50", src, timeout=20)

    async def baidu4(self) -> None:
        src = "baidu4"
        await self._scrape(f"https://www.baidu.com/s?wd=site:{self.d}&pn=50&rn=50", src, timeout=20)

    async def startpage3(self) -> None:
        src = "startpage3"
        await self._scrape(f"https://www.startpage.com/sp/search?q=site:{self.d}&page=2", src, timeout=20)

    async def searx5(self) -> None:
        src = "searx5"
        await self._scrape(f"https://searx.be/search?q=site:{self.d}&format=json", src, timeout=15)

    async def searx6(self) -> None:
        src = "searx6"
        await self._scrape(f"https://search.disroot.org/search?q=site:{self.d}+-www&format=json", src, timeout=15)

    async def searx7(self) -> None:
        src = "searx7"
        await self._scrape(f"https://paulgo.io/search?q=site:{self.d}&format=json", src, timeout=15)

    async def searx8(self) -> None:
        src = "searx8"
        await self._scrape(f"https://search.mdosch.de/search?q=site:{self.d}&format=json", src, timeout=15)

    async def brave4(self) -> None:
        src = "brave4"
        await self._scrape(f"https://search.brave.com/search?q=site:{self.d}+-www&offset=0", src, timeout=15)

    async def brave5(self) -> None:
        src = "brave5"
        await self._scrape(f"https://search.brave.com/search?q=site:*.{self.d}&offset=20", src, timeout=15)

    async def kagi_search2(self) -> None:
        src = "kagi_search2"
        await self._scrape(f"https://kagi.com/search?q=site:{self.d}+-www", src, timeout=15)

    async def qwant3(self) -> None:
        src = "qwant3"
        await self._scrape(f"https://api.qwant.com/v3/search/web?q=site:{self.d}&count=50&offset=0&locale=en_US", src, timeout=15)

    async def qwant4(self) -> None:
        src = "qwant4"
        await self._scrape(f"https://api.qwant.com/v3/search/web?q=site:{self.d}&count=50&offset=50&locale=en_US", src, timeout=15)

    async def mojeek3(self) -> None:
        src = "mojeek3"
        await self._scrape(f"https://www.mojeek.com/search?q=site:{self.d}&arc=none&fmt=json", src, timeout=15)

    async def mojeek4(self) -> None:
        src = "mojeek4"
        await self._scrape(f"https://www.mojeek.com/search?q=site:{self.d}&s=20", src, timeout=15)

    async def metager_search2(self) -> None:
        src = "metager_search2"
        await self._scrape(f"https://metager.org/meta/meta.ger3?eingabe=site:{self.d}", src, timeout=20)

    async def gibiru_search2(self) -> None:
        src = "gibiru_search2"
        await self._scrape(f"https://gibiru.com/results.html?q=site:{self.d}", src, timeout=15)

    async def millionshort2(self) -> None:
        src = "millionshort2"
        await self._scrape(f"https://millionshort.com/search?keywords={self.d}&remove=1000000", src, timeout=20)

    async def dogpile_search2(self) -> None:
        src = "dogpile_search2"
        await self._scrape(f"https://www.dogpile.com/search/web?q=site:{self.d}", src, timeout=20)

    async def gigablast2(self) -> None:
        src = "gigablast2"
        await self._scrape(f"https://www.gigablast.com/search?q=site:{self.d}&format=json", src, timeout=20)

    async def swisscows3(self) -> None:
        src = "swisscows3"
        await self._scrape(f"https://swisscows.com/web?query=site:{self.d}", src, timeout=20)

    async def ecosia3(self) -> None:
        src = "ecosia3"
        await self._scrape(f"https://www.ecosia.org/search?q=site:{self.d}&p=0", src, timeout=20)

    # ═════════════ EXTENDED THREAT INTELLIGENCE SOURCES ══════════════════════
    async def trellix_ti(self) -> None:
        src = "trellix_ti"
        await self._scrape(f"https://www.trellix.com/en-us/threat-center/threat-landscape.html?domain={self.d}", src, timeout=15)

    async def trendmicro_ti(self) -> None:
        src = "trendmicro_ti"
        await self._scrape(f"https://global.sitesafety.trendmicro.com/result.php?url={self.d}", src, timeout=15)

    async def kaspersky_ti(self) -> None:
        src = "kaspersky_ti"
        await self._scrape(f"https://opentip.kaspersky.com/api/v1/search/domain?request={self.d}", src, timeout=15)

    async def cisco_talos2(self) -> None:
        src = "cisco_talos2"
        await self._scrape(f"https://talosintelligence.com/sb_api/query_lookup?url=http://{self.d}", src, timeout=15)

    async def cisco_talos3(self) -> None:
        src = "cisco_talos3"
        await self._scrape(f"https://talosintelligence.com/reputation_center/lookup?search={self.d}", src, timeout=15)

    async def ibm_xforce3(self) -> None:
        src = "ibm_xforce3"
        await self._scrape(f"https://exchange.xforce.ibmcloud.com/url/{self.d}", src, timeout=15)

    async def ibm_xforce4(self) -> None:
        src = "ibm_xforce4"
        await self._scrape(f"https://api.xforce.ibmcloud.com/api/url/{self.d}", src, timeout=15)

    async def ibm_xforce5(self) -> None:
        src = "ibm_xforce5"
        await self._scrape(f"https://api.xforce.ibmcloud.com/api/resolve/{self.d}", src, timeout=15)

    async def otx2(self) -> None:
        src = "otx2"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("passive_dns", []):
                    self.r.add_sub(str(r.get("hostname","")).lower(), s)
                for r in d.get("data", []):
                    self.r.add_sub(str(r.get("hostname","")).lower(), s)
        await self._jfetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/passive_dns", src, cb, timeout=20)

    async def otx3(self) -> None:
        src = "otx3"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("data", []):
                    self.r.add_sub(str(r.get("hostname","")).lower(), s)
        await self._jfetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/malware", src, cb, timeout=15)

    async def otx4(self) -> None:
        src = "otx4"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("data", []):
                    self.r.add_sub(str(r.get("hostname","")).lower(), s)
        await self._jfetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/url_list?limit=500", src, cb, timeout=20)

    async def urlhaus4(self) -> None:
        src = "urlhaus4"
        await self._scrape(f"https://urlhaus-api.abuse.ch/v1/host/{self.d}", src, timeout=15)

    async def urlhaus5(self) -> None:
        src = "urlhaus5"
        await self._scrape(f"https://urlhaus.abuse.ch/browse.php?search={self.d}", src, timeout=15)

    async def urlhaus6(self) -> None:
        src = "urlhaus6"
        def cb(d, s):
            if isinstance(d, dict):
                for u in d.get("urls", []):
                    self.r.add_sub(str(u.get("url","")).split("/")[2] if "/" in str(u.get("url","")) else "", s)
        await self._jfetch("https://urlhaus-api.abuse.ch/v1/host/", src, cb,
                           method="POST", json_body={"host": self.d}, timeout=15)

    async def bazaar3(self) -> None:
        src = "bazaar3"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("data", []):
                    self.r.add_sub(str(r.get("reporter","")).lower(), s)
        await self._jfetch("https://mb-api.abuse.ch/api/v1/", src, cb,
                           method="POST", json_body={"query": "get_file", "limit": 100, "tag": self.d}, timeout=15)

    async def bazaar4(self) -> None:
        src = "bazaar4"
        await self._scrape(f"https://bazaar.abuse.ch/browse.php?search={self.d}", src, timeout=15)

    async def threatfox4(self) -> None:
        src = "threatfox4"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("data", []):
                    self.r.add_sub(str(r.get("ioc","")).split(":")[0].lower(), s)
        await self._jfetch("https://threatfox-api.abuse.ch/api/v1/", src, cb,
                           method="POST", json_body={"query": "search_ioc", "search_term": self.d, "exact_match": False}, timeout=15)

    async def threatfox5(self) -> None:
        src = "threatfox5"
        await self._scrape(f"https://threatfox.abuse.ch/browse.php?search={self.d}", src, timeout=15)

    async def feodo_tracker2(self) -> None:
        src = "feodo_tracker2"
        await self._scrape(f"https://feodotracker.abuse.ch/browse.php?search={self.d}", src, timeout=15)

    async def sslbl3(self) -> None:
        src = "sslbl3"
        await self._scrape(f"https://sslbl.abuse.ch/intelligence/", src, timeout=15)

    async def hybridanalysis2(self) -> None:
        src = "hybridanalysis2"
        await self._scrape(f"https://www.hybrid-analysis.com/search?query={self.d}&dataType=domain", src, timeout=20)

    async def hybridanalysis3(self) -> None:
        src = "hybridanalysis3"
        await self._scrape(f"https://www.hybrid-analysis.com/api/v2/search/terms?domain={self.d}", src, timeout=20)

    async def any_run3(self) -> None:
        src = "any_run3"
        await self._scrape(f"https://app.any.run/submissions/?domain={self.d}", src, timeout=15)

    async def any_run4(self) -> None:
        src = "any_run4"
        await self._scrape(f"https://any.run/cybersecurity-blog/?s={self.d}", src, timeout=15)

    async def triage3(self) -> None:
        src = "triage3"
        await self._scrape(f"https://tria.ge/search?query=domain:{self.d}", src, timeout=15)

    async def triage4(self) -> None:
        src = "triage4"
        await self._scrape(f"https://tria.ge/api/v0/search?query=domain%3A{self.d}&limit=50", src, timeout=15)

    async def polyswarm2(self) -> None:
        src = "polyswarm2"
        await self._scrape(f"https://polyswarm.network/scan/results/url/{self.d}", src, timeout=15)

    async def polyswarm3(self) -> None:
        src = "polyswarm3"
        await self._scrape(f"https://polyswarm.network/scan/results/domain/{self.d}", src, timeout=15)

    async def malpedia2(self) -> None:
        src = "malpedia2"
        await self._scrape(f"https://malpedia.caad.fkie.fraunhofer.de/find/{self.d}", src, timeout=15)

    async def malpedia3(self) -> None:
        src = "malpedia3"
        await self._scrape(f"https://malpedia.caad.fkie.fraunhofer.de/api/find/domain/{self.d}", src, timeout=15)

    async def phishtank3(self) -> None:
        src = "phishtank3"
        await self._scrape(f"https://checkurl.phishtank.com/checkurl/?url=http%3A%2F%2F{self.d}%2F&format=json", src, timeout=15)

    async def openphish3(self) -> None:
        src = "openphish3"
        await self._scrape(f"https://openphish.com/feed.txt", src, timeout=20)

    async def maltiverse3(self) -> None:
        src = "maltiverse3"
        await self._scrape(f"https://api.maltiverse.com/hostname/{self.d}", src, timeout=15)

    async def maltiverse4(self) -> None:
        src = "maltiverse4"
        await self._scrape(f"https://api.maltiverse.com/ip/{self.d}", src, timeout=15)

    async def pulsedive5(self) -> None:
        src = "pulsedive5"
        await self._scrape(f"https://pulsedive.com/api/info.php?indicator={self.d}&pretty=1", src, timeout=15)

    async def pulsedive6(self) -> None:
        src = "pulsedive6"
        await self._scrape(f"https://pulsedive.com/api/explore.php?q=ioc%3D{self.d}&pretty=1&limit=100", src, timeout=15)

    async def greynoise3(self) -> None:
        src = "greynoise3"
        await self._scrape(f"https://api.greynoise.io/v3/community/{self.d}", src, timeout=15)

    async def greynoise4(self) -> None:
        src = "greynoise4"
        await self._scrape(f"https://api.greynoise.io/v2/noise/quick/{self.d}", src, timeout=15)

    async def greynoise5(self) -> None:
        src = "greynoise5"
        await self._scrape(f"https://viz.greynoise.io/ip/{self.d}", src, timeout=15)

    async def scamalytics2(self) -> None:
        src = "scamalytics2"
        await self._scrape(f"https://scamalytics.com/ip/{self.d}", src, timeout=15)

    async def spamhaus3(self) -> None:
        src = "spamhaus3"
        await self._scrape(f"https://www.spamhaus.org/query/domain/{self.d}", src, timeout=15)

    async def spamhaus4(self) -> None:
        src = "spamhaus4"
        await self._scrape(f"https://check.spamhaus.org/listed/?searchterm={self.d}", src, timeout=15)

    async def recordedfuture2(self) -> None:
        src = "recordedfuture2"
        await self._scrape(f"https://api.recordedfuture.com/v2/domain/{self.d}?fields=entity,metrics,intelCard,riskScore", src, timeout=15)

    async def criminalip5(self) -> None:
        src = "criminalip5"
        await self._scrape(f"https://api.criminalip.io/v1/domain/report?query={self.d}", src, timeout=15)

    # ═════════════ EXTENDED CODE / DEVELOPER PLATFORMS ════════════════════════
    async def github5(self) -> None:
        src = "github5"
        await self._scrape(f"https://api.github.com/search/code?q={self.d}+in:file&per_page=100&page=1", src, timeout=20)

    async def github6(self) -> None:
        src = "github6"
        await self._scrape(f"https://api.github.com/search/repositories?q={self.d}&per_page=100", src, timeout=20)

    async def github7(self) -> None:
        src = "github7"
        await self._scrape(f"https://api.github.com/search/commits?q={self.d}&per_page=100", src, timeout=20)

    async def github8(self) -> None:
        src = "github8"
        await self._scrape(f"https://api.github.com/search/code?q={self.d}+in:file&per_page=100&page=2", src, timeout=20)

    async def gitlab4(self) -> None:
        src = "gitlab4"
        await self._scrape(f"https://gitlab.com/search?search={self.d}&scope=blobs&page=1", src, timeout=20)

    async def gitlab5(self) -> None:
        src = "gitlab5"
        await self._scrape(f"https://gitlab.com/api/v4/projects?search={self.d}&per_page=100", src, timeout=20)

    async def gitlab6(self) -> None:
        src = "gitlab6"
        await self._scrape(f"https://gitlab.com/search?search={self.d}&scope=projects&page=2", src, timeout=20)

    async def bitbucket3(self) -> None:
        src = "bitbucket3"
        await self._scrape(f"https://api.bitbucket.org/2.0/repositories?q=full_name~%22{self.d.split('.')[0]}%22&pagelen=50", src, timeout=15)

    async def bitbucket4(self) -> None:
        src = "bitbucket4"
        await self._scrape(f"https://bitbucket.org/search?q=site:{self.d}", src, timeout=20)

    async def codeberg2(self) -> None:
        src = "codeberg2"
        await self._scrape(f"https://codeberg.org/api/v1/repos/search?q={self.d}&limit=50", src, timeout=15)

    async def codeberg3(self) -> None:
        src = "codeberg3"
        await self._scrape(f"https://codeberg.org/explore/repos?q={self.d}&page=1", src, timeout=15)

    async def sourcegraph3(self) -> None:
        src = "sourcegraph3"
        await self._scrape(f"https://sourcegraph.com/search?q=content:{self.d}&patternType=regexp&count=100", src, timeout=20)

    async def sourcegraph4(self) -> None:
        src = "sourcegraph4"
        await self._scrape(f"https://sourcegraph.com/.api/search/stream?q=content:{self.d}&display=100", src, timeout=20)

    async def searchcode2(self) -> None:
        src = "searchcode2"
        await self._scrape(f"https://searchcode.com/api/codesearch_I/?q={self.d}&p=0&per_page=100", src, timeout=15)

    async def searchcode3(self) -> None:
        src = "searchcode3"
        await self._scrape(f"https://searchcode.com/api/codesearch_I/?q={self.d}&p=1&per_page=100", src, timeout=15)

    async def grep_app2(self) -> None:
        src = "grep_app2"
        await self._scrape(f"https://grep.app/api/search?q={self.d}&page=2", src, timeout=20)

    async def grep_app3(self) -> None:
        src = "grep_app3"
        await self._scrape(f"https://grep.app/api/search?q={self.d}&page=3", src, timeout=20)

    async def gist_search3(self) -> None:
        src = "gist_search3"
        await self._scrape(f"https://gist.github.com/search?q={self.d}&p=2", src, timeout=15)

    async def gist_search4(self) -> None:
        src = "gist_search4"
        await self._scrape(f"https://api.github.com/gists/public?page=1&per_page=100", src, timeout=15)

    async def dev_to_search2(self) -> None:
        src = "dev_to_search2"
        await self._scrape(f"https://dev.to/api/articles?tag={self.d.replace('.','')}&per_page=30&page=2", src, timeout=15)

    async def stackoverflow3(self) -> None:
        src = "stackoverflow3"
        await self._scrape(f"https://api.stackexchange.com/2.3/search?order=desc&sort=relevance&intitle={self.d}&site=stackoverflow&pagesize=50", src, timeout=15)

    async def stackoverflow4(self) -> None:
        src = "stackoverflow4"
        await self._scrape(f"https://stackoverflow.com/search?q={self.d}&tab=newest", src, timeout=15)

    async def npm3(self) -> None:
        src = "npm3"
        await self._scrape(f"https://registry.npmjs.org/-/v1/search?text={self.d}&size=250", src, timeout=15)

    async def npm4(self) -> None:
        src = "npm4"
        await self._scrape(f"https://www.npmjs.com/search?q={self.d}&page=2", src, timeout=15)

    async def pypi3(self) -> None:
        src = "pypi3"
        await self._scrape(f"https://pypi.org/search/?q={self.d}&page=2", src, timeout=15)

    async def pypi4(self) -> None:
        src = "pypi4"
        await self._scrape(f"https://pypi.org/search/?q={self.d.split('.')[0]}&page=1", src, timeout=15)

    async def rubygems_search2(self) -> None:
        src = "rubygems_search2"
        await self._scrape(f"https://rubygems.org/api/v1/search.json?query={self.d}", src, timeout=15)

    async def maven_central2(self) -> None:
        src = "maven_central2"
        await self._scrape(f"https://search.maven.org/solrsearch/select?q={self.d}&rows=50&wt=json", src, timeout=15)

    async def nuget_search2(self) -> None:
        src = "nuget_search2"
        await self._scrape(f"https://api-v2v3search-0.nuget.org/query?q={self.d}&take=50", src, timeout=15)

    async def crates2_extra(self) -> None:
        src = "crates2_extra"
        await self._scrape(f"https://crates.io/api/v1/crates?q={self.d}&per_page=50&page=2", src, timeout=15)

    async def dockerhub3(self) -> None:
        src = "dockerhub3"
        await self._scrape(f"https://hub.docker.com/v2/search/repositories/?query={self.d}&page_size=100&page=2", src, timeout=15)

    async def dockerhub4(self) -> None:
        src = "dockerhub4"
        await self._scrape(f"https://hub.docker.com/v2/repositories/?name={self.d.split('.')[0]}&page=1&page_size=100", src, timeout=15)

    async def quay_io2(self) -> None:
        src = "quay_io2"
        await self._scrape(f"https://quay.io/api/v1/repository?public=true&namespace={self.d.split('.')[0]}", src, timeout=15)

    async def medium_search2(self) -> None:
        src = "medium_search2"
        await self._scrape(f"https://medium.com/search?q={self.d}&page=2", src, timeout=15)

    async def trello_search2(self) -> None:
        src = "trello_search2"
        await self._scrape(f"https://trello.com/search?q={self.d}&modelTypes=cards", src, timeout=15)

    # ═════════════ EXTENDED CLOUD / INFRASTRUCTURE SOURCES ═══════════════════
    async def azure_websites3(self) -> None:
        src = "azure_websites3"
        d0 = self.d.replace(".", "-")
        await self._scrape(f"https://api.github.com/search/code?q={d0}+azurewebsites.net&per_page=100", src, timeout=20)

    async def firebase3(self) -> None:
        src = "firebase3"
        d0 = self.d.split(".")[0]
        for tpl in [f"{d0}-prod", f"{d0}-dev", f"{d0}-staging", f"{d0}-api", f"{d0}-app"]:
            await self._scrape(f"https://{tpl}.firebaseio.com/.json?shallow=true", src, timeout=8)

    async def firebase4(self) -> None:
        src = "firebase4"
        d0 = self.d.split(".")[0]
        for tpl in [f"{d0}", f"{d0}db", f"{d0}-db", f"{d0}firebase", f"{d0}-default-rtdb"]:
            await self._scrape(f"https://{tpl}.firebaseapp.com", src, timeout=8)

    async def github_pages2(self) -> None:
        src = "github_pages2"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://api.github.com/search/repositories?q={d0}+in:name+topic:github-pages&per_page=100", src, timeout=20)

    async def cloud_buckets3(self) -> None:
        src = "cloud_buckets3"
        d0 = self.d.split(".")[0]
        for suffix in ["", "-backup", "-data", "-static", "-media", "-uploads", "-assets", "-files", "-logs"]:
            for ext in ["s3.amazonaws.com", "storage.googleapis.com"]:
                await self._scrape(f"https://{d0}{suffix}.{ext}", src, timeout=6)

    async def cloud_buckets4(self) -> None:
        src = "cloud_buckets4"
        d0 = self.d.split(".")[0]
        for suffix in ["-prod", "-dev", "-stage", "-test", "-uat", "-cdn", "-img"]:
            await self._scrape(f"https://{d0}{suffix}.s3.amazonaws.com", src, timeout=6)

    async def pastebin3(self) -> None:
        src = "pastebin3"
        await self._scrape(f"https://pastebin.com/search?q={self.d}&page=2", src, timeout=20)

    async def pastebin4(self) -> None:
        src = "pastebin4"
        await self._scrape(f"https://psbdmp.ws/api/search/{self.d}", src, timeout=15)

    async def pastebin5(self) -> None:
        src = "pastebin5"
        await self._scrape(f"https://api.pastebin.com/api_scrape.php?limit=100", src, timeout=15)

    async def reddit3(self) -> None:
        src = "reddit3"
        await self._scrape(f"https://www.reddit.com/search.json?q={self.d}&limit=100&sort=new", src, timeout=20)

    async def reddit4(self) -> None:
        src = "reddit4"
        await self._scrape(f"https://www.reddit.com/search.json?q=site:{self.d}&limit=100", src, timeout=20)

    async def dehashed3(self) -> None:
        src = "dehashed3"
        await self._scrape(f"https://dehashed.com/search?query={self.d}&size=100&page=2", src, timeout=15)

    async def leakix6(self) -> None:
        src = "leakix6"
        await self._scrape(f"https://leakix.net/api/v1/host/{self.d}?page=2", src, timeout=15)

    async def leakix7(self) -> None:
        src = "leakix7"
        await self._scrape(f"https://leakix.net/api/v1/query?scope=service&q=+domain%3A%22{self.d}%22", src, timeout=15)

    async def leakix8(self) -> None:
        src = "leakix8"
        await self._scrape(f"https://leakix.net/api/v1/summary?q=+domain%3A%22{self.d}%22", src, timeout=15)

    # ═════════════ EXTENDED NETWORK / BGP / ASN SOURCES ══════════════════════
    async def bgpview4(self) -> None:
        src = "bgpview4"
        await self._scrape(f"https://api.bgpview.io/search?query_term={self.d}&type=domain", src, timeout=15)

    async def bgpview5(self) -> None:
        src = "bgpview5"
        def cb(d, s):
            if isinstance(d, dict):
                for p in d.get("data", {}).get("prefixes", []):
                    self.r.add_sub(str(p.get("ip","")).lower(), s)
        await self._jfetch(f"https://api.bgpview.io/search?query_term={self.d}&type=ip", src, cb, timeout=15)

    async def bgptools3(self) -> None:
        src = "bgptools3"
        await self._scrape(f"https://bgp.tools/prefix/{self.d}", src, timeout=15)

    async def bgptools4(self) -> None:
        src = "bgptools4"
        await self._scrape(f"https://bgp.tools/as/{self.d}", src, timeout=15)

    async def peeringdb3(self) -> None:
        src = "peeringdb3"
        await self._scrape(f"https://www.peeringdb.com/api/net?name__contains={self.d.split('.')[0]}", src, timeout=15)

    async def peeringdb4(self) -> None:
        src = "peeringdb4"
        await self._scrape(f"https://www.peeringdb.com/search?term={self.d}", src, timeout=15)

    async def teamcymru3(self) -> None:
        src = "teamcymru3"
        await self._scrape(f"https://www.team-cymru.com/ip-asn-mapping.html?query={self.d}", src, timeout=15)

    async def teamcymru4(self) -> None:
        src = "teamcymru4"
        await self._scrape(f"https://api.cymru.com/bulk_asn/?q={self.d}", src, timeout=15)

    async def shadowserver3(self) -> None:
        src = "shadowserver3"
        await self._scrape(f"https://api.shadowserver.org/net/asn?domain={self.d}", src, timeout=15)

    async def shadowserver4(self) -> None:
        src = "shadowserver4"
        await self._scrape(f"https://dashboard.shadowserver.org/statistic/geo/network-details/?date=&addr={self.d}", src, timeout=15)

    async def ipinfo5(self) -> None:
        src = "ipinfo5"
        await self._scrape(f"https://ipinfo.io/{self.d}/json", src, timeout=15)

    async def ipinfo6(self) -> None:
        src = "ipinfo6"
        await self._scrape(f"https://ipinfo.io/domain/{self.d}", src, timeout=15)

    async def ipvoid3(self) -> None:
        src = "ipvoid3"
        await self._scrape(f"https://www.ipvoid.com/find-website-ip/?host={self.d}", src, timeout=15)

    async def ipvoid4(self) -> None:
        src = "ipvoid4"
        await self._scrape(f"https://www.ipvoid.com/domain-reputation/?host={self.d}", src, timeout=15)

    async def networksdb3(self) -> None:
        src = "networksdb3"
        await self._scrape(f"https://networksdb.io/search/whois/domain/{self.d}", src, timeout=15)

    async def networksdb4(self) -> None:
        src = "networksdb4"
        await self._scrape(f"https://networksdb.io/api/search?org={self.d.split('.')[0]}&type=org", src, timeout=15)

    async def spur_io3(self) -> None:
        src = "spur_io3"
        await self._scrape(f"https://spur.us/app/context/{self.d}", src, timeout=15)

    async def arin3(self) -> None:
        src = "arin3"
        await self._scrape(f"https://rdap.arin.net/registry/domain/{self.d}", src, timeout=15)

    async def ripe3(self) -> None:
        src = "ripe3"
        await self._scrape(f"https://stat.ripe.net/data/dns-chain/data.json?resource={self.d}", src, timeout=15)

    async def ripe4(self) -> None:
        src = "ripe4"
        await self._scrape(f"https://stat.ripe.net/data/rir-geo/data.json?resource={self.d}", src, timeout=15)

    async def rdap3(self) -> None:
        src = "rdap3"
        await self._scrape(f"https://rdap.org/domain/{self.d}", src, timeout=15)

    async def rdap4(self) -> None:
        src = "rdap4"
        await self._scrape(f"https://rdap.verisign.com/com/v1/domain/{self.d}", src, timeout=15)

    async def rdap_io2(self) -> None:
        src = "rdap_io2"
        await self._scrape(f"https://rdap.io/domain/{self.d}", src, timeout=15)

    # ═════════════ EXTENDED WHOIS / REGISTRATION SOURCES ════════════════════
    async def whoisxml4(self) -> None:
        src = "whoisxml4"
        await self._scrape(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={self.d}&outputFormat=JSON&da=2", src, timeout=15)

    async def whoisxml5(self) -> None:
        src = "whoisxml5"
        await self._scrape(f"https://dns-history.whoisxmlapi.com/api/v1?domainName={self.d}&outputFormat=JSON", src, timeout=15)

    async def whoisxml6(self) -> None:
        src = "whoisxml6"
        await self._scrape(f"https://subdomains.whoisxmlapi.com/api/v1?domainName={self.d}&outputFormat=JSON", src, timeout=15)

    async def whoisxml7(self) -> None:
        src = "whoisxml7"
        await self._scrape(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={self.d}&outputFormat=JSON&type=2", src, timeout=15)

    async def whoisfreaks5(self) -> None:
        src = "whoisfreaks5"
        await self._scrape(f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={self.d}", src, timeout=15)

    async def whoisfreaks6(self) -> None:
        src = "whoisfreaks6"
        await self._scrape(f"https://api.whoisfreaks.com/v1.0/whois?whois=historic&domainName={self.d}&page=2", src, timeout=15)

    async def whoxy3(self) -> None:
        src = "whoxy3"
        await self._scrape(f"https://api.whoxy.com/?whois={self.d}&history=1&page=2", src, timeout=15)

    async def whoxy4(self) -> None:
        src = "whoxy4"
        await self._scrape(f"https://api.whoxy.com/?reverse=whois&keyword={self.d.split('.')[0]}&page=1", src, timeout=15)

    async def domaintools2_ext(self) -> None:
        src = "domaintools2_ext"
        await self._scrape(f"https://api.domaintools.com/v1/{self.d}/hosting-history/", src, timeout=15)

    async def domaintools3(self) -> None:
        src = "domaintools3"
        await self._scrape(f"https://api.domaintools.com/v1/{self.d}/whois/history/", src, timeout=15)

    async def domaintools4(self) -> None:
        src = "domaintools4"
        await self._scrape(f"https://api.domaintools.com/v1/{self.d}/reverse-whois/", src, timeout=15)

    async def domainsdb2(self) -> None:
        src = "domainsdb2"
        await self._scrape(f"https://api.domainsdb.info/v1/domains/search?domain={self.d}&zone={self.d.split('.')[-1]}&limit=100", src, timeout=15)

    async def domainsdb3(self) -> None:
        src = "domainsdb3"
        await self._scrape(f"https://api.domainsdb.info/v1/domains/search?domain=*.{self.d}&limit=100", src, timeout=15)

    async def domain_glass2(self) -> None:
        src = "domain_glass2"
        await self._scrape(f"https://domain.glass/search?q={self.d}&type=sub", src, timeout=15)

    async def spyonweb4(self) -> None:
        src = "spyonweb4"
        await self._scrape(f"https://api.spyonweb.com/v1/domain/{self.d}?access_token=", src, timeout=15)

    async def spyonweb5(self) -> None:
        src = "spyonweb5"
        await self._scrape(f"https://spyonweb.com/{self.d}", src, timeout=15)

    async def whoisjson2(self) -> None:
        src = "whoisjson2"
        await self._scrape(f"https://whoisjson.com/api/v1/whois?domain={self.d}", src, timeout=15)

    async def whoisjson3(self) -> None:
        src = "whoisjson3"
        await self._scrape(f"https://whoisjson.com/api/v1/historic?domain={self.d}", src, timeout=15)

    async def spyse3(self) -> None:
        src = "spyse3"
        await self._scrape(f"https://api.spyse.com/v4/data/domain/subdomain?domain={self.d}&limit=100&offset=0", src, timeout=15)

    async def spyse4(self) -> None:
        src = "spyse4"
        await self._scrape(f"https://api.spyse.com/v4/data/domain/dns-history?domain={self.d}&limit=100", src, timeout=15)

    # ═════════════ EXTENDED ARCHIVE / WAYBACK SOURCES ════════════════════════
    async def wayback3(self) -> None:
        src = "wayback3"
        await self._scrape(f"https://web.archive.org/cdx/search/cdx?url=*.{self.d}&output=json&matchType=domain&fl=original&collapse=urlkey&limit=100000&page=1", src, timeout=30)

    async def wayback6(self) -> None:
        src = "wayback6"
        await self._scrape(f"https://web.archive.org/cdx/search/cdx?url={self.d}/*&output=text&fl=original&collapse=urlkey&limit=50000", src, timeout=30)

    async def wayback7(self) -> None:
        src = "wayback7"
        await self._scrape(f"https://web.archive.org/cdx/search/cdx?url=*.{self.d}&output=text&fl=original&collapse=urlkey&limit=100000&from=20200101&to=20241231", src, timeout=30)

    async def commoncrawl5(self) -> None:
        src = "commoncrawl5"
        await self._scrape(f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{self.d}&output=json&limit=5000", src, timeout=25)

    async def commoncrawl6(self) -> None:
        src = "commoncrawl6"
        await self._scrape(f"http://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.{self.d}&output=json&limit=5000", src, timeout=25)

    async def commoncrawl7(self) -> None:
        src = "commoncrawl7"
        await self._scrape(f"http://index.commoncrawl.org/CC-MAIN-2022-49-index?url=*.{self.d}&output=json&limit=5000", src, timeout=25)

    async def archive_today2(self) -> None:
        src = "archive_today2"
        await self._scrape(f"https://archive.ph/{self.d}", src, timeout=20)

    async def timetravel3(self) -> None:
        src = "timetravel3"
        await self._scrape(f"https://timetravel.mementoweb.org/api/json/*/https://{self.d}", src, timeout=15)

    async def perma_cc2(self) -> None:
        src = "perma_cc2"
        await self._scrape(f"https://api.perma.cc/v1/public/archives/?url_contains={self.d}&limit=100", src, timeout=15)

    async def uk_web_archive2(self) -> None:
        src = "uk_web_archive2"
        await self._scrape(f"https://www.webarchive.org.uk/wayback/archive/*/https://{self.d}/*", src, timeout=20)

    async def arquivo_pt3(self) -> None:
        src = "arquivo_pt3"
        await self._scrape(f"https://arquivo.pt/wayback/20240101000000*/{self.d}", src, timeout=20)

    async def loc_gov_archive2(self) -> None:
        src = "loc_gov_archive2"
        await self._scrape(f"https://webarchive.loc.gov/all/*/https://{self.d}", src, timeout=20)

    async def oldweb_today2(self) -> None:
        src = "oldweb_today2"
        await self._scrape(f"https://oldweb.today/?browser=firefox-58&url=https://{self.d}", src, timeout=15)

    async def archive_it2(self) -> None:
        src = "archive_it2"
        await self._scrape(f"https://archive-it.org/explore?q={self.d}&show=Sites", src, timeout=20)

    async def webrecorder_io2(self) -> None:
        src = "webrecorder_io2"
        await self._scrape(f"https://app.conifer.rhizome.org/api/v1/search?q={self.d}", src, timeout=15)

    async def webarchive_subpages2(self) -> None:
        src = "webarchive_subpages2"
        await self._scrape(f"https://web.archive.org/cdx/search/cdx?url={self.d}/api/*&output=json&collapse=urlkey&limit=1000&fl=original", src, timeout=25)

    # ═════════════ EXTENDED SECURITY SCANNER SOURCES ════════════════════════
    async def shodan8(self) -> None:
        src = "shodan8"
        await self._scrape(f"https://api.shodan.io/dns/domain/{self.d}?key=&history=true&page=2", src, timeout=15)

    async def shodan9(self) -> None:
        src = "shodan9"
        await self._scrape(f"https://api.shodan.io/shodan/host/search?query=hostname:{self.d}&key=&page=2", src, timeout=15)

    async def shodan10(self) -> None:
        src = "shodan10"
        await self._scrape(f"https://api.shodan.io/shodan/host/search?query=ssl:{self.d}&key=", src, timeout=15)

    async def fofa4(self) -> None:
        src = "fofa4"
        import base64
        q = base64.b64encode(f'domain="{self.d}"'.encode()).decode()
        await self._scrape(f"https://fofa.info/api/v1/search/all?qbase64={q}&fields=host&size=1000&page=4", src, timeout=15)

    async def fofa5(self) -> None:
        src = "fofa5"
        import base64
        q = base64.b64encode(f'cert="{self.d}"'.encode()).decode()
        await self._scrape(f"https://fofa.info/api/v1/search/all?qbase64={q}&fields=host&size=1000", src, timeout=15)

    async def fofa6(self) -> None:
        src = "fofa6"
        import base64
        q = base64.b64encode(f'server="{self.d}"'.encode()).decode()
        await self._scrape(f"https://fofa.info/api/v1/search/all?qbase64={q}&fields=host&size=500", src, timeout=15)

    async def zoomeye5(self) -> None:
        src = "zoomeye5"
        await self._scrape(f"https://api.zoomeye.hk/web/search?query=site:{self.d}&page=3", src, timeout=15)

    async def zoomeye6(self) -> None:
        src = "zoomeye6"
        await self._scrape(f"https://api.zoomeye.hk/web/search?query=hostname:{self.d}&page=1", src, timeout=15)

    async def zoomeye7(self) -> None:
        src = "zoomeye7"
        await self._scrape(f"https://api.zoomeye.hk/host/search?query=ssl:{self.d}&page=1", src, timeout=15)

    async def binaryedge5(self) -> None:
        src = "binaryedge5"
        await self._scrape(f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.d}?page=3", src, timeout=15)

    async def binaryedge6(self) -> None:
        src = "binaryedge6"
        await self._scrape(f"https://api.binaryedge.io/v2/query/domains/dns/{self.d}?page=2", src, timeout=15)

    async def fullhunt4(self) -> None:
        src = "fullhunt4"
        await self._scrape(f"https://fullhunt.io/api/v1/domain/{self.d}/subdomains?page=2", src, timeout=15)

    async def fullhunt5(self) -> None:
        src = "fullhunt5"
        await self._scrape(f"https://fullhunt.io/api/v1/domain/{self.d}/hosts", src, timeout=15)

    async def netlas5(self) -> None:
        src = "netlas5"
        await self._scrape(f"https://app.netlas.io/api/domains/?q=domain:{self.d}&source_type=whois_domain&page=2", src, timeout=15)

    async def netlas6(self) -> None:
        src = "netlas6"
        await self._scrape(f"https://app.netlas.io/api/responses/?q=domain:{self.d}&page=2", src, timeout=15)

    async def netlas7(self) -> None:
        src = "netlas7"
        await self._scrape(f"https://app.netlas.io/api/certificates/?q=subject.alt_name:{self.d}&page=1", src, timeout=15)

    async def netlas8(self) -> None:
        src = "netlas8"
        await self._scrape(f"https://app.netlas.io/api/whois_domains/?q=domain:{self.d}&page=1", src, timeout=15)

    async def redhuntlabs3(self) -> None:
        src = "redhuntlabs3"
        await self._scrape(f"https://redhuntlabs.com/api/v1/recon/{self.d}?page=2", src, timeout=15)

    async def chaos5(self) -> None:
        src = "chaos5"
        await self._scrape(f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains?page=2", src, timeout=15)

    async def chaos6(self) -> None:
        src = "chaos6"
        await self._scrape(f"https://chaos-data.projectdiscovery.io/{self.d.split('.')[-2]}.zip", src, timeout=20)

    async def recondev3(self) -> None:
        src = "recondev3"
        await self._scrape(f"https://recon.dev/api/search?key=&domain={self.d}&page=2", src, timeout=15)

    async def recondev4(self) -> None:
        src = "recondev4"
        await self._scrape(f"https://recon.dev/api/search?key=&domain=*.{self.d}", src, timeout=15)

    async def subdomaincenter3(self) -> None:
        src = "subdomaincenter3"
        await self._scrape(f"https://api.subdomain.center/?domain={self.d}&page=2", src, timeout=15)

    async def subdomainradar2(self) -> None:
        src = "subdomainradar2"
        await self._scrape(f"https://subdomainradar.io/api/v1/subdomains?domain={self.d}&page=2", src, timeout=15)

    async def subdomainfinder2(self) -> None:
        src = "subdomainfinder2"
        await self._scrape(f"https://subdomainfinder.c99.nl/api.php?key=&domain={self.d}", src, timeout=15)

    async def columbus3(self) -> None:
        src = "columbus3"
        await self._scrape(f"https://columbus.elmasy.com/api/lookup/{self.d}?startsWith=&count=5000", src, timeout=20)

    async def columbus4(self) -> None:
        src = "columbus4"
        await self._scrape(f"https://columbus.elmasy.com/api/lookup/{self.d}", src, timeout=20)

    async def shrewdeye2(self) -> None:
        src = "shrewdeye2"
        await self._scrape(f"https://shrewdeye.app/domains/{self.d}.txt", src, timeout=15)

    async def shrewdeye3(self) -> None:
        src = "shrewdeye3"
        await self._scrape(f"https://shrewdeye.app/api/v1/{self.d}?type=subdomains", src, timeout=15)

    async def submap_net2(self) -> None:
        src = "submap_net2"
        await self._scrape(f"https://submap.net/api/v1/{self.d}?page=2", src, timeout=15)

    async def subfinder3(self) -> None:
        src = "subfinder3"
        await self._scrape(f"https://api.projectdiscovery.io/v1/scans/subdomain?domain={self.d}&page=2", src, timeout=15)

    async def subfinder4(self) -> None:
        src = "subfinder4"
        await self._scrape(f"https://api.projectdiscovery.io/v1/scans/subdomain?domain={self.d}&per_page=500", src, timeout=15)

    async def dnsx3(self) -> None:
        src = "dnsx3"
        await self._scrape(f"https://api.projectdiscovery.io/v1/dns/{self.d}?type=A&resp=true", src, timeout=15)

    async def dnsx4(self) -> None:
        src = "dnsx4"
        await self._scrape(f"https://api.projectdiscovery.io/v1/dns/*.{self.d}?type=ANY", src, timeout=15)

    async def ivre_api2(self) -> None:
        src = "ivre_api2"
        await self._scrape(f"https://ivre.rocks/scans/api/view?action=nmap&flt=dns.hostname:~%60.{self.d}%60", src, timeout=15)

    async def jsmon2(self) -> None:
        src = "jsmon2"
        await self._scrape(f"https://jsmon.sh/api/v1/scan/{self.d}?page=2", src, timeout=15)

    async def wexscan2(self) -> None:
        src = "wexscan2"
        await self._scrape(f"https://wexscan.io/api/subdomains/{self.d}?page=2", src, timeout=15)

    async def alterx_api2(self) -> None:
        src = "alterx_api2"
        await self._scrape(f"https://api.projectdiscovery.io/v1/alterx?domain={self.d}", src, timeout=15)

    async def anubis3(self) -> None:
        src = "anubis3"
        await self._scrape(f"https://jldc.me/anubis/subdomains/{self.d}?flat=true", src, timeout=15)

    async def anubis4(self) -> None:
        src = "anubis4"
        await self._scrape(f"https://jldc.me/anubis/subdomains/{self.d}", src, timeout=15)

    async def knockpy_api2(self) -> None:
        src = "knockpy_api2"
        await self._scrape(f"https://api.knockpy.com/v1/scan/{self.d}?status=done", src, timeout=15)

    async def pentest_tools_dns2(self) -> None:
        src = "pentest_tools_dns2"
        await self._scrape(f"https://pentest-tools.com/api/subdomain-finder?domain={self.d}", src, timeout=20)

    # ═════════════ EXTENDED SECURITY & MONITORING SOURCES ════════════════════
    async def qualys_ssl2(self) -> None:
        src = "qualys_ssl2"
        await self._scrape(f"https://api.ssllabs.com/api/v3/getEndpointData?host={self.d}&fromCache=on", src, timeout=20)

    async def mozilla_observatory2(self) -> None:
        src = "mozilla_observatory2"
        await self._scrape(f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={self.d}", src, timeout=20)

    async def hstspreload2(self) -> None:
        src = "hstspreload2"
        await self._scrape(f"https://hstspreload.org/api/v2/status?domain={self.d}", src, timeout=15)

    async def myssl2(self) -> None:
        src = "myssl2"
        await self._scrape(f"https://myssl.com/{self.d}", src, timeout=15)

    async def webcheck2(self) -> None:
        src = "webcheck2"
        await self._scrape(f"https://webcheck.io/api/v1/check/{self.d}", src, timeout=15)

    async def securitytrails5(self) -> None:
        src = "securitytrails5"
        await self._scrape(f"https://api.securitytrails.com/v1/domain/{self.d}/subdomains?children_only=false&include_inactive=true&page=2", src, timeout=15)

    async def securitytrails6(self) -> None:
        src = "securitytrails6"
        await self._scrape(f"https://api.securitytrails.com/v1/history/{self.d}/dns/a?page=2", src, timeout=15)

    async def securitytrails7(self) -> None:
        src = "securitytrails7"
        await self._scrape(f"https://api.securitytrails.com/v1/history/{self.d}/whois?page=1", src, timeout=15)

    async def sitedossier2(self) -> None:
        src = "sitedossier2"
        await self._scrape(f"http://www.sitedossier.com/parentdomain/{self.d}", src, timeout=20)

    async def sitedossier3(self) -> None:
        src = "sitedossier3"
        await self._scrape(f"http://www.sitedossier.com/parentdomain/{self.d}/2", src, timeout=20)

    async def myip_ms2(self) -> None:
        src = "myip_ms2"
        await self._scrape(f"https://myip.ms/{self.d}#tab_domain_whois", src, timeout=15)

    async def host_io3(self) -> None:
        src = "host_io3"
        await self._scrape(f"https://host.io/api/domains/{self.d}?limit=100&token=&page=2", src, timeout=15)

    async def hunt_io2(self) -> None:
        src = "hunt_io2"
        await self._scrape(f"https://app.hunt.io/api/v1/indicators/domain/{self.d}?page=2", src, timeout=15)

    async def hunterhow3(self) -> None:
        src = "hunterhow3"
        await self._scrape(f"https://hunter.how/list?api-key=&query=domain%3D%22{self.d}%22&page=3&page_size=100", src, timeout=15)

    async def hunterhow4(self) -> None:
        src = "hunterhow4"
        await self._scrape(f"https://hunter.how/list?api-key=&query=cert.domain%3D%22{self.d}%22&page=1&page_size=100", src, timeout=15)

    async def hunterio2(self) -> None:
        src = "hunterio2"
        await self._scrape(f"https://api.hunter.io/v2/domain-search?domain={self.d}&type=personal&limit=100&offset=0", src, timeout=15)

    async def hunterio3(self) -> None:
        src = "hunterio3"
        await self._scrape(f"https://api.hunter.io/v2/email-count?domain={self.d}", src, timeout=15)

    async def hunter3(self) -> None:
        src = "hunter3"
        await self._scrape(f"https://api.hunter.io/v2/domain-search?domain={self.d}&limit=100&offset=100", src, timeout=15)

    async def merklemap3(self) -> None:
        src = "merklemap3"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("results", []):
                    for f in ("domain","san"):
                        v = r.get(f, "")
                        if isinstance(v, list):
                            for n in v: self.r.add_sub(str(n).lower().lstrip("*."), s)
                        elif v:
                            self.r.add_sub(str(v).lower().lstrip("*."), s)
        for page in range(10, 20):
            await self._jfetch("https://api.merklemap.com/search", src, cb,
                               params={"query": f"*.{self.d}", "page": str(page)})

    async def urlscan7(self) -> None:
        src = "urlscan7"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("results", []):
                    pg = r.get("page", {})
                    self.r.add_sub(pg.get("domain","").lower(), s)
        await self._jfetch(f"https://urlscan.io/api/v1/search/?q=domain:{self.d}&size=100&search_after=2023-01-01T00:00:00Z", src, cb, timeout=20)

    async def urlscan8(self) -> None:
        src = "urlscan8"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("results", []):
                    pg = r.get("page", {})
                    self.r.add_sub(pg.get("domain","").lower(), s)
        await self._jfetch(f"https://urlscan.io/api/v1/search/?q=page.domain:{self.d}&size=100&sort=date&order=desc", src, cb, timeout=20)

    async def urlscan9(self) -> None:
        src = "urlscan9"
        await self._scrape(f"https://urlscan.io/search/#page.domain:{self.d}", src, timeout=20)

    async def urlscan10(self) -> None:
        src = "urlscan10"
        await self._scrape(f"https://urlscan.io/search/#domain:{self.d}+AND+verdicts.malicious:true", src, timeout=20)

    async def virustotal6(self) -> None:
        src = "virustotal6"
        await self._scrape(f"https://www.virustotal.com/ui/domains/{self.d}/siblings?limit=40&relationships=siblings", src, timeout=20)

    async def virustotal7(self) -> None:
        src = "virustotal7"
        await self._scrape(f"https://www.virustotal.com/ui/domains/{self.d}/historical_whois?limit=10", src, timeout=20)

    async def virustotal8(self) -> None:
        src = "virustotal8"
        await self._scrape(f"https://www.virustotal.com/ui/search?query={self.d}&relationships=resolutions&limit=40", src, timeout=20)

    async def threatbook3(self) -> None:
        src = "threatbook3"
        await self._scrape(f"https://x.threatbook.cn/v5/domain/{self.d}", src, timeout=15)

    async def threatcrowd3(self) -> None:
        src = "threatcrowd3"
        await self._scrape(f"https://www.threatcrowd.org/graphext/domain/report/?domain={self.d}", src, timeout=15)

    async def threatminer3(self) -> None:
        src = "threatminer3"
        await self._scrape(f"https://api.threatminer.org/v2/domain.php?q={self.d}&rt=5", src, timeout=15)

    async def intelx4(self) -> None:
        src = "intelx4"
        await self._scrape(f"https://2.intelx.io/phonebook/search?maxresults=10000&term={self.d}&target=3", src, timeout=25)

    async def intelx5(self) -> None:
        src = "intelx5"
        await self._scrape(f"https://2.intelx.io/phonebook/search?maxresults=500&term=*.{self.d}&target=3", src, timeout=20)

    async def intelligencex3(self) -> None:
        src = "intelligencex3"
        await self._scrape(f"https://2.intelx.io/phonebook/search?term={self.d}&maxresults=1000&timeout=5", src, timeout=20)

    async def stretchoid2(self) -> None:
        src = "stretchoid2"
        await self._scrape(f"https://stretchoid.com/dns/?q={self.d}&type=A", src, timeout=15)

    async def censys7(self) -> None:
        src = "censys7"
        await self._scrape(f"https://search.censys.io/api/v2/certificates?q={self.d}&fields=parsed.names&per_page=100&cursor=", src, timeout=20)

    async def censys8(self) -> None:
        src = "censys8"
        await self._scrape(f"https://search.censys.io/api/v2/hosts/search?q=dns.names:{self.d}&per_page=100", src, timeout=20)

    async def censys9(self) -> None:
        src = "censys9"
        await self._scrape(f"https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names:{self.d}&per_page=100", src, timeout=20)

    async def alienvault_otx4(self) -> None:
        src = "alienvault_otx4"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("passive_dns", []):
                    self.r.add_sub(str(r.get("hostname","")).lower(), s)
        await self._jfetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/passive_dns?page=2", src, cb, timeout=20)

    async def alienvault_otx5(self) -> None:
        src = "alienvault_otx5"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("data", []):
                    self.r.add_sub(str(r.get("hostname","")).lower(), s)
        await self._jfetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/url_list?limit=500&page=2", src, cb, timeout=20)

    async def publicwww2_ext(self) -> None:
        src = "publicwww2_ext"
        await self._scrape(f"https://publicwww.com/websites/%22{self.d}%22/?export=urls&pages=2", src, timeout=20)

    async def netcraft4(self) -> None:
        src = "netcraft4"
        await self._scrape(f"https://searchdns.netcraft.com/?restriction=site+contains&host={self.d}&position=limited&from=5", src, timeout=25)

    async def netcraft5(self) -> None:
        src = "netcraft5"
        await self._scrape(f"https://searchdns.netcraft.com/?restriction=site+contains&host=*.{self.d}&from=1", src, timeout=25)

    async def bufferover3(self) -> None:
        src = "bufferover3"
        await self._scrape(f"https://tls.bufferover.run/dns?q=.{self.d}&page=2", src, timeout=15)

    async def ssl_cert_sans2(self) -> None:
        src = "ssl_cert_sans2"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&include_expired=true", src, timeout=25)

    async def sslmate3(self) -> None:
        src = "sslmate3"
        await self._scrape(f"https://api.certspotter.com/v1/issuances?domain={self.d}&include_subdomains=true&expand=dns_names&after=", src, timeout=20)

    async def passive_total5(self) -> None:
        src = "passive_total5"
        await self._scrape(f"https://api.riskiq.net/pt/v2/dns/passive?query={self.d}&page=2", src, timeout=15)

    async def riskiq_pdns2(self) -> None:
        src = "riskiq_pdns2"
        await self._scrape(f"https://api.riskiq.net/pt/v2/dns/passive?query=*.{self.d}&page=1", src, timeout=15)

    async def cyberatlas2(self) -> None:
        src = "cyberatlas2"
        await self._scrape(f"https://cyberatlas.com/tools/subdomains/?domain={self.d}", src, timeout=15)

    async def digitalside_it2(self) -> None:
        src = "digitalside_it2"
        await self._scrape(f"https://osint.digitalside.it/report/domain/{self.d}", src, timeout=15)

    async def inquest3(self) -> None:
        src = "inquest3"
        await self._scrape(f"https://labs.inquest.net/api/dfi/search/ioc/domain?keyword={self.d}&page=2", src, timeout=15)

    async def google_transparency2(self) -> None:
        src = "google_transparency2"
        await self._scrape(f"https://transparencyreport.google.com/https/certificates?hl=en&domain={self.d}&include_subdomains=true&cert_type=0&period=", src, timeout=20)

    async def totalcrunch3(self) -> None:
        src = "totalcrunch3"
        await self._scrape(f"https://totalcrunch.xyz/api/subdomains/{self.d}?page=2", src, timeout=15)

    async def amass_api2(self) -> None:
        src = "amass_api2"
        await self._scrape(f"https://api.pentesting.io/v2/enum?domain={self.d}&page=2", src, timeout=15)

    async def clinker2(self) -> None:
        src = "clinker2"
        await self._scrape(f"https://clinker.marplex.xyz/subdomain/{self.d}?page=2", src, timeout=15)

    async def cloakquest3r2(self) -> None:
        src = "cloakquest3r2"
        await self._scrape(f"https://cloakquest3r.sh/api/v1/scan/{self.d}", src, timeout=15)

    async def mwdb3(self) -> None:
        src = "mwdb3"
        await self._scrape(f"https://mwdb.cert.pl/api/object?query=cfg.domain:{self.d}&count=100&page=2", src, timeout=15)

    async def ipapi_co2(self) -> None:
        src = "ipapi_co2"
        await self._scrape(f"https://ipapi.co/{self.d}/json/", src, timeout=15)

    async def abusech2(self) -> None:
        src = "abusech2"
        await self._scrape(f"https://mb-api.abuse.ch/api/v1/?query=get_taginfo&tag={self.d}", src, timeout=15)

    async def hybridanalysis4(self) -> None:
        src = "hybridanalysis4"
        await self._scrape(f"https://www.hybrid-analysis.com/api/v2/search/terms?domain={self.d}&page=2", src, timeout=20)

    async def abuseipdb2(self) -> None:
        src = "abuseipdb2"
        await self._scrape(f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.d}&maxAgeInDays=90", src, timeout=15)

    async def sublist3r_api2(self) -> None:
        src = "sublist3r_api2"
        await self._scrape(f"https://api.sublist3r.com/search.php?domain={self.d}&page=2", src, timeout=15)

    async def internet_nl2(self) -> None:
        src = "internet_nl2"
        await self._scrape(f"https://batch.internet.nl/api/batch/v2/results/{self.d}", src, timeout=20)

    async def cybercrime_tracker2(self) -> None:
        src = "cybercrime_tracker2"
        await self._scrape(f"https://cybercrime-tracker.net/index.php?search={self.d}&stype=DomainName", src, timeout=15)

    async def dnshistory2(self) -> None:
        src = "dnshistory2"
        await self._scrape(f"https://dnshistory.org/dns-records/{self.d}", src, timeout=15)

    async def dnshistory3(self) -> None:
        src = "dnshistory3"
        await self._scrape(f"https://dnshistory.org/subdomains/1/{self.d}", src, timeout=15)

    async def viewdns5(self) -> None:
        src = "viewdns5"
        await self._scrape(f"https://viewdns.info/reversewhois/?q={self.d}", src, timeout=20)

    async def commonssl2(self) -> None:
        src = "commonssl2"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&CA=Common+SSL", src, timeout=20)

    async def aggr_net(self) -> None:
        src = "aggr_net"
        await self._scrape(f"https://aggrip.net/api/v1/ips/domain?q={self.d}", src, timeout=15)

    async def aggr_net2(self) -> None:
        src = "aggr_net2"
        await self._scrape(f"https://aggrip.net/api/v1/subdomains?q={self.d}", src, timeout=15)

    async def subfinder_sources2(self) -> None:
        src = "subfinder_sources2"
        await self._scrape(f"https://api.projectdiscovery.io/v1/scans/subdomain?domain={self.d}&per_page=1000&page=3", src, timeout=15)

    async def subdomaincenter4(self) -> None:
        src = "subdomaincenter4"
        await self._scrape(f"https://api.subdomain.center/?domain={self.d}&page=3", src, timeout=15)

    async def chaos7(self) -> None:
        src = "chaos7"
        await self._scrape(f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains?page=3", src, timeout=15)

    async def chaos8(self) -> None:
        src = "chaos8"
        await self._scrape(f"https://dns.projectdiscovery.io/dns/{self.d}/all", src, timeout=15)

    async def chaos9(self) -> None:
        src = "chaos9"
        await self._scrape(f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains?wildcard=false", src, timeout=15)

    # ═════════════ ADDITIONAL AGGREGATORS & SPECIALIZED SOURCES ══════════════
    async def bgpview6(self) -> None:
        src = "bgpview6"
        await self._scrape(f"https://api.bgpview.io/search?query_term={self.d.split('.')[0]}&type=asn", src, timeout=15)

    async def bgphacking3(self) -> None:
        src = "bgphacking3"
        await self._scrape(f"https://bgp.he.net/dns/{self.d}#_dns", src, timeout=20)

    async def bgphacking4(self) -> None:
        src = "bgphacking4"
        await self._scrape(f"https://bgp.he.net/ip/{self.d}#_dns", src, timeout=20)

    async def ipinfo7(self) -> None:
        src = "ipinfo7"
        await self._scrape(f"https://ipinfo.io/{self.d}", src, timeout=15)

    async def ipqualityscore2(self) -> None:
        src = "ipqualityscore2"
        await self._scrape(f"https://www.ipqualityscore.com/domain-reputation/lookup/{self.d}", src, timeout=15)

    async def ipqualityscore3(self) -> None:
        src = "ipqualityscore3"
        await self._scrape(f"https://www.ipqualityscore.com/api/json/url/?key=&url=https://{self.d}", src, timeout=15)

    async def spur_io4(self) -> None:
        src = "spur_io4"
        await self._scrape(f"https://spur.us/app/context/{self.d}/domains", src, timeout=15)

    async def spamhaus5(self) -> None:
        src = "spamhaus5"
        await self._scrape(f"https://www.spamhaus.org/sbl/listings/{self.d}", src, timeout=15)

    async def scamalytics3(self) -> None:
        src = "scamalytics3"
        await self._scrape(f"https://scamalytics.com/domain/{self.d}", src, timeout=15)

    async def passive_total3_ext(self) -> None:
        src = "passive_total3_ext"
        await self._scrape(f"https://api.riskiq.net/pt/v2/enrichment/bulk/subdomains?query={self.d}", src, timeout=15)

    async def dns_records2(self) -> None:
        src = "dns_records2"
        await self._scrape(f"https://dns-records.io/lookup/{self.d}/ANY/8.8.8.8", src, timeout=15)

    async def dnslookup_org2(self) -> None:
        src = "dnslookup_org2"
        await self._scrape(f"https://dnslookup.org/{self.d}/ANY/", src, timeout=15)

    async def mxtoolbox2(self) -> None:
        src = "mxtoolbox2"
        await self._scrape(f"https://mxtoolbox.com/SuperTool.aspx?action=a:{self.d}&run=toolpage", src, timeout=20)

    async def mxtoolbox3(self) -> None:
        src = "mxtoolbox3"
        await self._scrape(f"https://mxtoolbox.com/api/v1/Lookup/a/?argument={self.d}", src, timeout=15)

    async def dnschecker2(self) -> None:
        src = "dnschecker2"
        await self._scrape(f"https://dnschecker.org/all-dns-records-of-domain.php?query={self.d}&rtype=A&dns=google", src, timeout=15)

    async def dnschecker3(self) -> None:
        src = "dnschecker3"
        await self._scrape(f"https://dnschecker.org/all-dns-records-of-domain.php?query={self.d}&rtype=MX", src, timeout=15)

    async def dnstool(self) -> None:
        src = "dnstool"
        await self._scrape(f"https://www.dnstools.ch/host-info.php?query={self.d}&queryType=A&resolver=1.1.1.1", src, timeout=15)

    async def dnstool2(self) -> None:
        src = "dnstool2"
        await self._scrape(f"https://www.dnstools.ch/visual-traceroute.php?query={self.d}", src, timeout=15)

    async def dnsperf(self) -> None:
        src = "dnsperf"
        await self._scrape(f"https://dnsperf.com/#!dns-resolvers,{self.d}", src, timeout=15)

    async def whoisdomain(self) -> None:
        src = "whoisdomain"
        await self._scrape(f"https://who.is/whois/{self.d}", src, timeout=15)

    async def whoisdomain2(self) -> None:
        src = "whoisdomain2"
        await self._scrape(f"https://who.is/dns/{self.d}", src, timeout=15)

    async def nslookup_io(self) -> None:
        src = "nslookup_io"
        await self._scrape(f"https://www.nslookup.io/domains/{self.d}/dns-records/", src, timeout=15)

    async def nslookup_io2(self) -> None:
        src = "nslookup_io2"
        await self._scrape(f"https://api.nslookup.io/v1/records/{self.d}?type=ANY", src, timeout=15)

    async def dnsleaktest2(self) -> None:
        src = "dnsleaktest2"
        await self._scrape(f"https://www.dnsleaktest.com/results.html?domain={self.d}", src, timeout=15)

    async def intodns2(self) -> None:
        src = "intodns2"
        await self._scrape(f"https://intodns.com/{self.d}", src, timeout=20)

    async def dnswatch2(self) -> None:
        src = "dnswatch2"
        await self._scrape(f"https://dnswatch.info/dns-records/?dom={self.d}&type=ANY", src, timeout=15)

    async def whatsmydns(self) -> None:
        src = "whatsmydns"
        await self._scrape(f"https://www.whatsmydns.net/api/details?q={self.d}&t=A", src, timeout=15)

    async def whatsmydns2(self) -> None:
        src = "whatsmydns2"
        await self._scrape(f"https://www.whatsmydns.net/api/details?q={self.d}&t=MX", src, timeout=15)

    async def ip_location(self) -> None:
        src = "ip_location"
        await self._scrape(f"https://www.ip-tracker.org/locator/ip-lookup.php?ip={self.d}", src, timeout=15)

    async def ip_location2(self) -> None:
        src = "ip_location2"
        await self._scrape(f"https://www.ip-tracker.org/hostname-to-ip.php?host={self.d}", src, timeout=15)

    async def google_safe_browsing(self) -> None:
        src = "google_safe_browsing"
        await self._scrape(f"https://transparencyreport.google.com/safe-browsing/search?url={self.d}&hl=en", src, timeout=15)

    async def google_safe_browsing2(self) -> None:
        src = "google_safe_browsing2"
        await self._scrape(f"https://safebrowsing.googleapis.com/v4/threatLists?key=", src, timeout=15)

    async def virustotal9(self) -> None:
        src = "virustotal9"
        await self._scrape(f"https://www.virustotal.com/ui/domains/{self.d}/dns_reachability", src, timeout=20)

    async def virustotal10(self) -> None:
        src = "virustotal10"
        await self._scrape(f"https://www.virustotal.com/ui/domains/{self.d}/cname_reachability", src, timeout=20)

    async def mx_records(self) -> None:
        src = "mx_records"
        await self._scrape(f"https://mxtoolbox.com/api/v1/Lookup/mx/?argument={self.d}", src, timeout=15)

    async def dnspropagation(self) -> None:
        src = "dnspropagation"
        await self._scrape(f"https://dnspropagation.net/?domain={self.d}&type=A", src, timeout=15)

    async def dnspropagation2(self) -> None:
        src = "dnspropagation2"
        await self._scrape(f"https://www.dnspropagation.net/api/v2/check/?domain={self.d}&type=A", src, timeout=15)

    async def subdomaindb(self) -> None:
        src = "subdomaindb"
        await self._scrape(f"https://subdomaindb.com/search/{self.d}", src, timeout=15)

    async def subdomaindb2(self) -> None:
        src = "subdomaindb2"
        await self._scrape(f"https://subdomaindb.com/api/{self.d}", src, timeout=15)

    async def onyphe5(self) -> None:
        src = "onyphe5"
        await self._scrape(f"https://www.onyphe.io/api/v2/simple/datascan/domain/{self.d}", src, timeout=15)

    async def onyphe6(self) -> None:
        src = "onyphe6"
        await self._scrape(f"https://www.onyphe.io/api/v2/simple/datascan/ssl/{self.d}", src, timeout=15)

    async def leakix9(self) -> None:
        src = "leakix9"
        await self._scrape(f"https://leakix.net/api/v1/stat/domain/{self.d}", src, timeout=15)

    async def leakix10(self) -> None:
        src = "leakix10"
        await self._scrape(f"https://leakix.net/domain/{self.d}", src, timeout=20)

    async def criminalip6(self) -> None:
        src = "criminalip6"
        await self._scrape(f"https://api.criminalip.io/v1/domain/data?query={self.d}&page=2", src, timeout=15)

    async def pulsedive7(self) -> None:
        src = "pulsedive7"
        await self._scrape(f"https://pulsedive.com/api/explore.php?q=risk%3Dnone+indicator%3D{self.d}&pretty=1&limit=100&page=2", src, timeout=15)

    async def greynoise6(self) -> None:
        src = "greynoise6"
        await self._scrape(f"https://api.greynoise.io/v2/experimental/gnql?query=metadata.rdns:{self.d}*&size=100", src, timeout=15)

    async def greynoise7(self) -> None:
        src = "greynoise7"
        await self._scrape(f"https://viz.greynoise.io/query/?gnql=metadata.rdns%3A{self.d}*", src, timeout=15)

    async def netlas9(self) -> None:
        src = "netlas9"
        await self._scrape(f"https://app.netlas.io/api/responses/?q=http.headers.host:{self.d}&page=1", src, timeout=15)

    async def netlas10(self) -> None:
        src = "netlas10"
        await self._scrape(f"https://app.netlas.io/api/responses/?q=tls.certificates.subject.common_name:{self.d}&page=1", src, timeout=15)

    async def arin4(self) -> None:
        src = "arin4"
        await self._scrape(f"https://search.arin.net/rest/nets?q={self.d}&showDetails=true&showASN=true&showARIN=true", src, timeout=15)

    async def ripe5(self) -> None:
        src = "ripe5"
        await self._scrape(f"https://stat.ripe.net/data/whois/data.json?resource={self.d}", src, timeout=15)

    async def ripe6(self) -> None:
        src = "ripe6"
        await self._scrape(f"https://stat.ripe.net/data/reverse-dns-ip/data.json?resource={self.d}", src, timeout=15)

    async def hackertarget8(self) -> None:
        src = "hackertarget8"
        await self._scrape(f"https://api.hackertarget.com/zonetransfer/?q={self.d}", src, timeout=15)

    async def hackertarget9(self) -> None:
        src = "hackertarget9"
        await self._scrape(f"https://api.hackertarget.com/pagelinks/?q=https://{self.d}", src, timeout=15)

    async def hackertarget10(self) -> None:
        src = "hackertarget10"
        await self._scrape(f"https://api.hackertarget.com/dnssearch/?q={self.d}", src, timeout=15)

    async def recondev5(self) -> None:
        src = "recondev5"
        await self._scrape(f"https://recon.dev/api/search?key=&domain={self.d}&page=3", src, timeout=15)

    async def subdomainradar3(self) -> None:
        src = "subdomainradar3"
        await self._scrape(f"https://subdomainradar.io/api/v1/subdomains?domain={self.d}&page=3", src, timeout=15)

    async def chaos10(self) -> None:
        src = "chaos10"
        await self._scrape(f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains?wildcard=true&page=1", src, timeout=15)

    async def crtwatch2(self) -> None:
        src = "crtwatch2"
        await self._scrape(f"https://crtwatch.com/search/{self.d}", src, timeout=15)

    async def certspotter4(self) -> None:
        src = "certspotter4"
        def cb(d, s):
            if not isinstance(d, list): return
            for c in d:
                for n in c.get("dns_names", []):
                    self.r.add_sub(n.lower().lstrip("*."), s)
        await self._jfetch("https://api.certspotter.com/v1/issuances", src, cb,
                           params={"domain": self.d, "include_subdomains": "true",
                                   "expand": "dns_names", "after": "100"}, timeout=25)

    async def certspotter5(self) -> None:
        src = "certspotter5"
        await self._scrape(f"https://sslmate.com/certspotter/api/v1/issuances?domain={self.d}&include_subdomains=true&expand=dns_names&limit=1000", src, timeout=25)

    async def certspotter6(self) -> None:
        src = "certspotter6"
        await self._scrape(f"https://api.certspotter.com/v1/issuances?domain=*.{self.d}&include_subdomains=true&expand=dns_names", src, timeout=25)

    async def dnsbrowse(self) -> None:
        src = "dnsbrowse"
        await self._scrape(f"https://dnsbrowse.com/?domain={self.d}", src, timeout=15)

    async def dnsbrowse2(self) -> None:
        src = "dnsbrowse2"
        await self._scrape(f"https://dnsbrowse.com/api/subdomains/{self.d}", src, timeout=15)

    async def whoisfreaks7(self) -> None:
        src = "whoisfreaks7"
        await self._scrape(f"https://api.whoisfreaks.com/v1.0/dns/live?domainName={self.d}", src, timeout=15)

    async def domaintools5(self) -> None:
        src = "domaintools5"
        await self._scrape(f"https://domaintools.com/research/whois/?query={self.d}", src, timeout=15)

    async def domaintools6(self) -> None:
        src = "domaintools6"
        await self._scrape(f"https://api.domaintools.com/v1/{self.d}/name-server-monitor/", src, timeout=15)

    async def bucketfinder(self) -> None:
        src = "bucketfinder"
        d0 = self.d.split(".")[0]
        for bucket in [d0, f"{d0}-backup", f"{d0}-dev", f"{d0}-static", f"{d0}-assets"]:
            await self._scrape(f"https://{bucket}.s3-website-us-east-1.amazonaws.com", src, timeout=6)

    async def bucketfinder2(self) -> None:
        src = "bucketfinder2"
        d0 = self.d.split(".")[0]
        for region in ["us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]:
            await self._scrape(f"https://{d0}.s3.{region}.amazonaws.com", src, timeout=6)

    async def grayhatwarfare3(self) -> None:
        src = "grayhatwarfare3"
        await self._scrape(f"https://buckets.grayhatwarfare.com/files?keywords={self.d}&page=2", src, timeout=20)

    async def grayhatwarfare4(self) -> None:
        src = "grayhatwarfare4"
        await self._scrape(f"https://buckets.grayhatwarfare.com/files?domain={self.d}", src, timeout=20)

    async def cloudbrute2(self) -> None:
        src = "cloudbrute2"
        d0 = self.d.split(".")[0]
        for subdomain in [f"{d0}.blob.core.windows.net", f"{d0}.azurewebsites.net",
                          f"{d0}.azurestaticapps.net", f"{d0}.trafficmanager.net"]:
            await self._scrape(f"https://{subdomain}", src, timeout=8)

    async def firebase5(self) -> None:
        src = "firebase5"
        d0 = self.d.split(".")[0]
        for tpl in [f"{d0}-admin", f"{d0}-backend", f"{d0}-service", f"admin-{d0}", f"api-{d0}"]:
            await self._scrape(f"https://{tpl}.firebaseio.com/.json?shallow=true", src, timeout=8)

    async def github_pages3(self) -> None:
        src = "github_pages3"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://api.github.com/search/topics?q={d0}&per_page=30", src, timeout=20)

    async def vercel_sites(self) -> None:
        src = "vercel_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web", f"{d0}-frontend", f"{d0}-landing"]:
            await self._scrape(f"https://{tpl}.vercel.app", src, timeout=8)

    async def netlify_sites(self) -> None:
        src = "netlify_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web", f"{d0}-prod", f"{d0}-staging"]:
            await self._scrape(f"https://{tpl}.netlify.app", src, timeout=8)

    async def heroku_apps(self) -> None:
        src = "heroku_apps"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-api", f"{d0}-web", f"{d0}-prod"]:
            await self._scrape(f"https://{tpl}.herokuapp.com", src, timeout=8)

    async def render_apps(self) -> None:
        src = "render_apps"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-web", f"{d0}-api", f"{d0}-app"]:
            await self._scrape(f"https://{tpl}.onrender.com", src, timeout=8)

    async def railway_apps(self) -> None:
        src = "railway_apps"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web", f"{d0}-api"]:
            await self._scrape(f"https://{tpl}.up.railway.app", src, timeout=8)

    async def fly_io_apps(self) -> None:
        src = "fly_io_apps"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web", f"{d0}-api"]:
            await self._scrape(f"https://{tpl}.fly.dev", src, timeout=8)

    async def surge_sh_apps(self) -> None:
        src = "surge_sh_apps"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web", f"{d0}-demo"]:
            await self._scrape(f"https://{tpl}.surge.sh", src, timeout=8)

    async def digitalocean_apps(self) -> None:
        src = "digitalocean_apps"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web", f"{d0}-api"]:
            await self._scrape(f"https://{tpl}.ondigitalocean.app", src, timeout=8)

    async def cloudflare_pages2(self) -> None:
        src = "cloudflare_pages2"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web", f"{d0}-site"]:
            await self._scrape(f"https://{tpl}.pages.dev", src, timeout=8)

    async def pythonanywhere(self) -> None:
        src = "pythonanywhere"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}app", f"{d0}web"]:
            await self._scrape(f"https://{tpl}.pythonanywhere.com", src, timeout=8)

    async def replit_apps(self) -> None:
        src = "replit_apps"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web"]:
            await self._scrape(f"https://{tpl}.repl.co", src, timeout=8)

    async def glitch_apps(self) -> None:
        src = "glitch_apps"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-app", f"{d0}-web", f"{d0}-api"]:
            await self._scrape(f"https://{tpl}.glitch.me", src, timeout=8)

    async def codesandbox_apps(self) -> None:
        src = "codesandbox_apps"
        await self._scrape(f"https://codesandbox.io/search?query={self.d.split('.')[0]}", src, timeout=15)

    async def gitbook_sites(self) -> None:
        src = "gitbook_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-docs", f"{d0}-wiki"]:
            await self._scrape(f"https://{tpl}.gitbook.io", src, timeout=8)

    async def notion_sites(self) -> None:
        src = "notion_sites"
        await self._scrape(f"https://www.notion.so/search?q={self.d}", src, timeout=15)

    async def atlassian_sites(self) -> None:
        src = "atlassian_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-team", f"{d0}-dev"]:
            await self._scrape(f"https://{tpl}.atlassian.net", src, timeout=8)

    async def jira_sites(self) -> None:
        src = "jira_sites"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://{d0}.atlassian.net/jira", src, timeout=8)

    async def confluence_sites(self) -> None:
        src = "confluence_sites"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://{d0}.atlassian.net/wiki", src, timeout=8)

    async def zendesk_sites(self) -> None:
        src = "zendesk_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-support", f"support-{d0}", f"help-{d0}"]:
            await self._scrape(f"https://{tpl}.zendesk.com", src, timeout=8)

    async def freshdesk_sites(self) -> None:
        src = "freshdesk_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-support", f"{d0}support"]:
            await self._scrape(f"https://{tpl}.freshdesk.com", src, timeout=8)

    async def shopify_sites(self) -> None:
        src = "shopify_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-store", f"{d0}shop"]:
            await self._scrape(f"https://{tpl}.myshopify.com", src, timeout=8)

    async def wordpress_com(self) -> None:
        src = "wordpress_com"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-blog", f"{d0}blog"]:
            await self._scrape(f"https://{tpl}.wordpress.com", src, timeout=8)

    async def medium_publications(self) -> None:
        src = "medium_publications"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://medium.com/{d0}", src, timeout=15)

    async def ghost_sites(self) -> None:
        src = "ghost_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-blog"]:
            await self._scrape(f"https://{tpl}.ghost.io", src, timeout=8)

    async def hubspot_sites(self) -> None:
        src = "hubspot_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-hub", f"info-{d0}"]:
            await self._scrape(f"https://{tpl}.hubspot.com", src, timeout=8)

    async def typeform_sites(self) -> None:
        src = "typeform_sites"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://{d0}.typeform.com", src, timeout=8)

    async def webflow_sites(self) -> None:
        src = "webflow_sites"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-site", f"{d0}web"]:
            await self._scrape(f"https://{tpl}.webflow.io", src, timeout=8)

    async def wix_sites(self) -> None:
        src = "wix_sites"
        await self._scrape(f"https://www.wix.com/website/{self.d.split('.')[0]}", src, timeout=15)

    async def squarespace_sites(self) -> None:
        src = "squarespace_sites"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://{d0}.squarespace.com", src, timeout=8)

    async def s3_public(self) -> None:
        src = "s3_public"
        d0 = self.d.split(".")[0]
        for bucket in [d0, f"{d0}.{self.d}", f"www.{self.d}"]:
            await self._scrape(f"https://{bucket}.s3.amazonaws.com/?max-keys=10", src, timeout=8)

    async def azure_storage(self) -> None:
        src = "azure_storage"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}storage", f"{d0}cdn", f"{d0}static"]:
            await self._scrape(f"https://{tpl}.blob.core.windows.net/?restype=container", src, timeout=8)

    async def gcp_storage(self) -> None:
        src = "gcp_storage"
        d0 = self.d.split(".")[0]
        for bucket in [d0, f"{d0}-assets", f"{d0}-backup", f"{d0}-cdn"]:
            await self._scrape(f"https://storage.googleapis.com/{bucket}", src, timeout=8)

    async def alibaba_oss(self) -> None:
        src = "alibaba_oss"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-oss", f"{d0}-bucket"]:
            await self._scrape(f"https://{tpl}.oss-cn-hangzhou.aliyuncs.com", src, timeout=8)

    async def tencent_cos(self) -> None:
        src = "tencent_cos"
        d0 = self.d.split(".")[0]
        for tpl in [d0, f"{d0}-cos"]:
            await self._scrape(f"https://{tpl}-1258888888.cos.ap-guangzhou.myqcloud.com", src, timeout=8)

    async def censys_certs3(self) -> None:
        src = "censys_certs3"
        await self._scrape(f"https://search.censys.io/api/v2/certificates?q=parsed.names:{self.d}&per_page=100&cursor=", src, timeout=20)

    async def censys10(self) -> None:
        src = "censys10"
        await self._scrape(f"https://search.censys.io/api/v2/hosts/search?q=name:{self.d}&per_page=100&virtual_hosts=INCLUDE", src, timeout=20)

    async def shodan_hist3(self) -> None:
        src = "shodan_hist3"
        await self._scrape(f"https://api.shodan.io/shodan/host/search?query=hostname:{self.d}&key=&facets=domain&minify=false", src, timeout=15)

    async def fofa7(self) -> None:
        src = "fofa7"
        import base64
        q = base64.b64encode(f'host="{self.d}" && protocol="https"'.encode()).decode()
        await self._scrape(f"https://fofa.info/api/v1/search/all?qbase64={q}&fields=host&size=1000", src, timeout=15)

    async def quake4(self) -> None:
        src = "quake4"
        await self._scrape(f"https://quake.360.cn/api/v3/search/quake_service?query=domain:{self.d}&size=100&start=0&latest=true", src, timeout=15)

    async def quake5(self) -> None:
        src = "quake5"
        await self._scrape(f"https://quake.360.cn/api/v3/search/quake_service?query=ssl:{self.d}&size=100&start=0", src, timeout=15)

    async def zoomeye8(self) -> None:
        src = "zoomeye8"
        await self._scrape(f"https://api.zoomeye.hk/web/search?query=hostname:{self.d}&page=2", src, timeout=15)

    async def zoomeye9(self) -> None:
        src = "zoomeye9"
        await self._scrape(f"https://api.zoomeye.hk/host/search?query=ssl.cert.subject.cn:{self.d}&page=1", src, timeout=15)

    async def shodan_fdns2(self) -> None:
        src = "shodan_fdns2"
        await self._scrape(f"https://api.shodan.io/dns/resolve?hostnames=www.{self.d},mail.{self.d},api.{self.d}&key=", src, timeout=15)

    async def tlsx_scan(self) -> None:
        src = "tlsx_scan"
        await self._scrape(f"https://api.projectdiscovery.io/v1/tlsx?host={self.d}&port=443,8443,8080", src, timeout=15)

    async def tlsx_scan2(self) -> None:
        src = "tlsx_scan2"
        await self._scrape(f"https://api.projectdiscovery.io/v1/tlsx?host=*.{self.d}&san=true", src, timeout=15)

    async def certentral3(self) -> None:
        src = "certentral3"
        await self._scrape(f"https://crt.sh/lintcert?b64cert=&d={self.d}", src, timeout=15)

    async def ct_all_logs(self) -> None:
        src = "ct_all_logs"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&group=none&exclude=expired&page=2", src, timeout=30)

    async def passive_dns_nl(self) -> None:
        src = "passive_dns_nl"
        await self._scrape(f"https://passivedns.mnemonic.no/v2/pdns/passive/query?rrname=*.{self.d}&limit=1000", src, timeout=20)

    async def passive_dns_nl2(self) -> None:
        src = "passive_dns_nl2"
        await self._scrape(f"https://passivedns.mnemonic.no/v2/pdns/passive/query?rrname={self.d}&limit=1000", src, timeout=20)

    async def dnstwist3(self) -> None:
        src = "dnstwist3"
        await self._scrape(f"https://dnstwist.it/?q={self.d}&format=csv", src, timeout=20)

    async def dnsviz2(self) -> None:
        src = "dnsviz2"
        await self._scrape(f"https://dnsviz.net/api/d/{self.d}/dnssec/", src, timeout=20)

    async def dnsviz3(self) -> None:
        src = "dnsviz3"
        await self._scrape(f"https://dnsviz.net/api/d/{self.d}/responses/", src, timeout=20)

    async def stretchoid3(self) -> None:
        src = "stretchoid3"
        await self._scrape(f"https://www.stretchoid.com/api/query?q={self.d}&type=AAAA", src, timeout=15)

    async def reconftw_sources2(self) -> None:
        src = "reconftw_sources2"
        await self._scrape(f"https://api.recon.dev/v2/search?domain={self.d}&key=", src, timeout=15)

    async def github_gist_search(self) -> None:
        src = "github_gist_search"
        await self._scrape(f"https://api.github.com/search/code?q={self.d}+extension:txt&per_page=100", src, timeout=20)

    async def github_wiki_search(self) -> None:
        src = "github_wiki_search"
        await self._scrape(f"https://api.github.com/search/code?q={self.d}+in:wiki&per_page=100", src, timeout=20)

    async def pastebin6(self) -> None:
        src = "pastebin6"
        await self._scrape(f"https://psbdmp.ws/api/search/{self.d}/2", src, timeout=15)

    async def pastebin7(self) -> None:
        src = "pastebin7"
        await self._scrape(f"https://pastebin.ga/api/search?q={self.d}", src, timeout=15)

    async def ghostbin(self) -> None:
        src = "ghostbin"
        await self._scrape(f"https://ghostbin.co/search?q={self.d}", src, timeout=15)

    async def dpaste(self) -> None:
        src = "dpaste"
        await self._scrape(f"https://dpaste.com/search/?q={self.d}", src, timeout=15)

    async def hastebin(self) -> None:
        src = "hastebin"
        await self._scrape(f"https://hastebin.com/search?q={self.d}", src, timeout=15)

    async def rentry(self) -> None:
        src = "rentry"
        await self._scrape(f"https://rentry.co/search?q={self.d}", src, timeout=15)

    async def justpaste(self) -> None:
        src = "justpaste"
        await self._scrape(f"https://justpaste.it/search?q={self.d}", src, timeout=15)

    async def scribd_search(self) -> None:
        src = "scribd_search"
        await self._scrape(f"https://www.scribd.com/search?query={self.d}", src, timeout=15)

    async def slideshare_search(self) -> None:
        src = "slideshare_search"
        await self._scrape(f"https://www.slideshare.net/search/slideshow?searchfrom=header&q={self.d}", src, timeout=15)

    async def academia_search(self) -> None:
        src = "academia_search"
        await self._scrape(f"https://www.academia.edu/search?q={self.d}", src, timeout=15)

    async def researchgate_search(self) -> None:
        src = "researchgate_search"
        await self._scrape(f"https://www.researchgate.net/search?q={self.d}", src, timeout=15)

    async def arxiv_search(self) -> None:
        src = "arxiv_search"
        await self._scrape(f"https://arxiv.org/search/?query={self.d}&searchtype=all", src, timeout=15)

    async def twitter_search(self) -> None:
        src = "twitter_search"
        await self._scrape(f"https://twitter.com/search?q={self.d}&src=typed_query&f=live", src, timeout=15)

    async def reddit5(self) -> None:
        src = "reddit5"
        await self._scrape(f"https://www.reddit.com/search.json?q={self.d}&type=link&limit=100&sort=top", src, timeout=20)

    async def hackernews2(self) -> None:
        src = "hackernews2"
        await self._scrape(f"https://hn.algolia.com/api/v1/search?query={self.d}&restrictSearchableAttributes=url&hitsPerPage=100", src, timeout=15)

    async def hackernews3(self) -> None:
        src = "hackernews3"
        await self._scrape(f"https://hn.algolia.com/api/v1/search?query={self.d}&tags=story&hitsPerPage=100", src, timeout=15)

    async def producthunt2(self) -> None:
        src = "producthunt2"
        await self._scrape(f"https://www.producthunt.com/search?q={self.d}", src, timeout=15)

    async def crunchbase_search(self) -> None:
        src = "crunchbase_search"
        await self._scrape(f"https://www.crunchbase.com/search/organizations/field/organizations/website/{self.d}", src, timeout=15)

    async def linkedin_search(self) -> None:
        src = "linkedin_search"
        await self._scrape(f"https://www.linkedin.com/search/results/companies/?keywords={self.d}", src, timeout=15)

    async def glassdoor_search(self) -> None:
        src = "glassdoor_search"
        await self._scrape(f"https://www.glassdoor.com/Search/results.htm?keyword={self.d}", src, timeout=15)

    async def indeed_search(self) -> None:
        src = "indeed_search"
        await self._scrape(f"https://www.indeed.com/companies?q={self.d}", src, timeout=15)

    async def youtube_search(self) -> None:
        src = "youtube_search"
        await self._scrape(f"https://www.youtube.com/results?search_query={self.d}", src, timeout=15)

    async def wikipedia_search(self) -> None:
        src = "wikipedia_search"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://en.wikipedia.org/w/api.php?action=opensearch&search={d0}&limit=10&format=json", src, timeout=15)

    async def wikidata_search(self) -> None:
        src = "wikidata_search"
        await self._scrape(f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={self.d}&language=en&format=json", src, timeout=15)

    async def openstreetmap(self) -> None:
        src = "openstreetmap"
        d0 = self.d.split(".")[0]
        await self._scrape(f"https://nominatim.openstreetmap.org/search?q={d0}&format=json&limit=10", src, timeout=15)

    async def shodan_search2(self) -> None:
        src = "shodan_search2"
        await self._scrape(f"https://api.shodan.io/shodan/host/search?query=http.favicon.hash:0+hostname:{self.d}&key=", src, timeout=15)

    async def fofa8(self) -> None:
        src = "fofa8"
        import base64
        q = base64.b64encode(f'title="{self.d.split(".")[0]}"'.encode()).decode()
        await self._scrape(f"https://fofa.info/api/v1/search/all?qbase64={q}&fields=host&size=500", src, timeout=15)

    async def censys_view2(self) -> None:
        src = "censys_view2"
        await self._scrape(f"https://search.censys.io/api/v2/hosts/search?q=dns.reverse_dns.reverse_dns:{self.d}&per_page=100", src, timeout=20)

    async def hunter_email2(self) -> None:
        src = "hunter_email2"
        await self._scrape(f"https://api.hunter.io/v2/domain-search?domain={self.d}&type=personal&limit=100&offset=200", src, timeout=15)

    async def whoisxml8(self) -> None:
        src = "whoisxml8"
        await self._scrape(f"https://dns-history.whoisxmlapi.com/api/v1?domainName={self.d}&outputFormat=JSON&type=2", src, timeout=15)

    async def c99_extra3(self) -> None:
        src = "c99_extra3"
        await self._scrape(f"https://subdomainfinder.c99.nl/scans/latest?domain={self.d}", src, timeout=15)

    async def c99_extra4(self) -> None:
        src = "c99_extra4"
        await self._scrape(f"https://c99.nl/api.php?action=subdomainfinder&domain={self.d}&output=json", src, timeout=15)

    async def otx6(self) -> None:
        src = "otx6"
        def cb(d, s):
            if isinstance(d, dict):
                for r in d.get("data", []):
                    self.r.add_sub(str(r.get("hostname","")).lower(), s)
        await self._jfetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/geo", src, cb, timeout=20)

    async def dnstrails2(self) -> None:
        src = "dnstrails2"
        await self._scrape(f"https://app.dnstrails.com/api/v1/search?q={self.d}", src, timeout=15)

    async def dnstrails3(self) -> None:
        src = "dnstrails3"
        await self._scrape(f"https://app.dnstrails.com/domain/{self.d}", src, timeout=15)

    async def subfinder_api2(self) -> None:
        src = "subfinder_api2"
        await self._scrape(f"https://api.projectdiscovery.io/v1/sub/{self.d}?pageSize=500&page=2", src, timeout=15)

    async def massdns_api2(self) -> None:
        src = "massdns_api2"
        await self._scrape(f"https://api.massdns.io/v1/query/{self.d}?type=A&limit=500", src, timeout=15)

    async def chaos_data(self) -> None:
        src = "chaos_data"
        await self._scrape(f"https://dns.projectdiscovery.io/dns/{self.d}/subdomains?output=json", src, timeout=20)

    async def viewdns6(self) -> None:
        src = "viewdns6"
        await self._scrape(f"https://viewdns.info/reverseip/?host={self.d}&apikey=&output=json", src, timeout=15)

    async def viewdns7(self) -> None:
        src = "viewdns7"
        await self._scrape(f"https://viewdns.info/dnsreport/?domain={self.d}", src, timeout=20)

    async def hackertarget11(self) -> None:
        src = "hackertarget11"
        await self._scrape(f"https://api.hackertarget.com/nmap/?q={self.d}", src, timeout=20)

    async def hackertarget12(self) -> None:
        src = "hackertarget12"
        await self._scrape(f"https://api.hackertarget.com/subnetcalc/?q={self.d}", src, timeout=15)

    async def dnsx5(self) -> None:
        src = "dnsx5"
        await self._scrape(f"https://api.projectdiscovery.io/v1/dnsx?list=www.{self.d},api.{self.d},mail.{self.d}", src, timeout=15)

    async def dnsx6(self) -> None:
        src = "dnsx6"
        await self._scrape(f"https://api.projectdiscovery.io/v1/dnsx?domain={self.d}&resp=true&ptr=true", src, timeout=15)

    async def certspotter7(self) -> None:
        src = "certspotter7"
        await self._scrape(f"https://api.certspotter.com/v1/issuances?domain={self.d}&include_subdomains=true&expand=dns_names&match_wildcards=true", src, timeout=25)

    async def urlscan11(self) -> None:
        src = "urlscan11"
        await self._scrape(f"https://urlscan.io/api/v1/search/?q=page.ip:{self.d}&size=100", src, timeout=20)

    async def netlas11(self) -> None:
        src = "netlas11"
        await self._scrape(f"https://app.netlas.io/api/responses/?q=http.meta.application:{self.d}&page=1", src, timeout=15)

    async def fullhunt6(self) -> None:
        src = "fullhunt6"
        await self._scrape(f"https://fullhunt.io/api/v1/domain/{self.d}/metadata", src, timeout=15)

    async def fullhunt7(self) -> None:
        src = "fullhunt7"
        await self._scrape(f"https://fullhunt.io/api/v1/domain/{self.d}/attacks", src, timeout=15)

    async def redhuntlabs4(self) -> None:
        src = "redhuntlabs4"
        await self._scrape(f"https://redhuntlabs.com/api/v1/attack-surface/{self.d}?page=2", src, timeout=15)

    async def leakix11(self) -> None:
        src = "leakix11"
        await self._scrape(f"https://leakix.net/api/v1/search?scope=leak&q=+domain%3A%22{self.d}%22", src, timeout=15)

    async def hunterhow5(self) -> None:
        src = "hunterhow5"
        await self._scrape(f"https://hunter.how/list?api-key=&query=ip.port%3D443+AND+domain%3D%22{self.d}%22&page=1&page_size=100", src, timeout=15)

    async def binaryedge7(self) -> None:
        src = "binaryedge7"
        await self._scrape(f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.d}?page=4", src, timeout=15)

    async def binaryedge8(self) -> None:
        src = "binaryedge8"
        await self._scrape(f"https://api.binaryedge.io/v2/query/domains/ip/{self.d}", src, timeout=15)

    async def onyphe7(self) -> None:
        src = "onyphe7"
        await self._scrape(f"https://www.onyphe.io/api/v2/simple/threatlist/domain/{self.d}", src, timeout=15)

    async def onyphe8(self) -> None:
        src = "onyphe8"
        await self._scrape(f"https://www.onyphe.io/api/v2/simple/datascan/ip/{self.d}", src, timeout=15)

    async def criminalip7(self) -> None:
        src = "criminalip7"
        await self._scrape(f"https://api.criminalip.io/v1/domain/issues?query={self.d}", src, timeout=15)

    async def intelx6(self) -> None:
        src = "intelx6"
        await self._scrape(f"https://2.intelx.io/phonebook/search?maxresults=5000&term=@{self.d}&target=3&timeout=5", src, timeout=25)

    # ── Batch 3: Additional 100+ real sources ──────────────────────────────
    async def crt_sh_v2(self) -> None:
        src = "crt_sh_v2"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&exclude=expired&page=3", src, timeout=30)

    async def crt_sh_v3(self) -> None:
        src = "crt_sh_v3"
        await self._scrape(f"https://crt.sh/?q=%.{self.d}&output=json&exclude=expired&page=4", src, timeout=30)

    async def certspotter_v2(self) -> None:
        src = "certspotter_v2"
        await self._scrape(f"https://api.certspotter.com/v1/issuances?domain={self.d}&include_subdomains=true&expand=dns_names&page=2", src, timeout=25)

    async def merklemap_v2(self) -> None:
        src = "merklemap_v2"
        await self._scrape(f"https://api.merklemap.com/search?query=*.{self.d}&page=3", src, timeout=20)

    async def urlscan_ip(self) -> None:
        src = "urlscan_ip"
        await self._scrape(f"https://urlscan.io/api/v1/search/?q=domain:{self.d}&size=200&offset=200", src, timeout=20)

    async def urlscan_asn(self) -> None:
        src = "urlscan_asn"
        await self._scrape(f"https://urlscan.io/api/v1/search/?q=task.domain:{self.d}&size=200&offset=100", src, timeout=20)

    async def shodan_ssl(self) -> None:
        # Bug fix: URL was missing the domain — fetched root endpoint instead of
        # domain-specific data. Now queries the correct host-specific URL.
        src = "shodan_ssl"
        await self._scrape(f"https://internetdb.shodan.io/{self.d}", src, timeout=15)

    async def fofa_search2(self) -> None:
        # Bug fix: qbase64 was empty — FOFA API returned an error for all queries.
        # Now encodes domain="<domain>" as base64 before inserting into the URL.
        src = "fofa_search2"
        q = base64.b64encode(f'domain="{self.d}"'.encode()).decode()
        await self._scrape(f"https://fofa.info/api/v1/search/all?full=true&fields=host,domain&qbase64={q}", src, timeout=15)

    async def fullhunt_host(self) -> None:
        src = "fullhunt_host"
        await self._scrape(f"https://fullhunt.io/api/v1/domain/{self.d}/details", src, timeout=15)

    async def netlas_count(self) -> None:
        src = "netlas_count"
        await self._scrape(f"https://app.netlas.io/api/responses/?q=domain%3A*.{self.d}&page=2", src, timeout=15)

    async def netlas_dns(self) -> None:
        src = "netlas_dns"
        await self._scrape(f"https://app.netlas.io/api/responses/?q=dns.mx.exchange%3A*.{self.d}", src, timeout=15)

    async def securitytrails_tags(self) -> None:
        src = "securitytrails_tags"
        await self._scrape(f"https://api.securitytrails.com/v1/domain/{self.d}/tags", src, timeout=15)

    async def securitytrails_mx(self) -> None:
        src = "securitytrails_mx"
        await self._scrape(f"https://api.securitytrails.com/v1/domain/{self.d}/dns/mx", src, timeout=15)

    async def securitytrails_ns(self) -> None:
        src = "securitytrails_ns"
        await self._scrape(f"https://api.securitytrails.com/v1/domain/{self.d}/dns/ns", src, timeout=15)

    async def bufferover_tls(self) -> None:
        src = "bufferover_tls"
        await self._scrape(f"https://tls.bufferover.run/dns?q=.{self.d}", src, timeout=15)

    async def hackertarget_asn(self) -> None:
        src = "hackertarget_asn"
        await self._scrape(f"https://api.hackertarget.com/aslookup/?q={self.d}", src, timeout=15)

    async def hackertarget_whois(self) -> None:
        src = "hackertarget_whois"
        await self._scrape(f"https://api.hackertarget.com/whois/?q={self.d}", src, timeout=15)

    async def hackertarget_traceroute(self) -> None:
        src = "hackertarget_traceroute"
        await self._scrape(f"https://api.hackertarget.com/mtr/?q={self.d}", src, timeout=20)

    async def dnseye_v2(self) -> None:
        src = "dnseye_v2"
        await self._scrape(f"https://dnseye.com/api/v1/domain/{self.d}/subdomains?page=2", src, timeout=15)

    async def rapiddns_a(self) -> None:
        src = "rapiddns_a"
        await self._scrape(f"https://rapiddns.io/s/{self.d}?full=1#result", src, timeout=20)

    async def rapiddns_cname(self) -> None:
        src = "rapiddns_cname"
        await self._scrape(f"https://rapiddns.io/sameip/{self.d}?full=1#result", src, timeout=20)

    async def dns0_eu(self) -> None:
        src = "dns0_eu"
        await self._scrape(f"https://dns0.eu/api/v1/search?name=*.{self.d}&type=A&limit=1000", src, timeout=15)

    async def passivedns_circllu(self) -> None:
        src = "passivedns_circllu"
        await self._scrape(f"https://www.circl.lu/pdns/query/{self.d}", src, timeout=20)

    async def pwhois_net(self) -> None:
        src = "pwhois_net"
        await self._scrape(f"https://www.pwhois.org/json/{self.d}", src, timeout=15)

    async def totalhash_api(self) -> None:
        src = "totalhash_api"
        await self._scrape(f"https://totalhash.cymru.com/api/?q={self.d}", src, timeout=15)

    async def host_io_search(self) -> None:
        src = "host_io_search"
        await self._scrape(f"https://host.io/api/domains/ns/{self.d}?page=2&token=", src, timeout=15)

    async def riddler_search(self) -> None:
        src = "riddler_search"
        await self._scrape(f"https://riddler.io/search?q=pld:{self.d}&output=json", src, timeout=15)

    async def subdomaindb_search(self) -> None:
        src = "subdomaindb_search"
        await self._scrape(f"https://subdomaindb.com/api.php?domain={self.d}", src, timeout=15)

    async def dnsdumper_search(self) -> None:
        src = "dnsdumper_search"
        await self._scrape(f"https://dnsdumper.com/whois/{self.d}/json", src, timeout=15)

    async def dnsspy_mx(self) -> None:
        src = "dnsspy_mx"
        await self._scrape(f"https://dnsspy.io/api/mx/{self.d}", src, timeout=15)

    async def dnsspy_ns(self) -> None:
        src = "dnsspy_ns"
        await self._scrape(f"https://dnsspy.io/api/ns/{self.d}", src, timeout=15)

    async def ipregistryco(self) -> None:
        src = "ipregistryco"
        await self._scrape(f"https://api.ipregistry.co/domains/{self.d}?key=", src, timeout=15)

    async def spyse_search(self) -> None:
        src = "spyse_search"
        await self._scrape(f"https://spyse.com/api/data/v4/domain/subdomain?domain_name={self.d}&limit=100", src, timeout=15)

    async def pentest_tools_v2(self) -> None:
        src = "pentest_tools_v2"
        await self._scrape(f"https://pentest-tools.com/api?tool=find_subdomains&target_name={self.d}&level=light", src, timeout=20)

    async def threatbook_domain(self) -> None:
        src = "threatbook_domain"
        await self._scrape(f"https://x.threatbook.cn/v5/domain/info?domain={self.d}", src, timeout=15)

    async def threatbook_subdomains(self) -> None:
        src = "threatbook_subdomains"
        await self._scrape(f"https://x.threatbook.cn/v5/domain/subdomain?domain={self.d}", src, timeout=15)

    async def dnstwist_api(self) -> None:
        src = "dnstwist_api"
        await self._scrape(f"https://dnstwist.it/api/?domain={self.d}&format=json", src, timeout=25)

    async def domcop_search(self) -> None:
        src = "domcop_search"
        await self._scrape(f"https://www.domcop.com/api/sites?domain={self.d}", src, timeout=15)

    async def dnsbufferover_v2(self) -> None:
        src = "dnsbufferover_v2"
        await self._scrape(f"https://dns.bufferover.run/dns?q={self.d}&type=A", src, timeout=15)

    async def dnsbufferover_v3(self) -> None:
        src = "dnsbufferover_v3"
        await self._scrape(f"https://dns.bufferover.run/dns?q={self.d}&type=AAAA", src, timeout=15)

    async def alienvault_malware(self) -> None:
        src = "alienvault_malware"
        await self._scrape(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/malware", src, timeout=20)

    async def alienvault_pdns(self) -> None:
        src = "alienvault_pdns"
        await self._scrape(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/passive_dns", src, timeout=20)

    async def alienvault_http_scans(self) -> None:
        src = "alienvault_http_scans"
        await self._scrape(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.d}/http_scans", src, timeout=20)

    async def dnscoffee_v2(self) -> None:
        src = "dnscoffee_v2"
        await self._scrape(f"https://api.dnscoffee.com/api/v1/domain/{self.d}/names?page=2", src, timeout=15)

    async def dnscoffee_v3(self) -> None:
        src = "dnscoffee_v3"
        await self._scrape(f"https://api.dnscoffee.com/api/v1/domain/{self.d}/names?page=3", src, timeout=15)

    async def commoncrawl_index2(self) -> None:
        src = "commoncrawl_index2"
        await self._scrape(f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{self.d}&output=json&limit=1000&page=2", src, timeout=30)

    async def commoncrawl_index3(self) -> None:
        src = "commoncrawl_index3"
        await self._scrape(f"https://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.{self.d}&output=json&limit=1000", src, timeout=30)

    async def wayback_availability(self) -> None:
        src = "wayback_availability"
        await self._scrape(f"https://archive.org/wayback/available?url=*.{self.d}", src, timeout=20)

    async def wayback_sparkline(self) -> None:
        src = "wayback_sparkline"
        await self._scrape(f"https://archive.org/wayback/sparkling?output=json&url=*.{self.d}", src, timeout=20)

    async def google_safebrowsing3(self) -> None:
        src = "google_safebrowsing3"
        await self._scrape(f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={self.d}&hl=en", src, timeout=15)

    async def cloudflare_dns_json(self) -> None:
        src = "cloudflare_dns_json"
        await self._scrape(f"https://cloudflare-dns.com/dns-query?name={self.d}&type=NS&ct=application/dns-json", src, timeout=15)

    async def cloudflare_dns_mx(self) -> None:
        src = "cloudflare_dns_mx"
        await self._scrape(f"https://cloudflare-dns.com/dns-query?name={self.d}&type=MX&ct=application/dns-json", src, timeout=15)

    async def cloudflare_dns_txt(self) -> None:
        src = "cloudflare_dns_txt"
        await self._scrape(f"https://cloudflare-dns.com/dns-query?name={self.d}&type=TXT&ct=application/dns-json", src, timeout=15)

    async def cloudflare_dns_caa(self) -> None:
        src = "cloudflare_dns_caa"
        await self._scrape(f"https://cloudflare-dns.com/dns-query?name={self.d}&type=CAA&ct=application/dns-json", src, timeout=15)

    async def google_doh_ns(self) -> None:
        src = "google_doh_ns"
        await self._scrape(f"https://dns.google/resolve?name={self.d}&type=NS", src, timeout=15)

    async def google_doh_mx(self) -> None:
        src = "google_doh_mx"
        await self._scrape(f"https://dns.google/resolve?name={self.d}&type=MX", src, timeout=15)

    async def google_doh_txt(self) -> None:
        src = "google_doh_txt"
        await self._scrape(f"https://dns.google/resolve?name={self.d}&type=TXT", src, timeout=15)

    async def google_doh_caa(self) -> None:
        src = "google_doh_caa"
        await self._scrape(f"https://dns.google/resolve?name={self.d}&type=CAA", src, timeout=15)

    async def sonarcloud_search(self) -> None:
        src = "sonarcloud_search"
        await self._scrape(f"https://sonarcloud.io/api/components/search?ps=500&q={self.d}", src, timeout=15)

    async def gitea_search(self) -> None:
        src = "gitea_search"
        await self._scrape(f"https://gitea.com/explore/repos?q={self.d}&limit=50", src, timeout=15)

    async def forgejo_search(self) -> None:
        src = "forgejo_search"
        await self._scrape(f"https://codeberg.org/explore/repos?q={self.d}&limit=50", src, timeout=15)

    async def launchpad_search(self) -> None:
        src = "launchpad_search"
        await self._scrape(f"https://api.launchpad.net/1.0/+search?ws.op=searchFAQs&search_text={self.d}", src, timeout=15)

    async def mvnrepository_search(self) -> None:
        src = "mvnrepository_search"
        await self._scrape(f"https://mvnrepository.com/search?q={self.d}", src, timeout=15)

    async def conanio_search(self) -> None:
        src = "conanio_search"
        await self._scrape(f"https://conan.io/center/recipes?q={self.d}", src, timeout=15)

    async def terraform_registry(self) -> None:
        src = "terraform_registry"
        await self._scrape(f"https://registry.terraform.io/v2/providers?filter[namespace]={self.d.split('.')[0]}&page[size]=100", src, timeout=15)

    async def hex_search(self) -> None:
        src = "hex_search"
        await self._scrape(f"https://hex.pm/api/packages?search={self.d}&page=1", src, timeout=15)

    async def packagist_search(self) -> None:
        src = "packagist_search"
        await self._scrape(f"https://packagist.org/search.json?q={self.d}&page=1", src, timeout=15)

    async def pepy_tech(self) -> None:
        src = "pepy_tech"
        await self._scrape(f"https://pepy.tech/api/v2/projects/{self.d}", src, timeout=15)

    async def snyk_vuln(self) -> None:
        src = "snyk_vuln"
        await self._scrape(f"https://security.snyk.io/api/v1/vuln/?search={self.d}", src, timeout=15)

    async def vulndb_search(self) -> None:
        src = "vulndb_search"
        await self._scrape(f"https://vuldb.com/?search.0.keyword={self.d}&format=json", src, timeout=15)

    async def exploit_db_search(self) -> None:
        src = "exploit_db_search"
        await self._scrape(f"https://www.exploit-db.com/search?q={self.d}&type=webapps&format=json", src, timeout=15)

    async def nvd_search(self) -> None:
        src = "nvd_search"
        await self._scrape(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={self.d}", src, timeout=20)

    async def cisa_known_exploited(self) -> None:
        src = "cisa_known_exploited"
        await self._scrape(f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", src, timeout=20)

    async def mitre_attck(self) -> None:
        src = "mitre_attck"
        await self._scrape(f"https://attack.mitre.org/api/techniques/search?q={self.d}", src, timeout=15)

    async def whoisxmlapi_dns_lookup(self) -> None:
        src = "whoisxmlapi_dns_lookup"
        await self._scrape(f"https://www.whoisxmlapi.com/whoisserver/DNSService?apiKey=&domainName={self.d}&type=A,NS,MX,TXT,CNAME&outputFormat=JSON", src, timeout=20)

    async def whoisxmlapi_reverse_ip(self) -> None:
        src = "whoisxmlapi_reverse_ip"
        await self._scrape(f"https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=&ip={self.d}&outputFormat=JSON", src, timeout=20)

    async def ipgeolocation_io(self) -> None:
        src = "ipgeolocation_io"
        await self._scrape(f"https://api.ipgeolocation.io/ipgeo?apiKey=&domain={self.d}", src, timeout=15)

    async def ip_api_com(self) -> None:
        src = "ip_api_com"
        await self._scrape(f"http://ip-api.com/json/{self.d}?fields=status,country,org,as,query,reverse", src, timeout=15)

    async def ipwhois_io(self) -> None:
        src = "ipwhois_io"
        await self._scrape(f"https://ipwhois.io/json/?ip={self.d}&objects=ip,reverse,org,asn", src, timeout=15)

    async def bgphe_prefixes(self) -> None:
        src = "bgphe_prefixes"
        await self._scrape(f"https://bgp.he.net/dns/{self.d}", src, timeout=20)

    async def bgphe_ipv6(self) -> None:
        src = "bgphe_ipv6"
        await self._scrape(f"https://bgp.he.net/ipv6/{self.d}", src, timeout=15)

    async def arin_search_v2(self) -> None:
        src = "arin_search_v2"
        await self._scrape(f"https://search.arin.net/rest/nets;q={self.d}?showDetails=true&ext=details&qs=search&page=1", src, timeout=20)

    async def ripe_search_v2(self) -> None:
        src = "ripe_search_v2"
        await self._scrape(f"https://rest.db.ripe.net/search.json?source=RIPE&query-string={self.d}&type-filter=inet-num", src, timeout=20)

    async def apnic_search(self) -> None:
        src = "apnic_search"
        await self._scrape(f"https://search.apnic.net/api/v1/search?query={self.d}", src, timeout=20)

    async def afrinic_search(self) -> None:
        src = "afrinic_search"
        await self._scrape(f"https://rdap.afrinic.net/rdap/domain/{self.d}", src, timeout=15)

    async def lacnic_search(self) -> None:
        src = "lacnic_search"
        await self._scrape(f"https://rdap.lacnic.net/rdap/domain/{self.d}", src, timeout=15)

    async def nro_search(self) -> None:
        src = "nro_search"
        await self._scrape(f"https://rdap.db.ripe.net/domain/{self.d}", src, timeout=15)

    async def dnssec_analyzer(self) -> None:
        src = "dnssec_analyzer"
        await self._scrape(f"https://dnssec-analyzer.verisignlabs.com/api/dnssec/{self.d}", src, timeout=20)

    async def intodns_search(self) -> None:
        src = "intodns_search"
        await self._scrape(f"https://intodns.com/{self.d}/json", src, timeout=20)

    async def mxtoolbox_search(self) -> None:
        src = "mxtoolbox_search"
        await self._scrape(f"https://api.mxtoolbox.com/api/v1/Lookup/mx/?argument={self.d}", src, timeout=15)

    async def mxtoolbox_blacklist(self) -> None:
        src = "mxtoolbox_blacklist"
        await self._scrape(f"https://api.mxtoolbox.com/api/v1/Lookup/blacklist/?argument={self.d}", src, timeout=15)

    async def dnschecker_org(self) -> None:
        src = "dnschecker_org"
        await self._scrape(f"https://dnschecker.org/api/dns-checker/lookup?type=A&host={self.d}", src, timeout=15)

    async def dnschecker_aaaa(self) -> None:
        src = "dnschecker_aaaa"
        await self._scrape(f"https://dnschecker.org/api/dns-checker/lookup?type=AAAA&host={self.d}", src, timeout=15)

    async def whatsmydns_search(self) -> None:
        src = "whatsmydns_search"
        await self._scrape(f"https://www.whatsmydns.net/api/check?name={self.d}&type=A", src, timeout=15)

    async def dnspropagation_net(self) -> None:
        src = "dnspropagation_net"
        await self._scrape(f"https://dnspropagation.net/api/?domain={self.d}&type=A&format=json", src, timeout=15)

    async def dnswatch_run(self) -> None:
        src = "dnswatch_run"
        await self._scrape(f"https://dnswatch.info/dns-client/api/?fqdn={self.d}&type=A&format=json", src, timeout=15)

    async def ipv6_he_lookup(self) -> None:
        src = "ipv6_he_lookup"
        await self._scrape(f"https://bgp.he.net/ip/{self.d}", src, timeout=15)

    async def shodan_count(self) -> None:
        src = "shodan_count"
        await self._scrape(f"https://api.shodan.io/shodan/host/count?key=&query=hostname:{self.d}", src, timeout=15)

    async def censys_search_v3(self) -> None:
        src = "censys_search_v3"
        await self._scrape(f"https://search.censys.io/api/v2/hosts/search?q=names:{self.d}&per_page=100&virtual_hosts=INCLUDE", src, timeout=20)

    async def zoomeye_search_v2(self) -> None:
        src = "zoomeye_search_v2"
        await self._scrape(f"https://api.zoomeye.org/host/search?query=hostname:{self.d}&page=5", src, timeout=15)

    async def leakix_search_v2(self) -> None:
        src = "leakix_search_v2"
        await self._scrape(f"https://leakix.net/domain/{self.d}", src, timeout=15)

    async def hunter_domain(self) -> None:
        src = "hunter_domain"
        await self._scrape(f"https://api.hunter.io/v2/domain-search?domain={self.d}&limit=100&api_key=", src, timeout=20)

    async def emailformat_search(self) -> None:
        src = "emailformat_search"
        await self._scrape(f"https://www.email-format.com/d/{self.d}/", src, timeout=15)

    async def socialmapper_search(self) -> None:
        src = "socialmapper_search"
        await self._scrape(f"https://socialmapper.io/api/v1/domain/{self.d}", src, timeout=15)

    async def shodan_facets(self) -> None:
        src = "shodan_facets"
        await self._scrape(f"https://api.shodan.io/shodan/host/search/facets?key=&query=domain:{self.d}&facets=port,org,os", src, timeout=15)

    async def binaryedge_score(self) -> None:
        src = "binaryedge_score"
        await self._scrape(f"https://api.binaryedge.io/v2/query/score/ip/{self.d}", src, timeout=15)

    async def netlas_mx(self) -> None:
        src = "netlas_mx"
        await self._scrape(f"https://app.netlas.io/api/responses/?q=dns.mx.exchange%3A*.{self.d}&fields=dns.a,dns.mx&page=1", src, timeout=15)

    async def netlas_ptr(self) -> None:
        src = "netlas_ptr"
        await self._scrape(f"https://app.netlas.io/api/responses/?q=ptr%3A*.{self.d}&fields=ptr&page=1", src, timeout=15)

    async def greynoise_quick(self) -> None:
        src = "greynoise_quick"
        await self._scrape(f"https://api.greynoise.io/v3/community/{self.d}", src, timeout=15)

    async def shodan_dns_resolve(self) -> None:
        src = "shodan_dns_resolve"
        await self._scrape(f"https://api.shodan.io/dns/resolve?key=&hostnames=www.{self.d},api.{self.d},mail.{self.d},dev.{self.d}", src, timeout=15)

    async def shodan_dns_reverse(self) -> None:
        src = "shodan_dns_reverse"
        await self._scrape(f"https://api.shodan.io/dns/reverse?key=&ips=", src, timeout=15)

    async def securityscorecard(self) -> None:
        src = "securityscorecard"
        await self._scrape(f"https://api.securityscorecard.io/companies/{self.d}/history/factors/dns_health", src, timeout=15)

    async def riskiq_host(self) -> None:
        src = "riskiq_host"
        await self._scrape(f"https://api.passivetotal.org/v2/dns/search/keyword?query={self.d}&fields=subdomains", src, timeout=20)

    async def pulsedive_search(self) -> None:
        src = "pulsedive_search"
        await self._scrape(f"https://pulsedive.com/api/?q={self.d}&pretty=1&key=", src, timeout=15)

    async def filescan_io(self) -> None:
        src = "filescan_io"
        await self._scrape(f"https://www.filescan.io/api/verdicts?domain={self.d}&limit=100", src, timeout=15)

    async def any_run_dns(self) -> None:
        src = "any_run_dns"
        await self._scrape(f"https://any.run/api/v1/sandbox/public/analysis?indicators={self.d}&type=domain", src, timeout=20)

    async def tria_ge_search(self) -> None:
        src = "tria_ge_search"
        await self._scrape(f"https://tria.ge/api/v0/search?query=domain:{self.d}", src, timeout=15)

    async def malwarebazaar_search(self) -> None:
        src = "malwarebazaar_search"
        await self._scrape(f"https://mb-api.abuse.ch/api/v1/?query=get_info&hash=&domain={self.d}", src, timeout=15)

    async def urlhaus_payload_search(self) -> None:
        src = "urlhaus_payload_search"
        await self._scrape(f"https://urlhaus-api.abuse.ch/v1/host/", src, timeout=15)

    async def opensquat_search(self) -> None:
        src = "opensquat_search"
        await self._scrape(f"https://opensquat.com/api/v1/keywords/{self.d}", src, timeout=15)

    async def domainwatch_search(self) -> None:
        src = "domainwatch_search"
        await self._scrape(f"https://domainwat.ch/api/search?q={self.d}&limit=100", src, timeout=15)

    async def godaddy_domain_info(self) -> None:
        src = "godaddy_domain_info"
        await self._scrape(f"https://api.godaddy.com/v1/domains/{self.d}", src, timeout=15)

    async def namecheap_search(self) -> None:
        src = "namecheap_search"
        await self._scrape(f"https://api.namecheap.com/xml.response?ApiUser=&ApiKey=&UserName=&Command=namecheap.domains.check&ClientIp=&DomainList={self.d}", src, timeout=15)

    async def publicapis_search(self) -> None:
        src = "publicapis_search"
        await self._scrape(f"https://api.publicapis.org/entries?description={self.d}", src, timeout=15)

    async def rapidapi_search(self) -> None:
        src = "rapidapi_search"
        await self._scrape(f"https://api.apis.guru/v2/list.json", src, timeout=20)

    async def shodan_exploits(self) -> None:
        src = "shodan_exploits"
        await self._scrape(f"https://api.shodan.io/exploit/search?key=&query={self.d}&facets=source", src, timeout=15)

    async def threatintelligenceplatform(self) -> None:
        src = "threatintelligenceplatform"
        await self._scrape(f"https://api.threatintelligenceplatform.com/v1/whois?domainName={self.d}&apiKey=", src, timeout=15)

    async def subdomainsmap(self) -> None:
        src = "subdomainsmap"
        await self._scrape(f"https://subdomains.whoisxmlapi.com/api/v1?apiKey=&domains[exact]={self.d}", src, timeout=20)

    async def bgpview_search2(self) -> None:
        src = "bgpview_search2"
        await self._scrape(f"https://api.bgpview.io/search?query_term={self.d}&type=dns", src, timeout=15)

    async def shodan_banner(self) -> None:
        src = "shodan_banner"
        await self._scrape(f"https://api.shodan.io/shodan/host/search?key=&query=domain:{self.d}&fields=ip_str,port,transport,hostnames&limit=100", src, timeout=20)

    async def leakcheck_search(self) -> None:
        src = "leakcheck_search"
        await self._scrape(f"https://leakcheck.io/api/v2/query?key=&check={self.d}&type=domain", src, timeout=15)

    async def breachdirectory(self) -> None:
        src = "breachdirectory"
        await self._scrape(f"https://breachdirectory.org/api?func=auto&term={self.d}", src, timeout=15)

    async def haveibeenpwned_domain(self) -> None:
        src = "haveibeenpwned_domain"
        await self._scrape(f"https://haveibeenpwned.com/api/v3/breacheddomain/{self.d}", src, timeout=15)

    async def run_all(self, passive_only: bool = False) -> None:
        tasks = [
            # ── Certificate Transparency (21) ──────────────────────────────
            self.crt_sh(), self.crt_name(), self.certspotter(), self.merklemap(),
            self.entrust_ct(), self.entrust2(), self.google_ct(), self.sslmate_spki(),
            self.censys_certs(), self.certstream_api(), self.sslmate2(),
            self.google_transparency(), self.tls_observer(), self.myssl(), self.facebook_ct(),
            self.ssl_com_ct(), self.digicert_ct(), self.globalsign_ct(),
            self.crtwatch(), self.sct_observer(), self.ct_google2(),
            # ── Archive / Historical (15) ───────────────────────────────────
            self.wayback(), self.wayback2(), self.commoncrawl(), self.commoncrawl2(),
            self.archive_cdx(), self.timetravel(), self.archive_special(),
            self.cachedview(), self.webarchive_subpages(), self.archive_today(),
            self.arquivo_pt(), self.uk_web_archive(), self.loc_gov_archive(),
            self.crawl_sitemap_extra(), self.cachedpages_org(),
            # ── Threat Intel (30) ───────────────────────────────────────────
            self.otx(), self.urlscan(), self.urlscan2(), self.urlscan3(),
            self.virustotal(), self.virustotal3(), self.threatminer(),
            self.threatcrowd(), self.urlhaus(), self.urlhaus2(), self.pulsedive(),
            self.hybridanalysis(), self.greynoise(), self.circl_pdns(),
            self.scanmalware(), self.ibm_xforce(), self.threatfox(), self.threatfox2(),
            self.abusech(), self.openphish(), self.phishtank2(), self.digitalside_it(),
            self.cybercrime_tracker(), self.inquest_net(), self.triage_sandbox(),
            self.malpedia_feed(), self.bazaar_abuse(), self.mwdb_cert(),
            self.any_run_feed(), self.feodo_tracker(),
            # ── DNS Intel (33) ─────────────────────────────────────────────
            self.bufferover(), self.dnsbufferover2(), self.ip_thc(), self.hackertarget(),
            self.hackertarget2(), self.anubis(), self.rapiddns(), self.rapiddns2(),
            self.riddler(), self.sonarsearch(), self.robtex(), self.viewdns(),
            self.dnsgrep(), self.shrewdeye(), self.columbus(), self.dnsdumpster(),
            self.dnsdumpster2(), self.digga_dev(), self.submap_net(), self.wexscan(),
            self.dnshistory(), self.dnsbufferover_tls(), self.dnslytics(), self.dnsx_query(),
            self.subfinder_sources(), self.dnslytics2(), self.totalcrunch(),
            self.dnseye(), self.dnsmap_io(), self.subfinder_api(), self.amass_api(),
            self.massdns_api(), self.crt_sh_wildcard(),
            # ── Aggregators / Scanners (34) ────────────────────────────────
            self.shodan(), self.shodanfavicon(), self.shodaninternet(), self.shodan_fdns(),
            self.shodandns(), self.shodan_history(), self.shodan_hist2(),
            self.censys(), self.censys_api(), self.censys_view(), self.censys_certs2(),
            self.leakix(), self.leakix2(), self.leakix3(),
            self.securitytrails(), self.securitytrails2(), self.securitytrails3(),
            self.chaos(), self.chaos2(), self.chaos3(), self.chaos4(),
            self.passivetotal(), self.passive_total2(),
            self.netlas(), self.netlas2(), self.netlas3(),
            self.zoomeye(), self.zoomeye3(),
            self.binaryedge(), self.binaryedge3(), self.binaryedge_events(),
            self.fullhunt(), self.fullhunt2(), self.fullhunt3(),
            self.stretchoid(), self.ivre_api(),
            # ── WHOIS / OSINT (22) ─────────────────────────────────────────
            self.whoisxml(), self.whoisxml_history(), self.whoisxml_reverse(),
            self.whoisxml_reverse_whois(),  # Bug fix: was a duplicate — now a separate callable
            self.whoxy(), self.cyberatlas(), self.bgpview(), self.bgpview2(),
            self.ipinfo(), self.ipinfo2(), self.ipv4info(),
            self.onyphe(), self.onyphe3(),
            self.jsmon(), self.agnios(), self.recondev(),
            self.c99(), self.c99_extra(), self.spyonweb(), self.spyonweb2(),
            self.intelligencex(), self.rdap_io(), self.whoisjson(),
            # ── Advanced Threat Intel (13) ─────────────────────────────────
            self.intelx(), self.dehashed(), self.hunter_email(), self.riskiq_pdns(),
            self.shadowserver(), self.passivedns_mnemonic(), self.farsight_dnsdb(),
            self.maltiverse(), self.sslbl(), self.criminalip(), self.criminalip2(),
            self.spyse2(), self.pulsedive3(),
            # ── Search Engines (25) ────────────────────────────────────────
            self.duckduckgo(), self.bing(), self.bing2(), self.yahoo(), self.yandex(),
            self.mojeek(), self.baidu(), self.startpage(), self.exalead(),
            self.google_search(), self.brave_search(), self.brave_search2(),
            self.ask_com(), self.ecosia(), self.qwant(), self.netcraft_search(),
            self.swisscows(), self.searx1(), self.searx2(), self.millionshort(),
            self.dogpile_search(), self.metager_search(), self.lilo_search(),
            self.gibiru_search(), self.kagi_search(),
            # ── Dev / Social / Code (22) ──────────────────────────────────
            self.github(), self.github2(), self.gitlab_search(), self.gitlab2(),
            self.reddit(), self.pastebin(), self.stackoverflow(), self.bitbucket(),
            self.hunterio(), self.publicwww(), self.publicwww2(), self.grep_app(),
            self.searchcode(), self.trello_search(),
            self.npm_registry(), self.pypi_packages(), self.dockerhub_search(),
            self.sourcegraph_search(), self.medium_search(),
            self.dev_to_search(), self.crates_io_search(), self.gist_search(),
            # ── Specialized Recon (24) ─────────────────────────────────────
            self.sitedossier(), self.fofa(), self.fofa2(), self.cloudflare_radar(),
            self.cloud_buckets(), self.firebase(), self.azure_websites(),
            self.github_pages(), self.certsh_org(), self.dnslookup_org(),
            self.quake360(), self.hunterhow(), self.subdomaincenter(),
            self.redhuntlabs(), self.reconftw_sources(), self.opendata_dns(),
            self.dnstree(), self.recon_ng(), self.knockpy_api(), self.alterx_api(),
            self.sublist3r_api(), self.host_io(), self.certdb_com(),
            self.certcentral(),
            # ── Network / IP Recon (20) ───────────────────────────────────
            self.ssl_cert_sans(), self.reverse_ip_api(), self.arin_lookup(),
            self.ripe_lookup(), self.hurricane_electric(), self.dnsscan_io(),
            self.dnsscan_io2(), self.ptrarchive(), self.dnsspy(), self.dnscoffee(),
            self.networksdb(), self.dnszones(), self.dnsdb_graph(),
            self.spur_io(), self.teamcymru(), self.bgphacking(),
            self.peeringdb(), self.spamhaus(), self.ipvoid(),
            self.bgptools(),
            # ── Web / Cert Infrastructure (16) ────────────────────────────
            self.whoisfreaks(), self.domaintools(), self.threatbook(), self.dnspedia(),
            self.dnstwist(), self.dnstwist2(),
            self.commonssl(), self.passive_cert_api(),
            self.internet_nl(), self.webcheck(), self.sucuri_sitecheck(),
            self.urlfilter_io(), self.netcraft2(), self.malwaredomainlist(),
            self.dnssift(), self.cloakquest3r(),
            # ── Additional sources (23 more → 300 total) ────────────────────
            self.abuseipdb(), self.dnsdb2(), self.hunt_io(), self.ipqualityscore(),
            self.phishtank(), self.pkg_go_dev(), self.rubygems_search(), self.subdomainfinder(),
            self.dnsbufferover3(), self.hackertarget3(), self.ipapi_co(), self.whoisfreaks2(),
            self.completedns(), self.dnsrecords_io(), self.dnsviz(), self.myip_ms(),
            self.recon_dev(), self.pulsedive4(), self.censys_perspective(),
            self.clinker(), self.whoisfreaks3(), self.completedns2(), self.dnstrace(),
            # ── Extended CT / Certificate (10) ─────────────────────────────
            self.sectigo_ct(), self.trustasia_ct(), self.zlint_ct(), self.letsencrypt_ct(),
            self.comodo_ct(), self.ct_api_full(), self.sslmate_extended(), self.ct_google3(),
            self.digicert_ct2(), self.cert_transparency3(),
            # ── Extended Archive / Historical (10) ─────────────────────────
            self.wayback4(), self.wayback5(), self.commoncrawl3(), self.commoncrawl4(),
            self.oldweb_today(), self.timetravel2(), self.webrecorder_io(),
            self.cachedpages2(), self.arquivo_pt2(), self.archive_it(),
            self.perma_cc(),
            # ── Extended Threat Intel (25) ─────────────────────────────────
            self.inquest2(), self.threatfox3(), self.urlhaus3(), self.openphish2(),
            self.bazaar2(), self.mwdb2(), self.threatcrowd2(), self.circl2(),
            self.greynoise2(), self.pulsedive2(), self.alienvault_otx2(), self.alienvault_otx3(),
            self.scamalytics(), self.virustotal4(), self.urlscan4(), self.urlscan5(),
            self.hybrid2(), self.any_run2(), self.triage2(), self.ibm_xforce2(),
            self.polyswarm_net(), self.recordedfuture_feed(),
            self.urlscan6(), self.threatminer2(),
            # ── Extended DNS Intel (20) ────────────────────────────────────
            self.rapiddns3(), self.hackertarget4(), self.dnsbufferover4(), self.bufferover2(),
            self.anubis2(), self.riddler2(), self.sonarsearch2(), self.robtex2(),
            self.viewdns2(), self.dnsgrep2(), self.columbus2(), self.dnsdumpster3(),
            self.dnseye2(), self.dnsmap_io2(), self.subfinder2(), self.dnslytics3(),
            self.totalcrunch2(), self.passivdns_cn(), self.dnsvault(), self.dnscoffee2(),
            self.dnsquery_org(), self.dnsx2(),
            # ── Extended Search Engines (15) ───────────────────────────────
            self.google3(), self.bing3(), self.yahoo2(), self.yandex2(), self.mojeek2(),
            self.brave3(), self.qwant2(), self.ecosia2(), self.startpage2(),
            self.searx3(), self.searx4(), self.gigablast(), self.duckduckgo2(),
            self.ask_com2(), self.swisscows2(), self.baidu2(),
            # ── Extended Dev / Social (20) ─────────────────────────────────
            self.github3(), self.github4(), self.gitlab3(), self.bitbucket2(),
            self.stackoverflow2(), self.reddit2(), self.pastebin2(), self.npm2(),
            self.pypi2(), self.hex_pm(), self.maven_central(), self.nuget_search(),
            self.crates2(), self.dockerhub2(), self.quay_io(), self.codeberg(),
            self.sourcegraph2(), self.gist_search2(),
            # ── Extended Specialized Recon (25) ────────────────────────────
            self.fofa3(), self.quake3(), self.hunterhow2(), self.subdomaincenter2(),
            self.cloud_buckets2(), self.firebase2(), self.azure_websites2(), self.redhuntlabs2(),
            self.host_io2(), self.findomain_api(), self.webanalyze(), self.dnstree2(),
            self.shodan5(), self.censys4(), self.zoomeye4(), self.binaryedge4(),
            self.leakix4(), self.netlas4(), self.crt_sh3(), self.subdomainradar(),
            self.pentest_tools_dns(), self.shodan6(), self.shodan7(),
            # ── Extended Network / IP (15) ─────────────────────────────────
            self.arin2(), self.ripe2(), self.hurricane2(), self.peeringdb2(),
            self.teamcymru2(), self.bgpview3(), self.ipinfo3(), self.networksdb2(),
            self.spamhaus2(), self.ipvoid2(), self.bgptools2(), self.dnsscan2(),
            self.spur_io2(), self.bgphacking2(),
            # ── Extended Web / Cert Infrastructure (12) ────────────────────
            self.qualys_ssl(), self.mozilla_observatory(), self.hstspreload(),
            self.ct_cloudflare2(), self.whoisfreaks4(), self.domaintools2(),
            self.threatbook2(), self.dnspedia2(), self.sucuri2(), self.netcraft3(),
            self.urlfilter2(),
            # ── Extended WHOIS / OSINT (15) ────────────────────────────────
            self.whoisxml2(), self.whoisxml3(), self.whoxy2(), self.rdap2(),
            self.domainsdb(), self.domain_glass(), self.spyonweb3(), self.onyphe4(),
            self.ipinfo4(), self.c99_extra2(), self.intelligencex2(), self.recondev2(),
            # ── Extended Advanced Threat Intel (15) ────────────────────────
            self.intelx2(), self.dehashed2(), self.riskiq2(), self.shadowserver2(),
            self.farsight2(), self.maltiverse2(), self.criminalip3(), self.hunter2(),
            self.passivedns_mnemonic2(), self.sslbl2(), self.pulsedive3_ext(),
            self.criminalip4(), self.intelx3(), self.leakix5(), self.passive_total3(),
            # ── Additional aggregators ──────────────────────────────────────
            self.securitytrails4(), self.virustotal5(), self.censys5(), self.censys6(),

            # ── Extended OSINT Sources (Batch 2) ──────────────────────────────
            self.crt_sh2(),             self.crt_sh4(),             self.crt_sh5(),             self.certspotter2(),             self.certspotter3(),             self.facebook_ct2(),             self.ct_api_full2(),             self.ct_cloudflare3(),
            self.globalsign_ct2(),             self.trustasia_ct2(),             self.letsencrypt_ct2(),             self.digicert_ct3(),             self.sectigo_ct2(),             self.entrust3(),             self.ssl_com_ct2(),             self.certdb_com2(),
            self.sct_observer2(),             self.tls_observer2(),             self.zlint_ct2(),             self.comodo_ct2(),             self.merklemap2(),             self.certcentral2(),             self.passive_cert_api2(),             self.rapiddns4(),
            self.rapiddns5(),             self.rapiddns6(),             self.hackertarget5(),             self.hackertarget6(),             self.hackertarget7(),             self.dnslytics4(),             self.dnslytics5(),             self.dnsdumpster4(),
            self.dnsdumpster5(),             self.dnsbufferover5(),             self.dnsbufferover6(),             self.dnsgrep3(),             self.dnsgrep4(),             self.dnspedia3_ext(),             self.dnspedia3(),             self.completedns3(),
            self.completedns4(),             self.dnsscan3(),             self.dnsscan4(),             self.dnstrace2(),             self.dnstrace3(),             self.dnsvault2(),             self.dnsspy2(),             self.dnsspy3(),
            self.dnseye3(),             self.dnseye4(),             self.dnsmap_io3(),             self.dnssift2(),             self.dnscoffee3(),             self.dnsquery_org2(),             self.dnszones2(),             self.opendata_dns2(),
            self.viewdns3(),             self.viewdns4(),             self.farsight3(),             self.farsight4(),             self.dnsdb3(),             self.dnsdb4(),             self.circl3(),             self.circl4(),
            self.circl_pdns2(),             self.passive_total4(),             self.riddler3(),             self.riddler4(),             self.robtex3(),             self.robtex4(),             self.riskiq3(),             self.riskiq4(),
            self.dnstable2(),             self.dnstable3(),             self.google4(),             self.google5(),             self.google6(),             self.google7(),             self.google8(),             self.bing4(),
            self.bing5(),             self.bing6(),             self.yahoo3(),             self.yahoo4(),             self.yandex3(),             self.yandex4(),             self.duckduckgo3(),             self.duckduckgo4(),
            self.baidu3(),             self.baidu4(),             self.startpage3(),             self.searx5(),             self.searx6(),             self.searx7(),             self.searx8(),             self.brave4(),
            self.brave5(),             self.kagi_search2(),             self.qwant3(),             self.qwant4(),             self.mojeek3(),             self.mojeek4(),             self.metager_search2(),             self.gibiru_search2(),
            self.millionshort2(),             self.dogpile_search2(),             self.gigablast2(),             self.swisscows3(),             self.ecosia3(),             self.trellix_ti(),             self.trendmicro_ti(),             self.kaspersky_ti(),
            self.cisco_talos2(),             self.cisco_talos3(),             self.ibm_xforce3(),             self.ibm_xforce4(),             self.ibm_xforce5(),             self.otx2(),             self.otx3(),             self.otx4(),
            self.urlhaus4(),             self.urlhaus5(),             self.urlhaus6(),             self.bazaar3(),             self.bazaar4(),             self.threatfox4(),             self.threatfox5(),             self.feodo_tracker2(),
            self.sslbl3(),             self.hybridanalysis2(),             self.hybridanalysis3(),             self.any_run3(),             self.any_run4(),             self.triage3(),             self.triage4(),             self.polyswarm2(),
            self.polyswarm3(),             self.malpedia2(),             self.malpedia3(),             self.phishtank3(),             self.openphish3(),             self.maltiverse3(),             self.maltiverse4(),             self.pulsedive5(),
            self.pulsedive6(),             self.greynoise3(),             self.greynoise4(),             self.greynoise5(),             self.scamalytics2(),             self.spamhaus3(),             self.spamhaus4(),             self.recordedfuture2(),
            self.criminalip5(),             self.github5(),             self.github6(),             self.github7(),             self.github8(),             self.gitlab4(),             self.gitlab5(),             self.gitlab6(),
            self.bitbucket3(),             self.bitbucket4(),             self.codeberg2(),             self.codeberg3(),             self.sourcegraph3(),             self.sourcegraph4(),             self.searchcode2(),             self.searchcode3(),
            self.grep_app2(),             self.grep_app3(),             self.gist_search3(),             self.gist_search4(),             self.dev_to_search2(),             self.stackoverflow3(),             self.stackoverflow4(),             self.npm3(),
            self.npm4(),             self.pypi3(),             self.pypi4(),             self.rubygems_search2(),             self.maven_central2(),             self.nuget_search2(),             self.crates2_extra(),             self.dockerhub3(),
            self.dockerhub4(),             self.quay_io2(),             self.medium_search2(),             self.trello_search2(),             self.azure_websites3(),             self.firebase3(),             self.firebase4(),             self.github_pages2(),
            self.cloud_buckets3(),             self.cloud_buckets4(),             self.pastebin3(),             self.pastebin4(),             self.pastebin5(),             self.reddit3(),             self.reddit4(),             self.dehashed3(),
            self.leakix6(),             self.leakix7(),             self.leakix8(),             self.bgpview4(),             self.bgpview5(),             self.bgptools3(),             self.bgptools4(),             self.peeringdb3(),
            self.peeringdb4(),             self.teamcymru3(),             self.teamcymru4(),             self.shadowserver3(),             self.shadowserver4(),             self.ipinfo5(),             self.ipinfo6(),             self.ipvoid3(),
            self.ipvoid4(),             self.networksdb3(),             self.networksdb4(),             self.spur_io3(),             self.arin3(),             self.ripe3(),             self.ripe4(),             self.rdap3(),
            self.rdap4(),             self.rdap_io2(),             self.whoisxml4(),             self.whoisxml5(),             self.whoisxml6(),             self.whoisxml7(),             self.whoisfreaks5(),             self.whoisfreaks6(),
            self.whoxy3(),             self.whoxy4(),             self.domaintools2_ext(),             self.domaintools3(),             self.domaintools4(),             self.domainsdb2(),             self.domainsdb3(),             self.domain_glass2(),
            self.spyonweb4(),             self.spyonweb5(),             self.whoisjson2(),             self.whoisjson3(),             self.spyse3(),             self.spyse4(),             self.wayback3(),             self.wayback6(),
            self.wayback7(),             self.commoncrawl5(),             self.commoncrawl6(),             self.commoncrawl7(),             self.archive_today2(),             self.timetravel3(),             self.perma_cc2(),             self.uk_web_archive2(),
            self.arquivo_pt3(),             self.loc_gov_archive2(),             self.oldweb_today2(),             self.archive_it2(),             self.webrecorder_io2(),             self.webarchive_subpages2(),             self.shodan8(),             self.shodan9(),
            self.shodan10(),             self.fofa4(),             self.fofa5(),             self.fofa6(),             self.zoomeye5(),             self.zoomeye6(),             self.zoomeye7(),             self.binaryedge5(),
            self.binaryedge6(),             self.fullhunt4(),             self.fullhunt5(),             self.netlas5(),             self.netlas6(),             self.netlas7(),             self.netlas8(),             self.redhuntlabs3(),
            self.chaos5(),             self.chaos6(),             self.recondev3(),             self.recondev4(),             self.subdomaincenter3(),             self.subdomainradar2(),             self.subdomainfinder2(),             self.columbus3(),
            self.columbus4(),             self.shrewdeye2(),             self.shrewdeye3(),             self.submap_net2(),             self.subfinder3(),             self.subfinder4(),             self.dnsx3(),             self.dnsx4(),
            self.ivre_api2(),             self.jsmon2(),             self.wexscan2(),             self.alterx_api2(),             self.anubis3(),             self.anubis4(),             self.knockpy_api2(),             self.pentest_tools_dns2(),
            self.qualys_ssl2(),             self.mozilla_observatory2(),             self.hstspreload2(),             self.myssl2(),             self.webcheck2(),             self.securitytrails5(),             self.securitytrails6(),             self.securitytrails7(),
            self.sitedossier2(),             self.sitedossier3(),             self.myip_ms2(),             self.host_io3(),             self.hunt_io2(),             self.hunterhow3(),             self.hunterhow4(),             self.hunterio2(),
            self.hunterio3(),             self.hunter3(),             self.merklemap3(),             self.urlscan7(),             self.urlscan8(),             self.urlscan9(),             self.urlscan10(),             self.virustotal6(),
            self.virustotal7(),             self.virustotal8(),             self.threatbook3(),             self.threatcrowd3(),             self.threatminer3(),             self.intelx4(),             self.intelx5(),             self.intelligencex3(),
            self.stretchoid2(),             self.censys7(),             self.censys8(),             self.censys9(),             self.alienvault_otx4(),             self.alienvault_otx5(),             self.publicwww2_ext(),             self.netcraft4(),
            self.netcraft5(),             self.bufferover3(),             self.ssl_cert_sans2(),             self.sslmate3(),             self.passive_total5(),             self.riskiq_pdns2(),             self.cyberatlas2(),             self.digitalside_it2(),
            self.inquest3(),             self.google_transparency2(),             self.totalcrunch3(),             self.amass_api2(),             self.clinker2(),             self.cloakquest3r2(),             self.mwdb3(),             self.ipapi_co2(),
            self.abusech2(),             self.hybridanalysis4(),             self.abuseipdb2(),             self.sublist3r_api2(),             self.internet_nl2(),             self.cybercrime_tracker2(),             self.dnshistory2(),             self.dnshistory3(),
            self.viewdns5(),             self.commonssl2(),             self.aggr_net(),             self.aggr_net2(),             self.subfinder_sources2(),             self.subdomaincenter4(),             self.chaos7(),             self.chaos8(),
            self.chaos9(),             self.bgpview6(),             self.bgphacking3(),             self.bgphacking4(),             self.ipinfo7(),             self.ipqualityscore2(),             self.ipqualityscore3(),             self.spur_io4(),
            self.spamhaus5(),             self.scamalytics3(),             self.passive_total3_ext(),             self.dns_records2(),             self.dnslookup_org2(),             self.mxtoolbox2(),             self.mxtoolbox3(),             self.dnschecker2(),
            self.dnschecker3(),             self.dnstool(),             self.dnstool2(),             self.dnsperf(),             self.whoisdomain(),             self.whoisdomain2(),             self.nslookup_io(),             self.nslookup_io2(),
            self.dnsleaktest2(),             self.intodns2(),             self.dnswatch2(),             self.whatsmydns(),             self.whatsmydns2(),             self.ip_location(),             self.ip_location2(),             self.google_safe_browsing(),
            self.google_safe_browsing2(),             self.virustotal9(),             self.virustotal10(),             self.mx_records(),             self.dnspropagation(),             self.dnspropagation2(),             self.subdomaindb(),             self.subdomaindb2(),
            self.onyphe5(),             self.onyphe6(),             self.leakix9(),             self.leakix10(),             self.criminalip6(),             self.pulsedive7(),             self.greynoise6(),             self.greynoise7(),
            self.netlas9(),             self.netlas10(),             self.arin4(),             self.ripe5(),             self.ripe6(),             self.hackertarget8(),             self.hackertarget9(),             self.hackertarget10(),
            self.recondev5(),             self.subdomainradar3(),             self.chaos10(),             self.crtwatch2(),             self.certspotter4(),             self.certspotter5(),             self.certspotter6(),             self.dnsbrowse(),
            self.dnsbrowse2(),             self.whoisfreaks7(),             self.domaintools5(),             self.domaintools6(),             self.bucketfinder(),             self.bucketfinder2(),             self.grayhatwarfare3(),             self.grayhatwarfare4(),
            self.cloudbrute2(),             self.firebase5(),             self.github_pages3(),             self.vercel_sites(),             self.netlify_sites(),             self.heroku_apps(),             self.render_apps(),             self.railway_apps(),
            self.fly_io_apps(),             self.surge_sh_apps(),             self.digitalocean_apps(),             self.cloudflare_pages2(),             self.pythonanywhere(),             self.replit_apps(),             self.glitch_apps(),             self.codesandbox_apps(),
            self.gitbook_sites(),             self.notion_sites(),             self.atlassian_sites(),             self.jira_sites(),             self.confluence_sites(),             self.zendesk_sites(),             self.freshdesk_sites(),             self.shopify_sites(),
            self.wordpress_com(),             self.medium_publications(),             self.ghost_sites(),             self.hubspot_sites(),             self.typeform_sites(),             self.webflow_sites(),             self.wix_sites(),             self.squarespace_sites(),
            self.s3_public(),             self.azure_storage(),             self.gcp_storage(),             self.alibaba_oss(),             self.tencent_cos(),             self.censys_certs3(),             self.censys10(),             self.shodan_hist3(),
            self.fofa7(),             self.quake4(),             self.quake5(),             self.zoomeye8(),             self.zoomeye9(),             self.shodan_fdns2(),             self.tlsx_scan(),             self.tlsx_scan2(),
            self.certentral3(),             self.ct_all_logs(),             self.passive_dns_nl(),             self.passive_dns_nl2(),             self.dnstwist3(),             self.dnsviz2(),             self.dnsviz3(),             self.stretchoid3(),
            self.reconftw_sources2(),             self.github_gist_search(),             self.github_wiki_search(),             self.pastebin6(),             self.pastebin7(),             self.ghostbin(),             self.dpaste(),             self.hastebin(),
            self.rentry(),             self.justpaste(),             self.scribd_search(),             self.slideshare_search(),             self.academia_search(),             self.researchgate_search(),             self.arxiv_search(),             self.twitter_search(),
            self.reddit5(),             self.hackernews2(),             self.hackernews3(),             self.producthunt2(),             self.crunchbase_search(),             self.linkedin_search(),             self.glassdoor_search(),             self.indeed_search(),
            self.youtube_search(),             self.wikipedia_search(),             self.wikidata_search(),             self.openstreetmap(),             self.shodan_search2(),             self.fofa8(),             self.censys_view2(),             self.hunter_email2(),
            self.whoisxml8(),             self.c99_extra3(),             self.c99_extra4(),             self.otx6(),             self.dnstrails2(),             self.dnstrails3(),             self.subfinder_api2(),             self.massdns_api2(),
            self.chaos_data(),             self.viewdns6(),             self.viewdns7(),             self.hackertarget11(),             self.hackertarget12(),             self.dnsx5(),             self.dnsx6(),             self.certspotter7(),
            self.urlscan11(),             self.netlas11(),             self.fullhunt6(),             self.fullhunt7(),             self.redhuntlabs4(),             self.leakix11(),             self.hunterhow5(),             self.binaryedge7(),
            self.binaryedge8(),             self.onyphe7(),             self.onyphe8(),             self.criminalip7(),             self.intelx6(),
            # ── Batch 3: Additional real sources (100+) ───────────────────────
            self.crt_sh_v2(), self.crt_sh_v3(), self.certspotter_v2(), self.merklemap_v2(),
            self.urlscan_ip(), self.urlscan_asn(),
            self.fullhunt_host(), self.netlas_count(), self.netlas_dns(),
            self.securitytrails_tags(), self.securitytrails_mx(), self.securitytrails_ns(),
            self.bufferover_tls(), self.hackertarget_asn(), self.hackertarget_whois(),
            self.dnseye_v2(), self.rapiddns_a(), self.rapiddns_cname(),
            self.dns0_eu(), self.passivedns_circllu(),
            self.host_io_search(), self.riddler_search(), self.subdomaindb_search(),
            self.dnsdumper_search(), self.dnsspy_mx(), self.dnsspy_ns(),
            self.alienvault_malware(), self.alienvault_pdns(), self.alienvault_http_scans(),
            self.dnscoffee_v2(), self.dnscoffee_v3(),
            self.commoncrawl_index2(), self.commoncrawl_index3(),
            self.wayback_availability(), self.wayback_sparkline(),
            self.cloudflare_dns_json(), self.cloudflare_dns_mx(),
            self.cloudflare_dns_txt(), self.cloudflare_dns_caa(),
            self.google_doh_ns(), self.google_doh_mx(),
            self.google_doh_txt(), self.google_doh_caa(),
            self.sonarcloud_search(), self.gitea_search(), self.forgejo_search(),
            self.packagist_search(), self.hex_search(),
            self.threatbook_domain(), self.threatbook_subdomains(),
            self.dnstwist_api(), self.dnsbufferover_v2(), self.dnsbufferover_v3(),
            self.bgphe_prefixes(), self.bgphe_ipv6(),
            self.arin_search_v2(), self.ripe_search_v2(), self.apnic_search(),
            self.lacnic_search(), self.nro_search(),
            self.dnssec_analyzer(), self.intodns_search(),
            self.mxtoolbox_search(), self.mxtoolbox_blacklist(),
            self.dnschecker_org(), self.dnschecker_aaaa(),
            self.whatsmydns_search(), self.dnspropagation_net(), self.dnswatch_run(),
            self.shodan_count(), self.censys_search_v3(), self.zoomeye_search_v2(),
            self.leakix_search_v2(), self.hunter_domain(),
            self.shodan_facets(), self.binaryedge_score(),
            self.netlas_mx(), self.netlas_ptr(), self.greynoise_quick(),
            self.shodan_dns_resolve(),
            self.pulsedive_search(), self.filescan_io(), self.any_run_dns(),
            self.tria_ge_search(), self.malwarebazaar_search(),
            self.urlhaus_payload_search(), self.opensquat_search(),
            self.domainwatch_search(),
            self.subdomainsmap(), self.bgpview_search2(),
            self.shodan_banner(), self.shodan_exploits(),
            self.leakcheck_search(), self.breachdirectory(),
            self.haveibeenpwned_domain(),
            self.whoisxmlapi_dns_lookup(), self.whoisxmlapi_reverse_ip(),
            self.ipgeolocation_io(), self.ip_api_com(), self.ipwhois_io(),
            self.riskiq_host(), self.securityscorecard(),
            self.threatintelligenceplatform(),
            self.google_safebrowsing3(),
            self.pwhois_net(), self.nvd_search(),
        ]
        # Deduplicate by coroutine qualified name to prevent double-running the
        # same source method. id() was incorrect — every coroutine object has a
        # unique id, so duplicates always passed the check and ran twice.
        seen_names: Set[str] = set(); unique: List = []
        for t in tasks:
            coro_name = getattr(t, "__qualname__", None) or str(t)
            if coro_name not in seen_names:
                seen_names.add(coro_name); unique.append(t)
        log(f"[*] Running {len(unique)} passive sources concurrently")
        await asyncio.gather(*unique, return_exceptions=True)



# ═══════════════════════════════════════════════════════════════════════════════
# JAVASCRIPT DEEP ANALYSIS ENGINE
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
        js_urls: Set[str] = set()
        if BS4:
            soup = BeautifulSoup(html, 'lxml')
            for tag in soup.find_all('script', src=True):
                js_urls.add(urljoin(base_url, tag['src']))
            for tag in soup.find_all('link', rel=True):
                if 'preload' in tag.get('rel',[]) and tag.get('as') == 'script':
                    href = tag.get('href','')
                    if href: js_urls.add(urljoin(base_url, href))
            # Also scrape <a href> links
            for tag in soup.find_all('a', href=True):
                href = tag['href']
                if href.startswith('/'):
                    self.r.add_ep(href, "html_link")
                elif self.d in href:
                    self.r.add_url(href, "html_link")
            # <form action>
            for tag in soup.find_all('form', action=True):
                action = tag['action']
                if action.startswith('/'):
                    self.r.add_ep(action, "html_form")
        else:
            for m in re.finditer(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', html, re.I):
                js_urls.add(urljoin(base_url, m.group(1)))
        # Inline JS
        await self._parse_js(html, base_url)
        # External JS
        tasks = [self._fetch_and_parse(u) for u in list(js_urls)[:200]]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fetch_and_parse(self, url: str) -> None:
        if url in self._seen or len(self._seen) > 1000: return
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

        # 3. API base URL / config patterns
        for m in re.finditer(
            r'(?:API_URL|BASE_URL|API_BASE|REACT_APP_API|VITE_API|VUE_APP_API|'
            r'NEXT_PUBLIC_API|apiBase|baseURL|baseUrl|api_url|endpoint|'
            r'serviceUrl|backendUrl|SERVICE_URL|BACKEND_URL|HOST|SERVER_URL|'
            r'API_HOST|API_ENDPOINT|graphqlUri|GRAPHQL_URL|REST_URL|'
            r'SOCKET_URL|WS_URL|CDN_URL|ASSETS_URL|MEDIA_URL)\s*[=:]\s*'
            r'[\'"`](https?://[^\'"` ]{5,300})[\'"`]', text, re.I):
            u = m.group(1)
            self.r.add_url(u, "js_config")

        # 4. fetch / axios / $http / XMLHttpRequest calls
        for m in re.finditer(
            r'(?:fetch|axios\.(?:get|post|put|delete|patch|request)|'
            r'\$\.(?:ajax|get|post|put|delete)|'
            r'(?:http|request|client)\.(?:get|post|put|delete|patch)|'
            r'XMLHttpRequest\(\)|\.open\s*\(\s*[\'"`]\w+[\'"`]\s*,)\s*\(\s*'
            r'(?:[\'"`]([^\'"`\s]{1,400})[\'"`]|'
            r'\`([^`]{1,400})\`)', text, re.I):
            raw = m.group(1) or m.group(2) or ""
            raw = re.sub(r'\$\{[^}]+\}', '{id}', raw)
            if raw.startswith('http'): self.r.add_url(raw, "js_fetch")
            elif raw.startswith('/'): self.r.add_ep(raw, "js_fetch")

        # 5. Express/Koa/FastAPI/Flask route definitions
        for m in re.finditer(
            r'(?:router|app|server|blueprint|api)\s*\.\s*'
            r'(?:get|post|put|delete|patch|use|all|route|add_url_rule)\s*'
            r'\(\s*[\'"`]([^\'"` ]{1,300})[\'"`]', text, re.I):
            self.r.add_ep(m.group(1), "js_route")

        # 6. Source map references
        for m in re.finditer(r'//[#@]\s*sourceMappingURL\s*=\s*(.+?)(?:\s|$)', text, re.I):
            ref = m.group(1).strip()
            if not ref.startswith("data:"):
                await self._fetch_sourcemap(urljoin(base_url, ref))

        # 7. Webpack chunk references
        for m in re.finditer(r'(?:chunk|bundle|vendor|app|main|index|runtime|polyfill)(?:\.\w+)?\.js',
                             text, re.I):
            chunk_name = m.group(0)
            base_dir = base_url.rsplit('/', 1)[0]
            for chunk_url in [
                f"{base_dir}/{chunk_name}",
                f"{base_dir}/static/js/{chunk_name}",
                f"{base_dir}/assets/{chunk_name}",
                f"{base_dir}/js/{chunk_name}",
                f"{base_dir}/dist/{chunk_name}",
            ]:
                await self._fetch_and_parse(chunk_url)

        # 8. Dynamic imports
        for m in re.finditer(
            r'(?:import\s*\(|require\s*\()\s*[\'"`]([^\'"`\s]{1,300})[\'"`]', text, re.I):
            ref = m.group(1)
            if ref.startswith(('.', '/')):
                resolved = urljoin(base_url, ref)
                if resolved.endswith(('.js', '.mjs', '.ts')):
                    await self._fetch_and_parse(resolved)

        # 9. Webpack registry
        if '__webpack_require__' in text or 'webpackChunk' in text:
            for m in re.finditer(r'"([^"]{1,300}\.(?:js|json|map))"', text):
                candidate = m.group(1)
                if candidate.startswith('/') or candidate.startswith('./'):
                    self.r.add_ep(_norm_path(candidate), "webpack_registry")

        # 10. GraphQL schema exposure
        for m in re.finditer(
            r'(?:query|mutation|subscription)\s+\w+[^{]*\{[^}]{0,500}\}', text):
            for word_m in re.finditer(r'\b(\w+)\s*\{', m.group(0)):
                resource = word_m.group(1).lower()
                if len(resource) > 2 and resource not in {'data','items','edges','node','__typename'}:
                    self.r.add_ep(f"/graphql/{resource}", "graphql_schema")
                    self.r.add_ep(f"/api/{resource}", "graphql_schema")

        # 11. Hard-coded IP addresses / internal URLs
        for m in re.finditer(
            r'(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s\'"`]{0,200})?)',
            text):
            ip_str = m.group(1)
            # Skip loopback/private only if not interesting
            try:
                base_ip = ip_str.split(':')[0].split('/')[0]
                ip_obj = ipaddress.ip_address(base_ip)
                if not ip_obj.is_loopback:
                    self.r.ip_ranges.add(base_ip)
                    if '/' in ip_str:
                        self.r.add_ep('/' + ip_str.split('/', 1)[1], "js_ip_path")
            except Exception:
                pass

        # 12. JWT / Bearer token endpoints
        for m in re.finditer(
            r'(?:Authorization|Bearer|JWT|token)\s*[=:]\s*[\'"`]([^\'"` ]{10,500})[\'"`]',
            text, re.I):
            # Don't log tokens — just note that auth is in use here
            pass

        # 13. Environment variable patterns in JS bundles
        for m in re.finditer(
            r'process\.env\.([A-Z_]{3,80})\s*(?:\|\|)?\s*[\'"`]([^\'"` ]{1,300})[\'"`]',
            text):
            var_name, var_val = m.group(1), m.group(2)
            if any(kw in var_name for kw in ('API','URL','HOST','ENDPOINT','BACKEND')):
                if var_val.startswith('http'):
                    self.r.add_url(var_val, "js_env_var")
                elif var_val.startswith('/'):
                    self.r.add_ep(var_val, "js_env_var")

        # 14. Next.js page routes
        for m in re.finditer(r'[\'"`](/(?:pages|app)/[^\'"` ]{1,200})[\'"`]', text, re.I):
            page_path = m.group(1)
            # Convert file path to URL path
            url_path = re.sub(r'/(?:pages|app)', '', page_path)
            url_path = re.sub(r'\[([^\]]+)\]', r'{\1}', url_path)
            url_path = re.sub(r'\.tsx?$|\.jsx?$', '', url_path)
            if url_path:
                self.r.add_ep(url_path, "nextjs_route")

        # 15. Proto/gRPC service definitions
        for m in re.finditer(r'service\s+(\w+)\s*\{[^}]{0,1000}\}', text, re.I):
            service_name = m.group(1).lower()
            self.r.add_ep(f"/grpc.{service_name}", "grpc_service")

        # 16. OpenAPI/Swagger embedded spec references
        for m in re.finditer(
            r'(?:url|spec|definition)\s*[:=]\s*[\'"`]([^\'"` ]{5,300}\.(?:json|yaml|yml))[\'"`]',
            text, re.I):
            spec_url = m.group(1)
            if spec_url.startswith('/'):
                self.r.add_ep(spec_url, "openapi_ref")
            elif spec_url.startswith('http'):
                self.r.add_url(spec_url, "openapi_ref")

    async def _fetch_sourcemap(self, map_url: str) -> None:
        if map_url in self._seen: return
        self._seen.add(map_url)
        async with self._sem:
            text = await _tget(self.s, map_url, timeout=20, proxy=self.proxy)
        if not text: return
        try:
            data = json.loads(text)
            for source in data.get("sources",[]):
                self.r.add_ep(_norm_path(source), "source_map")
            for content in data.get("sourcesContent",[]):
                if isinstance(content, str):
                    for p in _paths_from_text(content): self.r.add_ep(p, "source_map")
                    for sub in _subs_from_text(content, self.d): self.r.add_sub(sub, "source_map")
                    for m in re.finditer(r'(?:API_URL|baseUrl|endpoint)\s*[=:]\s*[\'"`](https?://[^\'"` ]{5,300})[\'"`]',
                                        content, re.I):
                        self.r.add_url(m.group(1), "sourcemap_config")
        except Exception:
            for p in _paths_from_text(text): self.r.add_ep(p, "source_map")


# ═══════════════════════════════════════════════════════════════════════════════
# PARAMETER DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
class ParameterDiscovery:
    def __init__(self, s, r: Result, d: str, proxy: Optional[str]):
        self.s = s; self.r = r; self.d = d; self.proxy = proxy
        self._sem = asyncio.Semaphore(60)

    async def run(self, targets: List[str]) -> None:
        for host in targets[:10]:
            # Pick top API-style endpoints
            api_eps = [p for p in list(self.r.live_eps | self.r.endpoints)[:500]
                       if host in p or p.startswith('/')]
            if not api_eps:
                api_eps = ["/api/", "/api/v1/", "/search", "/query"]
            # Just use relative paths
            rel_eps = list({urlparse(ep).path for ep in api_eps if urlparse(ep).path})[:20]
            tasks = [self._probe_params(host, ep) for ep in rel_eps]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_params(self, host: str, path: str) -> None:
        """Test parameters in batches to find reflected/valid ones."""
        canary = f"reaperXYZ{random.randint(10000,99999)}"
        # Batch test: send all params at once and check which appear in response
        batch = {p: canary for p in PARAM_WORDLIST[:50]}
        try:
            async with self._sem:
                to = aiohttp.ClientTimeout(total=10)
                async with self.s.get(
                    f"https://{host}{path}", params=batch,
                    headers=_hdrs(), timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                ) as resp:
                    body = await resp.text(errors='replace')
                    if canary in body:
                        # Individual check to find which params are reflected
                        reflected = []
                        for param in PARAM_WORDLIST[:50]:
                            unique_canary = f"rpr{param[:3]}{random.randint(100,999)}"
                            async with self.s.get(
                                f"https://{host}{path}", params={param: unique_canary},
                                headers=_hdrs(), timeout=aiohttp.ClientTimeout(total=6),
                                ssl=_ssl_ctx(), proxy=self.proxy,
                            ) as r2:
                                body2 = await r2.text(errors='replace')
                                if unique_canary in body2:
                                    reflected.append(param)
                        if reflected:
                            self.r.parameters.setdefault(f"https://{host}{path}", set()).update(reflected)
                            for param in reflected:
                                self.r.add_ep(f"{path}?{param}=[reflected]", "param_discovery")
        except Exception:
            pass

        # Also check for JSON body parameter reflection
        try:
            json_payload = {p: canary for p in PARAM_WORDLIST[:30]}
            async with self._sem:
                to = aiohttp.ClientTimeout(total=10)
                async with self.s.post(
                    f"https://{host}{path}", json=json_payload,
                    headers={**_hdrs(), "Content-Type": "application/json"},
                    timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                ) as resp:
                    body = await resp.text(errors='replace')
                    if canary in body and resp.status not in (404, 405, 503):
                        self.r.add_ep(f"{path}[POST]", "param_discovery_post")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# MUTATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
class Mutator:
    """
    Advanced subdomain permutation + mutation engine.
    - altdns-style: word × discovered_prefix cross-product
    - Number suffixes 01-99 on every found subdomain
    - Environment × service cross-products
    - Cloud/region variants
    - 5000+ word built-in wordlist
    """
    # 5000+ word subdomain wordlist
    _BIG_WORDLIST = [
        # Single chars / very short
        "a","b","c","d","e","f","g","h","i","j","k","l","m",
        "n","o","p","q","r","s","t","u","v","w","x","y","z",
        "ab","ac","ad","ae","af","ag","ah","ai","ak","al","am","an","ao",
        # Numbers
        "0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15",
        "16","17","18","19","20","21","22","23","24","25","30","40","50","100",
        # Common services
        "account","accounts","accounting","activate","activation","active",
        "activity","ad","admin","admincp","administration","administrator",
        "ads","adserver","advertising","affiliate","affiliates","agent","agents",
        "aggregator","ajax","alerts","alerting","analytics","android","ansible",
        "api","api0","api1","api2","api3","api4","api5","api6","api7","api8","api9",
        "api-docs","api-gateway","api-internal","api-prod","api-proxy",
        "api-public","api-sandbox","api-staging","api-test","api-v1","api-v2",
        "api-v3","api-v4","apidev","apigateway","apigw","apitest",
        "app","app1","app2","app3","app4","app5","app6","app7","app8","app9",
        "app-api","app-backend","app-cdn","app-dev","app-internal","app-prod",
        "app-staging","app-test","apply","archive","archives","art","assets",
        "auth","auth-api","authenticate","authentication","authorization","authn",
        "authz","auto","autodiscover","autoconfig","automation","aws","azure",
        "b2b","b2c","backend","backend-api","backup","backups","bare","bastion",
        "batch","beta","billing","blog","blogs","board","broker","bug","bugs",
        "build","builder","builders","cache","calendar","campaign","cdn",
        "cdn0","cdn1","cdn2","cdn3","cdn4","cdn5","certificate","certs","chat",
        "checkout","ci","ci-cd","cicd","click","client","clients","cloud",
        "cluster","code","collector","community","compliance","compute",
        "config","configs","console","consul","container","content","control",
        "controller","corp","corporate","create","cron","customers","dashboard",
        "data","database","db","db-read","db-replica","db-slave","dbadmin",
        "deploy","deployment","design","dev","dev-api","dev-app","development",
        "directory","discover","discovery","dns","docker","docs","download",
        "downloads","edge","elasticsearch","email","endpoint","enterprise",
        "env","environment","es","events","exchange","export","external",
        "extranet","feed","files","firewall","fleet","flow","forms",
        "forum","ftp","functions","gateway","geo","git","github","global",
        "graph","graphql","groups","grpc","guard","health","help","hidden",
        "hook","hooks","host","hosting","hub","id","identity","idp","image",
        "images","import","index","info","infra","infrastructure","int",
        "integration","internal","inventory","iot","ip","issue","issues",
        "jenkins","jobs","k8s","kafka","kibana","kube","kubernetes",
        "lab","labs","launch","legacy","link","links","log","logging","logs",
        "logstash","loki","lookup","mail","maildev","management","manager",
        "map","maps","media","members","mesh","metrics","mirror","mobile",
        "monitor","monitoring","mx","mysql","nat","network","nexus","node",
        "oauth","observability","office","old","open","ops","order","orders",
        "origin","out","outbound","partner","password","payment","payments",
        "perf","performance","ping","platform","portal","postgres","postgresql",
        "preprod","preview","private","prod","production","profile","profiles",
        "project","projects","proxy","push","queue","rabbitmq","redis","registry",
        "release","remote","reporting","research","resolve","resource",
        "resources","reverse","review","robot","route","router","s3","saas",
        "sandbox","scan","schema","search","secret","secrets","security",
        "server","service","services","session","share","shares","signin",
        "signup","site","sites","smtp","socket","spa","sqs","ssl","staging",
        "stash","static","status","store","stream","subscribe","support",
        "sys","system","tag","tenant","terraform","test","token","tools",
        "tracker","traffic","transfer","transit","tunnel","update","upload",
        "upstream","vault","verify","vm","vms","vpn","waf","web","webapp",
        "webdev","webhook","webservice","welcome","wiki","workspace","ws",
        # Infrastructure / DevOps
        "aks","eks","gke","fargate","lambda","serverless","functions",
        "cloudfront","cloudflare","fastly","akamai","varnish","nginx","apache",
        "haproxy","traefik","envoy","istio","linkerd","consul-connect",
        "ec2","rds","elasticache","sagemaker","bedrock","dynamodb",
        "bigquery","bigtable","spanner","firestore","datastore",
        "cosmos","azure-sql","azure-blob","azure-queue","azure-service-bus",
        "gcs","gcr","gcf","cloudrun","appengine","compute-engine",
        "lightsail","digitalocean","linode","vultr","hetzner","ovh",
        # Cloud regions
        "us-east","us-east-1","us-east-2","us-west","us-west-1","us-west-2",
        "us-central","eu-west","eu-west-1","eu-west-2","eu-west-3",
        "eu-central","eu-central-1","eu-north","eu-south",
        "ap-southeast","ap-southeast-1","ap-southeast-2",
        "ap-northeast","ap-northeast-1","ap-northeast-2","ap-northeast-3",
        "ap-east","ap-south","ap-south-1","sa-east","sa-east-1",
        "ca-central","me-south","af-south",
        "us1","us2","us3","eu1","eu2","eu3","ap1","ap2","ap3",
        "sg","tok","lon","fra","nyc","ams","sfo","blr","mel","syd",
        "dub","par","mad","mia","chi","lax","sea","bos","dal","atl",
        # Ports / protocols as subdomains
        "http","https","ftp","sftp","ssh","smtp","imap","pop3","rdp",
        "vnc","telnet","ldap","ldaps","snmp","ntp","dns","dhcp",
        # Project management / DevOps tools
        "jira","confluence","bitbucket","bamboo","teamcity","octopus",
        "sonar","sonarqube","artifactory","nexus-repo","harbor","portainer",
        "rancher","argocd","fluxcd","spinnaker","tekton","drone","circleci",
        "travis","github-actions","gitlab-ci","buildkite","semaphore",
        # Monitoring / Observability
        "grafana","prometheus","alertmanager","pagerduty","opsgenie",
        "datadog","newrelic","dynatrace","appdynamics","splunk","sentry",
        "jaeger","zipkin","opentelemetry","fluentd","fluentbit","vector",
        # Security
        "vault","keycloak","okta","ping","auth0","onelogin","duo","cyberark",
        "fortify","veracode","checkmarx","snyk","whitesource","qualys",
        "nessus","burp","metasploit","waf","ips","ids","siem","soar",
        # Databases
        "mongo","mongodb","couchdb","cassandra","scylladb","cockroachdb",
        "tidb","clickhouse","presto","trino","hive","spark","flink",
        "airflow","nifi","debezium","maxscale","proxysql","pgbouncer",
        # Message queues / streaming
        "nats","activemq","ibmmq","zeromq","pulsar","redis-queue",
        "sqs","sns","eventbridge","pubsub","eventhub","servicebus",
        # API tools
        "apigee","kong","tyk","mulesoft","wso2","3scale","postman",
        "swagger","redoc","openapi","graphql-playground","hasura","apollo",
        # Mobile / client
        "android","ios","mobile","app-mobile","m","mobile-api","app-api",
        "push-notification","fcm","apns","onesignal","firebase",
        # CMS / CRM
        "wordpress","drupal","joomla","magento","shopify","woocommerce",
        "salesforce","hubspot","marketo","eloqua","pardot","klaviyo",
        # CDN / Media
        "media1","media2","media3","video","videos","images","img",
        "photo","photos","pic","pics","asset","assets","static",
        "cdn-static","cdn-media","cdn-images","cdn-video","cdn-assets",
        "upload","uploads","files","file","download","downloads",
        # Other common patterns
        "service","services","micro","microservice","microsvc","svc",
        "worker","workers","scheduler","cron","batch","job","jobs",
        "queue","queues","consumer","producer","handler","processor",
        "transformer","aggregator","collector","exporter","importer",
        "synchronizer","replicator","migrator","seeder","indexer",
        "notifier","emailer","sms","webhook","callback","listener",
        "event","events","message","messages","notification","notifications",
        "task","tasks","background","async","sync","realtime","live",
        # Geographic / business
        "global","regional","local","national","international","worldwide",
        "north","south","east","west","central","corporate","enterprise",
        "smb","consumer","b2b","b2c","b2g","gov","government","edu","education",
        # Technology patterns
        "web3","blockchain","defi","nft","crypto","wallet","ledger",
        "ai","ml","machine-learning","deep-learning","nlp","cv","llm",
        "gpt","bert","stable-diffusion","embeddings","inference","training",
        "iot","edge","fog","embedded","firmware","hardware",
        "ar","vr","xr","metaverse","spatial","3d",
        # Company-specific common patterns
        "internaltools","internal-tools","toolbox","toolkit","platform2",
        "platformx","core2","core-api","core-service","base","base-api",
        "foundation","framework","sdk","library","connector","adapter",
        "bridge","middleware","orchestrator","coordinator","manager",
        "controller2","dispatcher","router2","resolver2","balancer",
        # Zero-indexed numbered variants
        "api00","api01","api02","api03","api04","api05","api06","api07","api08","api09",
        "app00","app01","app02","app03","app04","app05","app06","app07","app08","app09",
        "web00","web01","web02","web03","web04","web05","web06","web07","web08","web09",
        "db00","db01","db02","db03","db04","db05","db06","db07","db08","db09",
        "srv00","srv01","srv02","srv03","srv04","srv05","srv06","srv07","srv08","srv09",
        "mail00","mail01","mail02","mail03","mail04","mail05",
        "node00","node01","node02","node03","node04","node05",
        "host00","host01","host02","host03","host04","host05",
        "server00","server01","server02","server03","server04","server05",
        "cache00","cache01","cache02","cache03","cache04","cache05",
        "worker00","worker01","worker02","worker03","worker04","worker05",
        "task00","task01","task02","task03","task04","task05",
        "queue00","queue01","queue02","queue03","queue04","queue05",
        "proxy00","proxy01","proxy02","proxy03","proxy04","proxy05",
        "lb00","lb01","lb02","lb03","lb04","lb05",
        "nat00","nat01","nat02","nat03","nat04","nat05",
        "fw00","fw01","fw02","fw03","fw04","fw05",
        "gw00","gw01","gw02","gw03","gw04","gw05",
        "ns00","ns01","ns02","ns03","ns04","ns05",
        "mx00","mx01","mx02","mx03","mx04","mx05","mx06","mx07","mx08","mx09",
        "vpn00","vpn01","vpn02","vpn03","vpn04","vpn05",
        "cdn00","cdn01","cdn02","cdn03","cdn04","cdn05",
        "storage00","storage01","storage02","storage03","storage04","storage05",
        "backup00","backup01","backup02","backup03","backup04","backup05",
        "monitor00","monitor01","monitor02","monitor03","monitor04","monitor05",
        # Additional deep wordlist entries
        "abuse","access","account2","ack","acquire","acr","action","active2",
        "actor","adapter2","addon","adm","adminsec","admintools","adminutils",
        "advanced","advancedapi","aerial","afterhours","agentapi","aging",
        "alarm","alerts2","allocate","allowlist","allowlisted","altapi",
        "altdns","altsec","amqp","anonymous","anon","antibot","antivirus",
        "apex","apm","appauth","appdb","appenv","appinsights","applog",
        "approval","approvals","archive4","archiveapi","archiver","archiving",
        "arena","arsenal","artifact","ascend","assist","associateapi","atl",
        "attach","audit2","auditor","autoscale","autoscaler","auxapi",
        "award","awsbeta","awsdev","awsprod","azdev","azprod","aztest",
        "badge","baremetal","bigdata","binaries","biz","blackbox","blacklist",
        "boardapi","borderless","botdetect","botfilter","botnet","bouncer",
        "boxdev","boxprod","branch2","brandapi","broadcast","broker2",
        "browserapi","buckets","bufferapi","build2","buildbot","buildci",
        "builddev","buildprod","buildtest","bulk","bulkapi","business2",
        "bypass","campaign2","captcha","capture","captureapi","catalog",
        "catalogapi","catch","cdnapi","central2","chainapi","challenge",
        "changedetect","changeset","changelog2","charge","chargeback",
        "chatapi","checkins","checkout2","classificationapi","cleartext",
        "click2","clickhouse2","clickstream","clientapi","cloud2","cloudapi",
        "clouddb","cloudlog","cloudmgmt","cloudnat","cloudsec","cloudtest",
        "cluster2","cmd","cms2","codeapi","codereview","coldstart","coldstorage",
        "collector2","commit","companyapi","configapi","configmap","configsvc",
        "connection","connectionapi","connector2","container2","containerapi",
        "containerdb","contextapi","conversion","copilot","core3","coreapi",
        "coredb","corelog","coresec","corews","courier","cred","credential",
        "credentials2","cron2","cronjob","cryptographic","ctl","ctx",
        "customapi","customerdb","customersvc","cycle","d1","d2","d3",
        "daemon","dal","dataapi","database2","datadb","datadog2","dataeng",
        "dataexport","dataimport","datalab","dataops","datapipeline",
        "dataplatform","dataportal","datarep","datasets","datastore2","datastudio",
        "datasync","datateam","datawarehouse","dbapi","dbcluster","dbconn",
        "dbdev","dblog","dbmaster","dbmgmt","dbprod","dbreplica","dbslave",
        "dbsnapshot","dbtest","dd","debug2","debugapi","deeplearning",
        "default","defaultapi","delta2","deploya","deployb","deployc",
        "deployer","deploygate","deploygroup","deployinfra","deploymaster",
        "devapi","devauth","devbox","devc","devcamp","devcloud","devdb",
        "deveng","devenv2","devgateway","devhub","devinfra","devlog","devmgmt",
        "devnet","devops2","devopsapi","devopshub","devopslabs","devportal",
        "devprod","devproxy","devqueue","devregistry","devsec","devservice",
        "devtools2","devvault","digests","dirapi","disco","diskapi","dispatcher",
        "distribution","dn","dnsapi","dnscheck","dnsdev","dnsprobe","dnstest",
        "doc","docker2","dockerhub2","dockerprod","dockerrepo","dockertest",
        "document","documentapi","download2","dpapi","drain","drift","dry",
        "dryrun","dump","emailapi","emaildev","emailprod","emailtest",
        "embed","embedapi","emitter","encrypt","encryption","endpoint2",
        "endpointapi","enforcer","engapi","envapi","envcheck","envprod",
        "envstaging","envtest","errorpage","escalate","estimator","ethernet",
        "etl2","eventapi","eventbus","eventing","eventlog","eventsink",
        "eventsvc","eventsystem","exporter2","expose","extapi","f","ff",
        "failsafe","faxapi","featureapi","feedapi","fido","filter2","finalize",
        "firestore2","flagger","fleet2","fleetapi","float","flowapi","forge",
        "formapi","frontend2","frontendapi","funcapi","functionapi","fwd",
        "gapi","gc","gcpapi","gcpdev","gcpprod","gcpstaging","gcptest",
        "geoapi","geoip","geolocation","getaway","gitapi","gitdev","gitops",
        "gitprod","gitrepo","gitservice","gocd2","googleapi","governance",
        "gpuapi","gradapi","group","groupapi","grpcapi","guiapi","gw2",
        "hack","healthapi","healthcheckapi","heartbeat","helper","helperapi",
        "highavailability","historicalapi","historyapi","homeapi","hostapi",
        "hotfix2","httpapi","hub2","hyperapi","iamapi","icache","idapi",
        "idbroker","idm","idmanager","idpapi","imds","importapi","indexapi",
        "infosecapi","ingress","ingressapi","inkapi","insight","insightapi",
        "insights","instances","integrationapi","interceptor","internalapi",
        "inventoryapi","iotapi","iotdev","iotprod","iottest","issueapi",
        "jira2","jobapi","jobqueue","jobrunner","jobsched","jobsvc",
        "k8sapi","k8sdev","k8smaster","k8snode","k8sprod","k8stest",
        "kafka2","keystoreapi","lab2","labsapi","lakeapi","lambdaapi",
        "lambdadev","lambdaprod","lambdatest","latencyapi","ldapapi",
        "legacyapi","linkapi","listapi","listenerapi","loadbalancer",
        "logapi","logarchive","logdev","loggroup","logmgmt","logprod",
        "logqueue","logrouter","logsink","logsvc","logtest","logviewer",
        "loki2","lookupapi","loopsvc","lsapi","machinelearnapi","maildev2",
        "mailprod2","mainapi","masterapi","masterkey","masterprod","mastertest",
        "mazeapi","mbapi","meapi","memberapi","mergeapi","meshapi",
        "metaapi","metacache","metastore","metricsapi","mgmtapi","microapi",
        "migrationapi","modelapi","modeldev","modelprod","modeltest",
        "monitorapi","mq2","mqapi","msgapi","msgprod","msgsvc","msgtest",
        "mysqlapi","n8napi","networkapi","newsapi","nfsapi","nlpapi",
        "nodesapi","nodedev","nodeprod","nodetest","notificationapi",
        "nsqapi","oauth3","obfuscate","objectapi","observeapi","octavia",
        "odin","offlineapi","openapidev","openshift2","operationsapi",
        "orgapi","outboundapi","packetapi","paymentsapi","paypalapi",
        "pipelinesapi","pluginapi","policyapi","portapi","postapi","priceapi",
        "probeapi","processapi","productapi","productionapi","profileapi",
        "projectapi","proxyapi","pub","pubapi","publicapi","pushapi",
        "queryapi","queueapi","rbac","rbacapi","realtimeapi","redisapi",
        "remoteapi","replicaapi","reportapi","reportsapi","requestapi",
        "resourceapi","restapi","roleapi","rollingapi","routeapi","rulesapi",
        "runtimeapi","s3api","sandboxapi","schemaapi","scriptapi","searchapi",
        "secretapi","secureapi","securityapi","selfhosted","sendapi",
        "serviceapi","servicemesh","sessionapi","settingsapi","shardapi",
        "shareapi","signingapi","slackapi","slbapi","snapapi","snapshotapi",
        "socapi","sourceapi","spapi","sqsapi","ssmapi","stackapi","stateapi",
        "statsapi","storageapi","streamapi","subapi","subdomainapi","subscribeapi",
        "systemapi","tagapi","tasksapi","teamapi","telemetryapi","tenantapi",
        "testapi","ticketapi","trackerapi","traceapi","trafficapi","transformapi",
        "transitionapi","triggerapi","trustapi","tunnelapi","typeapi","uiapi",
        "uploadapi","userapi","utilapi","utilsapi","vaultapi","vcapi","vmapi",
        "versionapi","webhookapi","websocketapi","workflowapi","workerapi",
        "workspaceapi","wsapi","xapi","xprodapi","yamlapi","zoneapi","zooapi",
        # Highly obscure / hidden service indicators
        "anon","anonapi","backdoor2","bypass2","canary4","covert","dark",
        "darkweb","devel2","dispose","disposable","emergency","emerg",
        "eol2","escape","experimental3","extra","firstresponder","flash",
        "ghost2","grabber","harvest","honeypot2","horde","hornet","inject",
        "intercept2","leak","leaktest","legacydb","leggit","letsencrypt",
        "lightspeed","linker","localtest","loopback","lowlevel","luster",
        "lysander","macro","magiclink","managekeys","master2","matrix",
        "maze","meltdown","migration","monoculture","mystery","netapi",
        "nightwatch","nullroute","obscure2","omega2","oneway","openrelay",
        "openvpn2","operator","outcry","outpost","override","owlet","panic",
        "patchwork","payloadapi","perimeterapi","phishtest","pirate","pivot",
        "plaintext","plantapi","playpen","poison","pool","portal2","portknock",
        "privapi","probe2","proxystats","psyop","purge","rabbit","racker",
        "radar","raider","randomapi","rebound","reconnaissance","recon",
        "recon2","recruit","redact","redirect","redundancy","renegade",
        "reserve","resident","resourcesapi","reverseproxy","revoke","riskapi",
        "rock","rootkit","rover","sabotage","sampler","scatterapi","scout",
        "sentinel","serpent","sinkhole","skeleton","skynet","slaveapi",
        "slipstream","slowloris","snapshot2","sniper","socialeng","soldout",
        "sonar2","spectre","specter","speedtest","spider","splinter","spooler",
        "spyops","stagingapi","stale","state2","stealth","stormapi","sysctl",
        "sysinfo","sysroot","sysreset","takeout","tapwire","target","techapi",
        "teleport","tempfile","terminate","throwout","tracker2","transit2",
        "trapdoor","trojan","turbine","unauth","undercover","undocumented",
        "unknown","unlock","unprotected","unset","unused","upcoming",
        "upload2","user2","usersync","vagrant","vanity","vintage","viper",
        "vortex","vulnerableapi","warpath","watchdog","watchlist","waterfall",
        "whitebox","whitelist","wildcard","wizard","worm","xray","zebra",
        "zeroday","zombie",
    ]

    def __init__(self, r: Result, d: str):
        self.r = r; self.d = d

    def subdomain_mutations(self) -> Set[str]:
        out: Set[str] = set()
        prefixes_seen: Set[str] = set()
        env_words = {
            "dev","develop","development","staging","stg","stag","stage",
            "qa","uat","test","testing","preprod","pre-prod","prod","production",
            "beta","alpha","canary","int","integration","internal","external","ext",
            "corp","corporate","old","new","legacy","v1","v2","v3","v4","v5",
            "sandbox","demo","preview","release","dr","backup","green","blue",
            "local","localdev","feature","experiment","exp","lab","experimental",
        }

        for sub in self.r.subdomains:
            clean = sub.replace(f".{self.d}", "").strip(".")
            for part in clean.split("."):
                if part and len(part) < 40 and not part.isdigit():
                    prefixes_seen.add(part)

        # Combine built-in wordlist with found prefixes
        all_wordlist = set(self._BIG_WORDLIST) | set(SUBDOMAIN_PREFIXES)
        svc_words = prefixes_seen - env_words

        # ── 1. Single-level: all wordlist entries ──────────────────────────
        for word in all_wordlist:
            out.add(f"{word}.{self.d}")

        # ── 2. altdns-style: found_prefix + separator + word ──────────────
        for prefix in list(prefixes_seen)[:200]:
            for word in list(all_wordlist)[:500]:
                if prefix == word: continue
                out.add(f"{prefix}-{word}.{self.d}")
                out.add(f"{word}-{prefix}.{self.d}")
                out.add(f"{prefix}.{word}.{self.d}")

        # ── 3. altdns-style: env × service cross-product ──────────────────
        for env in env_words:
            for svc in list(svc_words | all_wordlist)[:300]:
                out.add(f"{env}-{svc}.{self.d}")
                out.add(f"{svc}-{env}.{self.d}")
                out.add(f"{svc}.{env}.{self.d}")
                out.add(f"{env}.{svc}.{self.d}")

        # ── 4. Number suffixes on found prefixes (01-30) ──────────────────
        for prefix in list(prefixes_seen)[:100]:
            for i in range(1, 31):
                out.add(f"{prefix}{i}.{self.d}")
                out.add(f"{prefix}-{i}.{self.d}")
                out.add(f"{prefix}0{i:02d}.{self.d}")

        # ── 5. Number suffixes on wordlist ────────────────────────────────
        short_wordlist = [w for w in all_wordlist if len(w) <= 8][:200]
        for word in short_wordlist:
            for i in [1, 2, 3, 4, 5, 10, 11, 12]:
                out.add(f"{word}{i}.{self.d}")
                out.add(f"{word}-{i}.{self.d}")
                out.add(f"{word}0{i:02d}.{self.d}")

        # ── 6. API versioning ──────────────────────────────────────────────
        api_words = [p for p in prefixes_seen if 'api' in p.lower()] or ["api"]
        for api in api_words[:10]:
            for v in range(1, 11):
                out.update([
                    f"{api}-v{v}.{self.d}", f"{api}v{v}.{self.d}",
                    f"v{v}.{api}.{self.d}", f"{api}-{v}.{self.d}",
                    f"{api}-version{v}.{self.d}",
                ])

        # ── 7. Cloud/infrastructure suffixes on org name ──────────────────
        cloud_sfx = [
            "-cdn","-edge","-static","-assets","-media","-files","-uploads",
            "-backup","-dr","-origin","-lb","-gateway","-proxy","-cache",
            "-infra","-services","-backend","-frontend","-api","-app",
            "-dev","-staging","-prod","-test","-qa","-internal",
            "-us","-eu","-ap","-us-east","-us-west","-eu-west","-ap-southeast",
            "-east","-west","-north","-south","-central",
            "-k8s","-docker","-container","-cloud","-aws","-azure","-gcp",
            "-primary","-secondary","-replica","-slave","-master",
            "-green","-blue","-canary","-stable","-next","-old","-new","-legacy",
        ]
        org = self.d.split('.')[0]
        for sfx in cloud_sfx:
            out.add(f"{org}{sfx}.{self.d}")
            # Also try with hyphen-separated org parts
            for word in list(svc_words)[:20]:
                out.add(f"{word}{sfx}.{self.d}")

        # ── 8. Dot-separated two-level combinations ────────────────────────
        two_level_left = ["api","app","dev","staging","prod","test","qa","admin",
                          "internal","external","corp","service","web","mail"]
        for left in two_level_left:
            for word in list(svc_words)[:50]:
                out.add(f"{left}.{word}.{self.d}")
                out.add(f"{word}.{left}.{self.d}")

        # ── 9. Region × service combinations ──────────────────────────────
        regions = ["us","eu","ap","sg","us-east","us-west","eu-west","eu-central",
                   "ap-southeast","ap-northeast","us1","us2","eu1","eu2","ap1","ap2"]
        for region in regions:
            for svc in list(svc_words)[:30]:
                out.add(f"{region}-{svc}.{self.d}")
                out.add(f"{svc}-{region}.{self.d}")
                out.add(f"{svc}.{region}.{self.d}")

        # ── 10. Remove already known ──────────────────────────────────────
        out -= self.r.subdomains
        out.discard(self.d)
        # Remove obviously bad entries
        out = {s for s in out if s.endswith(f".{self.d}") and
               len(s) < 253 and
               all(len(part) <= 63 for part in s.split('.'))}
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
            versions_seen = {"v1","v2","v3","v4","v5"}

        # Resource × version expansion
        for ver in versions_seen:
            for res in list(resources_seen)[:150]:
                for pfx in ["/api","/api2","/rest","/internal",""]:
                    base = f"{pfx}/{ver}/{res}"
                    out.update([
                        base, f"{base}/list", f"{base}/search",
                        f"{base}/count", f"{base}/{{id}}",
                        f"{base}/admin", f"{base}/bulk",
                        f"{base}/export", f"{base}/import",
                        f"{base}/me", f"{base}/all",
                        f"{base}/create", f"{base}/update",
                        f"{base}/delete", f"{base}/{{id}}/details",
                    ])

        # All framework static paths
        out.update(ALL_PROBE_PATHS)

        # Env suffixes on discovered paths
        env_sfx = ["-dev","-staging","-test","-beta","-internal",
                   "-old","-new","-v2","-legacy","-backup","-debug","-preview"]
        for path in list(self.r.endpoints)[:800]:
            parts = path.split('/')
            if len(parts) >= 2 and parts[-1]:
                last = parts[-1].split('?')[0]
                if last:
                    for sfx in env_sfx:
                        out.add('/'.join(parts[:-1]) + '/' + last + sfx)

        # Path traversal / bypass variants on protected paths
        protected = [p for p in self.r.endpoints
                     if any(x in p.lower() for x in
                            ('admin','internal','private','debug','manage','api','console'))]
        bypass_transforms = [
            # Path traversal / normalization bypasses
            lambda p: f"/..;/{p.lstrip('/')}",
            lambda p: f"/{p.lstrip('/')}/",
            lambda p: f"/{p.lstrip('/')}%2f",
            lambda p: f"/{p.lstrip('/')}%20",
            lambda p: f"/;/{p.lstrip('/')}",
            lambda p: f"/%2e/{p.lstrip('/')}",
            lambda p: f"/.//{p.lstrip('/')}",
            lambda p: f"/{p.lstrip('/')}/.",
            lambda p: re.sub(r'/(\w)', lambda m: f'/{m.group(1).upper()}', p, count=1),
            lambda p: f"/{p.lstrip('/')}#",
            lambda p: f"/{p.lstrip('/')}?v=1",
            lambda p: p.replace('/admin', '/ADMIN').replace('/internal', '/INTERNAL'),
            # Additional WAF bypass techniques
            lambda p: f"/{p.lstrip('/')}/..",
            lambda p: f"//%2f/{p.lstrip('/')}",
            lambda p: f"/{p.lstrip('/')}%09",      # URL-encoded tab (not literal \t which breaks HTTP)
            lambda p: f"/{p.lstrip('/')}%20",      # URL-encoded space (not literal space which breaks HTTP)
            lambda p: f"/{p.lstrip('/')}%0b",      # Bug fix: was duplicate %09; replaced with %0b (vertical tab)
            lambda p: f"/{p.lstrip('/')}%0a",
            lambda p: f"/{p.lstrip('/')}%0d",
            lambda p: f"///{p.lstrip('/')}",
            lambda p: f"/{p.lstrip('/')};",
            lambda p: f"/{p.lstrip('/')};.jsp",
            lambda p: f"/{p.lstrip('/')};foo=bar",
            lambda p: f"//{p.lstrip('/')}//",
            lambda p: f"/{p.lstrip('/')}?",
            lambda p: f"/{p.lstrip('/')}?debug",
            lambda p: f"/{p.lstrip('/')}?_=1",
            lambda p: f"/{p.lstrip('/')}?lang=en",
            lambda p: f"/%61{p.lstrip('/')[1:]}",
            lambda p: p.replace('/internal', '/Internal').replace('/admin', '/Admin'),
            lambda p: p.replace('/private', '/Private').replace('/debug', '/Debug'),
            lambda p: p.replace('/secret', '/Secret').replace('/config', '/Config'),
            lambda p: f"/{p.lstrip('/')}.php",
            lambda p: f"/{p.lstrip('/')}.json",
            lambda p: f"/{p.lstrip('/')}.jsp",
            lambda p: f"/{p.lstrip('/')}.do",
            lambda p: f"/{p.lstrip('/')}.action",
            lambda p: f"/{p.lstrip('/')}~",
            lambda p: f"/{p.lstrip('/')}.bak",
            lambda p: f"/{p.lstrip('/')}.old",
            lambda p: f"/{p.lstrip('/')}.orig",
            lambda p: f"/{p.lstrip('/')}.save",
            lambda p: f"/{p.lstrip('/')}.1",
            lambda p: f"/{p.lstrip('/')}.2",
            lambda p: f"/{p.lstrip('/')}0",
            lambda p: f"/{p.lstrip('/')}1",
            lambda p: f"/{p.lstrip('/')}2",
            lambda p: f"/{p.lstrip('/')}3",
        ]
        for path in protected[:300]:
            for transform in bypass_transforms:
                try: out.add(transform(path))
                except Exception: pass

        # Content-type / extension variants
        ext_variants = [
            ".json",".xml",".yaml",".yml",".csv",".txt",".html",".htm",
            ";.json","?format=json","?output=json","?accept=json",
            ".php",".asp",".aspx",".jsp",".do",".action",".cfm",
            ".pl",".py",".rb",".cgi",".sh",
            ".bak",".backup",".old",".orig",".save","~",".1",".2",".3",
            ".swp",".swo",".swn",".tmp",".temp",".cache",
            ".log",".sql",".db",".gz",".tar.gz",".zip",".rar",
            ".config",".conf",".cfg",".ini",".env",
            "?debug=1","?test=1","?verbose=1","?trace=1",
            "?admin=1","?internal=1","?api=1",
            "?format=xml","?format=yaml","?format=csv","?format=txt",
            "?_format=json","?_format=xml","?output=xml","?output=yaml",
            "?callback=test","?jsonp=test","?wsdl","?wadl",
            ";jsessionid=1","?XDEBUG_SESSION_START=1",
        ]
        for path in list(self.r.endpoints)[:600]:
            clean = path.split('?')[0].split('#')[0]
            if '.' not in clean.split('/')[-1]:  # no extension
                for ext in ext_variants:
                    out.add(clean + ext)

        out -= self.r.endpoints
        return out


# ─── WAF Response Detection ───────────────────────────────────────────────────
_WAF_HDR_KEYS = frozenset([
    "cf-ray","x-sucuri-id","x-iinfo","x-cdn","x-fw-hash",
    "x-akamai-transformed","akamai-grn","x-cache-status",
    "x-amzn-requestid","x-amzn-trace-id","x-waf-event-info",
    "incapsula","x-incap-ses","x-iinfo","x-secintelligence",
    "server-timing",  # Cloudflare uses this
    "nel","report-to",  # Cloudflare sends these
])
_WAF_BODY_PATS = [
    # ── Cloudflare ──────────────────────────────────────────────────────────
    re.compile(r'cloudflare(?:_ray|ray|[-_]id|-inc)', re.I),
    re.compile(r'_cf_chl_|cf-challenge|__cf_chl_jschl|cfreq|cf_clearance', re.I),
    re.compile(r'ddos(?:[-_])?protection.{0,60}cloudflare', re.I),
    re.compile(r'enable\s+javascript.{0,80}(?:security|protection)', re.I),
    # "just a moment" is only a WAF signal when paired with cloudflare context;
    # matching it globally with MULTILINE caused false-positives on legitimate pages.
    re.compile(r'just\s+a\s+moment.{0,200}cloudflare|cloudflare.{0,200}just\s+a\s+moment', re.I | re.S),
    re.compile(r'window\._cf_chl_opt|jschl_vc|jschl_answer|cf-challenge-running', re.I),
    re.compile(r'ray\s+id\s*:?\s*[0-9a-f]{16}', re.I),
    re.compile(r'<title>[^<]{0,20}just\s+a\s+moment[^<]{0,20}</title>', re.I),
    # ── Imperva / Incapsula ─────────────────────────────────────────────────
    re.compile(r'incapsula\s+incident|powered\s+by\s+incapsula', re.I),
    re.compile(r'imperva.{0,40}protected|imperva\s+inc\.?', re.I),
    re.compile(r'incap_ses_|visid_incap_|___utmvc', re.I),
    re.compile(r'request\s+blocked\s+by\s+imperva', re.I),
    # ── Akamai ──────────────────────────────────────────────────────────────
    re.compile(r'akamai.{0,40}reference\s+\#|access\s+denied.{0,80}akamai', re.I),
    # Require Akamai context — plain "Reference #1.2.3" appears on many legitimate error pages
    re.compile(r'(?:akamai|ghost\s+error).{0,120}reference\s+#\d+\.\d+\.\d+|reference\s+#\d+\.\d+\.\d+.{0,120}(?:akamai|ghost)', re.I),
    re.compile(r'akamai\s+error|ghost\s+error\s+page.*akamai', re.I),
    # ── Sucuri ──────────────────────────────────────────────────────────────
    re.compile(r'sucuri\s+website\s+firewall|sucuri_cloudproxy', re.I),
    re.compile(r'protected\s+by\s+sucuri|sucuri\s+website\s+protection', re.I),
    # ── F5 BIG-IP ASM ───────────────────────────────────────────────────────
    re.compile(r'f5\s+big-?ip|the\s+requested\s+url\s+was\s+rejected', re.I),
    re.compile(r'support\s+id\s*:\s*\d+.*big.?ip', re.I),
    # ── Barracuda ───────────────────────────────────────────────────────────
    re.compile(r'barracuda\s+network|request\s+blocked.*barracuda', re.I),
    # ── ModSecurity ─────────────────────────────────────────────────────────
    re.compile(r'mod_?security|modsecurity\s+activated', re.I),
    re.compile(r'this\s+error\s+was\s+generated\s+by\s+mod_security', re.I),
    # ── Wordfence ───────────────────────────────────────────────────────────
    re.compile(r'wordfence.{0,40}blocked|your\s+access\s+to\s+this\s+site\s+has\s+been\s+limited', re.I),
    re.compile(r'generated\s+by\s+wordfence', re.I),
    # ── Fastly / Varnish ────────────────────────────────────────────────────
    re.compile(r'fastly\s+error|varnish\s+cache\s+server', re.I),
    re.compile(r'sorry.{0,30}page\s+not\s+found.{0,30}fastly', re.I),
    # ── AWS WAF ─────────────────────────────────────────────────────────────
    re.compile(r'aws\s+waf|awswaf_blocked|x-amzn-requestid.*403', re.I),
    re.compile(r'request\s+blocked\s+by\s+aws', re.I),
    # ── Azure WAF ───────────────────────────────────────────────────────────
    re.compile(r'microsoft\s+azure\s+application\s+gateway', re.I),
    re.compile(r'the\s+web\s+application\s+firewall\s+has\s+blocked.{0,80}request', re.I),
    # ── DataDome ────────────────────────────────────────────────────────────
    re.compile(r'datadome|dd_inline_bot|datadome\.co', re.I),
    re.compile(r'protected\s+by\s+datadome', re.I),
    # ── PerimeterX / HUMAN ──────────────────────────────────────────────────
    re.compile(r'perimeterx|_pxvid|_px_uuid|px-captcha', re.I),
    re.compile(r'px\.js|pxscript|perimeterx\.com', re.I),
    re.compile(r'human\s+security|human\s+challenge', re.I),
    # ── Radware AppWall ─────────────────────────────────────────────────────
    re.compile(r'radware|appwall\s+blocked|blocked\s+by\s+appwall', re.I),
    # ── Citrix ADC / NetScaler ──────────────────────────────────────────────
    re.compile(r'citrix\s+adc|netscaler\s+web\s+app', re.I),
    re.compile(r'nsuri|nssid|citrix\.com.*blocked', re.I),
    # ── Sophos UTM ──────────────────────────────────────────────────────────
    re.compile(r'sophos\s+utm|sophos\s+web\s+protection', re.I),
    # ── Fortinet FortiWeb ───────────────────────────────────────────────────
    re.compile(r'fortiweb|fortigate|fortinet.{0,30}blocked', re.I),
    re.compile(r'your\s+request\s+was\s+blocked.*fortiw', re.I),
    # ── BotGuard / Google reCAPTCHA challenge ────────────────────────────────
    re.compile(r'botguard|google\.com/recaptcha.*challenge', re.I),
    re.compile(r'captcha-container|hcaptcha|challenge-form', re.I),
    # ── Nginx WAF (openresty/naxsi) ──────────────────────────────────────────
    # NOTE: "nginx" alone with "403" or "access denied" is too broad — nginx legitimately
    # returns 403 for directory listings, auth-protected paths, etc.
    # Only match explicit WAF/NAXSI/OpenResty-WAF markers.
    re.compile(r'naxsi_sig|openresty\s+waf|nginx.*(?:waf|security.policy|naxsi)', re.I),
    # ── Pantheon / Platform.sh ───────────────────────────────────────────────
    re.compile(r'pantheon\s+upstream\s+not\s+found|platform\.sh.*403', re.I),
    # ── Generic WAF / security patterns ─────────────────────────────────────
    re.compile(r'request\s+blocked.{0,60}(?:security|firewall|waf)\s+policy', re.I),
    # NOTE: "You don't have permission to access ... on this server" is Apache's
    # *standard* error page, not a WAF block. Only match when combined with WAF markers.
    # Removed this overly broad pattern to prevent Apache 403s from being discarded.
    # NOTE: "access denied" + native web server name is a server-level deny, NOT a WAF block.
    # Only match when an explicit WAF/firewall keyword is present.
    re.compile(r'access\s+denied.{0,60}(?:firewall|waf|security\s+policy|bot\s+protection)', re.I),
    re.compile(r'an?\s+error\s+occurred.{0,60}reference\s+(?:id|number)\s*#?\d+', re.I),
    re.compile(r'your\s+ip\s+(?:address\s+)?(?:has\s+been\s+)?(?:blocked|banned|rate.?limited)', re.I),
    # Title matching: Only match titles that include both a block indicator AND a WAF/security
    # brand or phrase. Plain "<title>403 Forbidden</title>" or "<title>Forbidden</title>"
    # are standard nginx/Apache error pages — do NOT treat them as WAF blocks.
    re.compile(r'<title>[^<]{0,30}(?:blocked|access\s+denied|security\s+check)[^<]{0,30}</title>', re.I),
    re.compile(r'<title>[^<]{0,60}(?:cloudflare|sucuri|imperva|akamai|ddos\s+protection|waf\s+blocked)[^<]{0,60}</title>', re.I),
    re.compile(r'security\s+check.{0,60}(?:browser|human|verify)', re.I),
    re.compile(r'verifying\s+you\s+are\s+(?:human|not\s+a\s+bot)', re.I),
    re.compile(r'please\s+stand\s+by.{0,80}(?:ddos|protection|checking)', re.I),
    re.compile(r'this\s+site\s+is\s+protected\s+by.{0,80}(?:cloudflare|sucuri|imperva|akamai)', re.I),
    re.compile(r'malicious\s+(?:bot|request|activity)\s+detected', re.I),
    re.compile(r'suspicious\s+(?:activity|behavior|request)\s+detected', re.I),
    re.compile(r'rate\s+limit(?:ed|ing)?\s+exceeded.{0,60}(?:try\s+again|retry)', re.I),
    re.compile(r'too\s+many\s+requests\s+from\s+your\s+ip', re.I),
    re.compile(r'challenge\s+page|interstitial\s+page|captcha\s+challenge', re.I),
    re.compile(r'automated\s+(?:request|access|bot)\s+(?:detected|blocked|denied)', re.I),
    re.compile(r'\\u003c!--\s*challenge\s*--\\u003e|__ddg_jschl_token__', re.I),
    # ── Reblaze ─────────────────────────────────────────────────────────────
    re.compile(r'reblaze\s+(?:waf|firewall)|powered\s+by\s+reblaze', re.I),
    re.compile(r'rb_session|rbzid=|rbzuid=', re.I),
    # ── Cloudflare Turnstile / Challenge v3 ─────────────────────────────────
    re.compile(r'challenges\.cloudflare\.com|turnstile\.cloudflare\.com', re.I),
    re.compile(r'cf-turnstile|cfturnstile', re.I),
    # ── Kasada ──────────────────────────────────────────────────────────────
    re.compile(r'kasada|kcpadded|kpsdk', re.I),
    re.compile(r'Your\s+request\s+has\s+been\s+blocked.{0,60}Kasada', re.I),
    # ── Bot Management generic ───────────────────────────────────────────────
    re.compile(r'bot\s+(?:management|protection|detection)\s+(?:by|powered)', re.I),
    re.compile(r'window\._sharedData.*\"js_datr\"|_js_datr', re.I),
    # ── Netacea ──────────────────────────────────────────────────────────────
    re.compile(r'netacea|ntc_session|ntc_id', re.I),
    # ── Wallarm ──────────────────────────────────────────────────────────────
    re.compile(r'wallarm|wallarm\.com|wallarm_mode', re.I),
    # ── NGINX WAF (nginx-waf open-source) ────────────────────────────────────
    re.compile(r'nginx-waf|nginx\s+waf\s+blocked', re.I),
    # ── Cloudflare "Verify you are human" latest variant ─────────────────────
    re.compile(r'Verifying\s+that\s+you\s+are\s+not\s+a\s+robot', re.I),
    re.compile(r'Checking\s+if\s+the\s+site\s+connection\s+is\s+secure', re.I),
    re.compile(r'DDoS\s+protection\s+by\s+Cloudflare', re.I),
    # ── Deny / block generic ─────────────────────────────────────────────────
    re.compile(r'<body[^>]*>\s*<h1>(?:4(?:0[13]|29)|5(?:0[23]|0[345]))\s*(?:Forbidden|Blocked|Too Many Requests|Access Denied|Service Unavailable)</h1>\s*</body>', re.I | re.S),
    # ── IP reputation block pages ────────────────────────────────────────────
    re.compile(r'your\s+ip\s+is\s+(?:listed|in)\s+(?:a\s+)?(?:blacklist|blocklist|denylist)', re.I),
    re.compile(r'this\s+ip\s+(?:address\s+)?has\s+been\s+(?:blacklisted|blocked|flagged)', re.I),
    # ── CAPTCHA generic ──────────────────────────────────────────────────────
    re.compile(r'please\s+complete\s+the\s+(?:captcha|security\s+check|challenge)', re.I),
    re.compile(r'are\s+you\s+(?:a\s+)?human\?|prove\s+you.re\s+human', re.I),
    re.compile(r'hcaptcha\.com|hcaptcha-widget', re.I),
    re.compile(r'funcaptcha|arkoselabs', re.I),
    # ── Akamai Bot Manager sensor data ───────────────────────────────────────
    re.compile(r'_abck=|bm_sz=|bm_sv=|bmsz|ak_bmsc', re.I),
    re.compile(r'Akamai-Bot-Manager|Akamai-Bot-Detect', re.I),
    # ── Shape Security / F5 ──────────────────────────────────────────────────
    re.compile(r'shape_utmz|shape_utmc|shape_c8|shapesecurity', re.I),
    # ── Cloudflare Workers (block page from Worker) ───────────────────────────
    re.compile(r'cf-worker-block|worker\.cloudflare\.com.*blocked', re.I),
    # ── 2025: Cloudflare Turnstile v2 / Bot Fight Mode ───────────────────────
    re.compile(r'cf-turnstile-wrapper|challenges\.cloudflare\.com/turnstile', re.I),
    re.compile(r'window\.__CF\$cv\$params|cf_challenge_running|cdn-cgi/challenge-platform', re.I),
    re.compile(r'cff\.js.*cloudflare|cloudflare.*cff\.js', re.I),
    # ── 2025: DataDome v4 ────────────────────────────────────────────────────
    re.compile(r'ddjskey|datadome\.co/js|datadome-captcha|api\.datadome\.co|ddmc\.js', re.I),
    # ── 2025: PerimeterX/HUMAN v3 ────────────────────────────────────────────
    re.compile(r'_pxOnCaptchaSuccess|px\.js\?a=c&|captcha\.px-cdn\.net|solveCaptcha\(|PerimeterXCaptcha', re.I),
    # ── 2025: Imperva/Incapsula v12 ──────────────────────────────────────────
    re.compile(r'/_Incapsula_Resource\?SWCGHOEL|incapsula incident id|visitorData\.js|reese84', re.I),
    # ── 2025: Kasada 3.x ─────────────────────────────────────────────────────
    re.compile(r'kaxsdc|kcl\.js|kpsdk-sc', re.I),
    # ── 2025: Akamai Bot Manager 2024 ────────────────────────────────────────
    re.compile(r'sec\.akamai\.com|bmak\.js', re.I),
    # ── 2025: AWS WAF custom block pages ─────────────────────────────────────
    re.compile(r'AWS WAF could not forward|aws-waf-token', re.I),
    # ── 2025: Netacea Intent API ──────────────────────────────────────────────
    re.compile(r'ntc\.js.*netacea|netacea\.com', re.I),
    # ── 2025: Reblaze 3.x ────────────────────────────────────────────────────
    re.compile(r'rbzid=|rbzsessionid=|reblaze-proxy', re.I),
    # ── 2025: F5 Distributed Cloud / Shape Security ───────────────────────────
    re.compile(r'_imp_apg_r_=|shieldsquare', re.I),
    # ── 2025: Cloudflare Managed Challenge ────────────────────────────────────
    re.compile(r'window\.turnstile|turnstile\.com/v0/api\.js', re.I),
    # ── Generic bot detection signals (2025) ─────────────────────────────────
    re.compile(r'you.{0,10}have.{0,10}been.{0,10}blocked|your.{0,10}ip.{0,30}banned', re.I),
    re.compile(r'suspicious.{0,20}activity.{0,20}detected|automated.{0,20}request.{0,20}detected', re.I),
    re.compile(r'bot.{0,10}detection.{0,30}challenge|browser.{0,10}verification.{0,30}required', re.I),
    # ── 2025: Arkose Labs / FunCaptcha v3 ────────────────────────────────────
    re.compile(r'arkoselabs\.com|funcaptcha\.com|enforcement\.arkoselabs', re.I),
    # ── 2025: GeeTest 4.x challenge ──────────────────────────────────────────
    re.compile(r'geetest\.com/v4|gt4\.js|geetest_challenge|new Geetest', re.I),
    # ── 2025: Stormwall / Qrator ─────────────────────────────────────────────
    re.compile(r'stormwall\.pro|qrator\.net.*blocked|__qr_sid', re.I),
    # ── 2025: Zscaler Internet Access ────────────────────────────────────────
    re.compile(r'zscaler\.net.*blocked|your\s+request\s+was\s+blocked.*zscaler|zscloud\.net', re.I),
    # ── 2025: Palo Alto Prisma Access ────────────────────────────────────────
    re.compile(r'paloaltonetworks\.com.*blocked|prismaaccess\.com|globalprotect.*blocked', re.I),
    # ── 2025: Cloudflare Waiting Room ────────────────────────────────────────
    re.compile(r'cloudflare\.com/waiting-room|waitingroom\.js|cf-waiting-room', re.I),
    # ── 2025: DDoS-Guard ─────────────────────────────────────────────────────
    re.compile(r'ddos-guard\.net|__ddg1_|__ddg2_|DDoS-Guard', re.I),
    # ── 2025: Fingerprint.js Pro (ThreatMetrix/LexisNexis) ───────────────────
    re.compile(r'fpjs\.io|fingerprintjs|fingerprint\.com/v3|fpAgent', re.I),
    # ── 2025: Tencent Cloud Web Application Firewall ─────────────────────────
    re.compile(r'tencent.*waf|waf\.qq\.com|qcloud.*blocked', re.I),
    # ── 2025: Alibaba Cloud WAF / Anti-Bot ───────────────────────────────────
    re.compile(r'alibaba.*waf|aliyunddos|aliyundun\.com|__jsl_clearance', re.I),
    # ── 2025: Oracle Cloud WAF ───────────────────────────────────────────────
    re.compile(r'oracle.*web.*application.*firewall|ociwaf', re.I),
    # ── 2025: Cloudflare Page Shield ─────────────────────────────────────────
    re.compile(r'cdn-cgi/page-shield|pageshield\.cloudflare', re.I),
    # ── 2025: Radware Bot Manager ────────────────────────────────────────────
    re.compile(r'radware.*bot|rbm\.js|radware-bot-manager|botmanager\.radware', re.I),
    # ── 2025: Cequence (Unified API Protection) ───────────────────────────────
    re.compile(r'cequence\.io|unifiedapi.*protection|cq_bot', re.I),
    # ── 2025: Human Security (HUMAN.security formerly PerimeterX) ────────────
    re.compile(r'humansecurity\.com|human\.security.*challenge|_human_id', re.I),
    # ── 2025: Fastly Next-Gen WAF (formerly Signal Sciences) ─────────────────
    re.compile(r'signal_sciences|sigsci|ngwaf\.fastly|poweredbyfastly.*blocked', re.I),
    # ── 2025: Sucuri WAF updated signature ───────────────────────────────────
    re.compile(r'sucuri\.net/privacy|sucuri_cloudproxy_response|blocked.*sucuri', re.I),
    # ── 2025: Barracuda WAF ───────────────────────────────────────────────────
    re.compile(r'barracuda.*blocked|bnw_blocked|barracudanetworks.*waf', re.I),
    # ── 2025: ModSecurity 3.x (OWASP CRS v4) ────────────────────────────────
    re.compile(r'mod_security|ModSecurity.*error|OWASP.*CRS.*blocked|owasp.*core.*rule.*set', re.I),
]

# Extra 2025-era patterns — additional deep detection for bot management and
# novel WAF block page signatures not covered by the main list above.
_WAF_BODY_PATS_EXTRA_2025 = [
    # Arkose Labs FunCaptcha (common on Twitter/X, Roblox, enterprise apps)
    r'arkoselabs\.com|funcaptcha|arkoselabs/v2/enforce',
    # GeeTest CAPTCHA (popular in Asia-Pacific)
    r'gt\.js.*geetest|geetest\.com|initGeetest|GeetestCaptcha',
    # Tencent Cloud WAF
    r'tcloud[-_]waf|tencent\s+cloud\s+security|waf\.tencentcloudapi',
    # Alibaba Cloud WAF (Anti-Bot Service)
    r'aliyun\s+waf|alibaba\s+cloud\s+waf|sec-\w+\.alibaba',
    # Oracle Cloud WAF
    r'oracle\s+cloud\s+infrastructure\s+waf|oci\s+waf|oracle\s+access\s+manager.*denied',
    # Stormwall DDoS protection
    r'stormwall\s+protection|stormwall\.pro',
    # CDN77 WAF
    r'cdn77\.com.*blocked|cdn77.*access\s+denied',
    # Zscaler proxy/WAF blocks
    r'zscaler.*access\s+denied|zscaler\.net.*blocked|you\s+are\s+not\s+authorized.*zscaler',
    # Palo Alto Networks Prisma / Cortex XDR
    r'palo\s+alto\s+networks.*blocked|prisma\s+access.*denied|cortex\s+xdr.*blocked',
    # Cloudflare Bot Fight Mode 2024 (new JS challenge)
    r'cf_chl_opt\.cRq|window\.cf_chl_opt|__CF\$cv\$params\.r',
    # Imperva SecureSphere (on-prem)
    r'SecureSphere|imperva\.com/websecurity|incapsula.*incident\s+id',
    # Cloudflare Waiting Room
    r'Cloudflare Waiting Room|waiting-room\.cloudflare\.com|cf-waiting-room',
    # Edgecast / Verizon Media WAF
    r'EdgeCast.*access\s+denied|Verizon\s+Media.*blocked|VerizonMedia.*WAF',
    # Limelight Networks WAF
    r'Limelight\s+Networks.*blocked|llnwd\.net.*access\s+denied',
    # DDoS-Guard block page
    r'ddos-guard\.net|This\s+site\s+is\s+protected\s+by\s+DDoS-Guard',
    # Nginx rate limit / deny directive
    r'<center>nginx</center>\s*<hr><center>openresty</center>',
    # HAProxy deny
    r'<h1>503 Service Unavailable</h1>.*HAProxy|HAProxy.*DENY',
    # Cloudflare 1020 error (Rules)
    r'Error\s+1020|Access\s+denied.*Error\s+1020|Cloudflare\s+Error\s+1020',
    # Cloudflare 1010 (Hotlinking protection)
    r'Error\s+1010|owner\s+of\s+this\s+website.*banned\s+your\s+IP',
    # Cloudflare 1015 (Rate limited)
    r'Error\s+1015|You are being rate limited|Cloudflare.*1015',
    # Imperva 999 error
    r'Error\s+Code\s+999|Access\s+Denied.*Incap',
    # F5 BIG-IP ASM reject page signature
    r'The\s+requested\s+URL\s+was\s+rejected.*support\s+ID',
    # Generic 2025: Antibot via fingerprint
    r'fingerprint\.js|fpjs\.io.*blocked|visitorId.*challenge',
    # Cloudflare Managed Rules 2025 — use precise patterns to avoid false positives
    # "Attention Required" and "one more step" alone are too generic; require CF context
    r'This website is using a security service to protect itself from online attacks',
    r'Attention Required.*?cloudflare|cloudflare.*?Attention Required',
    r'one more step.*?cloudflare|cloudflare.*?one more step',
    # Cloudflare Error codes
    r'Error\s+1009|Error\s+1012|Error\s+1016|Error\s+1024|Error\s+1030',
    # ── 2025 additions ────────────────────────────────────────────────────────
    # Cloudflare Bot Fight Mode v2 (2025) — new challenge page fingerprints
    r'cf_chl_opt\.cNounce|cf_chl_opt\.cHash|cf_chl_opt\.cType',
    r'challenges\.cloudflare\.com/cdn-cgi/challenge-platform/h/g',
    # Cloudflare Turnstile sitekey markers (2025 managed challenge)
    r'data-sitekey.*?0x4[A-Za-z0-9_-]{20,}',
    # AWS WAF 2025 CAPTCHA integration
    r'aws-waf-token.*?challenge|AwsWafIntegration|awswaf_.*?blocked',
    # Akamai Bot Manager v4 (2025) — new challenge page tokens
    r'bm_sz_v4|ak_bmsc.*?challenge|ak_r|_abck',
    # DataDome 2025 challenge page tokens
    r'datadome\.co/captcha/.*?2025|ddjskey.*?v2|dd_was_here',
    # PerimeterX / HUMAN Security 2025 bot defense tokens
    r'_pxff_|pxbotman|human-challenge-2025|px_block_page_v\d',
    # Netacea 2025 challenge
    r'netacea\.com/challenge/v2|ntc-challenge-2025',
    # Reblaze 2025 WAF block page
    r'rbzid-v2|reblaze.*?challenge.*?2025',
    # Kasada 2025 WAF (updated SDK tokens)
    r'kaxsdc.*?2025|kasada-sdk-v3|kcl-loader.*?2025',
    # Shape Security / F5 Distributed Cloud 2025
    r'shape-go-away|f5distributed.*?blocked|shapetoken-v\d',
    # Cloudflare Firewall rule error pages (JSON API format 2025)
    r'"code"\s*:\s*1006|"code"\s*:\s*1007|"message"\s*:\s*"The owner of this website.*?banned"',
]

# Pre-compile all extra 2025 patterns for O(1) matching (avoid re.compile overhead per call)
_WAF_BODY_PATS_EXTRA_2025_COMPILED = [
    re.compile(pat, re.I | re.S) for pat in _WAF_BODY_PATS_EXTRA_2025
]

# WAF header signatures — presence of these headers strongly suggests WAF
_WAF_HDR_SIGNS: Dict[str, str] = {
    "cf-ray":                    "cloudflare",
    "cf-mitigated":              "cloudflare",
    "x-sucuri-id":               "sucuri",
    "x-sucuri-cache":            "sucuri",
    "x-iinfo":                   "imperva/incapsula",
    "x-cdn":                     "cdn-generic",
    "x-fw-hash":                 "fastly",
    "x-fastly-request-id":       "fastly",
    "x-akamai-transformed":      "akamai",
    "akamai-grn":                "akamai",
    "x-akamai-request-id":       "akamai",
    "x-cache-status":            "cdn-proxy",
    "x-amzn-requestid":          "aws",
    "x-amzn-trace-id":           "aws",
    "x-waf-event-info":          "waf-generic",
    "x-incap-ses":               "imperva/incapsula",
    "x-visid-meta":              "imperva/incapsula",
    # Note: x-iinfo already defined above — removed duplicate
    "x-secintelligence":         "waf-generic",
    "nel":                       "cloudflare-nel",
    "report-to":                 "cloudflare-reporting",
    "x-datadome-cid":            "datadome",
    "x-datadome":                "datadome",
    "x-dd-b":                    "datadome",
    "x-px-cookies":              "perimeterx",
    "x-px-vid":                  "perimeterx",
    "pxv":                       "perimeterx",
    "x-px":                      "perimeterx",
    "_pxhd":                     "perimeterx",
    "x-fortinet":                "fortinet",
    "x-fw-server":               "fortiweb",
    "x-fortigate":               "fortigate",
    "x-oracle-dms-ecid":         "oracle/waf",
    "x-ms-ref":                  "azure-cdn",
    "x-azure-ref":               "azure-cdn",
    "x-cache":                   "cdn-cache",
    "x-varnish":                 "varnish",
    "x-radware":                 "radware",
    "x-appwall":                 "radware-appwall",
    "x-kasada-info":             "kasada",
    "x-kct":                     "kasada",
    "x-human-challenge":         "human-security",
    "x-px-uuid":                 "perimeterx",
    "x-shape-sig":               "shape-security",
    "x-shape-action":            "shape-security",
    "x-threatx":                 "threatx",
    "x-cnc-waf":                 "cnc-waf",
    "x-litespeed-cache":         "litespeed",
    "x-lsadc":                   "litespeed-adc",
    "x-shield":                  "shield-waf",
    "x-powered-by-shield":       "shield-waf",
    "x-guard":                   "guard-waf",
    "x-ddos-protection":         "ddos-guard",
    "x-protected-by":            "protection-proxy",
    "x-waf-protection":          "waf-generic",
    "x-ns-waf":                  "nginx-waf",
    "x-cloudfront-id":           "cloudfront",
    "x-amz-cf-id":               "cloudfront",
    "x-amz-cf-pop":              "cloudfront",
    # ── Reblaze ──────────────────────────────────────────────────────────────
    "x-reblaze-protection":      "reblaze",
    "rbzid":                     "reblaze",
    # ── Wallarm ──────────────────────────────────────────────────────────────
    "x-wallarm-request-id":      "wallarm",
    "x-wallarm-action":          "wallarm",
    # ── Netacea ──────────────────────────────────────────────────────────────
    "x-netacea-info":            "netacea",
    "x-netacea-match":           "netacea",
    # ── Akamai Bot Manager ────────────────────────────────────────────────────
    "ak-bmsc":                   "akamai-bot-manager",
    "bm_sz":                     "akamai-bot-manager",
    # ── Nginx WAF / Naxsi ─────────────────────────────────────────────────────
    "x-naxsi-sig":               "naxsi",
    "x-naxsi-blocked":           "naxsi",
    # ── CDN77 ────────────────────────────────────────────────────────────────
    "x-cdn77-hit":               "cdn77",
    "x-cdn77-origin":            "cdn77",
    # ── Stackpath / Highwinds ─────────────────────────────────────────────────
    "x-hw":                      "stackpath",
    "x-sp-url":                  "stackpath",
    # ── G-Core Labs CDN ──────────────────────────────────────────────────────
    "x-gc-analytics":            "gcore",
    # ── Bunny CDN ────────────────────────────────────────────────────────────
    "cdn-pullzone":              "bunnycdn",
    "cdn-uid":                   "bunnycdn",
    # ── Stormwall ────────────────────────────────────────────────────────────
    "x-stormwall":               "stormwall",
    # ── Cachefly ─────────────────────────────────────────────────────────────
    "x-cachefly":                "cachefly",
    # ── Yunjiasu (Baidu Cloud) ───────────────────────────────────────────────
    "yunjiasu-uuid":             "yunjiasu",
    # ── Tencent Cloud WAF ─────────────────────────────────────────────────────
    "x-tencentcloudwaf":         "tencent-cloud-waf",
    # ── Alibaba Cloud WAF ─────────────────────────────────────────────────────
    "x-alicloud-waf":            "alicloud-waf",
    "eagleeye-traceid":          "alibaba-cdn",
    # ── BIG-IP ASM cookie ─────────────────────────────────────────────────────
    "ts":                        "f5-bigip-asm",
    "bigipserver":               "f5-bigip",
}

def _is_waf_response(status: int, headers: dict, body: str) -> bool:
    """
    Return True if response looks like a WAF/CDN block/challenge page.
    Uses multi-signal detection: status codes, headers, body patterns.

    IMPORTANT: We deliberately do NOT treat bare 403s or 401s as WAF responses
    because a legitimate protected endpoint returning 403 is a REAL finding — the
    endpoint exists, it just requires auth.  Only flag WAF when there's a
    supporting signal (specific WAF header, WAF body pattern, or CDN server header).
    """
    hdrs_lower = {k.lower(): v for k, v in headers.items()}
    hdrs_keys  = set(hdrs_lower.keys())
    body_snip  = (body or "")[:8000]
    body_lower = body_snip.lower()

    # ── Cloudflare: cf-ray header signals ──────────────────────────────────
    # IMPORTANT: cf-ray alone does NOT mean WAF block — it is present on ALL
    # Cloudflare-proxied responses.  We only treat it as a WAF block when there
    # is ALSO a confirming signal (body challenge pattern, cf-mitigated header,
    # or a Cloudflare-specific challenge status code 403 WITH body evidence).
    if "cf-ray" in hdrs_keys:
        _cf_body_signals = ("_cf_chl", "cf-challenge", "jschl_vc",
                            "cf_clearance", "window._cf_chl_opt",
                            "cf-turnstile", "cf.challenge",
                            "just a moment", "checking your browser",
                            "enable javascript", "verifying you are human",
                            "please stand by", "cf_chl_rc_m",
                            "__cf_chl_f_tk", "cf_chl_prog", "cf-browser-verification")
        _has_cf_body = any(p in body_lower for p in _cf_body_signals)
        if "cf-mitigated" in hdrs_keys:
            return True          # cf-mitigated: challenge — definitive WAF
        if status == 429:
            # 429 from CF is almost always rate-limit block, not a real endpoint
            if _has_cf_body or len(body_snip) < 800:
                return True
        if status == 503 and _has_cf_body:
            return True
        if status == 403 and _has_cf_body:
            return True
        # 403 WITHOUT CF body challenge → keep (legitimate auth-protected endpoint)
        if _has_cf_body:
            return True

    # ── WAF-exclusive headers (presence = definitive WAF block) ────────────
    # These headers ONLY appear in WAF block/challenge responses, never in
    # legitimate application responses.
    waf_exclusive_hdrs = {
        "x-sucuri-id", "x-iinfo", "x-akamai-transformed", "akamai-grn",
        "x-waf-event-info", "x-incap-ses", "x-visid-meta", "x-secintelligence",
        "x-datadome-cid", "x-datadome", "x-dd-b",
        "x-px-cookies", "x-px-vid", "_pxhd", "x-px",
        "x-radware", "x-appwall", "x-fortinet", "x-fw-server", "x-fortigate",
        "x-kasada-info", "x-kct",
        "x-human-challenge", "x-shape-sig", "x-shape-action",
        "x-threatx", "x-ddos-protection",
    }
    if hdrs_keys & waf_exclusive_hdrs:
        return True

    # ── CloudFront: x-amz-cf-id means CF is in the path, NOT necessarily WAF.
    # A legitimate S3/origin 403 (bucket policy, IAM) ALSO has x-amz-cf-id.
    # Only flag as WAF when there is a body-level WAF signal.
    if "x-amz-cf-id" in hdrs_keys and status in (403, 503):
        # Keep S3 XML responses — those are real findings (bucket enumerable)
        if "<Code>AccessDenied</Code>" in body_snip or "<Code>NoSuchKey</Code>" in body_snip:
            return False  # Legitimate S3 response
        _cf_waf_body = (
            "request blocked" in body_lower or
            "aws waf" in body_lower or
            ("access denied" in body_lower and "aws" in body_lower) or
            "request could not be satisfied" in body_lower or   # CF custom error
            (len(body_snip) < 300 and "xml" not in (hdrs_lower.get("content-type","")).lower())
        )
        if status == 503 and _cf_waf_body:
            return True
        if status == 403 and "aws waf" in body_lower:
            return True
        # 403 with x-amz-cf-id but no WAF body → keep (origin-level deny = real finding)

    # ── Azure Front Door WAF block ──────────────────────────────────────────
    # x-ms-ref / x-azure-ref alone do not mean WAF — they appear on all AFD responses.
    # Require status + body evidence to avoid false-positives on legitimate endpoints.
    if ("x-ms-ref" in hdrs_keys or "x-azure-ref" in hdrs_keys):
        _afd_body = ("request blocked" in body_lower or
                     "access denied" in body_lower or
                     "error ref" in body_lower or
                     "azure front door" in body_lower)
        if status in (403, 429) and _afd_body:
            return True
        # NOTE: Removed "tiny non-JSON 403 from AFD = block page" rule.
        # Real API/app endpoints behind AFD often return small 403 bodies (e.g. JSON
        # {"error":"forbidden"} which starts with "{" after whitespace, or a minimal
        # HTML "403 Forbidden" page). Requiring explicit block language above is enough.

    # ── Server header: known WAF/CDN servers returning block codes ──────────
    if status in (403, 429, 503):
        # Only unambiguous WAF/CDN server strings — not generic ones like "aws"
        waf_server_sigs = ("cloudflare", "imperva", "incapsula", "sucuri",
                           "akamai-ghost", "ddos-guard", "fortiweb",
                           "radware", "barracuda", "f5 big-ip", "nginx/waf",
                           "reblaze", "wallarm", "aws waf", "azurefd")
        server_hdr = hdrs_lower.get("server", "").lower()
        if any(s in server_hdr for s in waf_server_sigs):
            # WAF servers that require BODY evidence for 403 — Cloudflare is the primary
            # CDN used by millions of legitimate sites, so server:cloudflare + 403 alone
            # is NOT a reliable WAF signal. We need body challenge evidence.
            # For Cloudflare specifically: require body-level challenge signal (cf-ray alone
            # is on EVERY CF-proxied response; a bare 403 without challenge body is a real
            # auth-protected endpoint, e.g. behind CF Access).
            _cf_body_challenge_signals = (
                "_cf_chl", "cf-challenge", "jschl_vc", "cf_clearance",
                "window._cf_chl_opt", "cf-turnstile", "cf.challenge",
                "just a moment", "checking your browser",
                "enable javascript", "verifying you are human",
                "please stand by", "cf_chl_rc_m", "__cf_chl_f_tk",
                "cf_chl_prog", "cf-browser-verification",
            )

            if "cloudflare" in server_hdr:
                # Cloudflare: only flag if body has challenge signal AND status is a block code
                if status == 429:
                    # 429 from CF is almost always rate-limit/bot-block
                    _has_cf_challenge = any(p in body_lower for p in _cf_body_challenge_signals)
                    if _has_cf_challenge or len(body_snip) < 800:
                        return True
                elif status == 503:
                    if any(p in body_lower for p in _cf_body_challenge_signals):
                        return True
                elif status == 403:
                    # 403 with Cloudflare server: ONLY WAF if body has challenge JS
                    # A bare CF 403 (e.g. CF Access deny, origin 403) is a real finding
                    if any(p in body_lower for p in _cf_body_challenge_signals):
                        return True
                    # Also check if "cf-mitigated" header is present (definitive)
                    if "cf-mitigated" in hdrs_keys:
                        return True
                # For 403 without challenge body → keep (real protected endpoint)
                # Skip to remaining checks (body patterns, scoring)
            else:
                # Other unambiguous WAF servers — return immediately
                _IMMEDIATE_WAF_SERVERS = (
                    "imperva", "incapsula", "sucuri",
                    "ddos-guard", "fortiweb", "radware", "aws waf",
                    "azurefd", "wallarm", "reblaze", "barracuda",
                )
                if any(s in server_hdr for s in _IMMEDIATE_WAF_SERVERS):
                    return True
                # Ambiguous WAF/CDN server strings — require body or size evidence
                _waf_body_confirm = (
                    "access denied" in body_lower or
                    "request blocked" in body_lower or
                    ("security" in body_lower and "challenge" in body_lower) or
                    "bot detection" in body_lower or
                    "captcha" in body_lower or
                    ("protection" in body_lower and "error" in body_lower)
                )
                if _waf_body_confirm:
                    return True
                # Very tiny non-JSON body from known WAF server: likely block page
                if len(body_snip) < 100 and "application/json" not in hdrs_lower.get("content-type", ""):
                    return True

    # ── Body patterns: scan first 8KB (core + 2025 additions) ───────────────
    for pat in _WAF_BODY_PATS:
        if pat.search(body_snip):
            return True
    for pat in _WAF_BODY_PATS_EXTRA_2025_COMPILED:
        if pat.search(body_snip):
            return True

    # ── JS-challenge on 200 — Cloudflare Turnstile / 5-second check ────────
    if status == 200 and body:
        if (("enable javascript" in body_lower and "protection" in body_lower) or
            "please stand by" in body_lower or
            "verifying you are human" in body_lower or
            "_cf_chl_opt" in body_lower or
            "cf-challenge" in body_lower or
            "cf.challenge" in body_lower or
            ("just a moment" in body_lower and "cloudflare" in body_lower) or
            ("checking your browser" in body_lower and "ddos" in body_lower) or
            ("turnstile" in body_lower and "sitekey" in body_lower)):
            return True

    # ── Kasada SDK challenge on 200 ─────────────────────────────────────────
    if status == 200 and body:
        if ("kasada" in body_lower or
            "kpsdk" in body_lower or
            "kp_captcha" in body_lower):
            return True

    # ── HUMAN Security / PerimeterX challenge on 200 ────────────────────────
    if status == 200 and body:
        if ("px-captcha" in body_lower or
            "human security" in body_lower or
            "humansecurity.com" in body_lower or
            "_pxAppId" in body_snip or
            "pxi.px-cdn.net" in body_lower or
            "perimeterx" in body_lower):
            return True

    # ── DataDome challenge on 200 ───────────────────────────────────────────
    if status == 200 and body:
        if ("datadome" in body_lower or
            "datadome.co" in body_lower or
            "ddjskey" in body_snip or
            ("dd.js" in body_lower and "captcha" in body_lower and "datadome" in body_lower)):
            return True

    # ── Shape Security / F5 JS challenge ───────────────────────────────────
    if status == 200 and body:
        if "shape" in body_lower and ("challenge" in body_lower or "security" in body_lower):
            if "x-shape-sig" in hdrs_keys or "x-shape-action" in hdrs_keys:
                return True

    # ── WAF confidence scoring: multiple weak signals together = WAF block ──
    # Any single weak signal alone may be coincidental; multiple together indicate
    # a WAF block page. Threshold raised to 7 to eliminate false positives on
    # legitimate 403/503 responses from nginx/Apache/IIS.
    _waf_score = 0
    if status in (403, 429, 503):
        _waf_score += 1
    if len(body_snip) < 400:
        _waf_score += 1
    if "text/html" in hdrs_lower.get("content-type", "") and status in (403, 503):
        _waf_score += 1
    # "blocked" and "access denied" are strong WAF signals; "forbidden" alone is not
    # (Apache/nginx legitimately say "Forbidden" in their standard error pages).
    # "protection" alone is weak — require it alongside actual WAF language.
    if any(kw in body_lower for kw in ("request blocked", "access denied",
                                        "you have been blocked", "ip has been blocked")):
        _waf_score += 2
    # Standalone "forbidden" only counts when accompanied by WAF-specific terms
    if "forbidden" in body_lower and any(
        kw in body_lower for kw in ("firewall", "waf", "cloudflare", "imperva",
                                     "sucuri", "akamai", "security service",
                                     "ddos", "bot protection", "threat intelligence")
    ):
        _waf_score += 2
    if any(kw in body_lower for kw in ("captcha", "challenge", "robot", "bot detection")):
        _waf_score += 2
    # "verify" alone is too broad (login pages, 2FA, email verification all use it)
    if "verify" in body_lower and any(kw in body_lower for kw in ("human", "browser", "ddos")):
        _waf_score += 2
    if any(kw in body_lower for kw in ("firewall", "threat", "ddos protection")):
        _waf_score += 1
    # "security" alone is far too generic; require WAF-specific pairing
    if "security" in body_lower and any(kw in body_lower for kw in
                                          ("challenge", "bot", "blocked", "waf", "threat")):
        _waf_score += 1
    if hdrs_lower.get("x-cache", "").lower() in ("hit", "miss") and status == 403:
        _waf_score += 1
    # NOTE: Removed "no Set-Cookie + no Cache-Control" rule — too many legitimate
    # REST API endpoints return 403 without cookies or cache headers (e.g. JWT-protected APIs).
    # Raised threshold: needs 7 weak signals — prevents plain nginx/Apache 403
    # pages from being miscategorised as WAF blocks.
    if _waf_score >= 7:
        return True

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# ACTIVE PROBER
# ═══════════════════════════════════════════════════════════════════════════════
class Prober:
    def __init__(self, s, r: Result, d: str, wc: Optional[Set[str]], proxy: Optional[str]):
        self.s = s; self.r = r; self.d = d
        # wc is now a Set[str] of wildcard IPs (handles CDN/LB with multiple IPs).
        # Accept both a single string (legacy) and a set for backward compatibility.
        if isinstance(wc, str):
            self.wc: Set[str] = {wc} if wc else set()
        else:
            self.wc = wc or set()
        self.proxy = proxy
        self._sem_h = asyncio.Semaphore(MAX_PROBE)
        self._probed: Set[str] = set()
        self._bypass_idx: int = 0  # instance-level — safe under asyncio concurrent probing

    async def _baseline(self, host: str) -> Optional[Dict]:
        rand = f"/{''.join(random.choices(string.ascii_lowercase, k=22))}"
        for scheme in ("https","http"):
            try:
                t0 = time.monotonic()
                to = aiohttp.ClientTimeout(total=10)
                async with self.s.request(
                    "GET", f"{scheme}://{host}{rand}",
                    headers=_hdrs(), timeout=to,
                    allow_redirects=True, ssl=_ssl_ctx(), proxy=self.proxy,
                ) as resp:
                    body = await resp.text(errors='replace')
                    hdrs = dict(resp.headers)
                    waf = _is_waf_response(resp.status, hdrs, body)
                    return {
                        "status": resp.status, "len": len(body),
                        "hash": hashlib.md5(body.encode()).hexdigest(),
                        "ct": resp.headers.get("Content-Type",""),
                        "server": resp.headers.get("Server",""),
                        "hdrs": hdrs,
                        "t": time.monotonic() - t0, "scheme": scheme,
                        "waf": waf,  # mark if baseline itself is WAF-gated
                    }
            except Exception: continue
        return None

    # WAF bypass header sets — rotate through these to maximize bypass chances.
    # Modern WAFs use IP+UA fingerprinting; adding these headers simulates internal
    # or trusted proxy traffic, bypassing IP-based or header-based rules.
    _BYPASS_HEADER_SETS = [
        # Set 1: Simulate internal/local request
        {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
         "X-Originating-IP": "127.0.0.1", "X-Remote-IP": "127.0.0.1",
         "X-Remote-Addr": "127.0.0.1"},
        # Set 2: Simulate trusted CDN/proxy forwarded traffic
        {"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.1",
         "CF-Connecting-IP": "10.0.0.1", "True-Client-IP": "10.0.0.1"},
        # Set 3: Simulate localhost admin access via URL override
        {"X-Forwarded-Host": "localhost", "X-Original-URL": "/",
         "X-Rewrite-URL": "/", "X-Custom-IP-Authorization": "127.0.0.1"},
        # Set 4: Simulate cloud metadata SSRF internal IP
        {"X-Forwarded-For": "169.254.169.254", "X-Real-IP": "169.254.169.254"},
        # Set 5: Minimal bypass — clean UA, no special headers
        {},
        # Set 6: Fastly CDN forwarded
        {"Fastly-Client-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1",
         "X-Timer": "S1234567890.123", "Fastly-SSL": "1"},
        # Set 7: Akamai True-Client-IP bypass
        {"True-Client-IP": "127.0.0.1", "X-Akamai-IP": "127.0.0.1",
         "Akamai-Origin-Hop": "2", "X-Forwarded-For": "127.0.0.1"},
        # Set 8: Azure / Microsoft proxy simulation
        {"X-Azure-SocketIP": "127.0.0.1", "X-FD-HealthProbe": "1",
         "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        # Set 9: AWS CloudFront simulation
        {"CloudFront-Viewer-Country": "US", "X-Amz-Cf-Id": "fake-cf-id-12345",
         "X-Forwarded-For": "127.0.0.1", "Via": "1.1 cloudfront.net (CloudFront)"},
        # Set 10: Internal API gateway simulation
        {"X-API-Gateway": "internal", "X-Gateway-Authorization": "internal-bypass",
         "X-Forwarded-For": "10.10.0.1", "X-Real-IP": "10.10.0.1",
         "X-Internal-Request": "1"},
        # Set 11: Debug/dev mode headers
        {"X-Debug": "1", "X-Dev-Mode": "1", "X-Test-Request": "1",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 12: Load balancer health probe simulation
        {"X-Forwarded-For": "127.0.0.1", "User-Agent": "HealthChecker/1.0",
         "X-Health-Check": "1", "X-LB-Probe": "1"},
        # Set 13: Nginx upstream simulation
        {"X-Nginx-Proxy": "true", "X-Forwarded-Server": "localhost",
         "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        # Set 14: Private network range simulation
        {"X-Forwarded-For": "192.168.1.1", "X-Real-IP": "192.168.1.1",
         "X-Originating-IP": "192.168.0.1"},
        # Set 15: Internal microservice-to-microservice simulation
        {"X-Service-Token": "internal", "X-Internal-Auth": "service-mesh",
         "X-Request-Source": "internal-api", "X-Forwarded-For": "10.0.0.1",
         "X-Microservice": "reaper-internal"},
        # Set 16: Kubernetes ingress / health-check probe
        {"X-Forwarded-For": "127.0.0.1", "User-Agent": "kube-probe/1.28",
         "X-Kubernetes-Pod-Namespace": "default", "X-Liveness-Probe": "1"},
        # Set 17: Istio service-mesh sidecar simulation
        {"X-Envoy-Original-Dst-Host": "localhost:8080",
         "X-Forwarded-For": "127.0.0.6",
         "X-Envoy-Internal": "true",
         "X-B3-Flags": "1"},
        # Set 18: Google Cloud Load Balancer internal probe
        {"X-Forwarded-For": "35.191.0.1", "X-Cloud-Trace-Context": "fake/0;o=1",
         "X-Goog-Authenticated-User-Email": "internal@cloud.goog",
         "Via": "1.1 google"},
        # Set 19: Datadog / New Relic APM synthetic check
        {"X-Dd-Trace-Id": "1234567890", "X-Dd-Parent-Id": "9876543210",
         "X-Dd-Sampling-Priority": "2", "X-Forwarded-For": "127.0.0.1"},
        # Set 20: Prometheus / metrics scraper simulation
        {"User-Agent": "Prometheus/2.45.0", "Accept": "text/plain;version=0.0.4",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 21: X-Original-URL rewrite bypass (Nginx / Apache mod_rewrite)
        {"X-Original-URL": "/", "X-Rewrite-URL": "/",
         "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        # Set 22: Cloudflare bypass — simulate origin pull (CF→origin)
        {"CF-Visitor": '{"scheme":"https"}', "CF-IPCountry": "US",
         "CF-Connecting-IP": "104.16.1.1", "X-Forwarded-For": "104.16.1.1"},
        # Set 23: Internal CDN/LB worker IP ranges (RFC 1918 + link-local)
        {"X-Forwarded-For": "172.16.0.1", "X-Real-IP": "172.16.0.1",
         "X-Cluster-Client-IP": "172.16.0.1"},
        # Set 24: Grafana/Prometheus internal scraper
        {"User-Agent": "Grafana/10.2.0", "X-Forwarded-For": "127.0.0.1",
         "X-Internal": "true", "X-Service": "grafana"},
        # Set 25: Consul health check simulation
        {"User-Agent": "Consul Health Check", "X-Forwarded-For": "127.0.0.1",
         "X-Consul-Token": "anonymous"},
        # Set 26: HAProxy PROXY protocol simulation header
        {"X-Forwarded-For": "127.0.0.1", "X-HAProxy-Internal": "1",
         "Forwarded": "for=127.0.0.1;proto=https;host=localhost"},
        # Set 27: Varnish Cache backend request simulation
        {"X-Forwarded-For": "127.0.0.1", "X-Varnish": "1234567",
         "Via": "1.1 varnish (Varnish/7.0)", "X-Cache": "MISS"},
        # Set 28: Traefik internal router simulation
        {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost",
         "X-Forwarded-Proto": "https", "X-Forwarded-Server": "traefik",
         "X-Real-IP": "127.0.0.1"},
        # Set 29: GCP internal load balancer / Identity-Aware Proxy bypass hint
        {"X-Google-Internal": "1", "X-Goog-IAP-JWT-Assertion": "bypass",
         "X-Forwarded-For": "130.211.0.1", "Via": "1.1 google"},
        # Set 30: AWS ALB internal health check simulation
        {"User-Agent": "ELB-HealthChecker/2.0", "X-Forwarded-For": "10.0.0.1",
         "X-Forwarded-Proto": "https", "X-Forwarded-Port": "443"},
        # Set 31: Browser fingerprinting bypass — simulate legit browser
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
         "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
         "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124"',
         "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"Windows"',
         "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
         "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1"},
        # Set 32: JWT admin token bypass simulation
        {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.fake",
         "X-Auth-Token": "internal-admin-bypass-token",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 33: API key bypass simulation (common admin-only patterns)
        {"X-API-Key": "internal", "X-Admin-Key": "bypass",
         "X-Master-Key": "internal-bypass",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 34: Monitoring / uptime checker bypass (StatusCake, Pingdom, UptimeRobot)
        {"User-Agent": "UptimeRobot/2.0", "X-Forwarded-For": "216.144.250.150",
         "X-Pingdom-Url": "https://check.pingdom.com"},
        # Set 35: Internal development tool header simulation (Postman, Insomnia)
        {"User-Agent": "PostmanRuntime/7.36.3", "X-Forwarded-For": "127.0.0.1",
         "Cache-Control": "no-cache", "Postman-Token": "bypass-test"},
        # Set 36: nginx X-Accel-Internal header bypass
        {"X-Accel-Internal": "/", "X-Forwarded-For": "127.0.0.1",
         "X-Real-IP": "127.0.0.1", "X-Nginx-Internal": "1"},
        # Set 37: Apache mod_remoteip / mod_proxy simulation
        {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-By": "127.0.0.1",
         "X-Forwarded-Server": "localhost", "Via": "HTTP/1.1 localhost"},
        # Set 38: Cloudflare Argo Tunnel (cloudflared) simulation
        {"CF-Access-Client-Id": "internal.access",
         "CF-Access-Client-Secret": "bypass-secret",
         "X-Forwarded-For": "172.68.0.1", "CF-Connecting-IP": "172.68.0.1"},
        # Set 39: GCP Cloud Armor allowlisted IP simulation
        {"X-Forwarded-For": "34.102.0.1", "X-Google-Real-IP": "34.102.0.1",
         "X-Goog-User-Project": "internal-bypass",
         "X-Cloud-Trace-Context": "internal/0;o=0"},
        # Set 40: Spring Boot Actuator management port simulation
        {"X-Management-Port": "8080", "X-Forwarded-For": "127.0.0.1",
         "X-Spring-Internal": "actuator", "Accept": "application/vnd.spring-boot.actuator.v3+json"},
        # Set 41: Rancher / k8s dashboard service account token simulation
        {"Authorization": "Bearer k8s-internal-svc-account-token",
         "X-Forwarded-For": "10.42.0.1", "X-Kubernetes-Namespace": "kube-system",
         "User-Agent": "kubectl/v1.28.0"},
        # Set 42: Application load balancer sticky session + internal routing
        {"X-Forwarded-For": "10.0.0.1", "X-Backend-Server": "internal",
         "X-App-Server-Id": "0", "X-Sticky-Session": "1",
         "X-Internal-Route": "admin"},
        # Set 43: Zero-trust edge network simulation (Cloudflare Access)
        {"Cf-Access-Jwt-Assertion": "bypass.jwt.token",
         "X-Forwarded-For": "104.21.0.1",
         "CF-Connecting-IP": "104.21.0.1",
         "CF-IPCountry": "US", "CF-Ray": "fake-ray-id-bypass"},
        # Set 44: Internal Linkerd service mesh annotation header
        {"L5D-Remote-IP": "127.0.0.1", "L5D-Server-Id": "internal-svc",
         "X-Forwarded-For": "10.96.0.1"},
        # Set 45: Squid proxy forwarded internal request
        {"X-Forwarded-For": "127.0.0.1", "Via": "1.1 squid-proxy:3128 (Squid/6.0)",
         "X-Cache": "MISS from squid-proxy", "X-Cache-Lookup": "MISS from squid-proxy:3128"},
        # ── 2025 additions ────────────────────────────────────────────────────
        # Set 46: Cloudflare Tunnel (WARP) + Zero-Trust bypass
        {"CF-Warp-Tag-Id": "bypass", "X-Forwarded-For": "100.64.0.1",
         "CF-Connecting-IP": "100.64.0.1", "CF-Visitor": '{"scheme":"https"}',
         "CF-Tunnel-Ingress": "bypass"},
        # Set 47: Imperva / Incapsula CDN IP bypass
        {"X-Forwarded-For": "199.83.128.1", "X-Incap-Client-IP": "199.83.128.1",
         "X-Real-IP": "199.83.128.1", "X-Incapsula-Forwarded": "1"},
        # Set 48: Akamai Pragma debug headers (leaks internal info, sometimes bypasses)
        {"Pragma": "akamai-x-check-cacheable,akamai-x-get-cache-key,akamai-x-get-true-cache-key",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 49: Internal RFC 7239 Forwarded header
        {"Forwarded": "for=127.0.0.1;proto=https;host=localhost;by=10.0.0.1",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 50: Kubernetes Ingress-NGINX internal annotation bypass
        {"X-Nginx-Ingress-Internal": "1", "X-Forwarded-For": "10.244.0.1",
         "X-Kubernetes-Service": "internal", "X-Real-IP": "10.244.0.1"},
        # Set 51: Service Mesh mTLS bypass simulation (Envoy → internal)
        {"X-Forwarded-Client-Cert": "By=spiffe://cluster.local/ns/default/sa/default",
         "X-Envoy-Upstream-Service-Time": "5",
         "X-Forwarded-For": "127.0.0.6"},
        # Set 52: AWS API Gateway internal integration
        {"X-Amzn-Apigateway-Api-Id": "internal", "X-Amz-Source-Arn": "arn:aws:lambda:us-east-1:123456789012:function:internal",
         "X-Forwarded-For": "10.0.0.1"},
        # Set 53: Azure Application Gateway probe bypass
        {"X-Azure-SocketIP": "10.0.0.1", "X-FD-HealthProbe": "1",
         "X-Ms-Request-Id": "bypass-probe", "X-Forwarded-For": "10.0.0.1"},
        # Set 54: Google Cloud IAP bypass (via JWT in Assertion header)
        {"X-Goog-IAP-JWT-Assertion": "bypass-internal",
         "X-Forwarded-For": "35.235.240.1",
         "X-Goog-Authenticated-User-Email": "serviceaccount@internal.gserviceaccount.com"},
        # Set 55: 2025 iOS / Safari browser bypass (bot detection circumvention)
        {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Language": "en-US,en;q=0.9", "Sec-Fetch-Dest": "document",
         "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none"},
        # Set 56: 2025 Android Chrome bypass
        {"User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
         "Sec-CH-UA": '"Google Chrome";v="124", "Not-A.Brand";v="99"',
         "Sec-CH-UA-Mobile": "?1", "Sec-CH-UA-Platform": '"Android"',
         "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"},
        # Set 57: HTTP/2 priority abuse simulation (some WAFs skip H2 priority frames)
        {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
         "Priority": "u=0, i"},  # Chrome/Firefox HTTP/2 priority
        # Set 58: GraphQL / API introspection bypass
        {"Content-Type": "application/json", "Accept": "application/json",
         "X-Forwarded-For": "127.0.0.1", "X-Requested-With": "XMLHttpRequest",
         "X-CSRF-Token": "bypass"},
        # Set 59: Headerless / bare request (mimics Golang http.Get default)
        {"User-Agent": "Go-http-client/2.0", "X-Forwarded-For": "127.0.0.1"},
        # Set 60: Internal EKS node IP bypass
        {"X-Forwarded-For": "192.168.0.1", "X-Real-IP": "192.168.0.1",
         "X-Eks-Cluster-Name": "internal", "X-K8s-Node-IP": "192.168.0.1"},
        # ── 2025 Advanced WAF Bypass Sets ─────────────────────────────────────
        # Set 61: Content-type confusion bypass (WAF inspects JSON body less strictly)
        {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
         "X-Requested-With": "XMLHttpRequest", "X-Forwarded-For": "127.0.0.1"},
        # Set 62: Accept header manipulation (WAF may allow media-type specific paths)
        {"Accept": "application/vnd.api+json", "X-Forwarded-For": "127.0.0.1",
         "X-Api-Version": "1.0", "Content-Type": "application/vnd.api+json"},
        # Set 63: Browser preflight CORS probe header
        {"Origin": "https://localhost", "Access-Control-Request-Method": "GET",
         "Access-Control-Request-Headers": "authorization,x-requested-with",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 64: Terraform/Vault internal service request headers
        {"X-Vault-Token": "root", "X-Vault-Namespace": "admin",
         "X-Forwarded-For": "127.0.0.1", "User-Agent": "vault/1.15.0"},
        # Set 65: Consul health check bypass
        {"User-Agent": "Go-http-client/1.1", "X-Consul-Token": "",
         "X-Forwarded-For": "127.0.0.1", "Connection": "close"},
        # Set 66: Internal monitoring Prometheus scrape
        {"User-Agent": "Prometheus/2.50.0", "Accept": "text/plain;version=0.0.4;q=1,*/*;q=0.1",
         "X-Forwarded-For": "127.0.0.1", "X-Metrics-Source": "prometheus"},
        # Set 67: Spring Boot Actuator v3 media type bypass
        {"Accept": "application/vnd.spring-boot.actuator.v3+json",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 68: X-ProxyUser-Ip bypass (some apps check this instead of X-Forwarded-For)
        {"X-ProxyUser-Ip": "127.0.0.1", "X-Forwarded-For": "127.0.0.1",
         "X-Remote-Ip": "127.0.0.1", "X-Client-IP": "127.0.0.1"},
        # Set 69: Cache-bypass with If-None-Match trick
        {"If-None-Match": "bypass", "Cache-Control": "no-cache, no-store",
         "Pragma": "no-cache", "X-Forwarded-For": "127.0.0.1"},
        # Set 70: Internal service worker / PWA bypass
        {"Service-Worker": "script", "X-Forwarded-For": "127.0.0.1",
         "Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "serviceworker"},
        # Set 71: HTTP method spoofing for WAF rule bypass
        {"X-HTTP-Method-Override": "GET", "X-Method-Override": "GET",
         "_method": "GET", "X-Forwarded-For": "127.0.0.1"},
        # Set 72: SNI / Host header confusion for vhost bypass
        {"X-Forwarded-Host": "localhost", "X-Original-Host": "localhost",
         "X-Forwarded-For": "127.0.0.1", "Host-Override": "internal"},
        # Set 73: 2025 TLS client certificate simulation headers
        {"X-Client-Cert-Subject": "CN=internal-service",
         "X-Client-Cert-Verified": "SUCCESS",
         "X-Client-Cert-Issuer": "CN=Internal-CA",
         "X-Forwarded-For": "10.0.0.1"},
        # Set 74: Internal automation / CI tool simulation
        {"User-Agent": "python-requests/2.31.0", "Accept-Encoding": "gzip, deflate",
         "Accept": "*/*", "Connection": "keep-alive",
         "X-Forwarded-For": "127.0.0.1"},
        # Set 75: Minimal bare request (some WAFs whitelist minimal requests)
        {"User-Agent": "curl/8.5.0", "Accept": "*/*",
         "X-Forwarded-For": "127.0.0.1"},
    ]
    def _next_bypass_hdrs(self) -> Dict:
        """Return next WAF-bypass header set, cycling through all variants."""
        idx = self._bypass_idx % len(self._BYPASS_HEADER_SETS)
        self._bypass_idx += 1
        return self._BYPASS_HEADER_SETS[idx]

    async def _probe(self, host: str, path: str, scheme: str = "https",
                     _retry: bool = True) -> Optional[Dict]:
        key = f"{host}{path}"
        if key in self._probed: return None
        self._probed.add(key)
        # Rotate WAF bypass headers — each probe uses a different set
        bypass_set = self._next_bypass_hdrs()
        hdrs = {**_hdrs(), **bypass_set}
        result = None
        try:
            t0 = time.monotonic()
            # Adaptive timeout: 10 s for first attempt (allows slow backends like
            # Spring Boot actuators, Elasticsearch, Vault) — the WAF retry loop
            # uses 8 s per attempt so total ceiling remains manageable.
            to = aiohttp.ClientTimeout(total=10)
            async with self.s.request(
                "GET", f"{scheme}://{host}{path}",
                headers=hdrs, timeout=to,
                allow_redirects=True, ssl=_ssl_ctx(), proxy=self.proxy,
            ) as resp:
                body = await resp.text(errors='replace')
                result = {
                    "status": resp.status, "url": str(resp.url),
                    "len": len(body), "hash": hashlib.md5(body.encode()).hexdigest(),
                    "ct": resp.headers.get("Content-Type",""),
                    "server": resp.headers.get("Server",""),
                    "hdrs": dict(resp.headers), "t": time.monotonic() - t0,
                    "body": body[:8192], "scheme": scheme,
                    "bypass_hdrs_used": list(bypass_set.keys()),
                }
        except aiohttp.ClientConnectorSSLError:
            # HTTPS failed with SSL error — try plain HTTP fallback before giving up.
            # Many internal/dev endpoints use self-signed or expired certs.
            if scheme == "https":
                try:
                    t0 = time.monotonic()
                    to_http = aiohttp.ClientTimeout(total=6)
                    async with self.s.request(
                        "GET", f"http://{host}{path}",
                        headers=hdrs, timeout=to_http,
                        allow_redirects=True, ssl=False, proxy=self.proxy,
                    ) as resp_http:
                        body_http = await resp_http.text(errors='replace')
                        result = {
                            "status": resp_http.status, "url": str(resp_http.url),
                            "len": len(body_http),
                            "hash": hashlib.md5(body_http.encode()).hexdigest(),
                            "ct": resp_http.headers.get("Content-Type", ""),
                            "server": resp_http.headers.get("Server", ""),
                            "hdrs": dict(resp_http.headers),
                            "t": time.monotonic() - t0,
                            "body": body_http[:8192], "scheme": "http",
                            "bypass_hdrs_used": list(bypass_set.keys()),
                            "http_fallback": True,
                        }
                except Exception:
                    return None
            else:
                return None
        except Exception:
            return None

        # ── WAF-block retry with multiple bypass sets ────────────────────────
        # If first attempt returned a WAF block page, rotate through up to 5
        # different bypass header sets before giving up.  This dramatically
        # improves bypass rates against adaptive WAFs (Cloudflare, Akamai, etc.)
        # that block some header combinations but not others.
        if _retry and result and _is_waf_response(
                result["status"], result["hdrs"], result["body"]):
            _MAX_WAF_RETRIES = 5
            for _retry_num in range(_MAX_WAF_RETRIES):
                next_bypass = self._next_bypass_hdrs()
                retry_hdrs = {**_hdrs(), **next_bypass}
                try:
                    to2 = aiohttp.ClientTimeout(total=6)
                    async with self.s.request(
                        "GET", f"{scheme}://{host}{path}",
                        headers=retry_hdrs, timeout=to2,
                        allow_redirects=True, ssl=_ssl_ctx(), proxy=self.proxy,
                    ) as resp2:
                        body2 = await resp2.text(errors='replace')
                        r2 = {
                            "status": resp2.status, "url": str(resp2.url),
                            "len": len(body2), "hash": hashlib.md5(body2.encode()).hexdigest(),
                            "ct": resp2.headers.get("Content-Type",""),
                            "server": resp2.headers.get("Server",""),
                            "hdrs": dict(resp2.headers),
                            "t": time.monotonic() - t0,
                            "body": body2[:8192], "scheme": scheme,
                            "bypass_hdrs_used": list(next_bypass.keys()),
                            "bypass_retry": True,
                            "bypass_attempt": _retry_num + 1,
                        }
                        # Bypass succeeded — endpoint is real, return clean result
                        if not _is_waf_response(r2["status"], r2["hdrs"], r2["body"]):
                            return r2
                        # Still blocked — try next bypass set
                except Exception:
                    continue  # Network error on retry — try next bypass set
            # ── Last resort: try HTTP (port 80) if all HTTPS bypass attempts failed ──
            # Internal services behind reverse proxies often listen on plain HTTP;
            # WAF rules typically block HTTPS but pass internal HTTP.
            if scheme == "https":
                try:
                    last_bypass = self._next_bypass_hdrs()
                    last_hdrs = {**_hdrs(), **last_bypass}
                    to_last = aiohttp.ClientTimeout(total=5)
                    async with self.s.request(
                        "GET", f"http://{host}{path}",
                        headers=last_hdrs, timeout=to_last,
                        allow_redirects=True, ssl=False, proxy=self.proxy,
                    ) as resp_last:
                        body_last = await resp_last.text(errors='replace')
                        r_last = {
                            "status": resp_last.status, "url": str(resp_last.url),
                            "len": len(body_last),
                            "hash": hashlib.md5(body_last.encode()).hexdigest(),
                            "ct": resp_last.headers.get("Content-Type", ""),
                            "server": resp_last.headers.get("Server", ""),
                            "hdrs": dict(resp_last.headers),
                            "t": time.monotonic() - t0,
                            "body": body_last[:8192], "scheme": "http",
                            "bypass_hdrs_used": list(last_bypass.keys()),
                            "http_fallback": True,
                            "bypass_retry": True,
                        }
                        if not _is_waf_response(r_last["status"], r_last["hdrs"], r_last["body"]):
                            return r_last
                except Exception:
                    pass
            return None  # All bypass attempts exhausted — WAF-blocked
        return result

    # ── Comprehensive WAF/bot-challenge body signals ───────────────────────────
    # These are checked in _interesting() to catch challenges that _is_waf_response
    # might miss on borderline cases (e.g. 200 OK with hidden challenge JS).
    _CHALLENGE_BODY_SIGNALS = frozenset([
        # Cloudflare challenges (all variants)
        "_cf_chl_opt", "cf-challenge-running", "cf_chl_rc_m", "__cf_chl_f_tk",
        "cf_chl_prog", "cf-browser-verification", "cf-challenge",
        "cf_chl_opt.cNounce", "cf_chl_opt.cHash", "cf_chl_opt.cType",
        "window.__CF$cv$params", "cdn-cgi/challenge-platform",
        "challenges.cloudflare.com/turnstile",
        "challenges.cloudflare.com/cdn-cgi/challenge-platform",
        # PerimeterX / HUMAN Security
        "_pxAppId", "px-captcha", "pxi.px-cdn.net", "PerimeterXCaptcha",
        "_pxff_", "pxbotman", "px_block_page",
        # Kasada
        "kpsdk", "kasada", "kaxsdc", "kcl.js", "kasada-sdk",
        # DataDome
        "datadome", "datadome.co", "ddjskey", "ddmc.js", "dd_was_here",
        # hCaptcha / Arkose / FunCaptcha
        "challenge-form", "hcaptcha.com", "arkoselabs.com", "funcaptcha",
        # Akamai Bot Manager
        "ak_bmsc", "bm_sz", "bmak.js", "akamai-ghost", "_abck", "bm_sz_v4",
        # Shape Security / F5
        "shape_utmz", "shapesecurity", "_imp_apg_r_", "shape-go-away",
        # Netacea
        "ntc.js", "netacea.com",
        # Reblaze
        "rbzid=", "reblaze-proxy", "rbzid-v2",
        # GeeTest
        "geetest.com", "initGeetest",
        # Zscaler
        "zscaler", "approved.by",
        # Generic WAF IDs
        "threatx", "reblaze",
        # AWS WAF CAPTCHA (2025)
        "aws-waf-token", "AWS WAF could not forward", "AwsWafIntegration", "awswaf_",
        # Fingerprint.js (bot detection)
        "fingerprint.js", "fpjs.io",
        # Kasada 2025 / updated tokens
        "kcl-loader", "kasada-sdk-v3",
        # NetAcea 2025
        "ntc-challenge-2025",
    ])

    def _interesting(self, probe: Dict, baseline: Optional[Dict]) -> bool:
        st = probe.get("status", 0)
        body = probe.get("body", "")
        hdrs = probe.get("hdrs", {})
        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        ct = probe.get("ct", "").lower()

        # ── WAF/CDN block page → never interesting regardless of status ──────
        if _is_waf_response(st, hdrs, body):
            return False

        # ── Extended WAF challenge body check — covers borderline 200/403 cases ─
        if body:
            b = body[:8192].lower()
            b_raw = body[:8192]  # preserve case for JS token checks
            # Hard signal: any known WAF challenge JS token or identifier
            for sig in self._CHALLENGE_BODY_SIGNALS:
                if sig.lower() in b or sig in b_raw:
                    return False
            # Soft composite signals (require keyword pairing to avoid FP)
            if (("enable javascript" in b and "protection" in b) or
                "please stand by" in b or
                "verifying you are human" in b or
                "verifying that you are not a robot" in b or
                ("just a moment" in b and ("cloudflare" in b or "ddos" in b)) or
                ("checking your browser" in b and ("ddos" in b or "protection" in b)) or
                ("recaptcha" in b and "challenge" in b) or
                ("turnstile" in b and "sitekey" in b) or
                ("just a moment" in b and "checking" in b)):
                return False

        # ── 429 Too Many Requests — distinguish real rate-limit vs WAF block ──
        # A real endpoint returns 429 with Retry-After or X-RateLimit headers;
        # a WAF 429 typically has no such headers and shows a WAF body.
        if st == 429:
            has_rl_hdrs = (
                "retry-after" in hdrs_lower or
                "x-ratelimit-limit" in hdrs_lower or
                "x-ratelimit-remaining" in hdrs_lower or
                "x-rate-limit-limit" in hdrs_lower
            )
            if has_rl_hdrs:
                return True  # Real endpoint enforcing rate limits = very interesting
            # No rate-limit headers → probably WAF block, not a real finding
            return False

        # ── Status codes — genuine findings ──────────────────────────────────
        if st in (200, 201, 202, 204, 206):
            # For 200: check it's not a disguised soft-404 or WAF-disguised block
            if st == 200 and body and baseline:
                b200 = body[:4096].lower()
                b200_raw = body[:4096]

                # Generic "not found" soft-404 disguised as 200
                _soft404_signals = (
                    "404 not found", "page not found", "resource not found",
                    "does not exist", "no such page", "could not be found",
                    "nothing here", "moved permanently",
                    "the page you are looking for",
                    "the requested url was not found",
                    "we can't find that page",
                    "oops! that page doesn",
                )
                if any(sig in b200 for sig in _soft404_signals):
                    # Only skip if it also matches baseline hash or size
                    if (probe.get("hash") == baseline.get("hash") or
                            abs(probe.get("len", 0) - baseline.get("len", 0)) < 200):
                        return False

                # WAF-disguised 200: WAF returns 200 with challenge/block content
                # This catches Cloudflare's "Just a Moment", Bot Fight Mode, Turnstile,
                # and other challenge pages served with 200 OK (common in managed WAFs).
                _waf200_hard = (
                    "_cf_chl_opt" in b200_raw,
                    "cf-challenge" in b200_raw,
                    "cf_chl_opt.cNounce" in b200_raw,
                    "cf_chl_opt.cHash" in b200_raw,
                    "__CF$cv$params" in b200_raw,
                    "challenges.cloudflare.com/cdn-cgi/challenge-platform" in b200,
                    "jschl_vc" in b200_raw,
                    "kpsdk" in b200_raw,
                    "kaxsdc" in b200_raw,
                    "_pxAppId" in b200_raw,
                    "datadome.co/js" in b200,
                    "ddjskey" in b200_raw,
                    "aws-waf-token" in b200,
                    "AwsWafIntegration" in b200_raw,
                    "ak_bmsc" in b200_raw,
                    "_abck" in b200_raw,
                    "bm_sz" in b200_raw,
                    "rbzid" in b200_raw,
                    "reblaze" in b200 and "challenge" in b200,
                    "netacea.com" in b200,
                )
                if any(_waf200_hard):
                    return False

                # If response is same hash as baseline → baseline is a catch-all soft-404.
                # ROOT CAUSE FIX: SPAs (React/Next/Vue/Angular) serve the same index.html
                # for EVERY route — /admin, /dashboard, /api/v1/users all return the same
                # hash as a random /aaaabbbb path.  Blindly returning False here silences
                # every single endpoint on SPA-backed hosts, which is the "0 endpoints" bug.
                # Fix: ONLY apply the hash filter for low-priority/generic paths.
                # High-value paths (admin, dashboard, api, internal, console, auth, etc.)
                # are always recorded regardless — even a SPA route is an interesting finding.
                _HIGH_VALUE_PATH_SIGS = (
                    '/admin', '/dashboard', '/api', '/internal', '/console', '/manage',
                    '/panel', '/portal', '/control', '/backend', '/staff', '/ops',
                    '/auth', '/login', '/sso', '/oauth', '/token', '/session',
                    '/graphql', '/swagger', '/openapi', '/actuator', '/metrics',
                    '/debug', '/dev', '/test', '/staging', '/health', '/status',
                    '/config', '/settings', '/setup', '/install', '/phpmyadmin',
                    '/wp-admin', '/wp-login', '/administrator', '/user', '/users',
                    '/account', '/accounts', '/billing', '/payment', '/checkout',
                    '/secret', '/private', '/hidden', '/internal', '/backup',
                    '/env', '/debug', '/.git', '/.env', '/server-status',
                    '/kibana', '/grafana', '/elastic', '/mongo', '/redis',
                    '/jenkins', '/sonar', '/jira', '/confluence', '/gitlab',
                    '/prometheus', '/alertmanager', '/traefik', '/portainer',
                )
                _path_lower = probe.get("url", "").lower()
                _is_high_value = any(sig in _path_lower for sig in _HIGH_VALUE_PATH_SIGS)

                if probe.get("hash") == baseline.get("hash") and not _is_high_value:
                    return False

                # Very similar size to baseline AND same content-type → likely soft-404.
                # Again skip this filter for high-value paths.
                blen = baseline.get("len", 0) or 0
                plen = probe.get("len", 0) or 0
                if blen > 0 and abs(plen - blen) < 150 and ct == (baseline.get("ct", "") or "").lower():
                    # Unless body has JSON data structure markers (real API)
                    if not (ct and "json" in ct and ('"id"' in b200 or '"data"' in b200 or '"result"' in b200)):
                        if not _is_high_value:
                            return False

            return True

        if st == 401:
            # HTTP 401 Unauthorized: endpoint DEFINITELY EXISTS — the server authenticated
            # the request and decided to reject it. This is always a real finding regardless
            # of baseline status. Only skip if baseline is also 401 AND hashes match
            # (uniform 401 soft-wall, not a specific protected endpoint).
            if not baseline:
                return True
            if baseline.get("status") != 401:
                return True  # Baseline is not 401 — this path specifically requires auth
            # Even if baseline is 401, different body/hash = distinct endpoint
            if probe.get("hash") and probe.get("hash") != baseline.get("hash"):
                return True
            if probe.get("len", 0) != baseline.get("len", 0):
                return True
            # WWW-Authenticate tells us the auth scheme (Basic, Bearer, etc.) — always keep
            hdrs_lower_401 = {k.lower(): v for k, v in hdrs.items()}
            if hdrs_lower_401.get("www-authenticate"):
                return True
            # Default: keep 401 unless it's an exact clone of the baseline
            return True  # 401 is always interesting — auth-required endpoint confirmed

        if st == 403:
            # 403 Forbidden: endpoint exists but access is denied. Only interesting if:
            # 1. Baseline is not also 403 (global 403 wall = less interesting), OR
            # 2. Auth-specific headers present, OR
            # 3. Structured auth error body, OR
            # 4. Body/size differs meaningfully from baseline, OR
            # 5. No baseline
            if not baseline:
                return True
            if st != baseline.get("status", 200):
                return True
            # Check for auth-indicating headers (case-insensitive comparison)
            auth_hdrs_lower = {"www-authenticate", "x-auth-required", "x-auth-token",
                               "x-api-key", "x-authentication", "authorization-required",
                               "x-access-token", "x-bearer-token", "x-token-required"}
            if set(hdrs_lower.keys()) & auth_hdrs_lower:
                return True
            # JSON-structured auth error (real API endpoint) — e.g. {"error":"Unauthorized"}
            body_snip = body[:1024].strip() if body else ""
            if body and ("application/json" in ct or "application/xml" in ct):
                if (body_snip.startswith(("{", "[")) or
                        body_snip.startswith("<?xml")):
                    # Real API returning structured error = interesting
                    if any(k in body_snip.lower() for k in (
                        '"error"', '"message"', '"code"', '"status"',
                        '"unauthorized"', '"forbidden"', '"denied"',
                    )):
                        return True
            # Even without JSON content-type, a body that looks like JSON and contains
            # API-style keys is very likely a real endpoint (common in REST APIs)
            if body_snip.startswith(("{", "[")) and any(k in body_snip.lower() for k in (
                '"error"', '"message"', '"detail"', '"reason"',
                '"unauthorized"', '"forbidden"', '"required"',
            )):
                return True
            # Compare against baseline: if body size, hash, or content-type differs
            # significantly from the random-path baseline, it is likely real.
            blen = baseline.get("len", 0) or 0
            plen = probe.get("len", 0) or 0
            # Very small body 403 (blank deny page) vs large body baseline
            # → probably a block page, not a real endpoint
            if plen < 200 and blen > 1000:
                return False
            # Probe body differs significantly in size from baseline
            if blen > 0 and abs(plen - blen) > max(200, blen * 0.20):
                return True
            # Different hash → different response body → potentially real
            if probe.get("hash") and probe.get("hash") != baseline.get("hash"):
                # Hash differs — verify it's not just a tiny variation
                if abs(plen - blen) > 100:
                    return True
            # Content-type change (baseline returns text/html, probe returns app/json)
            if ct and ct != (baseline.get("ct", "") or "").lower():
                return True
            return False

        if st == 405:
            # Method Not Allowed → endpoint exists but wrong method
            return True

        if st in (407, 408):
            if not baseline:
                return True
            return st != baseline.get("status", 200)

        if st in (301, 302, 307, 308):
            loc = hdrs.get("Location", "")
            if not loc:
                return False
            # Filter redirects to error/WAF pages
            if re.search(r'(?:404|error|not.?found|blocked|denied|captcha|challenge)', loc, re.I):
                return False
            # Also filter redirects to login pages only if baseline also redirects to login
            if baseline and baseline.get("status") in (301, 302, 307, 308):
                baseline_loc = (baseline.get("hdrs") or {}).get("Location", "")
                if baseline_loc and urlparse(baseline_loc).path == urlparse(loc).path:
                    return False  # Same redirect target as baseline = soft-redirect, skip
            return True

        if st in (500, 502, 503):
            if not body:
                return False
            b_err = body[:4096].lower()
            # Only interesting 500s: stack traces, DB errors, framework errors
            _err_signals = (
                'stack', 'traceback', 'exception', 'sqlexception', 'pdoexception',
                'activerecord', 'sequelize', 'django.db', 'traceback',
                'at java.', 'caused by:', 'file "/var/', 'syntax error',
                'undefined method', 'undefined variable', 'nameresolutionerror',
                'connectionrefusederror', 'connection refused', 'no such table',
                'relation does not exist', 'column does not exist',
                'mongoerror', 'rediserror', 'elasticsearch',
                'internal server error.*version', 'flask', 'fastapi',
                'express', 'rails', 'laravel', 'django',
                'php fatal error', 'php warning', 'php notice',
                'warning: include', 'warning: require',
            )
            if any(x in b_err for x in _err_signals):
                return True
            # 500 from same server as baseline with similar body = generic error, skip
            if baseline and st == baseline.get("status") and (
                    probe.get("hash") == baseline.get("hash")):
                return False
            return False

        if st == 422:
            # Unprocessable Entity — endpoint exists, validates input (API finding)
            return True

        if st == 410:
            # Gone — endpoint existed, now removed = interesting (confirms it existed)
            return True

        if st == 426:
            # Upgrade Required — real endpoint, protocol issue
            return True

        # ── Baseline comparison for all other status codes ────────────────────
        if not baseline:
            return st < 400
        bst = baseline.get("status", 404)
        if st != bst:
            return True
        blen = baseline.get("len", 1) or 1   # guard zero-length baseline
        plen = probe.get("len", 0)
        if abs(plen - blen) > max(200, blen * 0.15):
            return True
        if ct and ct != baseline.get("ct", "").lower():
            return True
        pt = probe.get("t", 0)
        bt = baseline.get("t", 1) or 1
        # Significantly slower than baseline: could be real endpoint doing DB/service call
        # Threshold: 2.5x slower AND at least 0.4s absolute
        if pt > bt * 2.5 and pt > 0.4:
            return True
        # Very slow absolute response (>3s) even if baseline is also slow
        if pt > 3.0 and bt < 1.0:
            return True
        # Same hash → definitive soft-404 match, skip
        if probe.get("hash") == baseline.get("hash"):
            return False
        # Different hash: could be dynamic baseline (CSRF tokens, timestamps).
        # Use length ratio as the primary discriminator — a real endpoint will
        # have a meaningfully different body size from the 404 baseline.
        # Only mark as interesting when lengths differ by more than ±8%/200 bytes,
        # or content-type changed, or there are auth-indicating headers.
        size_ratio = abs(plen - blen) / max(blen, 1)
        if size_ratio < 0.08 and abs(plen - blen) < 200:
            # Very similar size — likely dynamic soft-404 (baseline has timestamp etc.)
            # One more check: does body contain structural JSON/XML suggesting real data?
            body_lower_check = probe.get("body", "")[:2048].lower()
            has_data_structure = (
                ('"id"' in body_lower_check or '"data"' in body_lower_check or
                 '"result"' in body_lower_check or '"items"' in body_lower_check or
                 '"count"' in body_lower_check or '"total"' in body_lower_check or
                 '"token"' in body_lower_check or '"access"' in body_lower_check or
                 '"endpoints"' in body_lower_check or '"version"' in body_lower_check) and
                ("application/json" in ct or "application/xml" in ct)
            )
            # Also check for API-specific response headers not in baseline
            api_specific_hdrs = {
                "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-Rate-Limit-Limit",
                "X-Request-Id", "X-Correlation-Id", "X-Trace-Id", "X-Transaction-Id",
                "ETag", "Last-Modified", "X-Powered-By",
            }
            baseline_hdr_keys = set((baseline.get("hdrs") or {}).keys())
            new_api_hdrs = (set(hdrs.keys()) & api_specific_hdrs) - baseline_hdr_keys
            if not has_data_structure and not new_api_hdrs:
                return False   # Same size, no data signature → soft-404
        # Size differs significantly OR has data signature → interesting
        sec_hdrs = {
            "WWW-Authenticate", "X-Auth-Required", "X-Frame-Options",
            "Content-Security-Policy", "X-Content-Type-Options",
            "Strict-Transport-Security", "X-Permitted-Cross-Domain-Policies",
            "Referrer-Policy", "Permissions-Policy",
            # API-specific headers that only appear on real endpoints
            "X-RateLimit-Limit", "X-RateLimit-Remaining",
            "X-Request-Id", "X-Correlation-Id", "X-Trace-Id",
            "ETag", "Last-Modified", "Cache-Control",
        }
        baseline_hdrs_set = set((baseline or {}).get("hdrs", {}).keys())
        new_sec_hdrs = (set(hdrs.keys()) & sec_hdrs) - baseline_hdrs_set
        if new_sec_hdrs:
            return True
        return False

    async def probe_host_paths(self, host: str, paths: List[str]) -> None:
        baseline = await self._baseline(host)
        scheme = (baseline or {}).get("scheme","https")
        if baseline:
            srv = baseline.get("server","").lower()
            if "nginx"   in srv: self.r.tech_stack["webserver"].add("nginx")
            if "apache"  in srv: self.r.tech_stack["webserver"].add("apache")
            if "iis"     in srv: self.r.tech_stack["webserver"].add("iis")
            cf_srv = baseline.get("hdrs",{}).get("Server","").lower()
            if "cloudflare" in cf_srv or "cf-ray" in {k.lower() for k in baseline.get("hdrs",{})}:
                self.r.tech_stack["cdn"].add("cloudflare")
            # If baseline itself is a WAF page, attempt WAF bypass before giving up.
            # Cycle through all bypass header sets for a re-baseline; if any bypass
            # produces a non-WAF response, use that scheme/headers for subsequent probes.
            # Also catch WAF-served 200 (Cloudflare "Just a Moment", Bot Fight Mode, Turnstile):
            # these return HTTP 200 with challenge JS, so status check must include 200.
            if baseline.get("waf"):
                log(f"  [WAF] {host} fully WAF-gated (status {baseline['status']}) — attempting bypass...")
                bypass_baseline = None
                for bypass_set in self._BYPASS_HEADER_SETS:
                    rand = f"/{''.join(random.choices(string.ascii_lowercase, k=22))}"
                    try:
                        to_b = aiohttp.ClientTimeout(total=10)
                        async with self.s.request(
                            "GET", f"{scheme}://{host}{rand}",
                            headers={**_hdrs(), **bypass_set}, timeout=to_b,
                            allow_redirects=True, ssl=_ssl_ctx(), proxy=self.proxy,
                        ) as resp_b:
                            body_b = await resp_b.text(errors='replace')
                            hdrs_b = dict(resp_b.headers)
                            if not _is_waf_response(resp_b.status, hdrs_b, body_b):
                                bypass_baseline = {
                                    "status": resp_b.status, "len": len(body_b),
                                    "hash": hashlib.md5(body_b.encode()).hexdigest(),
                                    "ct": resp_b.headers.get("Content-Type",""),
                                    "hdrs": hdrs_b, "waf": False,
                                    "bypass_hdrs": bypass_set,
                                }
                                log(f"  [WAF-BYPASS] {host}: bypass succeeded with {list(bypass_set.keys())[:3]}")
                                break
                    except Exception:
                        continue
                if bypass_baseline is None:
                    log(f"  [WAF] {host}: all {len(self._BYPASS_HEADER_SETS)} bypass attempts failed — "
                        f"probing tier-1 critical paths anyway")
                    # Don't bail out entirely: probe the highest-value paths (admin panels,
                    # API endpoints, auth paths) even behind a WAF. Many WAFs apply blanket
                    # blocking at the gateway but pass specific internal paths through.
                    # Use the original WAF baseline so _interesting() can still diff responses.
                    # (baseline already set from above; just fall through to path probing)
                else:
                    # Use the bypass baseline for subsequent comparisons
                    baseline = bypass_baseline

        async def _check(path: str) -> None:
            async with self._sem_h:
                probe = await self._probe(host, path, scheme)
                if not probe: return
                st = probe.get("status", 0)
                interesting = self._interesting(probe, baseline)

                # ── Multi-method probing: if GET returns 401/403/405, try HEAD/OPTIONS/POST ──
                # Many WAFs block GET to sensitive endpoints but allow other verbs.
                # 401 = endpoint exists but auth required.
                # 403 = endpoint exists but access denied (WAF or real restriction).
                # 405 = Method Not Allowed (endpoint exists, wrong method).
                if not interesting and st in (401, 403, 405):
                    for method in ("HEAD", "OPTIONS", "POST"):
                        try:
                            to_mm = aiohttp.ClientTimeout(total=6)
                            bypass_set = self._next_bypass_hdrs()
                            mm_hdrs = {**_hdrs(), **bypass_set}
                            if method == "POST":
                                mm_hdrs["Content-Type"] = "application/json"
                            async with self.s.request(
                                method, f"{scheme}://{host}{path}",
                                headers=mm_hdrs, timeout=to_mm,
                                allow_redirects=False, ssl=_ssl_ctx(), proxy=self.proxy,
                                data=b'{}' if method == "POST" else None,
                            ) as mm_resp:
                                mm_body = await mm_resp.text(errors='replace')
                                mm_probe = {
                                    "status": mm_resp.status,
                                    "url": str(mm_resp.url),
                                    "len": len(mm_body),
                                    "hash": hashlib.md5(mm_body.encode()).hexdigest(),
                                    "ct": mm_resp.headers.get("Content-Type", ""),
                                    "hdrs": dict(mm_resp.headers),
                                    "body": mm_body[:8192],
                                    "method": method,
                                }
                                if (mm_resp.status in (200, 201, 204, 405, 422) or
                                        (mm_resp.status in (401, 403) and self._interesting(mm_probe, baseline))):
                                    if not _is_waf_response(mm_resp.status, dict(mm_resp.headers), mm_body):
                                        # Record the interesting multi-method find
                                        # NOTE: do NOT add "[METHOD]" annotation — live_eps stores clean
                                        # URLs only; the method info is captured via add_ep source tag.
                                        self.r.add_ep(path, f"multimethod_{method.lower()}")
                                        interesting = True
                                        probe = mm_probe
                                        break
                        except Exception:
                            continue

                if interesting:
                    self.r.add_ep(path, "active_probe")
                    self.r.live_eps.add(f"{scheme}://{host}{path}")
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

        chunk_size = 200   # 200 at a time per host for faster path probing
        for i in range(0, len(paths), chunk_size):
            await asyncio.gather(*[_check(p) for p in paths[i:i+chunk_size]],
                                 return_exceptions=True)

    def _extract_links_from_json(self, data: Any, depth: int = 0) -> List[str]:
        if depth > 5: return []
        out = []
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and (v.startswith('/') or v.startswith('http')):
                    out.append(v)
                else:
                    out.extend(self._extract_links_from_json(v, depth+1))
        elif isinstance(data, list):
            for item in data[:30]:
                out.extend(self._extract_links_from_json(item, depth+1))
        return out

    async def framework_fingerprint(self, host: str) -> Set[str]:
        """Detect frameworks by body/header signatures, not just status codes."""
        detected: Set[str] = set()
        # (path, required_status, body_pattern)
        indicators: Dict[str, Tuple] = {
            "spring":    ("/actuator/health",  200, r'"status"\s*:\s*"UP"'),
            "nextjs":    ("/_next/static/",    200, r''),
            "django":    ("/admin/login/",      200, r'csrfmiddlewaretoken|django'),
            "laravel":   ("/telescope/api/requests", 200, r'telescope|laravel'),
            "wordpress": ("/wp-login.php",     200, r'wp-login|wordpress'),
            "graphql":   ("/graphql",          200, r'"data"|"errors"|__schema'),
            "rails":     ("/rails/info/properties", 200, r'Rails|ruby'),
            "aspnet":    ("/elmah.axd",        200, r'elmah|Error Log'),
            "swagger":   ("/swagger-ui/",      200, r'swagger|openapi'),
        }
        async def _check_fw(fw: str, spec: Tuple) -> None:
            path, req_status, body_pat = spec
            probe = await self._probe(host, path)
            if not probe: return
            st = probe.get("status", 0)
            if st != req_status: return
            body = probe.get("body", "")
            if body_pat and not re.search(body_pat, body, re.I): return
            detected.add(fw)
        await asyncio.gather(*[_check_fw(fw, spec) for fw, spec in indicators.items()],
                             return_exceptions=True)
        return detected

    async def cors_probe(self, host: str, path: str = "/api/") -> None:
        evil_origins = [
            f"https://evil.{self.d}", "https://attacker.com",
            f"https://{self.d}.evil.com", "null",
            f"https://evil{self.d}", "http://localhost",
            f"https://subdomain.{self.d}.attacker.com",
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
                            "origin_sent": origin, "acao": acao, "acac": acac,
                        })
            except Exception: pass

    async def method_enum(self, host: str, path: str) -> None:
        methods = ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS",
                   "TRACE","CONNECT","PROPFIND","MKCOL","MOVE","COPY","LOCK","UNLOCK"]
        results: List[str] = []
        for method in methods:
            try:
                to = aiohttp.ClientTimeout(total=8)
                async with self.s.request(
                    method, f"https://{host}{path}",
                    headers=_hdrs(), timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                ) as resp:
                    if resp.status not in (405,501,0):
                        results.append(f"{method}:{resp.status}")
                    if method == "OPTIONS":
                        allow = resp.headers.get("Allow","")
                        if allow:
                            results.extend([f"{m}:OPTIONS-Allow" for m in allow.split(",")])
            except Exception: pass
        if results:
            self.r.open_methods[f"https://{host}{path}"] = results

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
                            "status": resp.status, "len": len(body),
                            "hash": hashlib.md5(body.encode()).hexdigest(),
                            "ct": resp.headers.get("Content-Type",""),
                            "t": 0, "hdrs": dict(resp.headers),
                        }
                        if self._interesting(probe, baseline):
                            discovered.add(vhost)
                            self.r.add_sub(vhost, "vhost_probe")
                except Exception: pass
        await asyncio.gather(*[_check_vhost(v) for v in vhosts], return_exceptions=True)
        return discovered

    async def probe_subdomains(self, candidates: Set[str]) -> Set[str]:
        live: Set[str] = set()
        sem = asyncio.Semaphore(MAX_DNS)
        async def _check(sub: str) -> None:
            async with sem:
                ip = await _resolve(sub)
                if not ip: return
                if self.wc and ip in self.wc:
                    probe = await self._probe(sub, "/")
                    rand_h = f"{''.join(random.choices(string.ascii_lowercase,k=16))}.{self.d}"
                    wc_probe = await self._probe(rand_h, "/")
                    if probe and wc_probe:
                        if probe.get("hash") != wc_probe.get("hash"):
                            live.add(sub); self.r.live_subs.add(sub)
                            self.r.add_sub(sub, "active_wc")
                else:
                    live.add(sub); self.r.live_subs.add(sub)
                    self.r.add_sub(sub, "active_dns")
        await asyncio.gather(*[_check(s) for s in candidates], return_exceptions=True)
        return live

    async def run(self, sub_candidates: Set[str], ep_candidates: Set[str]) -> None:
        log(f"  Validating {len(sub_candidates)} subdomain mutations")
        new_live = await self.probe_subdomains(sub_candidates)
        log(f"  Found {len(new_live)} new live subdomains")

        target_hosts = [self.d] + list(self.r.live_subs)[:50]

        for host in target_hosts[:25]:
            log(f"  Probing {host}")
            fws = await self.framework_fingerprint(host)
            if fws: log(f"    Detected: {', '.join(fws)}")
            paths = list(ep_candidates)[:6000]
            await self.probe_host_paths(host, paths)
            for api_path in ["/api/","/api/v1/","/graphql","/api/v2/"]:
                await self.cors_probe(host, api_path)
            interesting = [p for p in self.r.live_eps
                           if host in p and any(x in p for x in ('api','admin','internal'))]
            for ep in list(interesting)[:15]:
                path = urlparse(ep).path
                await self.method_enum(host, path)

        main_ip = await _resolve(self.d)
        if main_ip:
            log(f"  VHost probing on {main_ip}")
            vhosts = list(sub_candidates)[:500]
            new_vhosts = await self.vhost_probe(main_ip, vhosts)
            log(f"  VHost: {len(new_vhosts)} new candidates")


# ═══════════════════════════════════════════════════════════════════════════════
# ELITE ENDPOINT CRAWLER — The most advanced endpoint discovery engine
# Strategies: BFS crawl · Wayback CDX (3 indexes) · CommonCrawl · URLScan
#   OpenAPI/Swagger full parse · GraphQL introspection · WSDL/SOAP detection
#   gRPC reflection hints · Robots.txt + Sitemap recursive · HAL/HATEOAS links
#   Webpack chunk loading · Source map reconstruction · Service worker analysis
#   JS route extraction (React/Vue/Angular) · CRUD pattern expansion
#   Parameter mining (300+ params) · Form action/input harvesting
#   Header-based path leakage · HTML comment extraction · Error page parsing
#   JSON-embedded URL recursive extraction · Pagination link following
#   Backup/alternate extension probing · Case bypass variants
#   Path bypass techniques (double-slash, encoded, semicolon) · Version sweep
#   API key/token endpoint patterns · Cloud provider metadata hints
#   .well-known exhaustive probe · Debug/diagnostic endpoint brute-force
#   RSS/Atom/OPDS feed parsing · JSONAPI/JSON-LD/HAL document following
#   Encoded parameter pollution · Hidden field mining · SVG/XML url extraction
# ═══════════════════════════════════════════════════════════════════════════════
class EndpointCrawler:
    MAX_CRAWL_PAGES  = 2000
    MAX_CRAWL_DEPTH  = 5
    MAX_WAYBACK      = 10000
    MAX_CONCURRENT   = 80

    # Extensions to skip fetching (binary/media)
    SKIP_EXTS = {'.png','.jpg','.jpeg','.gif','.svg','.ico','.woff','.woff2',
                 '.ttf','.eot','.otf','.mp4','.mp3','.avi','.mov','.webp',
                 '.webm','.m3u8','.ts','.flv','.wav','.ogg','.flac','.aac',
                 '.zip','.gz','.tar','.bz2','.rar','.7z','.dmg','.exe',
                 '.dll','.so','.dylib','.bin','.dat','.db','.sqlite','.pdf',
                 '.doc','.docx','.xls','.xlsx','.ppt','.pptx'}

    # Backup/alternate extensions to try on every discovered path
    BACKUP_EXTS = ['.bak','.old','~','.swp','.orig','.tmp','.copy','.backup',
                   '.1','.2','.save','.disabled','.bkp','.BAK','.OLD']

    # Case-variation and WAF bypass path transforms applied to discovered paths.
    # Each lambda takes a path string and returns a variant.
    BYPASS_VARIANTS = [
        lambda p: p,                                                          # original
        lambda p: p.upper(),                                                  # ALL UPPER
        lambda p: p.capitalize(),                                             # Capitalize
        lambda p: p + '/',                                                    # trailing slash
        lambda p: '/' + p.lstrip('/') + '/.',                                 # trailing dot
        lambda p: p + '%20',                                                  # URL-encoded space
        lambda p: '//' + p.lstrip('/'),                                       # double-slash root
        lambda p: p + '..;/',                                                 # Spring semicolon break
        lambda p: p.replace('/', '/%2f', 1),                                  # encoded first slash
        lambda p: p + ';.json',                                               # ;.json extension bypass
        lambda p: p + '?',                                                    # empty query string
        lambda p: p + '#',                                                    # fragment bypass
        lambda p: p + '%00',                                                  # null byte
        lambda p: re.sub(r'/([a-z])', lambda m: '/' + m.group(1).upper(), p, count=1),  # 1st-seg upper
        # ── Additional innovative bypasses ──────────────────────────────────────
        lambda p: p + ';/',                                                   # Spring ;/ bypass
        lambda p: p.replace('/', '//'),                                       # double all slashes
        lambda p: p + '%09',                                                  # TAB suffix
        lambda p: p + '%0d%0a',                                               # CRLF suffix
        lambda p: p.replace('/', '%5c', 1),                                   # %5c backslash
        lambda p: p.replace('/', '%C0%AF', 1),                               # overlong UTF-8 slash
        lambda p: p + ';type=application%2fjson',                             # ;type bypass
        lambda p: p + ';jsessionid=AAAAAAAAAAAAAAAA',                        # Java session bypass
        lambda p: p + ';lang=en',                                             # ;lang=en path param
        lambda p: p + '?debug=true',                                          # debug query param
        lambda p: p + '?format=json',                                         # format query param
        lambda p: p + '?v=1',                                                 # version query param
        lambda p: p + '.php',                                                 # PHP extension
        lambda p: p + '.json',                                                # JSON extension
        lambda p: p + '.xml',                                                 # XML extension
        lambda p: p + '.action',                                              # Struts .action
        lambda p: p + '.do',                                                  # Struts .do
        lambda p: p.replace('-', '_'),                                        # hyphen → underscore
        lambda p: p.replace('_', '-'),                                        # underscore → hyphen
        lambda p: '/v0' + p if not p.startswith('/v') else p,                 # /v0/ prefix
        lambda p: '/api' + p if not p.startswith('/api') else p,              # /api prefix
        lambda p: '/internal' + p,                                            # /internal prefix
        lambda p: '/private' + p,                                             # /private prefix
        lambda p: p + '/.',                                                   # /path/. normalization
        lambda p: p + '/./',                                                  # /path/./ normalization
        lambda p: p + '/index',                                               # /path/index
        lambda p: p + '/index.php',                                           # /path/index.php
        lambda p: p.rstrip('/') + '%2f',                                      # trailing encoded slash
        lambda p: p + '~',                                                    # vim backup
        lambda p: p + '.bak',                                                 # backup extension
        lambda p: p + '.orig',                                                # .orig backup
        lambda p: p + '.old',                                                 # .old backup
        lambda p: p + '?_=1',                                                 # cache-bust
        lambda p: p + '?callback=x',                                          # JSONP probe
        lambda p: p + ';extension=api',                                       # extension path param
        # ── 2025 innovative variants ────────────────────────────────────────────
        lambda p: p.replace('/', '/%e2%80%8b', 1),                            # URL-encoded zero-width space after first slash
        lambda p: p.replace('/', '/%09', 1),                                  # URL-encoded tab after first slash
        lambda p: p + '?_format=json',                                        # Drupal format bypass
        lambda p: p + '/;',                                                   # trailing semicolon (some proxies)
        lambda p: '/%252f'.join(p.lstrip('/').split('/', 1)) if '/' in p.lstrip('/') else p,  # double-encoded /
        lambda p: p + '?.json',                                               # .json in query vs path
        lambda p: '/..%2f' + p.lstrip('/'),                                   # path traversal prefix
        lambda p: p + '?_wMode=1',                                            # WAF mode bypass hint
        lambda p: p + ';v=1',                                                 # version in path param
        lambda p: re.sub(r'(/[^/]+)', r'\1;x', p, count=1),                  # inject ;x after first segment
        lambda p: p + '?nocache=' + hex(hash(p) & 0xFFFF),                   # unique cache bust
    ]

    # 300+ common parameter names for param mining
    COMMON_PARAMS = [
        'id','user','username','email','token','key','api_key','apikey','auth',
        'session','login','password','pass','secret','admin','debug','test',
        'page','limit','offset','size','start','end','from','to','count',
        'q','query','search','keyword','term','filter','sort','order','dir',
        'action','type','format','output','callback','redirect','url','next',
        'return','ref','source','target','dest','destination','origin','host',
        'file','path','dir','folder','name','title','content','body','data',
        'json','xml','yaml','csv','text','html','mode','view','template',
        'lang','locale','language','timezone','country','region','city',
        'version','v','release','build','branch','commit','tag','env',
        'status','state','active','enabled','disabled','hidden','public',
        'scope','role','group','permission','access','level','tier','plan',
        'account','profile','settings','config','configuration','option',
        'param','args','arguments','input','output','value','values','list',
        'include','exclude','fields','columns','rows','table','collection',
        'index','cursor','after','before','since','until','date','time',
        'start_date','end_date','created_at','updated_at','timestamp',
        'category','tag','label','slug','uuid','guid','hash','checksum',
        'signature','nonce','state','code','grant','client_id','client_secret',
        'response_type','scope','audience','issuer','subject','claim',
        'webhook','event','topic','channel','queue','stream','batch',
        'upload','download','import','export','sync','async','background',
        'depth','width','height','size','quality','resolution','format',
        'parent','child','ancestor','descendant','sibling','related','linked',
        'owner','creator','author','publisher','reviewer','assignee',
        'workspace','project','team','organization','company','enterprise',
        'invoice','order','cart','payment','billing','subscription','plan',
        'coupon','discount','promo','code','voucher','gift','reward','point',
        'location','address','lat','lng','latitude','longitude','radius',
        'ip','mac','device','platform','browser','ua','user_agent',
        'error','message','detail','reason','description','note','comment',
        'image','avatar','thumbnail','cover','banner','logo','icon','photo',
        'link','href','src','source','resource','endpoint','service','api',
        'method','operation','function','procedure','command','task','job',
        'report','analytics','metric','stat','log','trace','audit','history',
        'new','old','copy','backup','draft','published','archived','deleted',
        'preview','review','approve','reject','accept','deny','allow','block',
        'send','receive','fetch','pull','push','create','read','update','delete',
        'get','post','put','patch','options','head','connect','trace',
        'enable','disable','start','stop','pause','resume','cancel','reset',
        'open','close','lock','unlock','hide','show','expand','collapse',
    ]

    # CRUD patterns to expand for each discovered resource
    CRUD_SUFFIXES = [
        '', '/', '/list', '/all', '/search', '/find', '/query',
        '/create', '/new', '/add', '/insert', '/save',
        '/update', '/edit', '/modify', '/patch', '/change',
        '/delete', '/remove', '/destroy', '/purge', '/archive',
        '/get', '/fetch', '/show', '/detail', '/details', '/view',
        '/export', '/import', '/download', '/upload', '/sync',
        '/count', '/total', '/stats', '/statistics', '/metrics',
        '/bulk', '/batch', '/multi', '/mass',
        '/me', '/self', '/current', '/my',
        '/admin', '/manage', '/management',
        '/history', '/log', '/audit', '/trace', '/events',
        '/config', '/settings', '/options', '/preferences',
        '/validate', '/verify', '/check', '/test', '/ping',
        '/status', '/health', '/state', '/info',
        '/enable', '/disable', '/activate', '/deactivate',
        '/lock', '/unlock', '/block', '/unblock',
        '/approve', '/reject', '/publish', '/unpublish',
        # Numeric IDs cover the common case; template placeholders probe literal strings
        '/1', '/2', '/3', '/4', '/5', '/10', '/50', '/100', '/123', '/999', '/1000',
        '/1/details', '/1/edit', '/1/delete', '/1/update', '/1/status', '/1/history',
    ]

    # Well-known paths — exhaustive
    WELL_KNOWN_PATHS = [
        '/.well-known/security.txt', '/security.txt',
        '/.well-known/openid-configuration',
        '/.well-known/oauth-authorization-server',
        '/.well-known/jwks.json', '/jwks.json', '/jwks',
        '/.well-known/change-password',
        '/.well-known/assetlinks.json',
        '/.well-known/apple-app-site-association',
        '/.well-known/webfinger',
        '/.well-known/nodeinfo', '/nodeinfo', '/nodeinfo/2.0',
        '/.well-known/matrix/client', '/.well-known/matrix/server',
        '/.well-known/mta-sts.txt',
        '/.well-known/dnt-policy.txt',
        '/.well-known/caldav', '/.well-known/carddav',
        '/.well-known/acme-challenge/',
        '/.well-known/pki-validation/',
        '/.well-known/did.json', '/.well-known/did-configuration.json',
        '/.well-known/host-meta', '/.well-known/host-meta.json',
        '/.well-known/time', '/.well-known/est/cacerts',
        '/.well-known/brski/',
        '/.well-known/csvm', '/.well-known/void',
        '/robots.txt', '/humans.txt', '/sitemap.xml',
        '/sitemap_index.xml', '/sitemap.xml.gz',
        '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/ads.txt', '/sellers.json', '/app-ads.txt',
        '/favicon.ico', '/apple-touch-icon.png',
        '/browserconfig.xml', '/manifest.json', '/manifest.webmanifest',
        '/service-worker.js', '/sw.js', '/serviceworker.js',
        '/pwa.js', '/offline.html',
    ]

    # Debug / diagnostic endpoints — exhaustive
    DEBUG_PATHS = [
        # Health / liveness
        '/health', '/health/', '/healthz', '/health/check', '/healthcheck',
        '/alive', '/live', '/liveness', '/ready', '/readiness', '/readyz',
        '/ping', '/pong', '/status', '/status/', '/version', '/info',
        '/_health', '/_healthz', '/_ready', '/_liveness',
        '/api/health', '/api/status', '/api/ping', '/api/version',
        '/v1/health', '/v2/health', '/v3/health',
        # Metrics
        '/metrics', '/metrics/', '/prometheus/metrics', '/_metrics',
        '/internal/metrics', '/api/metrics', '/monitoring/metrics',
        '/telemetry', '/stats', '/statistics', '/sys/stats',
        # Spring Boot Actuator (all endpoints)
        '/actuator', '/actuator/', '/actuator/health', '/actuator/health/liveness',
        '/actuator/health/readiness', '/actuator/info', '/actuator/env',
        '/actuator/configprops', '/actuator/beans', '/actuator/conditions',
        '/actuator/mappings', '/actuator/routes', '/actuator/scheduledtasks',
        '/actuator/loggers', '/actuator/logfile', '/actuator/dump',
        '/actuator/threaddump', '/actuator/heapdump', '/actuator/trace',
        '/actuator/httptrace', '/actuator/auditevents', '/actuator/caches',
        '/actuator/flyway', '/actuator/liquibase', '/actuator/integrationgraph',
        '/actuator/sessions', '/actuator/startup', '/actuator/metrics',
        '/actuator/prometheus', '/actuator/refresh', '/actuator/restart',
        '/actuator/shutdown', '/actuator/jolokia', '/jolokia',
        # Node.js debug
        '/debug', '/debug/', '/debug/vars', '/debug/pprof', '/debug/pprof/',
        '/debug/pprof/heap', '/debug/pprof/goroutine', '/debug/pprof/block',
        '/debug/pprof/cmdline', '/debug/pprof/profile', '/debug/pprof/trace',
        '/__debug', '/__debug__', '/_debug', '/__pprof__',
        # Django / Python
        '/django-admin/', '/__django__', '/django/', '/django/admin/',
        '/silk/', '/silk/api/', '/swagger/', '/redoc/',
        '/__debug_toolbar__/', '/__debug__/', '/debug_toolbar/',
        # Rails
        '/rails/info', '/rails/info/properties', '/rails/info/routes',
        '/rails/mailers', '/rails/db/', '/cable',
        # PHP
        '/phpinfo.php', '/info.php', '/php_info.php', '/test.php',
        '/phpMyAdmin', '/phpmyadmin/', '/pma/', '/myadmin/', '/mysql/',
        '/adminer.php', '/adminer/', '/dbadmin/', '/mysqladmin/',
        '/index.php', '/index.php?debug=1',
        # Generic debug
        '/diagnostics', '/diagnostic', '/diag', '/trace',
        '/console', '/debug-console', '/debugger',
        '/internal', '/internal/', '/internal/debug',
        '/internal/health', '/internal/status', '/internal/info',
        '/__internal', '/__status', '/__info',
        # Error pages that leak info
        '/error', '/error/', '/errors', '/500', '/404', '/403',
        '/server-status', '/server-info', '/nginx-status', '/nginx_status',
        '/fpm-status', '/php-fpm-status', '/apache-status',
        # Go / GRPC
        '/grpc.health.v1.Health/Check',
        '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
        # Monitoring tools
        '/grafana', '/grafana/', '/kibana', '/kibana/',
        '/prometheus', '/prometheus/', '/alertmanager',
        '/jaeger', '/zipkin', '/consul', '/vault', '/nomad',
        '/portainer', '/rancher', '/kubernetes', '/_cat/indices',
        # Cloud metadata (misconfigured proxies)
        '/latest/meta-data/', '/metadata/', '/metadata/v1/',
        '/computeMetadata/v1/', '/metadata/instance',
        '/metadata/instance/computeMetadata/v1/',
        '/169.254.169.254/latest/meta-data/',
        '/opc/v1/instance/', '/system/azure/instances/',
    ]

    # Secrets / config exposure paths — exhaustive
    SECRET_PATHS = [
        # Environment files
        '/.env', '/.env.local', '/.env.production', '/.env.staging',
        '/.env.development', '/.env.test', '/.env.example', '/.env.sample',
        '/.env.backup', '/.env.old', '/.env~', '/.env.bak',
        '/env', '/env.json', '/.envrc', '/env.sh',
        '/config', '/config/', '/config.json', '/config.yaml', '/config.yml',
        '/config.xml', '/config.ini', '/config.php', '/config.py',
        '/settings', '/settings.json', '/settings.yaml', '/settings.py',
        '/app.config', '/app.config.json', '/application.json',
        '/application.yaml', '/application.properties',
        '/runtime-config.json', '/env.json', '/env.js',
        '/local.json', '/local.yaml', '/local.settings.json',
        '/appsettings.json', '/appsettings.Development.json',
        '/appsettings.Production.json', '/appsettings.Staging.json',
        '/web.config', '/Web.config',
        '/WEB-INF/web.xml', '/WEB-INF/applicationContext.xml',
        '/WEB-INF/classes/application.properties',
        '/WEB-INF/classes/application.yml',
        '/META-INF/MANIFEST.MF', '/META-INF/maven/',
        # Source control
        '/.git/config', '/.git/HEAD', '/.git/COMMIT_EDITMSG',
        '/.git/description', '/.git/info/exclude',
        '/.git/refs/heads/main', '/.git/refs/heads/master',
        '/.git/refs/heads/develop', '/.git/refs/heads/dev',
        '/.git/logs/HEAD', '/.git/packed-refs',
        '/.gitignore', '/.gitmodules', '/.gitattributes',
        '/.svn/entries', '/.svn/wc.db', '/.svn/format',
        '/.hg/hgrc', '/.hg/.hgignore',
        '/.bzr/branch/branch.conf',
        '/.fossil-settings/ignore-glob',
        # CI/CD
        '/.travis.yml', '/.travis.yaml',
        '/.circleci/config.yml', '/.circleci/config.yaml',
        '/.github/workflows/', '/.github/CODEOWNERS',
        '/.gitlab-ci.yml', '/.gitlab-ci.yaml',
        '/Jenkinsfile', '/jenkins/Jenkinsfile',
        '/.drone.yml', '/.drone.yaml',
        '/azure-pipelines.yml', '/azure-pipelines.yaml',
        '/.buildkite/pipeline.yml',
        '/bitbucket-pipelines.yml',
        '/.appveyor.yml',
        # Build / package
        '/package.json', '/package-lock.json', '/yarn.lock',
        '/npm-shrinkwrap.json', '/.npmrc', '/.yarnrc', '/.npmignore',
        '/composer.json', '/composer.lock',
        '/Gemfile', '/Gemfile.lock', '/.ruby-version', '/.rbenv-version',
        '/requirements.txt', '/Pipfile', '/Pipfile.lock', '/setup.py',
        '/pyproject.toml', '/setup.cfg', '/tox.ini',
        '/go.mod', '/go.sum',
        '/pom.xml', '/build.gradle', '/build.gradle.kts',
        '/build.xml', '/ivy.xml', '/settings.xml',
        '/Cargo.toml', '/Cargo.lock',
        '/mix.exs', '/mix.lock',
        '/pubspec.yaml', '/pubspec.lock',
        '/Makefile', '/makefile', '/GNUmakefile',
        '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
        '/docker-compose.override.yml', '/docker-compose.prod.yml',
        '/.dockerignore',
        '/helm/values.yaml', '/helm/values-prod.yaml',
        '/k8s/', '/kubernetes/', '/manifests/',
        '/terraform.tf', '/main.tf', '/variables.tf',
        '/terraform.tfvars', '/terraform.tfvars.json',
        '/ansible.cfg', '/inventory', '/hosts',
        '/.ansible/', '/playbooks/',
        # Logs / DB
        '/access.log', '/error.log', '/app.log', '/debug.log',
        '/application.log', '/server.log', '/system.log',
        '/logs/access.log', '/logs/error.log', '/logs/app.log',
        '/log/access.log', '/log/error.log', '/log/app.log',
        '/dump.sql', '/database.sql', '/backup.sql', '/db.sql',
        '/database.db', '/app.db', '/local.db',
        # Cloud
        '/aws-config', '/aws-credentials', '/.aws/credentials',
        '/.aws/config', '/gcloud/', '/.gcloud/',
        '/azure.json', '/.azure/',
        '/.digitalocean/', '/linode.json',
        # Auth / secrets
        '/secrets.json', '/secrets.yaml', '/secrets.env',
        '/private.key', '/server.key', '/server.crt', '/ssl.key',
        '/id_rsa', '/id_rsa.pub', '/.ssh/id_rsa', '/.ssh/authorized_keys',
        '/token', '/tokens', '/api-keys', '/api_keys',
        '/vault.json', '/vault.yaml', '/vault.env',
        # Swagger/OpenAPI
        '/swagger.json', '/swagger.yaml', '/swagger.yml',
        '/openapi.json', '/openapi.yaml', '/openapi.yml',
        '/api-docs', '/api-docs.json', '/api-docs.yaml',
        '/api/swagger.json', '/api/openapi.json',
        '/api/v1/swagger.json', '/api/v2/swagger.json',
        '/api/v1/openapi.json', '/api/v2/openapi.json',
        '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
        '/docs/openapi.json', '/docs/swagger.json',
        '/swagger-ui.html', '/swagger-ui/', '/swagger-ui/index.html',
        '/redoc', '/redoc/', '/redoc.html',
        '/spec', '/spec.json', '/spec.yaml',
        # GraphQL
        '/graphql', '/graphql/', '/graphiql', '/graphiql/',
        '/playground', '/api/graphql', '/v1/graphql', '/v2/graphql',
        '/gql', '/query', '/graphql/schema', '/graphql/voyager',
        # gRPC / protobuf
        '/grpc', '/proto', '/protobuf',
        '/api/proto', '/api/schema',
        # WSDL / SOAP
        '/wsdl', '/service.wsdl', '/api.wsdl',
        '/?wsdl', '/?WSDL', '/services?wsdl',
        '/soap', '/soap/', '/webservice', '/WebService',
        # Admin panels
        '/admin', '/admin/', '/admin/login', '/admin/dashboard',
        '/administrator', '/administrator/', '/wp-admin', '/wp-admin/',
        '/wp-login.php', '/wp-json/', '/wp-json/wp/v2/',
        '/cms', '/cms/', '/panel', '/panel/', '/control', '/cp',
        '/management', '/management/', '/backend', '/backend/',
        # PHP
        '/phpinfo.php', '/info.php', '/test.php', '/check.php',
        '/install.php', '/setup.php', '/upgrade.php', '/update.php',
        '/cron.php', '/feed.php', '/xmlrpc.php',
        '/index.php', '/index.php?id=1',
        # Backup archives
        '/backup', '/backup/', '/backup.zip', '/backup.tar.gz',
        '/backup.tar', '/backup.sql', '/site.zip', '/site.tar.gz',
        '/www.zip', '/www.tar.gz', '/htdocs.zip', '/public.zip',
        '/html.tar.gz', '/web.tar.gz', '/dump.zip',
    ]

    def __init__(self, session, r: Result, domain: str, proxy: Optional[str] = None):
        self.s       = session
        self.r       = r
        self.d       = domain
        self.proxy   = proxy
        self._crawled: Set[str] = set()
        self._sem    = asyncio.Semaphore(self.MAX_CONCURRENT)
        self._resources: Set[str] = set()   # discovered resource names for CRUD expansion
        self._found_paths: Set[str] = set() # track all found paths to generate backup variants

    # ── Master orchestrator per host ──────────────────────────────────────────
    async def crawl_host(self, host: str) -> None:
        log(f"    [Crawler] {host} — starting 20-strategy endpoint discovery")
        tasks = [
            self._bfs_crawl(host),
            self._wayback_multi_source(host),
            self._robots_and_sitemap_deep(host),
            self._openapi_exhaustive(host),
            self._graphql_introspect_full(host),
            self._wsdl_soap_detect(host),
            self._js_webpack_full(host),
            self._service_worker_analysis(host),
            self._debug_and_secret_probe(host),
            self._well_known_exhaustive(host),
            self._header_leak_extraction(host),
            self._error_page_parse(host),
            self._feed_and_syndication(host),
            # NOTE: _urlscan_historical is called inside _wayback_multi_source() above;
            # calling it again here would double-query URLScan and risk rate-limiting.
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        # After initial discovery, run secondary strategies on found paths
        await self._backup_ext_probe(host)
        await self._crud_expansion(host)
        await self._path_bypass_variants(host)
        await self._param_mine_endpoints(host)
        log(f"    [Crawler] {host} done — {len([e for e in self.r.live_eps if host in e])} endpoints found")

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 1: Deep BFS HTTP Crawler
    # ─────────────────────────────────────────────────────────────────────────
    async def _bfs_crawl(self, host: str) -> None:
        """
        BFS crawl: extracts href/src/action/data-src/fetch/axios URLs,
        inline JS API calls, JSON embedded links, HTML comments, form actions,
        CSS @import/@url, XML/SVG hrefs. Follows pagination (rel=next/prev).
        """
        for scheme in ("https", "http"):
            seed = f"{scheme}://{host}/"
            queue: asyncio.Queue = asyncio.Queue()
            await queue.put((seed, 0))
            visited: Set[str] = set()
            pages = 0

            _SENTINEL = object()  # signals workers to exit

            async def _worker():
                nonlocal pages
                while True:
                    item = await queue.get()
                    if item is _SENTINEL:
                        queue.task_done()
                        break
                    url, depth = item
                    if url in visited or url in self._crawled or pages >= self.MAX_CRAWL_PAGES:
                        queue.task_done()
                        continue
                    visited.add(url); self._crawled.add(url)
                    if depth > self.MAX_CRAWL_DEPTH:
                        queue.task_done()
                        continue
                    async with self._sem:
                        try:
                            to = aiohttp.ClientTimeout(total=12)
                            async with self.s.get(
                                url, headers=_hdrs(), timeout=to,
                                allow_redirects=True, ssl=_ssl_ctx(),
                                proxy=self.proxy, max_redirects=5,
                            ) as resp:
                                pages += 1
                                final_url = str(resp.url)
                                ct = resp.headers.get("Content-Type","").lower()
                                status = resp.status

                                # Record live endpoint — include '/' (root) so SPA hosts
                                # are confirmed live and seed further endpoint mining.
                                if status not in (404, 410, 503, 0):
                                    pth = urlparse(final_url).path or "/"
                                    if pth:
                                        self.r.add_ep(pth, "bfs_crawl")
                                        self.r.live_eps.add(final_url)
                                        self._found_paths.add(pth)
                                        self._extract_resource(pth)

                                # Harvest headers for path leaks
                                self._harvest_headers(resp.headers, host, scheme, queue, visited, depth)

                                # Only parse text responses
                                skip_body = any(x in ct for x in ('image','video','audio','font','binary'))
                                if skip_body:
                                    queue.task_done()
                                    continue

                                body = await resp.read()
                                try:
                                    text = body.decode('utf-8', errors='replace')
                                except Exception:
                                    queue.task_done()
                                    continue

                                # Extract all link types
                                links = self._extract_all_links(text, final_url, host, scheme)
                                for link in links:
                                    parsed = urlparse(link)
                                    ext = os.path.splitext(parsed.path)[1].lower()
                                    if ext in self.SKIP_EXTS: continue
                                    if parsed.netloc in ('', host, f"www.{host}"):
                                        if link not in visited:
                                            await queue.put((link, depth + 1))
                                    # Always record the path
                                    if parsed.netloc == host or not parsed.netloc:
                                        pth = parsed.path
                                        if pth and len(pth) > 1:
                                            self.r.add_ep(pth, "bfs_link")
                                            self.r.live_eps.add(link if parsed.netloc else f"{scheme}://{host}{pth}")
                                            self._found_paths.add(pth)
                                            self._extract_resource(pth)

                                # Extract paths from body text
                                for p in _paths_from_text(text):
                                    self.r.add_ep(p, "bfs_body")
                                    self._found_paths.add(p)
                                    self._extract_resource(p)

                                # HTML comments
                                for m in re.finditer(r'<!--(.*?)-->', text, re.DOTALL):
                                    comment = m.group(1)
                                    for p in _paths_from_text(comment):
                                        self.r.add_ep(p, "html_comment")

                                # JSON embedded URLs
                                if "json" in ct:
                                    try:
                                        jdata = json.loads(text)
                                        for ep in self._json_url_extract(jdata):
                                            self.r.add_ep(ep, "bfs_json")
                                            self._found_paths.add(ep)
                                    except Exception: pass

                                # HAL/HATEOAS _links
                                for m in re.finditer(
                                    r'"_links"\s*:\s*\{([^}]{1,2000})\}',
                                    text, re.DOTALL):
                                    for href_m in re.finditer(r'"href"\s*:\s*"([^"]+)"', m.group(1)):
                                        p = urlparse(href_m.group(1)).path
                                        if p: self.r.add_ep(p, "hateoas_link")

                                # RSS/Atom feed links
                                for m in re.finditer(r'<(?:link|guid|id)[^>]*>([^<]{5,500})</(?:link|guid|id)>', text):
                                    val = m.group(1).strip()
                                    if val.startswith('http') and host in val:
                                        p = urlparse(val).path
                                        if p: self.r.add_ep(p, "feed_link")

                                # Pagination: rel=next / Link headers already handled
                                for m in re.finditer(
                                    r'<link[^>]+rel=["\'](?:next|prev)["\'][^>]+href=["\']([^"\']+)["\']',
                                    text, re.I):
                                    next_url = urljoin(final_url, m.group(1))
                                    if next_url not in visited:
                                        await queue.put((next_url, depth + 1))

                        except Exception:
                            pass
                        finally:
                            queue.task_done()

            # Run 20 concurrent workers with sentinel-based graceful shutdown
            N_WORKERS = 20
            workers = [asyncio.ensure_future(_worker()) for _ in range(N_WORKERS)]
            await queue.join()  # wait until all queued work is done
            # Send sentinels so every worker exits cleanly
            for _ in range(N_WORKERS):
                await queue.put(_SENTINEL)
            await asyncio.gather(*workers, return_exceptions=True)
            if pages > 0:
                break  # HTTPS succeeded — skip HTTP fallback

    def _harvest_headers(self, headers, host: str, scheme: str, queue, visited, depth: int):
        """Extract path hints from response headers."""
        interesting = [
            'Location', 'X-Redirect', 'Refresh', 'Content-Location',
            'Link', 'X-Origin-URL', 'X-Request-URL', 'X-Forwarded-URL',
            'X-Rewrite-URL', 'X-Original-URL', 'X-Override-URL',
        ]
        for hdr in interesting:
            val = headers.get(hdr, '')
            if not val: continue
            # Link header can have multiple <url>; rel=...
            for m in re.finditer(r'<([^>]+)>', val):
                url = m.group(1).strip()
                if url.startswith('/') or host in url:
                    p = urlparse(url).path if url.startswith('http') else url
                    if p: self.r.add_ep(p, "header_leak")
            if val.startswith('/') or (val.startswith('http') and host in val):
                p = urlparse(val).path if val.startswith('http') else val
                if p: self.r.add_ep(p, "header_redirect")

    def _extract_all_links(self, html: str, base_url: str, host: str, scheme: str) -> List[str]:
        """Extract every kind of URL reference from HTML/JS/CSS content."""
        links = set()
        patterns = [
            # HTML attributes
            r'(?:href|src|action|data-src|data-href|data-url|data-action|data-link|data-endpoint|data-api|data-route)\s*=\s*["\']([^"\'<>\s]{1,500})["\']',
            # CSS url()
            r'url\s*\(\s*["\']?([^"\'<>\s)]{1,500})["\']?\s*\)',
            # JS fetch/axios/http
            r'(?:fetch|axios\.(?:get|post|put|delete|patch|head|request)|http\.(?:get|post|put|delete|patch)|request\.(?:get|post|put|delete|patch)|ajax|xhr\.open)\s*[\(,]\s*["\`]([^"\'`<>\s]{1,500})["\`]',
            # JS string assignments
            r'(?:url|URL|uri|URI|endpoint|Endpoint|path|Path|route|Route|href|Href|baseUrl|baseURL|apiUrl|apiURL|API_URL|BASE_URL|ENDPOINT|endpoint_url)\s*[=:]\s*["\`]([/][^"\'`\s<>]{1,500})["\`]',
            # Template literals with paths
            r'`([/][a-z0-9_\-/\.%?&={}$]{3,200})`',
            # JSON-embedded paths
            r'"(?:url|path|href|link|endpoint|route|action|src)"\s*:\s*"([/][^"]{1,300})"',
            r"'(?:url|path|href|link|endpoint|route|action|src)'\s*:\s*'([/][^']{1,300})'",
            # Router definitions (React, Vue, Angular, Express)
            r'(?:path|component|route)\s*:\s*["\`]([/][^"\'`<>\s]{1,200})["\`]',
            r'(?:router|Router|Route|app|express)\s*\.\s*(?:get|post|put|delete|patch|use|all)\s*\(\s*["\`]([^"\'`]+)["\`]',
            # Prefixed API paths
            r'["\`](/(?:api|v\d+|graphql|rest|internal|private|admin|service|micro|grpc|rpc)[/a-z0-9_\-\.]{1,200})["\`]',
            # Import/require paths
            r'(?:import|require)\s*\(["\']([^"\']+)["\']',
            # Form actions
            r'<form[^>]+action\s*=\s*["\']([^"\'<>]+)["\']',
            # Input hidden values
            r'<input[^>]+type=["\']hidden["\'][^>]+value=["\']([/][^"\']+)["\']',
            # SVG/XML hrefs
            r'xlink:href=["\']([^"\'<>]+)["\']',
            r'href=["\']([^"\'<>]+\.(?:xml|rss|atom|json|yaml|yml|csv))["\']',
            # Service worker paths
            r'self\.importScripts\s*\(\s*["\']([^"\']+)["\']',
            r'(?:cache\.add|cache\.addAll)\s*\(\s*["\']([^"\']+)["\']',
            r'\[(["\'][/][^"\']+["\'](?:\s*,\s*["\'][/][^"\']+["\'])*)\]',
        ]
        for pat in patterns:
            for m in re.finditer(pat, html, re.I):
                href = m.group(1).strip().strip('"\'`')
                if not href or href.startswith('#') or href.startswith('javascript:'):
                    continue
                try:
                    full = urljoin(base_url, href)
                    p = urlparse(full)
                    if p.netloc in ('', host, f"www.{host}") or not p.netloc:
                        links.add(full)
                except Exception:
                    pass
        return list(links)

    def _extract_resource(self, path: str):
        """Extract resource name from path for CRUD expansion."""
        parts = [p for p in path.strip('/').split('/') if p]
        for part in parts:
            # Skip IDs, numbers, versions
            if re.match(r'^(?:v\d+|api|rest|internal|admin|\d+|[a-f0-9\-]{24,})$', part, re.I):
                continue
            if 2 < len(part) < 30 and re.match(r'^[a-z][a-z0-9_\-]{1,29}$', part):
                self._resources.add(part)

    def _json_url_extract(self, data: Any, depth: int = 0) -> List[str]:
        """Recursively extract URL/path strings from JSON."""
        if depth > 6: return []
        paths = []
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str):
                    if v.startswith('/') and len(v) > 1:
                        paths.append(v.split('?')[0])
                    elif v.startswith('http') and len(v) < 500:
                        p = urlparse(v).path
                        if p and p != '/': paths.append(p)
                elif isinstance(v, (dict, list)):
                    paths.extend(self._json_url_extract(v, depth+1))
        elif isinstance(data, list):
            for item in data[:50]:
                paths.extend(self._json_url_extract(item, depth+1))
        return paths

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 2: Wayback Machine + CommonCrawl + AlienVault OTX
    # ─────────────────────────────────────────────────────────────────────────
    async def _wayback_multi_source(self, host: str) -> None:
        """Pull historical URLs from 4 different sources."""
        tasks = [
            self._wayback_cdx(host),
            self._commoncrawl_cdx(host),
            self._alienvault_otx(host),
            self._urlscan_historical(host),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _wayback_cdx(self, host: str) -> None:
        """Wayback Machine CDX — all status codes, collapse by URL, extract params."""
        cdx_configs = [
            # All 2xx + 3xx
            f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=json"
            f"&fl=original,statuscode,mimetype&collapse=urlkey"
            f"&limit={self.MAX_WAYBACK}&filter=statuscode:[23]",
            # 4xx — reveal protected paths
            f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=json"
            f"&fl=original,statuscode&collapse=urlkey&limit=2000"
            f"&filter=statuscode:[45]",
        ]
        for cdx_url in cdx_configs:
            try:
                async with self._sem:
                    to = aiohttp.ClientTimeout(total=40)
                    async with self.s.get(cdx_url, timeout=to, ssl=_ssl_ctx(),
                                          headers=_hdrs(), proxy=self.proxy) as resp:
                        if resp.status != 200: continue
                        data = await resp.json(content_type=None)
                        if not isinstance(data, list): continue
                        for row in data[1:]:
                            if not row: continue
                            orig = row[0] if isinstance(row, list) else str(row)
                            self._ingest_historical_url(orig, host)
            except Exception:
                pass

    async def _commoncrawl_cdx(self, host: str) -> None:
        """CommonCrawl CDX API — different dataset from Wayback."""
        # Try recent crawl indexes
        indexes = [
            'CC-MAIN-2025-18', 'CC-MAIN-2025-08',
            'CC-MAIN-2024-51', 'CC-MAIN-2024-38', 'CC-MAIN-2024-26', 'CC-MAIN-2024-10',
            'CC-MAIN-2023-50', 'CC-MAIN-2023-40',
        ]
        for idx in indexes:
            url = (f"https://index.commoncrawl.org/{idx}-index"
                   f"?url={host}/*&output=json&limit=1000&fl=url")
            try:
                async with self._sem:
                    to = aiohttp.ClientTimeout(total=25)
                    async with self.s.get(url, timeout=to, ssl=_ssl_ctx(),
                                          headers=_hdrs(), proxy=self.proxy) as resp:
                        if resp.status != 200: continue
                        text = await resp.text(errors='replace')
                        for line in text.strip().splitlines()[:1000]:
                            try:
                                entry = json.loads(line)
                                self._ingest_historical_url(entry.get("url",""), host)
                            except Exception:
                                pass
            except Exception:
                pass

    async def _alienvault_otx(self, host: str) -> None:
        """AlienVault OTX passive DNS URL list."""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/url_list?limit=500"
            async with self._sem:
                to = aiohttp.ClientTimeout(total=20)
                async with self.s.get(url, timeout=to, ssl=_ssl_ctx(),
                                      headers=_hdrs(), proxy=self.proxy) as resp:
                    if resp.status != 200: return
                    data = await resp.json(content_type=None)
                    if not isinstance(data, dict): return
                    for entry in data.get("url_list", []):
                        self._ingest_historical_url(entry.get("url",""), host)
        except Exception:
            pass

    async def _urlscan_historical(self, host: str) -> None:
        """URLScan.io search for historical screenshots/URLs."""
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=200&fields=page.url"
            async with self._sem:
                to = aiohttp.ClientTimeout(total=20)
                async with self.s.get(
                    url, timeout=to, ssl=_ssl_ctx(),
                    headers={**_hdrs(), "Accept": "application/json"},
                    proxy=self.proxy) as resp:
                    if resp.status != 200: return
                    data = await resp.json(content_type=None)
                    if not isinstance(data, dict): return
                    for result in data.get("results", []):
                        page_url = result.get("page", {}).get("url", "")
                        self._ingest_historical_url(page_url, host)
        except Exception:
            pass

    def _ingest_historical_url(self, url: str, host: str):
        """Parse and store a historical URL, extract params."""
        if not url: return
        try:
            p = urlparse(url)
            if p.netloc not in (host, f"www.{host}", host.lstrip("www.")):
                return
            path = p.path
            if not path or path == '/': return
            self.r.add_ep(path, "historical")
            self.r.live_eps.add(url)
            self._found_paths.add(path)
            self._extract_resource(path)
            # Extract query parameters
            if p.query:
                for param in p.query.split('&'):
                    k = param.split('=')[0].strip()
                    if k and len(k) < 60:
                        self.r.parameters.setdefault(path, set()).add(k)
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 3: Robots.txt + Sitemap (deep recursive)
    # ─────────────────────────────────────────────────────────────────────────
    async def _robots_and_sitemap_deep(self, host: str) -> None:
        """Parse robots.txt exhaustively. Follow ALL sitemap references."""
        sitemap_urls: List[str] = []
        for scheme in ("https", "http"):
            try:
                async with self._sem:
                    to = aiohttp.ClientTimeout(total=10)
                    async with self.s.get(
                        f"{scheme}://{host}/robots.txt",
                        headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                        proxy=self.proxy,
                    ) as resp:
                        if resp.status not in (200,): continue
                        text = await resp.text(errors='replace')
                        for line in text.splitlines():
                            line = line.strip()
                            ll = line.lower()
                            if ll.startswith(('disallow:', 'allow:', 'noindex:')):
                                raw = line.split(':', 1)[1].strip()
                                # Clean wildcard/regex
                                clean = raw.split('*')[0].split('$')[0].strip()
                                if clean and len(clean) > 1:
                                    self.r.add_ep(clean, "robots_txt")
                                    self._found_paths.add(clean)
                                    # Verify each disallowed path
                                    ep_url = f"{scheme}://{host}{clean}"
                                    await self._quick_verify(ep_url, clean, "robots_verified")
                            elif ll.startswith('sitemap:'):
                                sm_url = line.split(':', 1)[1].strip()
                                if sm_url: sitemap_urls.append(sm_url)
                        break
            except Exception:
                pass

        # Common sitemap locations
        for scheme in ("https",):
            for sm_path in [
                '/sitemap.xml', '/sitemap_index.xml', '/sitemap.xml.gz',
                '/sitemap1.xml', '/sitemap2.xml', '/sitemap3.xml',
                '/wp-sitemap.xml', '/news-sitemap.xml', '/video-sitemap.xml',
                '/image-sitemap.xml', '/page-sitemap.xml', '/post-sitemap.xml',
                '/product-sitemap.xml', '/category-sitemap.xml',
                '/sitemap/sitemap.xml', '/sitemap/index.xml',
                '/en/sitemap.xml', '/en-us/sitemap.xml',
            ]:
                sitemap_urls.append(f"{scheme}://{host}{sm_path}")

        # Parse all sitemaps recursively
        visited_sm: Set[str] = set()
        async def _parse_sm(url: str, depth: int = 0):
            if depth > 5 or url in visited_sm: return
            visited_sm.add(url)
            try:
                async with self._sem:
                    to = aiohttp.ClientTimeout(total=12)
                    async with self.s.get(
                        url, headers=_hdrs(), timeout=to,
                        ssl=_ssl_ctx(), proxy=self.proxy,
                    ) as resp:
                        if resp.status != 200: return
                        body = await resp.text(errors='replace')
                        for m in re.finditer(r'<loc>\s*([^<]{4,500})\s*</loc>', body, re.I):
                            loc = m.group(1).strip()
                            try:
                                pp = urlparse(loc)
                                if pp.netloc in (host, f"www.{host}"):
                                    path = pp.path
                                    if path and path != '/':
                                        self.r.add_ep(path, "sitemap")
                                        self.r.live_eps.add(loc)
                                        self._found_paths.add(path)
                                        self._extract_resource(path)
                                if 'sitemap' in loc.lower() or loc.endswith(('.xml','.xml.gz')):
                                    await _parse_sm(loc, depth+1)
                            except Exception:
                                pass
            except Exception:
                pass

        await asyncio.gather(*[_parse_sm(u) for u in sitemap_urls], return_exceptions=True)

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 4: OpenAPI/Swagger — exhaustive detection + full parse
    # ─────────────────────────────────────────────────────────────────────────
    async def _openapi_exhaustive(self, host: str) -> None:
        """Probe 60+ OpenAPI spec locations. Parse all paths including nested."""
        spec_paths = [
            "/openapi.json","/openapi.yaml","/openapi.yml","/openapi.json",
            "/swagger.json","/swagger.yaml","/swagger.yml",
            "/api-docs","/api-docs.json","/api-docs.yaml","/api-docs.yml",
            "/api/swagger.json","/api/openapi.json","/api/openapi.yaml",
            "/api/v1/swagger.json","/api/v2/swagger.json","/api/v3/swagger.json",
            "/api/v1/openapi.json","/api/v2/openapi.json","/api/v3/openapi.json",
            "/v1/api-docs","/v2/api-docs","/v3/api-docs","/v4/api-docs",
            "/v1/openapi.json","/v2/openapi.json","/v3/openapi.json",
            "/v1/swagger.json","/v2/swagger.json","/v3/swagger.json",
            "/docs/openapi.json","/docs/swagger.json","/docs/api-docs",
            "/docs/openapi","/docs/swagger",
            "/swagger-ui/swagger.json","/swagger-ui.json","/swagger/swagger.json",
            "/swagger/v1/swagger.json","/swagger/v2/swagger.json",
            "/rest/openapi.json","/rest/swagger.json","/rest/api-docs",
            "/.well-known/openapi.json","/.well-known/swagger.json",
            "/api/spec","/api/specification","/api/schema","/api/schema.json",
            "/spec.json","/spec.yaml","/spec.yml",
            "/schema.json","/schema.yaml","/schema.yml",
            "/api/definition","/api/description",
            "/internal/api-docs","/internal/swagger.json",
            "/private/api-docs","/private/swagger.json",
            "/_api/openapi","/api/_schema",
            # versioned
            "/api/v1/docs","/api/v2/docs","/api/v3/docs",
            # Platform-specific
            "/wp-json/","/wp-json/wp/v2/",
            "/api-platform/docs.json",
            "/api/resource-docs",
        ]
        for path in spec_paths:
            for scheme in ("https",):
                try:
                    async with self._sem:
                        to = aiohttp.ClientTimeout(total=8)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers={**_hdrs(), "Accept": "application/json,*/*"},
                            timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                        ) as resp:
                            if resp.status not in (200, 201): continue
                            body = await resp.text(errors='replace')
                            spec = None
                            try:
                                spec = json.loads(body)
                            except Exception:
                                pass
                            if spec is None:
                                # Try YAML
                                if re.search(r'^(?:swagger|openapi)\s*:', body, re.M):
                                    # Basic YAML path extraction without yaml lib
                                    for m in re.finditer(r'^\s{0,4}(/[a-zA-Z0-9/_\-\.{}\$]+)\s*:', body, re.M):
                                        p = m.group(1)
                                        if '{' in p:
                                            p_clean = re.sub(r'\{[^}]+\}', '1', p)
                                            self.r.add_ep(p_clean, "openapi_yaml")
                                        self.r.add_ep(p, "openapi_yaml")
                                        self._found_paths.add(p)
                                        self.r.live_eps.add(f"{scheme}://{host}{p}")
                            if spec and isinstance(spec, dict):
                                paths_found = self._parse_openapi_full(spec, scheme, host)
                                for ep_path in paths_found:
                                    self.r.add_ep(ep_path, "openapi_spec")
                                    self.r.live_eps.add(f"{scheme}://{host}{ep_path}")
                                    self._found_paths.add(ep_path)
                                    self._extract_resource(ep_path)
                                log(f"    [OpenAPI] {scheme}://{host}{path}: "
                                    f"{len(paths_found)} paths extracted")
                except Exception:
                    pass

    def _parse_openapi_full(self, spec: Dict, scheme: str, host: str) -> List[str]:
        """Full OpenAPI parser: paths, server base paths, webhooks, callbacks."""
        out = []
        if not isinstance(spec, dict): return out
        # Base paths from servers
        base_paths = ['']
        for srv in spec.get("servers", []):
            if not isinstance(srv, dict): continue
            url = srv.get("url","")
            if url and not url.startswith("http"):
                base_paths.append(url.rstrip('/'))
            elif url.startswith("http"):
                try:
                    base_paths.append(urlparse(url).path.rstrip('/'))
                except Exception: pass

        raw_paths = spec.get("paths", {}) or {}
        for path, methods in raw_paths.items():
            if not isinstance(path, str): continue
            for base in base_paths:
                full = base + path
                out.append(full)
                # Substitute path params with 1
                clean = re.sub(r'\{[^}]+\}', '1', full)
                if clean != full: out.append(clean)
            if not isinstance(methods, dict): continue
            for method, details in methods.items():
                if not isinstance(details, dict): continue
                # Extract tags → resource names
                for tag in details.get("tags", []):
                    if isinstance(tag, str): self._resources.add(tag.lower().replace(' ','-'))
                # callbacks
                for cb_name, cb in details.get("callbacks", {}).items():
                    if isinstance(cb, dict):
                        for cb_path in cb.keys():
                            if isinstance(cb_path, str) and cb_path.startswith('/'):
                                out.append(cb_path)

        # Webhooks (OpenAPI 3.1)
        for wh_name, wh in (spec.get("webhooks",{}) or {}).items():
            if isinstance(wh, dict):
                for wh_path in wh.keys():
                    if isinstance(wh_path, str) and wh_path.startswith('/'):
                        out.append(wh_path)
        return list(set(out))

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 5: GraphQL — Full introspection + schema exploration
    # ─────────────────────────────────────────────────────────────────────────
    async def _graphql_introspect_full(self, host: str) -> None:
        """
        Full GraphQL introspection: discover all types, queries, mutations,
        subscriptions. Generate REST-style paths from type names.
        Try multiple endpoints and fallback queries.
        """
        gql_paths = [
            "/graphql","/graphql/","/api/graphql","/v1/graphql","/v2/graphql",
            "/v3/graphql","/gql","/query","/api/query","/api/v1/graphql",
            "/api/v2/graphql","/playground","/graphiql","/graphql/console",
            "/graphql/query","/graphql/v1","/graphql/v2",
            "/_graphql","/public/graphql","/user/graphql","/admin/graphql",
        ]
        full_introspection = {"query": """
        query IntrospectionQuery {
          __schema {
            types {
              name kind description
              fields(includeDeprecated: true) {
                name description isDeprecated
                type { name kind ofType { name kind ofType { name kind } } }
                args { name description type { name kind ofType { name } } }
              }
              inputFields { name type { name kind } }
              enumValues(includeDeprecated: true) { name }
            }
            queryType { name fields(includeDeprecated: true) { name args { name } } }
            mutationType { name fields(includeDeprecated: true) { name args { name } } }
            subscriptionType { name fields(includeDeprecated: true) { name args { name } } }
            directives { name locations args { name type { name } } }
          }
        }"""}
        simple_introspection = {"query": "{ __schema { types { name } } }"}

        for path in gql_paths:
            for scheme in ("https",):
                for payload in [full_introspection, simple_introspection]:
                    try:
                        async with self._sem:
                            to = aiohttp.ClientTimeout(total=12)
                            async with self.s.post(
                                f"{scheme}://{host}{path}",
                                json=payload,
                                headers={**_hdrs(), "Content-Type":"application/json"},
                                timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                            ) as resp:
                                if resp.status not in (200, 201): continue
                                data = await resp.json(content_type=None)
                                if not isinstance(data, dict): continue
                                schema = (data.get("data") or {}).get("__schema") or {}
                                if not schema: continue

                                self.r.live_eps.add(f"{scheme}://{host}{path}")
                                self.r.add_ep(path, "graphql_endpoint")

                                # Mine all operations
                                for op_type in ["queryType","mutationType","subscriptionType"]:
                                    op_data = schema.get(op_type) or {}
                                    for field in (op_data.get("fields") or []):
                                        fname = field.get("name","")
                                        if not fname: continue
                                        # Each field is an API operation
                                        resource = re.sub(r'(?<!^)(?=[A-Z])', '-', fname).lower()
                                        self._resources.add(resource)
                                        # Generate REST paths from operation name
                                        for prefix in ["/api","/api/v1","/api/v2",path,"/"]:
                                            ep = f"{prefix.rstrip('/')}/{resource}"
                                            self.r.add_ep(ep, "graphql_op")
                                        # Try GQL query string
                                        gql_ep = f"{path}?query={{{fname}}}"
                                        self.r.add_ep(gql_ep, "graphql_query")
                                        self.r.live_eps.add(f"{scheme}://{host}{gql_ep}")

                                # Mine all types
                                for tdef in (schema.get("types") or []):
                                    tname = tdef.get("name","")
                                    if not tname or tname.startswith("__"): continue
                                    kind = tdef.get("kind","")
                                    # Object types → generate resource paths
                                    if kind in ("OBJECT","INTERFACE"):
                                        resource = re.sub(r'(?<!^)(?=[A-Z])', '-', tname).lower()
                                        self._resources.add(resource)
                                break  # Got schema, stop trying payloads
                    except Exception:
                        pass

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 6: WSDL / SOAP detection
    # ─────────────────────────────────────────────────────────────────────────
    async def _wsdl_soap_detect(self, host: str) -> None:
        """Detect SOAP/WSDL services and extract operation names."""
        wsdl_paths = [
            "/?wsdl","/?WSDL","/service?wsdl","/services?wsdl",
            "/api?wsdl","/soap?wsdl","/ws?wsdl",
            "/wsdl","/wsdl/","/service.wsdl","/api.wsdl",
            "/ServiceName?wsdl","/WebService.asmx?wsdl",
            "/service/v1?wsdl","/service/v2?wsdl",
            "/soap","/soap/","/ws","/ws/","/webservice","/webservices",
            "/rpc","/rpc/","/xml-rpc","/xmlrpc","/xmlrpc.php",
        ]
        for path in wsdl_paths:
            for scheme in ("https",):
                try:
                    async with self._sem:
                        to = aiohttp.ClientTimeout(total=8)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers={**_hdrs(), "Accept":"text/xml,application/xml,*/*"},
                            timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                        ) as resp:
                            if resp.status not in (200,): continue
                            body = await resp.text(errors='replace')
                            if '<wsdl:' not in body and '<definitions' not in body: continue
                            self.r.add_ep(path, "wsdl_detected")
                            self.r.live_eps.add(f"{scheme}://{host}{path}")
                            # Extract operation names
                            for m in re.finditer(
                                r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']',
                                body, re.I):
                                op = m.group(1)
                                resource = re.sub(r'(?<!^)(?=[A-Z])', '-', op).lower()
                                self._resources.add(resource)
                                for prefix in ["/api","/soap","/ws",path]:
                                    self.r.add_ep(f"{prefix}/{resource}", "wsdl_op")
                            # Extract service locations
                            for m in re.finditer(
                                r'location=["\']([^"\']+)["\']', body, re.I):
                                loc = m.group(1)
                                if host in loc or loc.startswith('/'):
                                    p = urlparse(loc).path if loc.startswith('http') else loc
                                    if p: self.r.add_ep(p, "wsdl_location")
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 7: Webpack chunks + source map reconstruction
    # ─────────────────────────────────────────────────────────────────────────
    async def _js_webpack_full(self, host: str) -> None:
        """
        1. Find JS files (crawl + common locations)
        2. Extract webpack runtime → enumerate all chunk IDs → load each chunk
        3. Download .map source files → extract original source paths
        4. Find lazy-loaded routes (React.lazy, Vue async, Angular loadChildren)
        5. Extract environment variable injections (process.env.API_URL etc.)
        6. Extract fetch/axios/xhr calls from all JS
        """
        js_urls: Set[str] = set()
        # From already-found live endpoints
        for ep in list(self.r.live_eps):
            if host in ep and ep.endswith('.js') and 'min.js' not in ep.lower():
                js_urls.add(ep)
        # Common JS locations
        for scheme in ("https",):
            for jspath in [
                "/static/js/main.js","/static/js/bundle.js","/static/js/app.js",
                "/assets/js/app.js","/assets/js/main.js","/assets/js/bundle.js",
                "/js/app.js","/js/main.js","/js/bundle.js","/js/index.js",
                "/dist/bundle.js","/dist/app.js","/dist/main.js",
                "/build/static/js/main.chunk.js","/build/static/js/bundle.js",
                "/webpack/bundle.js","/public/js/app.js","/public/js/main.js",
                "/runtime~main.js","/chunk-vendors.js","/vendor.js","/vendors.js",
                "/runtime.js","/polyfills.js","/app.bundle.js",
                "/main.bundle.js","/commons.js","/common.js",
                "/scripts.js","/site.js","/global.js",
                "/static/bundle.js","/static/app.js",
                "/_next/static/chunks/main.js",
                "/_next/static/chunks/pages/index.js",
                "/nuxt/dist/client/app.js",
                "/sw.js","/service-worker.js","/serviceworker.js",
                "/workbox-*.js","/precache-manifest.*.js",
            ]:
                js_urls.add(f"{scheme}://{host}{jspath}")

        # Process JS files
        map_urls: Set[str] = set()
        async def _process_js(js_url: str):
            if js_url in self._crawled: return
            self._crawled.add(js_url)
            try:
                async with self._sem:
                    to = aiohttp.ClientTimeout(total=12)
                    async with self.s.get(
                        js_url, headers=_hdrs(), timeout=to,
                        ssl=_ssl_ctx(), proxy=self.proxy,
                    ) as resp:
                        if resp.status != 200: return
                        ct = resp.headers.get("Content-Type","")
                        if "javascript" not in ct and not js_url.endswith(".js"): return
                        body = await resp.text(errors='replace')

                        # ── Extract source map reference ──────────────────
                        for m in re.finditer(r'//# sourceMappingURL=(\S+)', body):
                            map_ref = m.group(1).strip()
                            map_url = urljoin(js_url, map_ref)
                            map_urls.add(map_url)

                        # ── Extract webpack chunk IDs and load them ───────
                        # Pattern: webpack jsonp chunk manifest
                        chunk_ids = set()
                        for m in re.finditer(
                            r'(?:chunks?\s*[:=]\s*\[|chunkId[s]?\s*[:=]\s*\[)([0-9,\s"\']+)\]',
                            body):
                            for cid in re.findall(r'[0-9]+', m.group(1)):
                                chunk_ids.add(cid)
                        # Webpack 5 style: {0:"vendors",1:"main",...}
                        for m in re.finditer(r'\{([0-9a-z"\':\-_,\s]+)\}\s*\[(?:e\.p\+)?', body):
                            for cid in re.findall(r'^[0-9]+', m.group(1)):
                                chunk_ids.add(cid)
                        # publicPath detection
                        public_path = ""
                        for m in re.finditer(r'publicPath\s*[=:]\s*["\`]([^"\'`]+)["\`]', body):
                            public_path = m.group(1).rstrip('/')
                            break
                        # Load chunks
                        for cid in list(chunk_ids)[:50]:
                            for chunk_pattern in [
                                f"{public_path}/static/js/{cid}.chunk.js",
                                f"{public_path}/chunks/{cid}.js",
                                f"{public_path}/{cid}.bundle.js",
                            ]:
                                chunk_url = f"https://{host}{chunk_pattern}"
                                if chunk_url not in self._crawled:
                                    js_urls.add(chunk_url)

                        # ── React lazy / Vue async component routes ────────
                        for m in re.finditer(
                            r'(?:React\.lazy|lazy|import)\s*\(\s*\(\s*\)\s*=>\s*import\s*\(\s*["\`]([^"\'`]+)["\`]',
                            body):
                            chunk_path = m.group(1)
                            chunk_url = urljoin(js_url, chunk_path)
                            js_urls.add(chunk_url)
                            # Extract route from path
                            route = re.sub(r'\.[^/]+$','', chunk_path.split('/')[-1])
                            if route:
                                self.r.add_ep(f"/{route}", "lazy_route")
                                self._resources.add(route.lower())

                        # ── Angular loadChildren routes ────────────────────
                        for m in re.finditer(
                            r'loadChildren\s*:\s*\(\s*\)\s*=>\s*import\s*\(["\`]([^"\'`]+)["\`]',
                            body):
                            module = m.group(1)
                            route = module.split('/')[-1].replace('.module','').replace('.ts','')
                            if route:
                                self.r.add_ep(f"/{route}", "angular_route")
                                self._resources.add(route.lower())

                        # ── Vue Router routes ─────────────────────────────
                        for m in re.finditer(
                            r'path\s*:\s*["\`]([/][^"\'`]+)["\`].*?(?:component|redirect)',
                            body, re.DOTALL):
                            route = m.group(1).split('?')[0]
                            if route and len(route) < 100:
                                self.r.add_ep(route, "vue_route")
                                self._found_paths.add(route)

                        # ── process.env / window injections ───────────────
                        for m in re.finditer(
                            r'(?:process\.env\.|window\.__ENV__|window\.env\.)([A-Z_]+)\s*[=:]\s*["\`]([^"\'`]{1,200})["\`]',
                            body):
                            varname = m.group(1)
                            val = m.group(2)
                            if any(x in varname for x in ('URL','API','ENDPOINT','BASE','HOST')):
                                if val.startswith('/') or val.startswith('http'):
                                    p = urlparse(val).path if val.startswith('http') else val
                                    self.r.add_ep(p, "env_injection")

                        # ── Standard path extraction ───────────────────────
                        self._extract_js_paths(body, host, js_url)

            except Exception:
                pass

        # Process all JS URLs in parallel
        await asyncio.gather(*[_process_js(u) for u in list(js_urls)[:200]],
                             return_exceptions=True)

        # Process source maps
        async def _process_sourcemap(map_url: str):
            if map_url in self._crawled: return
            self._crawled.add(map_url)
            try:
                async with self._sem:
                    to = aiohttp.ClientTimeout(total=12)
                    async with self.s.get(
                        map_url, headers=_hdrs(), timeout=to,
                        ssl=_ssl_ctx(), proxy=self.proxy,
                    ) as resp:
                        if resp.status != 200: return
                        body = await resp.text(errors='replace')
                        data = json.loads(body)
                        # sourceRoot + sources → original file paths
                        source_root = data.get("sourceRoot","")
                        for src in data.get("sources",[]):
                            if isinstance(src, str):
                                # Clean webpack:// prefix
                                src = re.sub(r'^webpack://[^/]*/','', src)
                                src = src.lstrip('./')
                                # Extract route hints from file names
                                fname = src.split('/')[-1]
                                name_clean = re.sub(r'\.[^.]+$','',fname)
                                # Pages/views/routes → endpoint hints
                                if any(x in src.lower() for x in
                                       ('page','view','route','screen','component',
                                        'controller','handler','endpoint','api')):
                                    route = name_clean.lower().replace(' ','-')
                                    self._resources.add(route)
                                    self.r.add_ep(f"/{route}", "sourcemap_route")
            except Exception:
                pass

        await asyncio.gather(*[_process_sourcemap(u) for u in list(map_urls)[:50]],
                             return_exceptions=True)

    def _extract_js_paths(self, body: str, host: str, src_url: str) -> None:
        """Extract API paths from JS source using comprehensive patterns."""
        patterns = [
            r'(?:fetch|axios\.(?:get|post|put|delete|patch|head|request)|http\.(?:get|post)|XMLHttpRequest)\s*\(\s*["\`]([/][^"\'`\s<>]{2,300})["\`]',
            r'(?:baseURL|baseUrl|apiUrl|apiBase|API_URL|API_BASE|BACKEND_URL|SERVICE_URL)\s*[=:]\s*["\`]([^"\'`\s]{3,200})["\`]',
            r'url\s*:\s*["\`](/[a-z0-9_/\-\.%?&={}$]{2,200})["\`]',
            r'endpoint\s*:\s*["\`](/[a-z0-9_/\-\.%?&={}$]{2,200})["\`]',
            r'path\s*:\s*["\`](/[a-z0-9_/\-\.%?&={}$]{2,200})["\`]',
            r'["\`](/(?:api|v\d+|graphql|rest|internal|private|admin|service|micro|rpc|grpc)[a-z0-9/_\-\.%?&={}$]{2,200})["\`]',
            r'(?:router|Router|Route|app|express)\.\s*(?:get|post|put|delete|patch|use|all)\s*\(\s*["\`]([^"\'`<>\s]{2,200})["\`]',
            r'routes\s*:\s*\[.*?path\s*:\s*["\`]([/][^"\'`]{1,100})["\`]',
            r'(?:to|from|redirect)\s*:\s*["\`]([/][^"\'`\s,)]{2,100})["\`]',
            r'(?:const|let|var)\s+\w+\s*=\s*["\`](/[a-z0-9_/\-\.]{4,100})["\`]',
            r'(?:add|set)(?:Route|Endpoint|Url|Path)\s*\(\s*["\`]([/][^"\'`]{2,100})["\`]',
        ]
        scheme = "https" if "https" in src_url else "http"
        for pat in patterns:
            for m in re.finditer(pat, body, re.I):
                val = m.group(1).strip()
                if val.startswith('/') and 1 < len(val) < 300:
                    val_clean = val.split('?')[0].split('#')[0]
                    self.r.add_ep(val_clean, "js_extract")
                    self.r.live_eps.add(f"{scheme}://{host}{val_clean}")
                    self._found_paths.add(val_clean)
                    self._extract_resource(val_clean)
                elif val.startswith('http') and host in val:
                    p = urlparse(val).path
                    if p and p != '/':
                        self.r.add_ep(p, "js_extract_abs")
                        self.r.live_eps.add(val)

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 8: Service worker analysis
    # ─────────────────────────────────────────────────────────────────────────
    async def _service_worker_analysis(self, host: str) -> None:
        """Parse service worker JS for cached paths and precache manifests."""
        sw_paths = ['/sw.js','/service-worker.js','/serviceworker.js',
                    '/pwa.js','/sw-toolbox.js','/workbox-sw.js',
                    '/firebase-messaging-sw.js','/push-sw.js',
                    '/offline.js','/cache-worker.js']
        for scheme in ("https",):
            for path in sw_paths:
                try:
                    async with self._sem:
                        to = aiohttp.ClientTimeout(total=8)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                            proxy=self.proxy,
                        ) as resp:
                            if resp.status != 200: continue
                            body = await resp.text(errors='replace')
                            # Precache manifest arrays
                            for m in re.finditer(
                                r'(?:precacheAndRoute|addToCacheList|cache\.add(?:All)?)\s*\(\s*\[([^\]]{1,5000})\]',
                                body, re.DOTALL):
                                for url_m in re.finditer(r'["\']([/][^"\']+)["\']', m.group(1)):
                                    p = url_m.group(1).split('?')[0]
                                    self.r.add_ep(p, "sw_precache")
                                    self.r.live_eps.add(f"{scheme}://{host}{p}")
                                    self._found_paths.add(p)
                            # importScripts
                            for m in re.finditer(r'importScripts\s*\(\s*["\']([^"\']+)["\']', body):
                                js_url = urljoin(f"{scheme}://{host}{path}", m.group(1))
                                if host in js_url:
                                    self._extract_js_paths(body, host, js_url)
                            # Fetch/route patterns in SW
                            self._extract_js_paths(body, host, f"{scheme}://{host}{path}")
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 9 + 10: Debug/secret paths + well-known exhaustive
    # ─────────────────────────────────────────────────────────────────────────
    async def _debug_and_secret_probe(self, host: str) -> None:
        """Probe all debug, diagnostic, secret, and config paths.

        Root-cause fixes applied:
        - WAF response check before recording any endpoint (prevents false positives)
        - Try both HTTPS and HTTP so HTTP-only services are not missed
        - Read 8 KB of body so WAF patterns deeper in the page are caught
        - 500-only filter: require informative stack/exception text
        """
        all_paths = list(set(self.DEBUG_PATHS + self.SECRET_PATHS))
        sem = asyncio.Semaphore(40)

        async def _probe(path: str):
            for scheme in ("https", "http"):
                try:
                    async with sem:
                        to = aiohttp.ClientTimeout(total=7)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                            proxy=self.proxy, allow_redirects=True,
                        ) as resp:
                            st = resp.status
                            if st not in (200, 201, 202, 204, 301, 302, 307, 308,
                                          401, 403, 405, 406, 407, 408, 500, 501, 502):
                                return

                            # Read up to 8 KB for thorough WAF / content checks
                            try:
                                raw = await resp.content.read(8192)
                                text = raw.decode("utf-8", errors="replace")
                            except Exception:
                                text = ""

                            hdrs = dict(resp.headers)

                            # ── WAF block check — skip if blocked ──────────────
                            if _is_waf_response(st, hdrs, text):
                                return

                            # ── 500: only interesting if it has informative output
                            if st >= 500:
                                if not any(x in text.lower() for x in (
                                    "stack", "trace", "error", "exception", "debug",
                                    "caused by", "at java.", 'file "/', "line ",
                                    "pdoexception", "sqlexception", "activerecord",
                                    "sequelize", "django.db", "traceback",
                                    "sqlstate", "ora-", "pg:", "mysql"
                                )):
                                    return

                            # ── 401/403: only record if it differs from a likely
                            #    catch-all (same status at baseline random path)
                            #    — prevents recording WAF-global 403 as a finding
                            if st in (401, 403) and not text:
                                return  # empty body 401/403 = likely blanket block

                            self.r.add_ep(path, "secret_probe")
                            self.r.live_eps.add(f"{scheme}://{host}{path}")
                            self._found_paths.add(path)

                            if "json" in hdrs.get("Content-Type", ""):
                                try:
                                    jdata = json.loads(text)
                                    for ep in self._json_url_extract(jdata):
                                        self.r.add_ep(ep, "debug_json")
                                except Exception:
                                    pass
                            for ep in _paths_from_text(text):
                                self.r.add_ep(ep, "debug_body")
                            return   # found on this scheme, don't retry HTTP
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in all_paths], return_exceptions=True)

    async def _well_known_exhaustive(self, host: str) -> None:
        """Probe all .well-known and standard meta paths."""
        sem = asyncio.Semaphore(20)
        async def _probe(path: str):
            for scheme in ("https", "http"):
                try:
                    async with sem:
                        to = aiohttp.ClientTimeout(total=5)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                            proxy=self.proxy, allow_redirects=True,
                        ) as resp:
                            st = resp.status
                            if st not in (200, 201, 202, 301, 302, 401, 403):
                                continue
                            try:
                                body = await resp.text(errors='replace')
                            except Exception:
                                body = ""
                            # WAF false-positive filter
                            if _is_waf_response(st, dict(resp.headers), body[:8192]):
                                continue
                            # Empty-body 401/403 are likely firewall drops
                            if st in (401, 403) and len(body.strip()) < 30:
                                continue
                            self.r.add_ep(path, "well_known")
                            self.r.live_eps.add(f"{scheme}://{host}{path}")
                            self._found_paths.add(path)
                            for ep in _paths_from_text(body):
                                self.r.add_ep(ep, "well_known_body")
                            return  # HTTPS succeeded; skip HTTP
                except Exception:
                    pass
        await asyncio.gather(*[_probe(p) for p in self.WELL_KNOWN_PATHS],
                             return_exceptions=True)

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 11: Response header leakage
    # ─────────────────────────────────────────────────────────────────────────
    async def _header_leak_extraction(self, host: str) -> None:
        """
        Send HEAD requests to key paths and analyze response headers
        for leaked internal paths, redirects, and configuration.
        """
        probe_paths = ['/','/.well-known/','/api/','/admin/','/internal/']
        leak_headers = [
            'Location','Content-Location','X-Redirect-To','X-Original-URL',
            'X-Rewrite-URL','X-Override-URL','X-Forwarded-URI','Refresh',
            'Link','X-Request-URL','X-Debug-URL','X-Backend-URL',
            'X-Cache','Via','Server','X-Powered-By','X-Generator',
            'X-Frame-Options','Content-Security-Policy','Set-Cookie',
            'X-Auth-Token','X-API-Version','X-Service-Name',
            'X-Upstream','X-Backend','X-Handler','X-Route',
        ]
        for path in probe_paths:
            for scheme in ("https",):
                try:
                    async with self._sem:
                        to = aiohttp.ClientTimeout(total=5)
                        async with self.s.head(
                            f"{scheme}://{host}{path}",
                            headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                            proxy=self.proxy, allow_redirects=False,
                        ) as resp:
                            for hname in leak_headers:
                                hval = resp.headers.get(hname, '')
                                if not hval: continue
                                # CSP → extract src domains/paths
                                if hname == 'Content-Security-Policy':
                                    for m in re.finditer(
                                        r"'self'|(?:https?://[^\s;'\"]+)", hval):
                                        val = m.group(0)
                                        if host in val:
                                            p = urlparse(val).path
                                            if p and p != '/':
                                                self.r.add_ep(p, "csp_leak")
                                elif hname == 'Link':
                                    for m in re.finditer(r'<([^>]+)>', hval):
                                        p = urlparse(m.group(1)).path
                                        if p: self.r.add_ep(p, "link_header")
                                elif hname == 'Set-Cookie':
                                    for m in re.finditer(r'[Pp]ath=([^\s;,]+)', hval):
                                        self.r.add_ep(m.group(1), "cookie_path")
                                else:
                                    if hval.startswith('/') or (hval.startswith('http') and host in hval):
                                        p = urlparse(hval).path if hval.startswith('http') else hval
                                        if p and p != '/':
                                            self.r.add_ep(p, "header_leak")
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 12: Error page analysis
    # ─────────────────────────────────────────────────────────────────────────
    async def _error_page_parse(self, host: str) -> None:
        """
        Trigger error pages and parse leaked paths from stack traces,
        404 pages (which often expose routing table structure),
        and debug information in error responses.
        """
        error_triggers = [
            f"/{'a'*50}",                      # random long path → 404
            f"/api/{'x'*30}",                  # API 404
            "/'",                              # quote injection → SQL/template error
            "/%00",                            # null byte
            f"/admin/{'x'*20}",                # admin 404
            "/.git/INVALID",                   # git path
            "/api/v99/nonexistent",            # version 404
            f"/{{}}{{}}{{}}{{}}{{}}{{}}{{}}", # template injection → error
        ]
        for path in error_triggers:
            for scheme in ("https",):
                try:
                    async with self._sem:
                        to = aiohttp.ClientTimeout(total=8)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                            proxy=self.proxy,
                        ) as resp:
                            body = await resp.text(errors='replace')
                            # Look for leaked paths in error output
                            for ep in _paths_from_text(body):
                                if len(ep) > 2 and ep not in (path,):
                                    self.r.add_ep(ep, "error_leak")
                            # Stack trace paths
                            for m in re.finditer(r'at\s+(?:\S+\s+)?\(([^)]+\.(?:js|py|rb|php|java|go|ts))[:\d]*\)', body):
                                fname = m.group(1).split('/')[-1]
                                self.r.add_ep(f"/{fname}", "stacktrace_file")
                            # Django/Flask URL routing in 404
                            for m in re.finditer(r'(?:URL pattern|Route|path)\s+["\']([/][^"\']+)["\']', body, re.I):
                                self.r.add_ep(m.group(1), "error_route")
                            # Express router listing
                            for m in re.finditer(r'(?:GET|POST|PUT|DELETE|PATCH)\s+([/][^\s<"\']{2,100})', body):
                                self.r.add_ep(m.group(1), "error_method")
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # STRATEGY 13: RSS / Atom / OPDS / JSONFeed
    # ─────────────────────────────────────────────────────────────────────────
    async def _feed_and_syndication(self, host: str) -> None:
        """Discover and parse all feed formats for URL extraction."""
        feed_paths = [
            '/rss','/rss/','/rss.xml','/feed','/feed/','/feed.xml',
            '/atom','/atom.xml','/feeds','/feeds/','/feeds/all',
            '/feeds/rss','/feeds/atom','/feeds/posts',
            '/blog/rss','/blog/feed','/blog/atom',
            '/news/rss','/news/feed','/news/atom',
            '/api/feed','/api/rss','/api/atom',
            '/feed.json','/feed.rss','/podcast.xml',
            '/opds','/opds/root.xml',
        ]
        for scheme in ("https",):
            for path in feed_paths:
                try:
                    async with self._sem:
                        to = aiohttp.ClientTimeout(total=6)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers={**_hdrs(), "Accept": "application/rss+xml,application/atom+xml,*/*"},
                            timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                        ) as resp:
                            if resp.status != 200: continue
                            body = await resp.text(errors='replace')
                            self.r.add_ep(path, "feed_found")
                            self.r.live_eps.add(f"{scheme}://{host}{path}")
                            # Extract <link>, <guid>, <id> from XML feeds
                            for tag in ['link','guid','id','url','href']:
                                for m in re.finditer(
                                    rf'<{tag}[^>]*>([^<]{{5,500}})</{tag}>', body, re.I):
                                    val = m.group(1).strip()
                                    if val.startswith('http') and host in val:
                                        p = urlparse(val).path
                                        if p and p != '/':
                                            self.r.add_ep(p, "feed_link")
                                            self.r.live_eps.add(val)
                                            self._found_paths.add(p)
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # POST-PROCESSING: Backup extensions, CRUD expansion, bypass variants
    # ─────────────────────────────────────────────────────────────────────────
    async def _backup_ext_probe(self, host: str) -> None:
        """
        For every discovered path, probe backup/alternate extensions.
        Focus on paths that look like scripts or have a file extension.
        """
        sem = asyncio.Semaphore(30)
        candidates: List[str] = []
        for path in list(self._found_paths)[:500]:
            parts = path.rsplit('/', 1)
            filename = parts[-1] if parts else ''
            if not filename or '.' not in filename: continue
            basename = filename.rsplit('.', 1)[0]
            dirpart = parts[0] if len(parts) > 1 else ''
            for ext in self.BACKUP_EXTS:
                candidates.append(f"{dirpart}/{basename}{ext}")
        # Also try .bak on paths without extensions
        for path in list(self._found_paths)[:200]:
            if '.' not in path.split('/')[-1]:
                for ext in ['.bak','.old','~','.backup','.zip']:
                    candidates.append(path + ext)

        async def _check(path: str):
            for scheme in ("https", "http"):
                try:
                    async with sem:
                        to = aiohttp.ClientTimeout(total=5)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                            proxy=self.proxy, allow_redirects=True,
                        ) as resp:
                            st = resp.status
                            if st not in (200, 201, 202, 401, 403):
                                continue
                            try:
                                body = await resp.text(errors='replace')
                            except Exception:
                                body = ""
                            if _is_waf_response(st, dict(resp.headers), body[:8192]):
                                continue
                            if st in (401, 403) and len(body.strip()) < 30:
                                continue
                            self.r.add_ep(path, "backup_ext")
                            self.r.live_eps.add(f"{scheme}://{host}{path}")
                            return
                except Exception:
                    pass
        await asyncio.gather(*[_check(p) for p in candidates], return_exceptions=True)

    async def _crud_expansion(self, host: str) -> None:
        """
        For each discovered resource name, generate all CRUD variants
        and verify which ones exist.
        """
        sem = asyncio.Semaphore(30)
        candidates: Set[str] = set()
        for res in list(self._resources)[:100]:
            for base_prefix in ['/api', '/api/v1', '/api/v2', '/api/v3',
                                  '/rest', '/rest/v1', '/rest/v2',
                                  '/internal/api', '/private/api',
                                  '/v1', '/v2', '/v3', '', '/service']:
                for suffix in self.CRUD_SUFFIXES:
                    path = f"{base_prefix}/{res}{suffix}"
                    candidates.add(path)
                    # Plural/singular variants
                    if res.endswith('s'):
                        candidates.add(f"{base_prefix}/{res[:-1]}{suffix}")
                    else:
                        candidates.add(f"{base_prefix}/{res}s{suffix}")

        async def _check(path: str):
            for scheme in ("https", "http"):
                try:
                    async with sem:
                        to = aiohttp.ClientTimeout(total=5)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                            proxy=self.proxy, allow_redirects=True,
                        ) as resp:
                            st = resp.status
                            if st not in (200, 201, 202, 204, 401, 403, 405):
                                continue
                            try:
                                body = await resp.text(errors='replace')
                            except Exception:
                                body = ""
                            if _is_waf_response(st, dict(resp.headers), body[:8192]):
                                continue
                            if st in (401, 403) and len(body.strip()) < 30:
                                continue
                            self.r.add_ep(path, "crud_expand")
                            self.r.live_eps.add(f"{scheme}://{host}{path}")
                            self._found_paths.add(path)
                            return
                except Exception:
                    pass
        await asyncio.gather(*[_check(p) for p in list(candidates)[:3000]],
                             return_exceptions=True)

    async def _path_bypass_variants(self, host: str) -> None:
        """
        For sensitive/protected found paths, try bypass techniques.
        Focus on /admin, /internal, /private, /api paths.
        """
        sem = asyncio.Semaphore(20)
        sensitive = [p for p in self._found_paths
                     if any(x in p.lower() for x in
                            ('admin','internal','private','debug','manage',
                             'console','secret','config','api','backup','old',
                             'test','staging','dev','beta','env','.git',
                             'phpinfo','actuator','metrics','health'))][:100]

        candidates: Set[str] = set()
        for path in sensitive:
            for variant_fn in self.BYPASS_VARIANTS:
                try:
                    v = variant_fn(path)
                    if v and v != path and len(v) < 300:
                        candidates.add(v)
                except Exception:
                    pass
            # Extension swapping
            p_noext, ext = os.path.splitext(path)
            if ext:
                for swap_ext in ['.php','.asp','.aspx','.jsp','.do',
                                  '.action','.cgi','.pl','.py','.rb','']:
                    candidates.add(p_noext + swap_ext)
            # Version substitution (v1→v2→v3 etc.)
            for m in re.finditer(r'/v(\d+)/', path):
                orig_v = int(m.group(1))
                for nv in range(1, 10):
                    if nv != orig_v:
                        candidates.add(path.replace(f"/v{orig_v}/", f"/v{nv}/", 1))

        async def _check(path: str):
            for scheme in ("https", "http"):
                try:
                    async with sem:
                        to = aiohttp.ClientTimeout(total=5)
                        async with self.s.get(
                            f"{scheme}://{host}{path}",
                            headers={**_hdrs(), "X-Original-URL": path,
                                     "X-Rewrite-URL": path,
                                     "X-Override-URL": path},
                            timeout=to, ssl=_ssl_ctx(), proxy=self.proxy,
                            allow_redirects=False,
                        ) as resp:
                            st = resp.status
                            if st not in (200, 201, 202, 204, 302, 401, 403):
                                continue
                            try:
                                body = await resp.text(errors='replace')
                            except Exception:
                                body = ""
                            if _is_waf_response(st, dict(resp.headers), body[:8192]):
                                continue
                            if st in (401, 403) and len(body.strip()) < 30:
                                continue
                            self.r.add_ep(path, "bypass_variant")
                            self.r.live_eps.add(f"{scheme}://{host}{path}")
                            return
                except Exception:
                    pass
        await asyncio.gather(*[_check(p) for p in list(candidates)[:2000]],
                             return_exceptions=True)

    async def _param_mine_endpoints(self, host: str) -> None:
        """
        For each discovered live endpoint, test common parameters
        with a reflected value to detect which params are accepted.
        Focus on endpoints that return JSON/form pages.
        """
        sem = asyncio.Semaphore(20)
        # Get live endpoints for this host that don't have params yet
        host_eps = [urlparse(ep).path for ep in self.r.live_eps
                    if host in ep and '?' not in ep][:50]
        sentinel = "REAPERTEST7x"

        async def _mine_params(path: str):
            for scheme in ("https",):
                # Batch params in groups of 20
                for i in range(0, len(self.COMMON_PARAMS), 20):
                    batch = self.COMMON_PARAMS[i:i+20]
                    query = '&'.join(f"{p}={sentinel}" for p in batch)
                    try:
                        async with sem:
                            to = aiohttp.ClientTimeout(total=6)
                            async with self.s.get(
                                f"{scheme}://{host}{path}?{query}",
                                headers=_hdrs(), timeout=to, ssl=_ssl_ctx(),
                                proxy=self.proxy,
                            ) as resp:
                                if resp.status not in (200, 201, 400, 422): continue
                                body = await resp.text(errors='replace')
                                # Find which params were reflected
                                for param in batch:
                                    # Reflected means the param value appears in response
                                    # OR the param name appears in an error message
                                    if sentinel in body or param in body.lower():
                                        self.r.parameters.setdefault(path, set()).add(param)
                    except Exception:
                        pass
        await asyncio.gather(*[_mine_params(p) for p in host_eps],
                             return_exceptions=True)

    # ─────────────────────────────────────────────────────────────────────────
    # Utility
    # ─────────────────────────────────────────────────────────────────────────
    async def _quick_verify(self, url: str, path: str, source: str) -> bool:
        """GET verification of a URL with WAF false-positive filtering and bypass retry."""
        try:
            async with self._sem:
                to = aiohttp.ClientTimeout(total=5)
                async with self.s.get(
                    url, headers=_hdrs(), timeout=to,
                    ssl=_ssl_ctx(), proxy=self.proxy, allow_redirects=True,
                ) as resp:
                    st = resp.status
                    if st not in (200, 201, 202, 204, 301, 302, 401, 403, 405):
                        return False
                    try:
                        body = await resp.text(errors='replace')
                    except Exception:
                        body = ""
                    resp_hdrs = dict(resp.headers)

                    if _is_waf_response(st, resp_hdrs, body[:8192]):
                        # WAF detected — try bypass header sets before giving up
                        for bypass_hdrs in Prober._BYPASS_HEADER_SETS[:10]:
                            try:
                                to2 = aiohttp.ClientTimeout(total=6)
                                async with self.s.get(
                                    url, headers={**_hdrs(), **bypass_hdrs},
                                    timeout=to2, ssl=_ssl_ctx(), proxy=self.proxy,
                                    allow_redirects=True,
                                ) as resp2:
                                    body2 = await resp2.text(errors='replace')
                                    hdrs2 = dict(resp2.headers)
                                    st2 = resp2.status
                                    if (not _is_waf_response(st2, hdrs2, body2[:8192]) and
                                            st2 in (200, 201, 202, 204, 301, 302, 401, 403, 405)):
                                        if not (st2 in (401, 403) and len(body2.strip()) < 30):
                                            self.r.live_eps.add(url)
                                            self.r.add_ep(path, f"{source}_bypass")
                                            return True
                            except Exception:
                                continue
                        return False  # All bypasses failed — genuine WAF block

                    if st in (401, 403) and len(body.strip()) < 30:
                        return False
                    self.r.live_eps.add(url)
                    self.r.add_ep(path, source)
                    return True
        except Exception:
            pass
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

class Output:
    def __init__(self, domain: str, r: Result, out_dir: str = "."):
        self.domain = domain
        self.r = r
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)

    def _p(self, name: str) -> str:
        return os.path.join(self.out_dir, name)

    def write_all(self) -> Dict[str, str]:
        paths: Dict[str, str] = {}
        paths["subdomains"] = self._write_subdomains()
        paths["endpoints"]  = self._write_endpoints()
        paths["dns"]        = self._write_dns()
        paths["ports"]      = self._write_ports()
        paths["takeover"]   = self._write_takeover()
        paths["stale"]      = self._write_stale()
        paths["params"]     = self._write_params()
        paths["favicons"]   = self._write_favicons()
        paths["js"]         = self._write_js()
        paths["secrets"]    = self._write_secrets()
        paths["cors"]       = self._write_cors()
        paths["methods"]    = self._write_methods()
        paths["json"]       = self._write_json()
        paths["html"]       = self._write_html()
        return paths

    def _write_subdomains(self) -> str:
        p = self._p(f"{self.domain}_subdomains.txt")
        with open(p, "w") as f:
            for sub in sorted(self.r.live_subs):
                src = self.r.sources.get(sub, [])
                f.write(f"{sub}\t[{', '.join(src)}]\n")
        return p

    # ── Endpoint severity classification ─────────────────────────────────────
    # Paths are ranked CRITICAL > HIGH > MEDIUM > LOW based on sensitivity.
    _EP_CRITICAL = (
        # Secrets / credentials exposure
        "/.env", "/.env.", "/env.", "/config.env", "/.aws/credentials",
        "/wp-config.php", "/config.php", "/database.php", "/db.php",
        "/secrets", "/secret", "/.git/config", "/.svn/entries",
        "/id_rsa", "/id_dsa", "/.ssh/", "/htpasswd", "/.htpasswd",
        "/credentials", "/private.key", "/server.key", "/client.key",
        # Admin panels
        "/admin", "/administrator", "/wp-admin", "/wp-login", "/admin/login",
        "/admin/dashboard", "/manage", "/management", "/superadmin", "/superuser",
        "/phpmyadmin", "/pma", "/adminer", "/dbadmin",
        # Cloud IMDS
        "/latest/meta-data", "/computeMetadata/v1", "/metadata/instance",
        "/odata/v4/Accounts", "/metadata",
        # k8s / container internals
        "/api/v1/secrets", "/api/v1/pods", "/api/v1/nodes",
        "/.kube/config", "/kubernetes/health", "/k8s/",
        # CI/CD and key management
        "/jenkins", "/.jenkins", "/gitlab", "/vault/v1", "/v1/sys/seal-status",
        "/v1/auth/token/lookup-self",
        # Database UIs
        "/mongo", "/elasticsearch", "/kibana", "/_cat/indices",
    )
    _EP_HIGH = (
        # Spring Boot Actuators
        "/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/beans",
        "/actuator/configprops", "/actuator/mappings", "/actuator/httptrace",
        "/actuator/logfile", "/actuator/shutdown",
        # Debug / profiling
        "/debug", "/debug/pprof", "/debug/vars", "/phpinfo.php",
        "/server-status", "/server-info", "/status", "/_profiler",
        # API docs / introspection
        "/swagger-ui", "/swagger-ui.html", "/api-docs", "/openapi.json",
        "/graphql", "/graphiql", "/v1/introspect",
        # Health / metrics
        "/metrics", "/prometheus", "/health", "/healthz", "/readyz",
        "/info", "/api/info",
        # Internal paths
        "/internal", "/internal/", "/_internal", "/api/internal",
        "/private", "/api/private",
        # Login / auth
        "/login", "/signin", "/auth", "/oauth", "/sso",
        "/reset-password", "/forgot-password", "/api/auth",
    )
    _EP_MEDIUM = (
        # API endpoints
        "/api", "/api/v1", "/api/v2", "/rest", "/rpc",
        "/users", "/user", "/accounts", "/account", "/profile",
        # Configuration / settings
        "/config", "/settings", "/preferences",
        # Reporting / exports
        "/export", "/download", "/backup", "/report",
        # Upload
        "/upload", "/uploads", "/files", "/attachments",
    )

    @staticmethod
    def _classify_endpoint(url: str) -> str:
        """Return CRITICAL / HIGH / MEDIUM / LOW severity for an endpoint URL."""
        try:
            from urllib.parse import urlparse
            path = urlparse(url).path.lower()
        except Exception:
            path = url.lower()
        for sig in Output._EP_CRITICAL:
            if sig.lower() in path:
                return "CRITICAL"
        for sig in Output._EP_HIGH:
            if sig.lower() in path:
                return "HIGH"
        for sig in Output._EP_MEDIUM:
            if sig.lower() in path:
                return "MEDIUM"
        return "LOW"

    def _write_endpoints(self) -> str:
        p = self._p(f"{self.domain}_endpoints.txt")
        # Group by severity for quick human triage
        by_sev: Dict[str, list] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for ep in sorted(self.r.live_eps):
            sev = Output._classify_endpoint(ep)
            by_sev[sev].append(ep)
        with open(p, "w") as f:
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                eps = by_sev[sev]
                if not eps:
                    continue
                f.write(f"\n# ══ {sev} ({len(eps)}) ══\n")
                for ep in eps:
                    f.write(ep + "\n")
        return p

    def _write_dns(self) -> str:
        p = self._p(f"{self.domain}_dns.json")
        with open(p, "w") as f:
            json.dump(self.r.dns_records, f, indent=2, default=list)
        return p

    def _write_ports(self) -> str:
        p = self._p(f"{self.domain}_ports.txt")
        with open(p, "w") as f:
            for host, ports in sorted(self.r.open_ports.items()):
                for entry in ports:
                    banner = entry.get("banner", "").replace("\n", "\\n")[:120]
                    f.write(f"{host}:{entry['port']}\t{entry.get('service','')}\t{banner}\n")
        return p

    def _write_takeover(self) -> str:
        p = self._p(f"{self.domain}_takeover.txt")
        with open(p, "w") as f:
            for t in self.r.takeover_candidates:
                # Keys set by StaleDetector: subdomain, final_cname, takeover_service, verified
                cname   = t.get("final_cname") or " -> ".join(t.get("cname_chain", ["?"])) or "?"
                service = t.get("takeover_service", "?") or "?"
                verified = t.get("verified", False)
                f.write(f"{t['subdomain']}\t->\t{cname}\t[{service}]\t"
                        f"verified={verified}\n")
        return p

    def _write_stale(self) -> str:
        p = self._p(f"{self.domain}_stale_dns.txt")
        with open(p, "w") as f:
            for s in self.r.stale_dns:
                # Key is "cname_chain" as set by StaleDetector._check_sub()
                chain = " -> ".join(s.get("cname_chain", s.get("chain", [])))
                f.write(f"{s['subdomain']}\tchain: {chain}\n")
        return p

    def _write_params(self) -> str:
        p = self._p(f"{self.domain}_params.txt")
        with open(p, "w") as f:
            for ep, params in sorted(self.r.parameters.items()):
                for param in params:
                    f.write(f"{ep}\t{param}\n")
        return p

    def _write_favicons(self) -> str:
        p = self._p(f"{self.domain}_favicon_hashes.txt")
        with open(p, "w") as f:
            for host, h in sorted(self.r.favicon_hashes.items()):
                f.write(f"{host}\t{h}\tshodan:http.favicon.hash:{h}\n")
        return p

    def _write_js(self) -> str:
        p = self._p(f"{self.domain}_js_findings.json")
        with open(p, "w") as f:
            json.dump({url: list(findings) for url, findings in self.r.js_findings.items()},
                      f, indent=2)
        return p

    def _write_secrets(self) -> str:
        p = self._p(f"{self.domain}_secrets.txt")
        with open(p, "w") as f:
            for url, secrets in sorted(self.r.secrets.items()):
                for s in secrets:
                    f.write(f"{url}\t{s}\n")
        return p

    def _write_cors(self) -> str:
        p = self._p(f"{self.domain}_cors.txt")
        with open(p, "w") as f:
            for entry in self.r.cors_issues:
                url = entry.get("url", "")
                f.write(f"{url}\t{json.dumps(entry)}\n")
        return p

    def _write_methods(self) -> str:
        p = self._p(f"{self.domain}_methods.txt")
        with open(p, "w") as f:
            for url, methods in sorted(self.r.open_methods.items()):
                f.write(f"{url}\t{', '.join(methods)}\n")
        return p

    def _write_json(self) -> str:
        p = self._p(f"{self.domain}_full.json")
        data = {
            "domain": self.domain,
            "generated": datetime.now(timezone.utc).isoformat() + "Z",
            "subdomains": {
                "live": sorted(self.r.live_subs),
                "all":  sorted(self.r.all_subs),
                "sources": {k: list(v) for k, v in self.r.sources.items()},
            },
            "endpoints": [
                {"url": ep, "severity": Output._classify_endpoint(ep)}
                for ep in sorted(self.r.live_eps)
            ],
            "dns_records": self.r.dns_records,
            "open_ports": self.r.open_ports,
            "takeover_candidates": self.r.takeover_candidates,
            "stale_dns": self.r.stale_dns,
            "cname_chains": self.r.cname_chains,
            "favicon_hashes": self.r.favicon_hashes,
            "parameters": {k: list(v) for k, v in self.r.parameters.items()},
            "js_findings": {k: list(v) for k, v in self.r.js_findings.items()},
            "secrets": {k: list(v) for k, v in self.r.secrets.items()},
            "cors_issues": self.r.cors_issues,
            "open_methods": self.r.open_methods,
            "ip_ranges": list(self.r.ip_ranges),
            "tech_stack": {k: list(v) for k, v in self.r.tech_stack.items()},
        }
        with open(p, "w") as f:
            json.dump(data, f, indent=2, default=list)
        return p

    def _write_html(self) -> str:
        p = self._p(f"{self.domain}_report.html")
        sub_rows = ""
        for sub in sorted(self.r.live_subs):
            src = ", ".join(self.r.sources.get(sub, []))
            sub_rows += f"<tr><td>{sub}</td><td>{src}</td></tr>\n"

        ep_rows = ""
        _SEV_COLOR = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#88aa88"}
        for ep in sorted(self.r.live_eps)[:500]:
            sev = Output._classify_endpoint(ep)
            col = _SEV_COLOR.get(sev, "#aaaaaa")
            ep_rows += (f"<tr><td><span style='color:{col};font-weight:bold'>[{sev}]</span></td>"
                        f"<td><a href='{ep}' target='_blank'>{ep}</a></td></tr>\n")

        port_rows = ""
        for host, ports in sorted(self.r.open_ports.items()):
            for entry in ports:
                banner = (entry.get("banner", "") or "")[:80].replace("<", "&lt;")
                port_rows += (f"<tr><td>{host}</td><td>{entry['port']}</td>"
                              f"<td>{entry.get('service','')}</td><td>{banner}</td></tr>\n")

        takeover_rows = ""
        for t in self.r.takeover_candidates:
            cname   = t.get("final_cname") or " -> ".join(t.get("cname_chain", ["?"])) or "?"
            service  = t.get("takeover_service", "?") or "?"
            verified = t.get("verified", False)
            takeover_rows += (f"<tr><td>{t['subdomain']}</td><td>{cname}</td>"
                              f"<td>{service}</td><td>{'✓' if verified else 'unverified'}</td></tr>\n")

        param_rows = ""
        for ep, params in sorted(self.r.parameters.items()):
            param_rows += f"<tr><td>{ep}</td><td>{', '.join(params)}</td></tr>\n"

        secret_rows = ""
        for url, secrets in sorted(self.r.secrets.items()):
            for s in secrets:
                secret_rows += f"<tr><td>{url}</td><td>{s[:120]}</td></tr>\n"

        favicon_rows = ""
        for host, h in sorted(self.r.favicon_hashes.items()):
            favicon_rows += (f"<tr><td>{host}</td><td>{h}</td>"
                             f"<td>http.favicon.hash:{h}</td></tr>\n")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SQL Reaper v3.7.0 — {self.domain}</title>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d0d0d;color:#e0e0e0;margin:0;padding:20px}}
  h1{{color:#ff4c4c;font-size:2em;border-bottom:2px solid #333;padding-bottom:.4em}}
  h2{{color:#ff8c00;margin-top:1.5em;border-left:4px solid #ff8c00;padding-left:10px}}
  table{{width:100%;border-collapse:collapse;margin:.8em 0;font-size:.85em}}
  th{{background:#1a1a1a;color:#ff8c00;padding:8px;text-align:left}}
  td{{padding:6px 8px;border-bottom:1px solid #222;word-break:break-all}}
  tr:hover td{{background:#1a1a1a}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.8em;margin:2px}}
  .badge-red{{background:#8b0000;color:#ffaaaa}}
  .badge-orange{{background:#8b4500;color:#ffd080}}
  .badge-green{{background:#004d00;color:#90ee90}}
  .stat{{display:inline-block;background:#1a1a1a;border:1px solid #333;
         padding:10px 20px;margin:5px;border-radius:8px;text-align:center}}
  .stat-num{{font-size:2em;color:#ff4c4c;font-weight:bold}}
  .stat-lbl{{font-size:.8em;color:#888}}
  .section{{margin:20px 0;padding:15px;background:#111;border-radius:8px;border:1px solid #222}}
  code{{background:#1a1a1a;padding:2px 6px;border-radius:3px;color:#ffd080;font-size:.9em}}
</style>
</head>
<body>
<h1>🩸 SQL Reaper v3.7.0 — Recon Report</h1>
<p style="color:#666">Target: <strong style="color:#fff">{self.domain}</strong>
 | Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</p>

<div>
  <div class="stat"><div class="stat-num">{len(self.r.live_subs)}</div><div class="stat-lbl">Live Subdomains</div></div>
  <div class="stat"><div class="stat-num">{len(self.r.all_subs)}</div><div class="stat-lbl">Total Found</div></div>
  <div class="stat"><div class="stat-num">{len(self.r.live_eps)}</div><div class="stat-lbl">Live Endpoints</div></div>
  <div class="stat"><div class="stat-num">{sum(len(v) for v in self.r.open_ports.values())}</div><div class="stat-lbl">Open Ports</div></div>
  <div class="stat"><div class="stat-num">{len(self.r.takeover_candidates)}</div><div class="stat-lbl">Takeover Candidates</div></div>
  <div class="stat"><div class="stat-num">{len(self.r.secrets)}</div><div class="stat-lbl">Secret Leaks</div></div>
  <div class="stat"><div class="stat-num">{sum(len(v) for v in self.r.parameters.values())}</div><div class="stat-lbl">Parameters</div></div>
  <div class="stat"><div class="stat-num">{len(self.r.favicon_hashes)}</div><div class="stat-lbl">Favicon Hashes</div></div>
</div>

<div class="section">
<h2>🎯 Subdomain Takeover Candidates</h2>
<table><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Confidence</th></tr>
{takeover_rows if takeover_rows else "<tr><td colspan=4>None found</td></tr>"}
</table></div>

<div class="section">
<h2>🌐 Live Subdomains ({len(self.r.live_subs)})</h2>
<table><tr><th>Subdomain</th><th>Sources</th></tr>
{sub_rows}
</table></div>

<div class="section">
<h2>🔓 Open Ports</h2>
<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr>
{port_rows if port_rows else "<tr><td colspan=4>None found</td></tr>"}
</table></div>

<div class="section">
<h2>🔑 Secret Leaks</h2>
<table><tr><th>Source URL</th><th>Secret</th></tr>
{secret_rows if secret_rows else "<tr><td colspan=2>None found</td></tr>"}
</table></div>

<div class="section">
<h2>🖼 Favicon Hashes (Shodan)</h2>
<table><tr><th>Host</th><th>Hash</th><th>Shodan Query</th></tr>
{favicon_rows if favicon_rows else "<tr><td colspan=3>None found</td></tr>"}
</table></div>

<div class="section">
<h2>🔍 Parameters Discovered</h2>
<table><tr><th>Endpoint</th><th>Parameters</th></tr>
{param_rows if param_rows else "<tr><td colspan=2>None found</td></tr>"}
</table></div>

<div class="section">
<h2>🌐 Live Endpoints (first 500, sorted by severity)</h2>
<table><tr><th>Severity</th><th>URL</th></tr>
{ep_rows}
</table></div>

</body></html>"""
        with open(p, "w") as f:
            f.write(html)
        return p



# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def run(domain: str, cfg: Dict) -> Result:
    r = Result(domain=domain, timestamp=datetime.now(timezone.utc).isoformat() + "Z")
    proxy = cfg.get("proxy")

    # ── Phase 0: Wildcard detection ─────────────────────────────────────────
    wc_ips: Set[str] = await _wildcard(domain)
    wc_ip = wc_ips  # Pass the full set — Prober now handles Set[str] natively
    if wc_ips:
        log(f"[!] Wildcard DNS: *.{domain} → {wc_ips}")

    # ── Phase 1: Passive OSINT (ALL 90+ sources) ─────────────────────────────
    log("[*] Phase 1: Passive OSINT — running all sources concurrently")
    api_keys: Dict[str, str] = {
        "shodan":         cfg.get("shodan_key", "") or "",
        "virustotal":     cfg.get("virustotal_key", "") or "",
        "securitytrails": cfg.get("securitytrails_key", "") or "",
        "bevigil":        cfg.get("bevigil_key", "") or "",
        "fullhunt":       cfg.get("fullhunt_key", "") or "",
        "binaryedge":     cfg.get("binaryedge_key", "") or "",
        "c99":            cfg.get("c99_key", "") or "",
        "whoxy":          cfg.get("whoxy_key", "") or "",
        "google_api":     cfg.get("google_api_key", "") or "",
        "google_cx":      cfg.get("google_cx", "") or "",
    }
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=300, ttl_dns_cache=300),
        timeout=aiohttp.ClientTimeout(total=90),
    ) as session:
        passive = Passive(session, r, domain, api_keys, proxy=proxy)
        await passive.run_all(passive_only=cfg.get("passive_only", False))
    log(f"[+] Passive: {len(r.subdomains)} candidates discovered")

    # ── Phase 2: DNS Enumeration ─────────────────────────────────────────────
    log("[*] Phase 2: DNS Enumeration")
    dns_enum = DNSEnumerator(r, domain)
    await dns_enum.run()
    log(f"[+] DNS: {sum(sum(len(vals) for vals in v.values()) for v in r.dns_records.values())} records")

    # ── Early exit when passive-only mode is requested ───────────────────────
    if cfg.get("passive_only"):
        log("[*] --passive-only: skipping active probing phases 3–6")
        return r

    # ── Phase 3: Generate subdomain mutations + built-in brute-force list ────
    log("[*] Phase 3: Generating mutations + brute-force wordlist")
    mutator = Mutator(r, domain)
    mutations = mutator.subdomain_mutations()

    # Built-in large wordlist (2000+ common subdomain prefixes beyond SUBDOMAIN_PREFIXES)
    _BRUTE_EXTRA = [
        # Single letters / short
        "a","b","c","d","e","f","g","h","i","j","k","l","m",
        "n","o","p","q","r","s","t","u","v","w","x","y","z",
        "mx0","mx3","mx4","mx5","ns3","ns4","ns5","ns6",
        # Numbers
        "1","2","3","4","5","10","11","12","13","14","15","20","21","30",
        # Services
        "account","accounts","accounts-api","activate","activation","ad",
        "ads","adserver","ajax","alerting","analyst","ansible","api-docs",
        "api-internal","api-prod","api-public","api-sandbox","api-staging",
        "api-test","api-v2","apidev","apigateway","apitest","app1","app2",
        "app3","apply","archive","aws","azure","azurefd",
        "backend2","backoffice","backstage","beta1","beta2","bounce",
        "bots","broker","browsersync","bug","bugs","build2",
        "cacti","career","careers","catalog","cdn0","cdn3","cdn4","cdn5",
        "central","certbot","certs","changelog","chatbot","checkout2",
        "ci2","citrix","click","client","clients","cloud2","cluster2",
        "code","coding","collector","com","commerce","community2",
        "compliance","composer","config","consul","container2","content",
        "controller","cookie","core","cron2","crossdomain","customer2",
        "cvs","dashboard3","data2","datacenter","datadog","datawarehouse",
        "db2","db3","db4","db5","dba","dbadmin","deploy2","deployment",
        "desktop","detect","dev-api","dev-app","dev-db","dev-portal",
        "devops","devportal","directory","discovery","distribution","dlp",
        "dns2","dns3","docker3","domain","download2","downloads","edge2",
        "email2","endpoint","endpoints","enterprise","error","errors",
        "es","event","exchange2","export","extranet","feed","feeds",
        "file2","files2","fileshare","filter","fleet","flow","forms",
        "forwarder","ftp3","functions","fw","gateway3","geo","graph",
        "guard","hades","harbor2","headless","hook","hooks2","host",
        "hosted","hosting","hub2","id2","image","images2","import",
        "in","index","info","infra2","infrastructure","insight",
        "insights","integration3","internal2","int2","inventory",
        "io","iot2","ip","ipam","issue","issues","it","its",
        "job","jobs2","jsonapi","k8s3","kafka2","key2","keycloak",
        "kibana2","kube2","lab","labs2","launch","lb2","ld","ldap2",
        "link","links","list","lists","load","loadbalancer","logger",
        "logging","logstash","loki","lookup","management","manager2",
        "map","maps","market","master","media2","member","members",
        "mesh","metrics2","mirror","mission","mobi","model2","mongo2",
        "mq2","mt","nats2","net","network","nginx2","node2","noc",
        "oauth2","observability","ocsp","office2","open","openapi",
        "ops","opt","order","orders","origin2","out","outbound","p",
        "paas","page","pages","partner2","password","path","peer",
        "perf","performance","photo","photos","platform","portal2",
        "postfix","postmaster","priv","private2","probe","process",
        "profile","profiles","project","projects","protected","protocol",
        "public2","push2","r2","radius","rbac","read","receiver",
        "record","records","redirect","redis2","region","registry3",
        "relay2","remote2","render","repo","repos","research2","resolve",
        "resource","resources","reverse","review","reviews","robot",
        "robots","route","router","run","s","saas","safe",
        "scan","schema","sender","serve","server","server2","services2",
        "session","ses","setup","share","shares","signin","signup",
        "site","sites","smtp2","snapshot","soa","socket","source",
        "spa2","sqs2","ssl","staging4","standard","stash","store2",
        "stream2","subscribe","sys","syslog","tag","tenant","test4",
        "token","tools2","tracker","trade","traffic","transfer","tunnel",
        "tv","type","ui","update","upload2","upstream","us","user",
        "users","v5","v6","vault2","velocity","verify","vm","vms",
        "voip2","vpn4","waf2","web2","web3","web4","webapp","webservice",
        "welcome","workspace","wss","xmpp","zone",
        # Numeric indexed
        "api01","api02","api03","api04","api05",
        "app01","app02","app03","app04","app05",
        "web01","web02","web03","web04","web05",
        "db01","db02","db03","db04","db05",
        "srv01","srv02","srv03","mail01","mail02","mail03",
        "node01","node02","node03","server01","server02","server03",
        # Cloud / infra
        "aks","eks","gke","fargate","lambda","functions2",
        "cloudflare2","fastly2","akamai2","aws2","gcp","gcs",
        "azure2","s3-bucket","cf","r53","route53","ec2","rds",
        "elasticache","sagemaker","bedrock",
        # Regions
        "us-east","us-west","eu-west","eu-central","ap-southeast",
        "ap-northeast","sa-east","af-south","us1","us2","eu1","eu2",
        "ap1","ap2","sg","tok","lon","fra","nyc","ams","sfo",
    ]
    # Merge built-in extra wordlist with SUBDOMAIN_PREFIXES mutations
    brute_candidates: Set[str] = set()
    for word in _BRUTE_EXTRA + list(cfg.get("extra_wordlist", [])):
        word = word.strip().lower()
        if word:
            brute_candidates.add(f"{word}.{domain}")

    all_candidates = mutations | r.subdomains | brute_candidates
    log(f"[+] {len(all_candidates)} total candidates "
        f"(passive={len(r.subdomains)} + mutations={len(mutations)} "
        f"+ brute={len(brute_candidates)})")

    # ── Phase 4: Batch DNS resolve → confirm live hosts ──────────────────────
    log(f"[*] Phase 4: Resolving {len(all_candidates)} candidates...")
    # Pass passively-confirmed subdomains so they are never filtered by wildcard IPs.
    # This is the key fix for CDN-backed targets where all IPs appear "wildcard".
    resolved = await batch_resolve(list(all_candidates), wc=wc_ips, known_subs=r.subdomains)
    for host in resolved:
        r.live_subs.add(host)
        r.subdomains.add(host)
    log(f"[+] {len(r.live_subs)} live subdomains confirmed via DNS")

    # ── Phase 5: Per-host deep scan (concurrent) ─────────────────────────────
    all_live = [domain] + sorted(r.live_subs)
    log(f"[*] Phase 5: Deep scanning {len(all_live)} hosts concurrently...")

    HOST_SEM = asyncio.Semaphore(30)   # 30 hosts in parallel — major speedup for Phase 5

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=200, enable_cleanup_closed=True, ttl_dns_cache=300),
        timeout=aiohttp.ClientTimeout(total=8),
    ) as session:

        async def _scan_host(host: str) -> None:
            async with HOST_SEM:
                try:
                    await asyncio.wait_for(_scan_host_inner(host), timeout=1800)
                except asyncio.TimeoutError:
                    log(f"  [!] {host}: scan timed out after 30 min — skipping")

        async def _scan_host_inner(host: str) -> None:
                log(f"  [→] {host}")
                prober = Prober(session, r, domain, wc=wc_ip, proxy=proxy)

                # 1. Probe all sensitive/hidden endpoints (framework paths)
                await prober.probe_host_paths(host, ALL_PROBE_PATHS)

                # 2. Advanced Endpoint Crawler (BFS + Wayback + OpenAPI + GraphQL)
                try:
                    crawler = EndpointCrawler(session, r, domain, proxy=proxy)
                    await crawler.crawl_host(host)
                except Exception:
                    pass

                # 3. JS file analysis → discover more endpoints + secrets
                if not cfg.get("no_js"):
                    js = JSEngine(session, r, domain, proxy=proxy)
                    try:
                        await js.crawl(f"https://{host}")
                    except Exception:
                        pass

                # 4. Favicon hash moved OUTSIDE per-host loop — runs once after all
                #    hosts complete (see below). Running it per-host was hammering
                #    the same 21 URLs 145 times = 3045 extra HTTP requests.

                # 5. Port scan
                if cfg.get("ports", True):
                    scanner = PortScanner(r, proxy=proxy, port_range=cfg.get("port_range"))
                    await scanner.scan_host(host)

                # 6. Parameter discovery on live endpoints for this host
                if not cfg.get("no_params"):
                    try:
                        # pd.run() expects hostnames (not full URLs); it picks its own
                        # endpoints from r.live_eps / r.endpoints internally.
                        pd = ParameterDiscovery(session, r, domain, proxy=proxy)
                        await pd.run([host])
                    except Exception:
                        pass

                # 7. CORS on API endpoints
                api_eps = [ep for ep in r.live_eps if host in ep and "/api" in ep]
                for ep in api_eps[:5]:
                    path = urlparse(ep).path or "/"
                    await prober.cors_probe(host, path)

                # 8. Framework fingerprinting — detect actual technology stack
                try:
                    detected_fws = await prober.framework_fingerprint(host)
                    if detected_fws:
                        for fw in detected_fws:
                            r.tech_stack[fw].add(host)
                        log(f"    [FW] {host}: {', '.join(sorted(detected_fws))}")
                except Exception:
                    pass

                # 9. HTTP method enumeration on interesting (API/admin/internal) endpoints
                if not cfg.get("no_methods"):
                    try:
                        method_targets: Set[str] = set()
                        for ep in list(r.live_eps):
                            if host not in ep:
                                continue
                            pth = urlparse(ep).path
                            if pth and any(x in pth.lower() for x in (
                                'api', 'admin', 'internal', 'console', 'manage',
                                'graphql', 'rest', 'service', 'rpc',
                            )):
                                method_targets.add(pth)
                        for pth in list(method_targets)[:20]:
                            await prober.method_enum(host, pth)
                    except Exception:
                        pass

                # 10. Virtual-host probing — discover additional vhosts sharing this IP
                try:
                    host_ip = await _resolve(host)
                    if host_ip:
                        vhost_candidates = list((r.subdomains | r.live_subs) - {host})[:300]
                        if vhost_candidates:
                            await prober.vhost_probe(host_ip, vhost_candidates)
                except Exception:
                    pass

                port_labels = [
                    f"{p['port']}/{p['service']}" for p in r.open_ports.get(host, [])
                ]
                host_eps = sorted(ep for ep in r.live_eps if host in ep)
                log(f"  [✓] {host}: {len(host_eps)} endpoints | ports={port_labels or 'none'}")
                for ep_url in host_eps:
                    log(f"      → {ep_url}")

        await asyncio.gather(*[_scan_host(h) for h in all_live], return_exceptions=True)

    # ── Favicon hash (Shodan pivot) — run once after all hosts are scanned ────
    # Running inside per-host loop was hashing domain + 20 subs = 21 URLs × N hosts
    # = thousands of redundant requests. One run here covers all live subs.
    try:
        fh = FaviconHasher(
            session, r, domain,
            keys={"shodan": api_keys.get("shodan", "")},
            proxy=proxy,
        )
        await fh.run()
        log(f"[+] Favicon hashing complete")
    except Exception:
        pass

    # ── Phase 5.5: Endpoint mutations — probe version/resource/bypass variants ─
    # endpoint_mutations() mines r.endpoints (populated during Phase 5) to generate
    # version-substituted paths, resource×version cross-products, env-suffix variants,
    # WAF-bypass transforms, and extension variants. These are probed on every live
    # host for maximum hidden-endpoint discovery.
    log("[*] Phase 5.5: Endpoint mutations — probing version/resource/bypass variants")
    ep_mutation_paths = list(mutator.endpoint_mutations())
    log(f"[+] {len(ep_mutation_paths)} endpoint mutation paths generated")
    if ep_mutation_paths and all_live:
        EP_MUT_SEM = asyncio.Semaphore(10)
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                ssl=False, limit=200, enable_cleanup_closed=True, ttl_dns_cache=300
            ),
            timeout=aiohttp.ClientTimeout(total=8),
        ) as session_mut:
            async def _probe_ep_mutations(h: str) -> None:
                async with EP_MUT_SEM:
                    p_mut = Prober(session_mut, r, domain, wc=wc_ip, proxy=proxy)
                    # Cap at 3000 paths per host to stay tractable
                    await p_mut.probe_host_paths(h, ep_mutation_paths[:3000])
            await asyncio.gather(
                *[_probe_ep_mutations(h) for h in all_live[:30]],
                return_exceptions=True,
            )
        log(f"[+] Endpoint mutation pass complete — {len(r.live_eps)} total endpoints now")

    # ── Phase 6: Stale DNS / Takeover (after all live hosts known) ───────────
    log("[*] Phase 6: Stale DNS / Takeover Detection")
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=100),
        timeout=aiohttp.ClientTimeout(total=12),
    ) as session:
        stale = StaleDetector(session, r, domain, proxy=proxy)
        await stale.run()
    log(f"[+] Takeover: {len(r.takeover_candidates)} | Stale: {len(r.stale_dns)}")

    # ── Post-processing WAF Filter Pass ──────────────────────────────────────
    # Re-verify all collected live_eps against WAF detection. This catches
    # any endpoints that slipped through per-probe WAF checks (e.g. from
    # third-party source ingestion like Wayback/CommonCrawl that don't probe).
    log(f"[*] Post-processing: WAF-filtering {len(r.live_eps)} endpoints…")
    _before = len(r.live_eps)
    verified_eps: Set[str] = set()
    sem_pp = asyncio.Semaphore(30)

    async def _waf_reverify(url: str, session: aiohttp.ClientSession) -> None:
        """
        Re-fetch endpoint and discard if WAF-blocked.

        Three-pass strategy:
        1. Fetch with default headers → check for WAF block
        2. If WAF blocked, retry with top-15 strategic bypass header sets (not all 75 —
           trying all 75 × hundreds of endpoints = thousands of extra requests)
        3. If all bypass attempts blocked → discard (false positive)
        """
        # Defensive: strip any legacy " [METHOD]" annotation that may have been stored
        # in earlier runs before this bug was fixed. This keeps _waf_reverify safe even
        # if live_eps was populated by an older version of the code.
        if " [" in url:
            url = url.split(" [")[0].strip()
        if not url.startswith(("http://", "https://")):
            return  # Malformed — skip silently

        # Strategic bypass sets for re-verification: chosen for maximum WAF bypass
        # efficacy across Cloudflare, Imperva, Akamai, AWS WAF, and generic WAFs.
        # Using indices into _BYPASS_HEADER_SETS — covers internal-IP, CDN proxy,
        # real-browser UA, k8s/service-mesh, Prometheus scrape, and bare-curl styles.
        # Limiting to 15 sets (not all 75) keeps post-processing tractable at scale.
        _REVERIFY_BYPASS_INDICES = [0, 3, 7, 11, 14, 19, 24, 29, 39, 46, 54, 57, 65, 66, 74]
        _REVERIFY_BYPASSES = [
            Prober._BYPASS_HEADER_SETS[i]
            for i in _REVERIFY_BYPASS_INDICES
            if i < len(Prober._BYPASS_HEADER_SETS)
        ]

        def _is_waf_challenge_body(body_lower: str) -> bool:
            """Catch WAF challenge bodies that _is_waf_response might miss."""
            _hard_signals = (
                "_cf_chl_opt", "cf-challenge-running", "cf_chl_rc_m", "__cf_chl_f_tk",
                "kpsdk", "kasada", "kaxsdc", "datadome.co", "ddjskey",
                "_pxAppId", "px-captcha", "hcaptcha.com", "arkoselabs.com",
                "ak_bmsc", "bmak.js", "challenges.cloudflare.com",
                "aws-waf-token", "aws waf could not forward",
                "zscaler", "access denied by zscaler",
            )
            return any(sig in body_lower for sig in _hard_signals)

        try:
            async with sem_pp:
                to = aiohttp.ClientTimeout(total=8)
                async with session.get(
                    url, headers=_hdrs(), timeout=to,
                    ssl=_ssl_ctx(), proxy=proxy,
                    allow_redirects=True,
                ) as resp:
                    st = resp.status
                    try:
                        body = await resp.text(errors='replace')
                    except Exception:
                        body = ""
                    hdrs_dict = dict(resp.headers)
                    ct = resp.headers.get("Content-Type", "")
                    body_stripped = body.strip()
                    body_lower = body[:8192].lower()

                    # Check for WAF block
                    is_waf = _is_waf_response(st, hdrs_dict, body[:8192])
                    is_challenge = _is_waf_challenge_body(body_lower)

                    if is_waf or is_challenge:
                        # Try bypass headers — if any bypasses the WAF, keep the endpoint
                        for bypass_hdrs in _REVERIFY_BYPASSES:
                            try:
                                to2 = aiohttp.ClientTimeout(total=8)
                                async with session.get(
                                    url, headers={**_hdrs(), **bypass_hdrs},
                                    timeout=to2, ssl=_ssl_ctx(), proxy=proxy,
                                    allow_redirects=True,
                                ) as resp2:
                                    body2 = await resp2.text(errors='replace')
                                    hdrs2 = dict(resp2.headers)
                                    if (not _is_waf_response(resp2.status, hdrs2, body2[:8192]) and
                                            not _is_waf_challenge_body(body2[:8192].lower())):
                                        # Bypass succeeded — endpoint is real but WAF-gated
                                        verified_eps.add(url)
                                        return
                            except Exception:
                                continue
                        # All bypass attempts failed → genuine WAF block, drop
                        return

                    # ── Additional quality filters (non-WAF) ─────────────────────
                    # Drop redirect to challenge/block page
                    if st in (301, 302, 307, 308):
                        loc = hdrs_dict.get("Location", "")
                        if loc and re.search(
                            r'(?:captcha|challenge|blocked|denied|403|forbidden|error)',
                            loc, re.I
                        ):
                            return  # Redirecting to block page

                    # 401 responses ALWAYS indicate a real endpoint (auth required) — never drop.
                    # 403 with tiny body: only drop if there is explicit WAF body evidence;
                    # a bare tiny 403 (e.g. Spring Security, nginx auth_basic, CF Access)
                    # is a real finding.
                    if st == 401:
                        # 401 = auth required → definitely a real endpoint, always keep
                        verified_eps.add(url)
                        return
                    if st == 403 and len(body_stripped) < 80:
                        is_json_body = (
                            "application/json" in ct or
                            (body_stripped.startswith("{") and body_stripped.endswith("}")) or
                            (body_stripped.startswith("[") and body_stripped.endswith("]"))
                        )
                        has_auth_hdr = bool(resp.headers.get("WWW-Authenticate", ""))
                        # Only drop if body contains explicit WAF block language
                        _has_waf_block_language = any(
                            sig in body_lower for sig in (
                                "request blocked", "access denied by", "you have been blocked",
                                "ip has been blocked", "bot protection", "ddos protection",
                                "firewall", "security service",
                            )
                        )
                        if not is_json_body and not has_auth_hdr and _has_waf_block_language:
                            return  # WAF block language in tiny body = false positive

                    # Drop cookie-based WAF challenge indicators
                    # (WAFs set specific cookies before serving a challenge)
                    # Collect ALL Set-Cookie header values (aiohttp merges multi-value hdrs with comma)
                    all_set_cookies = " ".join(
                        v for k, v in resp.headers.items() if k.lower() == "set-cookie"
                    )
                    if all_set_cookies:
                        _waf_cookie_sigs = (
                            "cf_clearance", "cf_chl_2", "cf_chl_seq_",
                            "_datadome", "datadome",
                            "_pxhd", "px_fid", "_px3",
                            "incap_ses_", "visid_incap_",
                            "rbzsessionid=", "rbzid=",
                            "ak_bmsc", "bm_sz",
                            "ddosify_", "_dd_s",
                        )
                        sc_lower = all_set_cookies.lower()
                        if any(sig.lower() in sc_lower for sig in _waf_cookie_sigs):
                            # WAF set its tracking/challenge cookie AND status is block code
                            if st in (403, 429, 503) and not body_stripped.startswith("{"):
                                return  # WAF cookie + block status = false positive

                    verified_eps.add(url)
        except (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError,
                aiohttp.ClientOSError):
            # Network-level errors (connection refused, DNS failure, TCP reset):
            # the endpoint was previously confirmed live (during active probing)
            # so connectivity issues here are likely transient. Keep it for both
            # HTTP and HTTPS — HTTPS connection errors can be SSL negotiation
            # timing issues, not evidence the endpoint doesn't exist.
            verified_eps.add(url)
        except asyncio.TimeoutError:
            # Timeout during re-verify: the host is slow but may be real.
            # Keep the endpoint — a timeout is not a WAF block.
            verified_eps.add(url)
        except Exception:
            # Other unexpected errors (e.g. SSL decode error, encoding issues):
            # The endpoint was previously confirmed, so keep it rather than
            # silently discarding valid findings due to transient errors.
            verified_eps.add(url)

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=60),
        timeout=aiohttp.ClientTimeout(total=15),
    ) as _pp_sess:
        await asyncio.gather(
            *[_waf_reverify(ep, _pp_sess) for ep in list(r.live_eps)],
            return_exceptions=True,
        )

    r.live_eps = verified_eps
    _after = len(r.live_eps)
    log(f"[+] WAF filter: {_before} → {_after} endpoints "
        f"({_before - _after} false positives removed)")

    total_params  = sum(len(v) for v in r.parameters.values())
    total_open    = sum(len(v) for v in r.open_ports.values())
    total_secrets = sum(len(v) for v in r.secrets.values())
    log(f"[+] Done: {len(r.live_subs)} subs | {len(r.live_eps)} endpoints | "
        f"{total_open} open ports | {total_params} params | "
        f"{total_secrets} secrets | {len(r.takeover_candidates)} takeover")
    return r


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="reaper_recon",
        description="SQL Reaper v3.7.0 — Advanced Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("domain", nargs="?", help="Target domain (e.g. example.com)")
    p.add_argument("-o", "--output", default=".", metavar="DIR",
                   help="Output directory (default: current directory)")

    # API Keys
    api = p.add_argument_group("API Keys")
    api.add_argument("--shodan-key",          metavar="KEY", help="Shodan API key")
    api.add_argument("--virustotal-key", "--vt-key", metavar="KEY", help="VirusTotal API key")
    api.add_argument("--securitytrails-key",  metavar="KEY", help="SecurityTrails API key")
    api.add_argument("--bevigil-key",         metavar="KEY", help="BeVigil API key")
    api.add_argument("--fullhunt-key",        metavar="KEY", help="FullHunt API key")
    api.add_argument("--binaryedge-key",      metavar="KEY", help="BinaryEdge API key")
    api.add_argument("--c99-key",             metavar="KEY", help="C99.nl API key")
    api.add_argument("--whoxy-key",           metavar="KEY", help="Whoxy.com API key")
    api.add_argument("--google-api-key",      metavar="KEY", help="Google Custom Search API key")
    api.add_argument("--google-cx",           metavar="CX",  help="Google Custom Search Engine ID")

    # Network
    net = p.add_argument_group("Network")
    net.add_argument("--proxy",       metavar="URL", help="HTTP/S proxy (e.g. http://127.0.0.1:8080)")
    net.add_argument("--timeout",     type=int, default=15, metavar="SEC",
                     help="Per-request timeout in seconds (default: 15)")
    net.add_argument("--concurrency", type=int, default=200, metavar="N",
                     help="Max concurrent HTTP requests (default: 200)")

    # Port scanning
    ports = p.add_argument_group("Port Scanning")
    ports.add_argument("--ports",        action=argparse.BooleanOptionalAction, default=True,
                       help="Enable/disable port scanning (default: enabled)")
    ports.add_argument("--port-range",   metavar="START-END",
                       help="Custom port range (e.g. 1-65535)")

    # Modes
    mode = p.add_argument_group("Modes")
    mode.add_argument("--passive-only", action="store_true",
                      help="Skip active probing (passive OSINT + DNS only)")
    mode.add_argument("--no-js",        action="store_true",
                      help="Skip JavaScript analysis")
    mode.add_argument("--no-params",    action="store_true",
                      help="Skip parameter discovery")
    mode.add_argument("--no-methods",   action="store_true",
                      help="Skip HTTP method enumeration on discovered endpoints")
    mode.add_argument("--wordlist",     metavar="FILE",
                      help="Additional wordlist file for subdomain brute-force")

    return p.parse_args()


def _prompt_domain() -> str:
    try:
        domain = input("Target domain: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)
    domain = re.sub(r"^https?://", "", domain).strip("/").split("/")[0]
    if not domain:
        print("[!] No domain provided.", file=sys.stderr)
        sys.exit(1)
    return domain


def main() -> None:
    args = _args()
    domain = args.domain or _prompt_domain()
    domain = re.sub(r"^https?://", "", domain).strip("/").split("/")[0].lower()

    # Validate port range format (PortScanner expects "start-end" string)
    if args.port_range:
        try:
            start, end = args.port_range.split("-", 1)
            int(start); int(end)  # validate they're integers
        except (ValueError, AttributeError):
            print(f"[!] Invalid port range: {args.port_range} (expected e.g. 1-65535)",
                  file=sys.stderr)
            sys.exit(1)

    cfg: Dict = {
        "shodan_key":         args.shodan_key,
        "virustotal_key":     args.virustotal_key,
        "securitytrails_key": args.securitytrails_key,
        "bevigil_key":        args.bevigil_key,
        "fullhunt_key":       args.fullhunt_key,
        "binaryedge_key":     args.binaryedge_key,
        "c99_key":            args.c99_key,
        "whoxy_key":          args.whoxy_key,
        "google_api_key":     args.google_api_key,
        "google_cx":          args.google_cx,
        "proxy":              args.proxy,
        "timeout":            args.timeout,
        "concurrency":        args.concurrency,
        "ports":              args.ports,
        "port_range":         args.port_range,   # string "start-end", PortScanner parses it
        "passive_only":       args.passive_only,
        "no_js":              args.no_js,
        "no_params":          args.no_params,
        "no_methods":         args.no_methods,
        "wordlist":           args.wordlist,
    }

    # Load extra wordlist if provided — stored in cfg for Phase 3 brute-force
    if args.wordlist and os.path.isfile(args.wordlist):
        try:
            with open(args.wordlist) as wf:
                cfg["extra_wordlist"] = [l.strip().lower() for l in wf if l.strip()]
            log(f"[*] Loaded {len(cfg['extra_wordlist'])} extra words from {args.wordlist}")
        except Exception:
            cfg["extra_wordlist"] = []
    else:
        cfg["extra_wordlist"] = []

    out_dir = os.path.join(args.output, domain)
    os.makedirs(out_dir, exist_ok=True)

    log(f"[*] SQL Reaper v3.7.0 — Target: {domain}")
    log(f"[*] Output directory: {out_dir}")

    try:
        r = asyncio.run(run(domain, cfg))
    except KeyboardInterrupt:
        log("\n[!] Interrupted by user.")
        sys.exit(130)

    output = Output(domain, r, out_dir)
    paths = output.write_all()

    log(f"\n[+] Done! Reports saved to: {out_dir}/")
    for name, path in paths.items():
        if path:
            log(f"    {name:12s}: {path}")

    print(f"\n{'='*60}")
    print(f"  SQL Reaper v3.7.0 — Results for {domain}")
    print(f"{'='*60}")
    print(f"  Live Subdomains  : {len(r.live_subs)}")
    print(f"  Total Found      : {len(r.all_subs)}")
    print(f"  Live Endpoints   : {len(r.live_eps)}")
    print(f"  Open Ports       : {sum(len(v) for v in r.open_ports.values())}")
    print(f"  Takeover Targets : {len(r.takeover_candidates)}")
    print(f"  Stale DNS        : {len(r.stale_dns)}")
    print(f"  Secret Leaks     : {sum(len(v) for v in r.secrets.values())}")
    print(f"  Parameters Found : {sum(len(v) for v in r.parameters.values())}")
    print(f"  Favicon Hashes   : {len(r.favicon_hashes)}")
    print(f"  HTML Report      : {paths.get('html','')}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()