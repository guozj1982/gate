#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (修复可用节点为 0 的增强版)
"""

import base64
import csv
import io
import json
import os
import re
import socket
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API") or "http://www.vpngate.net/api/iphone/"
VPNGATE_MIRRORS = [
    os.environ.get("VPNGATE_MIRROR") or "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
    "https://cdn.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json",
    "https://fastly.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json",
]

DEFAULT_WORKER = "https://dxs.guozhanjun1982.vip/check"


def normalize_worker_url(raw):
    url = (raw or "").strip() or DEFAULT_WORKER
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url.lstrip("/")
    if "sstp=" in url:
        return url
    return url.rstrip("?&")


WORKER_CANDIDATES = []
for _w in re.split(r"[,\s]+", os.environ.get("CHECK_WORKER") or ""):
    if _w.strip():
        _u = normalize_worker_url(_w)
        if _u not in WORKER_CANDIDATES:
            WORKER_CANDIDATES.append(_u)
_default_u = normalize_worker_url(DEFAULT_WORKER)
if _default_u not in WORKER_CANDIDATES:
    WORKER_CANDIDATES.append(_default_u)
WORKER_CHECK_URL = WORKER_CANDIDATES[0]

CHECK_TOKEN = (os.environ.get("CHECK_TOKEN") or "").strip()
CHECK_SSTP_AUTH = (os.environ.get("CHECK_SSTP_AUTH") or "").strip()
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY") or "16"))  # 适当降低并发以防 Worker 触发流控
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT") or "120")         # 延长单请求超时至 120s
CHECK_RETRIES = max(0, int(os.environ.get("CHECK_RETRIES") or "1"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES") or "0")
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT") or "60")
ALLOW_EMPTY = (os.environ.get("ALLOW_EMPTY") or "").strip().lower() in ("1", "true", "yes")
PUBLIC_DIR = os.environ.get("PUBLIC_DIR") or os.path.join(REPO_DIR, "public")
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")


def worker_request_target(addr):
    base = WORKER_CHECK_URL
    if "sstp=" in base:
        if base.endswith("@"):
            return base + addr, None
        if base.endswith("sstp="):
            return base + quote(addr, safe=""), None
        sep = "&" if "?" in base else "?"
        return f"{base}{sep}sstp={quote(addr, safe='')}", None
    return base, {"sstp": (f"{CHECK_SSTP_AUTH}@{addr}" if CHECK_SSTP_AUTH else addr)}


DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(
            VPNGATE_API,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"},
        )
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    for mirror_url in VPNGATE_MIRRORS:
        try:
            log("VPN GATE", f"尝试回退镜像: {mirror_url}")
            resp = requests.get(mirror_url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
            resp.raise_for_status()
            rows = parse_mirror_json(resp.json())
            if rows:
                log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
                return rows, "github-mirror"
        except Exception as exc:
            log("VPN GATE", f"镜像 {mirror_url} 失败: {exc}")

    die("VPN Gate 官方 API 与所有备用回退镜像均不可用, 数据源完全失败")


def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {"hostname": idx.get("hostname", 0),
           "ip": idx.get("ip", 1),
           "countrylong": idx.get("countrylong", 5),
           "countryshort": idx.get("countryshort", 6),
           "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1)}

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows


def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows


_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
        })
    return nodes


def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"
    return "unknown"


def _short(text, limit=120):
    return re.sub(r"\s+", " ", text or "").strip()[:limit]


def _request_worker(session, target_addr):
    headers = {"User-Agent": "Mozilla/5.0 (gate-checker)"}
    if CHECK_TOKEN:
        headers["X-Check-Token"] = CHECK_TOKEN

    url, params = worker_request_target(target_addr)
    for attempt in range(CHECK_RETRIES + 1):
        try:
            r = session.get(url, params=params, timeout=CHECK_TIMEOUT, headers=headers)
            if r.status_code in (429, 500, 502, 503, 504) and attempt < CHECK_RETRIES:
                time.sleep(2 * (attempt + 1))
                continue
            return r, None
        except Exception as exc:
            if attempt < CHECK_RETRIES:
                time.sleep(2 * (attempt + 1))
                continue
            return None, f"{type(exc).__name__}: {exc}"
    return None, "max retries exceeded"


def check_one(node, session):
    target_addr = f"{node['host']}:{node['port']}"
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["success"] = False
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"

    r, err = _request_worker(session, target_addr)
    if r is None:
        out["error"] = err or "request error"
        out["worker_error"] = True
        return out

    if r.status_code != 200:
        out["error"] = f"HTTP {r.status_code}: {_short(r.text)}"
        out["worker_error"] = True
        return out

    try:
        j = r.json()
    except Exception:
        out["error"] = f"BadJSON: {_short(r.text)}"
        out["worker_error"] = True
        return out

    ok = bool(j.get("success"))
    out["success"] = ok
    out["status"] = "success" if ok else "failed"
    out["latency_ms"] = j.get("responseTime")
    out["colo"] = j.get("colo")
    out["error"] = None if ok else (j.get("error") or j.get("message") or "check failed")
    if not ok:
        out["_raw"] = _short(r.text, 200)

    exit_info = j.get("exit") or {}
    if exit_info:
        asn = exit_info.get("asn") or {}
        org = asn.get("org") or asn.get("name") or ""
        out["exit"] = {
            "ip": exit_info.get("ip"),
            "country": exit_info.get("country"),
            "country_code": exit_info.get("country_code"),
            "city": exit_info.get("city"),
            "continent": exit_info.get("continent"),
            "asn": asn.get("asn"),
            "org": org,
            "type": asn.get("type"),
            "is_datacenter": exit_info.get("is_datacenter"),
        }
        out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
    else:
        out["residential"] = classify_network(out["host"], None, None)
    return out


def check_all(nodes, session):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


def select_worker():
    global WORKER_CHECK_URL
    tried = []
    for cand in WORKER_CANDIDATES:
        host = urlparse(cand).hostname or ""
        try:
            socket.getaddrinfo(host, 443)
        except Exception as exc:
            tried.append(host)
            continue
        WORKER_CHECK_URL = cand
        return cand
    die("所有 Worker 域名都无法解析: " + ", ".join(tried))


def report_errors(failed):
    if not failed:
        return
    stat = Counter((r.get("error") or "unknown") for r in failed)
    for err, cnt in stat.most_common(5):
        log("CLOUDFLARE WORKER", f"失败原因统计 x{cnt}: {err}")
    samples = [r for r in failed if r.get("_raw")][:3]
    for r in samples:
        log("CLOUDFLARE WORKER", f"Worker 返回详情样例 {r['host']}:{r['port']} -> {r['_raw']}")


def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n.get("residential") == "residential"),
        "datacenter_est": sum(1 for n in available if n.get("residential") == "datacenter"),
    }

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n.get("residential") == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n.get("residential") == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


CHAIN_URL = os.environ.get("CHAIN_URL") or "https://guozj1982.github.io/gate/chains.txt"
HOSTS_URL = os.environ.get("HOSTS_URL") or "https://guozj1982.github.io/gate/hosts.txt"
SUB_URL = os.environ.get("SUB_URL") or "https://guozj1982.github.io/gate/sub.txt"

EDGE_HOSTS = [
    h.strip()
    for h in (os.environ.get("EDGE_HOSTS") or
              "cf.3666888.xyz:443,thebeat.gehealthcare.com:443,cf.nyanya.moe:443,cf.1o.ee:443,"
              "cf.xreak.top:443,www.wto.org:443,versantstore.pearson.com:443").split(",")
    if h.strip()
]

EDT_UUID = (os.environ.get("EDT_UUID") or "").strip()
EDT_DOMAIN = os.environ.get("EDT_DOMAIN") or "123.guozhanjun1982.vip"
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT") or "chrome"


def _ordered_countries(countries):
    return sorted(countries.items(), key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])))


def _sorted_nodes(grp):
    return sorted(grp["nodes"], key=lambda n: (0 if n.get("residential") == "residential" else 1, n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"] or ""))


def _zh_name(cname, grp):
    code = str(grp.get("code") or "?").upper()
    return COUNTRY_ZH.get(code) or (code if code and code != "?" else cname), code


def build_chains_text(data):
    lines = ["# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单", f"# 自动更新: {data['generated_at']}", f"# 固定地址: {CHAIN_URL}", "# ========================================================"]
    for cname, grp in _ordered_countries(data["countries"]):
        zh, code = _zh_name(cname, grp)
        nodes = _sorted_nodes(grp)
        lines.append("")
        lines.append(f"# ---- {zh} {code} · {grp['count']} 节点 ----")
        for i, n in enumerate([n for n in nodes if n.get("residential") == "residential"], 1):
            lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate([n for n in nodes if n.get("residential") != "residential"], 1):
            lines.append(f"{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


def build_hosts_text(data):
    _entry = (os.environ.get("HOSTS_ENTRY") or "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS or [f"{EDT_DOMAIN}:443"]
    lines = ["# edgetunnel 优选IP清单", f"# 自动更新: {data['generated_at']}", f"# 固定地址: {HOSTS_URL}", "# ========================================================"]
    idx = 0
    for cname, grp in _ordered_countries(data["countries"]):
        zh, code = _zh_name(cname, grp)
        nodes = _sorted_nodes(grp)
        lines.append("")
        lines.append(f"# ---- {zh} {code} · {grp['count']} 节点 ----")
        for i, n in enumerate([n for n in nodes if n.get("residential") == "residential"], 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate([n for n in nodes if n.get("residential") != "residential"], 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


def _b64_secret_encode(plaintext, secret):
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address, default_port=80):
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data):
    lines = ["# edgetunnel 完整订阅", f"# 自动更新: {data['generated_at']}", f"# 固定地址: {SUB_URL}", "# ========================================================"]
    if not EDT_UUID:
        lines.append("# 未设置 EDT_UUID，暂不生成 vless 链接")
        return "\n".join(lines) + "\n"

    for cname, grp in _ordered_countries(data["countries"]):
        zh, _code = _zh_name(cname, grp)
        for i, n in enumerate(_sorted_nodes(grp), 1):
            name = f"{zh}-{i:02d}"
            chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
            chain_json = json.dumps(chain, separators=(",", ":"))
            enc = _b64_secret_encode(chain_json, EDT_UUID)
            path = quote("/video/" + enc, safe="")
            link = f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            lines.append(link)
    return "\n".join(lines) + "\n"


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = "<html><body><h1>VPN Gate</h1><pre id='out'></pre><script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats))</script></body></html>"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    with open(os.path.join(PUBLIC_DIR, "chains.txt"), "w", encoding="utf-8") as f:
        f.write(build_chains_text(data))
    with open(os.path.join(PUBLIC_DIR, "hosts.txt"), "w", encoding="utf-8") as f:
        f.write(build_hosts_text(data))
    with open(os.path.join(PUBLIC_DIR, "sub.txt"), "w", encoding="utf-8") as f:
        f.write(build_sub_text(data))
    return data_path, html_path


def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    select_worker()
    log("CLOUDFLARE WORKER", f"检测地址: {WORKER_CHECK_URL}")
    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}")
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")
    report_errors(failed)

    # 保护机制：如果所有节点判定失败，打印具体详情但允许使用 ALLOW_EMPTY 兜底发布
    if uniq and not success and not ALLOW_EMPTY:
        log("WARNING", "本轮所有节点测速均未通过 (success=0)。若需强行生成空页面，请设置环境变量 ALLOW_EMPTY=1")

    for r in results:
        r.pop("_raw", None)

    data = build_outputs(results, raw_count, sstp_count, source)
    write_outputs(data)
    log("WEBSITE", "完成文件生成与打包发布")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
