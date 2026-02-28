"""
Forcepoint XML Parser + FortiGate Pusher
pip install flask requests urllib3
python app.py  ->  http://localhost:5000
"""

from flask import Flask, request, jsonify, send_file, render_template_string
import xml.etree.ElementTree as ET
import csv, io, zipfile, re, ipaddress, requests, urllib3
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# ═══════════════════════════════════════════════════════════
# NAME SANITIZER
# FortiGate rules: max 79 chars, allowed: a-z A-Z 0-9 - _ .
# ═══════════════════════════════════════════════════════════
_name_map = {}

def sanitize_name(orig: str, max_len=79) -> str:
    s = orig.strip()
    s = re.sub(r'[^\w\-\.]', '_', s)
    s = re.sub(r'_+', '_', s)
    s = s.strip('_').rstrip('.')  # FortiGate rejects trailing dots
    s = s or 'obj'
    s = s[:max_len]
    if s != orig:
        _name_map[orig] = s
    return s

# ═══════════════════════════════════════════════════════════
# FORCEPOINT BUILT-IN → FORTIGATE BUILT-IN MAPPING
# These are Forcepoint predefined services that are NOT in
# the exported XML. We map them to their FortiGate equivalents
# so they can still be used as group members.
# ═══════════════════════════════════════════════════════════
BUILTIN_MAP = {
    # TCP services (class_id=46)
    'HTTP':                               'HTTP',
    'HTTPS':                              'HTTPS',
    'FTP':                                'FTP',
    'SSH':                                'SSH',
    'Remote Desktop':                     'RDP',
    'DNS (TCP)':                          'DNS',
    'DNS (TCP with SafeSearch)':          'DNS',
    'NTP (TCP)':                          'NTP',
    'Kerberos':                           'Kerberos',
    'Kpasswd':                            'Kerberos',
    'LDAP (TCP)':                         'LDAP',
    'LDAPS (TCP)':                        'LDAPS',
    'LDAPS (with decryption)':            'LDAPS',
    'Microsoft-DS':                       'Microsoft-DS',
    'Microsoft Global Catalog LDAP (TCP)': 'LDAP',
    'Microsoft Global Catalog LDAPS (TCP)':'LDAPS',
    'SIP (TCP)':                          'SIP',
    'SIP Control (TCP)':                  'SIP',
    'SCCP':                               'SCCP',
    'HTTP (SafeSearch)':                  'HTTP',
    'IMAPS':                              'IMAPS',
    # UDP services (class_id=55)
    'DNS (UDP)':                          'DNS',
    'NTP (UDP)':                          'NTP',
    'LDAP (UDP)':                         'LDAP',
    'LDAPS (UDP)':                        'LDAPS',
    'NetBIOS Datagram':                   'NetBIOS',
    'SIP (UDP)':                          'SIP',
    'SIP Control (UDP)':                  'SIP',
    'TFTP':                               'TFTP',
    # ICMP (class_id=28)
    'Ping':                               'PING',
}

# ═══════════════════════════════════════════════════════════
# XML PARSER
# ═══════════════════════════════════════════════════════════
def flatten_element(el, prefix=""):
    row = {}
    for k, v in el.attrib.items():
        if len(v) > 500: v = v[:200] + "...[truncated]"
        row[f"{prefix}{k}" if prefix else k] = v
    if el.text and el.text.strip():
        row[f"{prefix}_text" if prefix else "_text"] = el.text.strip()
    child_count = defaultdict(int)
    for child in el: child_count[child.tag] += 1
    grouped, single = defaultdict(list), {}
    for child in el:
        if child_count[child.tag] > 1: grouped[child.tag].append(child)
        else: single[child.tag] = child
    for tag, children in grouped.items():
        cp = f"{prefix}{tag}." if prefix else f"{tag}."
        keys = list(dict.fromkeys(k for c in children for k in c.attrib))
        if keys:
            for k in keys:
                row[f"{cp}{k}"] = " | ".join(c.attrib[k] for c in children if k in c.attrib)
        else:
            vals = [c.text.strip() for c in children if c.text and c.text.strip()]
            if vals: row[f"{cp}_text"] = " | ".join(vals)
        ggg = defaultdict(list)
        for c in children:
            for gc in c: ggg[gc.tag].append(gc)
        for gt, gl in ggg.items():
            gcp = f"{cp}{gt}."
            for k in list(dict.fromkeys(k for gc in gl for k in gc.attrib)):
                row[f"{gcp}{k}"] = " | ".join(gc.attrib[k] for gc in gl if k in gc.attrib)
    for tag, child in single.items():
        row.update(flatten_element(child, prefix=f"{prefix}{tag}." if prefix else f"{tag}."))
    return row


def parse_xml(xml_bytes):
    root = ET.fromstring(xml_bytes)
    root_info = {"tag": root.tag, **root.attrib}
    direct = defaultdict(list)
    for child in root: direct[child.tag].append(child)
    all_els = defaultdict(list)
    for el in root.iter():
        if el is root: continue
        all_els[el.tag].append(el)
    summary = [{"tag": t, "is_direct": t in direct, "count": len(all_els[t])}
               for t in sorted(all_els)]
    sheets = {}
    sheets["00_ROOT"] = {"columns": ["Property", "Value"],
                         "rows": [["tag", root.tag]] + [[k,v] for k,v in root.attrib.items()]}
    sheets["01_SUMMARY"] = {"columns": ["Element Tag", "Is Direct Child", "Count"],
                            "rows": [[s["tag"], "Yes" if s["is_direct"] else "No", s["count"]] for s in summary]}
    for tag in sorted(all_els):
        els = all_els[tag]
        all_rows, all_cols, seen = [], [], set()
        for el in els:
            row = flatten_element(el)
            all_rows.append(row)
            for col in row:
                if col not in seen: seen.add(col); all_cols.append(col)
        sheets[tag] = {"columns": all_cols,
                       "rows": [[row.get(col,"") for col in all_cols] for row in all_rows],
                       "is_direct": tag in direct, "count": len(els)}
    return root_info, summary, sheets


# ═══════════════════════════════════════════════════════════
# FORCEPOINT -> FORTIGATE EXTRACTOR
# Order: hosts -> networks -> addr_ranges -> net_groups
#        -> services -> service_groups
# RULE: sanitize ALL names first, resolve ALL refs to sanitized,
#       skip any ref that doesn't exist in our XML (Forcepoint built-ins)
# ═══════════════════════════════════════════════════════════
def extract_objects(xml_bytes):
    global _name_map
    _name_map = {}
    root = ET.fromstring(xml_bytes)

    # ── PASS 1: build complete name registry ──────────────────
    # Collect every named object in the XML and pre-sanitize all names
    # So that references can be resolved before we process anything
    xml_object_tags = ('host','network','address_range','group',
                       'gen_service_group','service_tcp','service_udp')
    xml_names = set()   # all original names present in XML
    for tag in xml_object_tags:
        for el in root.iter(tag):
            n = el.attrib.get('name','').strip()
            if n:
                xml_names.add(n)
                safe = sanitize_name(n)   # populates _name_map if changed
                _ = safe  # ensure sanitize_name is called for side-effect

    def resolve(ref):
        """
        Return the correct FortiGate name for a reference:
        1. If ref exists in our XML → return its sanitized name
        2. If ref is a known Forcepoint built-in → return FortiGate equivalent
        3. Otherwise → return None (truly unknown, will be skipped)
        """
        if ref in xml_names:
            return _name_map.get(ref, ref)        # custom object, use sanitized name
        if ref in BUILTIN_MAP:
            return BUILTIN_MAP[ref]               # map to FortiGate built-in name
        return None                               # unknown, skip

    # ── 1. Hosts ──────────────────────────────────────────────
    hosts = []
    for el in root.iter('host'):
        ip_el = el.find('mvia_address')
        ip = ip_el.attrib.get('address','').strip() if ip_el is not None else ''
        if not ip: continue
        orig = el.attrib.get('name','').strip()
        hosts.append({
            "orig_name": orig,
            "name":      _name_map.get(orig, orig),
            "type":      "ipmask",
            "subnet":    f"{ip} 255.255.255.255",
            "comment":   el.attrib.get('comment','')[:255]
        })

    # ── 2. Networks ───────────────────────────────────────────
    networks = []
    for el in root.iter('network'):
        net = el.attrib.get('ipv4_network','').strip()
        if '/' not in net: continue
        try:
            n = ipaddress.IPv4Network(net, strict=False)
            ip, mask = str(n.network_address), str(n.netmask)
        except: continue
        orig = el.attrib.get('name','').strip()
        networks.append({
            "orig_name": orig,
            "name":      _name_map.get(orig, orig),
            "type":      "ipmask",
            "subnet":    f"{ip} {mask}",
            "comment":   el.attrib.get('comment','')[:255]
        })

    # ── 3. Address Ranges ─────────────────────────────────────
    addr_ranges = []
    for el in root.iter('address_range'):
        r = el.attrib.get('ip_range','').strip()
        if '-' not in r: continue
        start, end = [x.strip() for x in r.split('-', 1)]
        orig = el.attrib.get('name','').strip()
        addr_ranges.append({
            "orig_name": orig,
            "name":      _name_map.get(orig, orig),
            "type":      "iprange",
            "start-ip":  start,
            "end-ip":    end
        })

    # ── 4. Network Groups ─────────────────────────────────────
    net_groups = []
    for el in root.iter('group'):
        orig = el.attrib.get('name','').strip()
        members = []
        skipped = []
        for ne in el.findall('ne_list'):
            ref = ne.attrib.get('ref','').strip()
            if not ref: continue
            resolved = resolve(ref)
            if resolved is not None:
                members.append(resolved)
            else:
                skipped.append(ref)
        # deduplicate while preserving order
        seen = set()
        members = [m for m in members if not (m in seen or seen.add(m))]
        if not members: continue
        net_groups.append({
            "orig_name":    orig,
            "name":         _name_map.get(orig, orig),
            "member":       members,
            "skipped_refs": skipped
        })

    # ── 5. Services TCP + UDP ─────────────────────────────────
    services = []
    for el in root.iter('service_tcp'):
        min_p = el.attrib.get('min_dst_port','').strip()
        max_p = el.attrib.get('max_dst_port', min_p).strip()
        if not min_p: continue
        pr   = f"{min_p}-{max_p}" if max_p and max_p != min_p else min_p
        orig = el.attrib.get('name','').strip()
        services.append({
            "orig_name":     orig,
            "name":          _name_map.get(orig, orig),
            "protocol":      "TCP",
            "tcp-portrange": pr,
            "comment":       el.attrib.get('comment','')[:255]
        })
    for el in root.iter('service_udp'):
        min_p = el.attrib.get('min_dst_port','').strip()
        max_p = el.attrib.get('max_dst_port', min_p).strip()
        if not min_p: continue
        pr   = f"{min_p}-{max_p}" if max_p and max_p != min_p else min_p
        orig = el.attrib.get('name','').strip()
        services.append({
            "orig_name":     orig,
            "name":          _name_map.get(orig, orig),
            "protocol":      "UDP",
            "udp-portrange": pr,
            "comment":       el.attrib.get('comment','')[:255]
        })

    # ── 6. Service Groups ─────────────────────────────────────
    service_groups = []
    for el in root.iter('gen_service_group'):
        orig = el.attrib.get('name','').strip()
        members = []
        skipped = []
        for s in el.findall('service_ref'):
            ref = s.attrib.get('ref','').strip()
            if not ref: continue
            resolved = resolve(ref)
            if resolved is not None:
                members.append(resolved)
            else:
                skipped.append(ref)
        # deduplicate while preserving order
        seen = set()
        members = [m for m in members if not (m in seen or seen.add(m))]
        if not members: continue
        service_groups.append({
            "orig_name":    orig,
            "name":         _name_map.get(orig, orig),
            "member":       members,
            "skipped_refs": skipped
        })

    return {
        "hosts":          hosts,
        "networks":       networks,
        "addr_ranges":    addr_ranges,
        "net_groups":     net_groups,
        "services":       services,
        "service_groups": service_groups,
        "name_map":       _name_map
    }


# ═══════════════════════════════════════════════════════════
# FORTIGATE API CLIENT
# ═══════════════════════════════════════════════════════════
class FGClient:
    def __init__(self, host, token, port=80):
        port   = int(port)
        scheme = "http" if port in (80, 8080) else "https"
        self.base    = f"{scheme}://{host}:{port}/api/v2"
        self.token   = token.strip()
        self.session = requests.Session()
        self.session.verify = False

    def _h(self):
        return {"Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"}

    def _p(self): return {"vdom": "root"}

    def test(self):
        r = self.session.get(f"{self.base}/monitor/system/status",
                             headers=self._h(), params=self._p(), timeout=8)
        return r.status_code, r.json() if r.status_code == 200 else r.text[:300]

    def get_existing(self, ep):
        r = self.session.get(f"{self.base}/cmdb/{ep}",
                             headers=self._h(), params=self._p(), timeout=15)
        if r.status_code == 200:
            return {item['name'] for item in r.json().get('results', [])}
        return set()

    def post(self, ep, payload):
        r = self.session.post(f"{self.base}/cmdb/{ep}",
                              headers=self._h(), params=self._p(),
                              json=payload, timeout=15)
        return r.status_code, r.text[:400]

    def put(self, ep, name, payload):
        enc = requests.utils.quote(name, safe='')
        r   = self.session.put(f"{self.base}/cmdb/{ep}/{enc}",
                               headers=self._h(), params=self._p(),
                               json=payload, timeout=15)
        return r.status_code, r.text[:400]

    def upsert(self, ep, name, payload, existing):
        return self.put(ep, name, payload) if name in existing else self.post(ep, payload)


_fg = None

EP = {
    "hosts":          "firewall/address",
    "networks":       "firewall/address",
    "addr_ranges":    "firewall/address",
    "net_groups":     "firewall/addrgrp",
    "services":       "firewall.service/custom",
    "service_groups": "firewall.service/group",
}


# ═══════════════════════════════════════════════════════════
# HTML
# ═══════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Forcepoint → FortiGate</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@400;600;700;900&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#070f1a;--sur:#0d1829;--card:#111f33;--bdr:#1a2d45;
  --acc:#00c8f0;--acc2:#6d28d9;--grn:#10b981;--org:#f59e0b;
  --red:#ef4444;--txt:#dde6f0;--mut:#4e6680;
  --mono:'IBM Plex Mono',monospace;--sans:'Inter',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:var(--sans);min-height:100vh;direction:ltr}
body::before{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,200,240,.018) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(0,200,240,.018) 1px,transparent 1px);
  background-size:48px 48px;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:1700px;margin:0 auto;padding:0 24px}

/* ── Header ── */
header{padding:22px 0 16px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;gap:14px}
.logo{width:42px;height:42px;background:linear-gradient(135deg,var(--acc),var(--acc2));border-radius:10px;
  display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.brand h1{font-size:18px;font-weight:900;letter-spacing:-.3px}
.brand p{font-size:11px;color:var(--mut);font-family:var(--mono);margin-top:2px}
#hdr-right{margin-left:auto;display:flex;gap:10px;align-items:center}

/* ── Tabs ── */
.tabs{display:flex;gap:3px;background:var(--card);border:1px solid var(--bdr);
  border-radius:10px;padding:3px;margin:18px 0}
.tab{flex:1;padding:9px 20px;border-radius:8px;border:none;background:transparent;
  color:var(--mut);font-family:var(--sans);font-size:13px;font-weight:600;cursor:pointer;transition:all .2s}
.tab.active{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff}
.tab-pane{display:none}.tab-pane.active{display:block}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:7px;padding:9px 20px;border-radius:8px;
  border:none;font-family:var(--sans);font-size:13px;font-weight:600;cursor:pointer;transition:all .2s}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-primary{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff}
.btn-primary:not(:disabled):hover{opacity:.87;transform:translateY(-1px)}
.btn-sm{padding:6px 14px;font-size:12px;border-radius:7px}
.btn-outline{background:transparent;border:1px solid var(--bdr);color:var(--txt)}
.btn-outline:not(:disabled):hover{border-color:var(--acc);color:var(--acc)}
.btn-green{background:var(--grn);color:#fff}.btn-green:not(:disabled):hover{opacity:.85}
.btn-red{background:var(--red);color:#fff}
.btn-org{background:var(--org);color:#000}

/* ── Upload ── */
#upload-section{padding:40px 0;text-align:center}
.drop-zone{border:2px dashed var(--bdr);border-radius:16px;padding:56px 40px;
  cursor:pointer;transition:all .3s;background:var(--sur);position:relative;overflow:hidden}
.drop-zone::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at center,rgba(0,200,240,.05) 0%,transparent 70%);
  opacity:0;transition:opacity .3s}
.drop-zone:hover,.drop-zone.drag{border-color:var(--acc)}
.drop-zone:hover::before,.drop-zone.drag::before{opacity:1}
#file-input{display:none}

/* ── Progress ── */
#progress-section{display:none;padding:36px 0;text-align:center}
.pbar-wrap{height:4px;background:var(--bdr);border-radius:99px;overflow:hidden;margin:16px auto;max-width:360px}
.pbar{height:100%;background:linear-gradient(90deg,var(--acc),var(--acc2));border-radius:99px;width:0%;transition:width .4s}
#plabel{font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:6px}

/* ── Viewer ── */
#results-section{display:none;padding:16px 0 50px}
.stats-bar{display:flex;gap:12px;margin-bottom:18px;flex-wrap:wrap}
.stat-card{background:var(--sur);border:1px solid var(--bdr);border-radius:10px;padding:12px 20px;flex:1;min-width:120px}
.stat-card .val{font-size:22px;font-weight:900;font-family:var(--mono);color:var(--acc)}
.stat-card .lbl{font-size:10px;color:var(--mut);margin-top:2px;text-transform:uppercase;letter-spacing:.5px}
.actions-bar{display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
.search-box{flex:1;background:var(--sur);border:1px solid var(--bdr);border-radius:8px;
  padding:8px 13px;color:var(--txt);font-family:var(--mono);font-size:12px;outline:none;
  transition:border-color .2s;min-width:160px}
.search-box:focus{border-color:var(--acc)}
.search-box::placeholder{color:var(--mut)}
.sep{width:1px;height:26px;background:var(--bdr)}
.main-layout{display:grid;grid-template-columns:240px 1fr;gap:14px;align-items:start}
.sidebar{background:var(--sur);border:1px solid var(--bdr);border-radius:12px;overflow:hidden;
  position:sticky;top:12px;max-height:calc(100vh - 70px);display:flex;flex-direction:column}
.sidebar-hdr{padding:11px 14px;border-bottom:1px solid var(--bdr);font-size:10px;
  font-family:var(--mono);color:var(--mut);text-transform:uppercase;letter-spacing:1px}
.sheet-list{overflow-y:auto;flex:1;padding:5px}
.sheet-list::-webkit-scrollbar{width:3px}
.sheet-list::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:99px}
.sheet-item{display:flex;align-items:center;gap:7px;padding:7px 9px;border-radius:6px;
  cursor:pointer;transition:all .15s;font-size:11px;font-family:var(--mono)}
.sheet-item:hover{background:rgba(0,200,240,.07)}
.sheet-item.active{background:rgba(0,200,240,.13);color:var(--acc)}
.sheet-item .badge{margin-left:auto;background:var(--bdr);color:var(--mut);font-size:9px;padding:1px 5px;border-radius:99px}
.sheet-item.active .badge{background:rgba(0,200,240,.2);color:var(--acc)}
.dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.dot-d{background:var(--grn)}.dot-n{background:var(--mut)}.dot-s{background:var(--acc)}
.table-wrap{background:var(--sur);border:1px solid var(--bdr);border-radius:12px;overflow:hidden}
.table-hdr{padding:14px 18px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;gap:10px}
.table-title{font-size:15px;font-weight:700}
.table-meta{font-family:var(--mono);font-size:10px;color:var(--mut)}
.table-scroll{overflow:auto;max-height:60vh}
.table-scroll::-webkit-scrollbar{width:4px;height:4px}
.table-scroll::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:99px}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}
thead th{position:sticky;top:0;background:#0a1525;color:var(--acc);padding:9px 12px;
  text-align:left;font-weight:600;white-space:nowrap;border-bottom:1px solid var(--bdr);cursor:pointer}
thead th:hover{color:#fff}
tbody tr{border-bottom:1px solid rgba(255,255,255,.02)}
tbody tr:hover{background:rgba(0,200,240,.04)}
tbody td{padding:7px 12px;vertical-align:top;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tbody td.mv{color:var(--org)}
.no-data{text-align:center;padding:44px;color:var(--mut)}
.pagination{padding:11px 18px;border-top:1px solid var(--bdr);display:flex;align-items:center;gap:7px}
.pg-info{font-family:var(--mono);font-size:10px;color:var(--mut);flex:1}
.pg-btn{background:var(--bdr);border:none;color:var(--txt);padding:4px 10px;border-radius:5px;
  cursor:pointer;font-family:var(--mono);font-size:11px;transition:background .15s}
.pg-btn:hover:not(:disabled){background:var(--acc);color:#000}
.pg-btn:disabled{opacity:.4;cursor:not-allowed}
.pg-btn.active{background:var(--acc);color:#000}

/* ══ Push Panel ══ */
#results-section-push{padding:16px 0 50px}
.push-panel{background:var(--sur);border:1px solid var(--bdr);border-radius:14px;overflow:hidden}

/* Token form */
.token-form{padding:32px;max-width:580px}
.token-form h2{font-size:18px;font-weight:900;margin-bottom:4px}
.token-form .sub{color:var(--mut);font-size:11px;font-family:var(--mono);margin-bottom:22px}
.fg2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.fg1{display:grid;gap:12px;margin-top:12px}
.field label{display:block;font-size:10px;color:var(--mut);font-family:var(--mono);
  margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.field input{width:100%;background:var(--card);border:1px solid var(--bdr);border-radius:7px;
  padding:9px 12px;color:var(--txt);font-family:var(--mono);font-size:12px;outline:none;transition:border-color .2s}
.field input:focus{border-color:var(--acc)}
.field input::placeholder{color:var(--mut)}
.conn-bar{background:rgba(16,185,129,.1);border-bottom:1px solid rgba(16,185,129,.2);
  padding:11px 22px;display:flex;align-items:center;gap:10px;font-size:12px;font-family:var(--mono)}
.conn-dot{width:8px;height:8px;border-radius:50%;background:var(--grn);animation:pulse 2s infinite;flex-shrink:0}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

/* Name map warning */
.nm-box{margin:14px 22px 0;background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.2);
  border-radius:9px;padding:12px 16px}
.nm-box h4{color:var(--org);margin-bottom:8px;font-size:11px;font-family:var(--mono)}
.nm-row{display:flex;gap:12px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04);
  font-family:var(--mono);font-size:10px}
.nm-row:last-child{border:none}
.nm-orig{color:var(--mut);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nm-arr{color:var(--org)}.nm-new{color:var(--txt);flex:1}

/* Object cards */
.push-sec-title{padding:18px 22px 6px;font-size:10px;color:var(--mut);
  font-family:var(--mono);text-transform:uppercase;letter-spacing:1px}
.obj-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:10px;padding:6px 22px 18px}
.obj-card{background:var(--card);border:2px solid var(--bdr);border-radius:10px;
  padding:14px;cursor:pointer;transition:all .2s;user-select:none;position:relative}
.obj-card:hover{border-color:var(--acc)}
.obj-card.sel{border-color:var(--acc);background:rgba(0,200,240,.07)}
.obj-card .oicon{font-size:20px;margin-bottom:7px}
.obj-card .otitle{font-size:12px;font-weight:700;margin-bottom:3px}
.obj-card .ocount{font-family:var(--mono);font-size:10px;color:var(--mut)}
.obj-card .ochk{position:absolute;top:8px;right:8px;width:16px;height:16px;border-radius:4px;
  border:2px solid var(--bdr);display:flex;align-items:center;justify-content:center;font-size:9px;transition:all .2s}
.obj-card.sel .ochk{background:var(--acc);border-color:var(--acc);color:#000}

/* Push actions */
.push-actions{padding:14px 22px;border-top:1px solid var(--bdr);display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.push-note{font-size:11px;color:var(--mut);font-family:var(--mono)}

/* Live log */
.log-wrap{margin:0 22px 22px}
.log-title{font-size:12px;font-weight:700;padding:10px 0 6px;font-family:var(--mono)}
.push-log{background:var(--card);border:1px solid var(--bdr);border-radius:8px;
  max-height:280px;overflow-y:auto;font-family:var(--mono);font-size:11px}
.push-log::-webkit-scrollbar{width:3px}
.push-log::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:99px}
.lr{display:flex;gap:10px;padding:6px 12px;border-bottom:1px solid rgba(255,255,255,.025);align-items:flex-start}
.lr:last-child{border:none}
.ls{flex-shrink:0;font-weight:700;width:46px}
.ls.ok{color:var(--grn)}.ls.sk{color:var(--mut)}.ls.er{color:var(--red)}
.ln{color:var(--txt);flex:1;word-break:break-all}
.lc{color:var(--mut);font-size:10px;min-width:76px}

/* ══ REPORT MODAL ══ */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;
  display:flex;align-items:flex-start;justify-content:center;padding:40px 20px;overflow-y:auto}
.modal{background:var(--sur);border:1px solid var(--bdr);border-radius:16px;
  width:100%;max-width:900px;overflow:hidden}
.modal-hdr{padding:20px 28px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;gap:12px}
.modal-hdr h2{font-size:18px;font-weight:900;flex:1}
.modal-body{padding:24px 28px}

/* Report summary cards */
.rpt-summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.rpt-card{border-radius:10px;padding:16px 20px;text-align:center}
.rpt-card .rv{font-size:32px;font-weight:900;font-family:var(--mono)}
.rpt-card .rl{font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
.rpt-card.total{background:rgba(0,200,240,.1);border:1px solid rgba(0,200,240,.2)}
.rpt-card.total .rv{color:var(--acc)}
.rpt-card.ok{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.2)}
.rpt-card.ok .rv{color:var(--grn)}
.rpt-card.skip{background:rgba(78,102,128,.15);border:1px solid rgba(78,102,128,.3)}
.rpt-card.skip .rv{color:var(--mut)}
.rpt-card.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2)}
.rpt-card.err .rv{color:var(--red)}

/* Report category sections */
.rpt-section{margin-bottom:20px;background:var(--card);border:1px solid var(--bdr);border-radius:10px;overflow:hidden}
.rpt-sec-hdr{display:flex;align-items:center;gap:10px;padding:11px 16px;cursor:pointer;
  background:rgba(0,200,240,.04);border-bottom:1px solid var(--bdr)}
.rpt-sec-hdr:hover{background:rgba(0,200,240,.07)}
.rpt-sec-icon{font-size:16px}
.rpt-sec-title{font-weight:700;font-size:13px;flex:1}
.rpt-sec-chips{display:flex;gap:6px}
.chip{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:99px}
.chip-ok{background:rgba(16,185,129,.15);color:var(--grn)}
.chip-sk{background:rgba(78,102,128,.2);color:var(--mut)}
.chip-er{background:rgba(239,68,68,.15);color:var(--red)}
.rpt-sec-toggle{color:var(--mut);font-size:12px;transition:transform .2s}
.rpt-sec-body{overflow:hidden;transition:max-height .3s}

/* Report table */
.rpt-tbl{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}
.rpt-tbl th{padding:8px 14px;text-align:left;font-size:10px;color:var(--mut);
  text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bdr)}
.rpt-tbl td{padding:7px 14px;border-bottom:1px solid rgba(255,255,255,.025);vertical-align:top}
.rpt-tbl tr:last-child td{border:none}
.rpt-tbl tr:hover td{background:rgba(0,200,240,.03)}
.badge-ok{display:inline-block;background:rgba(16,185,129,.15);color:var(--grn);
  padding:2px 8px;border-radius:99px;font-size:10px;font-weight:700}
.badge-sk{display:inline-block;background:rgba(78,102,128,.2);color:var(--mut);
  padding:2px 8px;border-radius:99px;font-size:10px;font-weight:700}
.badge-er{display:inline-block;background:rgba(239,68,68,.15);color:var(--red);
  padding:2px 8px;border-radius:99px;font-size:10px;font-weight:700}
.name-changed{font-size:9px;color:var(--org);font-style:italic}

/* Report actions */
.rpt-actions{padding:16px 28px;border-top:1px solid var(--bdr);display:flex;gap:10px;align-items:center}

/* Toast */
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--grn);
  color:#fff;padding:10px 20px;border-radius:8px;font-weight:700;font-size:12px;
  opacity:0;transition:opacity .3s;z-index:200;pointer-events:none;white-space:nowrap}
.toast.show{opacity:1}

@media(max-width:860px){
  .main-layout{grid-template-columns:1fr}
  .sidebar{position:relative;max-height:240px}
  .fg2{grid-template-columns:1fr}
  .rpt-summary{grid-template-columns:repeat(2,1fr)}
}
</style>
</head>
<body>
<div class="wrap">

<!-- Header -->
<header>
  <div class="logo">🛡️</div>
  <div class="brand">
    <h1>Forcepoint &rarr; FortiGate</h1>
    <p>xml parser + api pusher</p>
  </div>
  <div id="hdr-right"></div>
</header>

<!-- Tabs (hidden until file loaded) -->
<div class="tabs" id="main-tabs" style="display:none">
  <button class="tab active" onclick="switchTab('viewer')">&#128202; XML Viewer</button>
  <button class="tab" onclick="switchTab('pusher')">&#128640; FortiGate Push</button>
</div>

<!-- Upload -->
<div id="upload-section">
  <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
    <div style="font-size:52px;margin-bottom:12px">&#128193;</div>
    <div style="font-size:20px;font-weight:700;margin-bottom:8px">Drop your Forcepoint XML here</div>
    <div style="color:var(--mut);font-size:12px;font-family:var(--mono);margin-bottom:20px">drag &amp; drop or click to browse &middot; .xml files only</div>
    <button class="btn btn-primary" onclick="event.stopPropagation();document.getElementById('file-input').click()">
      &#128193; Browse File
    </button>
  </div>
  <input type="file" id="file-input" accept=".xml" onchange="handleFile(this.files[0])"/>
</div>

<!-- Progress -->
<div id="progress-section">
  <div style="font-size:44px;margin-bottom:12px">&#9881;&#65039;</div>
  <div style="font-size:17px;font-weight:700;margin-bottom:14px">Analyzing file...</div>
  <div class="pbar-wrap"><div class="pbar" id="pbar"></div></div>
  <div id="plabel">reading xml...</div>
</div>

<!-- ═══ TAB: Viewer ═══ -->
<div class="tab-pane active" id="pane-viewer">
<div id="results-section">
  <div class="stats-bar" id="stats-bar"></div>
  <div class="actions-bar">
    <input class="search-box" id="search-box" placeholder="Search data..." oninput="filterTable()"/>
    <div class="sep"></div>
    <button class="btn btn-sm btn-outline" onclick="downloadCurrentCSV()">&#8595; Export CSV</button>
    <button class="btn btn-sm btn-green" onclick="downloadAllZip()">&#128230; Download All ZIP</button>
    <button class="btn btn-sm btn-outline" onclick="resetApp()">&#8635; New File</button>
  </div>
  <div class="main-layout">
    <div class="sidebar">
      <div class="sidebar-hdr">&#128203; Sheets</div>
      <div class="sheet-list" id="sheet-list"></div>
    </div>
    <div class="table-wrap">
      <div class="table-hdr">
        <div>
          <div class="table-title" id="table-title">-</div>
          <div class="table-meta" id="table-meta"></div>
        </div>
      </div>
      <div class="table-scroll">
        <table><thead id="thead"></thead><tbody id="tbody"></tbody></table>
      </div>
      <div class="pagination">
        <div class="pg-info" id="pg-info"></div>
        <button class="pg-btn" id="btn-prev" onclick="changePage(-1)">&laquo;</button>
        <div id="pg-nums"></div>
        <button class="pg-btn" id="btn-next" onclick="changePage(1)">&raquo;</button>
      </div>
    </div>
  </div>
</div>
</div>

<!-- ═══ TAB: Pusher ═══ -->
<div class="tab-pane" id="pane-pusher">
<div id="results-section-push">
<div class="push-panel">

  <!-- Step 1: Connect -->
  <div id="step-login">
    <div class="token-form">
      <h2>&#128273; FortiGate Connection</h2>
      <div class="sub">Enter the FortiGate IP and API Bearer Token (REST API Administrator)</div>
      <div class="fg2">
        <div class="field">
          <label>FortiGate IP / Hostname</label>
          <input id="fg-host" placeholder="172.16.0.101" type="text"/>
        </div>
        <div class="field">
          <label>Port</label>
          <input id="fg-port" placeholder="80" type="number" value="80"/>
        </div>
      </div>
      <div class="fg1">
        <div class="field">
          <label>API Token (Bearer)</label>
          <input id="fg-token" placeholder="Paste token here..." type="text"/>
        </div>
      </div>
      <div style="margin-top:18px;display:flex;gap:10px;align-items:center">
        <button class="btn btn-primary" onclick="doConnect()" id="btn-connect">
          &#128279; Test &amp; Connect
        </button>
        <span id="conn-status" style="font-family:var(--mono);font-size:11px;color:var(--mut)"></span>
      </div>
    </div>
  </div>

  <!-- Step 2: Select & Push -->
  <div id="step-objects" style="display:none">
    <div class="conn-bar">
      <div class="conn-dot"></div>
      <span id="conn-label">Connected</span>
      <button class="btn btn-sm btn-outline" style="margin-left:auto" onclick="doDisconnect()">
        Disconnect
      </button>
    </div>

    <!-- Name map warning -->
    <div id="nm-box-wrap" style="display:none">
      <div class="nm-box">
        <h4>&#9888; Automatic name adjustments — FortiGate does not allow special characters</h4>
        <div id="nm-rows"></div>
      </div>
    </div>

    <div class="push-sec-title">Select object categories to push (in order)</div>
    <div class="obj-grid" id="obj-grid"></div>

    <div class="push-actions">
      <button class="btn btn-primary" onclick="doPush()" id="btn-push">
        &#128640; Start Push
      </button>
      <div class="push-note" id="push-note"></div>
    </div>

    <!-- Live log -->
    <div class="log-wrap" id="log-wrap" style="display:none">
      <div class="log-title">Live Log &mdash; <span id="log-summary" style="color:var(--mut);font-weight:400"></span></div>
      <div class="push-log" id="push-log"></div>
    </div>
  </div>

</div>
</div>
</div>

</div><!-- /wrap -->

<!-- ═══ REPORT MODAL ═══ -->
<div class="modal-overlay" id="rpt-overlay" style="display:none" onclick="closeReport(event)">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="modal-hdr">
      <div style="font-size:22px">&#128203;</div>
      <h2>Push Report</h2>
      <div id="rpt-timestamp" style="font-family:var(--mono);font-size:11px;color:var(--mut)"></div>
      <button class="btn btn-sm btn-outline" style="margin-left:auto" onclick="closeReport()">&#10005; Close</button>
    </div>
    <div class="modal-body">
      <!-- Summary cards (clickable = filter) -->
      <div class="rpt-summary" id="rpt-summary"></div>
      <!-- Active filter bar -->
      <div id="rpt-filter-bar" style="display:none;margin-bottom:16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span style="font-family:var(--mono);font-size:11px;color:var(--mut)">Filtering:</span>
        <span id="rpt-filter-label" style="font-family:var(--mono);font-size:11px;font-weight:700"></span>
        <button class="btn btn-sm btn-outline" onclick="setFilter(null)" style="padding:3px 10px;font-size:11px">&#10005; Clear filter</button>
      </div>
      <div id="rpt-sections"></div>
    </div>
    <div class="rpt-actions">
      <button class="btn btn-sm btn-green" onclick="exportReportCSV()">&#8595; Export CSV</button>
      <button class="btn btn-sm btn-outline" onclick="exportReportCSV('filtered')" id="btn-export-filtered" style="display:none">&#8595; Export Filtered CSV</button>
      <button class="btn btn-sm btn-outline" onclick="closeReport()">Close</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
// ═══ State ═══════════════════════════════════════════════
let sheetsData = {}, foObjects = {}, nameMap = {};
let curSheet = null, curPage = 1, filteredRows = [], sortCol = -1, sortDir = 1;
const PAGE = 100;
let pushReport = null;   // filled after each push

const OBJ_ORDER = [
  { key:'hosts',          icon:'&#128187;', title:'Hosts'          },
  { key:'networks',       icon:'&#127758;', title:'Networks'        },
  { key:'addr_ranges',    icon:'&#128208;', title:'Address Ranges'  },
  { key:'net_groups',     icon:'&#128193;', title:'Address Groups'  },
  { key:'services',       icon:'&#128268;', title:'Services'        },
  { key:'service_groups', icon:'&#128230;', title:'Service Groups'  },
];

// ═══ Drag & Drop ═════════════════════════════════════════
const dz = document.getElementById('drop-zone');
dz.addEventListener('dragover',  e => { e.preventDefault(); dz.classList.add('drag'); });
dz.addEventListener('dragleave', ()  => dz.classList.remove('drag'));
dz.addEventListener('drop', e => {
  e.preventDefault(); dz.classList.remove('drag');
  handleFile(e.dataTransfer.files[0]);
});

// ═══ Upload ══════════════════════════════════════════════
function handleFile(file) {
  if (!file || !file.name.endsWith('.xml')) {
    showToast('File must be .xml', '#ef4444'); return;
  }
  const fd = new FormData(); fd.append('file', file);
  document.getElementById('upload-section').style.display = 'none';
  document.getElementById('progress-section').style.display = 'block';
  animProg();

  fetch('/parse', { method:'POST', body:fd })
    .then(r => r.json())
    .then(d => {
      clearInterval(window._piv);
      document.getElementById('pbar').style.width = '100%';
      if (d.error) { showToast(d.error, '#ef4444'); resetApp(); return; }

      sheetsData = d.sheets;
      nameMap    = d.fo_objects.name_map || {};
      foObjects  = {};
      OBJ_ORDER.forEach(({ key }) => {
        foObjects[key] = Array.isArray(d.fo_objects[key]) ? d.fo_objects[key] : [];
      });

      renderStats(d.summary, d.root_info);
      renderSidebar(d.summary);
      renderObjGrid();
      renderNameMap();

      document.getElementById('progress-section').style.display = 'none';
      document.getElementById('results-section').style.display = 'block';
      document.getElementById('main-tabs').style.display = 'flex';
      document.getElementById('hdr-right').innerHTML =
        '<span style="font-family:var(--mono);font-size:11px;color:var(--grn)">&#10004; ' +
        Object.keys(sheetsData).length + ' sheets loaded</span>';
      openSheet(Object.keys(sheetsData)[0]);
    })
    .catch(e => { showToast('Error: ' + e, '#ef4444'); resetApp(); });
}

function animProg() {
  const bar = document.getElementById('pbar'), lbl = document.getElementById('plabel');
  const steps = ['reading xml...','parsing elements...','extracting objects...','sanitizing names...','building sheets...'];
  let w = 0, si = 0;
  window._piv = setInterval(() => {
    w = Math.min(w + Math.random() * 9, 88);
    bar.style.width = w + '%';
    if (si < steps.length) lbl.textContent = steps[si++];
  }, 350);
}

// ═══ Tabs ════════════════════════════════════════════════
function switchTab(t) {
  document.querySelectorAll('.tab').forEach((b, i) =>
    b.classList.toggle('active', ['viewer','pusher'][i] === t));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.getElementById('pane-' + t).classList.add('active');
}

// ═══ Viewer ══════════════════════════════════════════════
function renderStats(summary, ri) {
  const dc = summary.filter(s => s.is_direct).length;
  const nc = summary.filter(s => !s.is_direct).length;
  const tot = summary.reduce((a, s) => a + s.count, 0);
  document.getElementById('stats-bar').innerHTML =
    `<div class="stat-card"><div class="val">${summary.length}</div><div class="lbl">Element Types</div></div>
     <div class="stat-card"><div class="val" style="color:var(--grn)">${dc}</div><div class="lbl">Direct</div></div>
     <div class="stat-card"><div class="val" style="color:var(--mut)">${nc}</div><div class="lbl">Nested</div></div>
     <div class="stat-card"><div class="val" style="color:var(--org)">${tot.toLocaleString()}</div><div class="lbl">Total Records</div></div>
     <div class="stat-card"><div class="val" style="color:var(--acc2);font-size:13px">${ri.tag||'-'}</div><div class="lbl">Root Tag</div></div>`;
}

function renderSidebar(summary) {
  let html = '';
  ['00_ROOT','01_SUMMARY'].forEach(k =>
    html += `<div class="sheet-item" id="si-${k}" onclick="openSheet('${k}')">
      <span class="dot dot-s"></span><span>${k}</span></div>`);
  html += `<div style="height:1px;background:var(--bdr);margin:5px 0"></div>`;
  summary.filter(s => s.is_direct).forEach(s =>
    html += `<div class="sheet-item" id="si-${s.tag}" onclick="openSheet('${s.tag}')">
      <span class="dot dot-d"></span>
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${s.tag}</span>
      <span class="badge">${s.count}</span></div>`);
  if (summary.some(s => !s.is_direct)) {
    html += `<div style="padding:7px 9px 3px;font-size:9px;color:var(--mut);font-family:var(--mono);text-transform:uppercase;letter-spacing:1px">Nested</div>`;
    summary.filter(s => !s.is_direct).forEach(s =>
      html += `<div class="sheet-item" id="si-${s.tag}" onclick="openSheet('${s.tag}')">
        <span class="dot dot-n"></span>
        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${s.tag}</span>
        <span class="badge">${s.count}</span></div>`);
  }
  document.getElementById('sheet-list').innerHTML = html;
}

function openSheet(key) {
  curSheet = key; curPage = 1; sortCol = -1; sortDir = 1;
  document.getElementById('search-box').value = '';
  document.querySelectorAll('.sheet-item').forEach(e => e.classList.remove('active'));
  const si = document.getElementById('si-' + key);
  if (si) { si.classList.add('active'); si.scrollIntoView({ block:'nearest' }); }
  const sh = sheetsData[key];
  document.getElementById('table-title').textContent = key;
  document.getElementById('table-meta').textContent =
    `${sh.rows.length} records  \u00b7  ${(sh.columns||[]).length} columns`;
  filteredRows = [...sh.rows];
  document.getElementById('thead').innerHTML = '<tr>' +
    (sh.columns||['Property','Value']).map((c, i) =>
      `<th onclick="doSort(${i})" title="${c}"><span>&#8645;</span> ${c}</th>`).join('') + '</tr>';
  renderPage();
}

function renderPage() {
  const sh = sheetsData[curSheet], cols = sh.columns || ['Property','Value'];
  const tot = filteredRows.length, start = (curPage-1)*PAGE, end = Math.min(start+PAGE, tot);
  document.getElementById('tbody').innerHTML =
    filteredRows.slice(start, end).map(row =>
      '<tr>' + cols.map((_, ci) => {
        const v = String(row[ci] ?? '');
        return `<td class="${v.includes(' | ') ? 'mv' : ''}" title="${v}">${v}</td>`;
      }).join('') + '</tr>').join('') ||
    '<tr><td colspan="999" class="no-data">No data</td></tr>';
  const tp = Math.ceil(tot / PAGE);
  document.getElementById('pg-info').textContent = `${start+1}–${end} of ${tot.toLocaleString()} records`;
  document.getElementById('btn-prev').disabled = curPage <= 1;
  document.getElementById('btn-next').disabled = curPage >= tp;
  let nums = '';
  for (let p = Math.max(1, curPage-2); p <= Math.min(tp, curPage+2); p++)
    nums += `<button class="pg-btn ${p===curPage?'active':''}" onclick="gotoPage(${p})">${p}</button>`;
  document.getElementById('pg-nums').innerHTML = nums;
}

function changePage(d) { gotoPage(curPage + d); }
function gotoPage(p) {
  curPage = Math.max(1, Math.min(p, Math.ceil(filteredRows.length / PAGE)));
  renderPage();
}
function doSort(ci) {
  if (sortCol === ci) sortDir *= -1; else { sortCol = ci; sortDir = 1; }
  filteredRows.sort((a, b) => String(a[ci]??'').localeCompare(String(b[ci]??'')) * sortDir);
  curPage = 1; renderPage();
}
function filterTable() {
  const q = document.getElementById('search-box').value.toLowerCase();
  filteredRows = q
    ? sheetsData[curSheet].rows.filter(r => r.some(c => String(c??'').toLowerCase().includes(q)))
    : [...sheetsData[curSheet].rows];
  curPage = 1; renderPage();
}

// ═══ Downloads ═══════════════════════════════════════════
function downloadCurrentCSV() {
  if (!curSheet) return;
  const sh = sheetsData[curSheet], cols = sh.columns || ['Property','Value'];
  let csv = cols.join(',') + '\n';
  sh.rows.forEach(row =>
    csv += cols.map((_, i) => '"' + String(row[i]??'').replace(/"/g,'""') + '"').join(',') + '\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type:'text/csv;charset=utf-8;' }));
  a.download = curSheet + '.csv'; a.click();
  showToast('CSV exported');
}
function downloadAllZip() {
  showToast('Preparing ZIP...');
  fetch('/download_all', { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ sheets: sheetsData }) })
  .then(r => r.blob()).then(blob => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'forcepoint_export.zip'; a.click();
    showToast('ZIP downloaded');
  });
}
function resetApp() {
  sheetsData = {}; foObjects = {}; nameMap = {}; curSheet = null; pushReport = null;
  ['results-section','progress-section'].forEach(
    id => document.getElementById(id).style.display = 'none');
  document.getElementById('upload-section').style.display = 'block';
  document.getElementById('main-tabs').style.display = 'none';
  document.getElementById('hdr-right').innerHTML = '';
  document.getElementById('file-input').value = '';
  doDisconnect(true);
}

// ═══ Name Map ════════════════════════════════════════════
function renderNameMap() {
  const entries = Object.entries(nameMap);
  const wrap = document.getElementById('nm-box-wrap');
  if (!entries.length) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'block';
  document.getElementById('nm-rows').innerHTML = entries.map(([orig, safe]) =>
    `<div class="nm-row">
      <span class="nm-orig" title="${orig}">${orig}</span>
      <span class="nm-arr">&#8594;</span>
      <span class="nm-new">${safe}</span>
    </div>`).join('');
}

// ═══ Obj Grid ════════════════════════════════════════════
function renderObjGrid() {
  document.getElementById('obj-grid').innerHTML = OBJ_ORDER.map(({ key, icon, title }) => {
    const count = (foObjects[key] || []).length;
    return `<div class="obj-card sel" id="oc-${key}" onclick="toggleObj('${key}')">
      <div class="ochk" id="ok-${key}">&#10003;</div>
      <div class="oicon">${icon}</div>
      <div class="otitle">${title}</div>
      <div class="ocount">${count} objects</div>
    </div>`;
  }).join('');
  updatePushNote();
}
function toggleObj(k) {
  document.getElementById('oc-' + k).classList.toggle('sel');
  document.getElementById('ok-' + k).innerHTML =
    document.getElementById('oc-' + k).classList.contains('sel') ? '&#10003;' : '';
  updatePushNote();
}
function selectedObjs() {
  return OBJ_ORDER.filter(({ key }) => document.getElementById('oc-' + key)?.classList.contains('sel'));
}
function updatePushNote() {
  const sel = selectedObjs();
  const tot = sel.reduce((a, { key }) => a + (foObjects[key] || []).length, 0);
  document.getElementById('push-note').textContent =
    sel.length ? `${tot} objects will be pushed` : 'Select at least one category';
}

// ═══ Connect ═════════════════════════════════════════════
function doConnect() {
  const host  = document.getElementById('fg-host').value.trim();
  const port  = document.getElementById('fg-port').value || '80';
  const token = document.getElementById('fg-token').value.trim();
  if (!host || !token) { showToast('Enter Host and Token', '#ef4444'); return; }
  const btn = document.getElementById('btn-connect');
  const st  = document.getElementById('conn-status');
  btn.disabled = true; btn.innerHTML = '&#9203; Connecting...'; st.textContent = '';

  fetch('/fg_connect', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ host, port, token })
  }).then(r => r.json()).then(d => {
    btn.disabled = false; btn.innerHTML = '&#128279; Test &amp; Connect';
    if (d.error) {
      st.style.color = 'var(--red)'; st.textContent = 'Error: ' + d.error;
      showToast('Connection failed', '#ef4444'); return;
    }
    document.getElementById('conn-label').textContent =
      `Connected to ${host}:${port}  |  ${d.version || 'FortiGate OK'}`;
    document.getElementById('step-login').style.display   = 'none';
    document.getElementById('step-objects').style.display = 'block';
    showToast('Connected successfully');
  }).catch(e => {
    btn.disabled = false; btn.innerHTML = '&#128279; Test &amp; Connect';
    showToast('Error: ' + e, '#ef4444');
  });
}
function doDisconnect(silent) {
  fetch('/fg_disconnect', { method:'POST' });
  document.getElementById('step-login').style.display   = 'block';
  document.getElementById('step-objects').style.display = 'none';
  document.getElementById('log-wrap').style.display     = 'none';
  document.getElementById('push-log').innerHTML         = '';
  document.getElementById('btn-connect').disabled       = false;
  document.getElementById('btn-connect').innerHTML      = '&#128279; Test &amp; Connect';
  document.getElementById('conn-status').textContent    = '';
  if (!silent) showToast('Disconnected');
}

// ═══ Push ════════════════════════════════════════════════
async function doPush() {
  const sel = selectedObjs();
  if (!sel.length) { showToast('Select at least one category', '#ef4444'); return; }

  const btn = document.getElementById('btn-push');
  btn.disabled = true; btn.innerHTML = '&#9203; Pushing...';
  document.getElementById('log-wrap').style.display = 'block';
  document.getElementById('push-log').innerHTML = '';

  // report data structure
  pushReport = {
    timestamp: new Date().toLocaleString(),
    categories: []
  };

  let totalOk = 0, totalErr = 0, totalSk = 0;

  for (const { key, title } of sel) {
    const items = foObjects[key] || [];
    if (!items.length) continue;
    addLogSec(`${title}  (${items.length} objects)`);

    const res  = await fetch('/fg_push', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ obj_type: key, items })
    });
    const d = await res.json();

    const catData = { key, title, results: [] };

    if (d.error) {
      addLogRow('ERR', title, '', d.error, 'er');
      catData.results.push({ status:'err', name:title, orig:'', reason: d.error });
      totalErr++;
    } else {
      for (const r of (d.results || [])) {
        catData.results.push(r);
        if      (r.status === 'ok')   { addLogRow('OK',   r.name, r.orig, `HTTP ${r.code}`, 'ok'); totalOk++;  }
        else if (r.status === 'skip') { addLogRow('SKIP', r.name, r.orig, r.msg,            'sk'); totalSk++;  }
        else                          { addLogRow('ERR',  r.name, r.orig, r.msg,            'er'); totalErr++; }
      }
    }
    pushReport.categories.push(catData);
  }

  pushReport.totalOk  = totalOk;
  pushReport.totalErr = totalErr;
  pushReport.totalSk  = totalSk;
  pushReport.total    = totalOk + totalErr + totalSk;

  btn.disabled = false; btn.innerHTML = '&#128640; Start Push';
  document.getElementById('log-summary').textContent =
    `${totalOk} OK  |  ${totalSk} Skipped  |  ${totalErr} Errors`;

  showToast(`Push complete: ${totalOk} OK  ${totalErr} errors`);

  // auto open report
  setTimeout(() => openReport(), 800);
}

function addLogSec(title) {
  const d = document.createElement('div');
  d.style.cssText = 'color:var(--acc);font-weight:700;padding:8px 12px 4px;background:rgba(0,200,240,.04);font-size:11px;border-bottom:1px solid var(--bdr)';
  d.textContent = '-- ' + title + ' --';
  document.getElementById('push-log').appendChild(d);
  const l = document.getElementById('push-log'); l.scrollTop = l.scrollHeight;
}
function addLogRow(status, name, orig, code, type) {
  const d = document.createElement('div'); d.className = 'lr';
  const note = (orig && orig !== name)
    ? ` <span style="color:var(--org);font-size:9px">(was: ${orig})</span>` : '';
  d.innerHTML = `<span class="ls ${type}">${status}</span><span class="ln">${name}${note}</span><span class="lc">${code||''}</span>`;
  document.getElementById('push-log').appendChild(d);
  const l = document.getElementById('push-log'); l.scrollTop = l.scrollHeight;
}

// ═══ Report ══════════════════════════════════════════════
let rptFilter = null;   // null = all, 'ok' | 'skip' | 'err'

const RPT_ICONS = {
  hosts:'&#128187;', networks:'&#127758;', net_groups:'&#128193;',
  addr_ranges:'&#128208;', services:'&#128268;', service_groups:'&#128230;'
};

function openReport() {
  if (!pushReport) return;
  rptFilter = null;
  renderReport();
  document.getElementById('rpt-overlay').style.display = 'flex';
}

function setFilter(f) {
  rptFilter = f;
  renderReport();
}

function renderReport() {
  const r = pushReport;

  // Summary cards — clickable, highlight active filter
  document.getElementById('rpt-timestamp').textContent = r.timestamp;
  const cards = [
    { cls:'total', val:r.total,    lbl:'Total',      f:null  },
    { cls:'ok',    val:r.totalOk,  lbl:'Successful', f:'ok'  },
    { cls:'skip',  val:r.totalSk,  lbl:'Skipped',    f:'skip'},
    { cls:'err',   val:r.totalErr, lbl:'Failed',     f:'err' },
  ];
  document.getElementById('rpt-summary').innerHTML = cards.map(c => {
    const active = rptFilter === c.f;
    const cursor = 'cursor:pointer;transition:all .2s;';
    const ring   = active ? 'box-shadow:0 0 0 2px var(--acc);transform:scale(1.04);' : '';
    return `<div class="rpt-card ${c.cls}" style="${cursor}${ring}" onclick="setFilter(${c.f===null?'null':'"'+c.f+'"'})">
      <div class="rv">${c.val}</div>
      <div class="rl">${c.lbl}${c.f&&c.val?'  &#128269;':''}</div>
    </div>`;
  }).join('');

  // Filter bar
  const filterBar = document.getElementById('rpt-filter-bar');
  const filterLbl = document.getElementById('rpt-filter-label');
  const btnExportF = document.getElementById('btn-export-filtered');
  if (rptFilter) {
    filterBar.style.display = 'flex';
    const map = {ok:'&#9989; Successful only', skip:'&#9888; Skipped only', err:'&#10060; Failed only'};
    filterLbl.innerHTML = map[rptFilter] || '';
    btnExportF.style.display = '';
  } else {
    filterBar.style.display = 'none';
    btnExportF.style.display = 'none';
  }

  // Category sections
  document.getElementById('rpt-sections').innerHTML = r.categories.map((cat, idx) => {
    const filtered = rptFilter
      ? cat.results.filter(x => x.status === rptFilter)
      : cat.results;

    // If filter active and no matching rows in this cat — hide section
    if (rptFilter && filtered.length === 0) return '';

    const ok  = cat.results.filter(x => x.status === 'ok').length;
    const sk  = cat.results.filter(x => x.status === 'skip').length;
    const err = cat.results.filter(x => x.status === 'err').length;

    const rows = filtered.map(item => {
      const badge = item.status === 'ok'
        ? '<span class="badge-ok">OK</span>'
        : item.status === 'skip'
          ? '<span class="badge-sk">SKIP</span>'
          : '<span class="badge-er">ERR</span>';
      const nameChanged = (item.orig && item.orig !== item.name)
        ? `<br><span class="name-changed">renamed from: ${item.orig}</span>` : '';
      const reason = item.status !== 'ok'
        ? `<span style="color:var(--mut);word-break:break-all">${item.msg || item.reason || ''}</span>` : '';
      return `<tr>
        <td>${badge}</td>
        <td>${item.name}${nameChanged}</td>
        <td style="color:var(--mut)">${item.status === 'ok' ? 'HTTP '+(item.code||200) : ''}</td>
        <td>${reason}</td>
      </tr>`;
    }).join('');

    const rowCount = rptFilter ? `${filtered.length} shown` : '';

    return `<div class="rpt-section">
      <div class="rpt-sec-hdr" onclick="toggleSection(${idx})">
        <span class="rpt-sec-icon">${RPT_ICONS[cat.key]||'&#128230;'}</span>
        <span class="rpt-sec-title">${cat.title}</span>
        <div class="rpt-sec-chips">
          ${ok  ? `<span class="chip chip-ok" style="cursor:pointer" onclick="event.stopPropagation();setFilter('ok')">${ok} OK</span>`    : ''}
          ${sk  ? `<span class="chip chip-sk" style="cursor:pointer" onclick="event.stopPropagation();setFilter('skip')">${sk} skip</span>` : ''}
          ${err ? `<span class="chip chip-er" style="cursor:pointer" onclick="event.stopPropagation();setFilter('err')">${err} err</span>`  : ''}
          ${rowCount ? `<span style="font-family:var(--mono);font-size:9px;color:var(--acc)">${rowCount}</span>` : ''}
        </div>
        <span class="rpt-sec-toggle" id="rpt-tog-${idx}">&#9660;</span>
      </div>
      <div class="rpt-sec-body" id="rpt-body-${idx}">
        <table class="rpt-tbl">
          <thead><tr>
            <th style="width:72px">Status</th>
            <th>Name</th>
            <th style="width:90px">HTTP</th>
            <th>Reason / Error</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  }).join('');
}

function toggleSection(idx) {
  const body = document.getElementById('rpt-body-' + idx);
  const tog  = document.getElementById('rpt-tog-' + idx);
  if (!body) return;
  const hidden = body.style.display === 'none';
  body.style.display = hidden ? '' : 'none';
  tog.innerHTML = hidden ? '&#9660;' : '&#9654;';
}

function closeReport(e) {
  if (!e || e.target === document.getElementById('rpt-overlay'))
    document.getElementById('rpt-overlay').style.display = 'none';
}

function exportReportCSV(mode) {
  if (!pushReport) return;
  let csv = 'Category,Name,Original Name,Status,HTTP Code,Reason\n';
  for (const cat of pushReport.categories) {
    const items = (mode === 'filtered' && rptFilter)
      ? cat.results.filter(x => x.status === rptFilter)
      : cat.results;
    for (const item of items) {
      csv += [
        cat.title,
        '"' + (item.name||'').replace(/"/g,'""') + '"',
        '"' + (item.orig||'').replace(/"/g,'""') + '"',
        item.status,
        item.code || '',
        '"' + (item.msg || item.reason || '').replace(/"/g,'""') + '"'
      ].join(',') + '\n';
    }
  }
  const suffix = (mode === 'filtered' && rptFilter) ? `_${rptFilter}_only` : '';
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type:'text/csv;charset=utf-8;' }));
  a.download = 'push_report' + suffix + '_' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.csv';
  a.click();
  showToast('Report CSV exported');
}

// ═══ Toast ═══════════════════════════════════════════════
function showToast(msg, color) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.style.background = color || 'var(--grn)';
  t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 3200);
}
</script>
</body>
</html>"""



# ═══════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════
@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/parse', methods=['POST'])
def parse():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if not f.filename.endswith('.xml'):
        return jsonify({'error': 'File must be .xml'}), 400
    try:
        content = f.read()
        root_info, summary, sheets = parse_xml(content)
        fo_objects = extract_objects(content)
        sheets_json = {}
        for key, sheet in sheets.items():
            sheets_json[key] = {
                'columns':   sheet.get('columns', ['Property','Value']),
                'rows':      sheet.get('rows', []),
                'is_direct': sheet.get('is_direct', False),
                'count':     sheet.get('count', 0)
            }
        return jsonify({'root_info': root_info, 'summary': summary,
                        'sheets': sheets_json, 'fo_objects': fo_objects})
    except ET.ParseError as e:
        return jsonify({'error': f'Invalid XML: {e}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/fg_connect', methods=['POST'])
def fg_connect():
    global _fg
    d = request.get_json()
    try:
        client = FGClient(host=d['host'], token=d['token'], port=d.get('port', 80))
        code, resp = client.test()
        if code != 200:
            return jsonify({'error': f'HTTP {code}: {str(resp)[:200]}'}), 400
        _fg = client
        version = ''
        if isinstance(resp, dict):
            res = resp.get('results', {})
            version = res.get('Version','') or res.get('version','')
        return jsonify({'ok': True, 'version': version})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/fg_disconnect', methods=['POST'])
def fg_disconnect():
    global _fg
    _fg = None
    return jsonify({'ok': True})


@app.route('/fg_push', methods=['POST'])
def fg_push():
    global _fg
    if not _fg:
        return jsonify({'error': 'Not connected to FortiGate'}), 400
    d        = request.get_json()
    obj_type = d.get('obj_type', '')
    items    = d.get('items', [])
    results  = []

    ep = EP.get(obj_type)
    if not ep:
        return jsonify({'error': f'Unknown obj_type: {obj_type}'}), 400

    try:
        existing = _fg.get_existing(ep)
        for item in items:
            name = item.get('name','').strip()
            orig = item.get('orig_name', name)
            if not name:
                results.append({'status':'skip','name':'','orig':'','msg':'Empty name'})
                continue
            try:
                if obj_type in ('hosts','networks','addr_ranges'):
                    payload = {'name': name, 'comment': item.get('comment','')[:255]}
                    if item.get('type') == 'ipmask':
                        payload['type']   = 'ipmask'
                        payload['subnet'] = item['subnet']
                    elif item.get('type') == 'iprange':
                        payload['type']     = 'iprange'
                        payload['start-ip'] = item['start-ip']
                        payload['end-ip']   = item['end-ip']

                elif obj_type == 'net_groups':
                    members = [{'name': m} for m in item.get('member', [])]
                    payload = {'name': name, 'member': members}
                    # report skipped built-in refs
                    for ref in item.get('skipped_refs', []):
                        results.append({'status':'skip','name':ref,'orig':ref,
                                        'msg':f'Not in XML (Forcepoint built-in) — skipped from group {name}'})

                elif obj_type == 'services':
                    payload = {'name': name, 'protocol': item['protocol'],
                               'comment': item.get('comment','')[:255]}
                    if item['protocol'] == 'TCP':
                        payload['tcp-portrange'] = item.get('tcp-portrange','')
                    else:
                        payload['udp-portrange'] = item.get('udp-portrange','')

                elif obj_type == 'service_groups':
                    members = [{'name': m} for m in item.get('member', [])]
                    payload = {'name': name, 'member': members}
                    # report skipped built-in refs
                    for ref in item.get('skipped_refs', []):
                        results.append({'status':'skip','name':ref,'orig':ref,
                                        'msg':f'Not in XML (Forcepoint built-in) — skipped from group {name}'})

                else:
                    results.append({'status':'skip','name':name,'orig':orig,'msg':'Unknown type'})
                    continue

                code, txt = _fg.upsert(ep, name, payload, existing)
                if code in (200, 201, 204):
                    results.append({'status':'ok','name':name,'orig':orig,'code':code})
                    existing.add(name)
                else:
                    results.append({'status':'err','name':name,'orig':orig,
                                    'msg':f'HTTP {code}: {txt[:150]}'})
            except Exception as e:
                results.append({'status':'err','name':name,'orig':orig,'msg':str(e)[:150]})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'results': results})


@app.route('/download_all', methods=['POST'])
def download_all():
    d      = request.get_json()
    sheets = d.get('sheets', {})
    buf    = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, sheet in sheets.items():
            cols = sheet.get('columns', ['Property','Value'])
            rows = sheet.get('rows', [])
            sb   = io.StringIO()
            w    = csv.writer(sb)
            w.writerow(cols)
            for row in rows:
                w.writerow([str(c) if c is not None else '' for c in row])
            zf.writestr(f"{name}.csv", sb.getvalue())
    buf.seek(0)
    return send_file(buf, mimetype='application/zip', as_attachment=True,
                     download_name='forcepoint_export.zip')


if __name__ == '__main__':
    print("\n" + "="*52)
    print("  Forcepoint XML Parser + FortiGate Pusher")
    print("  http://localhost:5000")
    print("  pip install flask requests urllib3")
    print("="*52 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
