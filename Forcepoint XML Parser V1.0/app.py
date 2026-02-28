"""
Forcepoint XML Parser
pip install flask
python app.py  ->  http://localhost:5000
"""

from flask import Flask, request, jsonify, send_file, render_template_string
import xml.etree.ElementTree as ET
import csv, io, zipfile, re, ipaddress
from collections import defaultdict

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
        Return the correct name for a reference:
        If ref exists in our XML → return its sanitized name
        Otherwise → return None (unknown, will be skipped)
        """
        if ref in xml_names:
            return _name_map.get(ref, ref)
        return None

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
# HTML
# ═══════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Forcepoint XML Parser</title>
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


/* Toast */
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--grn);
  color:#fff;padding:10px 20px;border-radius:8px;font-weight:700;font-size:12px;
  opacity:0;transition:opacity .3s;z-index:200;pointer-events:none;white-space:nowrap}
.toast.show{opacity:1}

@media(max-width:860px){
  .main-layout{grid-template-columns:1fr}
  .sidebar{position:relative;max-height:240px}
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
    <h1>Forcepoint XML Parser</h1>
    <p>xml structure viewer &amp; object extractor</p>
  </div>
  <div id="hdr-right"></div>
</header>


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

<!-- Results -->
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


</div><!-- /wrap -->

<div class="toast" id="toast"></div>

<script>
// ═══ State ═══════════════════════════════════════════════
let sheetsData = {}, foObjects = {}, nameMap = {};
let curSheet = null, curPage = 1, filteredRows = [], sortCol = -1, sortDir = 1;
const PAGE = 100;

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

      document.getElementById('progress-section').style.display = 'none';
      document.getElementById('results-section').style.display = 'block';
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
  sheetsData = {}; foObjects = {}; nameMap = {}; curSheet = null;
  ['results-section','progress-section'].forEach(
    id => document.getElementById(id).style.display = 'none');
  document.getElementById('upload-section').style.display = 'block';
  document.getElementById('hdr-right').innerHTML = '';
  document.getElementById('file-input').value = '';
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
    print("  Forcepoint XML Parser")
    print("  http://localhost:5000")
    print("  pip install flask")
    print("="*52 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)