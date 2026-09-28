"""Dependency-free admin UI: theme tokens, unified accounts and real metrics."""
import html
import json
import math
import re
import time
from urllib.parse import urlencode, urlsplit, parse_qs

VERSION = '2.4.2'
# ─── Chimera: full fingerprint list (mirrors XRAY_FP_LIST in fingerprint_manager.py) ───
# Single source of truth for the <select> in nodes_ui().
FINGERPRINTS = [
    ('chrome', 'Google Chrome (по умолчанию)'),
    ('firefox', 'Mozilla Firefox'),
    ('safari', 'Apple Safari (desktop)'),
    ('ios', 'Safari iOS / iPadOS'),
    ('android', 'Android / okhttp'),
    ('edge', 'Microsoft Edge'),
    ('360', '360 Browser (Qihoo)'),
    ('qq', 'QQ Browser (Tencent)'),
    ('random', 'случайный браузер (⚠️ несовместим с REALITY)'),
    ('randomized', 'рандом каждый handshake (⚠️ несовместим с REALITY)'),
    ('none', 'стандартный Go TLS (не uTLS)'),
]


def fingerprint_options(selected='chrome'):
    """Generate <option> tags for the fingerprint <select> in cascade node form."""
    return ''.join(
        f'<option value="{esc(fp)}" {"selected" if fp == selected else ""}>{esc(fp)} — {esc(desc)}</option>'
        for fp, desc in FINGERPRINTS
    )



def esc(value): return html.escape(str(value), quote=True)


def size(value):
    if value is None: return '—'
    value = max(0, float(value))
    for unit in ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ'):
        if value < 1024 or unit == 'ТБ': return ('%.0f' if unit == 'Б' else '%.1f') % value + ' ' + unit
        value /= 1024


def duration(value):
    if value is None: return '—'
    value = max(0, int(value))
    return f'{value//86400} д. {value%86400//3600} ч.' if value >= 86400 else f'{value//3600} ч. {value%3600//60} мин.'


def _hour_label(h):
    """'07' → '07:00' style label for hour 0..23."""
    return f"{h:02d}:00"


def _render_hourly_pattern(pattern):
    """Render Variant B — 24-bar chart of avg traffic per hour-of-day."""
    if not pattern or not pattern.get('buckets'):
        return '<div class="hourly-empty">Нет данных за последние 7 дней.</div>'
    buckets = pattern['buckets']
    max_total = max(1, pattern.get('max_avg_total', 0))
    days_observed = pattern.get('days_observed', 0)
    tz_label = pattern.get('tz', 'UTC')
    bars = []
    for b in buckets:
        h = b.get('hour', 0)
        up = max(0, int(b.get('up', 0)))
        down = max(0, int(b.get('down', 0)))
        total = up + down
        bar_h = (total / max_total) * 100 if total > 0 else 0.5  # min 0.5% for visibility
        # inside-bar up/down split
        up_pct = (up / total * 100) if total > 0 else 0
        down_pct = 100 - up_pct
        title = f"{_hour_label(h)} — ↑ {size(up)} · ↓ {size(down)} · avg of {b.get('days',0)} days"
        bars.append(
            f'<div class="hourly-bar" style="height:{bar_h:.2f}%" title="{esc(title)}">'
            f'<div class="hourly-seg down" style="height:{down_pct:.1f}%"></div>'
            f'<div class="hourly-seg up" style="height:{up_pct:.1f}%"></div>'
            f'</div>'
        )
    axis = ''.join(f'<span>{h:02d}</span>' for h in range(24))
    return (
        f'<div class="hourly-chart">{"".join(bars)}</div>'
        f'<div class="hourly-axis">{axis}</div>'
        f'<div class="hourly-legend">'
        f'<span><i class="up"></i>↑ Отправка</span>'
        f'<span><i class="down"></i>↓ Получение</span>'
        f'<span class="muted">Среднее за {days_observed} дн. · TZ {esc(tz_label)}</span>'
        f'</div>'
    )


def _render_hourly_heatmap(heatmap):
    """Render Variant C — 7×24 calendar heatmap (Mon..Sun × 00..23)."""
    if not heatmap or not heatmap.get('rows'):
        return '<div class="hourly-empty">Нет данных за последние 7 дней.</div>'
    rows = heatmap['rows']
    max_total = max(1, heatmap.get('max_total', 0))
    days_observed = heatmap.get('days_observed', 0)
    tz_label = heatmap.get('tz', 'UTC')
    # Header row with hour labels (skip the first cell which is the corner)
    header = '<div class="heatmap-corner"></div>' + ''.join(
        f'<div class="heatmap-hour-label">{h:02d}</div>' for h in range(24)
    )
    body_rows = []
    for row in rows:
        name = row.get('name', '')
        cells = []
        for cell in row.get('cells', []):
            h = cell.get('hour', 0)
            up = max(0, int(cell.get('up', 0)))
            down = max(0, int(cell.get('down', 0)))
            total = up + down
            # 5 intensity levels: 0 (empty) / 1 (low) / 2 (mid) / 3 (high) / 4 (max)
            if total == 0:
                level = 0
            else:
                ratio = total / max_total
                if ratio < 0.05:
                    level = 0
                elif ratio < 0.25:
                    level = 1
                elif ratio < 0.50:
                    level = 2
                elif ratio < 0.75:
                    level = 3
                else:
                    level = 4
            title = f"{name} {_hour_label(h)} — ↑ {size(up)} · ↓ {size(down)}"
            cells.append(
                f'<div class="heatmap-cell" data-level="{level}" title="{esc(title)}"></div>'
            )
        body_rows.append(
            f'<div class="heatmap-row">'
            f'<div class="heatmap-row-label">{esc(name)}</div>'
            f'{"".join(cells)}'
            f'</div>'
        )
    return (
        f'<div class="heatmap-grid">{header}{"".join(body_rows)}</div>'
        f'<div class="hourly-legend">'
        f'<span class="muted">Меньше</span>'
        f'<span class="heatmap-scale"><i data-level="0"></i><i data-level="1"></i><i data-level="2"></i><i data-level="3"></i><i data-level="4"></i></span>'
        f'<span class="muted">Больше · {days_observed} дн. · TZ {esc(tz_label)}</span>'
        f'</div>'
    )


def icon(name):
    paths = {'grid': '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
             'users': '<circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3M17 4a3 3 0 0 1 0 6m1 4a5 5 0 0 1 3 4v3"/>',
             'settings': '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="8" cy="18" r="2"/>',
             'nodes': '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/>',
             'logout': '<path d="M10 4H4v16h6m4-12 4 4-4 4m-6-4h10"/>',
             'sun': '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1 1m12 12 1 1M5 19l1-1M18 6l1-1"/>',
             'refresh': '<path d="M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 14 6M4 12a8 8 0 0 0 14 6"/>',
             'chart': '<path d="M3 3v18h18M6 15l4-5 4 3 6-8"/>',
             'link': '<path d="m10 13 4-4m-6 5-2 2a3 3 0 0 0 4 4l3-3m-2-10 3-3a3 3 0 0 1 4 4l-2 2"/>',
             'copy':'<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V4H4v12h4"/>',
             'edit':'<path d="m15 4 5 5M4 20l5-1L20 8a2 2 0 0 0-5-5L4 14z"/>',
             'qr':'<path d="M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h2v2h-2zM21 15v6h-6"/>',
             'trash':'<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
             'search':'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
             'github': '<path d="M9 21v-3c-4 1-4-2-6-2m12 5v-4c0-1-.4-1.7-1-2 3-.4 5-1.5 5-5a4 4 0 0 0-1-3c.3-1 0-3 0-3-2 0-3 1-3 1a11 11 0 0 0-6 0S8 4 6 4c0 0-.3 2 0 3a4 4 0 0 0-1 3c0 3.5 2 4.6 5 5-.6.3-1 1-1 2"/>',
             'youtube': '<rect x="2" y="5" width="20" height="14" rx="4"/><path d="m10 9 5 3-5 3z"/>'}
    return '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+paths.get(name, paths['grid'])+'</svg>'


CSS = '''
:root{color-scheme:dark;--bg:#071116;--surface:#0f2028;--raised:#152b35;--input:#0a1920;--line:#24404b;--text:#e9f4f6;--muted:#91aeb8;--accent:#56decb;--on-accent:#052820;--tint:#56decb12;--green:#8bdbaa;--red:#ff9993;--amber:#f5c989;--shadow:0 18px 60px #0003}
:root[data-theme=light]{color-scheme:light;--bg:#eaf0ed;--surface:#fbfdfb;--raised:#eff5f1;--input:#f5f8f5;--line:#cfddd5;--text:#142f2b;--muted:#5d7870;--accent:#087c6d;--on-accent:#fff;--tint:#087c6d0c;--green:#27754b;--red:#b94042;--amber:#886124;--shadow:0 18px 50px #153b2310}
*{box-sizing:border-box}body{margin:0;min-width:320px;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,sans-serif}button,input,select,textarea{font:inherit}button,input,select,textarea,a,summary{outline-offset:4px}a{color:var(--accent)}button{cursor:pointer}button:disabled{opacity:.45;cursor:not-allowed}h1,h2,h3,p{overflow-wrap:anywhere}h1{font-size:34px;line-height:1.15;letter-spacing:-.055em;margin:0;font-weight:650}h2{font-size:17px;margin:0;font-weight:600;letter-spacing:-.02em}h3{font-size:15px;margin:0}p{margin:8px 0 16px}.muted,small,.sub{color:var(--muted)}.ico{width:18px;height:18px;flex:0 0 auto}.eyebrow{display:block;font:10px/1.5 ui-monospace,monospace;letter-spacing:.18em;color:var(--accent);text-transform:uppercase;margin-bottom:9px}
.app{height:100dvh;padding:14px;display:grid;grid-template-columns:218px minmax(0,1fr);gap:14px}.sidebar{display:flex;flex-direction:column;min-height:0;overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:22px;padding:22px 14px}.brand{display:flex;gap:11px;align-items:center;padding:0 6px 20px}.brand img{width:42px;height:42px;border-radius:13px}.brand b{font-size:12px;letter-spacing:.035em}.brand small{display:block;font:10px/1.7 ui-monospace,monospace;margin-top:3px}.brand-tools{padding:0 6px 25px;display:flex;gap:8px}.brand-tools button{width:100%;justify-content:flex-start;font-size:11px;background:transparent}.nav{display:grid;gap:8px}.nav a,.logout{display:flex;align-items:center;gap:12px;padding:13px 14px;border:1px solid transparent;border-radius:12px;color:var(--muted);text-decoration:none;font-size:13px;font-weight:550}.nav a.active{background:var(--accent);color:var(--on-accent)}.nav a:hover:not(.active),.logout:hover{background:var(--raised);color:var(--text)}.side-footer{margin-top:auto;padding-top:32px}.logout{color:var(--muted)}.social{display:flex;justify-content:center;gap:16px;padding-top:21px;border-top:1px solid var(--line);margin-top:14px}.social a{display:flex;align-items:center;gap:5px;color:var(--muted);font-size:10px;text-decoration:none}.social .ico{width:14px;height:14px}.workspace{min-width:0;overflow:auto;scrollbar-width:thin;scrollbar-color:var(--line) transparent}main{max-width:1560px;margin:0 auto;padding:24px 24px 44px}.page-head{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:26px}.page-head p{font-size:13px;color:var(--muted);margin:8px 0 0}.card,.account{min-width:0;background:var(--surface);border:1px solid var(--line);border-radius:18px}.card{padding:23px;margin-bottom:18px}.card-title{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:20px}.card-title h2{display:flex;align-items:center;gap:8px}.btn,button{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 14px;border:1px solid var(--line);background:var(--raised);color:var(--text);border-radius:10px;text-decoration:none;font-size:12px;font-weight:550;line-height:1.4}.btn:hover,button:hover{border-color:var(--accent)}.btn.primary,button.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}button.danger,.btn.danger{background:transparent;color:var(--red)}button.quiet,.btn.quiet{background:transparent}.actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.actions form{margin:0}.note{margin:15px 0;padding:12px 15px;border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:9px;background:var(--tint);font-size:12px;color:var(--muted);overflow-wrap:anywhere}.note.warning{border-left-color:var(--amber);color:var(--amber)}.note code{font-size:11px;overflow-wrap:anywhere}input,textarea,select{width:100%;min-width:0;border:1px solid var(--line);background:var(--input);color:var(--text);padding:11px 13px;border-radius:10px}input:focus,textarea:focus,select:focus{border-color:var(--accent)}input[type=checkbox]{width:16px;height:16px;accent-color:var(--accent);cursor:pointer}label{display:block;font-size:12px;font-weight:550;color:var(--muted);margin:13px 0 7px}.checks{display:flex;gap:18px;flex-wrap:wrap;margin:18px 0}.check{display:flex;align-items:center;gap:8px;margin:0;color:var(--text)}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;white-space:nowrap;color:var(--muted)}.badge:before{content:"";width:5px;height:5px;border-radius:50%;background:var(--muted)}.badge.on{color:var(--green)}.badge.on:before{background:var(--green)}.pill{display:inline-flex;align-items:center;padding:3px 7px;border-radius:6px;border:1px solid var(--line);font-size:10px;line-height:1.5;color:var(--muted)}.pills{display:flex;flex-wrap:wrap;gap:5px}.proto-vless{color:var(--accent);background:var(--tint)}.proto-hysteria{color:var(--amber)}.proto-web{color:var(--green)}
.overview-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:22px}.overview-stat{padding:17px 19px;border-left:2px solid var(--line)}.overview-stat:first-child{border-color:var(--accent)}.overview-stat span{display:block;font-size:11px;color:var(--muted)}.overview-stat b{display:block;font:500 29px/1.3 ui-monospace,monospace;letter-spacing:-.07em;margin-top:5px}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.8fr) minmax(280px,1fr);gap:18px}.graph-card{background:linear-gradient(145deg,var(--surface),var(--input));border-top:2px solid var(--accent)}.graph-speeds{display:flex;gap:38px;margin:26px 0 0}.graph-speeds span{font-size:11px;color:var(--muted);display:block}.graph-speeds b{font:500 25px/1.8 ui-monospace,monospace;letter-spacing:-.05em}.graph-speeds small{font-size:11px;color:var(--muted)}.chart-wrap{height:250px;margin:6px 0 15px}.chart-wrap svg{display:block;width:100%;height:100%;overflow:visible}.chart-wrap text{fill:var(--muted);font:10px ui-monospace,monospace}.chart-empty{height:100%;display:flex;flex-direction:column;gap:12px;align-items:center;justify-content:center;text-align:center;color:var(--muted);font-size:12px}.chart-empty .ico{width:34px;height:34px;opacity:.6}.range{display:flex;gap:3px;padding:3px;border:1px solid var(--line);border-radius:9px}.range button{border:0;background:transparent;font-size:11px;padding:5px 9px}.range button.selected{background:var(--tint);color:var(--accent)}.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:10px;color:var(--muted)}.legend i{display:inline-block;width:7px;height:7px;border-radius:3px;background:var(--accent);margin-right:6px}.legend .down i{background:var(--amber)}.service-list{display:grid}.service-line{display:flex;justify-content:space-between;align-items:center;gap:8px;border-bottom:1px solid var(--line);padding:15px 0;font-size:12px}.service-line:last-child{border-bottom:0}.node-domain{font-size:15px;font-weight:550;overflow-wrap:anywhere;margin-bottom:8px}.node-label{display:flex;align-items:center;gap:8px}.node-label i{display:block;width:8px;height:8px;border:2px solid var(--accent);border-radius:50%}.update-box{border-top:1px dashed var(--line);padding-top:20px;margin-top:20px}.update-box p{font-size:11px;color:var(--muted);margin:10px 0 0}.resource-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px}.resource{padding:19px;background:var(--surface);border:1px solid var(--line);border-radius:15px}.resource-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}.resource strong{font-size:12px;font-weight:550}.resource-head b{font:500 20px ui-monospace,monospace;color:var(--accent)}.meter{height:4px;background:var(--line);border-radius:4px;overflow:hidden;margin-bottom:12px}.meter i{display:block;width:var(--value,0%);height:100%;background:var(--accent);border-radius:4px}.resource small{display:block;font-size:10px}.two-col.equal{display:grid;grid-template-columns:1fr 1fr;gap:18px}.detail-list{display:grid;gap:14px}.detail-line{display:flex;justify-content:space-between;gap:18px;font-size:12px}.detail-line span{color:var(--muted)}.detail-line strong{font-weight:550;text-align:right}.dashboard-clients{display:grid;gap:1px}.client-glance{display:grid;grid-template-columns:minmax(140px,1fr) minmax(100px,1fr) 120px auto;gap:16px;align-items:center;padding:15px 0;border-top:1px solid var(--line);font-size:12px}.client-glance:first-child{border-top:0}.client-glance strong{font-size:13px;overflow-wrap:anywhere}.client-glance small{display:block;margin-top:3px}.client-glance .btn{padding:6px 10px;font-size:11px}.client-glance .traffic-value{text-align:right}
.clients-summary{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border:1px solid var(--line);background:var(--surface);border-radius:18px;margin-bottom:20px;padding:20px 5px}.client-stat{padding:2px 18px;border-right:1px solid var(--line)}.client-stat:last-child{border:0}.client-stat span{display:block;font-size:10px;color:var(--muted);white-space:nowrap}.client-stat b{display:block;margin-top:6px;font:500 23px ui-monospace,monospace}.client-stat:first-child b{color:var(--accent)}.client-stat:nth-child(3) b{color:var(--green)}.clients-panel{border:1px solid var(--line);background:var(--surface);border-radius:18px;overflow:hidden}.clients-toolbar{display:flex;align-items:center;gap:10px;padding:16px;border-bottom:1px solid var(--line);flex-wrap:wrap}.search-field{flex:1;min-width:180px;display:flex;align-items:center;gap:8px;padding-left:12px;border:1px solid var(--line);border-radius:10px;background:var(--input);color:var(--muted)}.search-field input{border:0;background:transparent;padding-left:0;font-size:12px}.clients-toolbar select{font-size:12px;width:auto;max-width:175px;padding:10px 30px 10px 11px}.table-scroll{overflow-x:auto;scrollbar-width:thin;scrollbar-color:var(--line) transparent}.clients-table{width:100%;min-width:930px;border-collapse:collapse;text-align:left;table-layout:auto}.clients-table th{font-size:10px;font-weight:500;letter-spacing:.03em;color:var(--muted);background:var(--raised);padding:12px 11px;white-space:nowrap}.clients-table td{padding:18px 11px;border-bottom:1px solid var(--line);font-size:12px;vertical-align:middle}.clients-table tr:last-child td{border-bottom:0}.clients-table tbody tr:hover{background:var(--tint)}.clients-table .select-col{width:40px;text-align:center;padding-right:4px}.clients-table .client-name{min-width:155px;max-width:240px}.client-name strong{display:block;font-size:13px;overflow-wrap:anywhere}.client-name small{display:block;color:var(--muted);font:10px/1.8 ui-monospace,monospace}.clients-table .protocol-col{max-width:160px;min-width:105px}.traffic-cell{min-width:120px}.traffic-cell b{font:500 12px ui-monospace,monospace}.traffic-cell small{display:block;font-size:9px;white-space:nowrap;margin-top:4px}.traffic-split{height:3px;margin-top:9px;background:var(--line);border-radius:4px;overflow:hidden;display:flex}.traffic-split i{height:100%;display:block}.traffic-split .up{background:var(--accent)}.traffic-split .down{background:var(--amber)}.hwid-cell{font:12px ui-monospace,monospace}.hwid-cell small{font:9px "Segoe UI",sans-serif;display:block}.row-actions{display:flex;gap:3px;align-items:center}.icon-btn{height:30px;width:30px;padding:6px;background:transparent;border-color:transparent;border-radius:8px;color:var(--muted)}.icon-btn .ico{width:16px;height:16px}.icon-btn:hover{color:var(--accent)}.icon-btn.danger:hover{color:var(--red);border-color:var(--red)}.access-switch{padding:0;width:33px;height:19px;background:var(--line);border:0;border-radius:20px;display:block;position:relative}.access-switch:after{content:"";position:absolute;top:3px;left:3px;width:13px;height:13px;background:var(--muted);border-radius:50%;transition:left .15s}.access-switch[aria-checked=true]{background:var(--accent)}.access-switch[aria-checked=true]:after{left:17px;background:var(--on-accent)}.access-switch:disabled{opacity:.6}.bulk-bar{padding:11px 16px;background:var(--tint);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:9px;flex-wrap:wrap}.bulk-bar strong{font-size:11px;margin-right:auto}.bulk-bar button{font-size:11px;padding:7px 11px}.list-footer{padding:13px 17px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;font-size:10px;color:var(--muted)}.empty{padding:30px;text-align:center;color:var(--muted);font-size:13px}.table-loading{opacity:.6;pointer-events:none}
dialog{padding:25px;width:min(570px,calc(100vw - 32px));max-height:90dvh;background:var(--surface);border:1px solid var(--line);color:var(--text);border-radius:20px;box-shadow:var(--shadow)}dialog::backdrop{background:#020d14aa;backdrop-filter:blur(7px)}.dialog-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:20px}.dialog-head h2{font-size:21px}.dialog-head button{padding:4px 10px;font-size:21px}.client-detail .account{padding:0;border:0;background:transparent}.account{padding:20px;margin:0}.account-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}.account-head .identity{display:flex;align-items:center;gap:12px;min-width:0}.avatar{display:grid;place-items:center;width:40px;height:40px;flex-shrink:0;background:var(--tint);color:var(--accent);border-radius:12px}.account h3{font-size:16px}.account .pills{margin-top:5px}.account-metrics{display:flex;gap:22px;margin:20px 0;font-size:13px}.account-metrics span{display:block;font-size:10px;color:var(--muted);margin-bottom:4px}.account details{border-top:1px solid var(--line);padding-top:12px;margin-top:18px}.account summary{cursor:pointer;color:var(--muted);font-size:12px;padding:4px 0}.sub-url{font:11px/1.5 ui-monospace,monospace;margin-bottom:12px}.device{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 0;border-top:1px solid var(--line);font-size:12px}.device small{display:block;font-size:10px}.qr-image{display:block;width:100%;max-width:260px;padding:12px;background:#fff;border-radius:10px;margin:18px auto}.client-detail .account>details>summary{display:none}
.update-dialog{width:min(470px,calc(100vw - 28px));padding:0;overflow:hidden}.update-dialog .dialog-head{padding:22px 24px 17px;margin:0;border-bottom:1px solid var(--line)}.update-dialog-body{padding:23px 24px}.update-release{display:flex;align-items:center;gap:14px;padding:16px;border:1px solid var(--line);border-radius:13px;background:var(--input)}.update-release-mark{display:grid;place-items:center;width:43px;height:43px;flex:0 0 auto;border-radius:12px;background:var(--tint);color:var(--accent)}.update-release-mark .ico{width:22px;height:22px}.update-release span{display:block;font-size:10px;color:var(--muted);margin-bottom:4px}.update-release strong{font:600 17px/1.3 ui-monospace,monospace}.update-dialog-body>p{margin:17px 0 0;color:var(--muted);font-size:12px;line-height:1.65}.update-dialog-actions{display:flex;justify-content:flex-end;gap:9px;padding:15px 24px 21px;border-top:1px solid var(--line)}
.release-banner{max-width:1512px;margin:14px auto 0;padding:13px 16px;display:flex;align-items:center;gap:13px;border:1px solid color-mix(in srgb,var(--accent) 55%,var(--line));border-radius:13px;background:linear-gradient(100deg,var(--tint),var(--surface) 58%);box-shadow:0 12px 34px #0002}.release-banner[hidden]{display:none}.release-banner-mark{display:grid;place-items:center;width:38px;height:38px;flex:0 0 auto;border-radius:11px;background:var(--accent);color:var(--on-accent)}.release-banner-mark .ico{width:19px;height:19px}.release-banner-copy{min-width:0;flex:1}.release-banner-copy b{display:block;font-size:12px}.release-banner-copy small{display:block;margin-top:2px;font-size:10px}.release-banner-version{font:600 11px ui-monospace,monospace;color:var(--accent);white-space:nowrap}.release-banner-actions{display:flex;align-items:center;gap:7px}.release-banner-actions .btn{padding:8px 12px}.release-banner-close{width:34px;height:34px;padding:6px;background:transparent;font-size:18px;color:var(--muted)}
@media(max-width:700px){.release-banner{margin:10px 8px 0;align-items:flex-start;flex-wrap:wrap}.release-banner-copy{width:calc(100% - 54px)}.release-banner-version{margin-left:51px}.release-banner-actions{margin-left:auto}.release-banner-actions .btn{font-size:11px}}
.version-manager{margin-top:18px}.version-manager h3{font-size:13px;margin:0 0 5px}.version-manager>p{margin:0 0 14px;color:var(--muted);font-size:10px}.version-row{display:grid;grid-template-columns:110px minmax(120px,1fr) auto;gap:8px;align-items:center;margin-top:9px}.version-row label{margin:0;font-size:11px}.version-row select{min-width:0;padding:9px}.version-row button{white-space:nowrap}.version-state{display:block;grid-column:2/-1;color:var(--muted);font-size:9px}
.updates-hero{display:flex;align-items:center;justify-content:space-between;gap:24px;background:linear-gradient(135deg,var(--surface),var(--raised));border-top:2px solid var(--accent)}.updates-hero-copy{display:flex;align-items:center;gap:16px}.updates-hero-icon{display:grid;place-items:center;width:52px;height:52px;flex:0 0 auto;border-radius:15px;background:var(--tint);color:var(--accent)}.updates-hero-icon .ico{width:25px;height:25px}.updates-hero p{margin:6px 0 0;color:var(--muted);font-size:12px}.updates-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.updates-card{display:flex;flex-direction:column;margin:0}.updates-card .card-title{align-items:flex-start}.updates-card .card-title p{margin:6px 0 0;color:var(--muted);font-size:11px}.update-installed{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:14px 15px;margin-bottom:15px;border:1px solid var(--line);border-radius:11px;background:var(--input)}.update-installed span{font-size:11px;color:var(--muted)}.update-installed strong{font:600 13px ui-monospace,monospace}.update-control{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:9px;align-items:end}.update-control label{grid-column:1/-1;margin-top:0}.update-control button{min-width:126px}.component-stack{display:grid;gap:12px}.component-item{padding:15px;border:1px solid var(--line);border-radius:12px;background:var(--input)}.component-item-head{display:flex;justify-content:space-between;gap:12px;margin-bottom:12px}.component-item-head strong{font-size:13px}.component-item-head small{font:10px ui-monospace,monospace}.update-status{min-height:46px;margin:16px 0 0}.update-safety{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:18px}.update-safety div{padding:15px;border:1px solid var(--line);border-radius:12px;background:var(--surface)}.update-safety b{display:block;font-size:11px;margin-bottom:4px}.update-safety small{font-size:10px;line-height:1.55}
@media(max-width:900px){.updates-grid{grid-template-columns:1fr}.updates-hero{align-items:flex-start}.update-safety{grid-template-columns:1fr}}
@media(max-width:600px){.version-row{grid-template-columns:1fr}.version-state{grid-column:auto}.version-row button{width:100%}.updates-hero{display:block}.updates-hero>.actions{margin-top:16px}.update-control{grid-template-columns:1fr}.update-control button{width:100%}.updates-hero-copy{align-items:flex-start}}
.preset-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.preset{position:relative;display:flex;flex-direction:column;align-items:flex-start;min-width:0;padding:18px;background:var(--raised);border:1px solid var(--line);border-radius:14px}.preset .preset-art{display:grid;place-items:center;height:54px;width:100%;font-size:28px;border-bottom:1px dashed var(--line);padding-bottom:12px;margin-bottom:15px}.preset b{font-size:12px}.preset p{font-size:11px;color:var(--muted);margin:7px 0 18px}.preset button{width:100%;margin-top:auto;font-size:11px}.editor-bar{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:13px 16px;font:11px ui-monospace,monospace;color:var(--muted);border:1px solid var(--line);border-bottom:0;border-radius:12px 12px 0 0;background:var(--raised)}.editor-bar i{font-style:normal;color:var(--accent)}.code-editor{display:block;min-height:340px;max-height:700px;padding:19px;border-radius:0 0 12px 12px;font:12px/1.9 ui-monospace,Consolas,monospace;resize:vertical;tab-size:2}.editor-actions{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:17px}.preview-dialog{width:min(1240px,calc(100vw - 32px));padding:0;overflow:hidden}.preview-top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:15px 18px;border-bottom:1px solid var(--line)}.preview-top strong{font-size:13px}.preview-stage{display:flex;justify-content:center;padding:20px;background:var(--bg);height:min(72dvh,780px);min-height:240px}.preview-stage iframe{display:block;width:100%;max-width:100%;height:100%;border:1px solid var(--line);border-radius:10px;background:transparent}.preview-stage.phone iframe{width:390px;border-radius:24px}.preview-caption{margin:0;padding:10px 18px;border-top:1px solid var(--line);font-size:11px;color:var(--muted)}
.login-page{min-height:100dvh;display:grid;place-items:center;padding:28px;background:radial-gradient(ellipse at 15% 20%,var(--tint),transparent 65%),var(--bg)}.login-shell{width:min(910px,100%);display:grid;grid-template-columns:1.1fr 1fr;border:1px solid var(--line);border-radius:26px;overflow:hidden;background:var(--surface);box-shadow:var(--shadow)}.login-story{padding:48px;background:var(--input);display:flex;flex-direction:column;justify-content:space-between;min-height:440px;position:relative;overflow:hidden}.login-story:after{content:"";position:absolute;width:330px;height:330px;right:-180px;bottom:-180px;border:50px solid var(--tint);border-radius:50%;pointer-events:none}.login-brand{display:flex;gap:12px;align-items:center;font-size:12px;letter-spacing:.06em}.login-brand img{width:48px;height:48px;border-radius:15px}.login-story h2{font-size:40px;line-height:1.12;font-weight:500;letter-spacing:-.05em;max-width:290px}.login-story p{color:var(--muted);font-size:13px;max-width:270px;margin-top:18px}.login-story small{font:10px ui-monospace,monospace;letter-spacing:.12em;color:var(--accent)}.signin{padding:46px 38px;display:flex;flex-direction:column;justify-content:center}.signin h1{font-size:27px}.signin p{font-size:12px;color:var(--muted);margin-bottom:20px}.signin .primary{width:100%;margin-top:25px}.login-theme{position:fixed;right:24px;top:20px}.mobile-caption{display:none}[hidden]{display:none!important}
@media(min-width:1700px){main{padding-left:36px;padding-right:36px}.app{grid-template-columns:230px minmax(0,1fr)}}
@media(max-width:1150px){.app{grid-template-columns:192px minmax(0,1fr);padding:10px;gap:8px}main{padding:24px 18px}.brand{gap:8px}.brand b{font-size:11px}.brand img{width:36px;height:36px}.dashboard-grid{grid-template-columns:minmax(0,1.5fr) minmax(245px,1fr)}.clients-summary{grid-template-columns:repeat(3,minmax(0,1fr));row-gap:18px}.client-stat:nth-child(3){border-right:0}.resource-grid{grid-template-columns:1fr 1fr}.graph-speeds{gap:20px}.graph-speeds b{font-size:22px}.preset-grid{grid-template-columns:1fr 1fr}.client-glance{grid-template-columns:1fr 1fr auto}.client-glance .badge{display:none}}
@media(max-width:900px){.dashboard-grid,.two-col.equal{grid-template-columns:1fr}.overview-stats{grid-template-columns:1fr 1fr}.graph-card{margin-bottom:0}.graph-speeds b{font-size:27px}.clients-toolbar select{max-width:100%}.login-story{padding:30px}.login-story h2{font-size:34px}.signin{padding:35px 28px}}
@media(max-width:700px){.app{display:block;height:auto;padding:8px}.sidebar{padding:14px;border-radius:16px;overflow:visible}.brand{padding:0 50px 13px 2px}.brand b{font-size:12px}.brand img{width:37px;height:37px}.brand-tools{position:absolute;right:25px;top:24px;padding:0;gap:5px}.brand-tools button{width:34px;height:34px;padding:7px}.brand-tools button span{display:none}.brand-tools .mobile-caption{display:none}.nav{grid-template-columns:repeat(3,minmax(0,1fr));gap:6px}.nav a{padding:9px 4px;font-size:11px;gap:6px;justify-content:center}.nav .ico{width:15px}.side-footer{display:flex;justify-content:space-between;align-items:center;padding-top:10px}.side-footer .logout{font-size:10px;padding:4px 6px;gap:5px}.social{margin:0;padding:0;border:0;gap:14px}.social a{font-size:9px}.social .ico{width:12px}.workspace{overflow:visible}main{padding:23px 5px 35px}.page-head{align-items:flex-start;gap:12px;margin-bottom:21px}.page-head h1{font-size:30px}.page-head p{font-size:12px}.page-head>button{font-size:11px;padding:10px;max-width:145px}.eyebrow{font-size:9px}.card{padding:18px}.graph-speeds{gap:20px}.graph-speeds b{font-size:23px}.chart-wrap{height:210px}.resource{padding:15px}.resource-head b{font-size:17px}.resource-head strong{font-size:11px}.overview-stat{padding:10px 14px}.overview-stat b{font-size:24px}.client-glance{grid-template-columns:minmax(0,1fr) auto;gap:9px}.client-glance .pills{display:none}.client-glance .btn{grid-column:1/-1;justify-self:start}.clients-summary{padding:16px 0;row-gap:16px;border-radius:15px}.client-stat{padding:0 11px}.client-stat b{font-size:20px}.client-stat span{font-size:9px}.clients-toolbar{padding:12px;gap:8px}.search-field{flex-basis:100%}.clients-toolbar select{flex:1 1 100%;font-size:12px;min-width:0;width:100%;padding-right:28px}.clients-table{display:block;min-width:0}.clients-table thead{display:none}.clients-table tbody{display:grid;gap:12px;padding:12px}.clients-table tr{position:relative;display:grid;grid-template-columns:1fr 1fr;border:1px solid var(--line);border-radius:13px;padding:12px;gap:10px;background:var(--input)}.clients-table td{display:block;padding:0;border:0;min-width:0}.clients-table td:before{content:attr(data-label);display:block;color:var(--muted);font-size:9px;margin-bottom:4px}.clients-table .select-col{position:absolute;right:12px;top:14px;width:20px}.clients-table .client-name{grid-column:1/-1;max-width:none;padding-right:28px}.client-name strong{font-size:15px}.clients-table .state-col{position:static;grid-area:2/2;justify-self:end;align-self:center}.clients-table .state-col:before{display:none}.clients-table .activity-col{grid-area:2/1;min-height:26px;align-self:center}.clients-table .activity-col:before{display:none}.clients-table .protocol-col{max-width:none}.traffic-cell{min-width:0}.clients-table .actions-col{grid-column:1/-1;border-top:1px solid var(--line);padding-top:9px}.clients-table .actions-col:before{display:none}.row-actions{justify-content:flex-end;gap:9px}.row-actions .icon-btn{width:35px;height:33px;border:1px solid var(--line)}.clients-table tr:last-child td{border:0}.bulk-bar{padding:12px}.form-grid{grid-template-columns:1fr}.account-head{flex-wrap:wrap}.account-metrics{gap:15px}.device{flex-wrap:wrap}.preview-top{padding:12px}.preview-stage{padding:10px;height:65dvh}.preview-dialog{width:calc(100vw - 16px)}.editor-actions{align-items:stretch;flex-direction:column}.preset-grid{gap:8px}.preset{padding:13px}.preset button{padding:9px}.login-page{padding:80px 18px 30px}.login-shell{grid-template-columns:1fr;max-width:420px}.login-story{padding:25px;min-height:0;gap:20px}.login-story h2{font-size:27px}.login-story p,.login-story>small{display:none}.login-story .eyebrow{display:none}.signin{padding:28px}.login-theme{top:18px;right:18px}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
'''

THEME_INIT = """<script>try{const saved=localStorage.getItem('wpp-theme');document.documentElement.dataset.theme=saved==='light'?'light':'dark'}catch(e){document.documentElement.dataset.theme='dark'}</script>"""
COMMON_JS = """<script>
document.querySelectorAll('[data-theme-toggle]').forEach(b=>{function label(){const light=document.documentElement.dataset.theme==='light';b.querySelector('span').textContent=light?'Тёмная тема':'Светлая тема';b.setAttribute('aria-label',light?'Включить тёмную тему':'Включить светлую тему')}label();b.addEventListener('click',()=>{const t=document.documentElement.dataset.theme==='light'?'dark':'light';document.documentElement.dataset.theme=t;try{localStorage.setItem('wpp-theme',t)}catch(e){}document.querySelectorAll('[data-theme-toggle] span').forEach(s=>s.textContent=t==='light'?'Тёмная тема':'Светлая тема');label()})});
async function wppCopy(text,container=document.body){try{await navigator.clipboard.writeText(text);return}catch(e){}const prior=document.activeElement,x=document.createElement('textarea');x.value=text;x.setAttribute('aria-label','Копирование ссылки');x.style.position='fixed';x.style.opacity='0';container.appendChild(x);try{x.focus();x.select();if(!document.execCommand('copy'))throw new Error('Clipboard unavailable')}finally{x.remove();if(prior?.isConnected)prior.focus()}}
document.addEventListener('click',async e=>{const b=e.target.closest('[data-copy]');if(b&&!b.disabled){const old=b.innerHTML;b.disabled=true;try{await wppCopy(b.dataset.copy,b.closest('dialog')||document.body);b.textContent=b.classList.contains('icon-btn')?'✓':'✓ Скопировано'}catch(err){b.textContent=b.classList.contains('icon-btn')?'!':'Не удалось скопировать'}finally{setTimeout(()=>{b.innerHTML=old;b.disabled=false},1600)}}const close=e.target.closest('[data-close-dialog]');if(close){const d=close.closest('dialog');d.close();const frame=d.querySelector('iframe');if(frame){frame.removeAttribute('srcdoc')}}});
document.addEventListener('submit',e=>{const f=e.target.closest('form[data-confirm]');if(f&&!confirm(f.dataset.confirm))e.preventDefault()});
</script>"""


def qr_attributes(endpoint, name, link, protocols, kind='direct', user_port=None):
    labels={'web':'WEB Proxy','vless':'VLESS XHTTP','hysteria':'Hysteria2','mtproto':'MTProto','awg20':'AWG 2.0','awg31':'AWG 3.1','openflux':'OpenFlux'}
    parsed=urlsplit(link)
    web=protocols==['web']
    openflux=protocols==['openflux']
    telegram=web or protocols==['mtproto']
    host=parsed.hostname or '' if openflux else parse_qs(parsed.query).get('server',[parsed.hostname or ''])[0] if telegram else parsed.hostname or ''
    port=None if web or openflux or kind=='subscription' else int(parse_qs(parsed.query).get('port',['443'])[0]) if protocols==['mtproto'] else parsed.port or 443
    if protocols and protocols[0] in ('awg20','awg31'):
        match=re.search(r'(?m)^Endpoint\s*=\s*([^:\s]+):(\d+)\s*$',link)
        host=match.group(1) if match else ''
        port=int(match.group(2)) if match else (int(user_port) if user_port else None)
    info={'name':name,'link':link,'protocols':' · '.join(labels.get(p,p) for p in protocols),
          'kind':kind,'host':host,'port':port,'web':telegram,'openflux':openflux}
    return 'data-qr="'+esc(endpoint)+'" data-qr-info="'+esc(json.dumps(info,ensure_ascii=False))+'"'


QR_CSS='''
.connection-dialog{width:min(700px,calc(100vw - 32px));padding:0;overflow:auto;background:linear-gradient(145deg,var(--surface),var(--input));border-radius:24px}
.connection-header{display:flex;align-items:center;gap:11px;padding:23px 26px 20px}.connection-mark{display:grid;place-items:center;width:36px;height:36px;border-radius:11px;background:var(--tint);color:var(--accent)}.connection-header h2{font-size:16px;letter-spacing:-.02em}.connection-header small{font-size:10px;letter-spacing:.09em}.connection-close{margin-left:auto;width:33px;height:33px;padding:0;background:transparent;font-size:21px;color:var(--muted)}
.connection-body{display:grid;grid-template-columns:234px minmax(0,1fr);gap:26px;padding:0 26px 25px;align-items:center}.qr-visual{text-align:center;min-width:0}.qr-canvas{width:234px;height:234px;max-width:100%;display:grid;place-items:center;background:#fff;border-radius:15px;padding:12px;box-shadow:0 8px 30px #0001}.qr-canvas img{display:block;width:100%;height:100%;object-fit:contain;image-rendering:pixelated}.qr-canvas p{font-size:12px;line-height:1.5;color:#4d6269;margin:0;padding:16px}.qr-caption{font-size:10px;color:var(--muted);margin-top:12px}.connection-info{min-width:0}.connection-kind{font-size:10px;letter-spacing:.04em;color:var(--accent);margin:0 0 5px}.connection-info h3{font-size:23px;font-weight:600;line-height:1.2;letter-spacing:-.035em}.connection-protocol{display:block;font-size:11px;color:var(--muted);margin:9px 0 17px;overflow-wrap:anywhere}.connection-meta{display:flex;flex-wrap:wrap;gap:12px;font-size:11px;margin-bottom:18px}.connection-meta span{color:var(--muted)}.connection-meta b{color:var(--text);font-weight:500;overflow-wrap:anywhere}.connect-steps{display:grid;gap:11px;margin:0;padding:0;list-style:none;counter-reset:step}.connect-steps li{display:flex;gap:10px;font-size:12px;color:var(--muted);line-height:1.5}.connect-steps li:before{counter-increment:step;content:counter(step);display:grid;place-items:center;flex:0 0 22px;height:22px;border:1px solid var(--line);border-radius:50%;color:var(--accent);font-size:10px}.connection-footer{padding:18px 26px 21px;border-top:1px solid var(--line);background:var(--tint)}.connection-footer>.actions{justify-content:space-between;gap:14px}.connection-footer .primary{min-width:210px}.connection-footer small{font-size:10px;max-width:245px}.connection-status{margin:8px 0 0;font-size:12px;color:var(--accent)}.connection-status:empty{display:none}.connection-link{margin-top:8px;font-size:11px;color:var(--muted)}.connection-link summary{cursor:pointer;width:fit-content}.connection-link input{margin-top:10px;font:11px/1.5 ui-monospace,monospace}.qr-retry{margin:10px 0 0;font-size:11px}
@media(max-width:600px){.connection-dialog{width:calc(100vw - 24px);max-height:92dvh}.connection-header{padding:19px 19px 16px}.connection-body{grid-template-columns:1fr;gap:18px;padding:0 20px 20px}.qr-visual{grid-row:2}.qr-canvas{margin:0 auto;width:216px;height:216px}.connection-info{text-align:center}.connection-info h3{font-size:22px}.connection-meta{justify-content:center;margin-bottom:12px}.connection-protocol{margin:7px 0 10px}.connect-steps{text-align:left;max-width:285px;margin:0 auto;gap:7px}.connection-footer{padding:16px 20px}.connection-footer>.actions{display:grid;justify-content:stretch}.connection-footer .primary{width:100%}.connection-footer small{max-width:none}.connection-status{text-align:center}}
'''
CSS += QR_CSS
CSS += '''.preset>.actions{display:grid;grid-template-columns:1fr 1fr;width:100%;gap:7px;margin-top:auto}.preset>.actions form{min-width:0}.preset>.actions button{margin:0;padding:9px 7px}'''
CSS += '''.preset .preset-delete{grid-column:1/-1}.preset-create{border-style:dashed;text-align:left;cursor:pointer}.preset-create:hover{border-color:var(--accent);background:var(--tint)}.preset-create-mark{display:grid;place-items:center;width:54px;height:54px;margin-bottom:15px;border-radius:15px;background:var(--tint);color:var(--accent);font-size:25px}.preset-create .btn{width:100%;margin-top:auto}.preset-create-dialog{width:min(920px,calc(100vw - 28px))}.preset-create-dialog .code-editor{min-height:300px;max-height:46dvh}.preset-create-dialog .editor-bar{margin-top:0}@media(max-width:700px){.preset-create-dialog .form-grid{grid-template-columns:1fr}.preset-create-dialog .code-editor{min-height:240px}}'''
CSS += '''
.openflux-card{overflow:hidden;background:radial-gradient(circle at 100% 0,var(--tint),transparent 38%),var(--surface)}.openflux-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px}.openflux-title{display:flex;align-items:center;gap:13px}.openflux-mark{display:grid;place-items:center;width:43px;height:43px;flex:0 0 auto;border:1px solid color-mix(in srgb,var(--accent) 40%,var(--line));border-radius:12px;background:var(--tint);color:var(--accent);font-weight:750}.openflux-title h2{margin:0}.openflux-title p{margin:4px 0 0;color:var(--muted);font-size:11px}.openflux-status{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid var(--line);border-radius:99px;color:var(--muted);font-size:10px;white-space:nowrap}.openflux-status i{width:7px;height:7px;border-radius:50%;background:var(--muted)}.openflux-status.on{color:var(--green)}.openflux-status.on i{background:var(--green);box-shadow:0 0 0 4px color-mix(in srgb,var(--green) 14%,transparent)}.openflux-form{margin-top:22px}.openflux-input{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:9px}.openflux-input input{font:11px ui-monospace,monospace}.openflux-input button{min-width:155px}.openflux-hint{display:block;margin-top:9px;font-size:10px}.openflux-client{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:20px;padding-top:20px;border-top:1px solid var(--line)}.openflux-field{min-width:0;padding:13px;border:1px solid var(--line);border-radius:10px;background:var(--input)}.openflux-field.wide{grid-column:1/-1}.openflux-field span{display:block;margin-bottom:7px;color:var(--muted);font-size:9px;letter-spacing:.06em;text-transform:uppercase}.openflux-value{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:6px}.openflux-value input{min-width:0;padding:9px;font:10px ui-monospace,monospace}.openflux-value button{padding:8px 10px}.openflux-field b{font:500 12px ui-monospace,monospace}.openflux-controls{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:15px}.openflux-controls>small{max-width:600px;font-size:10px}.openflux-controls .actions{margin-left:auto}.openflux-copy-status{min-height:16px;margin:9px 0 0;color:var(--accent);font-size:10px}@media(max-width:700px){.openflux-head{align-items:stretch;flex-direction:column}.openflux-status{width:max-content}.openflux-input{grid-template-columns:1fr}.openflux-input button{width:100%}.openflux-client{grid-template-columns:1fr}.openflux-field.wide{grid-column:auto}.openflux-controls{align-items:stretch;flex-direction:column}.openflux-controls .actions{display:grid;width:100%;margin:0}.openflux-controls .actions form,.openflux-controls .actions button{width:100%}}
'''

# Graphite-blue theme restored from the selected reference; light mode remains available.
CSS += '''
:root{--bg:#101318;--surface:#1b1e24;--raised:#22262e;--input:#171a20;--line:#303641;--text:#f3f5f8;--muted:#93a0b8;--accent:#3b82f6;--on-accent:#fff;--tint:#3b82f619;--green:#41c78d;--red:#f06f75;--amber:#dcae43;--sidebar:#181b21;--shadow:0 14px 46px #0006}
:root[data-theme=light]{--bg:#f3f5f8;--surface:#fff;--raised:#eef1f5;--input:#f9fafc;--line:#d8dde6;--text:#202630;--muted:#667188;--accent:#2563d9;--on-accent:#fff;--tint:#2563d912;--green:#25865b;--red:#bd464c;--amber:#916918;--sidebar:#fff;--shadow:0 8px 30px #17203614}
body{font-size:14px;line-height:1.5}h1{font-size:32px;font-weight:650;letter-spacing:-.035em}h2{letter-spacing:-.015em}.eyebrow{display:none}
.app{padding:0;gap:0;grid-template-columns:216px minmax(0,1fr)}.sidebar{border:0;border-right:1px solid var(--line);border-radius:0;background:var(--sidebar);padding:36px 18px 22px}.brand{display:block;padding:0 16px 50px}.brand-wordmark{display:block;font-size:40px!important;line-height:1.1;letter-spacing:-.06em!important;color:var(--accent)}.brand-name{display:block;font-size:10px;letter-spacing:.07em;color:var(--muted);margin-top:9px}.brand small{font:10px/1.5 inherit;margin-top:5px}.nav{gap:9px}.nav a,.logout{font-size:13px;font-weight:500;padding:13px 15px;border-radius:9px}.nav a.active{background:var(--tint);color:var(--accent)}.side-footer{padding-top:36px}.brand-tools{padding:16px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin-bottom:12px}.brand-tools button{width:100%;font-size:11px;justify-content:flex-start;border:0;padding:10px}.theme-track{margin-left:auto;width:29px;height:17px;border-radius:20px;background:var(--accent);position:relative;flex-shrink:0}.theme-track:after{content:"";position:absolute;top:3px;right:3px;width:11px;height:11px;background:var(--on-accent);border-radius:50%}:root[data-theme=dark] .theme-track:after{right:15px}.social{border:0;justify-content:flex-start;padding:20px 12px 0;gap:18px}.social a{font-size:10px}.social .ico{width:16px;height:16px}.workspace{background:var(--bg)}main{max-width:1720px;padding:38px 36px 44px}.page-head{margin-bottom:32px;align-items:center}.page-head p{font-size:13px;margin-top:6px}.page-head .primary{padding:12px 17px;font-size:13px}.btn,button{border-radius:8px;font-weight:500;background:var(--surface)}.btn.primary,button.primary{box-shadow:0 2px 6px #0003}input,textarea,select{border-radius:8px;background:var(--input)}button:hover,.btn:hover{background:var(--tint)}button.primary:hover,.btn.primary:hover{background:var(--accent);filter:brightness(1.08)}.card,.account{border-radius:14px}.pill,.proto-hysteria,.proto-web,.proto-vless{border:0;background:var(--tint);color:var(--accent);font-size:11px;padding:4px 7px}.badge{font-size:10px}.avatar{border-radius:50%}
.clients-layout{display:grid;grid-template-columns:minmax(0,1fr);gap:24px;align-items:start}.clients-content{min-width:0}.connection-slot:empty{display:none}.clients-summary{grid-template-columns:repeat(4,minmax(0,1fr));border:1px solid var(--line);border-radius:12px;background:var(--surface);padding:18px 5px;margin-bottom:20px;gap:0}.client-stat{padding:0 20px}.client-stat:first-child{padding-left:20px}.client-stat:nth-child(3){border-right:1px solid var(--line)}.client-stat:last-child{border:0}.client-stat span{font-size:11px;white-space:normal}.client-stat b{font:600 25px/1.3 "Segoe UI",system-ui,sans-serif;font-variant-numeric:tabular-nums;color:var(--text);margin-top:8px}.client-stat:first-child b{color:var(--accent)}.clients-panel{border:1px solid var(--line);border-radius:12px;background:var(--surface);overflow:hidden}.clients-toolbar{padding:16px;border-bottom:1px solid var(--line);gap:8px}.search-field{min-width:190px;border-radius:8px;flex:2}.search-field input{font-size:12px}.clients-toolbar select{flex:1;min-width:110px;max-width:180px;font-size:11px;background:var(--input)}.clients-toolbar #clientSort{max-width:140px}.clients-table{min-width:730px}.clients-table th{padding:12px 8px;font-size:11px;letter-spacing:0;background:var(--raised);border-bottom:1px solid var(--line)}.clients-table td{padding:16px 8px;font-size:12px}.clients-table .client-name{min-width:170px;max-width:260px}.client-identity{display:flex;align-items:center;gap:11px;min-width:0}.client-initial{display:grid;place-items:center;width:35px;height:35px;flex-shrink:0;border-radius:50%;background:var(--tint);color:var(--accent);font-size:16px;font-weight:500}.client-identity>div{min-width:0}.client-name strong{font-size:13px;font-weight:550}.client-name small{font:10px/1.7 "Segoe UI",system-ui,sans-serif}.client-name .badge{margin-top:4px}.clients-table .activity-col{display:none}.clients-table .hwid-cell{display:none}.clients-table .protocol-col{max-width:170px}.traffic-cell{min-width:104px}.traffic-cell b{font:500 12px "Segoe UI",system-ui,sans-serif;font-variant-numeric:tabular-nums}.traffic-cell small{font-size:9px}.traffic-split{height:2px;opacity:.5}.row-actions{gap:2px}.row-actions .icon-btn{width:28px;height:30px;border:0}.icon-btn.danger{color:var(--muted)}.icon-btn.danger:hover{color:var(--red)}.clients-table .select-col{width:28px;padding-left:0}.clients-table input[type=checkbox]{width:13px;height:13px}.access-switch{width:36px;height:21px}.access-switch:after{width:15px;height:15px}.access-switch[aria-checked=true]:after{left:18px}.clients-table tr.qr-selected{background:var(--tint);box-shadow:inset 2px 0 var(--accent)}.clients-table tr.qr-selected [data-qr]{color:var(--accent);background:var(--surface)}.list-footer{padding:15px 16px;border-top:1px solid var(--line);font-size:11px}.list-footer span:last-child{font-size:10px}.client-help{border:0;background:none;border-top:1px solid var(--line);border-radius:0;padding:16px 0;margin-top:22px}.client-help summary{cursor:pointer}.bulk-bar{border:1px solid var(--line);border-radius:8px;margin-bottom:10px}
.connection-dialog{width:min(390px,calc(100vw - 32px));padding:0;border-radius:14px;background:var(--surface);max-height:90dvh;box-shadow:var(--shadow)}.connection-header{padding:22px 23px 18px}.connection-header h2{font-size:15px;font-weight:550}.connection-close{border:0;width:30px;height:30px}.connection-body{display:flex;flex-direction:column;gap:19px;padding:0 24px 20px}.connection-info{width:100%;text-align:left}.connection-person{display:flex;align-items:center;gap:12px}.connection-person .client-initial{width:45px;height:45px;font-size:22px}.connection-person>div{min-width:0}.connection-info h3{font-size:21px;letter-spacing:-.025em;overflow-wrap:anywhere}.connection-kind{font-size:11px;letter-spacing:0;color:var(--muted);margin:5px 0 0}.connection-protocol{display:flex;justify-content:center;flex-wrap:wrap;gap:6px;margin:18px 0 10px}.connection-meta{justify-content:center;margin:0;gap:8px;font-size:10px}.qr-canvas{width:220px;height:220px;max-width:100%;margin:0 auto;border:1px solid #e1e6df;border-radius:12px;box-shadow:none;padding:12px}.qr-visual{width:100%}.qr-caption{font-size:11px;max-width:230px;margin:12px auto 0;line-height:1.6}.connection-footer{padding:0 24px 20px;border:0;background:transparent}.connection-footer .primary{width:100%;min-width:0;padding:12px;font-size:12px}.connection-status{font-size:11px;margin-top:10px;text-align:center}.connection-link{margin-top:14px}.connection-link summary{margin:0 auto;color:var(--accent);padding:5px;font-size:12px;list-style:none}.connection-link summary::-webkit-details-marker{display:none}.connection-link input{font-size:10px}.connection-privacy{margin:20px 0 0;padding-top:16px;border-top:1px solid var(--line);font-size:10px;line-height:1.6;color:var(--muted);text-align:center}.connection-dialog.docked{position:static;inset:auto;margin:0;width:100%;max-height:none;box-shadow:0 2px 8px #233c2508}.connection-slot{min-width:0}.connection-slot:has(.docked[open]){position:sticky;top:28px}
.graph-card{background:var(--surface);border-top:1px solid var(--line)}.graph-speeds b,.overview-stat b,.resource-head b{font-family:"Segoe UI",system-ui,sans-serif;letter-spacing:-.03em;font-variant-numeric:tabular-nums}.resource{border-radius:12px}.resource-grid{gap:14px}.preset{background:var(--raised)}.login-page{background:radial-gradient(circle at 18% 20%,var(--tint),transparent 38%),var(--bg)}.login-shell{padding:0;border-radius:18px}.login-story{background:var(--tint)}.login-story:after{display:none}.login-story h2{font-weight:550}.signin h1{font-size:28px}.login-brand .brand-wordmark{font-size:32px!important}.login-brand{align-items:flex-start;flex-direction:column;gap:4px;letter-spacing:.02em}
@media(min-width:1440px){.clients-layout:has(.docked[open]){grid-template-columns:minmax(0,1fr) 304px}.clients-layout:has(.docked[open]) .page-head .primary{font-size:12px;padding:12px}.clients-layout:has(.docked[open]) .page-head{gap:10px}}
@media(max-width:1150px){.app{padding:0;gap:0;grid-template-columns:190px minmax(0,1fr)}main{padding:28px 24px}.sidebar{padding:30px 12px 20px}.brand{padding-left:12px}.client-stat{padding:0 12px}.client-stat b{font-size:23px}.clients-summary{grid-template-columns:repeat(4,minmax(0,1fr))}.clients-toolbar select{max-width:none}}
@media(max-width:700px){.app{display:block;padding:0}.sidebar{padding:18px 16px 10px;border:0;border-bottom:1px solid var(--line);border-radius:0}.brand{padding:0 58px 18px 0}.brand-wordmark{font-size:28px!important}.brand-name{font-size:8px;margin-top:4px}.brand small{display:none}.brand-tools{top:21px;right:16px;border:0;margin:0;padding:0;position:absolute}.brand-tools button{border:1px solid var(--line);width:36px;height:36px;padding:8px}.theme-track{display:none}.nav a{padding:10px 4px;font-size:12px}.side-footer{padding-top:8px}.side-footer .logout{font-size:11px;padding:6px 0}.social{padding:0;gap:15px}.social a{font-size:10px}main{padding:24px 16px 36px}.page-head{align-items:flex-start;margin-bottom:25px;flex-wrap:wrap}.page-head h1{font-size:29px}.page-head .primary{font-size:12px;padding:10px 14px}.page-head .actions{gap:6px}.clients-summary{grid-template-columns:repeat(2,minmax(0,1fr));row-gap:20px;margin-bottom:25px}.client-stat{padding:0 14px}.client-stat:nth-child(odd){padding-left:0}.client-stat:nth-child(even){border-right:0}.client-stat b{font-size:24px;margin-top:5px}.client-stat span{font-size:11px}.clients-toolbar{padding:0 0 18px}.clients-toolbar select{flex:1 1 calc(50% - 8px);width:auto;max-width:none;font-size:12px}.clients-toolbar #clientSort{max-width:none}.clients-table{min-width:0}.clients-table tbody{padding:0;gap:12px}.clients-table tr{padding:15px;background:var(--surface);grid-template-columns:1fr 1fr}.clients-table td{padding:0}.clients-table .client-name{max-width:none;padding-right:25px}.client-name strong{font-size:15px}.client-identity{gap:10px}.client-name .badge{display:none}.clients-table .activity-col,.clients-table .hwid-cell{display:block}.clients-table .protocol-col{max-width:none}.clients-table .state-col{justify-self:end}.client-name small{font-size:10px}.clients-table .select-col{right:14px;top:14px}.clients-table .actions-col{padding-top:10px}.row-actions{gap:12px}.row-actions .icon-btn{height:38px;width:38px;border:1px solid var(--line)}.client-help{font-size:11px}.connection-dialog{width:min(390px,calc(100vw - 24px));max-height:92dvh}.connection-body{padding:0 20px 18px;gap:17px}.connection-header{padding:18px 20px 15px}.connection-footer{padding:0 20px 18px}.connection-info h3{font-size:21px}.connection-info{text-align:left}.qr-canvas{width:210px;height:210px}.connection-slot{position:static!important}.connection-privacy{margin-top:15px}.login-shell{padding:0}.login-brand{flex-direction:row;align-items:center;gap:10px}.login-story{padding:25px}.signin{padding:26px}.login-story h2{font-size:26px}.login-theme{position:absolute}}
'''

# Classic graphite shell: wide workspace, slim top bar and the dashboard geometry
# from the earlier stable interface. Current account and protocol controls remain.
CSS += '''
.app{display:block;height:auto;min-height:100dvh}.sidebar{display:none!important}.workspace{min-height:100dvh;overflow:visible;background:var(--bg)}
.appbar{position:sticky;top:0;z-index:40;min-height:61px;padding:0 28px;display:grid;grid-template-columns:minmax(220px,1fr) auto minmax(220px,1fr);align-items:center;gap:20px;background:color-mix(in srgb,var(--surface) 96%,transparent);border-bottom:1px solid var(--line);backdrop-filter:blur(16px)}
.appbar-left,.appbar-tools,.topnav{display:flex;align-items:center}.appbar-left{gap:14px;min-width:0}.mini-brand{display:block;width:38px;height:38px;overflow:hidden;border:1px solid var(--line);border-radius:10px;background:#061531;text-decoration:none;box-shadow:0 3px 12px #001b4b55}.mini-brand img{display:block;width:100%;height:100%;object-fit:cover}.appbar .host{display:flex;align-items:center;gap:8px;min-width:0;color:var(--muted);font-size:12px;overflow-wrap:anywhere}.appbar .host i{width:6px;height:6px;flex:0 0 auto;border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px var(--tint)}
.topnav{justify-content:center;gap:4px}.topnav a{display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:7px;color:var(--muted);text-decoration:none;font-size:12px;font-weight:550}.topnav a:hover{color:var(--text);background:var(--raised)}.topnav a.active{color:var(--accent);background:var(--tint)}.topnav .ico{width:16px;height:16px}
.appbar-tools{justify-content:flex-end;gap:6px}.appbar-tools button,.appbar-tools .btn{border-color:var(--line);background:var(--raised);padding:8px 11px}.appbar-tools .theme-track{display:none}.appbar-tools .logout{width:37px;height:37px;padding:8px;border:1px solid var(--line);border-radius:8px}.appbar-tools .logout span{display:none}
main{width:100%;max-width:1680px;margin:0 auto;padding:34px clamp(22px,4vw,66px) 50px}.page-head{margin-bottom:26px}.page-head h1{font-size:31px}.classic-footer{max-width:1680px;margin:0 auto;padding:0 clamp(22px,4vw,66px) 26px;display:flex;justify-content:flex-end;gap:16px}.classic-footer a{display:flex;align-items:center;gap:5px;color:var(--muted);font-size:10px;text-decoration:none}.classic-footer .ico{width:14px;height:14px}
.card,.account,.clients-summary,.clients-panel{border-radius:12px}.overview-stats{gap:18px}.overview-stat{padding:18px 20px;border:1px solid var(--line);border-radius:12px;background:var(--surface)}.overview-stat:first-child{border-color:var(--line)}.overview-stat b{font-family:"Segoe UI",system-ui,sans-serif;font-size:25px;letter-spacing:-.03em}
.resource-deck{padding:22px 0;margin-bottom:18px}.resource-deck .resource-grid{margin:0;gap:0}.resource-deck .resource{display:flex;align-items:center;gap:17px;padding:0 22px;border:0;border-right:1px solid var(--line);border-radius:0;background:transparent}.resource-deck .resource:last-child{border-right:0}.resource-ring{position:relative;display:grid;place-items:center;width:72px;height:72px;flex:0 0 auto;border-radius:50%;background:conic-gradient(var(--accent) var(--value,0%),var(--line) 0)}.resource-ring:before{content:"";position:absolute;inset:5px;border-radius:50%;background:var(--surface)}.resource-ring b{position:relative;font-size:11px;font-weight:650;font-variant-numeric:tabular-nums}.resource-copy{min-width:0}.resource-copy strong{display:block;font-size:12px}.resource-copy small{display:block;margin-top:5px;font-size:10px}.resource-grid-title{display:none}
.graph-card{border-top:1px solid var(--line);background:var(--surface)}
.login-page{background:radial-gradient(circle at 50% 20%,var(--tint),transparent 34%),var(--bg)}.login-card{width:min(430px,100%);padding:34px;border:1px solid var(--line);border-radius:15px;background:var(--surface);box-shadow:var(--shadow)}.login-card .signin-logo{display:block;width:62px;height:62px;margin:0 auto 22px;border-radius:17px}.login-card h1{text-align:center;font-size:27px}.login-card>p{text-align:center;color:var(--muted);font-size:13px;margin-bottom:23px}.login-card .primary{width:100%;margin-top:23px}.login-card .login-version{display:block;text-align:center;margin-top:22px;font:10px ui-monospace,monospace;color:var(--muted)}
@media(max-width:900px){.appbar{grid-template-columns:1fr auto;padding:10px 18px;gap:10px}.topnav{grid-column:1/-1;grid-row:2;justify-content:stretch}.topnav a{flex:1;justify-content:center}.appbar-tools .theme-label{display:none}.appbar-left{gap:11px}main{padding:28px 20px 42px}.resource-deck .resource-grid{grid-template-columns:repeat(2,minmax(0,1fr));row-gap:22px}.resource-deck .resource:nth-child(2){border-right:0}.resource-deck .resource:nth-child(n+3){border-top:1px solid var(--line);padding-top:22px}.overview-stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:560px){.appbar{position:static;padding:12px 14px}.mini-brand{width:34px;height:34px}.appbar .host{font-size:10px}.topnav{gap:2px}.topnav a{min-width:0;padding:9px 2px;font-size:9px;gap:0}.topnav .ico{display:none}.appbar-tools button,.appbar-tools .btn{width:34px;height:34px;padding:7px}.appbar-tools button span{display:none}main{padding:24px 14px 36px}.resource-deck{padding:0}.resource-deck .resource-grid{grid-template-columns:1fr}.resource-deck .resource{padding:16px 18px;border-right:0;border-top:1px solid var(--line)!important}.resource-deck .resource:first-child{border-top:0!important}.resource-ring{width:62px;height:62px}.overview-stats{gap:10px}.overview-stat{padding:15px}.classic-footer{padding:0 14px 22px}.login-card{padding:28px 22px}.login-theme{right:14px;top:14px}}
'''

# Compact connection workspace and quiet social actions in the fixed app bar.
CSS += '''
.classic-footer{display:none}.appbar-tools .social-icon,.appbar-tools .logout{display:grid;place-items:center;width:37px;height:37px;padding:8px;border:1px solid var(--line);border-radius:8px;color:var(--muted);background:var(--raised);text-decoration:none}.appbar-tools .social-icon:hover,.appbar-tools .logout:hover{color:var(--accent);border-color:var(--accent);background:var(--tint)}.appbar-tools .social-icon .ico{width:17px;height:17px}.appbar-tools .logout span{display:none}
.connection-dialog{width:min(404px,calc(100vw - 32px));padding:0;border-radius:16px;background:var(--surface);max-height:92dvh;box-shadow:var(--shadow);overflow:auto}.connection-header{padding:20px 22px 15px;border-bottom:1px solid var(--line)}.connection-heading small{display:block;margin-bottom:3px;color:var(--accent);font:600 9px/1.4 ui-monospace,monospace;letter-spacing:.13em}.connection-header h2{font-size:16px;font-weight:600}.connection-close{border:1px solid var(--line);width:32px;height:32px;background:var(--input);font-size:19px}.connection-body{display:flex;flex-direction:column;gap:14px;padding:18px 22px}.connection-info{width:100%;padding:15px;border:1px solid var(--line);border-radius:12px;background:var(--input);text-align:left}.connection-person{display:flex;align-items:center;gap:12px}.connection-person .client-initial{width:43px;height:43px;font-size:20px}.connection-person>div{min-width:0}.connection-info h3{font-size:19px;letter-spacing:-.02em;overflow-wrap:anywhere}.connection-kind{font-size:10px;letter-spacing:0;color:var(--muted);margin:3px 0 0}.connection-protocol{display:flex;justify-content:flex-start;flex-wrap:wrap;gap:6px;margin:14px 0}.connection-meta{display:grid;grid-template-columns:minmax(0,1fr) auto;margin:0;gap:8px;font-size:10px}.connection-meta span{display:block;min-width:0;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--surface)}.connection-meta small{display:block;margin-bottom:3px;font-size:8px;letter-spacing:.08em;text-transform:uppercase}.connection-meta b{display:block;max-width:100%;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.qr-visual{width:100%;padding:15px;border:1px solid var(--line);border-radius:12px;background:linear-gradient(145deg,var(--raised),var(--input));text-align:center}.qr-canvas{position:relative;width:214px;height:214px;max-width:100%;margin:0 auto;display:grid;place-items:center;border:1px solid #dfe4eb;border-radius:14px;background:#fff;box-shadow:0 10px 26px #0002;padding:12px;overflow:hidden}.qr-canvas img{width:100%;height:100%;object-fit:contain}.qr-canvas.has-error{height:156px;border-color:color-mix(in srgb,var(--red) 35%,var(--line));background:color-mix(in srgb,var(--red) 7%,var(--surface));box-shadow:none}.qr-canvas.has-error:before{content:"!";display:grid;place-items:center;width:30px;height:30px;margin:0 auto 9px;border-radius:50%;background:color-mix(in srgb,var(--red) 14%,transparent);color:var(--red);font-weight:700}.qr-canvas.has-error p{padding:0 14px;color:var(--muted)}.qr-canvas p{font-size:11px;line-height:1.55;color:#4d6269;margin:0;padding:14px}.qr-caption{font-size:10px;max-width:250px;margin:11px auto 0;line-height:1.55}.qr-retry{margin:10px auto 0;font-size:10px;padding:7px 10px}.connection-footer{padding:0 22px 20px;border:0;background:transparent}.connection-footer .primary{width:100%;min-width:0;padding:12px;font-size:12px}.connection-status{font-size:10px;margin-top:9px;text-align:center}.connection-link{margin-top:11px}.connection-link summary{margin:0 auto;color:var(--accent);padding:5px;font-size:11px;list-style:none}.connection-link input{font-size:10px}.connection-privacy{margin:15px 0 0;padding-top:14px;border-top:1px solid var(--line);font-size:9px;line-height:1.6;color:var(--muted);text-align:center}.connection-dialog.docked{position:static;inset:auto;margin:0;width:100%;max-height:none;box-shadow:0 2px 8px #0002}.connection-slot:has(.docked[open]){position:sticky;top:78px}
@media(max-width:700px){.connection-dialog{width:min(404px,calc(100vw - 20px))}.connection-header{padding:17px 18px 14px}.connection-body{padding:15px 18px}.connection-footer{padding:0 18px 18px}.qr-canvas{width:204px;height:204px}.appbar-tools .social-icon{width:36px;height:36px;padding:8px}}
@media(max-width:420px){.appbar-left .host{display:none}.appbar-tools{gap:4px}.appbar-tools .social-icon,.appbar-tools .logout{width:34px;height:34px;padding:7px}}
'''


def qr_dialog():
    return '''<dialog id="accountQr" class="connection-dialog" aria-labelledby="qrDialogTitle"><header class="connection-header"><div class="connection-heading"><small>ДОСТУП К КЛИЕНТУ</small><h2 id="qrDialogTitle">Подключение</h2></div><button type="button" class="connection-close" data-close-dialog aria-label="Закрыть QR">×</button></header><div class="connection-body"><section class="connection-info"><div class="connection-person"><span id="qrInitial" class="client-initial" aria-hidden="true"></span><div><h3 id="qrClientName"></h3><p id="qrKind" class="connection-kind"></p></div></div><div id="qrProtocol" class="connection-protocol"></div><div class="connection-meta"><span><small>Сервер</small><b id="qrHost"></b></span><span id="qrPortRow" hidden><small>Порт</small><b id="qrPort"></b></span></div></section><div class="qr-visual"><div class="qr-canvas" aria-busy="true"><img id="accountQrImage" alt="QR подключения" hidden><p id="qrImageStatus" role="status">Создаём QR…</p></div><button type="button" id="qrRetry" class="qr-retry quiet" hidden>Повторить загрузку</button><p class="qr-caption"><span id="qrStepOne"></span><br><span id="qrStepTwo"></span></p></div></div><footer class="connection-footer"><button type="button" class="primary" id="qrCopy">'''+icon('copy')+'''<span>Скопировать ссылку</span></button><p id="qrCopyStatus" class="connection-status" role="status"></p><details id="qrLinkDetails" class="connection-link"><summary>Показать ссылку вручную</summary><input id="qrLink" readonly aria-label="Ссылка подключения" spellcheck="false"></details><p class="connection-privacy">QR и ссылка открывают доступ к подключению.<br>Храните их как пароль.</p></footer></dialog>'''+QR_JS


QR_JS='''<script>
(()=>{const dialog=document.getElementById('accountQr'),image=document.getElementById('accountQrImage'),status=document.getElementById('qrImageStatus'),retry=document.getElementById('qrRetry'),canvas=dialog.querySelector('.qr-canvas'),copy=document.getElementById('qrCopy'),copyStatus=document.getElementById('qrCopyStatus'),link=document.getElementById('qrLink');let serial=0,endpoint='';
function clearImage(){image.onload=null;image.onerror=null;image.hidden=true;image.removeAttribute('src')}
function loadQr(){const generation=++serial;clearImage();canvas.classList.remove('has-error');status.hidden=false;status.textContent='Создаём QR…';canvas.setAttribute('aria-busy','true');retry.hidden=true;image.onload=()=>{if(generation!==serial)return;image.hidden=false;status.hidden=true;canvas.setAttribute('aria-busy','false')};image.onerror=()=>{if(generation!==serial)return;clearImage();canvas.classList.add('has-error');status.textContent='Не удалось создать QR. Обновите список и попробуйте ещё раз.';retry.hidden=false;canvas.setAttribute('aria-busy','false')};const separator=endpoint.includes('?')?'&':'?';image.src=endpoint+separator+'_qr='+generation+'-'+Date.now()}
const wide=matchMedia('(min-width:1440px)');let opener=null;
function selectedRow(q){document.querySelectorAll('[data-client]').forEach(row=>{const chosen=row===q?.closest('[data-client]');row.classList.toggle('qr-selected',chosen);const b=row.querySelector('[data-qr]');if(b)b.setAttribute('aria-expanded',String(chosen))})}
function openQr(q){let info;try{info=JSON.parse(q.dataset.qrInfo)}catch(e){return}opener=q;endpoint=q.dataset.qr;document.getElementById('qrClientName').textContent=info.name;document.getElementById('qrInitial').textContent=Array.from(info.name.trim())[0]?.toLocaleUpperCase('ru')||'•';document.getElementById('qrKind').textContent=info.kind==='subscription'?'Ссылка подписки':'Отдельное подключение';const protocols=document.getElementById('qrProtocol');protocols.replaceChildren();info.protocols.split(' · ').forEach(p=>{const badge=document.createElement('span');badge.className='pill';badge.textContent=p;protocols.appendChild(badge)});document.getElementById('qrHost').textContent=info.host;document.getElementById('qrPortRow').hidden=info.port===null;document.getElementById('qrPort').textContent=info.port??'';document.getElementById('qrStepOne').textContent=info.openflux?'Отсканируйте QR в приложении OpenFlux':info.web?'Сканируйте камерой другого устройства.':'Отсканируйте в совместимом приложении';document.getElementById('qrStepTwo').textContent=info.openflux?'Добавится ссылка на публичный документ.':info.web?'Откройте ссылку в Telegram.':'или скопируйте ссылку.';link.value=info.link;copyStatus.textContent='';copy.disabled=false;document.getElementById('qrLinkDetails').open=false;selectedRow(q);const dock=wide.matches&&!q.closest('dialog')&&!document.querySelector('dialog:modal');if(dialog.open&&dialog.classList.contains('docked')!==dock){dialog.close();return}dialog.classList.toggle('docked',dock);if(!dialog.open){if(dock)dialog.show();else dialog.showModal()}loadQr()}
document.addEventListener('click',e=>{const q=e.target.closest('[data-qr]');if(q)openQr(q)});
// Switching layout closes the private card instead of leaving a modal trapped off-screen.
wide.addEventListener('change',()=>{if(dialog.open)dialog.close()});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&dialog.open&&dialog.classList.contains('docked')&&!document.querySelector('dialog:modal')){e.preventDefault();dialog.close()}});
document.addEventListener('wpp-filtered',()=>{if(dialog.open&&opener?.closest('[data-client]')?.hidden)dialog.close()});
document.querySelectorAll('[data-open-client],#newAccount').forEach(b=>b.addEventListener('click',()=>{if(dialog.open)dialog.close()}));
retry.addEventListener('click',loadQr);copy.addEventListener('click',async()=>{const generation=serial;copy.disabled=true;try{await wppCopy(link.value,dialog);if(generation===serial)copyStatus.textContent='Ссылка скопирована — можно вставлять в приложение.'}catch(e){if(generation===serial){document.getElementById('qrLinkDetails').open=true;link.focus();link.select();copyStatus.textContent='Не удалось скопировать автоматически. Скопируйте выделенную ссылку.'}}finally{if(generation===serial)copy.disabled=false}});
dialog.addEventListener('close',()=>{++serial;clearImage();canvas.classList.remove('has-error');link.value='';endpoint='';copyStatus.textContent='';selectedRow(null);dialog.classList.remove('docked');if(opener?.isConnected&&!opener.closest('[hidden]')&&!document.querySelector('dialog:modal'))opener.focus({preventScroll:true})});
})();
</script>'''

CSS += '''
.create-dialog{width:min(760px,calc(100vw - 28px));padding:0;overflow:hidden}.create-dialog .dialog-head{padding:24px 26px 18px;margin:0;border-bottom:1px solid var(--line)}.create-dialog form{padding:22px 26px 25px;overflow:auto;max-height:calc(90dvh - 78px)}.create-step{margin-top:22px}.create-step:first-of-type{margin-top:18px}.create-step-title{display:flex;align-items:center;gap:9px;margin-bottom:11px;font-size:12px;color:var(--muted)}.create-step-title i{display:grid;place-items:center;width:22px;height:22px;border-radius:50%;background:var(--tint);color:var(--accent);font:600 11px/1 ui-monospace,monospace}.create-mode-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.choice-card{position:relative;display:flex;gap:12px;align-items:flex-start;margin:0;padding:15px;border:1px solid var(--line);border-radius:11px;background:var(--input);color:var(--text);cursor:pointer}.choice-card:hover{border-color:var(--accent)}.choice-card input{width:16px;height:16px;flex:0 0 auto;margin-top:3px;accent-color:var(--accent)}.choice-card:has(input:checked){border-color:var(--accent);background:var(--tint);box-shadow:inset 0 0 0 1px var(--accent)}.choice-card strong{display:block;font-size:13px}.choice-card small{display:block;font-size:10px;line-height:1.45;margin-top:4px}.protocol-picker{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.protocol-picker .choice-card{min-height:76px}.protocol-picker em{font:500 9px/1.5 ui-monospace,monospace;color:var(--accent);display:block;margin-top:5px}.device-row{display:grid;grid-template-columns:minmax(0,1fr) 150px;gap:14px;align-items:end}.device-row label{margin-top:0}.create-summary{display:flex;align-items:center;justify-content:space-between;gap:15px;margin-top:22px;padding:14px 15px;border:1px solid var(--line);border-radius:10px;background:var(--raised)}.create-summary span{font-size:11px;color:var(--muted)}.create-summary b{font-size:12px;text-align:right}.create-actions{position:sticky;z-index:2;bottom:-25px;justify-content:flex-end;margin-top:18px;padding:13px 0 0;background:linear-gradient(transparent,var(--surface) 18%)}.create-actions .primary{min-width:150px}.proto-mtproto{color:var(--green)}
.secret-editor{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:8px;margin:8px 0}.secret-editor input{min-width:0;font:11px ui-monospace,monospace}.secret-editor+small{display:block;margin-bottom:12px;line-height:1.5;color:var(--muted)}
.live-indicator{display:inline-flex;align-items:center;gap:7px;margin-left:auto;padding:7px 10px;border:1px solid var(--line);border-radius:8px;font-size:10px;color:var(--muted);white-space:nowrap}.live-indicator i{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 0 4px color-mix(in srgb,var(--green) 14%,transparent)}.live-indicator.stale i{background:var(--amber);box-shadow:none}.live-indicator.offline i{background:var(--red);box-shadow:none}.live-block{transition:opacity .18s ease}.live-block.refreshing{opacity:.72}
@media(max-width:620px){.create-dialog .dialog-head{padding:19px}.create-dialog form{padding:18px}.create-mode-grid,.protocol-picker{grid-template-columns:1fr}.device-row{grid-template-columns:1fr}.create-summary{align-items:flex-start;flex-direction:column}.create-actions{display:grid;grid-template-columns:1fr 1fr;bottom:-18px}.create-actions .primary{min-width:0}.secret-editor{grid-template-columns:1fr 1fr}.secret-editor input{grid-column:1/-1}}
'''


def theme_button(): return '<button type="button" class="quiet" data-theme-toggle>'+icon('sun')+'<span class="theme-label">Тёмная тема</span><i class="theme-track" aria-hidden="true"></i></button>'


def page_layout(title, body, path, active, domain):
    # Original WPP nav: 5 items (dashboard/users/nodes/updates/settings)
    # OpenFlux, landing editor, components — внутри /settings и /updates страниц
    links = ''.join(f'<a class="{"active" if key==active else ""}" href="{esc(path)}/{key}">{icon(glyph)}{label}</a>' for key, label, glyph in [('dashboard','Дашборд','grid'),('users','Пользователи','users'),('nodes','Ноды','nodes'),('updates','Обновления','refresh'),('settings','Настройки','settings')])
    social = f'''<a class="social-icon" href="https://www.youtube.com/@POLESNIESOVETI12" target="_blank" rel="noopener noreferrer" aria-label="YouTube автора" title="YouTube">{icon('youtube')}</a><a class="social-icon" href="https://github.com/POLESNIESOVETI12/web-panel-proxy" target="_blank" rel="noopener noreferrer" aria-label="GitHub проекта" title="GitHub">{icon('github')}</a>'''
    banner = f'''<aside id="releaseBanner" class="release-banner" role="status" hidden><span class="release-banner-mark">{icon('refresh')}</span><div class="release-banner-copy"><b>Доступна новая версия WEB PANEL PROXY</b><small>Обновление можно установить с автоматической резервной копией</small></div><span id="releaseBannerVersion" class="release-banner-version"></span><div class="release-banner-actions"><a class="btn primary" href="{esc(path)}/updates">Посмотреть</a><button type="button" id="releaseBannerClose" class="release-banner-close" aria-label="Скрыть уведомление">×</button></div></aside>'''
    banner_script = f'''<script>(()=>{{const banner=document.getElementById('releaseBanner'),version=document.getElementById('releaseBannerVersion'),close=document.getElementById('releaseBannerClose');if(!banner)return;function dismissed(v){{try{{return localStorage.getItem('wpp-release-banner:'+v)==='1'}}catch(e){{return false}}}}function show(d){{if(!d||!d.available||!d.latest||dismissed(d.latest)){{banner.hidden=true;return}}banner.dataset.version=d.latest;version.textContent=(d.current||'—')+' → '+d.latest;banner.hidden=false}}async function check(){{try{{const r=await fetch('{esc(path)}/update-status',{{cache:'no-store'}});if(r.ok&&!r.redirected)show(await r.json())}}catch(e){{}}}}close.addEventListener('click',()=>{{const v=banner.dataset.version;if(v)try{{localStorage.setItem('wpp-release-banner:'+v,'1')}}catch(e){{}}banner.hidden=true}});window.addEventListener('wpp-update-status',e=>show(e.detail));check();setInterval(check,30000)}})();</script>'''
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} · WPP</title>{THEME_INIT}<style>{CSS}</style></head><body><div class="app"><div class="workspace"><header class="appbar"><div class="appbar-left"><a class="mini-brand" href="{esc(path)}/dashboard" aria-label="WEB PANEL PROXY"><img src="{esc(path)}/__logo" alt="" width="38" height="38"></a><div class="host"><i></i>{esc(domain)}</div></div><nav class="topnav" aria-label="Разделы панели">{links}</nav><div class="appbar-tools">{theme_button()}{social}<a class="logout" href="{esc(path)}/logout" aria-label="Выйти">{icon('logout')}<span>Выйти</span></a></div></header>{banner}<main>{body}</main></div></div>{COMMON_JS}{banner_script}</body></html>'''


def login_ui(path):
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Вход · WPP</title>{THEME_INIT}<style>{CSS}</style></head><body class="login-page"><div class="login-theme">{theme_button()}</div><main class="login-card"><img class="signin-logo" src="{esc(path)}/__logo" alt="WPP"><h1>WEB PANEL PROXY</h1><p>Панель управления подключениями</p><form method="post" action="{esc(path)}/login"><label for="loginName">Логин</label><input id="loginName" name="user" autocomplete="username" required autofocus><label for="loginPassword">Пароль</label><input id="loginPassword" type="password" name="password" autocomplete="current-password" required><button class="primary">Войти</button></form><small class="login-version">{VERSION}</small></main>{COMMON_JS}</body></html>'''



def hidden(csrf, **values):
    return ''.join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">' for k,v in {'csrf':csrf, **values}.items())


def aggregate(ids, traffic, enabled=True):
    rows = [traffic.get(uid, {}) for uid in ids]
    return {'up': sum(max(0,int(r.get('up',0))) for r in rows), 'down': sum(max(0,int(r.get('down',0))) for r in rows),
            'active': enabled and any(r.get('service_active') and 0 <= time.time()-r.get('last_change',0) <= 90 for r in rows)}


def badge(active, enabled=True):
    return '<span class="badge '+('on' if active and enabled else '')+'">'+('Отключена' if not enabled else 'Передаёт трафик' if active else 'Нет трафика')+'</span>'


def protocol_checks(sub):
    choices=[('vless','VLESS XHTTP'),('hysteria','Hysteria2')]
    return '<div class="checks">'+''.join(f'<label class="check"><input type="checkbox" name="{p}" value="1" {"checked" if p in sub.get("protocols",["vless","hysteria"]) else ""}>{title}</label>' for p,title in choices)+'</div>'


def subscription_card(sub, path, domain, csrf, traffic, compact=False):
    sid = sub['id']; enabled = sub.get('enabled', True)
    total = aggregate(sub.get('profile_ids',[]), traffic, enabled)
    total['active'] = aggregate(sub.get('live_profile_ids', []), traffic, enabled)['active']
    url = 'https://'+domain+'/wpp-sub/'+sub['token']
    count = sum(not d.get('revoked') for d in sub['devices'])
    limit = str(count)+' / '+str(sub['max_devices']) if sub['max_devices'] else 'Без лимита'
    names={'vless':'VLESS','hysteria':'Hysteria2'}
    head = f'''<div class="account-head"><div class="identity"><div class="avatar">{icon('link')}</div><div><h3>{esc(sub['name'])}</h3><div class="pills"><span class="pill">Подписка</span>{''.join('<span class="pill">'+names.get(p,p)+'</span>' for p in sub['protocols'])}</div></div></div>{badge(total['active'],enabled)}</div><div class="account-metrics"><div><span>Устройства · HWID</span><b>{limit}</b></div><div><span>Трафик: {size(total['up']+total['down'])}</span><b>↑ {size(total['up'])} · ↓ {size(total['down'])}</b></div></div>'''
    buttons = f'<div class="actions"><button class="btn primary" data-copy="{esc(url)}">Скопировать подписку</button>'
    if compact:
        return f'<article class="account">{head}{buttons}<a class="btn" href="{esc(path)}/users#account-{esc(sid)}">Управление</a></div></article>'
    buttons += '<button '+qr_attributes(path+'/subscription-qr?'+urlencode({'id':sid}),sub['name'],url,sub['protocols'],'subscription')+'>QR</button></div>'
    def action(op, text, device=None, confirm=''):
        fields = {'operation':op,'id':sid}
        if device: fields['device_id']=device
        return f'<form method="post" action="{esc(path)}/subscription-action"'+(f' data-confirm="{esc(confirm)}"' if confirm else '')+'>'+hidden(csrf,**fields)+f'<button class="{"danger" if op in ("delete","rotate","revoke") else "quiet"}">{text}</button></form>'
    devices = []
    for d in sub['devices']:
        seen = time.strftime('%d.%m %H:%M UTC',time.gmtime(d.get('last_seen',0))) if d.get('last_seen') else '—'
        devices.append('<div class="device"><div><b>'+esc(d['name'])+'</b><small>'+('Отозвано' if d.get('revoked') else 'Разрешено')+' · обновление '+seen+'</small></div>'+action('allow' if d.get('revoked') else 'revoke','Разрешить' if d.get('revoked') else 'Отозвать',d['id'])+'</div>')
    details = f'''<details><summary>Настройки и устройства</summary><label>Ссылка подписки</label><input class="sub-url" value="{esc(url)}" readonly aria-label="Ссылка подписки {esc(sub['name'])}"><form method="post" action="{esc(path)}/subscription-action">{hidden(csrf,operation='update',id=sid)}<div class="form-grid"><div><label>Имя пользователя</label><input name="name" value="{esc(sub['name'])}" required maxlength="80"></div><div><label>Лимит HWID · 0 без привязки</label><input type="number" name="max_devices" min="0" max="20" value="{sub['max_devices']}" required></div></div>{protocol_checks(sub)}<button class="primary">Сохранить настройки</button></form><p class="note">Переход между 0 и ненулевым лимитом отзывает прежние ключи. Время обновления подписки не означает присутствие устройства онлайн.</p>{''.join(devices) or '<p class="muted">Устройства появятся после импорта подписки.</p>'}<div class="actions">{action('toggle','Отключить' if enabled else 'Включить')}{action('rotate','Сменить ссылку',confirm='Сменить ссылку и отозвать ключи всех устройств?')}{action('delete','Удалить',confirm='Удалить подписку и отозвать все её ключи?')}</div></details>'''
    return f'<article class="account" id="account-{esc(sid)}" data-account data-kind="subscription" data-name="{esc(sub["name"].lower())}">{head}{buttons}{details}</article>'


def direct_card(user, path, csrf, traffic, proxy_link, compact=False):
    uid=user['id']; proto=user.get('protocol','web'); port=int(user.get('backend_port',443))
    label={'web':'WEB Proxy','vless':'VLESS XHTTP','hysteria':'Hysteria2','mtproto':'MTProto','awg20':'AWG 2.0','awg31':'AWG 3.1'}.get(proto,proto)
    total=aggregate([uid],traffic,user.get('enabled',True))
    device_secrets=user.get('device_secrets') if proto=='mtproto' else None
    if not isinstance(device_secrets,list) or not device_secrets: device_secrets=[user['secret']]
    link=proxy_link(proto,device_secrets[0],port,user.get('name','Proxy'),user.get('username',''))
    qr=(path+'/__qr?'+urlencode({'id':uid}) if proto in ('awg20','awg31') else
        path+'/__qr?'+urlencode({'secret':user['secret'],'protocol':proto,
            'port':port if proto in ('hysteria','mtproto') else 443}))
    buttons=f'<button class="primary" data-copy="{esc(link)}">'+('Скопировать конфигурацию' if proto in ('awg20','awg31') else 'Скопировать ссылку')+'</button>'
    if not compact: buttons+='<button '+qr_attributes(qr,user['name'],link,[proto],user_port=port)+'>QR</button>'
    else: buttons+=f'<a class="btn" href="{esc(path)}/users#account-{esc(uid)}">Управление</a>'
    details=''
    if not compact:
        removal='<small>Основное подключение установки</small>' if uid=='primary' else f'<form method="post" action="{esc(path)}/delete-user" data-confirm="Удалить это подключение?">{hidden(csrf,id=uid)}<button class="danger">Удалить подключение</button></form>'
        secret_editor=''
        if proto in ('web','mtproto'):
            secret_editor=f'''<form method="post" action="{esc(path)}/client-action" data-client-action data-client-confirm="После сохранения прежний секрет сразу перестанет работать. Продолжить?">{hidden(csrf,id=uid,kind='direct',operation='secret')}<label for="secret-{esc(uid)}">Секрет {esc(label)}</label><div class="secret-editor"><input id="secret-{esc(uid)}" name="secret" type="password" value="{esc(user['secret'])}" minlength="32" maxlength="34" pattern="(?:dd)?[0-9A-Fa-f]{{32}}" autocomplete="off" spellcheck="false" required><button type="button" data-secret-reveal="secret-{esc(uid)}">Показать</button><button class="primary">Сохранить</button></div><small>32 символа 0–9, a–f. Для MTProto можно вставить секрет из Telegram с префиксом dd. Порт подключения не изменяется.</small><p data-form-status role="status"></p></form>'''
        value_title='Конфигурация AWG' if proto in ('awg20','awg31') else 'Ссылка подключения'
        value_control=f'<textarea class="sub-url" readonly rows="8" aria-label="{value_title} {esc(user["name"])}">{esc(link)}</textarea>' if proto in ('awg20','awg31') else f'<input class="sub-url" value="{esc(link)}" readonly aria-label="Ссылка {esc(user["name"])}">'
        if proto=='mtproto':
            device_rows=[]
            for index,secret in enumerate(device_secrets,1):
                device_link=proxy_link('mtproto',secret,port,user.get('name','MTProto')+' · '+str(index),'')
                device_qr=path+'/__qr?'+urlencode({'secret':secret,'protocol':'mtproto','port':port})
                device_rows.append(f'<div class="mtproto-device"><div><b>Устройство {index}</b><small>Отдельный ключ доступа</small></div><button type="button" data-copy="{esc(device_link)}">Скопировать</button><button type="button" '+qr_attributes(device_qr,user.get('name','MTProto')+' · устройство '+str(index),device_link,['mtproto'],user_port=port)+'>QR</button></div>')
            value_control=f'<div class="mtproto-access-head"><span>TCP-порт</span><b>{port}</b><small>Открыт панелью в firewall</small></div><div class="mtproto-devices">{"".join(device_rows)}</div>'
        download=f'<a class="btn" href="{esc(path)}/awg-config?{urlencode({"id":uid})}">Скачать .conf</a>' if proto in ('awg20','awg31') else ''
        access_note=(f'{len(device_secrets)} отдельных ключей устройств · Telegram не передаёт серверу HWID' if proto=='mtproto' else 'Отдельное подключение · без ограничения устройств')
        details=f'<details><summary>Параметры подключения</summary><p class="muted">{access_note}</p>{value_control}{download}{secret_editor}{removal}</details>'
    return f'''<article class="account" id="account-{esc(uid)}" data-account data-kind="direct" data-name="{esc(user['name'].lower())}"><div class="account-head"><div class="identity"><div class="avatar">{icon('users')}</div><div><h3>{esc(user['name'])}</h3><div class="pills"><span class="pill">{esc(label)}</span><span class="pill">Отдельная ссылка</span></div></div></div>{badge(total['active'],user.get('enabled',True))}</div><div class="account-metrics"><div><span>Получено</span><b>{size(total['down'])}</b></div><div><span>Отправлено</span><b>{size(total['up'])}</b></div><div><span>Всего</span><b>{size(total['up']+total['down'])}</b></div></div><div class="actions">{buttons}</div>{details}</article>'''


def live_subscriptions(subs, profiles):
    # Keep historical traffic, but never report a revoked profile as active.
    return [dict(s, live_profile_ids=[u['id'] for u in profiles
                 if u.get('subscription_id') == s['id'] and u.get('enabled', True)]) for s in subs]


def client_records(subs, profiles, traffic, domain, proxy_link):
    records=[]
    for s in live_subscriptions(subs,profiles):
        totals=aggregate(s.get('profile_ids',[]),traffic,s.get('enabled',True))
        totals['active']=aggregate(s['live_profile_ids'],traffic,s.get('enabled',True))['active']
        records.append(dict(id=s['id'],name=s['name'],kind='subscription',protocols=s['protocols'],
            enabled=s.get('enabled',True),created=s.get('created_at',0),totals=totals,
            link='https://'+domain+'/wpp-sub/'+s['token'],source=s,
            devices=sum(not d.get('revoked') for d in s['devices']),limit=s['max_devices']))
    for u in profiles:
        if u.get('subscription_id'): continue
        proto=u.get('protocol','web')
        # Old experimental builds could leave Mieru or NaiveProxy records in
        # users.json. Preserve them for rollback without rendering them.
        if proto not in {'web','vless','hysteria','mtproto','awg20','awg31'}:
            continue
        try:
            link=proxy_link(proto,u['secret'],int(u.get('backend_port',443)),u['name'],u.get('username',''))
        except (KeyError, TypeError, ValueError, RuntimeError):
            continue
        mt_devices=u.get('device_secrets') if proto=='mtproto' else None
        if proto=='mtproto' and (not isinstance(mt_devices,list) or not mt_devices): mt_devices=[u.get('secret','')]
        records.append(dict(id=u['id'],name=u['name'],kind='direct',protocols=[proto],
            enabled=u.get('enabled',True),created=u.get('created_at',0),totals=aggregate([u['id']],traffic,u.get('enabled',True)),
            link=link,source=u,devices=len(mt_devices) if proto=='mtproto' else None,
            limit=len(mt_devices) if proto=='mtproto' else None))
    return records


def client_protocols(protocols):
    names={'web':'WEB Proxy','vless':'VLESS XHTTP','hysteria':'Hysteria2','mtproto':'MTProto','awg20':'AWG 2.0','awg31':'AWG 3.1','openflux':'OpenFlux'}
    return '<div class="pills">'+''.join('<span class="pill proto-'+esc(p)+'">'+esc(names.get(p,p))+'</span>' for p in protocols)+'</div>'


def client_summary(records):
    counts=[('Всего',len(records)),('Передают данные',sum(bool(r['totals']['active']) for r in records)),
            ('Подписки',sum(r['kind']=='subscription' for r in records)),
            ('Трафик',size(sum(r['totals']['up']+r['totals']['down'] for r in records)))]
    return '<div class="clients-summary">'+''.join(f'<div class="client-stat"><span>{label}</span><b>{value}</b></div>' for label,value in counts)+'</div>'


def client_glances(records,path):
    rows=[]
    for r in records:
        t=r['totals']; kind='Подписка' if r['kind']=='subscription' else 'Отдельная ссылка'
        rows.append(f'<div class="client-glance"><div><strong>{esc(r["name"])}</strong><small>{kind}</small></div>{client_protocols(r["protocols"])}<div class="traffic-value">{size(t["up"]+t["down"])}</div><a class="btn quiet" href="{esc(path)}/users#account-{esc(r["id"])}">Управление ↗</a></div>')
    return '<div class="dashboard-clients">'+(''.join(rows) or '<p class="empty">Клиентов пока нет</p>')+'</div>'


def openflux_profiles_ui(profiles, path, csrf):
    cards=[]
    for profile in profiles:
        pid=profile['id']; ios=profile.get('platform')=='ios'; active=profile.get('active',False)
        platform='iOS' if ios else 'Android'
        transport=profile.get('transport','yandex')
        provider='Mail.ru Docs' if transport=='mailru' else 'Яндекс Документы'
        key='' if ios else f'''<div class="flux-profile-secret"><span>Ключ</span><input value="{esc(profile.get('key',''))}" readonly type="password" aria-label="Ключ OpenFlux — {esc(profile.get('name',''))}"><button type="button" data-copy="{esc(profile.get('key',''))}">{icon('copy')}</button></div>'''
        controls=f'''<form method="post" action="{esc(path)}/openflux-profile">{hidden(csrf,operation='disable' if profile.get('enabled') else 'enable',id=pid)}<button>{'Остановить' if profile.get('enabled') else 'Запустить'}</button></form>'''
        if not ios:
            controls+=f'''<form method="post" action="{esc(path)}/openflux-profile" data-confirm="Создать новый ключ для этого Android-профиля?">{hidden(csrf,operation='rotate',id=pid)}<button>Новый ключ</button></form>'''
        controls+=f'''<form method="post" action="{esc(path)}/openflux-profile" data-confirm="Удалить профиль OpenFlux «{esc(profile.get('name',''))}» и остановить его службу?">{hidden(csrf,operation='delete',id=pid)}<button class="danger">Удалить</button></form>'''
        cards.append(f'''<article class="flux-profile"><div class="flux-profile-head"><span class="flux-platform">{platform}</span><div><h3>{esc(profile.get('name','OpenFlux'))}</h3><small>{esc(provider)} · {'без AES · System VPN' if ios else 'AES-256-GCM'} · batched</small></div><span class="badge {'on' if active else ''}">{'Работает' if active else 'Остановлен'}</span></div><div class="flux-profile-secret"><span>{esc(provider)}</span><input value="{esc(profile.get('url',''))}" readonly aria-label="Документ OpenFlux — {esc(profile.get('name',''))}"><button type="button" data-copy="{esc(profile.get('url',''))}">{icon('copy')}</button></div>{key}<div class="actions">{controls}</div></article>''')
    empty='<div class="flux-empty"><b>Профилей пока нет</b><span>Создайте отдельный доступ для iPhone, iPad или Android.</span></div>'
    return f'''<section class="openflux-users"><div class="section-head"><div><span class="eyebrow">DOCUMENT TUNNEL</span><h2>Пользователи OpenFlux</h2><p>Яндекс или Mail.ru · каждому пользователю отдельный документ</p></div><button class="primary" type="button" data-open-dialog="newOpenFlux">＋ Добавить</button></div><div class="flux-profile-grid">{''.join(cards) if cards else empty}</div></section><dialog id="newOpenFlux" class="create-dialog"><div class="dialog-head"><div><h2>Новый профиль OpenFlux</h2><small>Используйте отдельный публичный документ</small></div><button type="button" data-close-dialog>×</button></div><form method="post" action="{esc(path)}/openflux-profile">{hidden(csrf,operation='create')}<label>Имя пользователя</label><input name="name" maxlength="80" required placeholder="Например, iPhone Анны"><label>Транспорт</label><div class="create-mode-grid flux-platform-picker"><label class="choice-card"><input type="radio" name="transport" value="yandex" checked><span><strong>Яндекс Документы</strong><small>Публичная ссылка disk.yandex.ru</small></span></label><label class="choice-card"><input type="radio" name="transport" value="mailru"><span><strong>Mail.ru Документы</strong><small>Публичная ссылка cloud.mail.ru</small></span></label></div><label>Ссылка на публичный документ</label><input name="url" type="url" maxlength="2048" required placeholder="https://disk.yandex.ru/i/… или https://cloud.mail.ru/public/…"><label>Устройство</label><div class="create-mode-grid flux-platform-picker"><label class="choice-card"><input type="radio" name="platform" value="ios" checked><span><strong>iOS</strong><small>iPhone и iPad · без AES-ключа</small></span></label><label class="choice-card"><input type="radio" name="platform" value="android"><span><strong>Android</strong><small>AES-256-GCM · ссылка и ключ</small></span></label></div><p class="note">Один документ нельзя одновременно использовать в нескольких активных профилях. В приложении выберите тот же транспорт, что и в панели.</p><div class="actions create-actions"><button type="button" data-close-dialog>Отмена</button><button class="primary">Создать профиль</button></div></form></dialog>'''


def openflux_create_dialog(path, csrf):
    markup = openflux_profiles_ui([], path, csrf)
    return markup[markup.index('<dialog id="newOpenFlux"'):]


def users_ui(subs, profiles, traffic, path, domain, csrf, proxy_link, openflux_profiles=None):
    records=client_records(subs,profiles,traffic,domain,proxy_link)
    rows=[]; dialogs=[]
    for r in records:
        uid=r['id']; sid=esc(uid); name=esc(r['name']); t=r['totals']; enabled=r['enabled']; total=t['up']+t['down']
        primary=uid=='primary'; kind=r['kind']; sub=kind=='subscription'
        proto=r['protocols'][0]
        qr=(path+'/subscription-qr?'+urlencode({'id':uid}) if sub else
            path+'/__qr?'+urlencode({'id':uid}) if proto in ('awg20','awg31') else
            path+'/__qr?'+urlencode({'secret':r['source']['secret'],'protocol':proto,
                'port':r['source'].get('backend_port',443) if proto in ('hysteria','mtproto') else 443}))
        disabled='disabled title="Основное подключение установки"' if primary else ''
        state=f'<button class="access-switch" type="button" role="switch" aria-label="Доступ — {name}" aria-checked="{str(bool(enabled)).lower()}" data-state="{sid}" data-kind="{kind}" {disabled}></button>'
        action=f'<button class="icon-btn" {qr_attributes(qr,r["name"],r["link"],r["protocols"],kind,user_port=r["source"].get("backend_port"))} aria-label="QR — {name}" title="QR">{icon("qr")}</button><button class="icon-btn" data-copy="{esc(r["link"])}" aria-label="Скопировать — {name}" title="Копировать">{icon("copy")}</button><button class="icon-btn" data-open-client="{sid}" aria-label="Настройки — {name}" title="Настройки">{icon("edit")}</button>'
        if not primary:
            route='subscription-action' if sub else 'delete-user'
            action+=f'<form method="post" action="{esc(path)}/{route}" data-confirm="Удалить клиента {name} и его ключи?">{hidden(csrf,id=uid,**({"operation":"delete"} if sub else {}))}<button class="icon-btn danger" aria-label="Удалить — {name}" title="Удалить">{icon("trash")}</button></form>'
        used=(str(r['devices'])+' / '+str(r['limit'])) if r['limit'] else 'Без лимита' if sub else '—'
        device_hint='HWID' if r['limit'] else 'Без привязки' if sub else 'Отдельная ссылка'
        share=t['up']/total*100 if total else 0
        split=f'<div class="traffic-split" title="Доля отправки и получения, не лимит"><i class="up" style="width:{share:.2f}%"></i><i class="down" style="width:{100-share if total else 0:.2f}%"></i></div>'
        rows.append(f'''<tr data-client data-id="{sid}" data-kind="{kind}" data-protocols="{esc(' '.join(r['protocols']))}" data-name="{name}" data-enabled="{int(bool(enabled))}" data-active="{int(bool(t['active']))}" data-created="{int(r['created'])}" data-traffic="{int(total)}" data-link="{esc(r['link'])}"><td class="select-col"><input type="checkbox" data-select-client aria-label="Выбрать — {name}" {'disabled' if primary else ''}></td><td class="client-name" data-label="Клиент"><div class="client-identity"><span class="client-initial" aria-hidden="true">{esc(r['name'].strip()[:1].upper() or '•')}</span><div><strong>{name}</strong><small>{'Подписка' if sub else 'Основное подключение' if primary else 'Отдельная ссылка'}</small>{badge(t['active'],enabled)}</div></div></td><td class="state-col" data-label="Доступ">{state}</td><td class="activity-col" data-label="Активность">{badge(t['active'],enabled)}</td><td class="protocol-col" data-label="Протоколы">{client_protocols(r['protocols'])}</td><td class="traffic-cell" data-label="Трафик"><b>{size(total)}</b><small>↑ {size(t['up'])} · ↓ {size(t['down'])}</small>{split}</td><td class="hwid-cell" data-label="Устройства">{used}<small>{device_hint}</small></td><td class="actions-col" data-label="Действия"><div class="row-actions">{action}</div></td></tr>''')
        detail=subscription_card(r['source'],path,domain,csrf,traffic) if sub else direct_card(r['source'],path,csrf,traffic,proxy_link)
        detail=detail.replace('<details>','<details open>')
        if not sub and not primary:
            rename=f'<form method="post" action="{esc(path)}/client-action" data-client-action>{hidden(csrf,id=uid,kind=kind,operation="rename")}<label for="rename-{sid}">Имя клиента</label><input id="rename-{sid}" name="name" value="{name}" required maxlength="80"><button style="margin:12px 0" class="primary">Сохранить имя</button><p data-form-status role="status"></p></form>'
            detail=detail.replace('<details open>','<details open>'+rename,1)
        dialogs.append(f'<dialog class="client-detail" id="client-{sid}"><div class="dialog-head"><h2>Профиль клиента</h2><button data-close-dialog aria-label="Закрыть профиль">×</button></div>{detail}{admin_user_actions(r["source"], path, csrf)}</dialog>')
    flux_profiles=openflux_profiles or []
    for profile in flux_profiles:
        pid=str(profile.get('id','')); sid=esc('openflux-'+pid); name=esc(profile.get('name','OpenFlux'))
        enabled=bool(profile.get('enabled',True)); active=bool(profile.get('active',False)); ios=profile.get('platform')=='ios'
        platform='iOS' if ios else 'Android'; transport=profile.get('transport','yandex')
        provider='Mail.ru' if transport=='mailru' else 'Яндекс'; created=int(profile.get('created_at',0) or 0)
        document_url=str(profile.get('url') or '')
        state=f'''<form method="post" action="{esc(path)}/openflux-profile">{hidden(csrf,operation='disable' if enabled else 'enable',id=pid)}<button class="access-switch" type="submit" role="switch" aria-label="Доступ OpenFlux — {name}" aria-checked="{str(enabled).lower()}" title="{'Остановить' if enabled else 'Запустить'} OpenFlux"></button></form>'''
        qr=esc(path)+'/openflux-qr?'+urlencode({'id':pid})
        action=f'''<button class="icon-btn" {qr_attributes(qr,profile.get('name','OpenFlux'),document_url,['openflux'],'direct')} aria-label="QR ссылки — {name}" title="QR ссылки на документ">{icon('qr')}</button><button class="icon-btn" data-copy="{esc(document_url)}" aria-label="Скопировать ссылку — {name}" title="Копировать ссылку на документ">{icon('copy')}</button><form method="post" action="{esc(path)}/openflux-profile" data-confirm="Удалить профиль OpenFlux «{name}» и остановить его службу?">{hidden(csrf,operation='delete',id=pid)}<button class="icon-btn danger" aria-label="Удалить — {name}" title="Удалить">{icon('trash')}</button></form>'''
        rows.append(f'''<tr data-client data-id="{sid}" data-kind="openflux" data-protocols="openflux" data-name="{name}" data-enabled="{int(enabled)}" data-active="{int(active)}" data-created="{created}" data-traffic="0" data-link="{esc(document_url)}"><td class="select-col"><input type="checkbox" data-select-client aria-label="OpenFlux управляется отдельно" disabled></td><td class="client-name" data-label="Клиент"><div class="client-identity"><span class="client-initial" aria-hidden="true">OF</span><div><strong>{name}</strong><small>Отдельное подключение · {esc(platform)}</small>{badge(active,enabled)}</div></div></td><td class="state-col" data-label="Доступ">{state}</td><td class="activity-col" data-label="Активность">{badge(active,enabled)}</td><td class="protocol-col" data-label="Протоколы">{client_protocols(['openflux'])}</td><td class="traffic-cell" data-label="Трафик"><b>—</b><small>Счётчики OpenFlux недоступны</small></td><td class="hwid-cell" data-label="Устройства">{esc(platform)}<small>{esc(provider)} Docs</small></td><td class="actions-col" data-label="Действия"><div class="row-actions">{action}</div></td></tr>''')
    summary_records=records+[{'kind':'direct','totals':{'active':bool(p.get('active',False)),'up':0,'down':0}} for p in flux_profiles]
    controls='''<div class="clients-toolbar"><div class="search-field">'''+icon('search')+'''<input type="search" id="accountSearch" aria-label="Поиск клиентов" placeholder="Поиск клиентов"></div><select id="clientFilter" aria-label="Фильтр клиентов"><option value="all">Все клиенты</option><option value="subscription">Подписки</option><option value="direct">Отдельные подключения</option><option value="openflux">OpenFlux</option><option value="active">Передают данные</option><option value="enabled">Доступ включён</option><option value="disabled">Отключены</option></select><select id="protocolFilter" aria-label="Фильтр протоколов"><option value="all">Все протоколы</option><option value="web">WEB Proxy</option><option value="mtproto">MTProto</option><option value="vless">VLESS XHTTP</option><option value="hysteria">Hysteria2</option><option value="awg20">AWG 2.0</option><option value="awg31">AWG 3.1</option><option value="openflux">OpenFlux</option></select><select id="clientSort" aria-label="Сортировка клиентов"><option value="default">По порядку</option><option value="name">По имени</option><option value="traffic">По трафику</option><option value="active">По активности</option><option value="newest">Сначала новые</option></select></div>'''
    content=f'''<div class="page-head"><div><h1>Клиенты</h1><p>Доступ, подписки и OpenFlux</p></div><div class="actions"><button id="reloadClients" aria-label="Обновить список">{icon('refresh')}</button><button class="primary" id="newAccount">＋ Добавить клиента</button></div></div>{client_summary(summary_records)}<p id="clientNotice" class="note" role="status" hidden></p><section class="clients-panel">{controls}<div id="bulkBar" class="bulk-bar" hidden><strong id="selectedCount"></strong><button data-bulk="1">Включить</button><button data-bulk="0">Отключить</button><button id="copySelected">Копировать ссылки</button><button id="clearSelected">Снять выбор</button></div><div class="table-scroll"><table class="clients-table"><thead><tr><th class="select-col"><input type="checkbox" id="selectAllClients" aria-label="Выбрать видимых клиентов"></th><th>Клиент</th><th>Доступ</th><th class="activity-col">Активность · 90 с</th><th>Протоколы</th><th>Трафик</th><th class="hwid-cell">Устройства</th><th>Действия</th></tr></thead><tbody id="clientRows">{''.join(rows)}</tbody></table><p id="noAccounts" class="empty" hidden>Ничего не найдено. Измените поиск или фильтр.</p></div><div class="list-footer"><span id="visibleCount"></span><span>↑ Отправка · ↓ Получение · OpenFlux показывает состояние службы</span></div></section><details class="note client-help"><summary>Что означают доступ, активность и HWID?</summary><p>Переключатель управляет разрешением доступа, а активность означает передачу данных за последние 90 секунд — не точное присутствие онлайн. Для OpenFlux показывается состояние отдельной службы профиля.</p><p>Лимит HWID ограничивает регистрацию идентификаторов клиента. HWID и ключ можно скопировать: это не аппаратная защита. Квоты гигабайтов и срок действия здесь не настроены. Основное подключение установки защищено от отключения и удаления.</p><p>Изменение доступа может кратковременно перезапустить службы. При массовом действии клиенты обрабатываются последовательно; OpenFlux управляется отдельно своим переключателем.</p></details>'''
    creation=f'''<dialog id="createAccount" class="create-dialog"><div class="dialog-head"><div><h2>Новый клиент</h2><small>Настройте доступ за два понятных шага</small></div><button type="button" data-close-dialog aria-label="Закрыть">×</button></div><form id="createClientForm" method="post" action="{esc(path)}/create-account">{hidden(csrf)}<input type="hidden" id="accountKind" name="kind" value="subscription"><label for="accountName">Имя клиента</label><input id="accountName" name="name" placeholder="Например, Александр или Телефон" maxlength="80" required autocomplete="off"><section class="create-step"><div class="create-step-title"><i>1</i><span>Как клиент будет получать доступ?</span></div><div class="create-mode-grid"><label class="choice-card"><input type="radio" name="access_mode" value="subscription" checked><span><strong>Одна подписка</strong><small>Одна ссылка для проверенных VLESS и Hysteria2.</small></span></label><label class="choice-card"><input type="radio" name="access_mode" value="direct"><span><strong>Отдельное подключение</strong><small>WEB Proxy, MTProto или один выбранный VPN-протокол.</small></span></label></div></section><section class="create-step" id="subscriptionFields"><div class="create-step-title"><i>2</i><span>Выберите протоколы подписки</span></div><div class="protocol-picker"><label class="choice-card"><input type="checkbox" name="vless" value="1" checked><span><strong>VLESS XHTTP</strong><small>TLS через домен · TCP 443</small><em>УНИВЕРСАЛЬНЫЙ</em></span></label><label class="choice-card"><input type="checkbox" name="hysteria" value="1" checked><span><strong>Hysteria2</strong><small>Быстрый QUIC · UDP 8443</small><em>ДЛЯ НЕСТАБИЛЬНЫХ СЕТЕЙ</em></span></label></div><div class="device-row"><p class="note">Лимит HWID относится к подписке. Значение 0 создаёт общую подписку без привязки.</p><div><label for="deviceLimit">Устройств</label><input id="deviceLimit" name="max_devices" type="number" min="0" max="20" value="2" inputmode="numeric"></div></div></section><section class="create-step" id="directFields" hidden><div class="create-step-title"><i>2</i><span>Выберите один протокол</span></div><div class="protocol-picker"><label class="choice-card"><input type="radio" name="direct_protocol" value="web" checked><span><strong>WEB Proxy</strong><small>Готовая ссылка для Telegram через HTTPS</small></span></label><label class="choice-card"><input type="radio" name="direct_protocol" value="mtproto"><span><strong>MTProto</strong><small>Прямое подключение Telegram · отдельный TCP-порт</small></span></label><label class="choice-card"><input type="radio" name="direct_protocol" value="vless"><span><strong>VLESS XHTTP</strong><small>TLS через домен · TCP 443</small></span></label><label class="choice-card"><input type="radio" name="direct_protocol" value="hysteria"><span><strong>Hysteria2</strong><small>QUIC · UDP 8443</small></span></label><label class="choice-card"><input type="radio" name="direct_protocol" value="awg20"><span><strong>AWG 2.0</strong><small>Совместимость с роутерами и прежними клиентами · уникальный UDP-порт</small><em>ОТДЕЛЬНЫЙ ОТПЕЧАТОК</em></span></label><label class="choice-card"><input type="radio" name="direct_protocol" value="awg31"><span><strong>AWG 3.1</strong><small>Защита заголовков и дополнительное заполнение · безопасный MTU</small><em>РЕКОМЕНДУЕТСЯ</em></span></label></div><p class="note">Каждый AWG-клиент получает собственные ключи, порт, подсеть и параметры маскировки. Если у провайдера VPS есть облачный firewall, разрешите показанный UDP-порт.</p></section><div class="create-summary"><span>Будет создано</span><b id="createSummary">Подписка · VLESS XHTTP + Hysteria2 · 2 устройства</b></div><div class="actions create-actions"><button type="button" data-close-dialog>Отмена</button><button class="primary" id="createClientSubmit">Создать клиента</button></div></form></dialog>'''
    creation=creation.replace('type="radio" name="hysteria"','type="radio" name="direct_protocol" value="hysteria"')
    creation=creation.replace('<label class="choice-card"><input type="checkbox" name="web" value="1"><span><strong>WEB Proxy</strong><small>Telegram через HTTPS · отдельный секрет устройству</small><em>С ЛИМИТОМ HWID</em></span></label>','')
    creation=creation.replace('Одна ссылка для VPN и WEB Proxy с общим лимитом устройств.','Одна ссылка для VLESS и Hysteria2 с общим лимитом устройств.')
    creation=creation.replace('Лимит работает по X-HWID и распространяется на все выбранные протоколы, включая WEB Proxy.','Лимит работает по X-HWID для VLESS и Hysteria2.')
    creation=creation.replace('Для ограничения WEB Proxy выберите «Одна подписка» и отметьте WEB Proxy. ','')
    creation=f'''<dialog id="createAccount" class="create-dialog"><div class="dialog-head"><div><h2>Новый доступ</h2><small>Выберите, что получит клиент</small></div><button type="button" data-close-dialog aria-label="Закрыть">×</button></div><form id="createClientForm" method="post" action="{esc(path)}/create-account">{hidden(csrf)}<input type="hidden" id="accountKind" name="kind" value="subscription"><div class="access-kind-grid"><label class="choice-card"><input type="radio" name="access_mode" value="subscription" checked><span><strong>Подписка</strong><small>Несколько протоколов в одной ссылке</small><span class="compatible-protocols"><i>VLESS</i><i>Hysteria2</i></span></span></label><label class="choice-card"><input type="radio" name="access_mode" value="direct"><span><strong>Отдельное подключение</strong><small>Один протокол или сервис для конкретного устройства</small><span class="compatible-protocols"><i>VPN</i><i>Telegram</i><i>OpenFlux</i></span></span></label></div><section class="create-step"><label for="accountName">Имя клиента или устройства</label><input id="accountName" name="name" placeholder="Например, Анна или Apple TV" maxlength="80" required autocomplete="off"></section><section class="create-step" id="subscriptionFields"><div class="create-step-title"><i>1</i><span>Протоколы подписки</span></div><div class="protocol-picker"><label class="choice-card"><input type="checkbox" name="vless" value="1" checked><span><strong>VLESS XHTTP</strong><small>Универсальное TLS-подключение</small></span></label><label class="choice-card"><input type="checkbox" name="hysteria" value="1" checked><span><strong>Hysteria2</strong><small>Быстрое подключение через QUIC</small></span></label></div><div class="device-row"><p class="note">Одна ссылка для выбранных протоколов и всех подключённых нод.</p><div><label for="deviceLimit">Устройств · 0 без лимита</label><input id="deviceLimit" name="max_devices" type="number" min="0" max="20" value="2" inputmode="numeric"></div></div></section><section class="create-step" id="directFields" hidden><div class="create-step-title"><i>1</i><span>Выберите одно подключение</span></div><div class="protocol-picker"><label class="choice-card"><input type="radio" name="direct_protocol" value="vless" checked><span><strong>VLESS XHTTP</strong><small>Универсальное TLS-подключение</small></span></label><label class="choice-card"><input type="radio" name="direct_protocol" value="hysteria"><span><strong>Hysteria2</strong><small>Быстрое подключение через QUIC</small></span></label><label class="choice-card"><input type="radio" name="direct_protocol" value="awg20"><span><strong>AWG 2.0</strong><small>Совместимость с прежними клиентами</small></span></label><label class="choice-card"><input type="radio" name="direct_protocol" value="awg31"><span><strong>AWG 3.1</strong><small>Новая маскировка и собственные параметры</small></span></label></div><div class="quick-access-title">Сервисы</div><div class="quick-access-grid"><button type="button" class="quick-access" data-quick-protocol="mtproto"><span class="quick-radio" aria-hidden="true"></span><span><b>MTProto</b><small>Прямое подключение для Telegram</small></span></button><button type="button" class="quick-access" data-quick-protocol="web"><span class="quick-radio" aria-hidden="true"></span><span><b>Web Proxy</b><small>Ссылка Telegram через HTTPS</small></span></button><button type="button" class="quick-access" data-open-openflux><span class="quick-radio" aria-hidden="true"></span><span><b>OpenFlux</b><small>Отдельный профиль для iOS или Android</small></span></button></div><p class="quick-access-note">Выберите VPN-протокол или один отдельный сервис.</p></section><section class="create-step quick-fields" id="quickFields" hidden><b id="quickTitle"></b><p id="quickDescription"></p></section><div class="create-summary"><span>Будет создано</span><b id="createSummary">Подписка · VLESS XHTTP + Hysteria2 · 2 устройства</b></div><div class="actions create-actions"><button type="button" data-close-dialog>Отмена</button><button class="primary" id="createClientSubmit">Создать доступ</button></div></form></dialog>'''
    creation=creation.replace('<input type="hidden" id="accountKind"', '<div id="createError" class="create-error" role="alert" hidden></div><input type="hidden" id="accountKind"',1)
    confirmation='''<dialog id="accessConfirm"><div class="dialog-head"><h2>Изменить доступ?</h2></div><p data-access-message></p><form method="dialog"><div class="actions"><button value="cancel">Отмена</button><button class="primary" value="apply">Подтвердить</button></div></form></dialog>'''
    return '<div class="clients-layout"><div class="clients-content">'+content+'</div><div class="connection-slot">'+qr_dialog()+'</div></div>'+openflux_create_dialog(path,csrf)+''.join(dialogs)+creation+confirmation+CLIENTS_JS.replace('@@PATH@@',json.dumps(path)).replace('@@CSRF@@',json.dumps(csrf))+admin_block()


NODE_COUNTRIES = [
    ('UN','Не указано'), ('DE','Германия'), ('FI','Финляндия'),
    ('NL','Нидерланды'), ('FR','Франция'), ('GB','Великобритания'), ('US','США'),
    ('CA','Канада'), ('SE','Швеция'), ('NO','Норвегия'), ('PL','Польша'),
    ('CZ','Чехия'), ('AT','Австрия'), ('CH','Швейцария'), ('ES','Испания'),
    ('IT','Италия'), ('LT','Литва'), ('LV','Латвия'), ('EE','Эстония'),
    ('RO','Румыния'), ('BG','Болгария'), ('TR','Турция'), ('KZ','Казахстан'),
    ('RU','Россия'), ('UA','Украина'), ('JP','Япония'), ('SG','Сингапур'),
    ('HK','Гонконг'), ('AE','ОАЭ')
]


def node_flag(code):
    code=str(code or 'UN').upper()
    return ''.join(chr(127397+ord(c)) for c in code) if len(code)==2 and code!='UN' and code.isalpha() else '🌐'


def node_flag_image(code, path):
    code=str(code or 'UN').lower()
    if not re.fullmatch(r'[a-z]{2}',code): code='un'
    return f'<img src="{esc(path)}/__flag/{esc(code)}.svg" alt="{esc(node_flag(code))}" width="48" height="36">'


def node_country_select(local):
    current=str(local.get('country_code','UN')).upper()
    countries=list(NODE_COUNTRIES)
    if current not in {code for code,_ in countries}:
        countries.insert(1,(current,str(local.get('country_name') or current)))
    options=[]
    for code,name in countries:
        title=str(local.get('country_name')) if code==current and local.get('country_name') else name
        options.append(f'<option value="{esc(code)}" data-country-name="{esc(title)}" {"selected" if code==current else ""}>{node_flag(code)} {esc(title)}</option>')
    return ''.join(options)


def _node_label(val, fallback):
    """Return val if it's a real non-empty label, else fallback.
    Treats empty/None and dash-only strings ('—', '-', '–', '−') as missing.
    Some cascade node APIs persist '—' as the default city when geo lookup
    returns no city — we want to render 'Город не определён' instead.
    """
    if not val:
        return fallback
    s = val.strip()
    if not s or set(s) <= set('—-−–'):
        return fallback
    return val


def _node_protocols(node):
    """Determine protocols label for a node — never returns the stale
    hardcoded 'VLESS · Hysteria2'. Falls back through:
    1. node['protocols'] (explicit field set by cascade bridge or remote API)
    2. parse node['version'] (e.g. 'cascade-reality' → 'VLESS REALITY')
    3. '—' (no false info)
    """
    p = node.get('protocols')
    if p and isinstance(p, str) and not _is_dash_str(p):
        return p
    if isinstance(p, list) and p:
        # Federation node may store list of protocols — join unique labels
        labels = []
        for x in p:
            if x and not _is_dash_str(x):
                labels.append(x if isinstance(x, str) else str(x))
        if labels:
            return ' · '.join(labels)
    v = node.get('version', '') or ''
    if v.startswith('cascade-'):
        proto = v[len('cascade-'):]
        mapping = {
            'reality': 'VLESS REALITY',
            'xhttp':   'VLESS XHTTP',
            'tcp':     'VLESS TCP',
            'ws':      'VLESS WebSocket',
            'grpc':    'VLESS gRPC',
        }
        if proto in mapping:
            return mapping[proto]
        return f'VLESS {proto.upper()}' if proto else 'VLESS'
    if v and not _is_dash_str(v):
        return v
    return '—'


def _is_dash_str(s):
    """True if string s is empty or consists only of dash characters."""
    if not s:
        return True
    stripped = s.strip() if isinstance(s, str) else ''
    return (not stripped) or (set(stripped) <= set('—-−–'))


def nodes_ui(nodes, local, connection_token, path, csrf):
    cards=[]
    for node in nodes:
        icon_flag=node_flag_image(node.get('country_code','UN'),path)
        node_city=_node_label(node.get('name'), 'Город не определён')
        node_country=_node_label(node.get('country_name'), 'Страна не определена')
        cards.append(f'''<article class="card node-card">
<div class="node-card-head"><span class="node-flag">{icon_flag}</span><div class="node-card-name"><h2>{esc(node_city)}</h2><span>{esc(node_country)}</span></div><span class="badge {'on' if node.get('enabled',True) else ''}">{'Подключена' if node.get('enabled',True) else 'Отключена'}</span></div>
<div class="node-endpoint">{icon('link')}<span>{esc(node.get('url',''))}</span></div>
<div class="node-card-meta"><div><span>Версия</span><strong>{esc(_node_label(node.get('version'), '—'))}</strong></div><div><span>Подключения</span><strong>{esc(_node_protocols(node))}</strong></div></div>
<form class="node-remove" method="post" action="{esc(path)}/node-action" data-confirm="Удалить ноду из этой панели?"><input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="operation" value="delete"><input type="hidden" name="id" value="{esc(node.get('id',''))}"><button class="danger">Удалить ноду</button></form></article>''')
    local_flag=node_flag_image(local.get('country_code','UN'),path)
    country_options=node_country_select(local)
    local_country=_node_label(local.get('country_name'), 'Страна не определена')
    local_city=_node_label(local.get('name'), 'Город не определён')
    empty=f'''<div class="nodes-empty"><span>{icon('nodes')}</span><h3>Здесь появятся ваши локации</h3><p>Установите WPP на другом VPS и вставьте его Node API token в форму выше.</p></div>'''
    return f'''<div class="page-head nodes-page-head"><div><span class="eyebrow">DISTRIBUTED ACCESS</span><h1>Ноды и локации</h1><p>Объединяйте несколько VPS в одну подписку и управляйте ими из этой панели</p></div><div class="nodes-count"><strong>{len(nodes)+1}</strong><span>локаций<br>в системе</span></div></div>
<div class="nodes-grid">
<section class="card local-node-card"><div class="local-node-head"><span class="local-node-flag">{local_flag}</span><div><span class="eyebrow">ТЕКУЩАЯ НОДА</span><h2>{esc(local_city)}</h2><small>{esc(local_country)}</small></div><span class="badge on">Активна</span></div>
<form class="node-location-form" method="post" action="{esc(path)}/node-action"><input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="operation" value="location"><input id="nodeCountryName" type="hidden" name="country_name" value="{esc(local.get('country_name','Сервер'))}"><div class="location-fields"><div class="country-flag-field"><label>Страна ноды</label><select id="nodeCountry" name="country_code" required>{country_options}</select></div><div><label>Город / название локации</label><input name="name" maxlength="80" value="{esc(local.get('name','Основная локация'))}" placeholder="Хельсинки" required></div></div><div class="location-actions"><small>Страна и город определяются по IP автоматически. Здесь их можно исправить вручную.</small><button class="primary">Сохранить</button></div></form><script>(()=>{{const select=document.getElementById('nodeCountry'),name=document.getElementById('nodeCountryName');if(select&&name)select.addEventListener('change',()=>{{name.value=select.selectedOptions[0].dataset.countryName||'Сервер'}})}})();</script>
<div class="node-token-box"><div class="node-token-title"><span>{icon('link')}</span><div><strong>Node API token</strong><small>Адрес и защищённый ключ подключения этой ноды</small></div></div><div class="node-token-copy"><input value="{esc(connection_token)}" readonly spellcheck="false" aria-label="Node API token"><button type="button" data-copy="{esc(connection_token)}">{icon('copy')}<span>Копировать</span></button></div><p>Храните токен как пароль. Он нужен только администратору другой WPP-панели.</p><details><summary>Доступные методы API</summary><div class="api-methods"><code>GET · /status</code><code>GET · /profiles</code><code>POST · /profiles/create</code><code>POST · /profiles/delete</code></div></details></div></section>
<section class="card node-connect-card"><div class="connect-mark">{icon('nodes')}</div><span class="eyebrow">НОВАЯ ЛОКАЦИЯ</span><h2>Подключить ноду</h2><p>Добавьте chimera cascade ноду (VLESS+REALITY) или WPP federation ноду.</p><details><summary>Добавить chimera cascade ноду</summary><div style="margin:12px 0;padding:14px;border:1px solid var(--line);border-radius:10px;background:var(--input)"><label style="margin-top:0">Вставьте VLESS URL — поля заполнятся автоматически</label><input name="_vless_url" placeholder="vless://uuid@host:443?security=reality&pbk=...&sni=...&fp=chrome&sid=...&type=tcp#Name" oninput="parseVlessUrl(this.value, this.closest('details'))" autocomplete="off" spellcheck="false" style="margin-top:6px;font:10px ui-monospace,monospace"><small style="display:block;margin-top:6px;font-size:10px;color:var(--muted)">Поддерживается стандартный формат VLESS+REALITY. Форма ниже останется — можно подправить любое поле.</small></div><script>function parseVlessUrl(url, container){{const m=url.trim().match(/^vless:\/\/([^@:]+)@([^:]+):(\d+)\??([^#]*)#?(.*)$/);if(!m)return;const[,uuid,host,port,qs,name]=m;const params=new URLSearchParams(qs);const f=container.querySelector('form');if(!f)return;const set=(n,v)=>{{if(!v)return;const el=f.querySelector('[name="'+n+'"]');if(el)el.value=v;}};set('host',host);set('port',port);set('uuid',uuid);set('pubkey',params.get('pbk')||'');set('shortid',params.get('sid')||params.get('shortId')||'');set('sni',params.get('sni')||'');set('fp',params.get('fp')||'chrome');const security=params.get('security')||'reality';const ps=f.querySelector('[name="proto"]');if(ps)ps.value=security==='reality'?'reality':'xhttp';}}</script><form method="post" action="{esc(path)}/node-action" style="margin-top:12px"><input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="operation" value="add-cascade"><div style="display:grid;gap:8px"><div><label>Host (домен)</label><input name="host" placeholder="fi.example.com" required></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px"><div><label>Порт</label><input name="port" value="443"></div><div><label>Протокол</label><select name="proto"><option value="reality">REALITY</option><option value="xhttp">XHTTP</option></select></div></div><div><label>UUID</label><input name="uuid" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></div><div><label>PublicKey (REALITY)</label><input name="pubkey" placeholder="base64url 43 chars"></div><div><label>ShortId</label><input name="shortid" placeholder="hex 8-16 chars"></div><div><label>SNI</label><input name="sni" placeholder="по умолчанию = host"></div><div><label>Fingerprint</label><select name="fp">{fingerprint_options()}</select><small style="display:block;margin-top:4px;font-size:10px;color:var(--muted)">Выберите TLS fingerprint клиента (uTLS). Chrome работает везде.</small></div></div><button class="primary" style="margin-top:12px;width:100%">Добавить cascade ноду</button></form></details><details><summary style="margin-top:14px">Подключить WPP federation ноду</summary><ol class="node-connect-steps"><li><i>1</i><span>Скопируйте Node API token на другом сервере</span></li><li><i>2</i><span>Вставьте его в поле ниже</span></li><li><i>3</i><span>Панель проверит домен, страну и доступность API</span></li></ol><form method="post" action="{esc(path)}/node-action" style="margin-top:12px"><input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="operation" value="add"><label>Node API token</label><div class="node-connect-input"><input name="connection_token" autocomplete="off" spellcheck="false" placeholder="wppnode1_…" required><button class="primary">Проверить и добавить</button></div><small class="secure-hint">Соединение проверяется через HTTPS. Токен не передаётся сторонним сервисам.</small></form></details></section></div>
<section class="nodes-section"><div class="nodes-section-head"><div><span class="eyebrow">NETWORK MAP</span><h2>Подключённые ноды</h2></div><span class="pill">{len(nodes)} / 16</span></div><div class="nodes-list">{''.join(cards) if cards else empty}</div></section>'''


CSS += '''
.nodes-page-head{padding-bottom:22px;border-bottom:1px solid var(--line)}.nodes-count{display:flex;align-items:center;gap:11px;padding:10px 14px;border:1px solid var(--line);border-radius:12px;background:var(--surface)}.nodes-count strong{font:500 25px/1 ui-monospace,monospace;color:var(--accent)}.nodes-count span{font-size:10px;line-height:1.35;color:var(--muted)}.nodes-grid{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(340px,.85fr);gap:18px;align-items:start}.local-node-card,.node-connect-card{margin:0}.local-node-card{padding:0;overflow:hidden}.local-node-head{display:flex;align-items:center;gap:14px;padding:22px 23px;border-bottom:1px solid var(--line);background:linear-gradient(135deg,var(--tint),transparent 60%)}.local-node-flag,.node-flag{display:grid;place-items:center;flex:0 0 auto;width:48px;height:48px;border:1px solid var(--line);border-radius:14px;background:var(--input);font-size:25px}.local-node-head>div{min-width:0}.local-node-head h2{font-size:19px}.local-node-head small{display:block;margin-top:4px}.local-node-head>.badge{margin-left:auto}.node-location-form{padding:20px 23px 22px}.location-fields{display:grid;grid-template-columns:90px 1fr 1fr;gap:11px}.location-fields label{margin-top:0}.location-fields input{text-overflow:ellipsis}.country-code-field input{text-align:center;text-transform:uppercase;font:600 14px ui-monospace,monospace}.location-actions{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:14px}.location-actions small{max-width:480px;font-size:10px}.location-actions button{min-width:110px}.node-token-box{margin:0 23px 23px;padding:18px;border:1px solid color-mix(in srgb,var(--accent) 36%,var(--line));border-radius:13px;background:linear-gradient(135deg,var(--tint),var(--input))}.node-token-title{display:flex;align-items:center;gap:11px;margin-bottom:13px}.node-token-title>span{display:grid;place-items:center;width:34px;height:34px;border-radius:9px;background:var(--accent);color:var(--on-accent)}.node-token-title .ico{width:16px}.node-token-title strong{display:block;font-size:12px}.node-token-title small{display:block;font-size:9px;margin-top:2px}.node-token-copy{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}.node-token-copy input{font:10px ui-monospace,monospace}.node-token-copy button{white-space:nowrap}.node-token-box>p{margin:10px 0 0;font-size:10px;color:var(--muted)}.node-token-box details{margin-top:10px}.node-token-box summary{width:max-content;cursor:pointer;font-size:10px;color:var(--accent)}.api-methods{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:10px}.api-methods code{padding:7px 9px;border:1px solid var(--line);border-radius:7px;background:var(--surface);font-size:9px;color:var(--muted)}.node-connect-card{position:relative;padding:28px;overflow:hidden;background:radial-gradient(circle at 100% 0,var(--tint),transparent 42%),var(--surface)}.connect-mark{display:grid;place-items:center;width:52px;height:52px;margin-bottom:24px;border:1px solid color-mix(in srgb,var(--accent) 38%,var(--line));border-radius:15px;background:var(--tint);color:var(--accent)}.connect-mark .ico{width:25px;height:25px}.node-connect-card h2{font-size:22px}.node-connect-card>p{max-width:460px;margin:8px 0 22px;color:var(--muted);font-size:12px}.node-connect-steps{display:grid;gap:10px;margin:0 0 24px;padding:0;list-style:none}.node-connect-steps li{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:11px}.node-connect-steps i{display:grid;place-items:center;flex:0 0 23px;height:23px;border:1px solid var(--line);border-radius:50%;color:var(--accent);font:600 10px ui-monospace,monospace}.node-connect-card form{padding-top:20px;border-top:1px solid var(--line)}.node-connect-card form label{margin-top:0;color:var(--text)}.node-connect-input{display:grid;gap:9px}.node-connect-input input{font:10px ui-monospace,monospace}.node-connect-input button{width:100%;padding:12px}.secure-hint{display:block;margin-top:10px;font-size:9px}.nodes-section{margin-top:27px}.nodes-section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:13px}.nodes-list{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px}.node-card{display:flex;flex-direction:column;margin:0;padding:19px}.node-card-head{display:flex;align-items:center;gap:11px}.node-flag{width:41px;height:41px;border-radius:11px;font-size:21px}.node-card-name{min-width:0}.node-card-name h2{font-size:15px}.node-card-name span{display:block;margin-top:2px;color:var(--muted);font-size:10px}.node-card-head>.badge{margin-left:auto}.node-endpoint{display:flex;align-items:center;gap:7px;margin:16px 0;padding:9px 10px;border-radius:8px;background:var(--input);color:var(--muted);font:9px ui-monospace,monospace}.node-endpoint .ico{width:13px}.node-endpoint span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.node-card-meta{display:grid;grid-template-columns:.7fr 1.3fr;gap:9px}.node-card-meta>div{padding:10px;border:1px solid var(--line);border-radius:8px}.node-card-meta span{display:block;font-size:8px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.node-card-meta strong{display:block;margin-top:4px;font-size:10px}.node-remove{margin-top:auto;padding-top:14px}.node-remove button{width:100%;font-size:10px}.nodes-empty{grid-column:1/-1;display:grid;justify-items:center;padding:43px 20px;border:1px dashed var(--line);border-radius:14px;text-align:center;background:var(--surface)}.nodes-empty>span{display:grid;place-items:center;width:45px;height:45px;border-radius:13px;background:var(--tint);color:var(--accent)}.nodes-empty h3{margin-top:14px}.nodes-empty p{max-width:440px;margin:6px 0 0;color:var(--muted);font-size:11px}@media(max-width:1000px){.nodes-grid{grid-template-columns:1fr}.nodes-list{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:650px){.nodes-count{display:none}.local-node-head{align-items:flex-start;padding:19px}.local-node-head>.badge{margin-left:auto}.node-location-form{padding:18px 19px}.location-fields{grid-template-columns:76px 1fr}.location-fields>div:last-child{grid-column:1/-1}.location-actions{align-items:stretch;flex-direction:column}.location-actions button{width:100%}.node-token-box{margin:0 19px 19px;padding:15px}.node-token-copy{grid-template-columns:1fr}.node-token-copy button span{display:inline}.api-methods{grid-template-columns:1fr}.node-connect-card{padding:21px}.nodes-list{grid-template-columns:1fr}}'''


CSS += '''
.node-location-form .location-fields{grid-template-columns:1fr 1fr}.country-flag-field select{font-size:13px}.country-flag-field option{background:var(--surface);color:var(--text)}
.openflux-users{margin-top:26px;padding-top:24px;border-top:1px solid var(--line)}.openflux-users .section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:14px}.openflux-users .section-head h2{margin-top:4px}.openflux-users .section-head p{margin:5px 0 0;color:var(--muted);font-size:11px}.flux-profile-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.flux-profile{padding:18px;border:1px solid var(--line);border-radius:14px;background:radial-gradient(circle at 100% 0,var(--tint),transparent 42%),var(--surface)}.flux-profile-head{display:flex;align-items:center;gap:11px;margin-bottom:15px}.flux-profile-head>div{min-width:0}.flux-profile-head h3{font-size:14px}.flux-profile-head small{display:block;margin-top:3px}.flux-profile-head>.badge{margin-left:auto}.flux-platform{display:grid;place-items:center;width:43px;height:43px;border:1px solid color-mix(in srgb,var(--accent) 35%,var(--line));border-radius:12px;background:var(--tint);color:var(--accent);font-weight:700;font-size:10px}.flux-profile-secret{display:grid;grid-template-columns:62px minmax(0,1fr) 36px;align-items:center;gap:8px;margin-top:8px}.flux-profile-secret>span{font-size:9px;color:var(--muted);text-transform:uppercase}.flux-profile-secret input{min-width:0;padding:9px;font:9px ui-monospace,monospace}.flux-profile-secret button{height:36px;padding:8px}.flux-profile>.actions{margin-top:15px}.flux-empty{grid-column:1/-1;display:grid;gap:5px;padding:30px;border:1px dashed var(--line);border-radius:14px;text-align:center;color:var(--muted)}.flux-empty b{color:var(--text)}.flux-platform-picker{margin-top:8px}
.client-detail{position:fixed;inset:0 0 0 auto;width:min(455px,100vw);height:100dvh;max-height:100dvh;margin:0;border-radius:20px 0 0 20px;overflow:auto}.client-detail .dialog-head{position:sticky;z-index:3;top:-25px;padding:20px 0 15px;background:var(--surface);border-bottom:1px solid var(--line)}
.access-kind-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}.access-kind-grid .choice-card{min-height:104px}.access-kind-grid .choice-card strong{font-size:14px}.compatible-protocols{display:flex;flex-wrap:wrap;gap:5px;margin-top:9px}.compatible-protocols i{padding:4px 6px;border:1px solid var(--line);border-radius:6px;color:var(--muted);font:500 8px/1 ui-monospace,monospace;font-style:normal}.quick-access-title{display:flex;align-items:center;gap:11px;margin:20px 0 10px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em}.quick-access-title:before,.quick-access-title:after{content:"";height:1px;flex:1;background:var(--line)}.quick-access-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.quick-access{display:flex;align-items:flex-start;gap:12px;min-width:0;min-height:76px;padding:15px;border:1px solid var(--line);border-radius:11px;background:var(--input);text-align:left;color:var(--text);cursor:pointer}.quick-access:hover,.quick-access.selected{border-color:var(--accent);background:var(--tint)}.quick-access.selected{box-shadow:inset 0 0 0 1px var(--accent)}.quick-access .quick-radio{display:block;width:16px;height:16px;flex:0 0 auto;margin-top:3px;border:1px solid var(--muted);border-radius:50%;background:transparent}.quick-access:hover .quick-radio{border-color:var(--accent)}.quick-access.selected .quick-radio{border-color:var(--accent);box-shadow:inset 0 0 0 4px var(--input);background:var(--accent)}.quick-access b{display:block;font-size:13px}.quick-access small{display:block;margin-top:4px;font-size:10px;line-height:1.45}.quick-access-note{margin:10px 0 0;color:var(--muted);font-size:9px}.quick-fields{padding:14px;border:1px solid var(--line);border-radius:10px;background:var(--raised)}.quick-fields b{display:block;font-size:12px}.quick-fields p{margin:5px 0 0;color:var(--muted);font-size:10px;line-height:1.5}
@media(max-width:650px){.node-location-form .location-fields{grid-template-columns:1fr}.node-location-form .location-fields>div:last-child{grid-column:auto}}
@media(max-width:760px){.openflux-users .section-head{align-items:stretch;flex-direction:column}.openflux-users .section-head button{width:100%}.flux-profile-grid{grid-template-columns:1fr}.flux-profile-secret{grid-template-columns:1fr 36px}.flux-profile-secret>span{grid-column:1/-1}.client-detail{width:100vw;border-radius:0}.access-kind-grid{grid-template-columns:1fr}.quick-access-grid{grid-template-columns:1fr}.quick-access{padding:12px}.mtproto-options{grid-template-columns:1fr}.mtproto-device{grid-template-columns:1fr 1fr}.mtproto-device>div{grid-column:1/-1}}
.mtproto-options{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:13px}.mtproto-options label{margin:0}.mtproto-options small{display:block;margin-top:5px;color:var(--muted);font-size:9px}.mtproto-access-head{display:grid;grid-template-columns:1fr auto;align-items:center;gap:4px 12px;margin:12px 0;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--raised)}.mtproto-access-head span,.mtproto-access-head small{color:var(--muted);font-size:10px}.mtproto-access-head small{grid-column:1/-1}.mtproto-devices{display:grid;gap:8px;margin:12px 0}.mtproto-device{display:grid;grid-template-columns:minmax(0,1fr) auto auto;align-items:center;gap:8px;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--input)}.mtproto-device b,.mtproto-device small{display:block}.mtproto-device small{margin-top:3px;color:var(--muted);font-size:9px}
@media(max-width:760px){.mtproto-options{grid-template-columns:1fr}.mtproto-device{grid-template-columns:1fr 1fr}.mtproto-device>div{grid-column:1/-1}}
'''

# Balanced access dialog and node cards. Dialog content fits on a normal
# desktop viewport without a nested scrollbar; small screens keep responsive
# single-column cards while scrollbars stay visually unobtrusive.
CSS += '''
dialog{scrollbar-width:none}dialog::-webkit-scrollbar{display:none}
.create-dialog{width:min(980px,calc(100vw - 28px));max-height:none;overflow:hidden}
.create-dialog .dialog-head{padding:18px 22px 14px}
.create-dialog form{padding:16px 22px 18px;max-height:none;overflow:visible}
.create-dialog .create-step{margin-top:14px}
.create-dialog .access-kind-grid .choice-card{min-height:88px}
.create-dialog #directFields .protocol-picker{grid-template-columns:repeat(4,minmax(0,1fr))}
.create-dialog .quick-access-title{margin:14px 0 9px}
.create-dialog .quick-access-grid{grid-template-columns:repeat(3,minmax(0,1fr))}
.create-dialog .create-summary{margin-top:14px;padding:11px 14px}
.create-dialog .create-actions{position:static;margin-top:11px;padding:0;background:none}
.create-error{margin:0 0 14px;padding:11px 13px;border:1px solid color-mix(in srgb,var(--red) 45%,var(--line));border-left:3px solid var(--red);border-radius:10px;background:color-mix(in srgb,var(--red) 9%,var(--surface));color:var(--red);font-size:11px;line-height:1.5}.create-error[hidden]{display:none}.create-dialog.is-submitting{cursor:wait}.create-dialog.is-submitting button,.create-dialog.is-submitting input,.create-dialog.is-submitting select{pointer-events:none}.clients-table tr.client-pending{opacity:.55;pointer-events:none}.clients-table tr.client-pending .client-name:after{content:'Применяем…';display:block;margin-top:4px;color:var(--accent);font-size:9px}
.local-node-flag,.node-flag{font-family:"Segoe UI Emoji","Apple Color Emoji","Noto Color Emoji",sans-serif;font-variant-emoji:emoji}
.local-node-flag img,.node-flag img{display:block;width:32px;height:24px;border-radius:4px;object-fit:cover;box-shadow:0 1px 5px #0004}.node-flag img{width:28px;height:21px}
.nodes-grid{align-items:stretch}.local-node-card,.node-connect-card{height:100%}
@media(max-width:900px){.create-dialog #directFields .protocol-picker{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.create-dialog{width:min(620px,calc(100vw - 18px))}.create-dialog .quick-access-grid{grid-template-columns:1fr}.create-dialog form{padding:15px 18px 17px}}
@media(max-width:1000px){.local-node-card,.node-connect-card{height:auto}}
'''

# CSS for hourly traffic pattern (Variant B) and weekly heatmap (Variant C)
CSS += '''
.hourly-card{margin-top:18px}.heatmap-card{margin-top:18px}
.hourly-chart{display:grid;grid-template-columns:repeat(24,minmax(0,1fr));gap:3px;height:140px;align-items:end;padding:8px 0 4px;border-bottom:1px solid var(--line)}
.hourly-bar{position:relative;width:100%;min-height:3px;border-radius:3px 3px 0 0;background:var(--input);cursor:help;transition:filter .15s;overflow:hidden}
.hourly-bar:hover{filter:brightness(1.25)}
.hourly-bar.zero{opacity:.55}
.hourly-seg{position:absolute;left:0;right:0}
.hourly-seg.up{bottom:0;background:var(--green)}
.hourly-seg.down{top:0;background:color-mix(in srgb,var(--green) 30%,var(--input))}
.hourly-axis{display:grid;grid-template-columns:repeat(24,minmax(0,1fr));font:9px ui-monospace,monospace;color:var(--muted);text-align:center;padding:5px 0 0}
.hourly-axis span{display:block}
.hourly-legend{display:flex;flex-wrap:wrap;gap:14px;font-size:10px;color:var(--muted);margin-top:8px}
.hourly-legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle}
.hourly-legend i.up{background:var(--green)}
.hourly-legend i.down{background:color-mix(in srgb,var(--green) 30%,var(--input))}
.hourly-legend .muted{margin-left:auto}
.hourly-empty{padding:30px 12px;text-align:center;color:var(--muted);font-size:12px}
.heatmap-grid{display:grid;grid-template-columns:34px repeat(24,minmax(0,1fr));gap:3px;padding:8px 0 4px;border-bottom:1px solid var(--line)}
.heatmap-corner{grid-column:1;grid-row:1}
.heatmap-hour-label{font:8px ui-monospace,monospace;color:var(--muted);text-align:center;padding:3px 0}
.heatmap-row{display:contents}
.heatmap-row-label{font:10px ui-monospace,monospace;color:var(--muted);text-align:right;padding:6px 6px 0 0;align-self:center}
.heatmap-cell{aspect-ratio:1;border-radius:3px;background:var(--input);cursor:help;transition:filter .15s,transform .1s}
.heatmap-cell:hover{filter:brightness(1.3);transform:scale(1.15)}
.heatmap-cell[data-level="0"]{background:var(--input)}
.heatmap-cell[data-level="1"]{background:color-mix(in srgb,var(--green) 22%,var(--input))}
.heatmap-cell[data-level="2"]{background:color-mix(in srgb,var(--green) 45%,var(--input))}
.heatmap-cell[data-level="3"]{background:color-mix(in srgb,var(--green) 70%,var(--input))}
.heatmap-cell[data-level="4"]{background:var(--green)}
.heatmap-scale{display:inline-flex;gap:2px;align-items:center;margin:0 6px;vertical-align:middle}
.heatmap-scale i{display:inline-block;width:11px;height:11px;border-radius:2px}
.heatmap-scale i[data-level="0"]{background:var(--input)}
.heatmap-scale i[data-level="1"]{background:color-mix(in srgb,var(--green) 22%,var(--input))}
.heatmap-scale i[data-level="2"]{background:color-mix(in srgb,var(--green) 45%,var(--input))}
.heatmap-scale i[data-level="3"]{background:color-mix(in srgb,var(--green) 70%,var(--input))}
.heatmap-scale i[data-level="4"]{background:var(--green)}
@media(max-width:900px){.hourly-chart{height:100px}.heatmap-grid{grid-template-columns:28px repeat(24,minmax(0,1fr))}.heatmap-row-label{font-size:9px;padding-right:3px}.heatmap-hour-label{font-size:7px}}
@media(max-width:600px){.hourly-chart{height:80px;gap:1px}.hourly-axis{font-size:8px}.heatmap-grid{gap:1px}.heatmap-cell{border-radius:2px}}
'''


CLIENTS_JS='''<script>
const clientPath=@@PATH@@,clientCsrf=@@CSRF@@,clientRows=document.getElementById('clientRows'),allRows=Array.from(clientRows.querySelectorAll('[data-client]')),search=document.getElementById('accountSearch'),filter=document.getElementById('clientFilter'),proto=document.getElementById('protocolFilter'),sort=document.getElementById('clientSort'),notice=document.getElementById('clientNotice');let changing=false;
document.querySelectorAll('[data-open-dialog]').forEach(button=>button.addEventListener('click',()=>document.getElementById(button.dataset.openDialog).showModal()));
function selected(){return allRows.filter(r=>!r.hidden&&r.querySelector('[data-select-client]').checked)}
function selection(){const n=selected().length,visible=allRows.filter(r=>!r.hidden&&!r.querySelector('[data-select-client]').disabled),header=document.getElementById('selectAllClients');document.getElementById('bulkBar').hidden=!n;document.getElementById('selectedCount').textContent='Выбрано: '+n;header.checked=visible.length>0&&visible.every(r=>r.querySelector('[data-select-client]').checked);header.indeterminate=n>0&&!header.checked}
function list(){const q=search.value.trim().toLocaleLowerCase('ru'),mode=filter.value,p=proto.value;let visible=0;allRows.forEach(r=>{const d=r.dataset,match=(d.name+' '+d.id+' '+(d.kind==='subscription'?'подписка':'отдельная ссылка')).toLocaleLowerCase('ru').includes(q)&&(p==='all'||d.protocols.split(' ').includes(p))&&(mode==='all'||d.kind===mode||mode==='active'&&d.active==='1'||mode==='enabled'&&d.enabled==='1'||mode==='disabled'&&d.enabled==='0');r.hidden=!match;if(!match)r.querySelector('[data-select-client]').checked=false;else visible++});const ordered=allRows.slice().sort((a,b)=>{const x=a.dataset,y=b.dataset;switch(sort.value){case'name':return x.name.localeCompare(y.name,'ru');case'traffic':return Number(y.traffic)-Number(x.traffic);case'active':return Number(y.active)-Number(x.active);case'newest':return Number(y.created)-Number(x.created);default:return allRows.indexOf(a)-allRows.indexOf(b)}});ordered.forEach(r=>clientRows.appendChild(r));document.getElementById('visibleCount').textContent='Показано '+visible+' из '+allRows.length;document.getElementById('noAccounts').hidden=visible>0;selection();document.dispatchEvent(new Event('wpp-filtered'))}
[search,filter,proto,sort].forEach(e=>e.addEventListener(e===search?'input':'change',list));document.getElementById('selectAllClients').addEventListener('change',e=>{allRows.forEach(r=>{const c=r.querySelector('[data-select-client]');if(!r.hidden&&!c.disabled)c.checked=e.target.checked});selection()});allRows.forEach(r=>r.querySelector('[data-select-client]').addEventListener('change',selection));document.getElementById('clearSelected').addEventListener('click',()=>{allRows.forEach(r=>r.querySelector('[data-select-client]').checked=false);selection()});
const createDialog=document.getElementById('createAccount'),createForm=document.getElementById('createClientForm'),kindField=document.getElementById('accountKind'),subFields=document.getElementById('subscriptionFields'),directFields=document.getElementById('directFields'),quickFields=document.getElementById('quickFields'),createSummary=document.getElementById('createSummary'),createError=document.getElementById('createError'),createSubmit=document.getElementById('createClientSubmit');let quickProtocol='';
quickFields.insertAdjacentHTML('beforeend','<div class="mtproto-options" id="mtprotoOptions" hidden><label>TCP-порт<input name="mtproto_port" id="mtprotoPort" type="number" min="1024" max="65535" value="2399" inputmode="numeric" required><small>Панель проверит и откроет порт автоматически</small></label><label>Устройств<input name="mtproto_devices" id="mtprotoDevices" type="number" min="1" max="20" value="1" inputmode="numeric" required><small>Отдельный ключ и QR для каждого устройства</small></label></div>');const mtprotoOptions=document.getElementById('mtprotoOptions'),mtprotoPort=document.getElementById('mtprotoPort'),mtprotoDevices=document.getElementById('mtprotoDevices');
const protocolNames={vless:'VLESS XHTTP',hysteria:'Hysteria2',mtproto:'MTProto',web:'WEB Proxy',awg20:'AWG 2.0',awg31:'AWG 3.1'};
function clearQuick(){quickProtocol='';createForm.querySelectorAll('[data-quick-protocol]').forEach(b=>b.classList.remove('selected'))}
function updateCreate(){const mode=createForm.querySelector('[name=access_mode]:checked').value,isSub=mode==='subscription',isQuick=Boolean(quickProtocol),isMtproto=quickProtocol==='mtproto';subFields.hidden=!isSub;directFields.hidden=isSub;quickFields.hidden=!isQuick;mtprotoOptions.hidden=!isMtproto;mtprotoPort.disabled=!isMtproto;mtprotoDevices.disabled=!isMtproto;if(isSub){kindField.value='subscription';const chosen=Array.from(subFields.querySelectorAll('input[type=checkbox]:checked')).map(x=>protocolNames[x.name]),limit=document.getElementById('deviceLimit').value;createSummary.textContent='Подписка · '+(chosen.join(' + ')||'выберите протокол')+' · '+(limit==='0'?'без лимита':limit+' устр.')}else if(isQuick){kindField.value=quickProtocol;document.getElementById('quickTitle').textContent=protocolNames[quickProtocol];document.getElementById('quickDescription').textContent=isMtproto?'Выберите порт и количество отдельных ключей Telegram.':'Будет создана отдельная HTTPS-ссылка для Telegram.';createSummary.textContent='Отдельное подключение · '+protocolNames[quickProtocol]+(isMtproto?' · порт '+mtprotoPort.value+' · '+mtprotoDevices.value+' устр.':'')}else{let direct=createForm.querySelector('[name=direct_protocol]:checked');if(!direct){direct=createForm.querySelector('[name=direct_protocol][value=vless]');direct.checked=true}kindField.value=direct.value;createSummary.textContent='Отдельное подключение · '+protocolNames[direct.value]}}
createForm.querySelectorAll('[name=access_mode]').forEach(x=>x.addEventListener('change',()=>{clearQuick();if(x.value==='direct'&&x.checked&&!createForm.querySelector('[name=direct_protocol]:checked'))createForm.querySelector('[name=direct_protocol][value=vless]').checked=true;updateCreate()}));createForm.querySelectorAll('[name=direct_protocol]').forEach(x=>x.addEventListener('change',()=>{clearQuick();updateCreate()}));createForm.querySelectorAll('#subscriptionFields input').forEach(x=>x.addEventListener('change',updateCreate));createForm.querySelectorAll('[data-quick-protocol]').forEach(button=>button.addEventListener('click',()=>{quickProtocol=button.dataset.quickProtocol;createForm.querySelector('[name=access_mode][value=direct]').checked=true;createForm.querySelectorAll('[name=direct_protocol]').forEach(input=>input.checked=false);createForm.querySelectorAll('[data-quick-protocol]').forEach(b=>b.classList.toggle('selected',b===button));updateCreate()}));const openFluxShortcut=createForm.querySelector('[data-open-openflux]');if(openFluxShortcut)openFluxShortcut.addEventListener('click',()=>{createDialog.close();document.getElementById('newOpenFlux').showModal()});document.getElementById('deviceLimit').addEventListener('input',updateCreate);createForm.addEventListener('submit',e=>{if(kindField.value==='subscription'&&!subFields.querySelector('input[type=checkbox]:checked')){e.preventDefault();createSummary.textContent='Выберите хотя бы один протокол';subFields.scrollIntoView({block:'center',behavior:'smooth'})}});document.getElementById('newAccount').addEventListener('click',()=>{createForm.reset();clearQuick();kindField.value='subscription';updateCreate();createDialog.showModal();setTimeout(()=>document.getElementById('accountName').focus(),30)});updateCreate();document.querySelectorAll('[data-open-client]').forEach(b=>b.addEventListener('click',()=>document.getElementById('client-'+b.dataset.openClient).showModal()));
mtprotoPort.addEventListener('input',updateCreate);mtprotoDevices.addEventListener('input',updateCreate);
function showCreateError(message){createError.textContent=message||'Не удалось создать подключение.';createError.hidden=false;createError.scrollIntoView({block:'nearest',behavior:'smooth'})}
createForm.addEventListener('input',()=>{createError.hidden=true});document.getElementById('newAccount').addEventListener('click',()=>{createError.hidden=true},{capture:true});
createForm.addEventListener('submit',async e=>{e.preventDefault();e.stopImmediatePropagation();if(kindField.value==='subscription'&&!subFields.querySelector('input[type=checkbox]:checked')){showCreateError('Выберите хотя бы один протокол.');return}createError.hidden=true;createDialog.classList.add('is-submitting');createSubmit.disabled=true;createSubmit.textContent='Создаём…';try{const response=await fetch(createForm.action,{method:'POST',headers:{'X-WPP-Async':'1'},body:new URLSearchParams(new FormData(createForm))});if(response.redirected)throw new Error('Сессия завершена. Войдите заново.');let result;try{result=await response.json()}catch(error){throw new Error('Панель вернула некорректный ответ. Повторите попытку.')}if(!response.ok||!result.ok)throw new Error(result.message||'Не удалось создать подключение.');location.href=clientPath+'/users'}catch(error){showCreateError(error.message)}finally{createDialog.classList.remove('is-submitting');createSubmit.disabled=false;createSubmit.textContent='Создать доступ'}},true);
async function requestClient(fields){const r=await fetch(clientPath+'/client-action',{method:'POST',body:new URLSearchParams({csrf:clientCsrf,...fields})});if(r.redirected)throw new Error('Сессия завершена. Войдите заново.');let d;try{d=await r.json()}catch(e){throw new Error('Нет корректного ответа. Обновите список перед повторной попыткой.')}if(!r.ok||!d.ok)throw new Error(d.message||'Изменение не применено')}
function updateClientStats(){const values=[allRows.length,allRows.filter(r=>r.dataset.active==='1').length,allRows.filter(r=>r.dataset.kind==='subscription').length,bytes(allRows.reduce((sum,r)=>sum+Number(r.dataset.traffic||0),0))];document.querySelectorAll('.client-stat b').forEach((b,i)=>b.textContent=values[i])}
function paintAccess(row,enabled,active=false){row.dataset.enabled=enabled?'1':'0';row.dataset.active=active?'1':'0';const toggle=row.querySelector('[role=switch]');if(toggle)toggle.setAttribute('aria-checked',enabled?'true':'false');row.querySelectorAll('.badge').forEach(badge=>{badge.classList.toggle('on',enabled&&active);badge.textContent=!enabled?'Отключена':row.dataset.kind==='openflux'?(active?'Работает':'Остановлен'):(active?'Передаёт трафик':'Нет трафика')});updateClientStats();list()}
function removeClientRow(row){const index=allRows.indexOf(row);if(index>=0)allRows.splice(index,1);const detail=document.getElementById('client-'+row.dataset.id);if(detail?.open)detail.close();detail?.remove();row.remove();updateClientStats();list()}
async function requestForm(form){const response=await fetch(form.action,{method:'POST',headers:{'X-WPP-Async':'1'},body:new URLSearchParams(new FormData(form))});if(response.redirected)throw new Error('Сессия завершена. Войдите заново.');let result;try{result=await response.json()}catch(error){throw new Error('Панель вернула некорректный ответ.')}if(!response.ok||!result.ok)throw new Error(result.message||'Операция не выполнена.');return result}
function lockClients(value){changing=value}
function confirmClientAccess(message){const d=document.getElementById('accessConfirm');if(d.open)return Promise.resolve(false);d.querySelector('[data-access-message]').textContent=message;d.returnValue='';return new Promise(resolve=>{d.addEventListener('close',()=>resolve(d.returnValue==='apply'),{once:true});d.showModal()})}
async function setAccess(rows,value,ask=false){if(changing||!rows.length)return;if(ask&&!await confirmClientAccess((value?'Включить':'Отключить')+' доступ для '+rows.length+' клиент(а/ов)? Соединения могут кратковременно прерваться.'))return;const previous=rows.map(r=>({enabled:r.dataset.enabled,active:r.dataset.active}));rows.forEach(r=>{paintAccess(r,Boolean(value),false);r.classList.add('client-pending')});lockClients(true);notice.hidden=false;let done=0;try{for(const r of rows){notice.textContent='Применение: '+(done+1)+' / '+rows.length;await requestClient({id:r.dataset.id,kind:r.dataset.kind,operation:'state',enabled:String(value)});done++}notice.textContent='Готово. Доступ изменён без перезагрузки страницы.';allRows.forEach(r=>{const c=r.querySelector('[data-select-client]');if(c)c.checked=false});selection()}catch(e){for(let i=done;i<rows.length;i++)paintAccess(rows[i],previous[i].enabled==='1',previous[i].active==='1');notice.textContent='Применено '+done+' из '+rows.length+'. '+e.message}finally{rows.forEach(r=>r.classList.remove('client-pending'));lockClients(false)}}
document.querySelectorAll('[data-state]').forEach(b=>b.addEventListener('click',()=>setAccess([b.closest('[data-client]')],b.getAttribute('aria-checked')==='true'?0:1)));document.querySelectorAll('[data-bulk]').forEach(b=>b.addEventListener('click',()=>setAccess(selected(),Number(b.dataset.bulk),true)));document.getElementById('reloadClients').addEventListener('click',()=>{if(!changing)location.reload()});
document.querySelectorAll('[data-secret-reveal]').forEach(b=>b.addEventListener('click',()=>{const field=document.getElementById(b.dataset.secretReveal),show=field.type==='password';field.type=show?'text':'password';b.textContent=show?'Скрыть':'Показать'}));
document.querySelectorAll('form[data-client-action]').forEach(f=>f.addEventListener('submit',async e=>{e.preventDefault();if(changing||(f.dataset.clientConfirm&&!confirm(f.dataset.clientConfirm)))return;const p=f.querySelector('[data-form-status]'),b=f.querySelector('button[type="submit"],button:not([type])'),fields=Object.fromEntries(new FormData(f));b.disabled=true;changing=true;try{await requestClient(fields);const row=allRows.find(r=>r.dataset.id===fields.id);if(fields.operation==='rename'&&row){row.dataset.name=fields.name.trim();row.querySelector('.client-name strong').textContent=fields.name.trim();list()}p.textContent=fields.operation==='secret'?'Секрет сохранён.':'Изменение сохранено.'}catch(err){p.textContent=err.message}finally{b.disabled=false;changing=false}}));
document.addEventListener('submit',async e=>{const form=e.target.closest('form');if(!form||form===createForm||form.matches('[data-client-action]'))return;const action=new URL(form.action,location.href).pathname;if(!['/delete-user','/subscription-action','/openflux-profile'].some(s=>action.endsWith(s)))return;e.preventDefault();e.stopImmediatePropagation();if(form.dataset.confirm&&!confirm(form.dataset.confirm))return;const fields=Object.fromEntries(new FormData(form)),operation=String(fields.operation||''),rawId=String(fields.id||''),row=form.closest('[data-client]')||allRows.find(r=>r.dataset.id===(action.endsWith('/openflux-profile')?'openflux-'+rawId:rawId)),button=form.querySelector('button[type="submit"],button:not([type])');if(button)button.disabled=true;if(row)row.classList.add('client-pending');notice.hidden=false;notice.textContent=operation==='delete'||action.endsWith('/delete-user')?'Удаляем клиента…':'Применяем изменение…';try{await requestForm(form);const deleting=operation==='delete'||action.endsWith('/delete-user');if(deleting&&row){removeClientRow(row);notice.textContent='Клиент удалён.'}else if(row&&action.endsWith('/openflux-profile')&&(operation==='enable'||operation==='disable')){const enabled=operation==='enable';row.classList.remove('client-pending');paintAccess(row,enabled,enabled);const input=form.querySelector('[name=operation]');if(input)input.value=enabled?'disable':'enable';if(button)button.disabled=false;notice.textContent='Состояние OpenFlux изменено.'}else{notice.textContent='Готово. Обновляем список…';location.reload();return}}catch(error){if(row)row.classList.remove('client-pending');if(button)button.disabled=false;notice.textContent=error.message}},true);
document.getElementById('copySelected').addEventListener('click',async()=>{const links=selected().map(r=>r.dataset.link).join('\\n');try{await navigator.clipboard.writeText(links);notice.textContent='Ссылки выбранных клиентов скопированы.'}catch(e){notice.textContent='Браузер не разрешил копирование. Используйте кнопки в строках.'}notice.hidden=false});list();if(location.hash.startsWith('#account-')){const a=document.getElementById(location.hash.slice(1));if(a&&a.closest('dialog'))a.closest('dialog').showModal()}
function bytes(value){let n=Math.max(0,Number(value)||0);for(const u of ['Б','КБ','МБ','ГБ','ТБ']){if(n<1024||u==='ТБ')return (u==='Б'?n.toFixed(0):n.toFixed(1))+' '+u;n/=1024}}
let polling=false;async function pollClients(){if(polling||changing||selected().length||document.querySelector('dialog:modal'))return;polling=true;try{const response=await fetch(clientPath+'/clients-state',{cache:'no-store'});if(response.redirected)throw new Error('Сессия завершена. Войдите заново.');if(!response.ok)throw new Error('Статистика не обновляется. Проверьте связь с панелью.');const data=await response.json();if(changing||selected().length||document.querySelector('dialog:modal'))return;const records=data.clients;if(records.length!==allRows.length||records.some(c=>!allRows.some(r=>r.dataset.id===c.id&&r.dataset.name===c.name&&r.dataset.protocols===c.protocols.join(' ')))){notice.hidden=false;notice.textContent='Данные клиентов изменились. Нажмите «Обновить список».';return}for(const c of records){const row=allRows.find(r=>r.dataset.id===c.id),total=c.up+c.down,flux=c.kind==='openflux';if(c.kind==='subscription'){const cell=row.querySelector('.hwid-cell');cell.firstChild.textContent=c.limit?c.devices+' / '+c.limit:'Без лимита';cell.querySelector('small').textContent=c.limit?'HWID':'Без привязки'}row.dataset.enabled=c.enabled?'1':'0';row.dataset.active=c.active?'1':'0';row.dataset.traffic=String(total);const access=row.querySelector('[role=switch]');if(access)access.setAttribute('aria-checked',c.enabled?'true':'false');row.querySelectorAll('.badge').forEach(badge=>{badge.classList.toggle('on',c.active&&c.enabled);badge.textContent=!c.enabled?'Отключена':flux?(c.active?'Работает':'Остановлен'):(c.active?'Передаёт трафик':'Нет трафика')});if(!flux){row.querySelector('.traffic-cell b').textContent=bytes(total);row.querySelector('.traffic-cell small').textContent='↑ '+bytes(c.up)+' · ↓ '+bytes(c.down);row.querySelector('.traffic-split .up').style.width=(total?c.up/total*100:0)+'%';row.querySelector('.traffic-split .down').style.width=(total?c.down/total*100:0)+'%'}}const counts=[records.length,records.filter(c=>c.active).length,records.filter(c=>c.kind==='subscription').length,bytes(records.reduce((n,c)=>n+c.up+c.down,0))];document.querySelectorAll('.client-stat b').forEach((b,i)=>b.textContent=counts[i]);list()}catch(err){notice.hidden=false;notice.textContent=err.message}finally{polling=false}}
setInterval(pollClients,30000);
</script>'''


def editor_ui(source, path, csrf, presets, has_draft):
    art={'countdown':'◷','cars':'🏎','cats-repair':'🐱','loading':'↻'}
    card_items=[]
    for preset in presets:
        delete=''
        if preset.get('custom') or str(preset.get('id','')).startswith('custom-'):
            delete=f'''<form class="preset-delete" method="post" action="{esc(path)}/custom-preset" data-confirm="Удалить свою заглушку «{esc(preset['name'])}»?"><input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="operation" value="delete"><input type="hidden" name="preset" value="{esc(preset['id'])}"><button class="danger">Удалить</button></form>'''
        card_items.append(f'''<div class="preset"><div class="preset-art">{art.get(preset["id"],"✦")}</div><b>{esc(preset["name"])}</b><p>{esc(preset["description"])}</p><div class="actions"><form method="post" action="{esc(path)}/draft-preset">{hidden(csrf,preset=preset["id"])}<button>Предпросмотр</button></form><form method="post" action="{esc(path)}/apply-preset" data-confirm="Заменить рабочую заглушку пресетом «{esc(preset['name'])}»?">{hidden(csrf,preset=preset["id"])}<button class="primary">Применить</button></form>{delete}</div></div>''')
    cards=''.join(card_items)
    create_card='''<button type="button" class="preset preset-create" id="openCustomPreset"><span class="preset-create-mark">＋</span><b>Создать свою заглушку</b><p>Добавьте название, описание и собственный HTML. Заглушка сохранится в этом списке.</p><span class="btn primary">Создать</span></button>'''
    return f'''<div class="card"><div class="card-title"><h2>Пресеты заглушек</h2><span class="muted" style="font-size:11px">Готовые и собственные страницы</span></div><div class="preset-grid">{create_card}{cards}</div><p class="muted" style="font-size:12px;margin-bottom:0">«Предпросмотр» открывает пресет в редакторе, а «Применить» сразу публикует его и очищает старый черновик.</p></div><div class="card"><div class="card-title"><h2>Редактор главной страницы</h2><span class="pill">{'Черновик' if has_draft else 'Опубликованный исходник'}</span></div><form id="editorForm" method="post" action="{esc(path)}/site-html">{hidden(csrf)}<div class="editor-bar"><span>index.html</span><i>HTML · CSS · JavaScript</i></div><textarea class="code-editor" id="htmlSource" name="html" spellcheck="false" aria-label="HTML главной страницы" required>{esc(source)}</textarea><div class="editor-actions"><div class="actions"><button type="button" id="previewHtml">{icon('chart')}Предпросмотр</button><button formaction="{esc(path)}/save-draft">Сохранить черновик</button></div><button class="primary" id="publishHtml">Опубликовать на сайте</button></div></form><div class="actions" style="margin-top:14px"><form method="post" action="{esc(path)}/discard-draft" data-confirm="Удалить черновик и вернуться к опубликованному исходнику?">{hidden(csrf)}<button class="quiet">Удалить черновик</button></form><small id="previewStatus" role="status">Предпросмотр не изменяет рабочий сайт</small></div><details class="note"><summary>Требования к HTML и изоляция предпросмотра</summary><p>Вставляйте стили и скрипты внутрь HTML. Внешние библиотеки, запросы, формы и сетевые переходы в предпросмотре заблокированы. События подключайте через addEventListener. После публикации проверьте живой сайт.</p></details></div>
<dialog id="customPresetDialog" class="create-dialog preset-create-dialog"><div class="dialog-head"><div><h2>Своя заглушка</h2><small>После сохранения она появится среди остальных пресетов</small></div><button type="button" data-close-dialog aria-label="Закрыть">×</button></div><form method="post" action="{esc(path)}/custom-preset"><input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="operation" value="create"><div class="form-grid"><div><label for="customPresetName">Название</label><input id="customPresetName" name="name" maxlength="80" required placeholder="Например, Скоро открытие"></div><div><label for="customPresetDescription">Краткое описание</label><input id="customPresetDescription" name="description" maxlength="180" placeholder="Что увидит посетитель"></div></div><label for="customPresetHtml">HTML заглушки</label><div class="editor-bar"><span>index.html</span><i>до 1 МБ</i></div><textarea class="code-editor" id="customPresetHtml" name="html" spellcheck="false" required placeholder="<!doctype html>…"></textarea><div class="actions create-actions"><button type="button" data-close-dialog>Отмена</button><button class="primary">Сохранить в пресеты</button></div></form></dialog>
<dialog id="previewDialog" class="preview-dialog"><div class="preview-top"><strong>Предпросмотр заглушки</strong><div class="actions"><div class="range"><button type="button" class="selected" id="previewDesktop">Компьютер</button><button type="button" id="previewPhone">Телефон</button></div><button type="button" data-close-dialog aria-label="Закрыть предпросмотр">×</button></div></div><div id="previewStage" class="preview-stage"><iframe id="landingPreview" title="Изолированный предпросмотр заглушки" sandbox="allow-scripts" referrerpolicy="no-referrer"></iframe></div><p class="preview-caption">Изолированный черновик · рабочий сайт не изменён</p></dialog>
<script>const ef=document.getElementById('editorForm'),pf=document.getElementById('landingPreview'),ps=document.getElementById('previewStatus'),pd=document.getElementById('previewDialog'),cp=document.getElementById('customPresetDialog');document.getElementById('openCustomPreset').addEventListener('click',()=>cp.showModal());document.getElementById('previewHtml').addEventListener('click',async e=>{{const b=e.currentTarget;b.disabled=true;ps.textContent='Подготовка предпросмотра…';try{{const r=await fetch('{esc(path)}/preview-html',{{method:'POST',body:new URLSearchParams(new FormData(ef))}});if(r.redirected)throw new Error('Сессия завершена. Войдите заново.');const d=await r.json();if(!r.ok)throw new Error(d.message||'Ошибка предпросмотра');pf.srcdoc=d.document;pd.showModal();ps.textContent='Предпросмотр обновлён. Рабочий сайт не изменён.'}}catch(err){{ps.textContent=err.message}}finally{{b.disabled=false}}}});['Desktop','Phone'].forEach(mode=>document.getElementById('preview'+mode).addEventListener('click',()=>{{document.getElementById('previewStage').classList.toggle('phone',mode==='Phone');['Desktop','Phone'].forEach(m=>document.getElementById('preview'+m).classList.toggle('selected',m===mode))}}));pd.addEventListener('close',()=>pf.removeAttribute('srcdoc'));ef.addEventListener('submit',e=>{{if(e.submitter&&e.submitter.id==='publishHtml'&&!confirm('Опубликовать текущий HTML на основном сайте?'))e.preventDefault()}});</script>'''


def openflux_ui(state, path, csrf):
    configured=bool(state.get('configured'))
    active=bool(state.get('active'))
    enabled=bool(state.get('enabled'))
    ios=bool(state.get('ios_compatible'))
    status='Запущен' if active else 'Остановлен' if configured else 'Не настроен'
    details=''
    if configured:
        key_field='' if ios else f'''<div class="openflux-field wide"><span>Ключ шифрования</span><div class="openflux-value"><input id="openfluxKey" type="password" readonly value="{esc(state.get("key",""))}" spellcheck="false"><button type="button" data-openflux-reveal="openfluxKey">Показать</button><button type="button" data-openflux-copy="openfluxKey">Копировать</button></div></div>'''
        rotate_action='' if ios else f'''<form method="post" action="{esc(path)}/openflux" data-confirm="Создать новый ключ? Старый ключ сразу перестанет подключаться.">{hidden(csrf,operation='rotate')}<button class="quiet">Новый ключ</button></form>'''
        client_hint=('На iPhone выберите Yandex Docs, вставьте ссылку и нажмите Start VPN. Поле ключа в iOS-клиенте не требуется.' if ios else 'В OpenFlux 1.0.0 для Android выберите Yandex Docs, режим VPN и кодек Batched, затем вставьте ссылку и ключ.')
        details=f'''<div class="openflux-client"><div class="openflux-field"><span>Транспорт</span><b>Yandex Docs</b></div><div class="openflux-field"><span>Клиент</span><b>{'iOS · System VPN' if ios else 'Android · AES-256-GCM'}</b></div><div class="openflux-field"><span>Защита канала</span><b>{'Без AES-шифрования' if ios else 'AES-256-GCM'}</b></div><div class="openflux-field wide"><span>Ссылка для клиента</span><div class="openflux-value"><input id="openfluxUrl" readonly value="{esc(state.get("url",""))}" spellcheck="false"><button type="button" data-openflux-copy="openfluxUrl">Копировать</button></div></div>{key_field}</div><p class="openflux-copy-status" id="openfluxCopyStatus" role="status"></p><div class="openflux-controls"><small>{client_hint} Документ должен открываться в классическом редакторе.</small><div class="actions"><form method="post" action="{esc(path)}/openflux">{hidden(csrf,operation='disable' if enabled else 'enable')}<button>{'Остановить' if enabled else 'Запустить'}</button></form>{rotate_action}</div></div>'''
    checked=' checked' if ios else ''
    mode_note=('Режим iOS отключает AES-шифрование OpenFlux, потому что текущий клиент TestFlight не принимает общий ключ.' if ios else 'Android-режим использует отдельный ключ AES-256-GCM. Для iPhone включите совместимость ниже.')
    return f'''<section class="card openflux-card"><div class="openflux-head"><div class="openflux-title"><span class="openflux-mark">OF</span><div><h2>OpenFlux через Яндекс Документы</h2><p>Экспериментальный TCP-туннель без открытого входящего порта</p></div></div><span class="openflux-status {'on' if active else ''}"><i></i>{status}</span></div><form class="openflux-form" method="post" action="{esc(path)}/openflux">{hidden(csrf,operation='save')}<label for="openfluxDocument">Ссылка на документ Яндекса</label><div class="openflux-input"><input id="openfluxDocument" name="url" type="url" required maxlength="2048" autocomplete="off" spellcheck="false" placeholder="https://disk.yandex.ru/i/…" value="{esc(state.get('url',''))}"><button class="primary">{'Применить настройки' if configured else 'Настроить OpenFlux'}</button></div><label style="display:flex;align-items:flex-start;gap:10px;margin-top:14px;padding:13px;border:1px solid var(--line);border-radius:10px;background:var(--input);cursor:pointer"><input type="checkbox" name="ios_compatible" value="1"{checked} style="width:17px;height:17px;margin-top:1px;accent-color:var(--accent)"><span><b style="display:block;margin-bottom:4px">Совместимость с iOS</b><small style="display:block;color:var(--muted);font-weight:400;line-height:1.5">{mode_note}</small></span></label></form>{details}</section><script>(()=>{{const status=document.getElementById('openfluxCopyStatus');document.querySelectorAll('[data-openflux-copy]').forEach(button=>button.addEventListener('click',async()=>{{const field=document.getElementById(button.dataset.openfluxCopy);try{{await wppCopy(field.value,button);if(status)status.textContent='Скопировано.'}}catch(e){{field.type='text';field.focus();field.select();if(status)status.textContent='Скопируйте выделенное значение вручную.'}}}}));document.querySelectorAll('[data-openflux-reveal]').forEach(button=>button.addEventListener('click',()=>{{const field=document.getElementById(button.dataset.openfluxReveal),show=field.type==='password';field.type=show?'text':'password';button.textContent=show?'Скрыть':'Показать'}}))}})();</script>'''


def chart(history, hours):
    end=int(time.time()); start=end-hours*3600
    points=[p for p in history if start<=p.get('time',0)<=end]
    valid=[p for p in points if p.get('up_rate') is not None and p.get('down_rate') is not None]
    if len(valid)<2: return '<div class="chart-empty">'+icon('chart')+'<span>История ещё накапливается<br>Первые точки появятся примерно через минуту</span></div>'
    # A newly installed graph should not be an invisible line at the far right.
    start=max(start,min(p['time'] for p in valid)-15)
    span=max(60,end-start)
    ceiling=max(1,max(max(p['up_rate'],p['down_rate']) for p in valid))*1.15
    paths=[]
    for key,color in [('up_rate','var(--accent)'),('down_rate','var(--amber)')]:
        segments=[]; last=None
        for p in points:
            value=p.get(key)
            if value is None: last=None; continue
            x=52+(p['time']-start)/span*738; y=184-min(1,max(0,value)/ceiling)*166
            segments.append(('M' if last is None or p['time']-last>120 else 'L')+f'{x:.1f},{y:.1f}')
            last=p['time']
        paths.append(f'<path d="{" ".join(segments)}" fill="none" stroke="{color}" stroke-width="2" vector-effect="non-scaling-stroke"/>')
    grid=''.join(f'<line x1="52" y1="{18+i*55.3:.1f}" x2="790" y2="{18+i*55.3:.1f}" stroke="var(--line)"/><text x="45" y="{22+i*55.3:.1f}" text-anchor="end">{size(ceiling*(1-i/3))}</text>' for i in range(4))
    ticks=''.join(f'<text x="{52+i*246}" y="210" text-anchor="{"start" if i==0 else "end" if i==3 else "middle"}">{time.strftime("%H:%M",time.gmtime(start+i*span/3))}</text>' for i in range(4))
    return '<svg viewBox="0 0 810 220" role="img" aria-label="Скорость трафика прокси за выбранный период">'+grid+''.join(paths)+ticks+'</svg>'


def _dashboard_body_legacy(data, subs, profiles, traffic, path, domain, csrf, proxy_link, current, hours=1):
    subs = live_subscriptions(subs, profiles)
    latest=data.get('latest',{}); age=max(0,int(time.time())-latest.get('time',0)); fresh=bool(latest) and age<=120
    fault=data.get('collector_error',{})
    if fault and fault.get('time',0)>=latest.get('time',0): fresh=False
    traffic_fresh=fresh and latest.get('traffic_fresh',True)
    health=''
    if not fresh:
        reason='Измерения VPS ещё не получены.' if not latest else 'Измерения VPS не обновляются.'
        health='<div class="note warning" role="status">'+reason+' Проверьте сборщик через SSH: <code>systemctl status wpp-metrics.service wpp-metrics.timer</code>. Журнал: <code>journalctl -u wpp-metrics.service -n 30 --no-pager</code>. Если таймер не установлен — <code>python3 -c "from chimera.modules.wpp_metrics import install_timer; print(install_timer())"</code></div>'
    elif not traffic_fresh:
        health='<div class="note warning" role="status">Ресурсы VPS измеряются, но нет свежих счётчиков трафика. Проверьте через SSH: <code>systemctl status wpp-metrics.service wpp-metrics.timer</code>. Журнал: <code>journalctl -u wpp-metrics.service -n 30 --no-pager</code>.</div>'
    graph=chart(data.get('history',[]),hours)
    if not fresh or not traffic_fresh:
        graph='<div class="chart-empty">'+icon('chart')+'<span>Нет свежих измерений<br>Диагностика сборщика указана выше</span></div>'
    resources=[]
    for key,label,used,total in [('cpu','Процессор',latest.get('cpu'),100),('ram','Память',latest.get('ram_used'),latest.get('ram_total')),('swap','Подкачка',latest.get('swap_used'),latest.get('swap_total')),('disk','Диск',latest.get('disk_used'),latest.get('disk_total'))]:
        percent=used/total*100 if used is not None and total and fresh else None
        text=f'{percent:.1f}%' if percent is not None else '—'
        detail=f'Ядер: {latest.get("cores", "—")} · средняя загрузка' if key=='cpu' else ('Не используется' if key=='swap' and total==0 else size(used)+' / '+size(total))
        resources.append(f'<div class="resource"><div class="resource-ring" style="--value:{max(0,min(100,percent or 0)):.2f}%"><b>{text}</b></div><div class="resource-copy"><strong>{label}</strong><small>{detail}</small></div></div>')
    direct=[u for u in profiles if not u.get('subscription_id')]
    active=sum(aggregate(s['live_profile_ids'],traffic,s.get('enabled',True))['active'] for s in subs)+sum(aggregate([u['id']],traffic,u.get('enabled',True))['active'] for u in direct)
    total_up=sum(max(0,int(v.get('up',0))) for v in traffic.values() if isinstance(v,dict)); total_down=sum(max(0,int(v.get('down',0))) for v in traffic.values() if isinstance(v,dict))
    stats=''.join(f'<div class="overview-stat"><span>{label}</span><b>{value}</b></div>' for label,value in [('Клиенты',len(subs)+len(direct)),('Подписок',len(subs)),('Передают трафик',active),('Всего трафика',size(total_up+total_down))])
    services=latest.get('services',{}); names={'xray':'Xray · VLESS / Hysteria2','relay':'Telegram WEB Proxy / MTProto','awg':'AmneziaWG 2.0 / 3.1','openflux':'OpenFlux · Yandex Docs','caddy':'Caddy · HTTPS','panel':'Панель управления'}
    services_html=''.join('<div class="service-line"><span>'+label+'</span><span class="badge '+('on' if fresh and services.get(key,{}).get('state')=='active' else '')+'">'+('Запущен' if fresh and services.get(key,{}).get('state')=='active' else esc(services.get(key,{}).get('state','Нет данных')) if fresh else 'Нет свежих данных')+'</span></div>' for key,label in names.items())
    xray=services.get('xray',{}); start=xray.get('start_us'); xu=max(0,latest.get('uptime',0)-start/1e6) if start and latest.get('uptime') else None
    detail=[('Время работы VPS',duration(latest.get('uptime'))),('Время работы Xray',duration(xu)),('Память Xray',size(xray.get('memory'))),('Задачи Xray',str(xray.get('tasks') if xray.get('tasks') is not None else '—')),('Нагрузка · 1 / 5 / 15 мин.',' / '.join(f'{v:.2f}' for v in latest.get('load',[])) or '—')]
    details=''.join(f'<div class="detail-line"><span>{k}</span><strong>{v}</strong></div>' for k,v in detail)
    controls=''.join(f'<button data-range="{n}" class="{"selected" if n==hours else ""}">{n} ч</button>' for n in (1,6,24))
    records=client_records(subs,profiles,traffic,domain,proxy_link)
    shown=sorted(records,key=lambda r:(bool(r['totals']['active']),r['totals']['up']+r['totals']['down']),reverse=True)[:8]
    # New: hourly pattern (Variant B — 24-bar chart) and heatmap (Variant C — 7×24 grid)
    hourly_pattern_html=_render_hourly_pattern(data.get('hourly_pattern'))
    hourly_heatmap_html=_render_hourly_heatmap(data.get('hourly_heatmap'))
    return f'''<div data-live-block="health" class="live-block">{health}</div><section class="card resource-deck live-block" data-live-block="resources"><div class="resource-grid">{''.join(resources)}</div></section><div class="overview-stats live-block" data-live-block="overview">{stats}</div><div class="dashboard-grid"><section class="card graph-card"><div class="card-title"><div><span class="eyebrow">TRAFFIC / LIVE HISTORY</span><h2>Трафик прокси</h2></div><div class="range">{controls}</div></div><div class="graph-speeds live-block" data-live-block="speeds"><div><span>↑ Отправка</span><b>{size(latest.get('up_rate')) if traffic_fresh else '—'}</b><small> / с</small></div><div><span>↓ Получение</span><b>{size(latest.get('down_rate')) if traffic_fresh else '—'}</b><small> / с</small></div></div><div class="chart-wrap live-block" data-live-block="chart">{graph}</div><div class="legend"><span><i></i>Отправка</span><span class="down"><i></i>Получение</span><span>До 24 часов · замер ~10 с · UTC</span></div></section><section class="card"><div class="card-title"><h2>Службы и версия</h2><span class="pill">{esc(current)}</span></div><div class="node-label"><i></i><div class="node-domain">{esc(domain)}</div></div><div class="service-list live-block" data-live-block="services">{services_html}</div><div class="update-box"><div class="actions"><button id="checkUpdate">{icon('refresh')}Загрузить версии</button></div><div class="version-row"><label for="panelRelease">Панель</label><select id="panelRelease" aria-label="Версия панели"><option>Сначала загрузите список</option></select><button class="primary" id="startUpdate" hidden>Установить</button></div><p id="updateStatus" role="status">Можно обновиться или вернуться на прежний стабильный релиз GitHub</p></div></section></div><section class="card hourly-card live-block" data-live-block="hourly-pattern"><div class="card-title"><div><span class="eyebrow">HOURLY PATTERN · LAST 7 DAYS</span><h2>Трафик по часам суток</h2></div></div>{hourly_pattern_html}<p class="note">Средний трафик за каждый час суток за последние 7 дней. Помогает увидеть типичный паттерн использования — когда обычно пик и провал.</p></section><section class="card heatmap-card live-block" data-live-block="hourly-heatmap"><div class="card-title"><div><span class="eyebrow">WEEKLY HEATMAP · 7×24</span><h2>Трафик по дням и часам</h2></div></div>{hourly_heatmap_html}<p class="note">Тепловая карта интенсивности по дням недели и часам. Помогает увидеть разницу между буднями и выходными.</p></section><section class="card version-manager"><div class="card-title"><div><h2>Версии компонентов</h2><p>Обновление и откат без выпуска новой версии панели</p></div><button id="checkComponents">{icon('refresh')}Загрузить версии</button></div><div class="version-row"><label for="xrayRelease">Xray</label><select id="xrayRelease"><option>Сначала загрузите список</option></select><button data-component-install="xray" class="primary" disabled>Установить</button><small class="version-state" id="xrayCurrent">Текущая версия определяется…</small></div><div class="version-row"><label for="openfluxRelease">OpenFlux</label><select id="openfluxRelease"><option>Сначала загрузите список</option></select><button data-component-install="openflux" class="primary" disabled>Установить</button><small class="version-state" id="openfluxCurrent">Текущая версия определяется…</small></div><p id="componentStatus" class="note" role="status">Перед заменой создаётся резервная копия. Если служба не запустится, прежний бинарник восстановится автоматически.</p></section><div class="two-col equal"><section class="card"><div class="card-title"><h2>Ресурсы сервера</h2><span class="pill">VPS</span></div><div class="detail-list live-block" data-live-block="server-details">{details}</div></section><section class="card"><div class="card-title"><h2>Накопленный трафик</h2></div><div class="detail-list live-block" data-live-block="traffic-details"><div class="detail-line"><span>Отправлено</span><strong>↑ {size(total_up)}</strong></div><div class="detail-line"><span>Получено</span><strong>↓ {size(total_down)}</strong></div><div class="detail-line"><span>Последнее измерение</span><strong>{str(age)+' с назад' if latest else 'Нет измерений'}</strong></div></div><p class="note">Только трафик прокси. Активность — передача данных за последние 90 секунд, не число устройств онлайн.</p></section></div><section class="card"><div class="card-title"><h2>Пользователи и подписки</h2><a href="{esc(path)}/users" class="btn quiet">Управление →</a></div><div class="live-block" data-live-block="clients">{client_glances(shown,path)}<small>Показано {len(shown)} из {len(records)} · сначала передающие данные</small></div></section>'''



def _dashboard_page_legacy(body,path,csrf):
    return f'''<div class="page-head"><div><h1>Дашборд</h1><p>Сервер, подключения и использование трафика</p></div><div class="actions"><span id="liveIndicator" class="live-indicator"><i></i><b>Онлайн</b><small id="liveAge">сейчас</small></span><button id="refreshDashboard">{icon('refresh')}Обновить</button></div></div><p id="dashboardNotice" class="note" role="status" hidden></p><div id="dashboardContent">{body}</div><dialog id="updateAvailableDialog" class="update-dialog" aria-labelledby="updateDialogTitle"><div class="dialog-head"><div><small class="eyebrow">НОВАЯ ВЕРСИЯ</small><h2 id="updateDialogTitle">Доступно обновление</h2></div><button type="button" data-close-dialog aria-label="Закрыть уведомление">×</button></div><div class="update-dialog-body"><div class="update-release"><span class="update-release-mark">{icon('refresh')}</span><div><span>WEB PANEL PROXY</span><strong><span id="updateCurrentVersion"></span> → <span id="updateLatestVersion"></span></strong></div></div><p>Перед установкой панель создаст резервную копию. Подключения могут кратковременно прерваться.</p></div><div class="update-dialog-actions"><button type="button" id="updateNoticeLater">Позже</button><button type="button" class="primary" id="updateNoticeInstall">Обновить</button></div></dialog><script>
const root=document.getElementById('dashboardContent'),notice=document.getElementById('dashboardNotice'),live=document.getElementById('liveIndicator'),liveAge=document.getElementById('liveAge'),updateDialog=document.getElementById('updateAvailableDialog');let range=1,busy=false,updating=false,lastSuccess=Date.now();try{{window._browserTZ=Intl.DateTimeFormat().resolvedOptions().timeZone||'Europe/Moscow'}}catch(e){{window._browserTZ='Europe/Moscow'}}
function updateDismissed(version){{try{{return localStorage.getItem('wpp-update-dismissed:'+version)==='1'}}catch(e){{return false}}}}
function dismissUpdate(version){{try{{localStorage.setItem('wpp-update-dismissed:'+version,'1')}}catch(e){{}}}}
function maybeNotifyUpdate(d){{window.dispatchEvent(new CustomEvent('wpp-update-status',{{detail:d}}))}}
function updateView(d){{const p=document.getElementById('updateStatus'),b=document.getElementById('startUpdate'),select=document.getElementById('panelRelease');if(!p||!b||!select)return;updating=['queued','running'].includes(d.phase);if(Array.isArray(d.releases)&&d.releases.length){{const old=select.value;select.innerHTML=d.releases.map(v=>'<option value="'+v+'">'+v.replace(/^v/,'')+(v.replace(/^v/,'')===(d.current||'').replace(/^v/,'')?' · установлена':'')+'</option>').join('');if(d.releases.includes(old))select.value=old}}p.textContent=d.message||(d.checked?'Версии загружены.':'Опубликованные стабильные релизы GitHub');b.hidden=!Array.isArray(d.releases)||!d.releases.length||updating;b.textContent='Установить выбранную';document.getElementById('checkUpdate').disabled=updating;select.disabled=updating;if(updating){{notice.hidden=false;notice.textContent='Изменение версии выполняется. Панель может временно отключиться; не запускайте повторную установку.'}}if(d.available)maybeNotifyUpdate(d)}}
function patchLive(html){{const template=document.createElement('template');template.innerHTML=html;template.content.querySelectorAll('[data-live-block]').forEach(next=>{{const current=root.querySelector('[data-live-block="'+CSS.escape(next.dataset.liveBlock)+'"]');if(!current||current.innerHTML===next.innerHTML)return;current.classList.add('refreshing');requestAnimationFrame(()=>{{current.innerHTML=next.innerHTML;current.className=next.className;current.setAttribute('data-live-block',next.dataset.liveBlock)}})}});root.querySelectorAll('[data-range]').forEach(b=>b.classList.toggle('selected',Number(b.dataset.range)===range))}}
function updateClock(){{const seconds=Math.floor((Date.now()-lastSuccess)/1000);liveAge.textContent=seconds<2?'сейчас':seconds+' с назад';live.classList.toggle('stale',seconds>20);live.classList.toggle('offline',seconds>45)}}
async function refresh(){{if(busy||document.hidden)return;busy=true;try{{const r=await fetch('{esc(path)}/dashboard-data?hours='+range+'&tz='+encodeURIComponent(window._browserTZ||'Europe/Moscow'),{{cache:'no-store'}});if(r.redirected){{location.href='{esc(path)}/login';return}}if(!r.ok)throw new Error('Нет ответа от панели');const d=await r.json();patchLive(d.html);updateView(d.update);lastSuccess=Date.now();updateClock();if(!updating)notice.hidden=true}}catch(e){{live.classList.add('offline');notice.hidden=false;notice.textContent=updating?'Панель перезапускается во время обновления. Ожидаем восстановления связи…':'Нет связи с панелью. Данные на экране могут быть устаревшими.'}}finally{{busy=false}}}}
async function automaticUpdateCheck(status){{if(status?.checked&&Date.now()/1000-Number(status.checked)<21600)return;try{{const r=await fetch('{esc(path)}/update-check',{{method:'POST',body:new URLSearchParams({{csrf:'{esc(csrf)}'}})}});if(!r.ok||r.redirected)return;updateView(await r.json())}}catch(e){{}}}}
document.getElementById('updateNoticeLater').addEventListener('click',()=>updateDialog.close());document.getElementById('updateNoticeInstall').addEventListener('click',()=>{{const button=document.getElementById('startUpdate');updateDialog.close();if(button&&!button.hidden)button.click()}});updateDialog.addEventListener('close',()=>{{if(updateDialog.dataset.version)dismissUpdate(updateDialog.dataset.version)}});
document.getElementById('refreshDashboard').addEventListener('click',refresh);root.addEventListener('click',async e=>{{const r=e.target.closest('[data-range]');if(r){{range=Number(r.dataset.range);refresh();return}}const b=e.target.closest('#checkUpdate,#startUpdate');if(!b||busy)return;const start=b.id==='startUpdate',target=document.getElementById('panelRelease').value;if(start&&!confirm('Установить версию '+target+'? Будет создана резервная копия. Панель и подключения могут временно прерваться.'))return;busy=true;b.disabled=true;try{{const body={{csrf:'{esc(csrf)}'}};if(start)body.target=target;const r=await fetch('{esc(path)}/'+(start?'update-start':'update-check'),{{method:'POST',body:new URLSearchParams(body)}});if(r.redirected)throw new Error('Сессия завершена. Войдите заново.');const d=await r.json();if(!r.ok)throw new Error(d.message||'Ошибка обновления');updateView(d)}}catch(err){{document.getElementById('updateStatus').textContent=err.message}}finally{{busy=false;b.disabled=false}}}});
function componentView(d){{const catalog=d.catalog||{{}},current=d.current||{{}},running=['queued','running'].includes(d.phase);for(const name of ['xray','openflux']){{const select=document.getElementById(name+'Release'),button=document.querySelector('[data-component-install="'+name+'"]'),versions=catalog[name]||[];if(versions.length){{const old=select.value;select.innerHTML=versions.map(v=>'<option value="'+v+'">'+v.replace(/^v/,'')+'</option>').join('');if(versions.includes(old))select.value=old}}select.disabled=running||!versions.length;button.disabled=running||!versions.length;document.getElementById(name+'Current').textContent='Установлено: '+(current[name]||'неизвестно')}}document.getElementById('componentStatus').textContent=d.message||'Выберите опубликованную версию GitHub.'}}
document.getElementById('checkComponents').addEventListener('click',async e=>{{const b=e.currentTarget;b.disabled=true;try{{const r=await fetch('{esc(path)}/component-check',{{method:'POST',body:new URLSearchParams({{csrf:'{esc(csrf)}'}})}}),d=await r.json();if(!r.ok)throw new Error(d.message||'Ошибка загрузки версий');componentView(d)}}catch(err){{document.getElementById('componentStatus').textContent=err.message}}finally{{b.disabled=false}}}});document.querySelectorAll('[data-component-install]').forEach(button=>button.addEventListener('click',async()=>{{const component=button.dataset.componentInstall,target=document.getElementById(component+'Release').value;if(!confirm('Установить '+component+' '+target+'? При ошибке будет выполнен автоматический откат.'))return;button.disabled=true;try{{const r=await fetch('{esc(path)}/component-install',{{method:'POST',body:new URLSearchParams({{csrf:'{esc(csrf)}',component,target}})}}),d=await r.json();if(!r.ok)throw new Error(d.message||'Ошибка установки');componentView(d)}}catch(err){{document.getElementById('componentStatus').textContent=err.message}}}}));
setInterval(refresh,5000);setInterval(updateClock,1000);setInterval(()=>fetch('{esc(path)}/component-status',{{cache:'no-store'}}).then(r=>r.ok?r.json():null).then(d=>d&&componentView(d)).catch(()=>{{}}),5000);document.addEventListener('visibilitychange',()=>{{if(!document.hidden)refresh()}});fetch('{esc(path)}/update-status',{{cache:'no-store'}}).then(r=>r.ok&&!r.redirected?r.json():null).then(d=>{{if(d){{updateView(d);automaticUpdateCheck(d)}}}}).catch(()=>automaticUpdateCheck(null));fetch('{esc(path)}/component-status',{{cache:'no-store'}}).then(r=>r.ok?r.json():null).then(d=>d&&componentView(d)).catch(()=>{{}});
</script>'''


def dashboard_body(data, subs, profiles, traffic, path, domain, csrf, proxy_link, current, hours=1):
    """Dashboard overview without version management controls."""
    body = _dashboard_body_legacy(data, subs, profiles, traffic, path, domain, csrf, proxy_link, current, hours)
    replacement = (f'<div class="update-box"><div class="actions">'
                   f'<a class="btn quiet" href="{esc(path)}/updates">{icon("refresh")}Управление обновлениями</a>'
                   f'</div><p>Версии панели, Xray и OpenFlux находятся в отдельном разделе.</p></div>'
                   f'</section></div><div class="two-col equal">')
    return re.sub(r'<div class="update-box">.*?</div></section></div><section class="card version-manager">.*?</section><div class="two-col equal">',
                  replacement, body, count=1, flags=re.S)


def dashboard_page(body, path, csrf):
    return f'''<div class="page-head"><div><h1>Дашборд</h1><p>Сервер, подключения и использование трафика</p></div><div class="actions"><span id="liveIndicator" class="live-indicator"><i></i><b>Онлайн</b><small id="liveAge">сейчас</small></span><button id="refreshDashboard">{icon('refresh')}Обновить</button></div></div><p id="dashboardNotice" class="note" role="status" hidden></p><div id="dashboardContent">{body}</div><dialog id="updateAvailableDialog" class="update-dialog" aria-labelledby="updateDialogTitle"><div class="dialog-head"><div><small class="eyebrow">НОВАЯ ВЕРСИЯ</small><h2 id="updateDialogTitle">Доступно обновление</h2></div><button type="button" data-close-dialog aria-label="Закрыть уведомление">×</button></div><div class="update-dialog-body"><div class="update-release"><span class="update-release-mark">{icon('refresh')}</span><div><span>WEB PANEL PROXY</span><strong><span id="updateCurrentVersion"></span> → <span id="updateLatestVersion"></span></strong></div></div><p>Подробности, выбор версии и безопасная установка находятся в разделе «Обновления».</p></div><div class="update-dialog-actions"><button type="button" id="updateNoticeLater">Позже</button><a class="btn primary" href="{esc(path)}/updates">Открыть обновления</a></div></dialog><script>
const root=document.getElementById('dashboardContent'),notice=document.getElementById('dashboardNotice'),live=document.getElementById('liveIndicator'),liveAge=document.getElementById('liveAge'),updateDialog=document.getElementById('updateAvailableDialog');let range=1,busy=false,updating=false,lastSuccess=Date.now();try{{window._browserTZ=Intl.DateTimeFormat().resolvedOptions().timeZone||'Europe/Moscow'}}catch(e){{window._browserTZ='Europe/Moscow'}}
function updateDismissed(version){{try{{return localStorage.getItem('wpp-update-dismissed:'+version)==='1'}}catch(e){{return false}}}}
function dismissUpdate(version){{try{{localStorage.setItem('wpp-update-dismissed:'+version,'1')}}catch(e){{}}}}
function maybeNotifyUpdate(d){{window.dispatchEvent(new CustomEvent('wpp-update-status',{{detail:d}}))}}
function updateView(d){{if(!d)return;updating=['queued','running'].includes(d.phase);if(updating){{notice.hidden=false;notice.textContent='Изменение версии выполняется. Откройте раздел «Обновления», чтобы увидеть статус.'}}if(d.available)maybeNotifyUpdate(d)}}
function patchLive(html){{const template=document.createElement('template');template.innerHTML=html;template.content.querySelectorAll('[data-live-block]').forEach(next=>{{const current=root.querySelector('[data-live-block="'+CSS.escape(next.dataset.liveBlock)+'"]');if(!current||current.innerHTML===next.innerHTML)return;current.classList.add('refreshing');requestAnimationFrame(()=>{{current.innerHTML=next.innerHTML;current.className=next.className;current.setAttribute('data-live-block',next.dataset.liveBlock)}})}});root.querySelectorAll('[data-range]').forEach(b=>b.classList.toggle('selected',Number(b.dataset.range)===range))}}
function updateClock(){{const seconds=Math.floor((Date.now()-lastSuccess)/1000);liveAge.textContent=seconds<2?'сейчас':seconds+' с назад';live.classList.toggle('stale',seconds>20);live.classList.toggle('offline',seconds>45)}}
async function refresh(){{if(busy||document.hidden)return;busy=true;try{{const r=await fetch('{esc(path)}/dashboard-data?hours='+range+'&tz='+encodeURIComponent(window._browserTZ||'Europe/Moscow'),{{cache:'no-store'}});if(r.redirected){{location.href='{esc(path)}/login';return}}if(!r.ok)throw new Error('Нет ответа от панели');const d=await r.json();patchLive(d.html);updateView(d.update);lastSuccess=Date.now();updateClock();if(!updating)notice.hidden=true}}catch(e){{live.classList.add('offline');notice.hidden=false;notice.textContent=updating?'Панель перезапускается во время обновления. Ожидаем восстановления связи…':'Нет связи с панелью. Данные на экране могут быть устаревшими.'}}finally{{busy=false}}}}
async function automaticUpdateCheck(status){{if(status?.checked&&Date.now()/1000-Number(status.checked)<21600)return;try{{const r=await fetch('{esc(path)}/update-check',{{method:'POST',body:new URLSearchParams({{csrf:'{esc(csrf)}'}})}});if(!r.ok||r.redirected)return;updateView(await r.json())}}catch(e){{}}}}
document.getElementById('updateNoticeLater').addEventListener('click',()=>updateDialog.close());updateDialog.addEventListener('close',()=>{{if(updateDialog.dataset.version)dismissUpdate(updateDialog.dataset.version)}});document.getElementById('refreshDashboard').addEventListener('click',refresh);root.addEventListener('click',e=>{{const r=e.target.closest('[data-range]');if(r){{range=Number(r.dataset.range);refresh()}}}});setInterval(refresh,5000);setInterval(updateClock,1000);document.addEventListener('visibilitychange',()=>{{if(!document.hidden)refresh()}});fetch('{esc(path)}/update-status',{{cache:'no-store'}}).then(r=>r.ok&&!r.redirected?r.json():null).then(d=>{{if(d){{updateView(d);automaticUpdateCheck(d)}}}}).catch(()=>automaticUpdateCheck(null));
</script>'''


def updates_ui(path, csrf, current):
    return f'''<div class="page-head"><div><span class="eyebrow">WPP / RELEASE CONTROL</span><h1>Обновления</h1><p>Версии панели и системных компонентов в одном месте</p></div><button id="refreshAll">{icon('refresh')}Обновить списки</button></div>
<section class="card updates-hero"><div class="updates-hero-copy"><span class="updates-hero-icon">{icon('refresh')}</span><div><h2>Центр обновлений</h2><p>Можно установить новую версию или вернуться на предыдущую. Перед заменой автоматически создаётся резервная копия.</p></div></div><div class="actions"><span class="pill">RC · ручная установка</span></div></section>
<div class="updates-grid">
<section class="card updates-card"><div class="card-title"><div><h2>WEB PANEL PROXY</h2><p>Интерфейс, менеджер подключений и служебные модули</p></div><span class="pill">Панель</span></div><div class="update-installed"><span>Установленная версия</span><strong id="panelCurrent">{esc(current)}</strong></div><div class="update-control"><label for="panelRelease">Доступная версия</label><select id="panelRelease" aria-label="Версия панели"><option>Загрузите список версий</option></select><button class="primary" id="startUpdate" disabled>Установить</button></div><p id="updateStatus" class="note update-status" role="status">Проверяем опубликованные релизы…</p></section>
<section class="card updates-card"><div class="card-title"><div><h2>Компоненты</h2><p>Xray и OpenFlux обновляются независимо от панели</p></div><span class="pill">Ядро</span></div><div class="component-stack"><div class="component-item"><div class="component-item-head"><strong>Xray</strong><small id="xrayCurrent">Версия определяется…</small></div><div class="update-control"><label for="xrayRelease">Версия</label><select id="xrayRelease"><option>Загрузите список версий</option></select><button class="primary" data-component-install="xray" disabled>Установить</button></div></div><div class="component-item"><div class="component-item-head"><strong>OpenFlux</strong><small id="openfluxCurrent">Версия определяется…</small></div><div class="update-control"><label for="openfluxRelease">Версия</label><select id="openfluxRelease"><option>Загрузите список версий</option></select><button class="primary" data-component-install="openflux" disabled>Установить</button></div></div></div><p id="componentStatus" class="note update-status" role="status">Проверяем версии компонентов…</p></section>
</div><div class="update-safety"><div><b>Резервная копия</b><small>Создаётся до замены файлов и бинарников.</small></div><div><b>Проверка запуска</b><small>После установки служба проходит автоматическую проверку.</small></div><div><b>Автоматический откат</b><small>Если новая версия не запустится, прежняя будет восстановлена.</small></div></div>
<script>
const panelSelect=document.getElementById('panelRelease'),panelButton=document.getElementById('startUpdate'),panelStatus=document.getElementById('updateStatus'),componentStatus=document.getElementById('componentStatus');let panelBusy=false;
function panelView(d){{if(!d)return;panelBusy=['queued','running'].includes(d.phase);document.getElementById('panelCurrent').textContent=d.current||'{esc(current)}';const releases=Array.isArray(d.releases)?d.releases:[];if(releases.length){{const old=panelSelect.value;panelSelect.innerHTML=releases.map(v=>'<option value="'+v+'">'+v.replace(/^v/,'')+(v.replace(/^v/,'')===(d.current||'').replace(/^v/,'')?' · установлена':'')+'</option>').join('');if(releases.includes(old))panelSelect.value=old}}panelSelect.disabled=panelBusy||!releases.length;panelButton.disabled=panelBusy||!releases.length;panelButton.textContent=panelBusy?'Установка…':'Установить';panelStatus.textContent=d.message||(d.checked?'Версии панели загружены.':'Нажмите «Обновить списки».')}}
function componentView(d){{if(!d)return;const catalog=d.catalog||{{}},current=d.current||{{}},running=['queued','running'].includes(d.phase);for(const name of ['xray','openflux']){{const select=document.getElementById(name+'Release'),button=document.querySelector('[data-component-install="'+name+'"]'),versions=catalog[name]||[];if(versions.length){{const old=select.value;select.innerHTML=versions.map(v=>'<option value="'+v+'">'+v.replace(/^v/,'')+(v.replace(/^v/,'')===String(current[name]||'').replace(/^v/,'')?' · установлена':'')+'</option>').join('');if(versions.includes(old))select.value=old}}select.disabled=running||!versions.length;button.disabled=running||!versions.length;document.getElementById(name+'Current').textContent='Установлено: '+(current[name]||'неизвестно')}}componentStatus.textContent=d.message||(d.checked?'Версии компонентов загружены.':'Нажмите «Обновить списки».')}}
async function request(endpoint,data,status){{const r=await fetch('{esc(path)}/'+endpoint,{{method:'POST',body:new URLSearchParams({{csrf:'{esc(csrf)}',...data}})}});if(r.redirected)throw new Error('Сессия завершена. Войдите заново.');let result;try{{result=await r.json()}}catch(e){{throw new Error('Панель вернула некорректный ответ.')}}if(!r.ok)throw new Error(result.message||'Операция завершилась ошибкой.');return result}}
async function loadPanel(check=false){{try{{const d=check?await request('update-check',{{}},panelStatus):await fetch('{esc(path)}/update-status',{{cache:'no-store'}}).then(r=>r.json());panelView(d)}}catch(e){{panelStatus.textContent=e.message}}}}
async function loadComponents(check=false){{try{{const d=check?await request('component-check',{{}},componentStatus):await fetch('{esc(path)}/component-status',{{cache:'no-store'}}).then(r=>r.json());componentView(d)}}catch(e){{componentStatus.textContent=e.message}}}}
document.getElementById('refreshAll').addEventListener('click',async e=>{{const b=e.currentTarget;b.disabled=true;b.textContent='Загрузка…';await Promise.all([loadPanel(true),loadComponents(true)]);b.disabled=false;b.innerHTML='{icon('refresh')}Обновить списки'}});
panelButton.addEventListener('click',async()=>{{const target=panelSelect.value;if(!confirm('Установить панель '+target+'? Панель и подключения могут кратковременно прерваться.'))return;panelButton.disabled=true;try{{panelView(await request('update-start',{{target}},panelStatus))}}catch(e){{panelStatus.textContent=e.message;panelButton.disabled=false}}}});
document.querySelectorAll('[data-component-install]').forEach(button=>button.addEventListener('click',async()=>{{const component=button.dataset.componentInstall,target=document.getElementById(component+'Release').value;if(!confirm('Установить '+component+' '+target+'? При ошибке будет выполнен автоматический откат.'))return;button.disabled=true;try{{componentView(await request('component-install',{{component,target}},componentStatus))}}catch(e){{componentStatus.textContent=e.message;button.disabled=false}}}}));
loadPanel();loadComponents();setInterval(()=>{{loadPanel();loadComponents()}},5000);
</script>'''

# ─── Portal UI functions (appended to wpp_ui.py) ────────────────────────────


def portal_login_page(path, csrf, error=""):
    """User Portal login page — WPP-styled, cookie-based auth."""
    error_html = ""
    if error:
        error_html = (
            f'<div class="portal-error">{esc(error)}</div>'
        )
    return f'''<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>User Portal — Вход</title>
<script>try{{var t=localStorage.getItem('wpp-theme');document.documentElement.dataset.theme=t==='light'?'light':'dark'}}catch(e){{document.documentElement.dataset.theme='dark'}}</script>
<style>
:root{{--bg:#101318;--surface:#1b1e24;--raised:#22262e;--input:#171a20;
--line:#303641;--text:#f3f5f8;--muted:#93a0b8;--accent:#3b82f6;
--on-accent:#fff;--tint:#3b82f619;--green:#41c78d;--red:#f06f75;
--amber:#dcae43;--yellow:#dcae43;--shadow:0 14px 46px #0006;
--radius:14px;color-scheme:dark}}
:root[data-theme=light]{{--bg:#f3f5f8;--surface:#fff;--raised:#eef1f5;
--input:#f9fafc;--text:#202630;--muted:#667188;--line:#d8dde6;
--accent:#2563d9;--on-accent:#fff;--tint:#2563d912;--green:#25865b;
--amber:#916918;--yellow:#916918;--red:#bd464c;
--shadow:0 8px 30px #17203614;--radius:14px;color-scheme:light}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{min-height:100vh;display:grid;place-items:center;padding:24px;
font:15px/1.6 -apple-system,system-ui,sans-serif;background:var(--bg);color:var(--text)}}
.wrap{{width:min(420px,100%);padding:36px 32px;border:1px solid var(--line);
border-radius:var(--radius);background:var(--surface);box-shadow:var(--shadow)}}
.logo{{display:grid;place-items:center;width:52px;height:52px;margin:0 auto 24px;
border-radius:14px;background:var(--accent);color:var(--on-accent);font-size:24px;
font-weight:700}}
h1{{text-align:center;font-size:22px;font-weight:600;margin-bottom:6px}}
.sub{{text-align:center;color:var(--muted);font-size:13px;margin-bottom:28px}}
label{{display:block;font-size:12px;color:var(--muted);margin:0 0 6px 2px}}
input{{width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:10px;
background:var(--input);color:var(--text);font:14px/1.5 inherit;outline:none;transition:border .15s}}
input:focus{{border-color:var(--accent)}}
.input-group{{margin-bottom:18px}}
.btn{{display:block;width:100%;padding:13px;border:0;border-radius:10px;
background:var(--accent);color:var(--on-accent);font:600 14px inherit;cursor:pointer;transition:opacity .15s}}
.btn:hover{{opacity:.88}}
.portal-error{{margin-bottom:18px;padding:11px 14px;border:1px solid var(--red);
border-radius:10px;background:rgba(248,113,113,.08);color:var(--red);font-size:13px;text-align:center}}
.foot{{margin-top:22px;text-align:center;font-size:11px;color:var(--muted)}}
</style></head><body>
<div class="wrap">
<div class="logo">VPN</div>
<h1>User Portal</h1>
<p class="sub">Управление подключением, трафиком и IP-адресами</p>
{error_html}
<form method="post" action="/portal/login" autocomplete="on">
<div class="input-group">
<label for="portalLogin">Email или логин</label>
<input id="portalLogin" name="login" type="text" required autocomplete="username" autofocus>
</div>
<div class="input-group">
<label for="portalPass">Пароль</label>
<input id="portalPass" name="password" type="password" required autocomplete="current-password">
</div>
<button class="btn" type="submit">Войти</button>
</form>
<div class="foot">Chimera · WPP Portal</div>
</div>
</body></html>'''


TRAFFIC_CSS = '''/* traffic tab */
.tf-hero{background:linear-gradient(135deg,var(--raised),var(--surface));border:1px solid var(--line);border-radius:var(--radius);padding:22px;margin-bottom:16px;position:relative;overflow:hidden}
.tf-hero::before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 100% 0,var(--tint),transparent 55%);pointer-events:none}
.tf-hero-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;position:relative}
.tf-hero-ico{font-size:24px;opacity:.85;line-height:1}
.tf-hero-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.tf-hero-num{font:700 32px/1.15 ui-monospace,monospace;color:var(--text);margin:6px 0 2px;letter-spacing:-.02em}
.tf-hero-sub{font-size:12px;color:var(--muted)}
.tf-split{display:flex;gap:14px;margin-top:16px;position:relative}
.tf-split-col{flex:1;min-width:0}
.tf-split-row{display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--muted);margin-bottom:6px}
.tf-split-row b{color:var(--text);font:600 12px ui-monospace,monospace}
.tf-split-track{height:7px;border-radius:4px;background:var(--input);overflow:hidden}
.tf-split-fill{height:100%;border-radius:4px;transform-origin:left center;animation:tfGrowX .6s ease both}
.tf-split-fill.up{background:var(--accent)}
.tf-split-fill.down{background:var(--green)}
.tf-daily{margin-bottom:16px}
.tf-chart{display:flex;align-items:flex-end;gap:5px;height:130px;padding:6px 2px 4px;overflow-x:auto;scrollbar-width:thin;scrollbar-color:var(--line) transparent}
.tf-bar-col{flex:1 1 0;min-width:20px;max-width:40px;display:flex;flex-direction:column;align-items:center;gap:5px;height:100%;justify-content:flex-end}
.tf-bar{width:100%;max-width:34px;border-radius:5px 5px 0 0;background:linear-gradient(180deg,var(--green),color-mix(in srgb,var(--green) 30%,var(--input)));min-height:3px;transform-origin:bottom;animation:tfGrowY .7s cubic-bezier(.2,.8,.2,1) both;transition:filter .15s}
.tf-bar.zero{background:var(--input);opacity:.55}
.tf-bar:hover{filter:brightness(1.25)}
.tf-bar-date{font:9px ui-monospace,monospace;color:var(--muted);white-space:nowrap}
.tf-empty{padding:28px 12px;text-align:center;color:var(--muted);font-size:12px;line-height:1.7}
.tf-empty .ico{font-size:24px;opacity:.6;margin-bottom:10px;display:block}
.tf-stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(125px,1fr));gap:10px}
.tf-stat{padding:13px;border:1px solid var(--line);border-radius:10px;background:var(--input)}
.tf-stat span{display:block;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.tf-stat b{display:block;font:600 15px ui-monospace,monospace;color:var(--text);margin-top:6px;overflow-wrap:anywhere}
.tf-stat.accent b{color:var(--accent)}
.tf-stat.green b{color:var(--green)}
.tf-ttl-row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)}
.tf-ttl-row:last-child{border:0}
.tf-ttl-row .label{color:var(--muted);font-size:12px}
.tf-ttl-row .val{font-weight:500}
.tf-progress{height:8px;border-radius:4px;background:var(--input);overflow:hidden;margin:12px 0 4px}
.tf-progress-fill{height:100%;border-radius:4px;transform-origin:left center;animation:tfGrowX .6s ease both}
.tf-progress-fill.on{background:linear-gradient(90deg,var(--green),var(--accent))}
.tf-progress-fill.off{background:var(--red)}
.tf-progress-meta{display:flex;justify-content:space-between;font:10px ui-monospace,monospace;color:var(--muted)}
@keyframes tfGrowY{from{transform:scaleY(0);opacity:0}to{transform:scaleY(1);opacity:1}}
@keyframes tfGrowX{from{transform:scaleX(0)}to{transform:scaleX(1)}}

/* === hourly pattern (Variant B) + heatmap (Variant C) — shared with admin CSS === */
.hourly-card{margin-top:18px}.heatmap-card{margin-top:18px}
.hourly-chart{display:grid;grid-template-columns:repeat(24,minmax(0,1fr));gap:3px;height:140px;align-items:end;padding:8px 0 4px;border-bottom:1px solid var(--line)}
.hourly-bar{position:relative;width:100%;min-height:3px;border-radius:3px 3px 0 0;background:var(--input);cursor:help;transition:filter .15s;overflow:hidden}
.hourly-bar:hover{filter:brightness(1.25)}
.hourly-bar.zero{opacity:.55}
.hourly-seg{position:absolute;left:0;right:0}
.hourly-seg.up{bottom:0;background:var(--green)}
.hourly-seg.down{top:0;background:color-mix(in srgb,var(--green) 30%,var(--input))}
.hourly-axis{display:grid;grid-template-columns:repeat(24,minmax(0,1fr));font:9px ui-monospace,monospace;color:var(--muted);text-align:center;padding:5px 0 0;gap:3px}
.hourly-axis span{display:block;text-align:center}
.hourly-legend{display:flex;flex-wrap:wrap;gap:14px;font-size:10px;color:var(--muted);margin-top:8px;align-items:center}
.hourly-legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle}
.hourly-legend i.up{background:var(--green)}
.hourly-legend i.down{background:color-mix(in srgb,var(--green) 30%,var(--input))}
.hourly-legend .muted{margin-left:auto}
.hourly-empty{padding:30px 12px;text-align:center;color:var(--muted);font-size:12px}
.heatmap-grid{display:grid;grid-template-columns:34px repeat(24,minmax(0,1fr));gap:3px;padding:8px 0 4px;border-bottom:1px solid var(--line)}
.heatmap-corner{grid-column:1;grid-row:1}
.heatmap-hour-label{font:8px ui-monospace,monospace;color:var(--muted);text-align:center;padding:3px 0}
.heatmap-row{display:contents}
.heatmap-row-label{font:10px ui-monospace,monospace;color:var(--muted);text-align:right;padding:6px 6px 0 0;align-self:center}
.heatmap-cell{aspect-ratio:1;border-radius:3px;background:var(--input);cursor:help;transition:filter .15s,transform .1s}
.heatmap-cell:hover{filter:brightness(1.3);transform:scale(1.15)}
.heatmap-cell[data-level="0"]{background:var(--input)}
.heatmap-cell[data-level="1"]{background:color-mix(in srgb,var(--green) 22%,var(--input))}
.heatmap-cell[data-level="2"]{background:color-mix(in srgb,var(--green) 45%,var(--input))}
.heatmap-cell[data-level="3"]{background:color-mix(in srgb,var(--green) 70%,var(--input))}
.heatmap-cell[data-level="4"]{background:var(--green)}
.heatmap-scale{display:inline-flex;gap:2px;align-items:center;margin:0 6px;vertical-align:middle}
.heatmap-scale i{display:inline-block;width:11px;height:11px;border-radius:2px}
.heatmap-scale i[data-level="0"]{background:var(--input)}
.heatmap-scale i[data-level="1"]{background:color-mix(in srgb,var(--green) 22%,var(--input))}
.heatmap-scale i[data-level="2"]{background:color-mix(in srgb,var(--green) 45%,var(--input))}
.heatmap-scale i[data-level="3"]{background:color-mix(in srgb,var(--green) 70%,var(--input))}
.heatmap-scale i[data-level="4"]{background:var(--green)}
@media(max-width:900px){.hourly-chart{height:100px}.heatmap-grid{grid-template-columns:28px repeat(24,minmax(0,1fr))}.heatmap-row-label{font-size:9px;padding-right:3px}.heatmap-hour-label{font-size:7px}}
@media(max-width:600px){.hourly-chart{height:80px;gap:1px}.hourly-axis{font-size:8px}.heatmap-grid{gap:1px}.heatmap-cell{border-radius:2px}}
'''
LOAD_TRAFFIC_JS = '''let lastTrafficData=null,trafficPeriod=30,trafficInterval=null;
function startTrafficRefresh(){if(trafficInterval)clearInterval(trafficInterval);trafficInterval=setInterval(function(){loadTraffic();},30000);}
function setTrafficPeriod(p){trafficPeriod=p;if(lastTrafficData)renderTraffic(lastTrafficData);}
function exportTrafficCSV(){const d=lastTrafficData;if(!d||!d.daily||!d.daily.length){showToast('Нет данных для экспорта','error');return;}
let csv='date,bytes,gb\\n';
d.daily.forEach(function(r){csv+=(r.date||'')+','+(r.bytes||0)+','+((r.bytes||0)/1024/1024/1024).toFixed(4)+'\\n';});
const blob=new Blob([csv],{type:'text/csv'});const a=document.createElement('a');
a.href=URL.createObjectURL(blob);a.download='traffic.csv';document.body.appendChild(a);a.click();document.body.removeChild(a);}
async function loadTraffic(){
const d=await api('/api/portal/traffic');if(!d)return;
lastTrafficData=d;renderTraffic(d);startTrafficRefresh();loadTrafficHourly();}
/* === Hourly pattern + heatmap (Variant B + C) — fetch from /api/portal/traffic-hourly === */
let _browserTZ='Europe/Moscow';
try{_browserTZ=Intl.DateTimeFormat().resolvedOptions().timeZone||'Europe/Moscow';}catch(e){}
async function loadTrafficHourly(){
const url='/api/portal/traffic-hourly?tz='+encodeURIComponent(_browserTZ);
let d;try{d=await api(url);}catch(e){return;}
if(!d)return;
const hc=document.getElementById('hourly-container');
const hm=document.getElementById('heatmap-container');
if(hc)hc.innerHTML=renderHourlyPattern(d.pattern||{});
if(hm)hm.innerHTML=renderHourlyHeatmap(d.heatmap||{});
}
function _fmtBytes(b){b=b||0;if(b>=1024*1024*1024)return (b/1024/1024/1024).toFixed(2)+' ГБ';
if(b>=1024*1024)return (b/1024/1024).toFixed(1)+' МБ';if(b>=1024)return Math.round(b/1024)+' КБ';return b+' Б';}
function renderHourlyPattern(p){
const buckets=p.buckets||[];if(!buckets.length)return '<div class="portal-empty"><span class="ico">📭</span>Нет данных за последние 7 дней.</div>';
const maxT=Math.max(1,p.max_avg_total||0);
const tz=p.tz||'UTC';const days=p.days_observed||0;
const bars=buckets.map(function(b){
const h=b.hour||0;const up=Math.max(0,b.up||0);const down=Math.max(0,b.down||0);
const total=up+down;const bh=total>0?(total/maxT*100):0.5;
const upPct=total>0?(up/total*100):0;const downPct=100-upPct;
const title=String(h).padStart(2,'0')+':00 — ↑ '+_fmtBytes(up)+' · ↓ '+_fmtBytes(down)+' · avg of '+(b.days||0)+' days';
return '<div class="hourly-bar" style="height:'+bh.toFixed(2)+'%" title="'+esc(title)+'">'+
'<div class="hourly-seg down" style="height:'+downPct.toFixed(1)+'%"></div>'+
'<div class="hourly-seg up" style="height:'+upPct.toFixed(1)+'%"></div></div>';
}).join('');
const axis=''.concat.apply('',Array.from({length:24},function(_,h){return '<span>'+String(h).padStart(2,'0')+'</span>';}));
return '<div class="hourly-chart">'+bars+'</div>'+
'<div class="hourly-axis">'+axis+'</div>'+
'<div class="hourly-legend"><span><i class="up"></i>↑ Отправка</span>'+
'<span><i class="down"></i>↓ Получение</span>'+
'<span class="muted">Среднее за '+days+' дн. · TZ '+esc(tz)+'</span></div>';
}
function renderHourlyHeatmap(hm){
const rows=hm.rows||[];if(!rows.length)return '<div class="portal-empty"><span class="ico">📭</span>Нет данных за последние 7 дней.</div>';
const maxT=Math.max(1,hm.max_total||0);
const tz=hm.tz||'UTC';const days=hm.days_observed||0;
let header='<div class="heatmap-corner"></div>';
for(let h=0;h<24;h++)header+='<div class="heatmap-hour-label">'+String(h).padStart(2,'0')+'</div>';
let body='';
rows.forEach(function(r){
body+='<div class="heatmap-row"><div class="heatmap-row-label">'+esc(r.name||'')+'</div>';
(r.cells||[]).forEach(function(c){
const h=c.hour||0;const up=Math.max(0,c.up||0);const down=Math.max(0,c.down||0);
const total=up+down;let lvl=0;
if(total>0){const ratio=total/maxT;
if(ratio<0.05)lvl=0;else if(ratio<0.25)lvl=1;else if(ratio<0.5)lvl=2;else if(ratio<0.75)lvl=3;else lvl=4;}
const title=esc((r.name||'')+' '+String(h).padStart(2,'0')+':00 — ↑ '+_fmtBytes(up)+' · ↓ '+_fmtBytes(down));
body+='<div class="heatmap-cell" data-level="'+lvl+'" title="'+title+'"></div>';
});
body+='</div>';
});
return '<div class="heatmap-grid">'+header+body+'</div>'+
'<div class="hourly-legend"><span class="muted">Меньше</span>'+
'<span class="heatmap-scale"><i data-level="0"></i><i data-level="1"></i><i data-level="2"></i><i data-level="3"></i><i data-level="4"></i></span>'+
'<span class="muted">Больше · '+days+' дн. · TZ '+esc(tz)+'</span></div>';
}
function renderTraffic(d){
const c=document.getElementById('traffic-container');
function fmt(b){b=b||0;const u=['ГБ','МБ','КБ','Б'];const f=[1024*1024*1024,1024*1024,1024,1];
for(let i=0;i<f.length;i++){if(b>=f[i]||i===f.length-1)return (b/f[i]).toFixed(i===3?0:(i<2?2:1))+' '+u[i];}return '0 Б';}
function fmtShort(b){b=b||0;if(b>=1024*1024*1024)return (b/1024/1024/1024).toFixed(2)+' ГБ';
if(b>=1024*1024)return (b/1024/1024).toFixed(1)+' МБ';if(b>=1024)return Math.round(b/1024)+' КБ';return b+' Б';}
const total=d.total_bytes||0,up=d.upload_bytes||0,down=d.download_bytes||0;
const maxSplit=Math.max(up,down,1);
const upPct=up/maxSplit*100,downPct=down/maxSplit*100;
const limitBytes=(d.limit_gb||0)*1024*1024*1024;
const ringPct=limitBytes>0?Math.min(100,Math.max(0,total/limitBytes*100)):0;
const heroIco=(d.limit_gb&&d.limit_gb>0)?'<div class="progress-ring" style="--pct:'+ringPct.toFixed(0)+'%"><span>'+ringPct.toFixed(0)+'%</span></div>':'<div class="tf-hero-ico">📊</div>';
let h='<div class="tf-hero"><div class="tf-hero-top"><div>'+
'<div class="tf-hero-label">Всего трафика</div>'+
'<div class="tf-hero-num">'+fmt(total)+'</div>'+
'<div class="tf-hero-sub">'+(d.total_gb?d.total_gb+' ГБ':'—')+'</div></div>'+
heroIco+'</div>'+
'<div class="tf-split">'+
'<div class="tf-split-col"><div class="tf-split-row"><span>↑ Отправлено</span><b>'+fmtShort(up)+'</b></div>'+
'<div class="tf-split-track"><div class="tf-split-fill up" style="width:'+upPct+'%"></div></div></div>'+
'<div class="tf-split-col"><div class="tf-split-row"><span>↓ Получено</span><b>'+fmtShort(down)+'</b></div>'+
'<div class="tf-split-track"><div class="tf-split-fill down" style="width:'+downPct+'%"></div></div></div>'+
'</div></div>';
h+='<div class="card tf-daily"><div class="card-title">📈 Трафик по дням</div>';
h+='<div class="tf-period-row" style="margin-bottom:10px;display:flex;gap:6px;align-items:center;flex-wrap:wrap">'+
'<button class="btn ghost sm tf-period-btn" data-period="7" onclick="setTrafficPeriod(7)">7 дней</button>'+
'<button class="btn ghost sm tf-period-btn" data-period="30" onclick="setTrafficPeriod(30)">30 дней</button>'+
'<button class="btn ghost sm tf-period-btn" data-period="0" onclick="setTrafficPeriod(0)">Всё</button>'+
'<button class="btn ghost sm" onclick="exportTrafficCSV()" style="margin-left:auto">📥 Экспорт CSV</button>'+
'</div>';
const allDaily=(d.daily||[]).slice().reverse();
const daily=trafficPeriod>0?allDaily.slice(-trafficPeriod):allDaily;
if(daily.length){
let maxB=Math.max.apply(null,daily.map(function(x){return x.bytes||0;}));
if(!maxB||maxB<1){maxB=1;}
h+='<div class="tf-chart">';
daily.forEach(function(r,i){
const v=r.bytes||0;const pct=Math.max(2.5,v/maxB*100);
const dt=r.date?r.date.slice(5):'';
h+='<div class="tf-bar-col" title="'+esc(r.date)+': '+fmtShort(v)+'">'+
'<div class="tf-bar'+(v?'':' zero')+'" style="height:'+pct+'%;animation-delay:'+(i*0.04)+'s"></div>'+
'<div class="tf-bar-date">'+esc(dt)+'</div></div>';
});
h+='</div>';
}else{
h+='<div class="tf-empty"><span class="ico">📅</span>История трафика собирается.<br>Возвращайтесь завтра — здесь появится график по дням.</div>';
}
h+='</div>';
const forecastGb=(d.monthly_forecast_gb!=null?d.monthly_forecast_gb:(d.avg_per_day_bytes||0)*30/1024/1024/1024);
h+='<div class="card"><div class="card-title">📋 Статистика</div><div class="tf-stats">'+
'<div class="tf-stat accent"><span>Дней активно</span><b>'+(d.days_active||0)+'</b></div>'+
'<div class="tf-stat"><span>Среднее/день</span><b>'+fmtShort(d.avg_per_day_bytes||0)+'</b></div>'+
(forecastGb?'<div class="tf-stat green"><span>📈 Прогноз/мес</span><b>~'+(typeof forecastGb==='number'?forecastGb.toFixed(2):forecastGb)+' ГБ</b></div>':'')+
'<div class="tf-stat green"><span>↓ Получено</span><b>'+fmtShort(down)+'</b></div>'+
'<div class="tf-stat"><span>↑ Отправлено</span><b>'+fmtShort(up)+'</b></div>'+
(d.reset_date?'<div class="tf-stat"><span>Сброс xray</span><b style="font-size:12px">'+esc(d.reset_date)+'</b></div>':'')+
(d.limit_gb?'<div class="tf-stat accent"><span>Лимит</span><b>'+d.limit_gb+' ГБ</b></div>':'')+
'</div></div>';
const pt=d.protocol_traffic||{};
const vless=pt.vless||{up:0,down:0},mtp=pt.mtproto||{up:0,down:0};
if(vless.up||vless.down||mtp.up||mtp.down){
h+='<div class="card"><div class="card-title">🧬 Трафик по протоколам</div><div class="tf-stats">'+
'<div class="tf-stat accent"><span>VLESS ↑/↓</span><b style="font-size:11px">'+fmtShort(vless.up)+' / '+fmtShort(vless.down)+'</b></div>'+
'<div class="tf-stat"><span>MTProto ↑/↓</span><b style="font-size:11px">'+fmtShort(mtp.up)+' / '+fmtShort(mtp.down)+'</b></div>'+
'</div></div>';
}
c.innerHTML=h;
document.querySelectorAll('.tf-period-btn').forEach(function(b){
const isActive=b.dataset.period==String(trafficPeriod);
b.style.borderColor=isActive?'var(--accent)':'var(--line)';
b.style.color=isActive?'var(--accent)':'var(--text)';
b.style.background=isActive?'var(--tint)':'var(--raised)';
});
const tc=document.getElementById('ttl-card');
if(d.has_ttl){
tc.style.display='';
let th='';
const now=Date.now();
let expMs=NaN;if(d.expires_at){expMs=new Date(d.expires_at).getTime();}
const totalDays=d.days||0;const totalMs=totalDays*86400000;
let remainDays=NaN,pct=0,elapsedDays=0;
if(!isNaN(expMs)){
remainDays=Math.ceil((expMs-now)/86400000);
elapsedDays=totalMs?Math.max(0,(totalMs-(expMs-now))/86400000):0;
pct=totalMs?Math.min(100,Math.max(0,elapsedDays/totalDays*100)):0;
}
const expired=d.expired||(!isNaN(expMs)&&expMs<=now);
th+='<div class="tf-ttl-row"><span class="label">Срок действия</span><span class="val">'+esc(d.expires_str||d.expires_at||'—')+'</span></div>';
th+='<div class="tf-ttl-row"><span class="label">Статус</span>'+(expired?'<span class="badge off">истёк</span>':'<span class="badge on">активен</span>')+'</div>';
if(!isNaN(remainDays)){th+='<div class="tf-ttl-row"><span class="label">Осталось дней</span><span class="val">'+(expired?0:Math.max(0,remainDays))+'</span></div>';}
if(totalMs>0){th+='<div class="tf-progress"><div class="tf-progress-fill '+(expired?'off':'on')+'" style="width:'+(expired?100:pct).toFixed(1)+'%"></div></div>';
th+='<div class="tf-progress-meta"><span>прошло '+elapsedDays.toFixed(0)+' д</span><span>из '+totalDays+' д</span></div>';}
document.getElementById('ttl-container').innerHTML=th;
}else{
tc.style.display='none';
}
}'''


# ─── Portal tabs redesign (matches Traffic tab visual language) ────────
# Plain triple-quoted strings (single braces) referenced via {NAME}
# placeholders inside the portal_page f-string, same trick as TRAFFIC_CSS.
PORTAL_TABS_CSS = """/* === shared portal primitives (all tabs) === */
.portal-hero{background:linear-gradient(135deg,var(--raised),var(--surface));border:1px solid var(--line);border-radius:var(--radius);padding:22px;margin-bottom:16px;position:relative;overflow:hidden;animation:pFade .4s ease both}
.portal-hero::before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 100% 0,var(--tint),transparent 55%);pointer-events:none}
.portal-hero-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;position:relative;flex-wrap:wrap}
.portal-hero-ico{font-size:24px;opacity:.85;line-height:1}
.portal-hero-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.portal-hero-title{font:700 22px/1.2 inherit;color:var(--text);margin:6px 0 2px;letter-spacing:-.02em;overflow-wrap:anywhere}
.portal-hero-sub{font-size:12px;color:var(--muted);line-height:1.5}
.portal-stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(125px,1fr));gap:10px;margin-top:14px}
.portal-stat{padding:13px;border:1px solid var(--line);border-radius:10px;background:var(--input)}.portal-stat b{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;display:block}.portal-stat{min-width:0}
.portal-stat span{display:block;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.portal-stat b{display:block;font:600 15px ui-monospace,monospace;color:var(--text);margin-top:6px;overflow-wrap:anywhere}
.portal-stat.accent b{color:var(--accent)}
.portal-stat.green b{color:var(--green)}
.portal-stat.red b{color:var(--red)}
.portal-stat.amber b{color:var(--yellow)}
.portal-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
.portal-tile{padding:16px;border:1px solid var(--line);border-radius:12px;background:var(--surface);transition:border .15s,transform .12s;animation:pFade .4s ease both}
.portal-tile:hover{border-color:var(--accent)}
.portal-tile-head{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.portal-tile-title{font-weight:600;font-size:14px;flex:1;min-width:0;overflow-wrap:anywhere}
.portal-empty{padding:28px 12px;text-align:center;color:var(--muted);font-size:12px;line-height:1.7}
.portal-empty .ico{font-size:24px;opacity:.6;margin-bottom:10px;display:block}
.portal-code-box{padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--input);font:11px/1.5 ui-monospace,monospace;word-break:break-all;margin:8px 0;cursor:pointer;transition:border .15s,background .15s;max-height:140px;overflow:auto}
.portal-code-box:hover{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 8%,var(--input))}
.portal-qr-frame{display:grid;place-items:center;padding:14px;margin:10px 0;border:1px solid var(--line);border-radius:14px;background:#fff;box-shadow:0 8px 28px #00000040}
.portal-qr-frame img{border-radius:8px;max-width:220px;display:block}
.portal-btn-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;align-items:center}
.portal-dl-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.portal-dl{display:flex;align-items:center;gap:12px;padding:14px;border:1px solid var(--line);border-radius:12px;background:var(--surface);text-decoration:none;color:var(--text);transition:border .15s,transform .12s}
.portal-dl:hover{border-color:var(--accent);transform:translateY(-1px)}
.portal-dl-ico{font-size:24px;flex:0 0 auto}
.portal-dl-main{flex:1;min-width:0}
.portal-dl-name{font-weight:600;font-size:13px}
.portal-dl-desc{font-size:11px;color:var(--muted);margin-top:2px}
.portal-info{padding:14px;border:1px solid var(--line);border-radius:10px;background:var(--input);font-size:12px;color:var(--muted);line-height:1.7}
.portal-info b{color:var(--accent)}
.portal-danger{padding:14px;border:1px solid rgba(248,113,113,.3);border-radius:10px;background:rgba(248,113,113,.05);font-size:12px;color:var(--muted);line-height:1.7;margin-top:12px}
.portal-danger b{color:var(--red)}
.portal-progress{height:8px;border-radius:4px;background:var(--input);overflow:hidden;margin:8px 0 4px}
.portal-progress-fill{height:100%;border-radius:4px;transform-origin:left center;animation:pGrowX .5s ease both;transition:width .25s}
.portal-progress-fill.on{background:linear-gradient(90deg,var(--green),var(--accent))}
.portal-progress-fill.off{background:var(--red)}
.portal-progress-fill.amber{background:var(--yellow)}
.portal-meta{display:flex;justify-content:space-between;font:10px ui-monospace,monospace;color:var(--muted)}
.portal-proto-badge{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:8px;background:var(--tint);color:var(--accent);font:600 11px ui-monospace,monospace;border:1px solid var(--line);overflow-wrap:anywhere}
.portal-chip{display:inline-block;padding:3px 8px;border-radius:6px;font:600 10px ui-monospace,monospace;background:var(--input);color:var(--muted);border:1px solid var(--line)}
.portal-chip.on{background:rgba(65,199,141,.14);color:var(--green);border-color:rgba(65,199,141,.3)}
.portal-chip.off{background:rgba(240,111,117,.14);color:var(--red);border-color:rgba(240,111,117,.3)}
.portal-chip.accent{background:var(--tint);color:var(--accent);border-color:rgba(59,130,246,.3)}
.portal-tile-row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)}
.portal-tile-row:last-child{border:0}
.portal-tile-row .label{color:var(--muted);font-size:12px}
.portal-tile-row .val{font-weight:500;font:500 12px ui-monospace,monospace;overflow-wrap:anywhere}
.portal-form{display:flex;gap:8px;flex-wrap:wrap}
.portal-form .input{flex:1;min-width:200px}
.portal-cpy-ok{display:inline-flex;align-items:center;gap:4px;color:var(--green);font:600 11px ui-monospace,monospace;opacity:0;transition:opacity .25s}
.portal-cpy-ok.show{opacity:1}
@keyframes pFade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes pGrowX{from{transform:scaleX(0)}to{transform:scaleX(1)}}
@media(max-width:600px){.portal-grid{grid-template-columns:1fr}.portal-dl-grid{grid-template-columns:1fr}.portal-stats{grid-template-columns:1fr 1fr}}
"""

# Plain triple-quoted string (single braces) referenced via {CONFIGS_CSS}
# placeholder inside the portal_page f-string, same trick as TRAFFIC_CSS.
CONFIGS_CSS = """/* === configs tab: server configs + client app cards === */
.cfg-section-head{display:flex;align-items:center;gap:8px;margin:18px 0 12px;font:600 14px inherit;color:var(--text)}
.cfg-sec-ico{font-size:18px;line-height:1}
.cfg-sec-sub{font-size:11px;color:var(--muted);font-weight:400;margin-left:auto;text-transform:none;letter-spacing:0}
.cfg-section-head:first-child{margin-top:0}
.cfg-server-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.cfg-server-card{display:flex;align-items:center;gap:12px;padding:14px;border:1px solid var(--line);border-radius:12px;background:var(--surface);text-decoration:none;color:var(--text);transition:border .15s,transform .12s;animation:pFade .4s ease both}
.cfg-server-card:hover{border-color:var(--accent);transform:translateY(-1px)}
.cfg-server-ico{font-size:26px;flex:0 0 auto}
.cfg-server-main{flex:1;min-width:0}
.cfg-server-name{font-weight:600;font-size:13px}
.cfg-server-desc{font-size:11px;color:var(--muted);margin-top:2px;line-height:1.4}
.cfg-server-card .cfg-format-badge{margin-top:6px}
.cfg-client-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.cfg-client-card{display:flex;flex-direction:column;gap:10px;padding:16px;border:1px solid var(--line);border-radius:14px;background:var(--surface);transition:border .15s,transform .12s,box-shadow .2s;animation:pFade .4s ease both;position:relative;overflow:hidden}
.cfg-client-card:hover{border-color:var(--accent);transform:translateY(-2px);box-shadow:var(--shadow)}
.cfg-client-card::before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 100% 0,var(--tint),transparent 55%);pointer-events:none;opacity:.7}
.cfg-client-head{display:flex;align-items:center;gap:10px;position:relative}
.cfg-client-ico{font-size:28px;flex:0 0 auto;line-height:1}
.cfg-client-name{font:700 15px inherit;color:var(--text);letter-spacing:-.01em;line-height:1.2;overflow-wrap:anywhere}
.cfg-client-desc{font-size:11px;color:var(--muted);line-height:1.5;position:relative}
.cfg-client-meta{display:flex;flex-wrap:wrap;gap:5px;position:relative}
.cfg-platform-badge{display:inline-flex;align-items:center;gap:3px;padding:3px 7px;border-radius:5px;font:600 9px ui-monospace,monospace;background:var(--input);color:var(--muted);border:1px solid var(--line);white-space:nowrap}
.cfg-format-badge{display:inline-flex;align-items:center;gap:3px;padding:3px 8px;border-radius:5px;font:600 9px ui-monospace,monospace;background:var(--tint);color:var(--accent);border:1px solid rgba(59,130,246,.3);white-space:nowrap}
.cfg-client-dl{display:inline-flex;align-items:center;justify-content:center;gap:6px;margin-top:auto;padding:9px 14px;border-radius:8px;background:var(--accent);color:var(--on-accent);font:600 12px inherit;text-decoration:none;transition:opacity .15s,transform .12s;position:relative}
.cfg-client-dl:hover{opacity:.9;transform:translateY(-1px)}
@media(max-width:900px){.cfg-client-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.cfg-client-grid{grid-template-columns:1fr}.cfg-server-grid{grid-template-columns:1fr}}
"""

PORTAL_TABS_JS = """/* === Portal tabs: shared helpers === */
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function pBadge(on,yes,no){return '<span class="portal-chip '+(on?'on':'off')+'">'+(on?(yes||'да'):(no||'нет'))+'</span>';}
function pStat(label,val,cls){return '<div class="portal-stat '+(cls||'')+'"><span>'+esc(label)+'</span><b>'+esc(val==null||val===''?'—':String(val))+'</b></div>';}

/* === 1. Подключение === */
async function loadLinks(){
const d=await api('/api/portal/links');if(!d||!d.links)return;
const c=document.getElementById('links-container');
const links=d.links||[];
const proto=links[0]&&links[0].protocol?links[0].protocol:'VLESS';
const plLabel=links.length===1?'ссылка':(links.length<5?'ссылки':'ссылок');
let h='<div class="portal-hero"><div class="portal-hero-top"><div>'+
'<div class="portal-hero-label">Подключение</div>'+
'<div class="portal-hero-title">🔗 '+links.length+' '+plLabel+'</div>'+
'<div class="portal-hero-sub">Скопируйте ссылку, отсканируйте QR или откройте в приложении</div></div>'+
'<span class="portal-proto-badge">'+esc(proto)+'</span></div></div>';
h+='<div class="portal-grid">';
links.forEach(function(item,i){
const qr='/api/portal/qr?data='+encodeURIComponent(item.link);
const isVlessLink=new RegExp('^vless://','i').test(item.link||'');
h+='<div class="portal-tile" style="display:flex;flex-direction:column">'+
'<div class="portal-tile-head"><span class="portal-chip accent">'+esc(item.protocol||'LINK')+'</span>'+
'<div class="portal-tile-title">'+esc(item.label||'Подключение')+'</div></div>'+
'<div class="portal-qr-frame"><img src="'+qr+'" alt="QR" loading="lazy"></div>'+
'<div class="portal-code-box" id="link-'+i+'" title="Нажмите чтобы скопировать" onclick="copyLink('+i+')">'+esc(item.link)+'</div>'+
'<div class="portal-btn-row"><button class="btn ghost sm" onclick="copyLink('+i+')">📋 Копировать</button>'+
'<span class="portal-cpy-ok" id="cpy-'+i+'">✓ скопировано</span></div>'+
(isVlessLink?'<a class="btn sm" href="'+esc(item.link)+'" style="margin-top:8px;width:100%;justify-content:center">🚀 Открыть в приложении</a>':'')+
'</div>';
});
h+='</div>';
c.innerHTML=h;
}
function copyLink(i){const el=document.getElementById('link-'+i);if(!el)return;
navigator.clipboard.writeText(el.textContent).then(function(){showToast('Ссылка скопирована');
const ok=document.getElementById('cpy-'+i);if(ok){ok.classList.add('show');setTimeout(function(){ok.classList.remove('show');},1800);}
}).catch(function(){showToast('Ошибка копирования','error');});}

/* === 2. Подписка === */
async function loadSubscription(){
let d;try{d=await api('/api/portal/sub-info');}catch(e){return;}
if(!d||!d.service_enabled||!d.urls||!d.urls.base64)return;
const card=document.getElementById('sub-card'),c=document.getElementById('sub-container');
card.style.display='';document.getElementById('tab-subscription').style.display='';
const qr='/api/portal/qr?data='+encodeURIComponent(d.urls.base64);
const nodes=(d.multinode&&d.multinode.enabled&&d.multinode.nodes)||[];
let h='<div class="portal-hero"><div class="portal-hero-top"><div>'+
'<div class="portal-hero-label">Подписка</div>'+
'<div class="portal-hero-title">📚 Моя подписка</div>'+
'<div class="portal-hero-sub">Универсальный URL для клиентов с автодополнением нод</div></div>'+
(nodes.length?'<span class="portal-proto-badge">🌐 '+nodes.length+' нод</span>':'')+
'</div></div>';
h+='<div class="portal-tile">'+
'<div class="portal-tile-head"><span class="portal-chip accent">URL</span><div class="portal-tile-title">Ссылка на подписку</div></div>'+
'<div class="portal-code-box" id="sub-url-box" title="Нажмите чтобы скопировать" onclick="copySub()">'+esc(d.urls.base64)+'</div>'+
'<div class="portal-btn-row"><button class="btn sm" onclick="copySub()">📋 Копировать URL</button></div>'+
'</div>';
h+='<div class="portal-grid" style="grid-template-columns:1fr 1fr">'+
'<div class="portal-tile" style="text-align:center">'+
'<div class="portal-tile-head"><span class="portal-chip accent">YAML</span><div class="portal-tile-title">mihomo / Clash Meta</div></div>'+
'<a class="btn ghost" href="/api/portal/sub-clash" download style="width:100%;justify-content:center">⬇ Скачать YAML</a>'+
'</div>'+
'<div class="portal-tile" style="text-align:center">'+
'<div class="portal-tile-head"><span class="portal-chip accent">JSON</span><div class="portal-tile-title">sing-box</div></div>'+
'<a class="btn ghost" href="/api/portal/sub-singbox" download style="width:100%;justify-content:center">⬇ Скачать JSON</a>'+
'</div></div>';
h+='<div class="portal-grid" style="grid-template-columns:1fr"><div class="portal-tile" style="text-align:center">'+
'<div class="portal-qr-frame"><img src="'+qr+'" alt="QR" loading="lazy"></div>'+
'<div class="portal-hero-sub">Отсканируйте QR в приложении клиента</div>'+
'</div></div>';
if(nodes.length){
h+='<div class="portal-tile"><div class="portal-tile-head"><span class="portal-chip accent">MULTI</span><div class="portal-tile-title">Ноды подписки</div></div>';
nodes.forEach(function(n){
const kind=String(n.kind||'node').toLowerCase();
const kindChip=kind==='cascade'?'<span class="portal-chip on">каскад</span>':(kind==='federation'?'<span class="portal-chip accent">федерация</span>':'<span class="portal-chip">'+esc(n.kind||'')+'</span>');
h+='<div class="portal-tile-row"><span class="val">🌐 '+esc(n.name||'—')+'</span>'+kindChip+'</div>';
});
h+='</div>';
}
c.innerHTML=h;
}
function copySub(){const el=document.getElementById('sub-url-box');if(!el)return;
navigator.clipboard.writeText(el.textContent).then(function(){showToast('URL подписки скопирован');}).catch(function(){showToast('Ошибка копирования','error');});}

/* === 4. IP-адреса === */
/* Convert 2-letter ISO country code (RU, NL, DE...) to flag emoji.
   Uses Regional Indicator Symbols (U+1F1E6–U+1F1FF). Returns 🏳️ on bad input. */
function countryFlag(cc){
  if(!cc||cc.length!==2)return '🏳️';
  cc=cc.toUpperCase();
  const A=0x41,Z=0x5A,base=0x1F1E6;
  const c1=cc.charCodeAt(0),c2=cc.charCodeAt(1);
  if(c1<A||c1>Z||c2<A||c2>Z)return '🏳️';
  return String.fromCodePoint(base+(c1-A),base+(c2-A));
}
async function loadIPs(){
const d=await api('/api/portal/ips');if(!d)return;
const detected=d.detected_ip||'';
const det=document.getElementById('ips-detected');
let hh='<div class="portal-hero"><div class="portal-hero-top"><div>'+
'<div class="portal-hero-label">IP-адреса</div>'+
'<div class="portal-hero-title">🛂 Мои IP-адреса</div>'+
'<div class="portal-hero-sub">Управление whitelist для защиты от блокировок по IP</div></div>'+
(detected?'<span class="portal-proto-badge">📡 '+esc(detected)+'</span>':'<span class="portal-chip">IP не определён</span>')+
'</div></div>';
/* Prominent "auto-add my IP" button — accent, full-width, with 📡 icon */
hh+='<button class="btn" style="width:100%;justify-content:center;padding:14px;margin-bottom:12px;font-size:14px" onclick="addAutoIP()">'+
'📡 Добавить мой IP'+(detected?(' ('+esc(detected)+')'):'')+
'</button>';
det.innerHTML=hh;
const c=document.getElementById('ips-list');
const ips=d.ips||[];
if(!ips.length){
c.innerHTML='<div class="portal-empty"><span class="ico">📭</span>IP-адресов нет.<br>Нажмите кнопку выше, чтобы добавить свой текущий IP.</div>';
return;
}
let rows='';
ips.forEach(function(ip){
const pinChip=ip.pinned?'<span class="portal-chip on">📌 закреплён</span>':'<span class="portal-chip">не закреплён</span>';
const g=ip.geo||{};
const flag=countryFlag(g.country_code||'');
const geoTxt=(g.city||g.country||g.isp)?(flag+' '+esc([g.city,g.country].filter(Boolean).join(', '))+(g.isp?(' · '+esc(g.isp)):'')):'';
rows+='<div class="portal-tile" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
'<div style="font:600 14px ui-monospace,monospace;color:var(--accent);min-width:0;flex:1;overflow-wrap:anywhere">'+esc(ip.ip)+'</div>'+
pinChip+
(geoTxt?'<span style="font:11px ui-monospace,monospace;color:var(--muted);flex:1 1 100%">'+geoTxt+'</span>':'')+
'<span style="font:10px ui-monospace,monospace;color:var(--muted)">'+esc(ip.added_at||'')+'</span>'+
'<button class="btn ghost sm" onclick="pinIP(\\''+esc(ip.ip)+'\\','+ip.pinned+')">'+(ip.pinned?'Открепить':'Закрепить')+'</button>'+
'<button class="btn danger sm" onclick="removeIP(\\''+esc(ip.ip)+'\\')">🗑 Удалить</button>'+
'</div>';
});
c.innerHTML='<div class="portal-grid" style="grid-template-columns:1fr">'+rows+'</div>';
}
async function addIP(){const v=document.getElementById('new-ip').value.trim();if(!v){showToast('Введите IP','error');return;}
const r=await fetch('/api/portal/ips',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:v})});
const d=await r.json().catch(()=>({}));
if(r.ok){showToast('IP добавлен');loadIPs();document.getElementById('new-ip').value='';}
else showToast(d.error||'Ошибка','error');}
async function addAutoIP(){const r=await fetch('/api/portal/ips',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:'auto'})});
const d=await r.json().catch(()=>({}));
if(r.ok){showToast('IP добавлен');loadIPs();}else showToast(d.error||'Ошибка','error');}
async function removeIP(ip){if(!confirm('Удалить IP '+ip+'?'))return;
const r=await fetch('/api/portal/ips?ip='+encodeURIComponent(ip),{method:'DELETE',credentials:'same-origin'});
const d=await r.json().catch(()=>({}));
if(r.ok){showToast('IP удалён');loadIPs();}else showToast(d.error||'Ошибка','error');}
async function replaceAllIPs(){if(!confirm('Заменить все IP на текущий?'))return;
const r=await fetch('/api/portal/ips/replace-all',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:'auto'})});
const d=await r.json().catch(()=>({}));
if(r.ok){showToast('IP заменены');loadIPs();}else showToast(d.error||'Ошибка','error');}
async function pinIP(ip,pinned){if(pinned){const r=await fetch('/api/portal/ips/unpin',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});if(r.ok){showToast('IP откреплен');loadIPs();}else{const d=await r.json().catch(()=>({}));showToast(d.error||'Ошибка','error');}}else{const r=await fetch('/api/portal/ips/pin',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});if(r.ok){showToast('IP закреплён');loadIPs();}else{const d=await r.json().catch(()=>({}));showToast(d.error||'Ошибка','error');}}}

/* === 5. Пароль === */
function pwStrength(v){
const fill=document.getElementById('pw-fill'),lbl=document.getElementById('pw-label');
if(!fill||!lbl)return;
let cls='off',w=0,t='—';
if(v.length===0){cls='off';w=0;t='—';}
else if(v.length<8){cls='off';w=25;t='слишком короткий';}
else if(v.length<12){cls='amber';w=50;t='средний';}
else if(v.length<16){cls='on';w=75;t='хороший';}
else{cls='on';w=100;t='сильный';}
fill.className='portal-progress-fill '+cls;
fill.style.width=w+'%';
lbl.textContent=t;
pwChecklist(v);
}
function pwChecklist(v){
v=v||'';
const has8=v.length>=8;
const hasLetter=/[a-zA-Zа-яА-ЯёЁ]/.test(v)&&/[0-9]/.test(v);
const hasSpec=/[^a-zA-Z0-9а-яА-ЯёЁ]/.test(v);
const setItem=function(id,ok){
const el=document.getElementById(id);
if(el){el.style.color=ok?'var(--green)':'var(--muted)';el.textContent=(ok?'✓':'○')+' '+(el.dataset.label||'');}
};
setItem('pw-chk-len',has8);
setItem('pw-chk-alnum',hasLetter);
setItem('pw-chk-spec',hasSpec);
}
async function loadPasswordInfo(){
let d=null;
try{d=await api('/api/portal/password-info');}catch(e){return;}
if(!d)return;
const el=document.getElementById('pw-changed-at-box');
if(el){el.textContent=d.password_changed_at?('Последняя смена: '+d.password_changed_at):'Пароль ещё не менялся (используйте выданный администратором).';}
}
async function changePassword(){
const v=document.getElementById('new-pass').value.trim();
if(v.length<8){showToast('Минимум 8 символов','error');return;}
const btn=document.getElementById('pw-submit');
const old=btn?btn.innerHTML:'';
if(btn){btn.disabled=true;btn.innerHTML='Сохранение…';}
const r=await fetch('/portal/password',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_password:v})});
const d=await r.json().catch(()=>({}));
if(btn){btn.disabled=false;btn.innerHTML=old;}
if(r.ok){showToast('Пароль изменён');document.getElementById('new-pass').value='';pwStrength('');loadPasswordInfo();}
else showToast(d.error||'Ошибка','error');}

/* === 6. Сателлиты === */
async function loadSatellites(){
let d;try{d=await api('/api/portal/sat-info');}catch(e){return;}
if(!d||!d.satellites||!d.satellites.length)return;
document.getElementById('tab-satellites').style.display='';
document.getElementById('sat-card').style.display='';
const c=document.getElementById('sat-container');
const sats=d.satellites||[];
let h='<div class="portal-hero"><div class="portal-hero-top"><div>'+
'<div class="portal-hero-label">Сателлиты</div>'+
'<div class="portal-hero-title">🛰 Сателлитные протоколы</div>'+
'<div class="portal-hero-sub">Привязанные доп. протоколы (Mieru / NaiveProxy / Telemt / TrustTunnel)</div></div>'+
'<span class="portal-proto-badge">'+sats.length+' привяз.</span></div></div>';
h+='<div class="portal-grid" style="grid-template-columns:1fr">';
sats.forEach(function(s){
const activeChip=s.active?'<span class="portal-chip on">● активен</span>':'<span class="portal-chip off">○ не активен</span>';
h+='<div class="portal-tile" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
'<div style="font-size:22px">🛰</div>'+
'<div style="flex:1;min-width:0">'+
'<div style="font-weight:600;font-size:13px">'+esc(s.label||s.satellite)+'</div>'+
'<div style="color:var(--muted);font:11px ui-monospace,monospace">'+esc(s.login||'')+'</div></div>'+
activeChip+
'<button class="btn ghost sm" onclick="unbindSat(\\''+esc(s.satellite)+'\\')">Отвязать</button>'+
'</div>';
});
h+='</div>';
h+='<div class="portal-tile"><div class="portal-tile-head"><span class="portal-chip accent">AUTO</span><div class="portal-tile-title">Авто-привязка</div></div>'+
'<div class="portal-hero-sub">Сканирует все сателлиты и предлагает привязки по имени/UUID</div>'+
'<div class="portal-btn-row"><button class="btn ghost" onclick="suggestSat()">🔍 Найти привязки</button></div>'+
'<div id="sat-suggest"></div></div>';
c.innerHTML=h;
}
async function suggestSat(){const r=await fetch('/api/portal/sat-suggest',{credentials:'same-origin'});const d=await r.json().catch(()=>({}));
if(!d||!d.suggestions||!d.suggestions.length){showToast('Предложений нет');return;}
let h='<div style="margin-top:10px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">Найдено: '+d.suggestions.length+'</div>';
h+='<div class="portal-grid" style="grid-template-columns:1fr">';
d.suggestions.forEach(function(s){
h+='<div class="portal-tile" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
'<div style="font-size:22px">🛰</div>'+
'<div style="flex:1;min-width:0">'+
'<div style="font-weight:600;font-size:13px">'+esc(s.label||s.satellite)+'</div>'+
'<div style="color:var(--muted);font:11px ui-monospace,monospace">'+esc(s.login||'')+'</div></div>'+
'<button class="btn sm" onclick="bindSat(\\''+esc(s.satellite)+'\\',\\''+esc(s.login)+'\\')">Привязать</button>'+
'</div>';
});
h+='</div>';
document.getElementById('sat-suggest').innerHTML=h;
}
async function bindSat(sat,login){const r=await fetch('/api/portal/sat-bind',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({satellite:sat,login:login})});
if(r.ok){showToast('Привязано');loadSatellites();}else{const d=await r.json().catch(()=>({}));showToast(d.error||'Ошибка','error');}}
async function unbindSat(sat){if(!confirm('Отвязать '+sat+'?'))return;
const r=await fetch('/api/portal/sat-unbind',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({satellite:sat})});
if(r.ok){showToast('Отвязано');loadSatellites();}else showToast('Ошибка','error');}

/* === 7. YouTube DPI (b4) === */
async function loadB4(){
let d;try{d=await api('/api/portal/b4-info');}catch(e){return;}
if(!d){return;}
document.getElementById('tab-b4').style.display='';
document.getElementById('b4-card').style.display='';
const c=document.getElementById('b4-container');
const installed=!!d.installed,active=!!d.active;
const statusChip=(!installed)?'<span class="portal-chip off">не установлен</span>':(active?'<span class="portal-chip on">● активен</span>':'<span class="portal-chip off">○ выключен</span>');
let h='<div class="portal-hero"><div class="portal-hero-top"><div>'+
'<div class="portal-hero-label">YouTube DPI Bypass</div>'+
'<div class="portal-hero-title">📺 B4 DPI Bypass</div>'+
'<div class="portal-hero-sub">Обход блокировок YouTube через модификацию DPI-трафика</div></div>'+
statusChip+'</div></div>';
h+='<div class="portal-stats">'+
pStat('Установлено',installed?'да':'нет',installed?'green':'red')+
pStat('Активно',active?'да':'нет',active?'green':'red')+
pStat('Preset',d.preset_label||d.preset||'—','accent')+
(d.active_set_name?pStat('Активный сет',d.active_set_name,''):'')+
'</div>';
if(!installed){
h+='<div class="portal-info" style="margin-top:14px"><b>ℹ️ B4 не установлен.</b><br>Свяжитесь с администратором, чтобы включить обход YouTube DPI.</div>';
}else if(!active){
h+='<div class="portal-info" style="margin-top:14px"><b>⚠ B4 установлен, но не активен.</b><br>Обход DPI в данный момент выключен.</div>';
}else{
h+='<div class="portal-info" style="margin-top:14px"><b>✓ B4 активен.</b><br>YouTube-трафик модифицируется для обхода DPI-блокировок. Используйте HTTP-прокси b4 в вашем клиенте.</div>';
}
c.innerHTML=h;
}

/* === 8. Сервер === */
let healthInterval=null;
function startHealthRefresh(){if(healthInterval)clearInterval(healthInterval);healthInterval=setInterval(function(){loadHealth();},30000);}
async function loadHealth(){
const d=await api('/api/portal/health');if(!d)return;
const g=document.getElementById('sys-grid');
const xrayTxt=String(d.xray||'').toLowerCase();
const xrayOn=xrayTxt==='active'||xrayTxt==='running'||xrayTxt==='ok'||xrayTxt==='true';
const sslDays=d.ssl_days_left;
const sslOk=typeof sslDays==='number'&&sslDays>=0;
let h='<div class="portal-hero"><div class="portal-hero-top"><div>'+
'<div class="portal-hero-label">Сервер</div>'+
'<div class="portal-hero-title">🖥 '+esc(d.domain||'сервер')+'</div>'+
'<div class="portal-hero-sub">'+esc(d.protocol_mode||'reality')+' • порт '+esc(d.server_port||443)+'</div></div>'+
(xrayOn?'<span class="portal-chip on">● онлайн</span>':'<span class="portal-chip off">○ офлайн</span>')+
'</div></div>';
h+='<div class="portal-stats">'+
pStat('Xray',d.xray||'—',xrayOn?'green':'red')+
pStat('Протокол',d.protocol_mode||'—','accent')+
pStat('SSL дней',sslOk?sslDays:'N/A',(sslOk&&sslDays<14)?'amber':(sslOk?'green':'red'))+
pStat('Порт',d.server_port||'—','')+
pStat('Uptime (ч)',d.uptime_hours||'—','')+
'</div>';
/* SSL certificate details */
const ci=d.cert_info||{};
if(ci.issuer||ci.valid_from||ci.valid_to||ci.subject){
h+='<div class="portal-tile" style="margin-top:14px"><div class="portal-tile-head"><span class="portal-chip accent">SSL</span><div class="portal-tile-title">🔐 Сертификат</div></div>'+
(ci.issuer?'<div class="portal-tile-row"><span class="label">Эмитент</span><span class="val" style="font-size:11px">'+esc(ci.issuer)+'</span></div>':'')+
(ci.subject?'<div class="portal-tile-row"><span class="label">Субъект</span><span class="val" style="font-size:11px">'+esc(ci.subject)+'</span></div>':'')+
(ci.valid_from?'<div class="portal-tile-row"><span class="label">Действует с</span><span class="val" style="font-size:11px">'+esc(ci.valid_from)+'</span></div>':'')+
(ci.valid_to?'<div class="portal-tile-row"><span class="label">Действует до</span><span class="val" style="font-size:11px">'+esc(ci.valid_to)+'</span></div>':'')+
'</div>';
}
/* Protocol explanation info-box */
const protoMode=String(d.protocol_mode||'reality').toLowerCase();
h+='<div class="portal-info" style="margin-top:14px"><b>ℹ️ Протоколы:</b><br>'+
(protoMode.indexOf('reality')>=0?'<b>REALITY</b> — маскирует VPN-трафик под обычный HTTPS к доверенному сайту. Невозможно обнаружить DPI.<br>':'')+
(protoMode.indexOf('xhttp')>=0||protoMode.indexOf('x-http')>=0?'<b>xHTTP</b> — передаёт данные через HTTP-запросы, маскируя под обычный веб-трафик.<br>':'')+
'Текущий режим: <b>'+esc(d.protocol_mode||'reality')+'</b></div>';
if(d.timestamp){
h+='<div class="portal-tile" style="margin-top:14px"><div class="portal-tile-row"><span class="label">Время последней проверки</span><span class="val">'+esc(d.timestamp)+'</span></div></div>';
}
g.innerHTML=h;
startHealthRefresh();
}

/* === 9. AmneziaWG === */
async function loadAWG(){
let peer=null;
try{
const r=await fetch('/api/awg/my-peer',{credentials:'same-origin'});
if(r.ok){const d=await r.json();peer=d&&d.peer?d.peer:null;}
}catch(e){return;}
if(!peer){return;}  // hide tab when no AWG peer configured
document.getElementById('tab-awg').style.display='';
document.getElementById('awg-card').style.display='';
const c=document.getElementById('awg-container');
const statusTxt=String(peer.status||'').toLowerCase();
const active=statusTxt==='active'||statusTxt==='running'||peer.handshake_ago&&peer.handshake_ago!=='0';
const handshake=peer.handshake_ago||'—';
const endpoint=peer.endpoint||peer.server_endpoint||peer.server_addr||'';
const port=peer.server_port||peer.port||'';
const clientIP=peer.client_address||peer.allowed_ip||peer.address||'';
let h='<div class="portal-hero"><div class="portal-hero-top"><div>'+
'<div class="portal-hero-label">AmneziaWG</div>'+
'<div class="portal-hero-title">🛡 AmneziaWG</div>'+
'<div class="portal-hero-sub">WireGuard-совместимый туннель с защитой от DPI-детекции</div></div>'+
(active?'<span class="portal-chip on">● активен</span>':'<span class="portal-chip">настроен</span>')+
'</div></div>';
h+='<div class="portal-stats">'+
pStat('Имя пира',peer.name||'—','accent')+
(endpoint?pStat('Endpoint',endpoint,''):'')+
(port?pStat('Порт',port,''):'')+
(clientIP?pStat('Client IP',clientIP,''):'')+
pStat('Handshake',handshake,'')+
(peer.rx_bytes!=null?pStat('Принято',fmtAWG(peer.rx_bytes),'green'):'')+
(peer.tx_bytes!=null?pStat('Отправлено',fmtAWG(peer.tx_bytes),'accent'):'')+
'</div>';
h+='<div class="portal-grid" style="grid-template-columns:1fr 1fr;align-items:start">'+
'<div class="portal-tile" style="text-align:center">'+
'<div class="portal-tile-head"><span class="portal-chip accent">QR</span><div class="portal-tile-title">QR-код</div></div>'+
'<div class="portal-qr-frame"><img src="/api/awg/my-peer/qr" alt="QR" loading="lazy"></div>'+
'</div>'+
'<div class="portal-tile">'+
'<div class="portal-tile-head"><span class="portal-chip accent">.CONF</span><div class="portal-tile-title">Файл конфигурации</div></div>'+
'<div class="portal-code-box" id="awg-conf-box" style="min-height:60px">Загрузка…</div>'+
'<div class="portal-btn-row">'+
'<button class="btn sm" onclick="copyAWG()">📋 Копировать</button>'+
'<a class="btn ghost" href="/api/awg/my-peer/config" download>⬇ Скачать .conf</a>'+
'</div></div></div>';
c.innerHTML=h;
// async fetch conf text
fetch('/api/awg/my-peer/config',{credentials:'same-origin'}).then(function(r){return r.ok?r.text():'';}).then(function(t){
const box=document.getElementById('awg-conf-box');
if(box){box.textContent=t||'Конфиг недоступен';}
}).catch(function(){const box=document.getElementById('awg-conf-box');if(box){box.textContent='Конфиг недоступен';}});
}
function fmtAWG(b){b=b||0;if(b>=1024*1024*1024)return (b/1024/1024/1024).toFixed(2)+' ГБ';if(b>=1024*1024)return (b/1024/1024).toFixed(1)+' МБ';if(b>=1024)return Math.round(b/1024)+' КБ';return b+' Б';}
function copyAWG(){const el=document.getElementById('awg-conf-box');if(!el)return;
navigator.clipboard.writeText(el.textContent).then(function(){showToast('Конфиг скопирован');}).catch(function(){showToast('Ошибка копирования','error');});}
"""

# ─── Portal visual polish (CSS + JS constants, same plain-string trick) ───────
# Referenced inside the portal_page f-string via {PORTAL_POLISH_CSS} and
# {PORTAL_POLISH_JS} placeholders, identical to TRAFFIC_CSS / PORTAL_TABS_CSS.
PORTAL_POLISH_CSS = """/* === portal visual polish: transitions, skeletons, ring, theme, mobile, ptr === */
/* 1. Tab transition animation */
.tab-panel{animation:tabFade 0.3s ease forwards}
@keyframes tabFade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

/* 2. Skeleton loading */
.skeleton{background:linear-gradient(90deg,var(--input) 25%,var(--raised) 50%,var(--input) 75%);background-size:200% 100%;animation:shimmer 1.5s infinite;border-radius:8px}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skeleton-card{height:80px;margin-bottom:12px}

/* 3. QR hover zoom (legacy .qr-img and portal .portal-qr-frame) */
.qr-img,.portal-qr-frame{position:relative;transition:transform 0.3s}
.qr-img:hover,.portal-qr-frame:hover{transform:scale(1.15);z-index:10}
.qr-img img,.portal-qr-frame img{transition:box-shadow 0.3s}
.qr-img:hover img,.portal-qr-frame:hover img{box-shadow:0 8px 30px rgba(0,0,0,0.5)}

/* 4. Empty state illustrations (override default .portal-empty) */
.portal-empty{display:grid;justify-items:center;padding:40px 20px;text-align:center;color:var(--muted);font-size:12px;line-height:1.7}
.portal-empty .ico{font-size:48px;margin-bottom:12px;opacity:0.5;display:block}

/* 5. Progress ring for traffic limit */
.progress-ring{width:80px;height:80px;border-radius:50%;background:conic-gradient(var(--accent) var(--pct,0%),var(--input) 0);display:grid;place-items:center;margin:0 auto 12px;position:relative}
.progress-ring::before{content:'';position:absolute;width:64px;height:64px;border-radius:50%;background:var(--surface)}
.progress-ring span{position:relative;z-index:1;font:600 14px ui-monospace,monospace;color:var(--accent)}

/* 6. Collapsible sections */
.portal-collapse{cursor:pointer;user-select:none;padding:10px 0;border-bottom:1px solid var(--line);font-weight:600;font-size:13px;color:var(--text)}
.portal-collapse::after{content:'▼';float:right;transition:transform 0.2s;font-size:10px;color:var(--muted)}
.portal-collapse.collapsed::after{transform:rotate(-90deg)}
.portal-collapse-body{transition:max-height 0.3s ease,opacity 0.2s;overflow:hidden;max-height:9999px;opacity:1}
.portal-collapse.collapsed+.portal-collapse-body{max-height:0;opacity:0}

/* 7. Theme toggle button + light theme variable overrides */
.theme-toggle-btn{flex:0 0 auto;width:40px;height:40px;display:grid;place-items:center;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--text);font-size:18px;cursor:pointer;transition:all .15s;padding:0}
.theme-toggle-btn:hover{border-color:var(--accent);color:var(--accent)}
[data-theme="light"]{--bg:#f3f5f8;--surface:#fff;--raised:#eef1f5;--input:#f9fafc;--text:#202630;--muted:#667188;--line:#d8dde6;--accent:#2563d9;--on-accent:#fff;--tint:#2563d912;--green:#25865b;--amber:#916918;--yellow:#916918;--red:#bd464c;--shadow:0 8px 30px #17203614;--radius:14px;color-scheme:light}
[data-theme="light"] .portal-qr-frame{background:#fff;box-shadow:0 8px 28px rgba(0,0,0,0.15)}

/* 8. Toast with SVG checkmark (override base .toast to flex) */
.toast{position:fixed;bottom:20px;right:20px;z-index:100;padding:12px 18px;border-radius:10px;background:var(--accent);color:var(--on-accent);font:600 12px inherit;opacity:0;transition:opacity .3s;pointer-events:none;max-width:380px;display:flex;align-items:center;gap:8px}
.toast.show{opacity:1}
.toast.error{background:var(--red)}
.toast-success-icon{display:inline-flex;align-items:center;flex:0 0 auto}
@keyframes drawCheck{0%{stroke-dashoffset:30}100%{stroke-dashoffset:0}}
.toast-success-icon svg path{stroke-dasharray:30;animation:drawCheck 0.3s ease forwards}

/* 10. Pull-to-refresh hint */
.ptr-hint{text-align:center;padding:8px;font-size:11px;color:var(--muted);opacity:0;transition:opacity 0.2s}
.ptr-hint.visible{opacity:1}

/* 9. Mobile bottom navigation */
@media(max-width:600px){
  .sticky-top{position:sticky;top:0;z-index:100}
  .tabs{position:fixed;bottom:0;left:0;right:0;overflow-x:auto;background:var(--surface);border-top:1px solid var(--line);padding:8px;z-index:100}
  .tab{flex:0 0 auto;font-size:0.7rem}
  body{padding-bottom:60px}
}

/* 11. Header connection-status dot */
.conn-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--muted);box-shadow:0 0 0 2px var(--bg);transition:background .2s,box-shadow .2s}
.conn-dot.on{background:var(--green);box-shadow:0 0 8px var(--green)}
.conn-dot.off{background:var(--red);box-shadow:0 0 8px var(--red)}

/* 12. Password requirements checklist */
.pw-checklist{display:flex;flex-direction:column;gap:6px;margin-top:12px;font:12px ui-monospace,monospace;color:var(--muted)}
.pw-checklist span{display:flex;align-items:center;gap:6px}

/* 13. Recommended client badge — short label, padding-top reserves space so badge never overlaps the head/description */
.cfg-client-card.recommended{border-color:var(--accent);box-shadow:0 0 0 2px var(--tint);padding-top:34px}
.cfg-client-card.recommended::after{content:"⭐ Рекомендуется";position:absolute;top:8px;right:10px;background:var(--accent);color:var(--on-accent);font:700 9px inherit;padding:3px 9px;border-radius:6px;z-index:3;letter-spacing:.03em;text-transform:uppercase;white-space:nowrap;box-shadow:0 4px 12px #00000040}
"""

PORTAL_POLISH_JS = """/* === Portal visual polish JS === */
/* Theme toggle */
function toggleTheme(){
  const cur=document.documentElement.dataset.theme||'dark';
  const nxt=cur==='dark'?'light':'dark';
  document.documentElement.dataset.theme=nxt;
  try{localStorage.setItem('wpp-theme',nxt);}catch(e){}
  const btn=document.getElementById('theme-toggle-btn');
  if(btn){btn.textContent=nxt==='dark'?'☀️':'🌙';}
}
/* Collapsible sections */
function toggleCollapse(el){el.classList.toggle('collapsed');}
/* Connection-status dot: turns green when detected_ip is in user's whitelist */
async function loadConnStatus(){
  let d=null;
  try{d=await api('/api/portal/ips');}catch(e){return;}
  if(!d)return;
  const dot=document.getElementById('conn-dot');
  if(!dot)return;
  const detected=(d.detected_ip||'').trim();
  const ips=(d.ips||[]).map(function(x){return x.ip;});
  if(!detected){dot.className='conn-dot';dot.title='IP не определён';return;}
  const matched=ips.some(function(ip){return ip===detected||(ip&&ip.indexOf(detected+'/')===0);});
  dot.className='conn-dot '+(matched?'on':'off');
  dot.title=matched?('Ваш IP в whitelist ('+detected+')'):('Ваш IP '+detected+' не в whitelist — добавьте его во вкладке IP');
}
/* Recommended client detection — matches navigator.userAgent to one card */
function detectRecommendedClient(){
  const ua=(navigator.userAgent||'').toLowerCase();
  const cards=document.querySelectorAll('.cfg-client-card[data-platforms]');
  if(!cards.length)return;
  let want='';
  if(/iphone|ipad|ipod|ios/.test(ua)){want='ios';}
  else if(/android/.test(ua)){want='android';}
  else if(/mac|darwin/.test(ua)){want='mac';}
  else if(/linux/.test(ua)&&!/android/.test(ua)){want='linux';}
  else if(/windows|win32|win64/.test(ua)){want='win';}
  if(!want){return;}
  /* Priority order: native-only clients first, then cross-platform ones */
  const priority={win:['v2rayN','Mihomo','Hiddify','Karing','Sing-box','AmneziaWG'],
    mac:['Hiddify','Karing','Mihomo','Sing-box','AmneziaWG'],
    linux:['Mihomo','Hiddify','Karing','Sing-box','AmneziaWG'],
    android:['v2rayNG','NekoBox','Hiddify','Karing','Mihomo','Sing-box','AmneziaWG'],
    ios:['Shadowrocket','Streisand','Hiddify','Karing','Sing-box']};
  const order=priority[want]||[];
  let chosen=null;
  for(let i=0;i<order.length&&!chosen;i++){
    cards.forEach(function(c){
      if(c.dataset.client===order[i]){chosen=c;}
    });
  }
  if(chosen){chosen.classList.add('recommended');}
}
/* Pull-to-refresh — at scrollY=0, drag down >50px then release to refresh all */
(function(){
  let startY=0,pulling=false;
  const hint=document.getElementById('ptr-hint');
  if(!hint)return;
  window.addEventListener('touchstart',function(e){
    if(window.scrollY<=0){startY=e.touches[0].clientY;pulling=true;}
    else{pulling=false;hint.classList.remove('visible');}
  },{passive:true});
  window.addEventListener('touchmove',function(e){
    if(!pulling)return;
    const dy=e.touches[0].clientY-startY;
    if(dy>50){hint.classList.add('visible');}else{hint.classList.remove('visible');}
  },{passive:true});
  window.addEventListener('touchend',function(){
    if(!pulling)return;
    pulling=false;
    if(hint.classList.contains('visible')){
      hint.classList.remove('visible');
      loadLinks();loadSubscription();loadTraffic();loadHealth();loadIPs();loadSatellites();loadB4();loadAWG();loadConnStatus();
    }
  },{passive:true});
})();
"""


def portal_page(user, path):
    """Main User Portal page with 10 tabs — WPP-styled."""
    email = esc(user.get("email", "user"))
    name = esc(user.get("name", email))
    initial = esc((user.get("name") or "U")[0].upper())
    return f'''<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Portal — {name}</title>
<script>(function(){{try{{var t=localStorage.getItem('wpp-theme');var theme=t==='light'?'light':'dark';document.documentElement.dataset.theme=theme;window.addEventListener('DOMContentLoaded',function(){{var b=document.getElementById('theme-toggle-btn');if(b)b.textContent=theme==='light'?'🌙':'☀️';}});}}catch(e){{document.documentElement.dataset.theme='dark';}}}})();</script>
<style>
:root{{--bg:#101318;--surface:#1b1e24;--raised:#22262e;--input:#171a20;
--line:#303641;--text:#f3f5f8;--muted:#93a0b8;--accent:#3b82f6;
--on-accent:#fff;--tint:#3b82f619;--green:#41c78d;--red:#f06f75;
--amber:#dcae43;--yellow:#dcae43;--shadow:0 14px 46px #0006;
--radius:14px;color-scheme:dark}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{min-height:100vh;font:14px/1.6 -apple-system,system-ui,sans-serif;
background:var(--bg);color:var(--text)}}
.container{{max-width:860px;margin:0 auto;padding:16px 20px 60px}}
.sticky-top{{position:sticky;top:0;z-index:10;background:var(--bg);padding-bottom:12px}}
.header{{display:flex;align-items:center;gap:12px;padding:14px 0;border-bottom:1px solid var(--line);margin-bottom:12px}}
.avatar{{display:grid;place-items:center;width:44px;height:44px;flex:0 0 auto;
border-radius:12px;background:var(--accent);color:var(--on-accent);font:700 18px inherit}}
.header h1{{font-size:17px;font-weight:600}}
.header .sub{{font-size:12px;color:var(--muted)}}
.header .logout{{margin-left:auto;padding:8px 14px;border:1px solid var(--line);
border-radius:8px;background:var(--surface);color:var(--muted);font:12px inherit;
text-decoration:none;cursor:pointer;transition:all .15s}}
.header .logout:hover{{border-color:var(--red);color:var(--red)}}
.tabs{{display:flex;gap:4px;overflow-x:auto;padding-bottom:8px;scrollbar-width:thin}}
.tab{{flex:0 0 auto;padding:8px 14px;border:1px solid transparent;border-radius:8px;
background:transparent;color:var(--muted);font:500 12px inherit;white-space:nowrap;
cursor:pointer;transition:all .15s}}
.tab:hover{{color:var(--text)}}
.tab.active{{background:var(--tint);border-color:var(--accent);color:var(--accent)}}
.tab-panel{{display:none}}
.tab-panel.active{{display:block}}
.card{{padding:20px;border:1px solid var(--line);border-radius:var(--radius);
background:var(--surface);margin-bottom:16px}}
.card-title{{font-size:15px;font-weight:600;margin-bottom:14px;padding-bottom:10px;
border-bottom:1px solid var(--line)}}
.row{{display:flex;align-items:center;justify-content:space-between;gap:12px;
padding:10px 0;border-bottom:1px solid var(--line)}}
.row:last-child{{border:0}}
.row .label{{color:var(--muted);font-size:12px}}
.row .val{{font-weight:500}}
.badge{{display:inline-block;padding:3px 8px;border-radius:6px;font:600 11px inherit;
background:var(--tint);color:var(--accent)}}
.badge.on{{background:rgba(65,199,141,.14);color:var(--green)}}
.badge.off{{background:rgba(240,111,117,.14);color:var(--red)}}
.input{{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;
background:var(--input);color:var(--text);font:13px inherit;outline:none}}
.input:focus{{border-color:var(--accent)}}
.btn{{display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border:0;
border-radius:8px;background:var(--accent);color:var(--on-accent);font:600 12px inherit;
cursor:pointer;text-decoration:none;transition:opacity .15s}}
.btn:hover{{opacity:.88}}
.btn.ghost{{background:var(--raised);color:var(--text);border:1px solid var(--line)}}
.btn.danger{{background:var(--red)}}
.btn.sm{{padding:5px 10px;font-size:11px}}
.link-box{{padding:10px 12px;border:1px solid var(--line);border-radius:8px;
background:var(--input);font:11px/1.5 ui-monospace,monospace;word-break:break-all;
margin:8px 0;cursor:pointer;transition:border .15s;height:48px;overflow-y:auto;display:flex;align-items:center;justify-content:center;padding:6px 8px}}
.link-box:hover{{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 8%,var(--input))}}
.qr-img{{display:grid;place-items:center;margin:12px 0}}
.qr-img img{{border-radius:8px;max-width:220px}}
.dl-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}}
.toast{{position:fixed;bottom:20px;right:20px;z-index:100;padding:12px 18px;
border-radius:10px;background:var(--accent);color:var(--on-accent);font:600 12px inherit;
opacity:0;transition:opacity .3s;pointer-events:none;max-width:380px}}
.toast.show{{opacity:1}}
.toast.error{{background:var(--red)}}
.loading{{display:grid;place-items:center;padding:30px;color:var(--muted)}}
.spinner{{width:18px;height:18px;border:2px solid var(--accent);border-top-color:transparent;
border-radius:50%;animation:spin .8s linear infinite}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.bar-track{{height:8px;border-radius:4px;background:var(--input);overflow:hidden;margin:8px 0}}
.bar-fill{{height:100%;border-radius:4px;background:var(--accent);transition:width .3s}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.info-box{{padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--input);
font-size:12px;color:var(--muted);line-height:1.7}}
.info-box b{{color:var(--accent)}}
.sat-item{{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--line)}}
.sat-item:last-child{{border:0}}
.sat-name{{font-weight:500;font-size:13px}}
.sat-login{{color:var(--muted);font:11px ui-monospace,monospace}}
.actions{{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}}
@media(max-width:600px){{.grid2{{grid-template-columns:1fr}}.dl-grid{{grid-template-columns:1fr}}}}
{PORTAL_TABS_CSS}
{TRAFFIC_CSS}
{CONFIGS_CSS}
{PORTAL_POLISH_CSS}
</style></head><body>
<div class="container">
<div class="ptr-hint" id="ptr-hint">↓ Потяните вниз, чтобы обновить</div>
<div class="sticky-top">
<div class="header">
<div class="avatar">{initial}</div>
<div style="flex:1;min-width:0">
<h1 style="display:flex;align-items:center;gap:8px">{name}<span id="conn-dot" class="conn-dot" title="Статус подключения" aria-label="Статус подключения"></span></h1>
<div class="sub">{email}</div>
</div>
<button class="theme-toggle-btn" id="theme-toggle-btn" onclick="toggleTheme()" title="Сменить тему" aria-label="Сменить тему">☀️</button>
<a class="logout" href="/portal/logout">Выход</a>
</div>
<div class="tabs" id="tabs">
<button class="tab active" data-tab="connect" onclick="switchTab('connect')">🔗 Подключение</button>
<button class="tab" data-tab="subscription" id="tab-subscription" style="display:none" onclick="switchTab('subscription')">📚 Подписка</button>
<button class="tab" data-tab="configs" onclick="switchTab('configs')">📥 Конфиги</button>
<button class="tab" data-tab="traffic" onclick="switchTab('traffic')">📊 Трафик</button>
<button class="tab" data-tab="ips" onclick="switchTab('ips')">🛂 IP</button>
<button class="tab" data-tab="password" onclick="switchTab('password')">🔒 Пароль</button>
<button class="tab" data-tab="satellites" id="tab-satellites" style="display:none" onclick="switchTab('satellites')">🛰 Сателлиты</button>
<button class="tab" data-tab="b4" id="tab-b4" style="display:none" onclick="switchTab('b4')">📺 YouTube DPI</button>
<button class="tab" data-tab="server" onclick="switchTab('server')">🖥 Сервер</button>
<button class="tab" data-tab="awg" id="tab-awg" style="display:none" onclick="switchTab('awg')">🛡 AmneziaWG</button>
</div>
</div>

<div class="tab-panel active" id="panel-connect">
<div class="card"><div class="card-title">🔗 Подключение</div>
<div id="links-container"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div></div>
</div>

<div class="tab-panel" id="panel-subscription">
<div class="card" id="sub-card"><div class="card-title">📚 Моя подписка</div>
<div id="sub-container"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div></div>
</div>

<div class="tab-panel" id="panel-configs">
<div class="card"><div class="card-title">📥 Конфиги</div>
<div class="portal-hero"><div class="portal-hero-top"><div>
<div class="portal-hero-label">Конфигурации и клиенты</div>
<div class="portal-hero-title">📥 Конфиги и клиенты</div>
<div class="portal-hero-sub">Скачайте готовый конфиг с сервера и подходящий клиент</div>
</div><span class="portal-proto-badge">4 + 10</span></div></div>

<div class="cfg-section-head"><span class="cfg-sec-ico">📦</span> Скачать конфиги <span class="cfg-sec-sub">с сервера</span></div>
<div class="cfg-server-grid">
<a class="cfg-server-card" href="/api/portal/clash" download>
<span class="cfg-server-ico">🌀</span>
<div class="cfg-server-main"><div class="cfg-server-name">Clash Meta</div>
<div class="cfg-server-desc">YAML для Mihomo / Clash Verge / FlClash</div>
<span class="cfg-format-badge">Clash YAML</span></div></a>
<a class="cfg-server-card" href="/api/portal/singbox" download>
<span class="cfg-server-ico">🟢</span>
<div class="cfg-server-main"><div class="cfg-server-name">Sing-box</div>
<div class="cfg-server-desc">JSON для sing-box / SFA</div>
<span class="cfg-format-badge">Sing-box JSON</span></div></a>
<a class="cfg-server-card" href="/api/portal/hiddify" download>
<span class="cfg-server-ico">📦</span>
<div class="cfg-server-main"><div class="cfg-server-name">Hiddify</div>
<div class="cfg-server-desc">JSON для Hiddify Next</div>
<span class="cfg-format-badge">Hiddify JSON</span></div></a>
<a class="cfg-server-card" href="/api/portal/vless-link" download>
<span class="cfg-server-ico">🔗</span>
<div class="cfg-server-main"><div class="cfg-server-name">VLESS-ссылка</div>
<div class="cfg-server-desc">vless://… для v2rayN / NekoBox / Karing</div>
<span class="cfg-format-badge">VLESS</span></div></a>
</div>

<div class="cfg-section-head"><span class="cfg-sec-ico">📱</span> Клиентские приложения <span class="cfg-sec-sub">последние версии с GitHub / App Store</span></div>
<div class="cfg-client-grid">

<div class="cfg-client-card" data-client="Mihomo" data-platforms="win,mac,linux,android">
<div class="cfg-client-head"><span class="cfg-client-ico">🌀</span>
<div class="cfg-client-name">Clash Meta / Mihomo</div></div>
<div class="cfg-client-desc">Ядро Clash на базе mihomo. GUI-оболочки: Clash Verge, FlClash.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">Clash YAML</span>
<span class="cfg-platform-badge">🖥 Win</span><span class="cfg-platform-badge">🍎 macOS</span><span class="cfg-platform-badge">🐧 Linux</span><span class="cfg-platform-badge">📱 Android</span></div>
<a class="cfg-client-dl" href="https://github.com/MetaCubeX/mihomo/releases/latest" target="_blank" rel="noopener">📥 Скачать</a>
</div>

<div class="cfg-client-card" data-client="Sing-box" data-platforms="win,mac,linux,android,ios">
<div class="cfg-client-head"><span class="cfg-client-ico">🟢</span>
<div class="cfg-client-name">Sing-box</div></div>
<div class="cfg-client-desc">Универсальное ядро: VLESS / Reality / Trojan / Hysteria.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">Sing-box JSON</span>
<span class="cfg-platform-badge">🖥 Win</span><span class="cfg-platform-badge">🍎 macOS</span><span class="cfg-platform-badge">🐧 Linux</span><span class="cfg-platform-badge">📱 Android</span><span class="cfg-platform-badge">🍎 iOS</span></div>
<a class="cfg-client-dl" href="https://github.com/SagerNet/sing-box/releases/latest" target="_blank" rel="noopener">📥 Скачать</a>
</div>

<div class="cfg-client-card" data-client="Hiddify" data-platforms="win,mac,linux,android,ios">
<div class="cfg-client-head"><span class="cfg-client-ico">📦</span>
<div class="cfg-client-name">Hiddify</div></div>
<div class="cfg-client-desc">Кроссплатформенный клиент с авто-настройкой и QR.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">Hiddify JSON / QR</span>
<span class="cfg-platform-badge">🖥 Win</span><span class="cfg-platform-badge">🍎 macOS</span><span class="cfg-platform-badge">🐧 Linux</span><span class="cfg-platform-badge">📱 Android</span><span class="cfg-platform-badge">🍎 iOS</span></div>
<a class="cfg-client-dl" href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener">📥 Скачать</a>
</div>

<div class="cfg-client-card" data-client="v2rayN" data-platforms="win">
<div class="cfg-client-head"><span class="cfg-client-ico">🖥️</span>
<div class="cfg-client-name">v2rayN</div></div>
<div class="cfg-client-desc">Популярный клиент для Windows на ядре Xray.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">QR / VLESS</span>
<span class="cfg-platform-badge">🖥 Win</span></div>
<a class="cfg-client-dl" href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener">📥 Скачать</a>
</div>

<div class="cfg-client-card" data-client="v2rayNG" data-platforms="android">
<div class="cfg-client-head"><span class="cfg-client-ico">📱</span>
<div class="cfg-client-name">v2rayNG</div></div>
<div class="cfg-client-desc">Android-клиент на ядре Xray, импорт по QR/ссылке.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">QR / VLESS</span>
<span class="cfg-platform-badge">📱 Android</span></div>
<a class="cfg-client-dl" href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener">📥 Скачать</a>
</div>

<div class="cfg-client-card" data-client="Karing" data-platforms="win,mac,linux,android,ios">
<div class="cfg-client-head"><span class="cfg-client-ico">🦊</span>
<div class="cfg-client-name">Karing</div></div>
<div class="cfg-client-desc">Кроссплатформенный клиент с поддержкой всех форматов.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">QR / VLESS</span>
<span class="cfg-platform-badge">🖥 Win</span><span class="cfg-platform-badge">🍎 macOS</span><span class="cfg-platform-badge">🐧 Linux</span><span class="cfg-platform-badge">📱 Android</span><span class="cfg-platform-badge">🍎 iOS</span></div>
<a class="cfg-client-dl" href="https://github.com/KaringNet/karing/releases/latest" target="_blank" rel="noopener">📥 Скачать</a>
</div>

<div class="cfg-client-card" data-client="NekoBox" data-platforms="android">
<div class="cfg-client-head"><span class="cfg-client-ico">🐱</span>
<div class="cfg-client-name">NekoBox</div></div>
<div class="cfg-client-desc">Android-клиент на ядре sing-box, импорт по QR. Мод qr243vbi v5.11.28.3 с extras для РФ-ДПИ.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">QR / VLESS</span>
<span class="cfg-platform-badge">📱 Android</span></div>
<a class="cfg-client-dl" href="https://github.com/qr243vbi/nekobox/releases/tag/5.11.28.3" target="_blank" rel="noopener">📥 Скачать</a>
</div>

<div class="cfg-client-card" data-client="Streisand" data-platforms="ios">
<div class="cfg-client-head"><span class="cfg-client-ico">🌉</span>
<div class="cfg-client-name">Streisand</div></div>
<div class="cfg-client-desc">iOS-клиент с поддержкой VLESS/Reality, скан QR.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">QR-код</span>
<span class="cfg-platform-badge">🍎 iOS</span></div>
<a class="cfg-client-dl" href="https://apps.apple.com/app/streisand/id1504799924" target="_blank" rel="noopener">🛍 App Store</a>
</div>

<div class="cfg-client-card" data-client="Shadowrocket" data-platforms="ios">
<div class="cfg-client-head"><span class="cfg-client-ico">🚀</span>
<div class="cfg-client-name">Shadowrocket</div></div>
<div class="cfg-client-desc">iOS-клиент, скан QR-кода или вставка ссылки.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">QR-код</span>
<span class="cfg-platform-badge">🍎 iOS</span></div>
<a class="cfg-client-dl" href="https://apps.apple.com/app/shadowrocket/id932747747" target="_blank" rel="noopener">🛍 App Store</a>
</div>

<div class="cfg-client-card" data-client="AmneziaWG" data-platforms="win,mac,linux,android,ios">
<div class="cfg-client-head"><span class="cfg-client-ico">🛡️</span>
<div class="cfg-client-name">AmneziaWG</div></div>
<div class="cfg-client-desc">WireGuard-совместимый туннель с защитой от DPI-детекции.</div>
<div class="cfg-client-meta"><span class="cfg-format-badge">AWG-конфиг</span>
<span class="cfg-platform-badge">🖥 Win</span><span class="cfg-platform-badge">🍎 macOS</span><span class="cfg-platform-badge">🐧 Linux</span><span class="cfg-platform-badge">📱 Android</span><span class="cfg-platform-badge">🍎 iOS</span></div>
<a class="cfg-client-dl" href="https://github.com/amneziavpn/amnezia-vpn/releases/latest" target="_blank" rel="noopener">📥 Скачать</a>
</div>

</div>

<div class="portal-info" style="margin-top:14px">
<b>ℹ️ Как пользоваться:</b><br>
1. Скачайте конфиг с сервера (раздел «Скачать конфиги») в формате вашего клиента.<br>
2. Установите клиентское приложение (раздел «Клиентские приложения»).<br>
3. Импортируйте конфиг в клиент: вставьте VLESS-ссылку, откройте JSON/YAML файл или отсканируйте QR-код из вкладки «🔗 Подключение».<br>
<b>AmneziaWG</b> — конфиг берётся во вкладке «🛡 AmneziaWG» (если у вас есть AWG-пир).
</div></div>
</div>

<div class="tab-panel" id="panel-traffic">
<div class="card"><div class="card-title">📊 Трафик</div>
<div id="traffic-container"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div></div>
<div class="card" id="hourly-card"><div class="card-title">🕐 Трафик по часам суток</div>
<div id="hourly-container"><div class="skeleton skeleton-card"></div></div>
<div class="portal-info" style="margin-top:14px"><b>ℹ️ Средний трафик за каждый час суток за последние 7 дней.</b> Помогает увидеть типичный паттерн — когда обычно пик и провал.</div>
</div>
<div class="card" id="heatmap-card"><div class="card-title">🔥 Трафик по дням и часам</div>
<div id="heatmap-container"><div class="skeleton skeleton-card"></div></div>
<div class="portal-info" style="margin-top:14px"><b>ℹ️ Тепловая карта интенсивности по дням недели и часам.</b> Помогает увидеть разницу между буднями и выходными.</div>
</div>
<div class="card" id="ttl-card" style="display:none"><div class="card-title">⏰ Срок действия</div>
<div id="ttl-container"></div></div>
</div>

<div class="tab-panel" id="panel-ips">
<div class="card"><div class="card-title">🛂 Мои IP-адреса</div>
<div id="ips-detected"></div>
<div class="portal-collapse" onclick="toggleCollapse(this)">📋 Список IP-адресов</div>
<div class="portal-collapse-body" id="ips-list" style="margin-bottom:12px"></div>
<div class="portal-tile">
<div class="portal-tile-head"><span class="portal-chip accent">+</span><div class="portal-tile-title">Добавить IP</div></div>
<div class="portal-form">
<input class="input" id="new-ip" placeholder="IP или CIDR (например 1.2.3.4 или /24)">
<button class="btn" onclick="addIP()">Добавить</button>
<button class="btn ghost" onclick="addAutoIP()">📱 Текущий</button>
</div>
</div>
<div class="portal-danger">
<b>⚠ Опасная зона — Заменить все IP на текущий</b><br>
Эта операция удалит все ваши IP (кроме закреплённых) и добавит текущий.
<div class="portal-btn-row"><button class="btn danger sm" onclick="replaceAllIPs()">🔄 Заменить все</button></div>
</div>
<div class="portal-info" style="margin-top:12px">
<b>ℹ️ Для чего это нужно:</b><br>
Если включена блокировка входящих из РФ — клиенты с российскими IP не смогут подключиться.
Добавьте свой IP сюда, и вы получите доступ. IP берётся из TCP-подключения — его нельзя подделать.<br><br>
<b>📌 Закрепление:</b> Закреплённые IP (📌) не удаляются при очистке старых адресов.<br>
<b>🔄 Заменить все:</b> Удаляет все ваши IP (кроме закреплённых) и добавляет текущий.
</div></div>
</div>

<div class="tab-panel" id="panel-password">
<div class="card"><div class="card-title">🔒 Смена пароля портала</div>
<div class="portal-hero"><div class="portal-hero-top"><div>
<div class="portal-hero-label">Безопасность</div>
<div class="portal-hero-title">🔒 Смена пароля</div>
<div class="portal-hero-sub">Минимум 8 символов. Не используйте пароль от VPN.</div>
</div><span class="portal-proto-badge">🔒</span></div></div>
<div class="portal-info" id="pw-changed-at-box" style="margin-bottom:14px">Последняя смена: загружается…</div>
<div id="pw-changed-at" style="display:none"></div>
<div class="portal-tile">
<label style="display:block;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Новый пароль</label>
<input class="input" id="new-pass" type="password" placeholder="Введите новый пароль" oninput="pwStrength(this.value)" style="width:100%">
<div class="portal-progress" id="pw-bar"><div class="portal-progress-fill off" id="pw-fill" style="width:0%"></div></div>
<div class="portal-meta"><span id="pw-label">—</span><span>мин. 8 символов</span></div>
<div class="pw-checklist">
<span id="pw-chk-len" data-label="8+ символов">○ 8+ символов</span>
<span id="pw-chk-alnum" data-label="буквы + цифры">○ буквы + цифры</span>
<span id="pw-chk-spec" data-label="спецсимволы">○ спецсимволы</span>
</div>
</div>
<div class="portal-btn-row">
<button class="btn" id="pw-submit" onclick="changePassword()">Сменить пароль</button>
</div>
<div class="portal-info" style="margin-top:12px">
<b>🛡 Советы по безопасности:</b><br>
• Используйте уникальный пароль (не от почты/соцсетей)<br>
• Длина 12+ символов — оптимально<br>
• Буквы разного регистра + цифры + спецсимволы<br>
• Пароль хранится в виде bcrypt-хэша и не передаётся на сервер VPN
</div>
</div>
</div>

<div class="tab-panel" id="panel-satellites">
<div class="card" id="sat-card" style="display:none"><div class="card-title">🛰 Сателлиты</div>
<div class="portal-collapse" onclick="toggleCollapse(this)">🛰 Список сателлитов</div><div class="portal-collapse-body" id="sat-container"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div></div>
</div>

<div class="tab-panel" id="panel-b4">
<div class="card" id="b4-card" style="display:none"><div class="card-title">📺 YouTube DPI Bypass</div>
<div id="b4-container"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div></div>
</div>

<div class="tab-panel" id="panel-server">
<div class="card"><div class="card-title">🖥 Состояние сервера</div>
<div class="grid2" id="sys-grid"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div></div>
</div>

<div class="tab-panel" id="panel-awg">
<div class="card" id="awg-card" style="display:none"><div class="card-title">🛡 AmneziaWG</div>
<div id="awg-container"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div></div>
</div>

</div>
<div class="toast" id="toast"></div>
<script>
function switchTab(t){{
document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.tab===t));
document.querySelectorAll('.tab-panel').forEach(p=>p.classList.toggle('active',p.id==='panel-'+t));
history.replaceState(null,'','#'+t);
}}
(function(){{const h=(location.hash||'#connect').slice(1);if(document.getElementById('panel-'+h))switchTab(h);}})();
function showToast(m,t='success'){{
  const e=document.getElementById('toast');
  const ico=t==='success'?'<span class="toast-success-icon"><svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M3 9.5L7 13.5L15 4.5" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg></span>':'';
  e.innerHTML=ico+'<span>'+esc(String(m==null?'':m))+'</span>';
  e.className='toast show '+t;
  clearTimeout(e._t);
  e._t=setTimeout(()=>e.className='toast',3000);
}}
async function api(p){{const r=await fetch(p,{{credentials:'same-origin'}});if(r.status===401){{location.href='/portal/';return null;}}if(!r.ok&&r.status!==400)return null;return r.json().catch(()=>null);}}

{PORTAL_TABS_JS}

{LOAD_TRAFFIC_JS}

{PORTAL_POLISH_JS}

loadLinks();loadSubscription();loadTraffic();loadHealth();loadIPs();loadSatellites();loadB4();loadAWG();
loadPasswordInfo();loadConnStatus();detectRecommendedClient();
</script>
</body></html>'''


# ─── Appended: Admin gap UI (per-user actions + settings widgets) ───
"""
wpp_ui_additions.py
──────────────────────────────────────────────────────────────────────────────
Admin gap UI — per-user action buttons + Settings-page widgets that expose
the wpp_admin_extras.py API endpoints in the WPP Web Panel browser UI.

Functions:
  admin_user_actions(source, path, csrf)   — per-user card (UUID, pass, ban, rename)
  admin_block()                            — page-level toast + CSS + script
  admin_health_widget(path)                — Health card markup
  admin_health_script()                    — Health JS (auto-refresh 30s)
  admin_backup_card(path, csrf)            — Backup card markup
  admin_backup_script()                    — Backup JS
  admin_geoip_card(path, csrf)             — GeoIP card markup
  admin_geoip_script()                     — GeoIP JS
  admin_b4_card(path, csrf)                — b4 card markup
  admin_b4_script()                        — b4 JS
  admin_tools_section(path, csrf)          — Combined Settings-page section
──────────────────────────────────────────────────────────────────────────────
This file is meant to be appended verbatim to chimera/modules/wpp_ui.py.
It depends on esc(), icon(), and re (already imported by wpp_ui.py).
"""


# ─── Shared CSS for admin widgets ────────────────────────────────────────────

ADMIN_CSS = '''<style>
.wpp-toast{position:fixed;bottom:24px;right:24px;z-index:200;padding:13px 18px;border-radius:11px;background:var(--accent);color:var(--on-accent);font:600 13px/1.4 inherit;opacity:0;transition:opacity .25s;pointer-events:none;max-width:420px;box-shadow:var(--shadow)}
.wpp-toast.show{opacity:1}
.wpp-toast.error{background:var(--red)}
.wpp-toast.warn{background:var(--amber)}
.admin-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:18px;margin-top:14px}
.admin-card{display:flex;flex-direction:column;gap:12px}
.admin-actions{margin:14px 0;padding:14px;border:1px solid var(--line);border-radius:12px;background:var(--input)}
.admin-actions>summary{cursor:pointer;font-weight:600;color:var(--accent);list-style:revert}
.admin-actions-row{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.admin-form{display:flex;flex-direction:column;gap:6px;margin:12px 0}
.admin-form>label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.admin-form-row{display:grid;grid-template-columns:1fr auto;gap:8px}
.admin-form-row input,.admin-form-row select{padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);font:13px inherit;min-width:0}
.admin-form-row input:focus,.admin-form-row select:focus{border-color:var(--accent)}
.admin-status{margin:8px 0 0;color:var(--muted);font-size:11px;min-height:14px}
.admin-health-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px}
.admin-health-item{padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--input)}
.admin-health-item span{display:block;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
.admin-health-item b{font:500 13px ui-monospace,monospace;word-break:break-word}
.admin-badge{display:inline-block;padding:3px 9px;border-radius:6px;font:600 11px ui-monospace,monospace;background:var(--raised);color:var(--text)}
.admin-badge.on{background:rgba(139,219,170,.18);color:var(--green)}
.admin-badge.off{background:rgba(255,153,147,.18);color:var(--red)}
.admin-backup-list,.admin-geoip-list{display:flex;flex-direction:column;gap:8px;max-height:280px;overflow:auto}
.admin-backup-item,.admin-geoip-item{padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--input)}
.admin-backup-item small,.admin-geoip-item span{display:block;color:var(--muted);font:11px ui-monospace,monospace;word-break:break-all}
.admin-b4-actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px}
@media(max-width:640px){.admin-grid{grid-template-columns:1fr}.admin-form-row{grid-template-columns:1fr}}
</style>'''


ADMIN_TOAST_MARKUP = '<div id="wppToast" class="wpp-toast" role="status" aria-live="polite"></div>'


# ─── Page-level toast + fetch helper (idempotent) ────────────────────────────

ADMIN_TOAST_SCRIPT = '''<script>(function(){
if(window.__wppAdminToast){return;} window.__wppAdminToast=true;
const toast=document.getElementById('wppToast');
function showToast(msg,type){
  type=type||'success';
  if(!toast){alert(msg);return;}
  toast.textContent=msg;
  toast.className='wpp-toast show '+(type==='error'?'error':type==='warn'?'warn':'');
  clearTimeout(toast._t);
  toast._t=setTimeout(function(){toast.className='wpp-toast';},3200);
}
window.wppShowToast=showToast;
window.wppApi=async function(method,url,body){
  const opt={method:method,credentials:'same-origin',headers:{'Content-Type':'application/json'}};
  if(body!==undefined){opt.body=JSON.stringify(body);}
  let r;
  try{r=await fetch(url,opt);}
  catch(e){throw new Error('Сеть недоступна: '+e.message);}
  let d={};
  try{d=await r.json();}catch(e){}
  if(!r.ok){throw new Error(d.error||d.message||('HTTP '+r.status));}
  return d;
};
async function adminUuid(b){
  if(!confirm('Сменить UUID пользователя '+b.dataset.email+'? Прежний UUID сразу перестанет работать.')){return;}
  b.disabled=true;
  try{
    const d=await wppApi('POST','/api/rotate/uuid',{email:b.dataset.email});
    showToast('UUID изменён: '+String(d.new_uuid||'').slice(0,8)+'…');
  }catch(err){showToast(err.message,'error');}
  finally{b.disabled=false;}
}
async function adminToggle(b){
  if(!confirm('Переключить бан/разбан для '+b.dataset.email+'?')){return;}
  b.disabled=true;
  try{
    const d=await wppApi('POST','/api/users/'+encodeURIComponent(b.dataset.email)+'/toggle',{});
    showToast('Статус: '+String(d.status||'ok'));
  }catch(err){showToast(err.message,'error');}
  finally{b.disabled=false;}
}
document.addEventListener('click',function(e){
  const b1=e.target.closest('[data-admin-uuid]');if(b1){adminUuid(b1);return;}
  const b2=e.target.closest('[data-admin-toggle]');if(b2){adminToggle(b2);return;}
});
document.addEventListener('submit',async function(e){
  const f=e.target.closest('form[data-admin-form]');if(!f){return;}
  e.preventDefault();
  const kind=f.dataset.adminForm;
  const email=f.dataset.email;
  const input=f.querySelector('input');
  const btn=f.querySelector('button[type=submit]');
  if(btn){btn.disabled=true;}
  try{
    if(kind==='password'){
      const v=input.value.trim();
      if(v.length<8){showToast('Минимум 8 символов','error');return;}
      await wppApi('POST','/api/users/'+encodeURIComponent(email)+'/password',{new_password:v});
      showToast('Пароль установлен');
      input.value='';
    }else if(kind==='rename'){
      const v=input.value.trim();
      if(v.length<3||v.length>32){showToast('Имя 3-32 символа','error');return;}
      const d=await wppApi('POST','/api/users/'+encodeURIComponent(email)+'/rename',{new_name:v});
      showToast('Переименован в '+String(d.new_name||v));
    }
  }catch(err){showToast(err.message,'error');}
  finally{if(btn){btn.disabled=false;}}
});
})();</script>'''


def admin_block():
    """Page-level admin CSS + toast + script. Include once per page.

    Used by users_ui() and admin_tools_section() in the settings page.
    The script is idempotent (guards via window.__wppAdminToast).
    """
    return ADMIN_CSS + ADMIN_TOAST_MARKUP + ADMIN_TOAST_SCRIPT


# ─── Per-user admin actions card (in users_ui detail dialog) ─────────────────

def admin_user_actions(source, path, csrf):
    """Per-user admin action card for the users detail dialog.

    Renders UUID rotate, password set, ban/unban toggle, rename form.
    Only renders when the user record carries an `email` field (VLESS users
    from /etc/xray/users.json — email field added by wpp_panel_web.users()).
    """
    src = source or {}
    email = str(src.get('email', '') or '').strip()
    if not email:
        return ''
    name = str(src.get('name', '') or email.split('@', 1)[0])
    e_email = esc(email)
    e_name = esc(name)
    return f'''<details class="admin-actions" open>
<summary>🔐 Администратор · {e_email}</summary>
<p class="muted">Действия ниже меняют учётные данные пользователя и синхронизируют их с Xray. Подключения клиента могут кратковременно прерваться.</p>
<div class="admin-actions-row">
<button type="button" class="btn ghost sm" data-admin-uuid data-email="{e_email}">🔄 Сменить UUID</button>
<button type="button" class="btn ghost sm" data-admin-toggle data-email="{e_email}">🔨 Ban / Unban</button>
</div>
<form class="admin-form" data-admin-form="password" data-email="{e_email}">
<label>🔑 Портальный пароль (мин. 8 символов)</label>
<div class="admin-form-row"><input type="password" minlength="8" required placeholder="новый пароль" autocomplete="new-password"><button type="submit" class="btn sm">Задать</button></div>
</form>
<form class="admin-form" data-admin-form="rename" data-email="{e_email}">
<label>✏️ Имя клиента (3-32 симв.)</label>
<div class="admin-form-row"><input value="{e_name}" maxlength="32" minlength="3" required><button type="submit" class="btn sm">Переименовать</button></div>
</form>
<p class="admin-status" role="status"></p>
</details>'''


# ─── Health widget (settings page) ───────────────────────────────────────────

def admin_health_widget(path):
    """Auto-refreshing system health card."""
    return '''<section class="card admin-card">
<div class="card-title"><h2>📊 Здоровье сервера</h2><span class="pill">обновление 30 с</span></div>
<p class="muted" id="adminHealthNote">Загрузка статуса…</p>
<div class="admin-health-grid" id="adminHealthGrid"></div>
</section>'''


ADMIN_HEALTH_SCRIPT = '''<script>(function(){
if(window.__wppAdminHealth){return;} window.__wppAdminHealth=true;
const grid=document.getElementById('adminHealthGrid');
const note=document.getElementById('adminHealthNote');
if(!grid){return;}
function badge(text,ok){return '<span class="admin-badge '+(ok?'on':'off')+'">'+text+'</span>';}
function fmt(v,unit){unit=unit||'';return (v===undefined||v===null)?'—':String(v)+unit;}
async function load(){
  try{
    const d=await wppApi('GET','/api/health');
    const xrayOk=String(d.xray||'').toLowerCase()==='active';
    const nginxOk=String(d.nginx||'').toLowerCase()==='active';
    const dnscryptOk=String(d.dnscrypt||'').toLowerCase()==='active';
    const sslOk=Number(d.ssl_days_left||0)>0;
    const items=[
      ['Xray', badge(d.xray||'inactive', xrayOk)],
      ['Nginx', badge(d.nginx||'inactive', nginxOk)],
      ['DNSCrypt', badge(d.dnscrypt||'inactive', dnscryptOk)],
      ['SSL дней', badge(fmt(d.ssl_days_left), sslOk)],
      ['CPU ядер', fmt(d.cpu_cores)],
      ['Uptime (ч)', fmt(d.uptime_hours)],
      ['RAM', fmt(d.ram_used_mb,' МБ')+' / '+fmt(d.ram_total_mb,' МБ')+' ('+fmt(d.ram_pct,' %')+')'],
      ['Disk', fmt(d.disk_used)+' / '+fmt(d.disk_total)+' ('+fmt(d.disk_pct,' %')+')'],
      ['Соединений Xray', fmt(d.xray_connections)],
      ['Домен', fmt(d.domain)]
    ];
    grid.innerHTML=items.map(function(it){return '<div class="admin-health-item"><span>'+it[0]+'</span><b>'+it[1]+'</b></div>';}).join('');
    if(note){note.textContent='Обновлено: '+(d.timestamp||'');}
  }catch(err){
    if(note){note.textContent='Ошибка: '+err.message;}
    grid.innerHTML='';
  }
}
load();
setInterval(load,30000);
})();</script>'''


# ─── Backup card (settings page) ─────────────────────────────────────────────

def admin_backup_card(path, csrf):
    """Backup creation + list card."""
    return f'''<section class="card admin-card">
<div class="card-title"><h2>🗄️ Бэкапы конфигурации</h2><span class="pill">/var/lib/xray-installer/backups</span></div>
<div class="actions"><button type="button" class="btn primary" id="adminBackupCreate">Создать бэкап</button><button type="button" class="btn ghost" id="adminBackupRefresh">{icon('refresh')} Обновить</button></div>
<p class="muted" id="adminBackupNote" role="status">Загрузка списка…</p>
<div class="admin-backup-list" id="adminBackupList"></div>
</section>'''


ADMIN_BACKUP_SCRIPT = '''<script>(function(){
if(window.__wppAdminBackup){return;} window.__wppAdminBackup=true;
const list=document.getElementById('adminBackupList');
const note=document.getElementById('adminBackupNote');
const createBtn=document.getElementById('adminBackupCreate');
const refreshBtn=document.getElementById('adminBackupRefresh');
function esc2(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function humanSize(b){
  b=Number(b||0);
  if(b<1024){return b+' Б';}
  const units=['КБ','МБ','ГБ','ТБ'];
  let i=-1;
  while(b>=1024 && i<units.length-1){b/=1024;i++;}
  return b.toFixed(1)+' '+units[i];
}
async function load(){
  if(list){list.innerHTML='<div class="loading"><div class="spinner"></div></div>';}
  try{
    const d=await wppApi('GET','/api/backup/list');
    const items=d.backups||[];
    if(!items.length){if(list){list.innerHTML='<p class="muted">Бэкапов нет</p>';}if(note){note.textContent='Бэкапов нет';}return;}
    if(list){list.innerHTML=items.map(function(b){
      const size=humanSize(b.size_bytes);
      const mtime=b.mtime?(' · '+esc2(b.mtime)):'';
      return '<div class="admin-backup-item"><div><b>'+esc2(b.name)+'</b><small>'+esc2(b.path||'')+' · '+size+mtime+'</small></div></div>';
    }).join('');}
    if(note){note.textContent='Всего: '+String(d.count||items.length);}
  }catch(err){if(note){note.textContent='Ошибка: '+err.message;}}
}
if(createBtn){createBtn.addEventListener('click',async function(){
  if(!confirm('Создать новый бэкап сейчас?')){return;}
  createBtn.disabled=true;createBtn.textContent='Создание…';
  try{await wppApi('POST','/api/backup',{});wppShowToast('Бэкап создан');load();}
  catch(err){wppShowToast(err.message,'error');}
  finally{createBtn.disabled=false;createBtn.textContent='Создать бэкап';}
});}
if(refreshBtn){refreshBtn.addEventListener('click',load);}
load();
})();</script>'''


# ─── GeoIP rules card (settings page) ───────────────────────────────────────

def admin_geoip_card(path, csrf):
    """GeoIP rules card — country allow/block list."""
    return f'''<section class="card admin-card">
<div class="card-title"><h2>🌐 GeoIP правила</h2><span class="pill">Xray routing.rules</span></div>
<p class="muted">Управление блокировкой/allowlist по странам (коды стран, напр. RU, CN). Allowlist пропускает только указанные страны и блокирует всё остальное — убедитесь, что ваш IP входит в разрешённые страны, иначе потеряете доступ.</p>
<div class="actions"><button type="button" class="btn ghost" id="adminGeoipRefresh">{icon('refresh')} Обновить</button><button type="button" class="btn danger" id="adminGeoipClear">Удалить все правила</button></div>
<p class="muted" id="adminGeoipNote" role="status">Загрузка…</p>
<div class="admin-geoip-list" id="adminGeoipList"></div>
<form class="admin-form" id="adminGeoipForm">
<label>Коды стран через запятую (RU,CN,US)</label>
<div class="admin-form-row">
<input name="codes" placeholder="RU,CN,US" required pattern="[A-Za-z,\\s]+" title="Коды стран (2 буквы) через запятую">
<select name="mode"><option value="block">Блокировать</option><option value="allow">Allowlist (только эти)</option></select>
<button type="submit" class="btn primary">Применить</button>
</div>
</form>
</section>'''


ADMIN_GEOIP_SCRIPT = '''<script>(function(){
if(window.__wppAdminGeoip){return;} window.__wppAdminGeoip=true;
const list=document.getElementById('adminGeoipList');
const note=document.getElementById('adminGeoipNote');
const refreshBtn=document.getElementById('adminGeoipRefresh');
const clearBtn=document.getElementById('adminGeoipClear');
const form=document.getElementById('adminGeoipForm');
function esc2(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
async function load(){
  if(list){list.innerHTML='<div class="loading"><div class="spinner"></div></div>';}
  try{
    const d=await wppApi('GET','/api/geoip/rules');
    const items=d.rules||[];
    if(!items.length){if(list){list.innerHTML='<p class="muted">Правил нет</p>';}if(note){note.textContent='Активных блокировок нет';}return;}
    if(list){list.innerHTML=items.map(function(r){
      const codes=(r.geoip||[]).map(esc2).join(', ');
      const tag=r.outboundTag||'block';
      return '<div class="admin-geoip-item"><b>'+esc2(tag)+'</b><span>'+codes+'</span></div>';
    }).join('');}
    if(note){note.textContent='Всего правил: '+String(d.count||items.length);}
  }catch(err){if(note){note.textContent='Ошибка: '+err.message;}}
}
if(refreshBtn){refreshBtn.addEventListener('click',load);}
if(clearBtn){clearBtn.addEventListener('click',async function(){
  if(!confirm('Удалить ВСЕ GeoIP правила и перезапустить Xray?')){return;}
  clearBtn.disabled=true;
  try{await wppApi('DELETE','/api/geoip/rules',undefined);wppShowToast('Правила удалены');load();}
  catch(err){wppShowToast(err.message,'error');}
  finally{clearBtn.disabled=false;}
});}
if(form){form.addEventListener('submit',async function(e){
  e.preventDefault();
  const fd=new FormData(form);
  const raw=(fd.get('codes')||'').toString();
  const codes=raw.split(/[\\s,]+/).map(function(s){return s.trim().toUpperCase();}).filter(function(s){return /^[A-Z]{2}$/.test(s);});
  const mode=fd.get('mode')||'block';
  if(!codes.length){wppShowToast('Введите хотя бы один код страны (2 буквы)','error');return;}
  const btn=form.querySelector('button[type=submit]');if(btn){btn.disabled=true;}
  try{
    await wppApi('POST','/api/geoip/rules',{codes:codes,mode:mode});
    wppShowToast('Применено: '+codes.join(', ')+(mode==='allow'?' (allowlist)':' (block)'));
    form.reset();
    load();
  }catch(err){wppShowToast(err.message,'error');}
  finally{if(btn){btn.disabled=false;}}
});}
load();
})();</script>'''


# ─── b4 management card (settings page) ─────────────────────────────────────

def admin_b4_card(path, csrf):
    """b4 management card."""
    return f'''<section class="card admin-card">
<div class="card-title"><h2>📡 b4 (DPI / MTProto bridge)</h2><span class="pill">admin</span></div>
<p class="muted">Управление сервисом b4. Действия запускают shell-команды и могут занять до минуты.</p>
<div class="admin-b4-actions">
<button type="button" class="btn primary" data-b4-action="install">Установить</button>
<button type="button" class="btn ghost" data-b4-action="enable">Включить</button>
<button type="button" class="btn ghost" data-b4-action="disable">Выключить</button>
<button type="button" class="btn ghost" data-b4-action="discovery">🔍 Discovery</button>
</div>
<p class="admin-status" id="adminB4Status" role="status">Готово к работе.</p>
</section>'''


ADMIN_B4_SCRIPT = '''<script>(function(){
if(window.__wppAdminB4){return;} window.__wppAdminB4=true;
const status=document.getElementById('adminB4Status');
document.querySelectorAll('[data-b4-action]').forEach(function(btn){
  btn.addEventListener('click',async function(){
    const action=btn.dataset.b4Action;
    if(!confirm('Запустить b4: '+action+'?')){return;}
    btn.disabled=true;
    if(status){status.textContent='Выполняется: '+action+'…';}
    try{
      const d=await wppApi('POST','/api/b4/'+action,{});
      const msg=action==='discovery'
        ? 'Discovery: '+(d.status||JSON.stringify(d).slice(0,80))
        : ('Результат: '+(d.status||'ok'));
      wppShowToast(msg);
      if(status){status.textContent=msg;}
    }catch(err){wppShowToast(err.message,'error');if(status){status.textContent='Ошибка: '+err.message;}}
    finally{btn.disabled=false;}
  });
});
})();</script>'''


# ─── Combined Settings-page section ──────────────────────────────────────────

def admin_tools_section(path, csrf):
    """Combined admin tools section for the Settings page.

    Renders: Health widget, Backup card, GeoIP card, b4 card — plus shared
    toast markup, CSS, and a single script block initializing all four.
    """
    parts = [
        '<section class="card admin-tools-card">',
        '<div class="card-title"><span class="eyebrow">WPP / ADMIN GAP</span><h2>Инструменты администратора</h2><p>API-эндпоинты из wpp_admin_extras.py — резервные копии, GeoIP, b4, здоровье сервера и управление пользователями.</p></div>',
        '<div class="admin-grid">',
        admin_health_widget(path),
        admin_backup_card(path, csrf),
        admin_geoip_card(path, csrf),
        admin_b4_card(path, csrf),
        '</div>',
        '</section>',
        ADMIN_CSS,
        ADMIN_TOAST_MARKUP,
        ADMIN_TOAST_SCRIPT,
        ADMIN_HEALTH_SCRIPT,
        ADMIN_BACKUP_SCRIPT,
        ADMIN_GEOIP_SCRIPT,
        ADMIN_B4_SCRIPT,
    ]
    return ''.join(parts)
