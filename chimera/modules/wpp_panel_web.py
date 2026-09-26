#!/usr/bin/env python3
"""
chimera/modules/wpp_panel_web.py — Direct port of WPP panel.py v2.4.2 (MIT).
ALL routing, UI, JS, CSS — 1:1 with original WPP project.
Only data source paths adapted to chimera.

Bootstrap for direct execution / systemd ExecStart:
"""
from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path
_ROOT = _Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import grp
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlparse
from collections import defaultdict, deque
from chimera.modules.wpp_subscriptions import PREFIX as SUB_PREFIX
from chimera.modules.wpp_panel_extras import preview_document
from chimera.modules.wpp_ui import page_layout, login_ui, dashboard_body, dashboard_page, users_ui, editor_ui, openflux_ui, client_records, nodes_ui, updates_ui
from chimera.modules import wpp_metrics as server_metrics
from chimera.modules import wpp_update as web_updates
from chimera.modules import wpp_components as components
from chimera.modules import wpp_nodes as node_api
from chimera.modules import wpp_openflux as openflux
from chimera.modules import wpp_awg as awg

HOST="127.0.0.1"
PORT=8090
DATA="/var/lib/xray-installer/wpp_panel_data.json"
KEY="/var/lib/xray-installer/wpp_panel_session.key"
DOMAIN=""
MTPROTO_HOST=""
PANEL_PATH=os.environ.get("WEBPROXY_PANEL_PATH","/panel")
PRIMARY=""
PROFILES="/etc/xray/users.json"
USERS="/etc/xray/users.json"
TRAFFIC="/var/lib/xray-installer/wpp_metrics.json"
XRAY_PATH_FILE=""
HYSTERIA_PORT=8443
MANAGER=""
QR="/usr/bin/qrencode"
LOGO=""
FLAGS=""
SITE_INDEX="/var/www/panel-stub/index.html"
SITE_BACKUP="/var/lib/xray-installer/wpp_panel_site_backup.html"
SITE_SOURCE="/var/lib/xray-installer/wpp_panel_site_source.html"
SITE_SOURCE_BACKUP="/var/lib/xray-installer/wpp_panel_site_source.html.bak"
SITE_CSS="/srv/tproxy-site/panel-site.css"
SITE_CSS_BACKUP="/var/lib/xray-installer/panel-site.css.bak"
SITE_JS="/srv/tproxy-site/panel-site.js"
SITE_JS_BACKUP="/var/lib/xray-installer/panel-site.js.bak"
MAX_HTML_BYTES=1024*1024
SITE_DRAFT="/var/lib/xray-installer/wpp_panel_stub.draft.html"
CUSTOM_PRESETS_FILE="/var/lib/xray-installer/custom-presets.json"
API_KEY_FILE="/var/lib/xray-installer/api.key"
NODES_FILE="/var/lib/xray-installer/nodes.json"
LOCATION_FILE="/var/lib/xray-installer/location.json"
try:
    API_KEY=node_api.ensure_api_key(API_KEY_FILE)
except Exception:
    API_KEY=""
SUB_FETCH_SLOTS=threading.BoundedSemaphore(4)
SUB_RATE_LOCK=threading.Lock()
SUB_REQUESTS={}

# Presets are deliberately standalone at authoring time: no CDN and no icon
# font. On publication the panel moves executable CSS/JS into immutable local
# files because the public relay uses a strict Content-Security-Policy.
PRESETS=[
 {"id":"countdown","name":"Обратный отсчёт","description":"Светлая страница с живым таймером и адаптацией для телефона.","html":'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#101b46"><title>Скоро открытие</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;color:#111936;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:radial-gradient(circle at 12% 12%,#bce7ff,transparent 34%),radial-gradient(circle at 88% 92%,#d9c8ff,transparent 36%),#f5f7ff}.card{width:min(780px,100%);padding:clamp(32px,7vw,70px);text-align:center;border:1px solid #fff;border-radius:34px;background:#fffffff0;box-shadow:0 25px 70px #344f8b27}.mark{width:68px;height:68px;margin:0 auto 22px;display:grid;place-items:center;border-radius:22px;background:linear-gradient(135deg,#2868ff,#7b4dff);color:#fff;font-size:32px;box-shadow:0 14px 28px #4168ce55}h1{margin:0;font-size:clamp(34px,7vw,62px);letter-spacing:-.06em}h1 span{color:#2868ff}p{max-width:530px;margin:18px auto 0;color:#56637e;font-size:clamp(16px,2.5vw,20px);line-height:1.6}.timer{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;max-width:510px;margin:38px auto}.unit{padding:17px 8px;border-radius:20px;background:#f6f8ff;border:1px solid #e7ebfa}.n{display:block;font-size:clamp(28px,5vw,45px);font-weight:800;line-height:1}.l{display:block;margin-top:8px;color:#77829b;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}.note{display:inline-flex;align-items:center;gap:9px;padding:12px 16px;border-radius:99px;background:#eef3ff;color:#3c568d;font-size:14px}.dot{width:8px;height:8px;border-radius:50%;background:#2ccf91;box-shadow:0 0 0 5px #2ccf9128}@media(max-width:440px){.card{padding:35px 18px;border-radius:26px}.timer{gap:7px}.unit{padding:14px 4px;border-radius:15px}.l{font-size:9px}}</style></head>
<body><main class="card"><div class="mark">✦</div><h1><span>Скоро</span> открытие</h1><p>Мы готовим что-то особенное. Оставьте эту страницу открытой — запуск уже близко.</p><section class="timer" aria-label="Обратный отсчёт"><div class="unit"><b class="n" id="d">00</b><i class="l">дней</i></div><div class="unit"><b class="n" id="h">00</b><i class="l">часов</i></div><div class="unit"><b class="n" id="m">00</b><i class="l">минут</i></div><div class="unit"><b class="n" id="s">00</b><i class="l">секунд</i></div></section><div class="note"><span class="dot"></span> Следите за обновлениями</div></main><script>const end=Date.now()+14*864e5;function tick(){let x=Math.max(0,end-Date.now());const v=[Math.floor(x/864e5),Math.floor(x/36e5)%24,Math.floor(x/6e4)%60,Math.floor(x/1e3)%60];['d','h','m','s'].forEach((id,i)=>document.getElementById(id).textContent=String(v[i]).padStart(2,'0'))}tick();setInterval(tick,1000)</script></body></html>'''},
 {"id":"cars","name":"Продажа авто","description":"Тёмная автомобильная витрина с акцентом на заявки.","html":'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0b0d14"><title>Автомобили скоро</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;overflow:hidden;font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#f8f9fc;background:#0b0d14}.glow{position:fixed;inset:0;background:radial-gradient(ellipse at 18% 15%,#ef4f5d36,transparent 32%),radial-gradient(ellipse at 82% 84%,#ffbb5a22,transparent 35%)}main{position:relative;min-height:100vh;display:grid;align-content:center;max-width:1100px;margin:auto;padding:36px}.tag{display:inline-flex;width:max-content;padding:8px 12px;border:1px solid #ffffff22;border-radius:99px;background:#ffffff0b;color:#ffb861;font-size:12px;font-weight:800;letter-spacing:.1em;text-transform:uppercase}.hero{display:grid;grid-template-columns:1.1fr .9fr;gap:34px;align-items:center;margin-top:22px}.kicker{color:#ffb861;font-weight:700;letter-spacing:.08em;text-transform:uppercase}h1{margin:12px 0 16px;font-size:clamp(44px,8vw,86px);line-height:.95;letter-spacing:-.07em}p{margin:0;max-width:560px;color:#afb6c8;font-size:18px;line-height:1.7}.car{min-height:285px;display:grid;place-items:center;border:1px solid #ffffff14;border-radius:30px;background:linear-gradient(145deg,#1c2132,#10131d);box-shadow:0 26px 70px #0007;font-size:clamp(130px,22vw,230px);transform:rotate(-4deg)}.action{display:inline-block;margin-top:30px;padding:15px 21px;border-radius:14px;background:#f4f6ff;color:#121621;text-decoration:none;font-weight:800;box-shadow:0 12px 28px #0005}.foot{margin-top:42px;padding-top:20px;border-top:1px solid #ffffff14;color:#71798e;font-size:13px}@media(max-width:700px){main{padding:24px}.hero{grid-template-columns:1fr}.car{min-height:190px;order:-1}p{font-size:16px}}</style></head><body><div class="glow"></div><main><span class="tag">Новая коллекция</span><section class="hero"><div><div class="kicker">Премиальный выбор</div><h1>Авто,<br>которые<br>ждут вас.</h1><p>Готовим каталог автомобилей с прозрачной историей, честными ценами и персональным подбором.</p><a class="action" href="mailto:info@example.com">Получить уведомление →</a></div><div class="car" aria-label="Автомобиль">🏎️</div></section><div class="foot">СКОРО ОТКРЫТИЕ · ПОДБОР · ПРОВЕРКА · ДОСТАВКА</div></main></body></html>'''},
 {"id":"cats-repair","name":"Технические работы","description":"Дружелюбная страница обслуживания с анимацией, прогрессом и интерактивной кнопкой.","html":'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#1a1a2e"><title>Технические работы</title><style>
*{box-sizing:border-box}html,body{margin:0;min-height:100%}body{min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden;padding:24px;color:#f0ece6;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 20% 50%,#ffc86414,transparent 60%),radial-gradient(ellipse at 80% 50%,#ff649614,transparent 60%),#1a1a2e}.stars{position:fixed;inset:0;pointer-events:none;overflow:hidden}.star{position:absolute;opacity:.3;font-size:1.5rem;animation:floatStar 8s ease-in-out infinite}.star:nth-child(1){top:10%;left:5%}.star:nth-child(2){top:20%;right:8%;animation-delay:1.5s}.star:nth-child(3){bottom:25%;left:10%;animation-delay:3s;font-size:2rem}.star:nth-child(4){right:5%;bottom:15%;animation-delay:4.5s}.star:nth-child(5){top:50%;left:2%;animation-delay:2s}.star:nth-child(6){top:40%;right:3%;animation-delay:3.5s}.box{position:relative;z-index:1;width:min(700px,100%);padding:48px 40px;text-align:center;border:1px solid #ffffff10;border-radius:48px;background:#ffffff0a;box-shadow:0 40px 80px #0006;backdrop-filter:blur(12px)}.cats{display:flex;justify-content:center;gap:24px;margin-bottom:28px;flex-wrap:wrap}.cat{display:inline-block;font-size:4.5rem;filter:drop-shadow(0 8px 24px #ffc86426);cursor:pointer;user-select:none;animation:catDance 1.8s ease-in-out infinite}.cat:nth-child(2){font-size:5rem;animation-delay:.3s}.cat:nth-child(3){animation-delay:.6s}.cat:nth-child(4){font-size:4.8rem;animation-delay:.9s}.cat:hover{animation-play-state:paused}.title{margin:0 0 8px;font-size:clamp(32px,7vw,44px);font-weight:900;letter-spacing:-.04em}.title span{color:#fbbf24}.subtitle{margin:0 0 28px;color:#a09088;font-size:17px;line-height:1.6}.track{height:8px;overflow:hidden;border-radius:8px;background:#ffffff0f}.bar{width:0;height:100%;border-radius:inherit;background:linear-gradient(90deg,#fbbf24,#f59e0b,#fbbf24);transition:width .08s linear}.progress-text{display:flex;justify-content:space-between;margin-top:10px;color:#756861;font-size:13px}.paws{color:#fbbf24;letter-spacing:2px}.status{min-height:72px;margin:24px 0 28px;padding:18px;display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap;border:1px solid #ffffff0a;border-radius:20px;background:#ffffff08}.status-emoji{font-size:2rem;animation:pop 1s ease-in-out infinite}.message{font-size:17px}.message span{color:#fbbf24}.fun{display:inline-flex;align-items:center;justify-content:center;gap:10px;padding:15px 38px;border:0;border-radius:60px;color:#1a1a2e;background:linear-gradient(135deg,#fbbf24,#f59e0b);box-shadow:0 8px 24px #fbbf2433;font:700 17px inherit;cursor:pointer;transition:transform .2s,box-shadow .2s}.fun:hover{transform:scale(1.04);box-shadow:0 12px 32px #fbbf244d}.counter{margin-top:22px;color:#756861;font-size:14px}.counter b{color:#fbbf24;font-size:18px}@keyframes floatStar{50%{transform:translateY(-30px) rotate(180deg);opacity:.8}}@keyframes catDance{0%,100%{transform:rotate(-8deg)}25%{transform:rotate(8deg) translateY(-8px)}50%{transform:rotate(-5deg)}75%{transform:rotate(10deg) translateY(-5px)}}@keyframes pop{50%{transform:scale(1.2)}}@media(max-width:600px){.box{padding:32px 24px;border-radius:32px}.cats{gap:12px}.cat,.cat:nth-child(2),.cat:nth-child(4){font-size:3.2rem}.subtitle{font-size:15px}.message{font-size:14px}.fun{width:100%;padding:14px}.stars{display:none}}@media(max-width:400px){.cat,.cat:nth-child(2),.cat:nth-child(4){font-size:2.6rem}.box{padding:28px 16px}.status{padding:14px}}
</style></head><body><div class="stars"><span class="star">✨</span><span class="star">⭐</span><span class="star">🌟</span><span class="star">✨</span><span class="star">⭐</span><span class="star">🌟</span></div><main class="box"><div class="cats"><span class="cat">🐱</span><span class="cat">😺</span><span class="cat">😸</span><span class="cat">🐈</span></div><h1 class="title"><span>Сайт</span> на обслуживании</h1><p class="subtitle">🐾 Мяу-инженеры уже в пути! Подождите немного… 🐾</p><section><div class="track"><div class="bar" id="progressBar"></div></div><div class="progress-text"><span class="paws">🐾🐾🐾</span><span id="progressPercent">0%</span><span class="paws">🐾🐾🐾</span></div></section><div class="status"><span class="status-emoji" id="statusEmoji">🔧</span><span class="message" id="statusMessage"><span>Котики</span> настраивают сервер…</span></div><button class="fun" id="funButton">🐾 Погладить котика 🐾</button><div class="counter">Котиков погладили: <b id="clickCount">0</b> раз</div></main><script>
(function(){const statuses=[['🔧','<span>Котики</span> настраивают сервер…'],['🐱','Один котик <span>залип</span> в клавиатуре…'],['💻','<span>Кот-программист</span> пишет мяу-код…'],['☕','Котики <span>пьют</span> кофе…'],['🐾','Котики <span>топчут</span> сервер лапками…'],['😹','Котики <span>смеются</span> над багами…'],['🍕','Котики <span>едят</span> пиццу…'],['✨','Котики <span>колдуют</span> над сайтом…'],['🛠️','<span>Главный кот</span> чинит провода…']];const emoji=document.getElementById('statusEmoji'),message=document.getElementById('statusMessage'),bar=document.getElementById('progressBar'),percent=document.getElementById('progressPercent'),button=document.getElementById('funButton'),countNode=document.getElementById('clickCount');let statusIndex=0,progress=0,count=0;function changeStatus(){const item=statuses[statusIndex++%statuses.length];emoji.textContent=item[0];message.innerHTML=item[1]}function pet(){countNode.textContent=++count;emoji.textContent='🐱';message.innerHTML='<span>Котик</span> мурлычет от счастья!';const old=button.textContent;button.textContent='😻 Котик доволен!';setTimeout(function(){button.textContent=old;changeStatus()},900)}button.addEventListener('click',pet);document.querySelectorAll('.cat').forEach(function(cat){cat.addEventListener('click',pet)});changeStatus();setInterval(changeStatus,2500);setInterval(function(){progress=(progress+.8)%100;bar.style.width=progress+'%';percent.textContent=Math.round(progress)+'%'},80)})();
</script></body></html>'''},
 {"id":"loading","name":"Загрузка","description":"Минималистичный экран статуса для технического запуска.","html":'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#070a12"><title>Подготовка сервиса</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;color:#edf1ff;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#070a12}.grid{position:fixed;inset:0;opacity:.3;background-image:linear-gradient(#ffffff0a 1px,transparent 1px),linear-gradient(90deg,#ffffff0a 1px,transparent 1px);background-size:34px 34px;mask-image:radial-gradient(circle at center,#000,transparent 75%)}main{position:relative;width:min(540px,calc(100% - 40px));padding:44px 38px;border:1px solid #ffffff19;border-radius:28px;background:#111726cc;box-shadow:0 28px 90px #0008}.icon{display:grid;place-items:center;width:58px;height:58px;border-radius:18px;background:#78f0cf;color:#07120f;font-size:25px;box-shadow:0 0 35px #78f0cf55}h1{margin:25px 0 10px;font-size:34px;letter-spacing:-.05em}p{margin:0;color:#aab4c9;line-height:1.6}.bar{height:9px;margin:30px 0 15px;overflow:hidden;border-radius:20px;background:#ffffff12}.bar i{display:block;width:42%;height:100%;border-radius:inherit;background:linear-gradient(90deg,#78f0cf,#78b5ff);animation:load 1.8s ease-in-out infinite}.row{display:flex;justify-content:space-between;color:#8d99b0;font-size:12px}@keyframes load{0%{transform:translateX(-100%)}100%{transform:translateX(340%)}}</style></head><body><div class="grid"></div><main><div class="icon">↻</div><h1>Почти готово</h1><p>Сервис запускается и проверяет безопасное соединение. Это займёт совсем немного времени.</p><div class="bar"><i></i></div><div class="row"><span>Подготовка</span><span id="status">Проверяем систему…</span></div></main><script>const s=['Проверяем систему…','Настраиваем доступ…','Завершаем запуск…'];let i=0;setInterval(()=>document.getElementById('status').textContent=s[i++%s.length],2200)</script></body></html>'''}
]

try:
    os.makedirs(os.path.dirname(DATA),exist_ok=True)
    if not os.path.exists(KEY):
        with open(KEY,"wb") as f: f.write(secrets.token_bytes(32))
    with open(KEY,"rb") as f: SESSION_KEY=f.read()
    os.chmod(KEY,0o600)
except (PermissionError, OSError):
    SESSION_KEY=secrets.token_bytes(32)
STATE_LOCK=threading.RLock()
LOGIN_LOCK=threading.RLock()
LOGIN_FAILURES=defaultdict(deque)
LOGIN_FAILURES_GLOBAL=deque()
LOGIN_WINDOW=10*60
LOGIN_LIMIT=8
LOGIN_GLOBAL_LIMIT=200

def esc(x): return html.escape(str(x),quote=True)
def hash_password(p):
    salt=secrets.token_bytes(16)
    d=hashlib.scrypt(p.encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
    return base64.b64encode(salt+d).decode()
def check_password(p,h):
    try:
        raw=base64.b64decode(h); salt,exp=raw[:16],raw[16:]
        got=hashlib.scrypt(p.encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
        return secrets.compare_digest(exp,got)
    except Exception:
        return False
def sign(x): return x+"."+hmac.new(SESSION_KEY,x.encode(),hashlib.sha256).hexdigest()
def rotate_session_key():
    global SESSION_KEY
    fresh=secrets.token_bytes(32)
    tmp=KEY+".tmp"
    with open(tmp,"wb") as f:
        f.write(fresh); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp,0o600)
    os.replace(tmp,KEY)
    SESSION_KEY=fresh
def client_id(handler):
    forwarded=handler.headers.get("X-Forwarded-For","")
    candidate=forwarded.split(",")[-1].strip() if forwarded else handler.client_address[0]
    try: return str(ipaddress.ip_address(candidate))
    except ValueError: return "unknown"
def login_blocked(client):
    now=time.monotonic(); cutoff=now-LOGIN_WINDOW
    with LOGIN_LOCK:
        bucket=LOGIN_FAILURES[client]
        while bucket and bucket[0]<cutoff: bucket.popleft()
        while LOGIN_FAILURES_GLOBAL and LOGIN_FAILURES_GLOBAL[0]<cutoff: LOGIN_FAILURES_GLOBAL.popleft()
        if not LOGIN_FAILURES_GLOBAL:
            LOGIN_FAILURES.clear()
            bucket=LOGIN_FAILURES[client]
        return len(bucket)>=LOGIN_LIMIT or len(LOGIN_FAILURES_GLOBAL)>=LOGIN_GLOBAL_LIMIT
def login_failed(client):
    now=time.monotonic()
    with LOGIN_LOCK:
        LOGIN_FAILURES[client].append(now)
        LOGIN_FAILURES_GLOBAL.append(now)
def login_succeeded(client):
    with LOGIN_LOCK: LOGIN_FAILURES.pop(client,None)
def load():
    try:
        with open(DATA,encoding="utf-8") as f: return json.load(f)
    except Exception:
        return {"admin":{"user":"admin","hash":""}}
def save(d):
    t=DATA+".tmp"
    with open(t,"w",encoding="utf-8") as f: json.dump(d,f,ensure_ascii=True,indent=2)
    os.chmod(t,0o600); os.replace(t,DATA)
def primary():
    try:
        with open(PRIMARY,encoding="utf-8") as f: return f.read().strip()
    except Exception: return ""
def users():
    try:
        with open(USERS,encoding="utf-8") as f:
            data=json.load(f)
            # Handle both chimera (list) and WPP (dict with "users" key) formats
            return data if isinstance(data,list) else data.get("users",[])
    except Exception: return []
def traffic():
    try:
        with open(TRAFFIC,encoding="utf-8") as f:
            value=json.load(f)
            return value if isinstance(value,dict) else {}
    except Exception: return {}
def human_bytes(value):
    value=max(0,int(value or 0))
    units=("Б","КБ","МБ","ГБ","ТБ")
    size=float(value)
    for unit in units:
        if size<1024 or unit==units[-1]:
            return ("%.0f"%size if unit=="Б" else "%.1f"%size)+" "+unit
        size/=1024
def traffic_info(uid,state=None):
    state=state or traffic()
    item=state.get(uid,{})
    up=max(0,int(item.get("up",0)))
    down=max(0,int(item.get("down",0)))
    last=max(0,int(item.get("last_change",0)))
    active=bool(item.get("service_active")) and last>0 and time.time()-last<=90
    return {"up":up,"down":down,"total":up+down,"last":last,"active":active,"service":bool(item.get("service_active"))}
def read_site_html():
    try:
        # Keep the author source separate from the generated public files.
        # Reading index.html here used to make the next edit depend on the
        # previous preset's CSS/JS files.
        if os.path.exists(SITE_SOURCE):
            with open(SITE_SOURCE,encoding="utf-8") as f: return f.read()
        with open(SITE_INDEX,encoding="utf-8") as f: return hydrate_legacy_assets(f.read())
    except Exception as e:
        raise RuntimeError("Не удалось прочитать index.html: "+str(e))
def install_public_file(path,raw):
    tmp=path+".tmp"
    try:
        with open(tmp,"wb") as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.chown(tmp,0,grp.getgrnam("tproxy").gr_gid)
        os.chmod(tmp,0o640)
        os.replace(tmp,path)
    except Exception:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
        raise
def install_private_file(path,raw):
    tmp=path+".tmp"
    try:
        with open(tmp,"wb") as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.chown(tmp,0,0)
        os.chmod(tmp,0o600)
        os.replace(tmp,path)
    except Exception:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
        raise
def restart_public_site():
    r=subprocess.run(["systemctl","restart","tproxy-server.service"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
    if r.returncode or subprocess.run(["systemctl","is-active","--quiet","tproxy-server.service"],timeout=10).returncode:
        raise RuntimeError((r.stderr or r.stdout or "tproxy-server failed to restart").strip())
    # systemd considers the process active before both HTTP listeners have
    # completed their startup. Wait for the local health endpoint instead of
    # racing the first landing-page request.
    for _ in range(30):
        health=subprocess.run(["curl","-fsS","--noproxy","*","--max-time","2",
                               "http://127.0.0.1:8081/healthz"],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=4)
        if health.returncode==0: break
        time.sleep(0.5)
    else:
        raise RuntimeError("Relay health endpoint did not become ready after restart")
def fetch_published(path):
    # Resolve the real HTTPS hostname to loopback. This validates Caddy and the
    # relay without depending on public DNS, IPv6 routing or hairpin NAT.
    commands=(
        ["curl","-kfsS","--noproxy","*","--resolve",DOMAIN+":443:127.0.0.1",
         "--connect-timeout","2","--max-time","5","https://"+DOMAIN+path],
        ["curl","-fsS","--noproxy","*","-H","Host: "+DOMAIN,
         "--connect-timeout","2","--max-time","5","http://127.0.0.1:8080"+path],
    )
    last=""
    for attempt in range(12):
        for command in commands:
            result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=8)
            if result.returncode==0: return result.stdout
            last=(result.stderr or result.stdout or "relay request failed").strip()
        time.sleep(min(0.5+attempt*0.15,1.5))
    raise RuntimeError("Relay did not publish the landing page after restart: "+last[-300:])
def verify_public_asset(path, marker):
    body=fetch_published(path)
    if marker not in body:
        raise RuntimeError("Relay did not publish "+path+" after restart")
def verify_public_page(css_name,js_name):
    # A query forces the relay's no-store path, avoiding a false success from
    # the five-minute public index cache while a new design is being published.
    stamp=hashlib.sha256(((css_name or "")+(js_name or "")).encode()).hexdigest()[:12]
    body=fetch_published("/?wpp-site-check="+stamp)
    if css_name and ('/'+css_name) not in body:
        raise RuntimeError("Published landing page does not reference its stylesheet")
    if js_name and ('/'+js_name) not in body:
        raise RuntimeError("Published landing page does not reference its script")
def insert_into_head(document,tag):
    """Insert an asset without placing anything before <!doctype html>."""
    closing=re.search(r"</head\s*>",document,flags=re.I)
    if closing:
        return document[:closing.start()]+tag+document[closing.start():]
    opening=re.search(r"<html\b[^>]*>",document,flags=re.I)
    if opening:
        return document[:opening.end()]+"<head>"+tag+"</head>"+document[opening.end():]
    doctype=re.match(r"\s*<!doctype\b[^>]*>",document,flags=re.I)
    position=doctype.end() if doctype else 0
    return document[:position]+"<head>"+tag+"</head>"+document[position:]
def externalize_inline_assets(source):
    # Static public pages intentionally block inline CSS/JS. Keep generated
    # assets at local paths that tproxy-server can serve from public_dir. Data
    # scripts (JSON-LD, import maps and other non-executable payloads) must stay
    # in the HTML exactly where the author put them.
    styles=[]
    def replace_style(match):
        css=match.group(1).strip()
        if not css: return ""
        styles.append(css)
        return '<link rel="stylesheet" href="/panel-site.css">' if len(styles)==1 else ""
    rendered=re.sub(r"<style\b[^>]*>(.*?)</style\s*>",replace_style,source,flags=re.I|re.S)
    scripts=[]
    def replace_script(match):
        attributes=match.group(1) or ""
        type_match=re.search(r'\btype\s*=\s*(["\'])(.*?)\1',attributes,flags=re.I|re.S)
        script_type=(type_match.group(2).strip().lower() if type_match else "")
        executable_types={"","module","text/javascript","application/javascript","text/ecmascript","application/ecmascript"}
        if script_type not in executable_types:
            return match.group(0)
        code=match.group(2).strip()
        if not code: return ""
        scripts.append(code)
        return '<script src="/panel-site.js" defer></script>' if len(scripts)==1 else ""
    rendered=re.sub(r"<script\b(?![^>]*\bsrc\s*=)([^>]*)>(.*?)</script\s*>",replace_script,rendered,flags=re.I|re.S)
    # The relay CSP intentionally rejects style="..." attributes. Convert
    # them to same-origin stylesheet rules so standalone HTML pasted into the
    # editor keeps its layout without enabling unsafe-inline globally.
    inline_styles=[]
    def replace_inline_style(match):
        value=match.group(2).strip()
        if not value: return ""
        index=len(inline_styles)
        marker="wpp-%d"%index
        inline_styles.append('[data-wpp-style="%s"]{%s}'%(marker,value))
        return ' data-wpp-style="'+marker+'"'
    rendered=re.sub(r'\sstyle\s*=\s*(["\'])(.*?)\1',replace_inline_style,rendered,flags=re.I|re.S)
    if inline_styles:
        styles.append("\n".join(inline_styles))
    css="/* WEB PANEL PROXY public CSS */\n"+"\n\n".join(styles) if styles else ""
    javascript="/* WEB PANEL PROXY public JS */\n"+"\n\n".join(scripts) if scripts else ""
    css_name="panel-site-"+hashlib.sha256(css.encode()).hexdigest()[:12]+".css" if css else ""
    js_name="panel-site-"+hashlib.sha256(javascript.encode()).hexdigest()[:12]+".js" if javascript else ""
    if css_name:
        rendered=rendered.replace('/panel-site.css','/'+css_name)
        if '/'+css_name not in rendered:
            rendered=insert_into_head(rendered,'<link rel="stylesheet" href="/'+css_name+'">')
    if js_name:
        rendered=rendered.replace('/panel-site.js','/'+js_name)
    # Never keep a reference to a generated asset unless we generated it in
    # this exact save. It prevents a stale link from a damaged old page.
    if not styles:
        rendered=re.sub(r'<link\b[^>]*\bhref\s*=\s*(["\'])/panel-site(?:-[a-f0-9]{12})?\.css\1[^>]*>\s*',"",rendered,flags=re.I)
    if not scripts:
        rendered=re.sub(r'<script\b[^>]*\bsrc\s*=\s*(["\'])/panel-site(?:-[a-f0-9]{12})?\.js\1[^>]*>\s*</script\s*>\s*',"",rendered,flags=re.I|re.S)
    return rendered,css,javascript,css_name,js_name
def hydrate_legacy_assets(source):
    """Convert pages saved by older panel versions back to one HTML file."""
    css_ref=re.search(r'/((?:panel-site)(?:-[a-f0-9]{12})?\.css)',source,flags=re.I)
    js_ref=re.search(r'/((?:panel-site)(?:-[a-f0-9]{12})?\.js)',source,flags=re.I)
    try:
        css_path=os.path.join(os.path.dirname(SITE_INDEX),css_ref.group(1)) if css_ref else SITE_CSS
        with open(css_path,encoding="utf-8") as f: css=f.read()
    except Exception: css=""
    try:
        js_path=os.path.join(os.path.dirname(SITE_INDEX),js_ref.group(1)) if js_ref else SITE_JS
        with open(js_path,encoding="utf-8") as f: javascript=f.read()
    except Exception: javascript=""
    if css:
        source=re.sub(
            r'<link\b[^>]*\bhref\s*=\s*(["\'])/panel-site(?:-[a-f0-9]{12})?\.css\1[^>]*>',
            '<style>\n'+css+'\n</style>', source, flags=re.I)
    if javascript:
        source=re.sub(
            r'<script\b[^>]*\bsrc\s*=\s*(["\'])/panel-site(?:-[a-f0-9]{12})?\.js\1[^>]*>\s*</script\s*>',
            '<script>\n'+javascript+'\n</script>', source, flags=re.I|re.S)
    return source
def write_site_html(source):
    # Preserve the author's original document in SITE_SOURCE. The public copy
    # references same-origin immutable assets so the relay's strict CSP does
    # not strip the design. JSON-LD, SEO and verification markup stay inline.
    rendered,css,javascript,css_name,js_name=externalize_inline_assets(source)
    raw=rendered.encode("utf-8")
    if not source.strip(): raise ValueError("HTML не может быть пустым")
    if len(source.encode("utf-8"))>MAX_HTML_BYTES: raise ValueError("HTML превышает лимит 1 МБ")
    with STATE_LOCK:
        had_index_backup=os.path.exists(SITE_INDEX)
        had_source_backup=os.path.exists(SITE_SOURCE)
        had_css_backup=os.path.exists(SITE_CSS)
        had_js_backup=os.path.exists(SITE_JS)
        if had_index_backup:
            shutil.copy2(SITE_INDEX,SITE_BACKUP)
            os.chmod(SITE_BACKUP,0o600)
        if had_source_backup:
            shutil.copy2(SITE_SOURCE,SITE_SOURCE_BACKUP)
            os.chmod(SITE_SOURCE_BACKUP,0o600)
        if had_css_backup:
            shutil.copy2(SITE_CSS,SITE_CSS_BACKUP)
            os.chmod(SITE_CSS_BACKUP,0o600)
        if had_js_backup:
            shutil.copy2(SITE_JS,SITE_JS_BACKUP)
            os.chmod(SITE_JS_BACKUP,0o600)
        try:
            css_path=os.path.join(os.path.dirname(SITE_INDEX),css_name) if css_name else ""
            js_path=os.path.join(os.path.dirname(SITE_INDEX),js_name) if js_name else ""
            if css:
                install_public_file(css_path,css.encode("utf-8"))
            if javascript:
                install_public_file(js_path,javascript.encode("utf-8"))
            install_public_file(SITE_INDEX,raw)
            # tproxy-server serves public_dir from memory; a successful
            # restart makes the edited landing page visible immediately.
            restart_public_site()
            if css: verify_public_asset("/"+css_name,"WEB PANEL PROXY public CSS")
            if javascript: verify_public_asset("/"+js_name,"WEB PANEL PROXY public JS")
            verify_public_page(css_name,js_name)
            install_private_file(SITE_SOURCE,source.encode("utf-8"))
            # Keep a few prior immutable assets for rollback/open browser tabs.
            generated=[]
            for name in os.listdir(os.path.dirname(SITE_INDEX)):
                if re.fullmatch(r"panel-site-[a-f0-9]{12}\.(?:css|js)",name):
                    path=os.path.join(os.path.dirname(SITE_INDEX),name)
                    generated.append((os.path.getmtime(path),path))
            for _,path in sorted(generated,reverse=True)[12:]:
                try: os.unlink(path)
                except FileNotFoundError: pass
        except Exception:
            if had_index_backup and os.path.exists(SITE_BACKUP):
                try:
                    install_public_file(SITE_INDEX,open(SITE_BACKUP,"rb").read())
                    if had_css_backup and os.path.exists(SITE_CSS_BACKUP):
                        install_public_file(SITE_CSS,open(SITE_CSS_BACKUP,"rb").read())
                    elif os.path.exists(SITE_CSS):
                        os.unlink(SITE_CSS)
                    if had_js_backup and os.path.exists(SITE_JS_BACKUP):
                        install_public_file(SITE_JS,open(SITE_JS_BACKUP,"rb").read())
                    elif os.path.exists(SITE_JS):
                        os.unlink(SITE_JS)
                    if had_source_backup and os.path.exists(SITE_SOURCE_BACKUP):
                        install_private_file(SITE_SOURCE,open(SITE_SOURCE_BACKUP,"rb").read())
                    elif os.path.exists(SITE_SOURCE):
                        os.unlink(SITE_SOURCE)
                    restart_public_site()
                except Exception: pass
            raise
def custom_presets():
    try:
        with open(CUSTOM_PRESETS_FILE,encoding="utf-8") as stream: value=json.load(stream)
        if not isinstance(value,list): return []
        return [item for item in value if isinstance(item,dict) and
                isinstance(item.get("id"),str) and item["id"].startswith("custom-") and
                isinstance(item.get("name"),str) and isinstance(item.get("description"),str) and
                isinstance(item.get("html"),str)]
    except (OSError,ValueError,TypeError,json.JSONDecodeError):
        return []
def save_custom_presets(items):
    install_private_file(CUSTOM_PRESETS_FILE,json.dumps(items,ensure_ascii=False,indent=2).encode("utf-8"))
def all_presets():
    return PRESETS+custom_presets()
def get_preset(preset_id):
    for preset in all_presets():
        if preset.get("id")==preset_id: return preset
    raise ValueError("Пресет не найден")

def ctl(*args):
    r=subprocess.run([MANAGER,*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=60)
    if r.returncode: raise RuntimeError(r.stderr.strip() or "manager failed")
    return json.loads(r.stdout) if r.stdout.strip() else None
def subscription_registry():
    try:
        with open(DATA,encoding="utf-8") as f:
            data=json.load(f)
            return data.get("subscriptions",[]) if isinstance(data,dict) else []
    except (FileNotFoundError, Exception):
        return []
def ctl_subscription(request):
    # Tokens and hardware identifiers never appear in process arguments.
    try:
        r=subprocess.run([MANAGER,"subscription"],input=json.dumps(request),stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,text=True,timeout=180)
        if not r.returncode:
            value=json.loads(r.stdout)
            if isinstance(value,dict): return value
    except (OSError,subprocess.TimeoutExpired,ValueError):
        pass
    return {"ok":False,"status":503,"message":"Менеджер занят или недоступен. Повторите позже."}
def ctl_manager_json(command,request):
    r=subprocess.run([MANAGER,command],input=json.dumps(request),stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,text=True,timeout=180)
    if r.returncode:
        message=r.stderr.strip() or "manager failed"
        marker="ValueError: "
        if marker in message: raise ValueError(message.rsplit(marker,1)[-1].strip())
        raise RuntimeError(message)
    value=json.loads(r.stdout)
    if not isinstance(value,dict): raise RuntimeError("manager returned invalid JSON")
    return value
def federation_id(subscription_id,device_id):
    return hashlib.sha256((DOMAIN+":"+subscription_id+":"+device_id).encode()).hexdigest()
def purge_remote_profiles(subscription,device_id=None):
    if not subscription: return
    devices=[d for d in subscription.get("devices",[]) if device_id is None or d.get("id")==device_id]
    for node in node_api.load_nodes(NODES_FILE):
        if not node.get("enabled",True): continue
        for device in devices:
            try: node_api.delete_profile(node,federation_id(subscription.get("id",""),device.get("id","")))
            except node_api.NodeError as exc:
                print("node profile cleanup failed:",node.get("url"),str(exc),file=sys.stderr,flush=True)
def purge_remote_profiles_async(subscription,device_id=None):
    if not subscription: return
    threading.Thread(target=purge_remote_profiles,args=(subscription,device_id),
                     name="wpp-node-cleanup",daemon=True).start()
def allow_subscription_request(client):
    now=time.monotonic()
    with SUB_RATE_LOCK:
        for key in list(SUB_REQUESTS):
            if SUB_REQUESTS[key][0]<now-60: del SUB_REQUESTS[key]
        if client not in SUB_REQUESTS:
            if len(SUB_REQUESTS)>=2048: return False
            SUB_REQUESTS[client]=[now,0]
        SUB_REQUESTS[client][1]+=1
        return SUB_REQUESTS[client][1]<=30
def validate_html(source):
    if not source.strip(): raise ValueError("HTML не может быть пустым")
    if len(source.encode("utf-8"))>MAX_HTML_BYTES: raise ValueError("HTML превышает лимит 1 МБ")
    return source
def web_link(secret):
    return "https://t.me/webproxy?server="+DOMAIN+"&secret="+secret
def mtproto_link(secret,port):
    # Keep the 32-hex server secret unchanged, but request Telegram's random
    # packet-padding mode on the client. This makes MTProxy substantially less
    # likely to be rejected by networks that identify its packet sizes.
    client_secret=secret if secret.startswith("dd") else "dd"+secret
    return "https://t.me/proxy?server="+MTPROTO_HOST+"&port="+str(int(port))+"&secret="+client_secret
def xray_path():
    with open(XRAY_PATH_FILE,encoding="utf-8") as f: value=f.read().strip()
    if not re.fullmatch(r"/vless-[a-f0-9]{24}",value): raise RuntimeError("Некорректный путь VLESS")
    return value
def proxy_link(protocol,secret,port=443,name="Proxy",username=""):
    if protocol=="mtproto": return mtproto_link(secret,port)
    if protocol=="web": return web_link(secret)
    protocol_label={"vless":"VLESS","hysteria":"Hysteria2","awg20":"AWG 2.0","awg31":"AWG 3.1"}.get(protocol,protocol)
    if not (name.startswith("🌐") or (name and 0x1F1E6 <= ord(name[0]) <= 0x1F1FF)):
        name=node_api.location_prefix(node_api.load_location(LOCATION_FILE))+" · "+protocol_label
    label=quote(name or "Proxy",safe="")
    if protocol=="vless":
        query=urlencode({"encryption":"none","security":"tls","sni":DOMAIN,"fp":"chrome","type":"xhttp","host":DOMAIN,"path":xray_path(),"mode":"auto","alpn":"h2"})
        return "vless://"+quote(secret,safe="-")+"@"+DOMAIN+":443?"+query+"#"+label
    if protocol=="hysteria":
        query=urlencode({"sni":DOMAIN,"alpn":"h3"})
        return "hysteria2://"+quote(secret,safe="-")+"@"+DOMAIN+":"+str(HYSTERIA_PORT)+"/?"+query+"#"+label
    if protocol in awg.PROTOCOLS:
        user=next((u for u in users() if u.get("protocol")==protocol and secrets.compare_digest(str(u.get("secret","")),str(secret))),None)
        if user is None: raise RuntimeError("Профиль AWG не найден")
        return awg.client_config(user,DOMAIN,name)
    raise RuntimeError("Неизвестный протокол")
def qr_png_bytes(link):
    return subprocess.run([QR,"-o","-","-t","PNG","-s","6","-m","2",link],
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout
def layout(title,body,active=""):
    return page_layout(title,body,PANEL_PATH,active,DOMAIN)

class Handler(BaseHTTPRequestHandler):
    timeout=20
    def log_message(self,*a): pass
    def send_html(self,s,code=200):
        b=s.encode(); self.send_response(code); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.send_header("Cache-Control","no-store"); self.send_header("X-Frame-Options","DENY"); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Referrer-Policy","no-referrer")
        # srcdoc is inline content. Deny network frame navigations as well as
        # requests from within the sandbox, including location/meta refresh.
        self.send_header("Content-Security-Policy","default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.end_headers(); self.wfile.write(b)
    def send_data(self,body,code=200,mime="text/plain; charset=utf-8",headers=None):
        raw=body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type",mime)
        self.send_header("Content-Length",str(len(raw)))
        self.send_header("Cache-Control","no-store, private")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Referrer-Policy","no-referrer")
        for key,value in (headers or {}).items(): self.send_header(key,str(value))
        self.end_headers()
        self.wfile.write(raw)
    def send_json(self,value,code=200):
        self.send_data(json.dumps(value,ensure_ascii=True),code,"application/json")
    def send_png(self,b):
        self.send_response(200); self.send_header("Content-Type","image/png"); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def send_logo(self,b):
        self.send_response(200); self.send_header("Content-Type","image/png"); self.send_header("Cache-Control","public, max-age=86400"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def send_svg(self,b):
        self.send_response(200); self.send_header("Content-Type","image/svg+xml"); self.send_header("Cache-Control","public, max-age=604800, immutable"); self.send_header("Content-Length",str(len(b))); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(b)
    def redirect(self,p):
        self.send_response(303); self.send_header("Location",PANEL_PATH+p if p.startswith("/") else p); self.end_headers()
    def form(self,max_bytes=MAX_HTML_BYTES*3+8192):
        try: n=int(self.headers.get("Content-Length","0"))
        except ValueError: n=0
        if n < 0 or n > max_bytes: raise ValueError("Invalid form size")
        return {k:v[-1] for k,v in parse_qs(self.rfile.read(n).decode("utf-8"),max_num_fields=32).items()}
    def auth(self):
        c=cookies.SimpleCookie(self.headers.get("Cookie","")); v=c.get("sid")
        if not v:return False
        try:
            x,_=v.value.rsplit(".",1)
            issued=int(x.split("-",1)[0])
            return secrets.compare_digest(sign(x),v.value) and 0 <= time.time()-issued < 86400
        except Exception:
            return False
    def session_cookie(self,value,max_age):
        # Caddy supplies this header for public requests.  Keeping Secure for
        # HTTPS prevents accidental exposure, while loopback diagnostics still
        # receive a usable cookie.
        secure="; Secure" if self.headers.get("X-Forwarded-Proto","").lower()=="https" else ""
        return f"sid={value}; Path={PANEL_PATH}; Max-Age={max_age}; HttpOnly{secure}; SameSite=Lax"
    def csrf(self):
        c=cookies.SimpleCookie(self.headers.get("Cookie","")); v=c.get("sid")
        if not v: return ""
        return hmac.new(SESSION_KEY,b"csrf:"+v.value.encode(),hashlib.sha256).hexdigest()
    def valid_csrf(self,form):
        return secrets.compare_digest(form.get("csrf",""),self.csrf())
    def api_auth(self):
        if node_api.bearer_valid(self.headers.get("Authorization",""),API_KEY): return True
        self.send_response(401); self.send_header("WWW-Authenticate",'Bearer realm="WPP API"')
        self.send_header("Content-Type","application/json"); body=b'{"ok":false,"message":"Unauthorized"}'
        self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(body)
        return False
    def json_request(self,maximum=65536):
        try: length=int(self.headers.get("Content-Length","0"))
        except ValueError: raise ValueError("Invalid content length")
        if length<2 or length>maximum: raise ValueError("Invalid JSON size")
        value=json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value,dict): raise ValueError("JSON object required")
        return value
    def do_GET(self):
        path=urlparse(self.path).path
        if path.startswith(node_api.API_PREFIX+"/"):
            if not self.api_auth(): return
            if path==node_api.API_PREFIX+"/status":
                loc=node_api.load_location(LOCATION_FILE)
                self.send_json({"ok":True,"api_version":1,"version":"2.4.2","domain":DOMAIN,
                    "location":loc,"capabilities":["vless","hysteria","awg20","awg31","federation"]}); return
            if path==node_api.API_PREFIX+"/profiles":
                result=[]
                for user in users():
                    if user.get("subscription_id"): continue
                    result.append({"id":user["id"],"name":user["name"],"protocol":user["protocol"],
                        "enabled":user.get("enabled",True),"link":proxy_link(user["protocol"],user["secret"],user.get("backend_port",443),user["name"],user.get("username",""))})
                self.send_json({"ok":True,"profiles":result}); return
            self.send_json({"ok":False,"message":"Not found"},404); return
        if path.startswith(SUB_PREFIX):
            self.serve_subscription(path[len(SUB_PREFIX):]); return
        d=load()
        if path==PANEL_PATH+"/__health":
            self.send_response(200)
            self.send_header("Content-Type","text/plain; charset=utf-8")
            self.send_header("Cache-Control","no-store")
            body=b"OK"
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path==PANEL_PATH+"/__logo":
            try:
                with open(LOGO,"rb") as f: logo=f.read()
                self.send_logo(logo)
            except OSError:
                self.send_html("Logo not found",404)
            return

        flag_match=re.fullmatch(re.escape(PANEL_PATH)+r"/__flag/([a-z]{2})\.svg",path)
        if flag_match:
            flag_path=os.path.join(FLAGS,flag_match.group(1)+".svg")
            if not os.path.isfile(flag_path): flag_path=os.path.join(FLAGS,"un.svg")
            try:
                with open(flag_path,"rb") as stream: flag_data=stream.read(131073)
                if len(flag_data)>131072: raise OSError("flag is too large")
                self.send_svg(flag_data)
            except OSError:
                self.send_html("Flag not found",404)
            return

        if path==PANEL_PATH+"/login":
            self.send_html(login_ui(PANEL_PATH)); return
        if path==PANEL_PATH+"/logout":
            self.send_response(303); self.send_header("Set-Cookie",self.session_cookie("",0)); self.send_header("Location",PANEL_PATH+"/login"); self.end_headers(); return
        if not self.auth():
            self.redirect("/login"); return

        if path==PANEL_PATH or path==PANEL_PATH+"/":
            self.redirect("/dashboard"); return

        if path in (PANEL_PATH+"/dashboard",PANEL_PATH+"/dashboard-data"):
            try: hours=int(parse_qs(urlparse(self.path).query).get("hours",["1"])[0])
            except ValueError: hours=1
            if hours not in (1,6,24): hours=1
            profiles=[{"id":"primary","name":"Основной WEB Proxy","secret":primary(),"protocol":"web","enabled":True,"backend_port":443}]+users()
            body=dashboard_body(server_metrics.dashboard_data(hours),subscription_registry(),profiles,traffic(),
                                PANEL_PATH,DOMAIN,self.csrf(),proxy_link,web_updates.current_version(),hours)
            if path.endswith("/dashboard-data"):
                self.send_json({"html":body,"update":web_updates.get_status()})
            else:
                self.send_html(layout("Дашборд",dashboard_page(body,PANEL_PATH,self.csrf()),"dashboard"))
            return

        if path==PANEL_PATH+'/clients-state':
            profiles=[{'id':'primary','name':'Основной WEB Proxy','secret':primary(),'protocol':'web','enabled':True,'backend_port':443}]+users()
            records=client_records(subscription_registry(),profiles,traffic(),DOMAIN,proxy_link)
            clients=[{'id':r['id'],'name':r['name'],'kind':r['kind'],'enabled':r['enabled'],
                'protocols':r['protocols'],'devices':r['devices'],'limit':r['limit'],**r['totals']} for r in records]
            clients.extend({'id':'openflux-'+p['id'],'name':p.get('name','OpenFlux'),'kind':'openflux',
                'enabled':bool(p.get('enabled',True)),'protocols':['openflux'],'devices':0,'limit':0,
                'up':0,'down':0,'active':bool(p.get('active',False))} for p in openflux.profile_states())
            self.send_json({'clients':clients})
            return

        if path==PANEL_PATH+"/users":
            profiles=[{"id":"primary","name":"Основной WEB Proxy","secret":primary(),"protocol":"web","enabled":True,"backend_port":443}]+users()
            body=users_ui(subscription_registry(),profiles,traffic(),PANEL_PATH,DOMAIN,self.csrf(),proxy_link,openflux.profile_states())
            self.send_html(layout("Клиенты",body,"users")); return
        if path==PANEL_PATH+"/nodes":
            body=nodes_ui([node_api.public_node(n) for n in node_api.load_nodes(NODES_FILE)],
                          node_api.load_location(LOCATION_FILE),node_api.make_connection_token(DOMAIN,API_KEY),PANEL_PATH,self.csrf())
            self.send_html(layout("Ноды",body,"nodes")); return
        if path==PANEL_PATH+"/updates":
            self.send_html(layout("Обновления",updates_ui(PANEL_PATH,self.csrf(),web_updates.current_version()),"updates")); return
        if path==PANEL_PATH+"/subscriptions":
            self.redirect("/users"); return
        if path==PANEL_PATH+"/update-status":
            self.send_json(web_updates.get_status()); return
        if path==PANEL_PATH+"/component-status":
            self.send_json(components.status()); return
        if path==PANEL_PATH+"/openflux-qr":
            profile_id=parse_qs(urlparse(self.path).query).get("id",[""])[0]
            profile=next((item for item in openflux.profile_states() if item.get("id")==profile_id),None)
            if profile is None: self.send_html("Not found",404); return
            try: self.send_png(qr_png_bytes(str(profile.get("url") or "")))
            except (OSError,subprocess.SubprocessError):
                self.send_json({'message':'Не удалось сформировать QR OpenFlux. Проверьте qrencode на сервере.'},503)
            return
        if path==PANEL_PATH+"/subscription-qr":
            sid=parse_qs(urlparse(self.path).query).get("id",[""])[0]
            sub=next((s for s in subscription_registry() if s["id"]==sid),None)
            if sub is None: self.send_html("Not found",404); return
            try: self.send_png(qr_png_bytes("https://"+DOMAIN+SUB_PREFIX+sub["token"]))
            except (OSError,subprocess.SubprocessError): self.send_json({'message':'Не удалось сформировать QR. Проверьте qrencode на сервере.'},503)
            return

        if path==PANEL_PATH+"/__qr":
            query=parse_qs(urlparse(self.path).query)
            q=query.get("secret",[""])[0]; protocol=query.get("protocol",["web"])[0]
            port=query.get("port",["443"])[0]
            uid=query.get("id",[""])[0]
            current_users=users()
            matching=(next((x for x in current_users if x.get("id")==uid and x.get("protocol") in awg.PROTOCOLS),None)
                      if uid else next((x for x in current_users if x.get("secret")==q or
                          (x.get("protocol")=="mtproto" and q in x.get("device_secrets",[]))),None))
            if uid and matching:
                q=matching.get("secret",""); protocol=matching.get("protocol",""); port=str(matching.get("backend_port",0))
            if q==primary(): matching={"protocol":"web","backend_port":443,"name":"Основной WEB Proxy"}
            if not matching or protocol!=matching.get("protocol","web"):
                self.send_html("Not found",404); return
            try:
                expected=str(int(matching.get("backend_port",443)))
                if protocol in ("mtproto","hysteria","awg20","awg31") and port!=expected:
                    self.send_html("Not found",404); return
                if protocol in ("web","vless") and port!="443":
                    self.send_html("Not found",404); return
                self.send_png(qr_png_bytes(proxy_link(protocol,q,expected,matching.get("name","Proxy"),matching.get("username",""))))
            except Exception:self.send_json({'message':'Не удалось сформировать QR. Проверьте qrencode на сервере.'},503)
            return

        if path==PANEL_PATH+"/awg-config":
            uid=parse_qs(urlparse(self.path).query).get("id",[""])[0]
            user=next((u for u in users() if u.get("id")==uid and u.get("protocol") in awg.PROTOCOLS),None)
            if user is None: self.send_html("Not found",404); return
            try:
                config=awg.client_config(user,DOMAIN,user.get("name","AWG"))
                self.send_data(config,mime="text/plain; charset=utf-8",
                    headers={"Content-Disposition":"attachment; filename=\"wpp-%s.conf\""%uid})
            except Exception:
                self.send_html("Не удалось сформировать конфигурацию AWG.",503)
            return


        if path==PANEL_PATH+"/settings":
            token=esc(self.csrf())
            has_draft=os.path.exists(SITE_DRAFT)
            try:
                if has_draft:
                    with open(SITE_DRAFT,encoding="utf-8") as f: site_html=f.read()
                else: site_html=read_site_html()
            except Exception: site_html="<!-- Не удалось прочитать исходник -->"
            editor=editor_ui(site_html,PANEL_PATH,self.csrf(),all_presets(),has_draft)
            body=f'''<div class="page-head"><div><span class="eyebrow">WPP / STUDIO</span><h1>Настройки</h1><p>Оформление сайта и доступ к панели</p></div></div>
{editor}
<div class=card><h2>Пароль администратора</h2><form method=post action="{PANEL_PATH}/password"><input type=hidden name=csrf value="{token}"><label for="adminNewPassword">Новый пароль</label><input id="adminNewPassword" type=password name=a minlength=3 required autocomplete=new-password><div class="actions" style="margin-top:16px"><button class="btn primary">Сохранить пароль</button><small>Минимум 3 символа · смена пароля завершит все сессии панели</small></div></form></div>'''
            self.send_html(layout("Настройки",body,"settings")); return

        self.redirect("/")

    def do_POST(self):
        path=urlparse(self.path).path

        if path.startswith(node_api.API_PREFIX+"/"):
            if not self.api_auth(): return
            try:
                request=self.json_request()
                if path==node_api.API_PREFIX+"/federation/sync":
                    result=ctl_manager_json("federation-sync",request)
                    profiles=[{"id":u["id"],"protocol":u["protocol"],
                        "link":proxy_link(u["protocol"],u["secret"],u.get("backend_port",443),u.get("name",request.get("name","")),u.get("username",""))}
                        for u in result.get("profiles",[])]
                    self.send_json({"ok":True,"profiles":profiles}); return
                if path==node_api.API_PREFIX+"/federation/delete":
                    result=ctl_manager_json("federation-delete",request)
                    self.send_json({"ok":True,"deleted":bool(result.get("deleted"))}); return
                if path==node_api.API_PREFIX+"/federation/purge":
                    result=ctl_manager_json("federation-purge",{})
                    self.send_json({"ok":True,"deleted":int(result.get("deleted",0))}); return
                if path==node_api.API_PREFIX+"/profiles/create":
                    protocol=str(request.get("protocol","")); name=str(request.get("name","")).strip()
                    if protocol not in ("web","mtproto","vless","hysteria","awg20","awg31") or not name or len(name)>80:
                        self.send_json({"ok":False,"message":"Invalid profile"},400); return
                    user=(ctl_manager_json("add-json",{"protocol":protocol,"name":name,
                        "port":request.get("port"),"devices":request.get("devices",1)})
                        if protocol=="mtproto" else ctl("add",protocol,name))
                    self.send_json({"ok":True,"profile":{"id":user["id"],"name":user["name"],"protocol":protocol,
                        "link":proxy_link(protocol,user["secret"],user.get("backend_port",443),name,user.get("username",""))}},201); return
                if path==node_api.API_PREFIX+"/profiles/delete":
                    uid=str(request.get("id",""))
                    if not re.fullmatch(r"[a-f0-9]{16}",uid): self.send_json({"ok":False,"message":"Invalid profile id"},400); return
                    ctl("delete",uid); self.send_json({"ok":True}); return
                self.send_json({"ok":False,"message":"Not found"},404)
            except (ValueError,json.JSONDecodeError) as exc: self.send_json({"ok":False,"message":str(exc)},400)
            except Exception as exc:
                print("API request failed:",type(exc).__name__,file=sys.stderr,flush=True)
                self.send_json({"ok":False,"message":"Node operation failed"},503)
            return

        # Login does not require an authenticated session.
        if path==PANEL_PATH+"/login":
            client=client_id(self)
            if login_blocked(client):
                body="Слишком много попыток входа. Повторите позже.".encode("utf-8")
                self.send_response(429)
                self.send_header("Retry-After",str(LOGIN_WINDOW))
                self.send_header("Content-Type","text/html; charset=utf-8")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers(); self.wfile.write(body)
                return
            try: form=self.form(8192)
            except (ValueError,UnicodeDecodeError):
                self.send_html("Некорректный запрос.",400); return
            d=load()
            username=form.get("user","")
            password=form.get("password","")
            if username==d.get("admin",{}).get("user","admin") and check_password(password,d.get("admin",{}).get("hash","")):
                # A cookie-safe token: the old ':' separator was accepted by
                # most browsers but is rejected/rewritten by some proxies.
                token=str(int(time.time()))+"-"+secrets.token_hex(16)
                sid=sign(token)
                login_succeeded(client)
                self.send_response(303)
                self.send_header("Set-Cookie",self.session_cookie(sid,86400))
                self.send_header("Location",PANEL_PATH+"/dashboard")
                self.end_headers()
            else:
                login_failed(client)
                self.send_html("""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#060910;color:#fff;font:15px system-ui}.b{width:min(420px,90vw);padding:28px;border:1px solid #223148;border-radius:22px;background:#0d1520}a{color:#8edcff}</style>
<div class=b><h2>Неверный логин или пароль</h2><p>Попробуйте войти ещё раз.</p><a href="%s/login">Вернуться</a></div>""" % esc(PANEL_PATH),401)
            return

        # Everything below requires an authenticated session.
        if not self.auth():
            self.redirect("/login")
            return

        try: form=self.form()
        except (ValueError,UnicodeDecodeError) as e:
            self.send_html(esc(e),400); return
        d=load()

        if not self.valid_csrf(form):
            self.send_html("Недействительный запрос. Обновите страницу и попробуйте снова.",403)
            return

        if path in (PANEL_PATH+"/update-check",PANEL_PATH+"/update-start"):
            try:
                result=web_updates.start_update(form.get("target","")) if path.endswith("/update-start") else web_updates.check_release()
                self.send_json(result)
            except ValueError as exc: self.send_json({"message":str(exc)},400)
            except (OSError,subprocess.TimeoutExpired): self.send_json({"message":"Служба обновления недоступна. Проверьте VPS через SSH."},503)
            return

        if path in (PANEL_PATH+"/component-check",PANEL_PATH+"/component-install"):
            try:
                result=(components.start(form.get("component",""),form.get("target",""))
                        if path.endswith("/component-install") else components.catalog(force=True))
                self.send_json(result)
            except ValueError as exc:
                self.send_json({"message":str(exc)},400)
            except (OSError,subprocess.TimeoutExpired):
                self.send_json({"message":"Не удалось связаться с GitHub или службой обновления."},503)
            return

        if path==PANEL_PATH+"/node-action":
            try:
                operation=form.get("operation","")
                if operation=="add":
                    bundled=node_api.parse_connection_token(form.get("connection_token",""))
                    candidate=bundled["url"]
                    if urlparse(candidate).hostname==DOMAIN:
                        raise node_api.NodeError("Нельзя добавить эту же панель как удалённую ноду.")
                    node_api.add_node(NODES_FILE,form)
                elif operation=="delete":
                    nodes=node_api.load_nodes(NODES_FILE); uid=form.get("id","")
                    selected=next((n for n in nodes if n.get("id")==uid),None)
                    if selected is None: raise node_api.NodeError("Нода не найдена.")
                    # Revoke remotely before forgetting the only credential that
                    # can remove controller-created profiles from this node.
                    node_api.purge_profiles(selected)
                    node_api.save_nodes(NODES_FILE,[n for n in nodes if n.get("id")!=uid])
                elif operation=="location":
                    node_api.save_location(LOCATION_FILE,form)
                else: raise node_api.NodeError("Неизвестная операция с нодой.")
                self.redirect("/nodes")
            except node_api.NodeError as exc:
                self.send_html(esc(str(exc)),400)
            return

        if path==PANEL_PATH+"/create-account":
            async_create=self.headers.get("X-WPP-Async","")=="1"
            def create_error(message,status=400):
                if async_create: self.send_json({"ok":False,"message":str(message)},status)
                else: self.send_html(esc(str(message)),status)
            name=form.get("name","").strip()
            kind=form.get("kind","")
            if not name or len(name)>80 or any(ord(c)<32 for c in name):
                create_error("Укажите имя длиной от 1 до 80 символов."); return
            if kind=="subscription":
                result=ctl_subscription({"operation":"create","name":name,"max_devices":form.get("max_devices","2"),
                                         "protocols":[p for p in ("vless","hysteria") if form.get(p)=="1"]})
                if not result.get("ok"):
                    create_error(result.get("message","Ошибка создания подписки"),int(result.get("status",400))); return
            elif kind in ("web","mtproto","vless","hysteria","awg20","awg31"):
                try:
                    if kind=="mtproto":
                        ctl_manager_json("add-json",{"protocol":kind,"name":name,
                            "port":form.get("mtproto_port",""),"devices":form.get("mtproto_devices","1")})
                    else: ctl("add",kind,name)
                except ValueError as exc:
                    create_error(str(exc)); return
                except Exception as exc:
                    print("create connection failed:",type(exc).__name__,file=sys.stderr,flush=True)
                    create_error("Не удалось создать подключение. Проверьте службы через SSH и повторите попытку.",503); return
            else:
                create_error("Неизвестный тип доступа"); return
            if async_create: self.send_json({"ok":True})
            else: self.redirect("/users")
            return

        if path==PANEL_PATH+"/openflux":
            operation=form.get("operation","")
            try:
                if operation=="save":
                    openflux.configure(form.get("url",""),form.get("ios_compatible","")=="1")
                elif operation=="enable": openflux.set_enabled(True)
                elif operation=="disable": openflux.set_enabled(False)
                elif operation=="rotate": openflux.rotate_key()
                else: raise openflux.OpenFluxError("Неизвестная операция OpenFlux.")
                self.redirect("/settings")
            except openflux.OpenFluxError as exc:
                self.send_html("Ошибка OpenFlux: "+esc(str(exc)),400)
            return

        if path==PANEL_PATH+"/openflux-profile":
            async_action=self.headers.get("X-WPP-Async","")=="1"
            operation=form.get("operation","")
            try:
                if operation=="create":
                    openflux.create_profile(form.get("name",""),form.get("url",""),form.get("platform",""),form.get("transport","yandex"))
                elif operation=="enable": openflux.profile_set_enabled(form.get("id",""),True)
                elif operation=="disable": openflux.profile_set_enabled(form.get("id",""),False)
                elif operation=="rotate": openflux.profile_rotate(form.get("id",""))
                elif operation=="delete": openflux.delete_profile(form.get("id",""))
                else: raise openflux.OpenFluxError("Неизвестная операция OpenFlux.")
                if async_action: self.send_json({"ok":True})
                else: self.redirect("/users")
            except openflux.OpenFluxError as exc:
                if async_action: self.send_json({"ok":False,"message":str(exc)},400)
                else: self.send_html("Ошибка OpenFlux: "+esc(str(exc)),400)
            return

        if path==PANEL_PATH+"/client-action":
            uid=form.get('id',''); kind=form.get('kind',''); operation=form.get('operation','')
            if uid!='primary' and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',uid):
                self.send_json({'message':'Подключение не найдено.'},400); return
            if uid=='primary' and operation!='secret':
                self.send_json({'message':'У основного подключения можно изменить только секрет.'},400); return
            if operation=='state' and form.get('enabled') not in ('0','1'):
                self.send_json({'message':'Некорректное состояние доступа.'},400); return
            if kind not in ('subscription','direct') or operation not in ('state','rename','secret'):
                self.send_json({'message':'Недопустимая операция.'},400); return
            if operation=='secret' and (kind!='direct' or not re.fullmatch(r'(?:dd)?[0-9A-Fa-f]{32}',form.get('secret','').strip())):
                self.send_json({'message':'Секрет должен содержать 32 символа 0–9, a–f; префикс dd допускается.'},400); return
            if operation=='rename' and (not form.get('name','').strip() or len(form['name'].strip())>80 or any(ord(c)<32 for c in form['name'])):
                self.send_json({'message':'Имя должно содержать от 1 до 80 символов без управляющих знаков.'},400); return
            try:
                if kind=='subscription':
                    previous=next((s for s in subscription_registry() if s.get('id')==uid),None)
                    request={'id':uid,'operation':'set-enabled' if operation=='state' else 'update'}
                    if operation=='state': request['enabled']=form['enabled']=='1'
                    else: request['name']=form.get('name','')
                    result=ctl_subscription(request)
                    if not result.get('ok'):
                        self.send_json({'message':result.get('message','Изменение не применено.')},int(result.get('status',400))); return
                    if operation=='rename' or (operation=='state' and form['enabled']=='0'):
                        purge_remote_profiles_async(previous)
                else:
                    if operation=='state': ctl('set-user',uid,form['enabled'])
                    elif operation=='rename': ctl('rename-user',uid,form.get('name',''))
                    else: ctl_manager_json('set-secret',{'id':uid,'secret':form.get('secret','')})
                self.send_json({'ok':True})
            except Exception:
                self.send_json({'message':'Изменение не применено. Проверьте службы через SSH и обновите список.'},503)
            return

        if path==PANEL_PATH+"/subscription-action":
            async_action=self.headers.get("X-WPP-Async","")=="1"
            request={k:form[k] for k in ("operation","id","device_id","name","max_devices") if k in form}
            if request.get("operation") not in ("create","update","toggle","rotate","delete","revoke","allow"):
                self.send_html("Недопустимая операция",400); return
            if request["operation"] in ("create","update"):
                request["protocols"]=[p for p in ("vless","hysteria") if form.get(p)=="1"]
            previous=next((s for s in subscription_registry() if s.get("id")==request.get("id")),None)
            result=ctl_subscription(request)
            if result.get("ok"):
                if request["operation"] in ("update","delete","rotate","toggle"):
                    purge_remote_profiles_async(previous)
                elif request["operation"]=="revoke":
                    purge_remote_profiles_async(previous,request.get("device_id"))
                if async_action: self.send_json({"ok":True})
                else: self.redirect("/users")
            elif async_action: self.send_json({"ok":False,"message":result.get("message","Ошибка подписки")},int(result.get("status",400)))
            else: self.send_html(esc(result.get("message","Ошибка подписки")),int(result.get("status",400)))
            return

        if path==PANEL_PATH+"/custom-preset":
            try:
                operation=form.get("operation","")
                items=custom_presets()
                if operation=="create":
                    name=form.get("name","").strip()
                    description=form.get("description","").strip() or "Пользовательская заглушка"
                    if not 1<=len(name)<=80: raise ValueError("Название должно содержать от 1 до 80 символов.")
                    if len(description)>180: raise ValueError("Описание не должно превышать 180 символов.")
                    if len(items)>=20: raise ValueError("Можно сохранить не более 20 своих заглушек.")
                    source=validate_html(form.get("html",""))
                    items.append({"id":"custom-"+secrets.token_hex(8),"name":name,
                                  "description":description,"html":source,"custom":True})
                    save_custom_presets(items)
                elif operation=="delete":
                    preset_id=form.get("preset","")
                    if not preset_id.startswith("custom-"): raise ValueError("Встроенный пресет удалить нельзя.")
                    retained=[item for item in items if item.get("id")!=preset_id]
                    if len(retained)==len(items): raise ValueError("Заглушка не найдена.")
                    save_custom_presets(retained)
                else:
                    raise ValueError("Неизвестная операция.")
                self.redirect("/settings")
            except ValueError as exc:
                self.send_html("Ошибка сохранения заглушки: "+esc(exc),400)
            except OSError as exc:
                print("custom preset failed:",type(exc).__name__,file=sys.stderr,flush=True)
                self.send_html("Не удалось сохранить заглушку на сервере.",503)
            return

        if path in (PANEL_PATH+"/preview-html",PANEL_PATH+"/save-draft",PANEL_PATH+"/draft-preset",PANEL_PATH+"/discard-draft"):
            try:
                if path.endswith("/discard-draft"):
                    with STATE_LOCK:
                        if os.path.exists(SITE_DRAFT): os.unlink(SITE_DRAFT)
                else:
                    source=validate_html(get_preset(form.get("preset",""))["html"] if path.endswith("/draft-preset") else form.get("html",""))
                    if path.endswith("/preview-html"):
                        self.send_json({"document":preview_document(source,externalize_inline_assets)}); return
                    with STATE_LOCK: install_private_file(SITE_DRAFT,source.encode("utf-8"))
                self.redirect("/settings")
            except ValueError as exc:
                self.send_json({"message":str(exc)},400)
            except (RuntimeError,OSError) as exc:
                print("landing draft failed:",type(exc).__name__,file=sys.stderr,flush=True)
                self.send_json({"message":"Не удалось обработать черновик. Проверьте службы через SSH."},503)
            return

        if path==PANEL_PATH+"/add-user":
            name=form.get("name","").strip()
            protocol=form.get("protocol","web").strip().lower()
            if not name or len(name)>80:
                self.send_html("Имя пользователя обязательно.",400); return
            if protocol not in ("web","mtproto","vless","hysteria","awg20","awg31"):
                self.send_html("Неизвестный протокол подключения.",400); return
            try:
                result=ctl("add",protocol,name)
                self.redirect("/users")
            except Exception as exc:
                print("create user failed:",type(exc).__name__,file=sys.stderr,flush=True)
                self.send_html("Не удалось создать пользователя. Проверьте службы через SSH и повторите попытку.",503)
            return

        if path==PANEL_PATH+"/delete-user":
            async_action=self.headers.get("X-WPP-Async","")=="1"
            uid=form.get("id","")
            if not uid or uid=="primary":
                if async_action: self.send_json({"ok":False,"message":"Нельзя удалить основной профиль."},400)
                else: self.send_html("Нельзя удалить основной профиль.",400)
                return
            try:
                ctl("delete",uid)
                if async_action: self.send_json({"ok":True})
                else: self.redirect("/users")
            except Exception as exc:
                print("delete user failed:",type(exc).__name__,file=sys.stderr,flush=True)
                if async_action: self.send_json({"ok":False,"message":"Не удалось удалить пользователя. Обновите список и повторите попытку."},503)
                else: self.send_html("Не удалось удалить пользователя. Обновите список и повторите попытку.",503)
            return

        if path==PANEL_PATH+"/site-html":
            try:
                with STATE_LOCK:
                    source=validate_html(form.get("html",""))
                    install_private_file(SITE_DRAFT,source.encode("utf-8"))
                    write_site_html(source)
                    if os.path.exists(SITE_DRAFT): os.unlink(SITE_DRAFT)
                self.redirect("/settings")
            except ValueError as exc:
                self.send_html("Ошибка сохранения HTML: "+esc(exc),400)
            except (RuntimeError,OSError) as exc:
                print("landing publish failed:",type(exc).__name__,file=sys.stderr,flush=True)
                self.send_html("Не удалось опубликовать HTML. Предыдущая страница сохранена; проверьте службы через SSH.",503)
            return

        if path==PANEL_PATH+"/apply-preset":
            try:
                preset=get_preset(form.get("preset",""))
                # Applying a bundled preset is an explicit publish operation.
                # Remove a stale custom draft so it cannot overwrite the
                # selected preset on the next save.
                with STATE_LOCK:
                    write_site_html(preset["html"])
                    if os.path.exists(SITE_DRAFT): os.unlink(SITE_DRAFT)
                self.redirect("/settings")
            except ValueError as exc:
                self.send_html("Ошибка применения пресета: "+esc(exc),400)
            except (RuntimeError,OSError) as exc:
                print("landing preset failed:",type(exc).__name__,file=sys.stderr,flush=True)
                self.send_html("Не удалось применить пресет. Предыдущая страница сохранена; проверьте службы через SSH.",503)
            return

        if path==PANEL_PATH+"/password":
            a=form.get("a","")
            if len(a)<3:
                self.send_html("Пароль должен содержать минимум 3 символа.",400)
                return
            d["admin"]["hash"]=hash_password(a)
            save(d)
            rotate_session_key()
            self.send_response(303)
            self.send_header("Set-Cookie",self.session_cookie("",0))
            self.send_header("Location",PANEL_PATH+"/login")
            self.end_headers()
            return

        self.send_html("Not found",404)

    def serve_subscription(self,token):
        if not re.fullmatch(r"[a-f0-9]{64}",token):
            self.send_data("Not found",404); return
        if not allow_subscription_request(client_id(self)):
            self.send_data("Слишком много запросов. Повторите через минуту.",429,headers={"Retry-After":"60"}); return
        if not SUB_FETCH_SLOTS.acquire(blocking=False):
            self.send_data("Сервис занят. Повторите позже.",503,headers={"Retry-After":"15"}); return
        try:
            # Reject unknown URLs before spawning any privileged helper.
            if not any(s.get("enabled") and secrets.compare_digest(s["token"],token) for s in subscription_registry()):
                self.send_data("Not found",404); return
            if "text/html" in self.headers.get("Accept",""):
                self.send_data("Добавьте эту ссылку как подписку в клиент. Для ограниченной подписки нужен X-HWID (Happ).",200); return
            result=ctl_subscription({"operation":"fetch","token":token,"hwid":self.headers.get("X-HWID","")})
            if not result.get("ok"):
                headers={"X-Hwid-Active":"true","subscription-always-hwid-enable":"true"}
                if result.get("code")=="hwid_required": headers["X-Hwid-Not-Supported"]="true"
                if result.get("code")=="device_limit": headers.update({"X-Hwid-Limit":"true","X-Hwid-Max-Devices-Reached":"true"})
                self.send_data(result.get("message","Подписка недоступна"),int(result.get("status",503)),headers=headers); return
            labels={"vless":"VLESS","hysteria":"Hysteria2"}
            local_name=node_api.location_prefix(node_api.load_location(LOCATION_FILE))
            lines=[proxy_link(u["protocol"],u["secret"],u["backend_port"],local_name+" · "+labels[u["protocol"]],u.get("username","")) for u in result["users"]]
            if result["users"]:
                first=result["users"][0]
                remote_id=federation_id(first.get("subscription_id",""),first.get("device_id",""))
                wanted=[u["protocol"] for u in result["users"] if u["protocol"] in ("vless","hysteria")]
                for node in node_api.load_nodes(NODES_FILE):
                    if not node.get("enabled",True): continue
                    try:
                        remote=node_api.sync_profile(node,remote_id,node_api.location_prefix(node),wanted)
                        lines.extend(p["link"] for p in remote.get("profiles",[]) if isinstance(p,dict) and isinstance(p.get("link"),str))
                    except node_api.NodeError as exc:
                        print("node subscription sync failed:",node.get("url"),str(exc),file=sys.stderr,flush=True)
            state=traffic()
            up=sum(int(state.get(u["id"],{}).get("up",0)) for u in result["users"])
            down=sum(int(state.get(u["id"],{}).get("down",0)) for u in result["users"])
            headers={"profile-title":"base64:"+base64.b64encode(result["name"].encode()).decode(),"profile-update-interval":"6",
                     "subscription-userinfo":f"upload={up}; download={down}; total=0; expire=0"}
            if result["limited"]: headers.update({"X-Hwid-Active":"true","subscription-always-hwid-enable":"true"})
            self.send_data(base64.b64encode(("\n".join(lines)+"\n").encode()).decode(),headers=headers)
        except Exception:
            self.send_data("Подписка временно недоступна.",503)
        finally:
            SUB_FETCH_SLOTS.release()

def main():
    try:
        import json as _json
        _state_file = _Path("/var/lib/xray-installer/wpp_panel_state.json")
        if _state_file.exists():
            _st = _json.loads(_state_file.read_text())
            if _st.get("web_port"):
                PORT = int(_st["web_port"])
    except Exception:
        pass
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()

if __name__=="__main__":
    if len(sys.argv)==2 and sys.argv[1]=="--repair-site":
        write_site_html(read_site_html())
        print("Public landing page assets repaired.")
    else:
        main()


# ─── Chimera systemd entry point ─────────────────────────────────────────────
# systemd ExecStart: python3 -c "from chimera.modules.wpp_panel_web import start_server; start_server()"
def start_server():
    """Entry point for systemd ExecStart — calls main()."""
    main()



