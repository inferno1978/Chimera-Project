"""
chimera/modules/nginx_setup_templates.py
───────────────────────────────────────────────────────────────────────────────
15 анимированных многостраничных шаблонов сайтов-заглушек.

Каждый шаблон:
  • Уникальная спокойная палитра (без режущих глаз цветов)
  • Уникальная анимация (CSS keyframes + transitions, без JS-зависимостей)
  • 4-5 реальных страниц с рабочей навигацией между ними
  • Адаптивный layout (CSS Grid / Flexbox)
  • Единый стиль header/footer/nav внутри шаблона

Шаблоны:
  1.  TechHub             — IT-портал (RU)              • slate + indigo       • fade-up reveal
  2.  NexCloud            — Serverless SaaS             • deep slate + sky     • gradient mesh morph
  3.  Holm & Oak          — Homeware store              • cream + sage         • parallax layers
  4.  Ember & Grain       — Wood-fired bistro           • charcoal + amber     • steam rise
  5.  NexHub              — Community + storage         • soft black + cobalt  • card flip
  6.  ByteForge           — Developer forum             • graphite + cyan      • code rain
  7.  Lumen Architects    — Architecture studio         • bone + bronze        • line draw
  8.  Verdant Botanical   — Plant shop                  • linen + forest       • leaf sway
  9.  Northwind Coffee    — Coffee roastery             • beige + espresso     • steam wisps
  10. Solstice Wellness   — Spa & wellness              • sand + dusty rose    • breathing pulse
  11. Atelier Meridian    — Design studio               • ivory + ink + gold   • shape morph
  12. Harborline Logistics— Shipping & freight          • navy + sand          • wave motion
  13. Quietude Library    — Digital library             • parchment + forest   • page flip
  14. Mensara Consulting  — Strategy consulting         • white + navy + gold  • slide reveal
  15. Cascade Analytics   — Data analytics SaaS         • mist + indigo + teal • data flow

Все шаблоны пишутся через единый хелпер _emit_site(web_root, css, pages).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict


# ── Хелпер ───────────────────────────────────────────────────────────────────
def _emit_site(web_root: Path, css: str, pages: Dict[str, str]) -> None:
    """Записывает style.css и все страницы в web_root.

    pages: dict вида { 'index.html': '<!DOCTYPE html>...',
                       'about/index.html': '...' }
    Пути с '/' создают подкаталоги.
    """
    web_root.mkdir(parents=True, exist_ok=True)
    (web_root / "style.css").write_text(css)
    for rel, content in pages.items():
        target = web_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)


def _doc(title: str, body: str, css_href: str = "/style.css") -> str:
    """Обёртка HTML5-документа. Дедуплицирует boilerplate."""
    return (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f'<title>{title}</title>\n'
        f'<link rel="stylesheet" href="{css_href}">\n'
        '</head>\n'
        f'<body>\n{body}\n</body>\n</html>\n'
    )


# =============================================================================
#  ШАБЛОН 1: TechHub — IT-портал (RU) • fade-up reveal + animated underline
# =============================================================================
def create_techhub(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#f4f5f7; --surface:#ffffff; --text:#1e293b; --muted:#64748b;
  --accent:#4f46e5; --accent-soft:#e0e7ff; --border:#e2e8f0;
  --shadow:0 1px 3px rgba(15,23,42,.05),0 4px 14px rgba(15,23,42,.04);
}
body{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(255,255,255,.85);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:1.2rem;font-weight:700;letter-spacing:-.3px}
.logo span{color:var(--accent)}
nav{display:flex;gap:.25rem;flex-wrap:wrap}
nav a{padding:.5rem .85rem;border-radius:6px;font-size:.9rem;color:var(--muted);transition:color .25s,background .25s;position:relative}
nav a::after{content:"";position:absolute;left:.85rem;right:.85rem;bottom:.3rem;height:2px;background:var(--accent);transform:scaleX(0);transform-origin:left;transition:transform .3s ease}
nav a:hover{color:var(--accent)}
nav a:hover::after{transform:scaleX(1)}
nav a.active{color:var(--accent);background:var(--accent-soft)}
.hero{padding:6rem 5% 5rem;max-width:1200px;margin:0 auto;text-align:center}
.hero .eyebrow{display:inline-block;font-size:.8rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);background:var(--accent-soft);padding:.4rem 1rem;border-radius:99px;margin-bottom:1.5rem;opacity:0;animation:fadeUp .8s .05s forwards}
.hero h1{font-size:clamp(2rem,5vw,3.4rem);font-weight:800;letter-spacing:-1px;margin-bottom:1.25rem;opacity:0;animation:fadeUp .8s .15s forwards}
.hero p{font-size:1.1rem;color:var(--muted);max-width:640px;margin:0 auto 2.25rem;opacity:0;animation:fadeUp .8s .25s forwards}
.btn{display:inline-block;padding:.85rem 1.9rem;border-radius:8px;font-weight:600;font-size:.95rem;transition:transform .2s,box-shadow .2s}
.btn-primary{background:var(--accent);color:#fff;box-shadow:0 4px 14px rgba(79,70,229,.25)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 22px rgba(79,70,229,.32)}
.btn-ghost{border:1px solid var(--border);color:var(--text);margin-left:.5rem}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
section{padding:4rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-size:1.75rem;font-weight:700;margin-bottom:2.5rem;letter-spacing:-.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.5rem}
.card{background:var(--surface);padding:1.75rem;border-radius:12px;border:1px solid var(--border);box-shadow:var(--shadow);transition:transform .3s,box-shadow .3s}
.card:hover{transform:translateY(-4px);box-shadow:0 8px 24px rgba(15,23,42,.08)}
.card .icon{width:40px;height:40px;border-radius:10px;background:var(--accent-soft);display:flex;align-items:center;justify-content:center;font-size:1.25rem;margin-bottom:1rem}
.card h3{font-size:1.1rem;margin-bottom:.5rem}
.card p{color:var(--muted);font-size:.92rem}
.tag{display:inline-block;font-size:.75rem;padding:.2rem .65rem;border-radius:4px;background:var(--accent-soft);color:var(--accent);margin-top:.85rem}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem}
footer h4{font-size:.85rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:1rem}
footer a{display:block;color:var(--text);font-size:.9rem;margin-bottom:.5rem;transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2.5rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.reveal{opacity:0;animation:fadeUp .7s forwards}
.reveal.d1{animation-delay:.1s}.reveal.d2{animation-delay:.2s}.reveal.d3{animation-delay:.3s}
.reveal.d4{animation-delay:.4s}.reveal.d5{animation-delay:.5s}.reveal.d6{animation-delay:.6s}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Tech<span>Hub</span></a>'
           '<nav>'
           '<a href="/" class="active">Главная</a>'
           '<a href="/hardware/">Железо</a>'
           '<a href="/software/">Софт</a>'
           '<a href="/network/">Сети</a>'
           '<a href="/contact/">Контакты</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("TechHub — портал о технологиях", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Свежий выпуск · 2026</span>
  <h1>Спокойный взгляд на мир технологий</h1>
  <p>TechHub собирает обзоры, разборы и практические гайды без суеты и кликбейта. Только выверенный материал и аккуратные выводы.</p>
  <a href="/hardware/" class="btn btn-primary">Открыть разделы</a>
  <a href="/contact/" class="btn btn-ghost">Связаться</a>
</div>
<section>
  <h2 class="section-title reveal">Разделы портала</h2>
  <div class="grid">
    <div class="card reveal d1"><div class="icon">◈</div><h3>Железо</h3><p>Обзоры процессоров, видеокарт и накопителей: трезвые тесты без маркетинга.</p><span class="tag">38 статей</span></div>
    <div class="card reveal d2"><div class="icon">▣</div><h3>Софт</h3><p>ОС, утилиты, дистрибутивы Linux и инструменты разработчика.</p><span class="tag">52 статьи</span></div>
    <div class="card reveal d3"><div class="icon">⇄</div><h3>Сети</h3><p>Маршрутизация, BGP, VPN и архитектура распределённых систем.</p><span class="tag">27 статей</span></div>
    <div class="card reveal d4"><div class="icon">⚿</div><h3>Безопасность</h3><p>Архитектура zero-trust, аудит инфраструктуры, печальный опыт инцидентов.</p><span class="tag">19 статей</span></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Tech<span>Hub</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.9rem;max-width:280px">Тихий уголок интернета для тех, кто строит и поддерживает системы.</p></div>
    <div><h4>Разделы</h4><a href="/hardware/">Железо</a><a href="/software/">Софт</a><a href="/network/">Сети</a></div>
    <div><h4>Редакция</h4><a href="/contact/">Контакты</a><a href="/contact/">Реклама</a></div>
    <div><h4>Документы</h4><a href="/contact/">Конфиденциальность</a><a href="/contact/">Условия</a></div>
  </div>
  <div class="foot-bottom">© 2026 TechHub. Все права защищены.</div>
</footer>"""),
        "hardware/index.html": _doc("Железо — TechHub", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Раздел · Железо</span>
  <h1>Тесты и обзоры компонентов</h1>
  <p>Процессоры, видеокарты, память и накопители. Только реальные измерения, никаких маркетинговых частот.</p>
</div>
<section>
  <h2 class="section-title reveal">Свежие обзоры</h2>
  <div class="grid">
    <div class="card reveal d1"><div class="icon">▦</div><h3>Архитектура Zen 5</h3><p>Разбираем ключевые изменения в микроархитектуре и смотрим на реальные задержки.</p><span class="tag">CPU</span></div>
    <div class="card reveal d2"><div class="icon">▤</div><h3>NVMe в 2026</h3><p>Сравниваем потребительские SSD на контроллерах Phison E26 и E28.</p><span class="tag">SSD</span></div>
    <div class="card reveal d3"><div class="icon">▣</div><h3>RDNA 4 в работе</h3><p>Энергопотребление, шум и реальная производительность в рабочих нагрузках.</p><span class="tag">GPU</span></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 TechHub. <a href="/" style="color:var(--accent)">← На главную</a></div></footer>"""),
        "software/index.html": _doc("Софт — TechHub", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Раздел · Софт</span>
  <h1>Операционные системы и инструменты</h1>
  <p>Linux-дистрибутивы, утилиты командной строки и подборки рабочего софта без шума.</p>
</div>
<section>
  <h2 class="section-title reveal">Темы</h2>
  <div class="grid">
    <div class="card reveal d1"><div class="icon">⌘</div><h3>Debian 13</h3><p>Что нового, что сломалось и стоит ли обновлять продакшен прямо сейчас.</p></div>
    <div class="card reveal d2"><div class="icon">⎕</div><h3>Wayland в 2026</h3><p>Подводные камни при переходе с X11, совместимость с драйверами.</p></div>
    <div class="card reveal d3"><div class="icon">⌥</div><h3>Контейнерный стек</h3><p>Podman vs Docker: где каждый из них уместен и где нет.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 TechHub. <a href="/" style="color:var(--accent)">← На главную</a></div></footer>"""),
        "network/index.html": _doc("Сети — TechHub", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Раздел · Сети</span>
  <h1>Архитектура сетей</h1>
  <p>Маршрутизация, туннели, балансировка и проектирование отказоустойчивых систем.</p>
</div>
<section>
  <h2 class="section-title reveal">Материалы</h2>
  <div class="grid">
    <div class="card reveal d1"><div class="icon">⇄</div><h3>BGP в малом ДЦ</h3><p>Два провайдера, одна AS, никакой магии — только выверенные политики.</p></div>
    <div class="card reveal d2"><div class="icon">⌬</div><h3>WireGuard в проде</h3><p>Чего не хватает в документации и какие сценарии ломают стереотипы.</p></div>
    <div class="card reveal d3"><div class="icon">⎈</div><h3>Overlay-сети</h3><p>Когда VXLAN уместен, а когда лучше остаться на bare L3.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 TechHub. <a href="/" style="color:var(--accent)">← На главную</a></div></footer>"""),
        "contact/index.html": _doc("Контакты — TechHub", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Связь с редакцией</span>
  <h1>Напишите нам</h1>
  <p>Письма читаем по будням. По тематическим предложениям — отвечаем в течение пары дней.</p>
</div>
<section>
  <h2 class="section-title reveal">Контакты</h2>
  <div class="grid">
    <div class="card reveal d1"><div class="icon">✉</div><h3>Почта</h3><p>editor@techhub.example</p></div>
    <div class="card reveal d2"><div class="icon">⌖</div><h3>Адрес</h3><p>ул. Тихая, 12, Москва</p></div>
    <div class="card reveal d3"><div class="icon">⌚</div><h3>Часы</h3><p>Пн–Пт, 10:00–18:00 МСК</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 TechHub. <a href="/" style="color:var(--accent)">← На главную</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 2: NexCloud — Serverless SaaS • gradient mesh morph
# =============================================================================
def create_nexcloud(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0b1220;--surface:#111a2e;--surface-2:#16203a;--text:#e6ecf5;--muted:#8b97ab;--accent:#7aa2f7;--accent-2:#9ece6a;--border:#1f2a44}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65;overflow-x:hidden;position:relative;min-height:100vh}
body::before{content:"";position:fixed;inset:0;background:
  radial-gradient(60% 50% at 15% 20%,rgba(122,162,247,.18),transparent 60%),
  radial-gradient(50% 40% at 85% 30%,rgba(158,206,106,.12),transparent 60%),
  radial-gradient(45% 35% at 70% 80%,rgba(187,154,247,.14),transparent 60%);
  filter:blur(40px);animation:mesh 22s ease-in-out infinite alternate;z-index:0;pointer-events:none}
@keyframes mesh{0%{transform:translate3d(0,0,0) scale(1)}50%{transform:translate3d(2%,-2%,0) scale(1.05)}100%{transform:translate3d(-2%,2%,0) scale(.97)}}
header,section,footer{position:relative;z-index:1}
a{color:inherit;text-decoration:none}
header{padding:1.1rem 5%;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);backdrop-filter:blur(12px);background:rgba(11,18,32,.55);position:sticky;top:0;z-index:50}
.logo{font-size:1.25rem;font-weight:800;letter-spacing:-.4px}
.logo span{color:var(--accent)}
nav{display:flex;gap:.35rem;flex-wrap:wrap}
nav a{padding:.45rem .9rem;border-radius:6px;font-size:.88rem;color:var(--muted);transition:color .25s,background .25s}
nav a:hover{color:var(--text);background:var(--surface-2)}
nav a.active{color:var(--text);background:var(--surface-2)}
.btn{display:inline-block;padding:.65rem 1.4rem;border-radius:8px;font-size:.88rem;font-weight:600;transition:transform .2s,box-shadow .2s}
.btn-primary{background:var(--accent);color:#0b1220}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(122,162,247,.3)}
.btn-ghost{border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent)}
.hero{padding:7rem 5% 5rem;max-width:1100px;margin:0 auto;text-align:center}
.hero .eyebrow{display:inline-block;font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);background:rgba(122,162,247,.12);padding:.4rem 1rem;border-radius:99px;margin-bottom:1.5rem}
.hero h1{font-size:clamp(2rem,5vw,3.5rem);font-weight:800;letter-spacing:-1px;margin-bottom:1.25rem;line-height:1.1}
.hero h1 span{background:linear-gradient(120deg,var(--accent),var(--accent-2));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{font-size:1.1rem;color:var(--muted);max-width:620px;margin:0 auto 2rem}
section{padding:4rem 5%;max-width:1100px;margin:0 auto}
.section-title{font-size:1.6rem;font-weight:700;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{color:var(--muted);margin-bottom:2.5rem;font-size:.95rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.25rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:1.75rem;transition:transform .3s,border-color .3s,background .3s}
.card:hover{transform:translateY(-4px);border-color:var(--accent);background:var(--surface-2)}
.card .icon{width:42px;height:42px;border-radius:10px;background:rgba(122,162,247,.12);display:flex;align-items:center;justify-content:center;font-size:1.2rem;color:var(--accent);margin-bottom:1rem}
.card h3{font-size:1.05rem;margin-bottom:.5rem}
.card p{color:var(--muted);font-size:.9rem}
.price-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:2rem;text-align:center;transition:transform .3s,border-color .3s}
.price-card:hover{transform:translateY(-4px);border-color:var(--accent)}
.price-card .price{font-size:2.5rem;font-weight:800;margin:1rem 0 .25rem}
.price-card .price small{font-size:.95rem;color:var(--muted);font-weight:500}
.price-card ul{list-style:none;margin:1.5rem 0;text-align:left}
.price-card li{padding:.5rem 0;border-bottom:1px solid var(--border);color:var(--muted);font-size:.9rem}
.price-card li::before{content:"✓";color:var(--accent-2);margin-right:.6rem}
.price-card.featured{border-color:var(--accent);background:var(--surface-2)}
footer{border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-bottom:1rem}
footer a{display:block;font-size:.88rem;color:var(--text);margin-bottom:.5rem;transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Nex<span>Cloud</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/product/">Product</a>'
           '<a href="/pricing/">Pricing</a>'
           '<a href="/about/">About</a>'
           '<a href="/contact/">Contact</a>'
           '</nav>'
           '<a href="/pricing/" class="btn btn-primary">Get started</a></header>')

    pages = {
        "index.html": _doc("NexCloud — Serverless Cloud Platform", f"""
{nav}
<div class="hero">
  <span class="eyebrow">v3.0 · Now with edge functions</span>
  <h1>Ship code, not <span>infrastructure</span></h1>
  <p>Serverless compute, managed databases and zero-trust security — all from one quiet dashboard. No YAML archaeology, no 2 a.m. pages.</p>
  <a href="/product/" class="btn btn-primary">See the platform</a>
  <a href="/pricing/" class="btn btn-ghost">View pricing</a>
</div>
<section>
  <h2 class="section-title">Everything in one place</h2>
  <p class="section-sub">A calm, predictable platform that scales with you.</p>
  <div class="grid">
    <div class="card"><div class="icon">⚡</div><h3>Edge Functions</h3><p>Run your code at the edge with 50 ms cold starts. Deploy with one git push.</p></div>
    <div class="card"><div class="icon">🗄</div><h3>Managed Databases</h3><p>Postgres, Redis and object storage — fully managed, automatically backed up.</p></div>
    <div class="card"><div class="icon">🔒</div><h3>Zero-Trust Security</h3><p>OIDC, mTLS and WAF baked in. Every request is verified, every time.</p></div>
    <div class="card"><div class="icon">📊</div><h3>Observability</h3><p>Logs, traces and metrics without configuration. Pay only for what you query.</p></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Nex<span>Cloud</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:260px">A quiet platform for serious workloads.</p></div>
    <div><h4>Product</h4><a href="/product/">Features</a><a href="/pricing/">Pricing</a></div>
    <div><h4>Company</h4><a href="/about/">About</a><a href="/contact/">Contact</a></div>
    <div><h4>Resources</h4><a href="/contact/">Docs</a><a href="/contact/">Status</a></div>
  </div>
  <div class="foot-bottom">© 2026 NexCloud Inc.</div>
</footer>"""),
        "product/index.html": _doc("Product — NexCloud", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Platform</span>
  <h1>One platform, <span>fewer surprises</span></h1>
  <p>Compute, storage, queues, observability and security — designed to feel like one product, not ten.</p>
</div>
<section>
  <h2 class="section-title">Capabilities</h2>
  <div class="grid">
    <div class="card"><div class="icon">⚡</div><h3>Functions</h3><p>TypeScript and Python runtimes with streaming responses and zero-config cron.</p></div>
    <div class="card"><div class="icon">🗄</div><h3>Storage</h3><p>S3-compatible object storage with edge caching and lifecycle policies.</p></div>
    <div class="card"><div class="icon">⟳</div><h3>Queues</h3><p>Durable queues with at-least-once delivery and dead-letter handling.</p></div>
    <div class="card"><div class="icon">🔍</div><h3>Tracing</h3><p>OpenTelemetry out of the box. Drop into any trace in two clicks.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 NexCloud Inc. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "pricing/index.html": _doc("Pricing — NexCloud", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Pricing</span>
  <h1>Simple, <span>predictable</span> pricing</h1>
  <p>Pay for what you use. No seat licenses, no surprise egress fees.</p>
</div>
<section>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr))">
    <div class="price-card"><h3>Hobby</h3><div class="price">$0<small>/mo</small></div><ul><li>1M function calls</li><li>1 GB storage</li><li>Community support</li></ul><a href="/contact/" class="btn btn-ghost">Start free</a></div>
    <div class="price-card featured"><h3>Pro</h3><div class="price">$29<small>/mo</small></div><ul><li>50M function calls</li><li>100 GB storage</li><li>Email support</li><li>Custom domains</li></ul><a href="/contact/" class="btn btn-primary">Choose Pro</a></div>
    <div class="price-card"><h3>Enterprise</h3><div class="price">Custom</div><ul><li>Unlimited calls</li><li>SAML SSO</li><li>SLA 99.99%</li><li>Dedicated engineer</li></ul><a href="/contact/" class="btn btn-ghost">Contact us</a></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 NexCloud Inc. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "about/index.html": _doc("About — NexCloud", f"""
{nav}
<div class="hero">
  <span class="eyebrow">About</span>
  <h1>We build quiet infrastructure</h1>
  <p>Founded in 2021, NexCloud is a small team focused on making cloud primitives that disappear into the background.</p>
</div>
<section>
  <h2 class="section-title">Our principles</h2>
  <div class="grid">
    <div class="card"><div class="icon">①</div><h3>Calm by default</h3><p>No pings at 3 a.m. The platform should be the most boring part of your stack.</p></div>
    <div class="card"><div class="icon">②</div><h3>Honest pricing</h3><p>You pay for resources, not for the privilege of using the platform.</p></div>
    <div class="card"><div class="icon">③</div><h3>Open standards</h3><p>OpenTelemetry, S3 API, OpenAI-compatible endpoints. No lock-in.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 NexCloud Inc. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — NexCloud", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Contact</span>
  <h1>Talk to us</h1>
  <p>Sales, support, or just curious — we read every message.</p>
</div>
<section>
  <div class="grid">
    <div class="card"><div class="icon">✉</div><h3>Email</h3><p>hello@nexcloud.example</p></div>
    <div class="card"><div class="icon">⌖</div><h3>Office</h3><p>2 Harbour Square, Suite 400</p></div>
    <div class="card"><div class="icon">⌚</div><h3>Support hours</h3><p>Mon–Fri, 24h response SLA</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 NexCloud Inc. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 3: Holm & Oak — Homeware store • parallax layers
# =============================================================================
def create_holm_oak(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#faf7f1;--surface:#fffdf8;--text:#3a352d;--muted:#857d6c;--accent:#7c8a5a;--accent-2:#b08968;--border:#e8e0d0}
body{font-family:'Cormorant Garamond','Georgia',serif;background:var(--bg);color:var(--text);line-height:1.7;font-size:1.05rem}
body{font-family:'Inter','Helvetica Neue',sans-serif;font-size:1rem}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(250,247,241,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.55rem;font-weight:600;letter-spacing:.5px}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.5rem;flex-wrap:wrap}
nav a{font-size:.92rem;color:var(--muted);transition:color .25s;position:relative;padding:.3rem 0}
nav a:hover{color:var(--accent)}
nav a.active{color:var(--accent)}
nav a.active::after{content:"";position:absolute;left:0;right:0;bottom:-4px;height:1px;background:var(--accent)}
.hero{position:relative;min-height:78vh;display:flex;align-items:center;justify-content:center;overflow:hidden;background:linear-gradient(180deg,#faf7f1 0%,#f0e9da 100%)}
.hero-bg{position:absolute;inset:0;background:
  radial-gradient(circle at 20% 30%,rgba(176,137,104,.18),transparent 50%),
  radial-gradient(circle at 80% 70%,rgba(124,138,90,.18),transparent 50%);
  animation:drift 24s ease-in-out infinite alternate}
@keyframes drift{from{transform:translate(0,0)}to{transform:translate(-30px,20px)}}
.hero-inner{position:relative;text-align:center;padding:2rem;max-width:720px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.25em;text-transform:uppercase;color:var(--accent-2);margin-bottom:1.25rem;display:block}
.hero h1{font-family:'Cormorant Garamond',Georgia,serif;font-size:clamp(2.4rem,6vw,4.5rem);font-weight:500;line-height:1.05;margin-bottom:1.5rem}
.hero p{color:var(--muted);max-width:520px;margin:0 auto 2.25rem;font-size:1.1rem}
.btn{display:inline-block;padding:.85rem 2rem;border-radius:2px;font-size:.85rem;letter-spacing:.12em;text-transform:uppercase;font-weight:600;transition:all .3s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#6b7849;transform:translateY(-2px)}
.btn-ghost{border:1px solid var(--text);color:var(--text);margin-left:.75rem}
.btn-ghost:hover{background:var(--text);color:var(--bg)}
section{padding:5rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-family:'Cormorant Garamond',Georgia,serif;font-size:2rem;font-weight:500;text-align:center;margin-bottom:.5rem}
.section-sub{text-align:center;color:var(--muted);margin-bottom:3rem;font-size:.95rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:2rem}
.product{background:var(--surface);border-radius:4px;overflow:hidden;border:1px solid var(--border);transition:transform .4s,box-shadow .4s}
.product:hover{transform:translateY(-6px);box-shadow:0 16px 36px rgba(58,53,45,.08)}
.product .img{height:240px;background:linear-gradient(135deg,#e8e0d0,#d4c8b0);position:relative;overflow:hidden}
.product .img::after{content:"";position:absolute;inset:0;background:linear-gradient(45deg,rgba(124,138,90,.1),rgba(176,137,104,.1));transition:transform .6s}
.product:hover .img::after{transform:scale(1.08)}
.product .body{padding:1.5rem}
.product h3{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.35rem;font-weight:500;margin-bottom:.4rem}
.product .price{color:var(--accent);font-weight:600}
.product p{color:var(--muted);font-size:.88rem;margin:.5rem 0 1rem}
.values{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:2rem;text-align:center;margin-top:3rem}
.value h3{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.4rem;font-weight:500;margin-bottom:.5rem;color:var(--accent)}
.value p{color:var(--muted);font-size:.9rem}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.9rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Holm <span>&amp;</span> Oak</a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/shop/">Shop</a>'
           '<a href="/about/">Story</a>'
           '<a href="/journal/">Journal</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Holm & Oak — Curated Homeware", f"""
{nav}
<div class="hero"><div class="hero-bg"></div><div class="hero-inner">
  <span class="eyebrow">Curated since 2014</span>
  <h1>Quiet objects for a considered home</h1>
  <p>Heirloom-grade textiles, ceramics and lighting — chosen for how they age, not how they photograph.</p>
  <a href="/shop/" class="btn btn-primary">Browse the collection</a>
  <a href="/about/" class="btn btn-ghost">Our story</a>
</div></div>
<section>
  <h2 class="section-title">New arrivals</h2>
  <p class="section-sub">Spring 2026 — quiet forms, warm tones.</p>
  <div class="grid">
    <div class="product"><div class="img"></div><div class="body"><h3>Linen Throw</h3><p>Stonewashed Belgian linen in oat and clay.</p><div class="price">€ 124</div></div></div>
    <div class="product"><div class="img"></div><div class="body"><h3>Stoneware Vase</h3><p>Hand-thrown, glazed in soft slate.</p><div class="price">€ 88</div></div></div>
    <div class="product"><div class="img"></div><div class="body"><h3>Oak Side Table</h3><p>Solid European oak, oil finish.</p><div class="price">€ 340</div></div></div>
    <div class="product"><div class="img"></div><div class="body"><h3>Paper Lantern</h3><p>Washi paper on bamboo frame.</p><div class="price">€ 96</div></div></div>
  </div>
</section>
<section>
  <h2 class="section-title">What we believe</h2>
  <div class="values">
    <div class="value"><h3>Materials</h3><p>Linen, oak, stoneware, brass — chosen to mellow with use.</p></div>
    <div class="value"><h3>Makers</h3><p>Small workshops in Europe and Japan, named on every label.</p></div>
    <div class="value"><h3>Longevity</h3><p>Each piece is repairable, replaceable, and meant to stay.</p></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Holm <span>&amp;</span> Oak</div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">Considered homeware from small workshops.</p></div>
    <div><h4>Shop</h4><a href="/shop/">All products</a><a href="/shop/">Textiles</a><a href="/shop/">Ceramics</a></div>
    <div><h4>About</h4><a href="/about/">Story</a><a href="/journal/">Journal</a></div>
    <div><h4>Help</h4><a href="/contact/">Contact</a><a href="/contact/">Shipping</a></div>
  </div>
  <div class="foot-bottom">© 2026 Holm &amp; Oak Studio</div>
</footer>"""),
        "shop/index.html": _doc("Shop — Holm & Oak", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">The collection</h2>
  <p class="section-sub">Pieces we live with, season after season.</p>
  <div class="grid">
    <div class="product"><div class="img"></div><div class="body"><h3>Wool Blanket</h3><p>Undyed highland wool, hand-finished edge.</p><div class="price">€ 210</div></div></div>
    <div class="product"><div class="img"></div><div class="body"><h3>Ceramic Bowl</h3><p>Wood-fired stoneware, food-safe glaze.</p><div class="price">€ 64</div></div></div>
    <div class="product"><div class="img"></div><div class="body"><h3>Brass Candleholder</h3><p>Solid brass, raw finish, ages gracefully.</p><div class="price">€ 78</div></div></div>
    <div class="product"><div class="img"></div><div class="body"><h3>Cotton Rug</h3><p>Flatweave in undyed cotton and soft clay.</p><div class="price">€ 420</div></div></div>
    <div class="product"><div class="img"></div><div class="body"><h3>Glass Carafe</h3><p>Mouth-blown, slight variation in each piece.</p><div class="price">€ 52</div></div></div>
    <div class="product"><div class="img"></div><div class="body"><h3>Oak Stool</h3><p>Joined, not screwed. Oil finish.</p><div class="price">€ 380</div></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Holm &amp; Oak Studio · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "about/index.html": _doc("Story — Holm & Oak", f"""
{nav}
<section style="padding-top:4rem;text-align:center;max-width:720px">
  <h2 class="section-title">Our story</h2>
  <p style="color:var(--muted);margin:1.5rem 0;line-height:1.8">Holm &amp; Oak began in 2014 as a single market stall in Copenhagen. We had one principle: only sell things we would happily live with for a decade. Twelve years later, that is still the only principle.</p>
  <p style="color:var(--muted);line-height:1.8">We work directly with small workshops in Portugal, Japan and the British Isles. Every maker is named on the label. Every material is traceable to a farm, a forest or a clay pit.</p>
</section>
<section>
  <div class="values">
    <div class="value"><h3>2014</h3><p>Founded at a Copenhagen market stall.</p></div>
    <div class="value"><h3>32 makers</h3><p>Across Europe and Japan, all named.</p></div>
    <div class="value"><h3>0%</h3><p>Of our pieces end up in landfill — repair or replace, free.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Holm &amp; Oak Studio · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "journal/index.html": _doc("Journal — Holm & Oak", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Journal</h2>
  <p class="section-sub">Notes on materials, makers and slow living.</p>
  <div class="grid">
    <div class="product"><div class="img" style="height:180px"></div><div class="body"><h3>How linen ages</h3><p>A field note on stonewashing, fading, and the patina of use.</p><span class="price">Read →</span></div></div>
    <div class="product"><div class="img" style="height:180px"></div><div class="body"><h3>The Mino kiln</h3><p>A visit to our stoneware workshop in central Japan.</p><span class="price">Read →</span></div></div>
    <div class="product"><div class="img" style="height:180px"></div><div class="body"><h3>On oak</h3><p>Why European oak is worth the wait — and the price.</p><span class="price">Read →</span></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Holm &amp; Oak Studio · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Holm & Oak", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Contact</h2>
  <p class="section-sub">We answer every email, usually within two days.</p>
  <div class="grid" style="max-width:800px;margin:2rem auto">
    <div class="value"><h3>Email</h3><p>studio@holmoak.example</p></div>
    <div class="value"><h3>Studio</h3><p>Værnedamsvej 6, Copenhagen</p></div>
    <div class="value"><h3>Hours</h3><p>Tue–Sat, 11–18</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Holm &amp; Oak Studio · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 4: Ember & Grain — Wood-fired bistro • steam rise
# =============================================================================
def create_ember_grain(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#1a1410;--surface:#221a14;--surface-2:#2b211a;--text:#f4e9d8;--muted:#a89484;--accent:#d4a574;--accent-2:#c87850;--border:#3a2c22}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.7}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(26,20,16,.88);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Playfair Display',Georgia,serif;font-size:1.4rem;font-weight:600;letter-spacing:.5px}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.5rem;flex-wrap:wrap}
nav a{font-size:.9rem;color:var(--muted);transition:color .25s;padding:.3rem 0}
nav a:hover{color:var(--accent)}
nav a.active{color:var(--accent)}
.btn{display:inline-block;padding:.8rem 1.9rem;border-radius:4px;font-size:.85rem;letter-spacing:.08em;text-transform:uppercase;font-weight:600;transition:all .3s}
.btn-primary{background:var(--accent);color:var(--bg)}
.btn-primary:hover{background:var(--accent-2);color:var(--text);transform:translateY(-2px)}
.btn-ghost{border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.hero{position:relative;min-height:80vh;display:flex;align-items:center;padding:5rem 5%;overflow:hidden;background:radial-gradient(ellipse at top,rgba(212,165,116,.12),transparent 60%)}
.steam{position:absolute;bottom:0;left:0;right:0;height:100%;pointer-events:none;overflow:hidden}
.steam span{position:absolute;bottom:-40px;width:60px;height:60px;background:radial-gradient(circle,rgba(244,233,216,.18),transparent 70%);border-radius:50%;animation:rise 9s linear infinite;filter:blur(8px)}
.steam span:nth-child(1){left:18%;animation-delay:0s}
.steam span:nth-child(2){left:38%;animation-delay:2.5s;animation-duration:11s}
.steam span:nth-child(3){left:58%;animation-delay:5s;animation-duration:10s}
.steam span:nth-child(4){left:78%;animation-delay:1.2s;animation-duration:12s}
@keyframes rise{0%{transform:translateY(0) scale(1);opacity:0}10%{opacity:.8}90%{opacity:.3}100%{transform:translateY(-90vh) scale(2.2);opacity:0}}
.hero-inner{position:relative;z-index:2;max-width:680px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.25em;text-transform:uppercase;color:var(--accent);margin-bottom:1.25rem;display:block}
.hero h1{font-family:'Playfair Display',Georgia,serif;font-size:clamp(2.4rem,6vw,4.4rem);font-weight:600;line-height:1.05;margin-bottom:1.5rem}
.hero p{color:var(--muted);max-width:520px;margin-bottom:2.25rem;font-size:1.1rem}
section{padding:5rem 5%;max-width:1100px;margin:0 auto}
.section-title{font-family:'Playfair Display',Georgia,serif;font-size:2.2rem;font-weight:600;text-align:center;margin-bottom:.5rem}
.section-sub{text-align:center;color:var(--muted);margin-bottom:3rem;font-size:.95rem;font-style:italic}
.menu-list{max-width:760px;margin:0 auto}
.menu-item{display:flex;justify-content:space-between;align-items:baseline;padding:1.25rem 0;border-bottom:1px solid var(--border)}
.menu-item h3{font-family:'Playfair Display',Georgia,serif;font-size:1.2rem;font-weight:600}
.menu-item .desc{display:block;color:var(--muted);font-size:.85rem;margin-top:.25rem;font-style:italic}
.menu-item .price{color:var(--accent);font-weight:600;font-size:1.05rem;white-space:nowrap;margin-left:1.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.5rem;margin-top:2rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:1.75rem;transition:transform .3s,border-color .3s}
.card:hover{transform:translateY(-4px);border-color:var(--accent)}
.card h3{font-family:'Playfair Display',Georgia,serif;font-size:1.25rem;margin-bottom:.5rem}
.card p{color:var(--muted);font-size:.9rem}
footer{border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.9rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Ember <span>&amp;</span> Grain</a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/menu/">Menu</a>'
           '<a href="/story/">Story</a>'
           '<a href="/reservations/">Reservations</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Ember & Grain — Wood-Fired Bistro", f"""
{nav}
<div class="hero">
  <div class="steam"><span></span><span></span><span></span><span></span></div>
  <div class="hero-inner">
    <span class="eyebrow">Wood-fired · Since 2018</span>
    <h1>Fire, grain, and patience</h1>
    <p>A small bistro on the edge of the river. We bake our own bread, cure our own bacon, and let the fire do most of the talking.</p>
    <a href="/reservations/" class="btn btn-primary">Book a table</a>
    <a href="/menu/" class="btn btn-ghost">View the menu</a>
  </div>
</div>
<section>
  <h2 class="section-title">This week on the table</h2>
  <p class="section-sub">A short menu, changed each Monday.</p>
  <div class="menu-list">
    <div class="menu-item"><div><h3>Sourdough loaf</h3><span class="desc">36-hour ferment, baked in the wood oven</span></div><span class="price">€ 8</span></div>
    <div class="menu-item"><div><h3>Beetroot tartare</h3><span class="desc">Smoked beetroot, capers, dill crème fraîche</span></div><span class="price">€ 14</span></div>
    <div class="menu-item"><div><h3>Wood-fired trout</h3><span class="desc">River trout, brown butter, charred lemon</span></div><span class="price">€ 26</span></div>
    <div class="menu-item"><div><h3>Honey cake</h3><span class="desc">Buckwheat, raw honey, crème fraîche</span></div><span class="price">€ 9</span></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Ember <span>&amp;</span> Grain</div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">A small wood-fired bistro on the river.</p></div>
    <div><h4>Visit</h4><a href="/reservations/">Reservations</a><a href="/contact/">Hours</a></div>
    <div><h4>Kitchen</h4><a href="/menu/">Menu</a><a href="/story/">Story</a></div>
    <div><h4>Follow</h4><a href="/contact/">Instagram</a><a href="/contact/">Newsletter</a></div>
  </div>
  <div class="foot-bottom">© 2026 Ember &amp; Grain</div>
</footer>"""),
        "menu/index.html": _doc("Menu — Ember & Grain", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">The menu</h2>
  <p class="section-sub">Short, seasonal, mostly wood-fired.</p>
  <div class="menu-list">
    <div class="menu-item"><div><h3>Cultured butter</h3><span class="desc">With warm sourdough</span></div><span class="price">€ 6</span></div>
    <div class="menu-item"><div><h3>Pickled mackerel</h3><span class="desc">Rye crisp, soft herbs</span></div><span class="price">€ 12</span></div>
    <div class="menu-item"><div><h3>Charred leek vinaigrette</h3><span class="desc">Hazelnut, soft egg</span></div><span class="price">€ 13</span></div>
    <div class="menu-item"><div><h3>Wood-fired duck</h3><span class="desc">Two courses, for two</span></div><span class="price">€ 56</span></div>
    <div class="menu-item"><div><h3>Stewed pears</h3><span class="desc">Cardamom, crème fraîche</span></div><span class="price">€ 9</span></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Ember &amp; Grain · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "story/index.html": _doc("Story — Ember & Grain", f"""
{nav}
<section style="padding-top:5rem;max-width:720px;margin:0 auto;text-align:center">
  <h2 class="section-title">Our story</h2>
  <p class="section-sub">A small kitchen with a single wood oven.</p>
  <p style="color:var(--muted);line-height:1.9;margin:1.5rem 0">Ember &amp; Grain opened in 2018 in an old boat-builder's shed. We cook almost entirely over oak and beech. Bread goes in at dawn, fish at noon, and game in the evening.</p>
  <p style="color:var(--muted);line-height:1.9">We cure, ferment, pickle and smoke in-house. The menu is short because the kitchen is small — and because that is how we like it.</p>
</section>
<footer><div class="foot-bottom">© 2026 Ember &amp; Grain · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "reservations/index.html": _doc("Reservations — Ember & Grain", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Reservations</h2>
  <p class="section-sub">Dinner only, Wednesday to Saturday. Two seatings: 18:00 and 20:30.</p>
  <div class="grid" style="max-width:780px;margin:2rem auto">
    <div class="card"><h3>By phone</h3><p>+33 1 23 45 67 89</p></div>
    <div class="card"><h3>By email</h3><p>book@embergrain.example</p></div>
    <div class="card"><h3>Walk-ins</h3><p>Bar seats only, from 21:30.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Ember &amp; Grain · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Ember & Grain", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Find us</h2>
  <p class="section-sub">On the river, two doors down from the old chandlery.</p>
  <div class="grid" style="max-width:780px;margin:2rem auto">
    <div class="card"><h3>Address</h3><p>4 Quai des Tanneurs</p></div>
    <div class="card"><h3>Phone</h3><p>+33 1 23 45 67 89</p></div>
    <div class="card"><h3>Hours</h3><p>Wed–Sat · 18:00–22:30</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Ember &amp; Grain · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 5: NexHub — Community + storage • card flip
# =============================================================================
def create_nexhub(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--surface:#161b22;--surface-2:#1c232e;--text:#e6edf3;--muted:#7d8590;--accent:#4493f8;--accent-2:#3fb950;--border:#30363d}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(13,17,23,.88);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:1.25rem;font-weight:800;letter-spacing:-.4px}
.logo span{color:var(--accent)}
nav{display:flex;gap:.4rem;flex-wrap:wrap}
nav a{padding:.45rem .85rem;border-radius:6px;font-size:.88rem;color:var(--muted);transition:color .2s,background .2s}
nav a:hover{color:var(--text);background:var(--surface-2)}
nav a.active{color:var(--text);background:var(--surface-2)}
.btn{display:inline-block;padding:.65rem 1.4rem;border-radius:6px;font-size:.88rem;font-weight:600;transition:transform .2s,box-shadow .2s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(68,147,248,.3)}
.btn-ghost{border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent)}
.hero{padding:6rem 5% 4rem;max-width:1100px;margin:0 auto;text-align:center}
.hero .eyebrow{font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);background:rgba(68,147,248,.12);padding:.4rem 1rem;border-radius:99px;margin-bottom:1.5rem;display:inline-block}
.hero h1{font-size:clamp(2rem,5vw,3.4rem);font-weight:800;letter-spacing:-1px;margin-bottom:1.25rem;line-height:1.1}
.hero p{color:var(--muted);max-width:600px;margin:0 auto 2rem}
.flip-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1.25rem;max-width:1100px;margin:3rem auto;padding:0 5%}
.flip{perspective:1000px;height:180px;animation:floatCard 6s ease-in-out infinite}
.flip:nth-child(2n){animation-delay:-1.5s}
.flip:nth-child(3n){animation-delay:-3s}
.flip:nth-child(4n){animation-delay:-4.5s}
@keyframes floatCard{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.flip-inner{position:relative;width:100%;height:100%;transition:transform .7s cubic-bezier(.4,.2,.2,1);transform-style:preserve-3d}
.flip:hover .flip-inner{transform:rotateY(180deg)}
.flip-front,.flip-back{position:absolute;inset:0;backface-visibility:hidden;border-radius:12px;padding:1.5rem;display:flex;flex-direction:column;justify-content:center;border:1px solid var(--border)}
.flip-front{background:var(--surface)}
.flip-back{background:var(--accent);color:#fff;transform:rotateY(180deg)}
.flip-front h3{font-size:1.1rem;margin-bottom:.4rem}
.flip-front p{color:var(--muted);font-size:.85rem}
.flip-back h3{font-size:1.05rem;margin-bottom:.5rem}
.flip-back a{color:#fff;text-decoration:underline;font-size:.85rem}
section{padding:4rem 5%;max-width:1100px;margin:0 auto}
.section-title{font-size:1.6rem;font-weight:700;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{color:var(--muted);margin-bottom:2.5rem;font-size:.92rem}
.list{display:grid;grid-template-columns:1fr;gap:.75rem;max-width:760px;margin:0 auto}
.list-item{display:flex;justify-content:space-between;align-items:center;background:var(--surface);border:1px solid var(--border);padding:1rem 1.25rem;border-radius:8px;transition:border-color .25s,transform .25s}
.list-item:hover{border-color:var(--accent);transform:translateX(4px)}
.list-item .meta{color:var(--muted);font-size:.85rem}
.list-item .tag{font-size:.72rem;padding:.2rem .55rem;border-radius:4px;background:rgba(63,185,80,.12);color:var(--accent-2);margin-left:.6rem}
footer{border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.88rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Nex<span>Hub</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/forum/">Forum</a>'
           '<a href="/storage/">Storage</a>'
           '<a href="/docs/">Docs</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("NexHub — Community & Storage", f"""
{nav}
<div class="hero">
  <span class="eyebrow">Open beta · 2026</span>
  <h1>A quiet corner of the internet</h1>
  <p>NexHub is a small community forum with attached cloud storage. No algorithms, no engagement metrics — just people sharing what they make.</p>
  <a href="/forum/" class="btn btn-primary">Enter the forum</a>
  <a href="/storage/" class="btn btn-ghost">Browse storage</a>
</div>
<div class="flip-grid">
  <div class="flip"><div class="flip-inner"><div class="flip-front"><h3>Forum</h3><p>4,218 threads · 312 online now</p></div><div class="flip-back"><h3>Join the conversation</h3><a href="/forum/">Open forum →</a></div></div></div>
  <div class="flip"><div class="flip-inner"><div class="flip-front"><h3>Storage</h3><p>10 GB free for every member</p></div><div class="flip-back"><h3>Upload and share</h3><a href="/storage/">Open storage →</a></div></div></div>
  <div class="flip"><div class="flip-inner"><div class="flip-front"><h3>Docs</h3><p>Wiki, guides, snippets</p></div><div class="flip-back"><h3>Read &amp; contribute</h3><a href="/docs/">Open docs →</a></div></div></div>
  <div class="flip"><div class="flip-inner"><div class="flip-front"><h3>Contact</h3><p>Mods, support, abuse</p></div><div class="flip-back"><h3>Get in touch</h3><a href="/contact/">Open contact →</a></div></div></div>
</div>
<footer>
  <div class="grid">
    <div><div class="logo">Nex<span>Hub</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">A small community, run by hand.</p></div>
    <div><h4>Community</h4><a href="/forum/">Forum</a><a href="/docs/">Docs</a></div>
    <div><h4>Storage</h4><a href="/storage/">Browse</a><a href="/contact/">Plans</a></div>
    <div><h4>Help</h4><a href="/contact/">Contact</a><a href="/contact/">Rules</a></div>
  </div>
  <div class="foot-bottom">© 2026 NexHub Cooperative</div>
</footer>"""),
        "forum/index.html": _doc("Forum — NexHub", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Recent threads</h2>
  <p class="section-sub">Sorted by last activity.</p>
  <div class="list">
    <a href="/forum/" class="list-item"><div><strong>Self-hosting email in 2026 — still worth it?</strong><span class="meta"> · 42 replies · 2h ago</span><span class="tag">active</span></div></a>
    <a href="/forum/" class="list-item"><div><strong>Best minimal Linux setup for old ThinkPads</strong><span class="meta"> · 18 replies · 5h ago</span></div></a>
    <a href="/forum/" class="list-item"><div><strong>NixOS on a VPS — first impressions</strong><span class="meta"> · 9 replies · 8h ago</span></div></a>
    <a href="/forum/" class="list-item"><div><strong>Quiet mechanical keyboards — show yours</strong><span class="meta"> · 67 replies · 12h ago</span><span class="tag">active</span></div></a>
    <a href="/forum/" class="list-item"><div><strong>What did you self-host this week?</strong><span class="meta"> · 124 replies · 1d ago</span></div></a>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 NexHub Cooperative · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "storage/index.html": _doc("Storage — NexHub", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Public storage</h2>
  <p class="section-sub">Curated archives, freely downloadable.</p>
  <div class="list">
    <a href="/storage/" class="list-item"><div><strong>Linux-distros archive</strong><span class="meta"> · 12.4 GB · 142 items</span></div></a>
    <a href="/storage/" class="list-item"><div><strong>Public-domain books</strong><span class="meta"> · 3.8 GB · 1,240 items</span></div></a>
    <a href="/storage/" class="list-item"><div><strong>Open fonts collection</strong><span class="meta"> · 540 MB · 312 items</span></div></a>
    <a href="/storage/" class="list-item"><div><strong>Field recordings</strong><span class="meta"> · 2.1 GB · 86 items</span></div></a>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 NexHub Cooperative · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "docs/index.html": _doc("Docs — NexHub", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Documentation</h2>
  <p class="section-sub">Wiki, guides, member handbook.</p>
  <div class="list">
    <a href="/docs/" class="list-item"><div><strong>Getting started</strong><span class="meta"> · 5 min read</span></div></a>
    <a href="/docs/" class="list-item"><div><strong>Forum rules</strong><span class="meta"> · 3 min read</span></div></a>
    <a href="/docs/" class="list-item"><div><strong>Storage policy</strong><span class="meta"> · 4 min read</span></div></a>
    <a href="/docs/" class="list-item"><div><strong>Moderation</strong><span class="meta"> · 6 min read</span></div></a>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 NexHub Cooperative · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — NexHub", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Contact</h2>
  <p class="section-sub">Moderation, support and abuse reports.</p>
  <div class="list">
    <a href="/contact/" class="list-item"><div><strong>Moderation</strong><span class="meta"> · mods@nexhub.example</span></div></a>
    <a href="/contact/" class="list-item"><div><strong>Support</strong><span class="meta"> · help@nexhub.example</span></div></a>
    <a href="/contact/" class="list-item"><div><strong>Abuse</strong><span class="meta"> · abuse@nexhub.example</span></div></a>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 NexHub Cooperative · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 6: ByteForge — Developer forum • code rain
# =============================================================================
def create_byteforge(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e14;--surface:#11151c;--surface-2:#161b24;--text:#c9d1d9;--muted:#7d8590;--accent:#56d4dd;--accent-2:#7ee787;--border:#21262d;--mono:'JetBrains Mono','SF Mono',Menlo,monospace}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65;overflow-x:hidden}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(10,14,20,.9);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:var(--mono);font-size:1.15rem;font-weight:700}
.logo span{color:var(--accent)}
nav{display:flex;gap:.4rem;flex-wrap:wrap}
nav a{padding:.45rem .85rem;border-radius:6px;font-size:.85rem;color:var(--muted);transition:color .2s,background .2s;font-family:var(--mono)}
nav a:hover{color:var(--accent);background:var(--surface-2)}
nav a.active{color:var(--accent);background:var(--surface-2)}
.btn{display:inline-block;padding:.65rem 1.4rem;border-radius:6px;font-size:.85rem;font-weight:600;font-family:var(--mono);transition:all .2s}
.btn-primary{background:var(--accent);color:var(--bg)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(86,212,221,.25)}
.btn-ghost{border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent)}
.hero{position:relative;padding:7rem 5% 5rem;max-width:1100px;margin:0 auto;overflow:hidden}
.rain{position:absolute;inset:0;pointer-events:none;font-family:var(--mono);font-size:.85rem;color:rgba(86,212,221,.18);overflow:hidden;z-index:0}
.rain span{position:absolute;top:-20px;animation:fall linear infinite;white-space:pre}
@keyframes fall{from{transform:translateY(-20px)}to{transform:translateY(110vh)}}
.hero-inner{position:relative;z-index:2}
.hero .eyebrow{font-family:var(--mono);font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);margin-bottom:1.25rem;display:block}
.hero h1{font-size:clamp(2rem,5vw,3.4rem);font-weight:800;letter-spacing:-1px;margin-bottom:1.25rem;line-height:1.1}
.hero h1 .code{font-family:var(--mono);color:var(--accent);font-weight:600;font-size:.9em}
.hero p{color:var(--muted);max-width:560px;margin-bottom:2rem;font-size:1.05rem}
section{padding:4rem 5%;max-width:1100px;margin:0 auto;position:relative}
.section-title{font-size:1.5rem;font-weight:700;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{color:var(--muted);margin-bottom:2.5rem;font-size:.92rem;font-family:var(--mono)}
.threads{display:grid;gap:.75rem}
.thread{display:flex;justify-content:space-between;align-items:center;background:var(--surface);border:1px solid var(--border);padding:1rem 1.25rem;border-radius:6px;transition:border-color .25s,transform .25s}
.thread:hover{border-color:var(--accent);transform:translateX(4px)}
.thread .title{font-family:var(--mono);font-size:.95rem}
.thread .title .lang{color:var(--accent-2);margin-right:.5rem}
.thread .meta{color:var(--muted);font-size:.8rem;font-family:var(--mono)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-top:1.5rem}
.tag-card{background:var(--surface);border:1px solid var(--border);padding:1.25rem;border-radius:6px;transition:transform .25s,border-color .25s}
.tag-card:hover{transform:translateY(-3px);border-color:var(--accent)}
.tag-card h3{font-family:var(--mono);color:var(--accent);font-size:.95rem;margin-bottom:.4rem}
.tag-card p{color:var(--muted);font-size:.85rem}
footer{border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-bottom:1rem;font-family:var(--mono)}
footer a{display:block;font-size:.88rem;margin-bottom:.5rem;color:var(--text);transition:color .2s;font-family:var(--mono)}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem;font-family:var(--mono)}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    # Build a "code rain" with 16 columns of slowly falling characters.
    cols = []
    import random as _r
    _r.seed(7)
    chars = "01{}[]<>/;:=+-*&|.$_"
    for i in range(16):
        left = 4 + i * 6.2
        dur = 9 + _r.randint(0, 9)
        delay = _r.randint(0, 8)
        snippet = "".join(_r.choice(chars) for _ in range(_r.randint(14, 24)))
        cols.append(
            f'<span style="left:{left}%;animation-duration:{dur}s;animation-delay:{delay}s">{snippet}</span>'
        )
    rain_html = '<div class="rain">' + "".join(cols) + '</div>'

    nav = ('<header><a href="/" class="logo">byte<span>forge</span></a>'
           '<nav>'
           '<a href="/" class="active">~/</a>'
           '<a href="/threads/">threads</a>'
           '<a href="/tags/">tags</a>'
           '<a href="/members/">members</a>'
           '<a href="/contact/">contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("byteforge — developer community", f"""
{nav}
<div class="hero">
  {rain_html}
  <div class="hero-inner">
    <span class="eyebrow">// est. 2019</span>
    <h1>A quiet forum for people who <span class="code">ship</span>.</h1>
    <p>No karma, no badges, no engagement loop. Just threads, written by people who write code, for people who write code.</p>
    <a href="/threads/" class="btn btn-primary">→ open threads</a>
    <a href="/contact/" class="btn btn-ghost">→ sign up</a>
  </div>
</div>
<section>
  <h2 class="section-title">Hot threads</h2>
  <p class="section-sub">// sorted by last reply</p>
  <div class="threads">
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[rust]</span>Why async traits finally feel right in 1.76</div><div class="meta">42 replies · 1h</div></a>
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[linux]</span>systemd-resolved vs dnsmasq on a small VPS</div><div class="meta">18 replies · 3h</div></a>
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[self-host]</span>Migrating 12 years of email to a single Pi 5</div><div class="meta">67 replies · 5h</div></a>
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[editor]</span>Helix vs Zed in late 2026 — actual daily use</div><div class="meta">29 replies · 8h</div></a>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">byte<span>forge</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.85rem;max-width:240px;font-family:var(--mono)">A small forum, run on a single VPS.</p></div>
    <div><h4>forum</h4><a href="/threads/">threads</a><a href="/tags/">tags</a></div>
    <div><h4>community</h4><a href="/members/">members</a><a href="/contact/">signup</a></div>
    <div><h4>meta</h4><a href="/contact/">rules</a><a href="/contact/">about</a></div>
  </div>
  <div class="foot-bottom">// © 2026 byteforge collective</div>
</footer>"""),
        "threads/index.html": _doc("threads — byteforge", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">All threads</h2>
  <p class="section-sub">// newest first</p>
  <div class="threads">
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[postgres]</span>Tuning autovacuum on a 2 TB table</div><div class="meta">8 replies · 25min</div></a>
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[rust]</span>Why async traits finally feel right in 1.76</div><div class="meta">42 replies · 1h</div></a>
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[linux]</span>systemd-resolved vs dnsmasq on a small VPS</div><div class="meta">18 replies · 3h</div></a>
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[editor]</span>Helix vs Zed in late 2026</div><div class="meta">29 replies · 8h</div></a>
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[self-host]</span>Migrating 12 years of email</div><div class="meta">67 replies · 5h</div></a>
    <a href="/threads/" class="thread"><div class="title"><span class="lang">[web]</span>HTMX in production: honest report after one year</div><div class="meta">14 replies · 1d</div></a>
  </div>
</section>
<footer><div class="foot-bottom">// © 2026 byteforge collective · <a href="/" style="color:var(--accent)">~/</a></div></footer>"""),
        "tags/index.html": _doc("tags — byteforge", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Tags</h2>
  <p class="section-sub">// by frequency</p>
  <div class="grid">
    <div class="tag-card"><h3>#rust</h3><p>412 threads</p></div>
    <div class="tag-card"><h3>#linux</h3><p>328 threads</p></div>
    <div class="tag-card"><h3>#self-host</h3><p>246 threads</p></div>
    <div class="tag-card"><h3>#postgres</h3><p>184 threads</p></div>
    <div class="tag-card"><h3>#editor</h3><p>152 threads</p></div>
    <div class="tag-card"><h3>#web</h3><p>131 threads</p></div>
  </div>
</section>
<footer><div class="foot-bottom">// © 2026 byteforge collective · <a href="/" style="color:var(--accent)">~/</a></div></footer>"""),
        "members/index.html": _doc("members — byteforge", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Members</h2>
  <p class="section-sub">// 1,247 active accounts</p>
  <div class="grid">
    <div class="tag-card"><h3>@ada</h3><p>312 posts · mod</p></div>
    <div class="tag-card"><h3>@babbage</h3><p>208 posts</p></div>
    <div class="tag-card"><h3>@curie</h3><p>164 posts</p></div>
    <div class="tag-card"><h3>@dijkstra</h3><p>152 posts</p></div>
    <div class="tag-card"><h3>@euler</h3><p>89 posts</p></div>
    <div class="tag-card"><h3>@feynman</h3><p>71 posts</p></div>
  </div>
</section>
<footer><div class="foot-bottom">// © 2026 byteforge collective · <a href="/" style="color:var(--accent)">~/</a></div></footer>"""),
        "contact/index.html": _doc("contact — byteforge", f"""
{nav}
<section style="padding-top:4rem">
  <h2 class="section-title">Contact</h2>
  <p class="section-sub">// signup is invite-only</p>
  <div class="grid">
    <div class="tag-card"><h3>signup</h3><p>invite@byteforge.example</p></div>
    <div class="tag-card"><h3>moderation</h3><p>mods@byteforge.example</p></div>
    <div class="tag-card"><h3>abuse</h3><p>abuse@byteforge.example</p></div>
  </div>
</section>
<footer><div class="foot-bottom">// © 2026 byteforge collective · <a href="/" style="color:var(--accent)">~/</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 7: Lumen Architects — Architecture studio • line draw
# =============================================================================
def create_lumen(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f7f4ee;--surface:#fffdf8;--text:#2a2622;--muted:#8a807a;--accent:#8a6d3b;--accent-2:#5d6b58;--border:#e2dcd0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.7}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(247,244,238,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.2rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.4rem;font-weight:500;letter-spacing:2px;text-transform:uppercase}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.75rem;flex-wrap:wrap}
nav a{font-size:.85rem;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;transition:color .25s;padding:.3rem 0}
nav a:hover{color:var(--accent)}
nav a.active{color:var(--accent)}
.hero{position:relative;min-height:84vh;display:flex;align-items:center;overflow:hidden}
.hero-line{position:absolute;left:5%;right:5%;top:50%;height:1px;background:var(--accent);transform-origin:left;animation:drawLine 1.6s .3s ease-out forwards;transform:scaleX(0)}
@keyframes drawLine{to{transform:scaleX(1)}}
.hero-inner{padding:5rem 5%;max-width:760px;position:relative;z-index:2}
.hero .eyebrow{font-size:.78rem;letter-spacing:.25em;text-transform:uppercase;color:var(--accent);margin-bottom:1.5rem;display:block}
.hero h1{font-family:'Cormorant Garamond',Georgia,serif;font-size:clamp(2.6rem,6vw,5rem);font-weight:400;line-height:1.05;margin-bottom:1.5rem;letter-spacing:-.5px}
.hero p{color:var(--muted);max-width:480px;margin-bottom:2.25rem;font-size:1.05rem}
.btn{display:inline-block;padding:.9rem 2rem;border-radius:0;font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;font-weight:600;transition:all .3s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#6f552d;transform:translateY(-2px)}
.btn-ghost{border:1px solid var(--text);color:var(--text);margin-left:.75rem}
.btn-ghost:hover{background:var(--text);color:var(--bg)}
section{padding:6rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-family:'Cormorant Garamond',Georgia,serif;font-size:2.4rem;font-weight:400;text-align:center;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{text-align:center;color:var(--muted);margin-bottom:4rem;font-size:.95rem;letter-spacing:.04em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:2.5rem}
.project{background:var(--surface);border:1px solid var(--border);transition:transform .4s,box-shadow .4s;overflow:hidden}
.project:hover{transform:translateY(-6px);box-shadow:0 16px 36px rgba(42,38,34,.08)}
.project .img{height:280px;background:linear-gradient(135deg,#d4cab8,#b8a988);position:relative;overflow:hidden}
.project .img::after{content:"";position:absolute;inset:0;background:linear-gradient(45deg,rgba(138,109,59,.08),rgba(93,107,88,.08))}
.project .body{padding:1.75rem}
.project .cat{font-size:.72rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);margin-bottom:.5rem}
.project h3{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.6rem;font-weight:500;margin-bottom:.4rem}
.project p{color:var(--muted);font-size:.88rem}
.values{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:3rem;margin-top:2rem}
.value{text-align:center}
.value .num{font-family:'Cormorant Garamond',Georgia,serif;font-size:3rem;color:var(--accent);font-weight:400}
.value h3{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.3rem;font-weight:500;margin:.5rem 0}
.value p{color:var(--muted);font-size:.88rem}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.72rem;text-transform:uppercase;letter-spacing:.18em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.88rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.78rem;letter-spacing:.06em}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Lumen <span>Architects</span></a>'
           '<nav>'
           '<a href="/" class="active">Studio</a>'
           '<a href="/projects/">Projects</a>'
           '<a href="/approach/">Approach</a>'
           '<a href="/team/">Team</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Lumen Architects — Architecture Studio", f"""
{nav}
<div class="hero">
  <div class="hero-line"></div>
  <div class="hero-inner">
    <span class="eyebrow">Established 2009 · Lisbon</span>
    <h1>Light, material, <br>and the silence between.</h1>
    <p>Lumen Architects designs residential and cultural buildings across Iberia. We work slowly, draw by hand, and answer every email ourselves.</p>
    <a href="/projects/" class="btn btn-primary">View projects</a>
    <a href="/approach/" class="btn btn-ghost">Our approach</a>
  </div>
</div>
<section>
  <h2 class="section-title">Selected work</h2>
  <p class="section-sub">A quiet portfolio, built over fifteen years.</p>
  <div class="grid">
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Residential · 2024</div><h3>Casa do Vale</h3><p>Single-family house, Alentejo coast</p></div></div>
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Cultural · 2023</div><h3>Quinta Gallery</h3><p>Conversion of a winery into a small museum</p></div></div>
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Residential · 2022</div><h3>Atelier Maré</h3><p>Artist's studio on the Atlantic cliff</p></div></div>
  </div>
</section>
<section>
  <div class="values">
    <div class="value"><div class="num">15</div><h3>Years</h3><p>Of slow, considered practice.</p></div>
    <div class="value"><div class="num">42</div><h3>Projects</h3><p>Built across Iberia and the Atlantic.</p></div>
    <div class="value"><div class="num">6</div><h3>People</h3><p>A small studio, by design.</p></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Lumen <span>Architects</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.85rem;max-width:240px">Light, material, silence.</p></div>
    <div><h4>Studio</h4><a href="/projects/">Projects</a><a href="/approach/">Approach</a></div>
    <div><h4>About</h4><a href="/team/">Team</a><a href="/contact/">Contact</a></div>
    <div><h4>Visit</h4><a href="/contact/">Lisbon</a><a href="/contact/">Porto</a></div>
  </div>
  <div class="foot-bottom">© 2026 LUMEN ARCHITECTS · LDA</div>
</footer>"""),
        "projects/index.html": _doc("Projects — Lumen Architects", f"""
{nav}
<section style="padding-top:6rem">
  <h2 class="section-title">Projects</h2>
  <p class="section-sub">Residential, cultural, and adaptive reuse.</p>
  <div class="grid">
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Residential · 2024</div><h3>Casa do Vale</h3><p>Alentejo coast</p></div></div>
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Cultural · 2023</div><h3>Quinta Gallery</h3><p>Setúbal</p></div></div>
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Residential · 2022</div><h3>Atelier Maré</h3><p>Ericeira</p></div></div>
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Adaptive · 2021</div><h3>Estrela Apartments</h3><p>Lisbon</p></div></div>
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Cultural · 2020</div><h3>Cabo Library</h3><p>Sagres</p></div></div>
    <div class="project"><div class="img"></div><div class="body"><div class="cat">Residential · 2019</div><h3>Olive House</h3><p>Évora</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 LUMEN ARCHITECTS · <a href="/" style="color:var(--accent)">← studio</a></div></footer>"""),
        "approach/index.html": _doc("Approach — Lumen Architects", f"""
{nav}
<section style="padding-top:6rem;max-width:760px;margin:0 auto;text-align:center">
  <h2 class="section-title">Approach</h2>
  <p class="section-sub">How we work.</p>
  <p style="color:var(--muted);line-height:1.9;margin:1.5rem 0">We begin every project with a single sketch — pencil on tracing paper, no rulers. From there, the work grows slowly through model-making, site visits, and long conversations with the people who will live in or use the building.</p>
  <p style="color:var(--muted);line-height:1.9">We work on no more than four projects at a time. We do not enter competitions. We answer every email ourselves.</p>
</section>
<footer><div class="foot-bottom">© 2026 LUMEN ARCHITECTS · <a href="/" style="color:var(--accent)">← studio</a></div></footer>"""),
        "team/index.html": _doc("Team — Lumen Architects", f"""
{nav}
<section style="padding-top:6rem">
  <h2 class="section-title">Team</h2>
  <p class="section-sub">Six people, one studio.</p>
  <div class="grid">
    <div class="project"><div class="img" style="height:200px"></div><div class="body"><h3>Inês Marques</h3><p>Founding partner</p></div></div>
    <div class="project"><div class="img" style="height:200px"></div><div class="body"><h3>Tomás Ribeiro</h3><p>Partner</p></div></div>
    <div class="project"><div class="img" style="height:200px"></div><div class="body"><h3>Cláudia Sousa</h3><p>Senior architect</p></div></div>
    <div class="project"><div class="img" style="height:200px"></div><div class="body"><h3>André Pinto</h3><p>Architect</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 LUMEN ARCHITECTS · <a href="/" style="color:var(--accent)">← studio</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Lumen Architects", f"""
{nav}
<section style="padding-top:6rem">
  <h2 class="section-title">Contact</h2>
  <p class="section-sub">We take on four new projects each year.</p>
  <div class="grid" style="max-width:840px;margin:1rem auto">
    <div class="value"><h3 style="font-family:'Cormorant Garamond',Georgia,serif;font-size:1.4rem">Studio</h3><p style="color:var(--muted)">Rua das Janelas Verdes 22, Lisbon</p></div>
    <div class="value"><h3 style="font-family:'Cormorant Garamond',Georgia,serif;font-size:1.4rem">Email</h3><p style="color:var(--muted)">studio@lumenarch.example</p></div>
    <div class="value"><h3 style="font-family:'Cormorant Garamond',Georgia,serif;font-size:1.4rem">Phone</h3><p style="color:var(--muted)">+351 21 234 5678</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 LUMEN ARCHITECTS · <a href="/" style="color:var(--accent)">← studio</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 8: Verdant Botanical — Plant shop • leaf sway
# =============================================================================
def create_verdant(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f4f1ea;--surface:#fffefb;--text:#2d3a2e;--muted:#7a8479;--accent:#5d7b4e;--accent-2:#8aa477;--border:#e0dcd0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.7}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(244,241,234,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.5rem;font-weight:500}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.5rem;flex-wrap:wrap}
nav a{font-size:.9rem;color:var(--muted);transition:color .25s;padding:.3rem 0;position:relative}
nav a:hover{color:var(--accent)}
nav a.active{color:var(--accent)}
nav a.active::after{content:"";position:absolute;left:0;right:0;bottom:-3px;height:1px;background:var(--accent)}
.btn{display:inline-block;padding:.8rem 1.9rem;border-radius:24px;font-size:.88rem;font-weight:600;transition:all .3s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#4d6840;transform:translateY(-2px);box-shadow:0 8px 20px rgba(93,123,78,.25)}
.btn-ghost{border:1px solid var(--border);color:var(--text);margin-left:.5rem}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.hero{position:relative;min-height:74vh;display:flex;align-items:center;overflow:hidden}
.leaf-bg{position:absolute;inset:0;pointer-events:none;overflow:hidden}
.leaf{position:absolute;font-size:3rem;color:rgba(93,123,78,.15);animation:sway 6s ease-in-out infinite}
.leaf:nth-child(1){top:18%;left:8%;animation-delay:0s}
.leaf:nth-child(2){top:62%;left:18%;animation-delay:1.2s;font-size:2rem}
.leaf:nth-child(3){top:24%;right:10%;animation-delay:2.4s;font-size:4rem}
.leaf:nth-child(4){top:70%;right:18%;animation-delay:0.8s;font-size:2.5rem}
.leaf:nth-child(5){top:45%;right:32%;animation-delay:3s;font-size:1.5rem}
@keyframes sway{0%,100%{transform:rotate(-8deg) translateY(0)}50%{transform:rotate(8deg) translateY(-8px)}}
.hero-inner{position:relative;z-index:2;padding:5rem 5%;max-width:680px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.22em;text-transform:uppercase;color:var(--accent);margin-bottom:1.25rem;display:block}
.hero h1{font-family:'Cormorant Garamond',Georgia,serif;font-size:clamp(2.4rem,6vw,4.4rem);font-weight:500;line-height:1.05;margin-bottom:1.5rem}
.hero p{color:var(--muted);max-width:480px;margin-bottom:2.25rem;font-size:1.05rem}
section{padding:5rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-family:'Cormorant Garamond',Georgia,serif;font-size:2.2rem;font-weight:500;text-align:center;margin-bottom:.5rem}
.section-sub{text-align:center;color:var(--muted);margin-bottom:3rem;font-size:.95rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.75rem}
.plant{background:var(--surface);border-radius:16px;overflow:hidden;border:1px solid var(--border);transition:transform .4s,box-shadow .4s}
.plant:hover{transform:translateY(-6px);box-shadow:0 16px 36px rgba(45,58,46,.08)}
.plant .img{height:240px;background:linear-gradient(135deg,#c8d4ba,#a8b89a);position:relative;display:flex;align-items:center;justify-content:center;font-size:3rem;color:rgba(93,123,78,.4)}
.plant .body{padding:1.5rem}
.plant h3{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.4rem;font-weight:500;margin-bottom:.3rem}
.plant .latin{color:var(--muted);font-style:italic;font-size:.85rem;margin-bottom:.6rem}
.plant .price{color:var(--accent);font-weight:600}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.9rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Verdant <span>Botanical</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/shop/">Shop</a>'
           '<a href="/care/">Care</a>'
           '<a href="/workshops/">Workshops</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Verdant Botanical — Plant Shop", f"""
{nav}
<div class="hero">
  <div class="leaf-bg"><div class="leaf">🌿</div><div class="leaf">🍃</div><div class="leaf">🌿</div><div class="leaf">🍃</div><div class="leaf">🌿</div></div>
  <div class="hero-inner">
    <span class="eyebrow">Slow-grown plants · Since 2017</span>
    <h1>Plants that grow with you</h1>
    <p>A small greenhouse in the city, raising uncommon houseplants with patience and care. Every plant comes with a handwritten note on its needs.</p>
    <a href="/shop/" class="btn btn-primary">Browse plants</a>
    <a href="/care/" class="btn btn-ghost">Care guides</a>
  </div>
</div>
<section>
  <h2 class="section-title">In the greenhouse</h2>
  <p class="section-sub">A small, slow-rotating selection.</p>
  <div class="grid">
    <div class="plant"><div class="img">🌿</div><div class="body"><h3>Monstera Albo</h3><div class="latin">Monstera deliciosa 'Albo-variegata'</div><div class="price">€ 120</div></div></div>
    <div class="plant"><div class="img">🍃</div><div class="body"><h3>Calathea Orbifolia</h3><div class="latin">Goeppertia orbifolia</div><div class="price">€ 38</div></div></div>
    <div class="plant"><div class="img">🌿</div><div class="body"><h3>Fiddle Leaf Fig</h3><div class="latin">Ficus lyrata</div><div class="price">€ 64</div></div></div>
    <div class="plant"><div class="img">🍃</div><div class="body"><h3>String of Pearls</h3><div class="latin">Curio rowleyanus</div><div class="price">€ 28</div></div></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Verdant <span>Botanical</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">A small greenhouse in the city.</p></div>
    <div><h4>Shop</h4><a href="/shop/">All plants</a><a href="/shop/">Pots</a></div>
    <div><h4>Learn</h4><a href="/care/">Care</a><a href="/workshops/">Workshops</a></div>
    <div><h4>Visit</h4><a href="/contact/">Greenhouse</a><a href="/contact/">Hours</a></div>
  </div>
  <div class="foot-bottom">© 2026 Verdant Botanical</div>
</footer>"""),
        "shop/index.html": _doc("Shop — Verdant Botanical", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">All plants</h2>
  <p class="section-sub">Grown in our greenhouse, shipped in biodegradable pots.</p>
  <div class="grid">
    <div class="plant"><div class="img">🌿</div><div class="body"><h3>Bird of Paradise</h3><div class="latin">Strelitzia nicolai</div><div class="price">€ 58</div></div></div>
    <div class="plant"><div class="img">🍃</div><div class="body"><h3>Rubber Plant</h3><div class="latin">Ficus elastica</div><div class="price">€ 32</div></div></div>
    <div class="plant"><div class="img">🌿</div><div class="body"><h3>Prayer Plant</h3><div class="latin">Maranta leuconeura</div><div class="price">€ 24</div></div></div>
    <div class="plant"><div class="img">🍃</div><div class="body"><h3>Pothos Marble Queen</h3><div class="latin">Epipremnum aureum</div><div class="price">€ 18</div></div></div>
    <div class="plant"><div class="img">🌿</div><div class="body"><h3>Philodendron Pink</h3><div class="latin">Philodendron erubescens</div><div class="price">€ 84</div></div></div>
    <div class="plant"><div class="img">🍃</div><div class="body"><h3>Snake Plant</h3><div class="latin">Dracaena trifasciata</div><div class="price">€ 22</div></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Verdant Botanical · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "care/index.html": _doc("Care — Verdant Botanical", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Care guides</h2>
  <p class="section-sub">Short notes, written by hand.</p>
  <div class="grid">
    <div class="plant"><div class="body"><h3>Light</h3><p style="color:var(--muted);font-size:.9rem">Bright, indirect. North or east windowsill is best.</p></div></div>
    <div class="plant"><div class="body"><h3>Water</h3><p style="color:var(--muted);font-size:.9rem">When the top 2 cm of soil is dry. Less in winter.</p></div></div>
    <div class="plant"><div class="body"><h3>Humidity</h3><p style="color:var(--muted);font-size:.9rem">50–70%. A pebble tray works wonders.</p></div></div>
    <div class="plant"><div class="body"><h3>Soil</h3><p style="color:var(--muted);font-size:.9rem">Three parts peat, one part perlite, one part bark.</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Verdant Botanical · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "workshops/index.html": _doc("Workshops — Verdant Botanical", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Workshops</h2>
  <p class="section-sub">Small groups, in the greenhouse.</p>
  <div class="grid">
    <div class="plant"><div class="body"><h3>Repotting 101</h3><p style="color:var(--muted);font-size:.9rem">Saturday mornings · € 35 · 2h</p></div></div>
    <div class="plant"><div class="body"><h3>Kokedama making</h3><p style="color:var(--muted);font-size:.9rem">First Sunday · € 48 · 3h</p></div></div>
    <div class="plant"><div class="body"><h3>Terrarium building</h3><p style="color:var(--muted);font-size:.9rem">Last Saturday · € 55 · 2.5h</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Verdant Botanical · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Verdant Botanical", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Visit us</h2>
  <p class="section-sub">The greenhouse is open Wednesday to Sunday.</p>
  <div class="grid" style="max-width:840px;margin:1rem auto">
    <div class="plant"><div class="body"><h3>Address</h3><p style="color:var(--muted);font-size:.9rem">14 Green Lane, Eastside</p></div></div>
    <div class="plant"><div class="body"><h3>Hours</h3><p style="color:var(--muted);font-size:.9rem">Wed–Sun · 10:00–18:00</p></div></div>
    <div class="plant"><div class="body"><h3>Email</h3><p style="color:var(--muted);font-size:.9rem">hello@verdant.example</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Verdant Botanical · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 9: Northwind Coffee — Coffee roastery • steam wisps
# =============================================================================
def create_northwind(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f1ebe1;--surface:#faf6ef;--text:#3a2c20;--muted:#8a7a68;--accent:#7a4a2b;--accent-2:#9c6b3f;--border:#e0d5c4}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.7}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(241,235,225,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Playfair Display',Georgia,serif;font-size:1.45rem;font-weight:700;letter-spacing:-.3px}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.5rem;flex-wrap:wrap}
nav a{font-size:.9rem;color:var(--muted);transition:color .25s;padding:.3rem 0}
nav a:hover{color:var(--accent)}
nav a.active{color:var(--accent)}
.btn{display:inline-block;padding:.8rem 1.9rem;border-radius:4px;font-size:.85rem;letter-spacing:.06em;font-weight:600;transition:all .3s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#5e381f;transform:translateY(-2px)}
.btn-ghost{border:1px solid var(--text);color:var(--text);margin-left:.5rem}
.btn-ghost:hover{background:var(--text);color:var(--bg)}
.hero{position:relative;min-height:74vh;display:flex;align-items:center;overflow:hidden;background:radial-gradient(ellipse at top right,rgba(122,74,43,.08),transparent 60%)}
.cup{position:absolute;right:8%;bottom:18%;width:160px;height:160px;background:linear-gradient(135deg,#7a4a2b,#5e381f);border-radius:0 0 80px 80px;box-shadow:0 16px 36px rgba(58,44,32,.2)}
.cup::before{content:"";position:absolute;top:0;left:0;right:0;height:30px;background:#3a2c20;border-radius:50%}
.wisp{position:absolute;bottom:50%;left:50%;width:8px;height:80px;background:linear-gradient(180deg,transparent,rgba(250,246,239,.4));border-radius:50%;transform-origin:bottom;animation:wisp 4s ease-in-out infinite;filter:blur(4px)}
.wisp:nth-child(2){left:42%;animation-delay:1s;animation-duration:5s}
.wisp:nth-child(3){left:58%;animation-delay:2s;animation-duration:4.5s}
@keyframes wisp{0%{transform:translate(-50%,0) scaleY(.4);opacity:0}30%{opacity:.8}100%{transform:translate(-50%,-120px) scaleY(1.6);opacity:0}}
.hero-inner{position:relative;z-index:2;padding:5rem 5%;max-width:680px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.22em;text-transform:uppercase;color:var(--accent);margin-bottom:1.25rem;display:block}
.hero h1{font-family:'Playfair Display',Georgia,serif;font-size:clamp(2.4rem,6vw,4.4rem);font-weight:700;line-height:1.05;margin-bottom:1.5rem;letter-spacing:-.5px}
.hero p{color:var(--muted);max-width:480px;margin-bottom:2.25rem;font-size:1.05rem}
section{padding:5rem 5%;max-width:1100px;margin:0 auto}
.section-title{font-family:'Playfair Display',Georgia,serif;font-size:2.2rem;font-weight:700;text-align:center;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{text-align:center;color:var(--muted);margin-bottom:3rem;font-size:.95rem;font-style:italic}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.5rem}
.bean{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.75rem;transition:transform .3s,box-shadow .3s}
.bean:hover{transform:translateY(-4px);box-shadow:0 12px 28px rgba(58,44,32,.08)}
.bean .origin{font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent-2);margin-bottom:.5rem}
.bean h3{font-family:'Playfair Display',Georgia,serif;font-size:1.4rem;font-weight:700;margin-bottom:.4rem}
.bean .notes{color:var(--muted);font-size:.88rem;margin-bottom:.85rem}
.bean .price{color:var(--accent);font-weight:600;font-size:1.1rem}
.menu-list{max-width:680px;margin:0 auto}
.menu-item{display:flex;justify-content:space-between;align-items:baseline;padding:1rem 0;border-bottom:1px solid var(--border)}
.menu-item h3{font-family:'Playfair Display',Georgia,serif;font-size:1.15rem;font-weight:600}
.menu-item .desc{display:block;color:var(--muted);font-size:.85rem;font-style:italic;margin-top:.2rem}
.menu-item .price{color:var(--accent);font-weight:600;white-space:nowrap;margin-left:1.5rem}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.9rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}.cup{display:none}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Northwind <span>Coffee</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/beans/">Beans</a>'
           '<a href="/menu/">Menu</a>'
           '<a href="/locations/">Locations</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Northwind Coffee — Roastery", f"""
{nav}
<div class="hero">
  <div class="cup"><div class="wisp"></div><div class="wisp"></div><div class="wisp"></div></div>
  <div class="hero-inner">
    <span class="eyebrow">Small-batch · Since 2015</span>
    <h1>Quiet coffee, slowly roasted</h1>
    <p>Three cafes, one roastery, and a small list of farms we have worked with for years. We roast on Mondays, ship on Tuesdays.</p>
    <a href="/beans/" class="btn btn-primary">Order beans</a>
    <a href="/menu/" class="btn btn-ghost">Cafe menu</a>
  </div>
</div>
<section>
  <h2 class="section-title">This week's beans</h2>
  <p class="section-sub">Roasted Monday, shipped Tuesday.</p>
  <div class="grid">
    <div class="bean"><div class="origin">Ethiopia · Yirgacheffe</div><h3>Konga Natural</h3><div class="notes">Bergamot, peach, jasmine</div><div class="price">€ 18 / 250g</div></div>
    <div class="bean"><div class="origin">Colombia · Huila</div><h3>El Tablón</h3><div class="notes">Brown sugar, cocoa, plum</div><div class="price">€ 16 / 250g</div></div>
    <div class="bean"><div class="origin">Guatemala · Acatenango</div><h3>Finca El Bosque</h3><div class="notes">Toffee, red apple, milk chocolate</div><div class="price">€ 17 / 250g</div></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Northwind <span>Coffee</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">Small-batch roastery and three quiet cafes.</p></div>
    <div><h4>Shop</h4><a href="/beans/">Beans</a><a href="/beans/">Subscriptions</a></div>
    <div><h4>Cafes</h4><a href="/locations/">Locations</a><a href="/menu/">Menu</a></div>
    <div><h4>Visit</h4><a href="/contact/">Contact</a><a href="/contact/">Hours</a></div>
  </div>
  <div class="foot-bottom">© 2026 Northwind Coffee Roasters</div>
</footer>"""),
        "beans/index.html": _doc("Beans — Northwind Coffee", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">All beans</h2>
  <p class="section-sub">Single-origin, roasted to order.</p>
  <div class="grid">
    <div class="bean"><div class="origin">Ethiopia</div><h3>Konga Natural</h3><div class="notes">Bergamot, peach, jasmine</div><div class="price">€ 18 / 250g</div></div>
    <div class="bean"><div class="origin">Colombia</div><h3>El Tablón</h3><div class="notes">Brown sugar, cocoa, plum</div><div class="price">€ 16 / 250g</div></div>
    <div class="bean"><div class="origin">Guatemala</div><h3>El Bosque</h3><div class="notes">Toffee, apple, chocolate</div><div class="price">€ 17 / 250g</div></div>
    <div class="bean"><div class="origin">Kenya</div><h3>Nyeri AA</h3><div class="notes">Blackcurrant, tomato, cane sugar</div><div class="price">€ 19 / 250g</div></div>
    <div class="bean"><div class="origin">Costa Rica</div><h3>Tarrazú Honey</h3><div class="notes">Honey, almond, citrus</div><div class="price">€ 18 / 250g</div></div>
    <div class="bean"><div class="origin">Blend</div><h3>Northwind House</h3><div class="notes">Hazelnut, milk chocolate, smooth</div><div class="price">€ 14 / 250g</div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Northwind Coffee Roasters · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "menu/index.html": _doc("Menu — Northwind Coffee", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Cafe menu</h2>
  <p class="section-sub">Espresso, filter, and a few things to eat.</p>
  <div class="menu-list">
    <div class="menu-item"><div><h3>Espresso</h3><span class="desc">Double shot, house blend</span></div><span class="price">€ 3</span></div>
    <div class="menu-item"><div><h3>Flat White</h3><span class="desc">5oz, silky microfoam</span></div><span class="price">€ 4</span></div>
    <div class="menu-item"><div><h3>Pour Over</h3><span class="desc">Single origin, V60</span></div><span class="price">€ 5</span></div>
    <div class="menu-item"><div><h3>Cold Brew</h3><span class="desc">18-hour steep</span></div><span class="price">€ 4.5</span></div>
    <div class="menu-item"><div><h3>Cinnamon Bun</h3><span class="desc">Baked daily in-house</span></div><span class="price">€ 4</span></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Northwind Coffee Roasters · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "locations/index.html": _doc("Locations — Northwind Coffee", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Our cafes</h2>
  <p class="section-sub">Three rooms, one roastery.</p>
  <div class="grid">
    <div class="bean"><h3>Roastery &amp; Cafe</h3><p style="color:var(--muted);font-size:.9rem">219 Mill Street · Daily 7–17</p></div>
    <div class="bean"><h3>Eastside Room</h3><p style="color:var(--muted);font-size:.9rem">14 Quay Lane · Daily 8–17</p></div>
    <div class="bean"><h3>Library Brew Bar</h3><p style="color:var(--muted);font-size:.9rem">City Library, 2F · Mon–Sat 9–17</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Northwind Coffee Roasters · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Northwind Coffee", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Say hello</h2>
  <p class="section-sub">Wholesale, subscriptions, or just a chat.</p>
  <div class="grid" style="max-width:780px;margin:1rem auto">
    <div class="bean"><h3>Email</h3><p style="color:var(--muted);font-size:.9rem">hello@northwind.example</p></div>
    <div class="bean"><h3>Wholesale</h3><p style="color:var(--muted);font-size:.9rem">trade@northwind.example</p></div>
    <div class="bean"><h3>Phone</h3><p style="color:var(--muted);font-size:.9rem">+44 20 7946 0958</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Northwind Coffee Roasters · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 10: Solstice Wellness — Spa & wellness • breathing pulse
# =============================================================================
def create_solstice(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f7f3ef;--surface:#fffdfb;--text:#423a36;--muted:#9a8d83;--accent:#b89888;--accent-2:#9caf98;--border:#ece3dc}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.75}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(247,243,239,.9);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.2rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.55rem;font-weight:500;letter-spacing:1px}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.5rem;flex-wrap:wrap}
nav a{font-size:.88rem;color:var(--muted);transition:color .25s;padding:.3rem 0}
nav a:hover{color:var(--accent)}
nav a.active{color:var(--accent)}
.btn{display:inline-block;padding:.85rem 2rem;border-radius:30px;font-size:.85rem;letter-spacing:.06em;font-weight:600;transition:all .3s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#a07f6e;transform:translateY(-2px);box-shadow:0 8px 22px rgba(184,152,136,.3)}
.btn-ghost{border:1px solid var(--border);color:var(--text);margin-left:.5rem}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.hero{position:relative;min-height:84vh;display:flex;align-items:center;justify-content:center;overflow:hidden;text-align:center}
.breath{position:absolute;top:50%;left:50%;width:480px;height:480px;transform:translate(-50%,-50%);border-radius:50%;background:radial-gradient(circle,rgba(184,152,136,.18),rgba(156,175,152,.08),transparent 70%);animation:breathe 9s ease-in-out infinite}
.breath::before{content:"";position:absolute;inset:60px;border-radius:50%;background:radial-gradient(circle,rgba(184,152,136,.22),transparent 70%);animation:breathe 9s ease-in-out infinite reverse}
@keyframes breathe{0%,100%{transform:translate(-50%,-50%) scale(.85);opacity:.6}50%{transform:translate(-50%,-50%) scale(1.1);opacity:.95}}
.hero-inner{position:relative;z-index:2;padding:5rem 5%;max-width:720px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.25em;text-transform:uppercase;color:var(--accent);margin-bottom:1.5rem;display:block}
.hero h1{font-family:'Cormorant Garamond',Georgia,serif;font-size:clamp(2.4rem,6vw,4.6rem);font-weight:400;line-height:1.1;margin-bottom:1.5rem;letter-spacing:-.3px}
.hero p{color:var(--muted);max-width:480px;margin:0 auto 2.25rem;font-size:1.05rem}
section{padding:5rem 5%;max-width:1100px;margin:0 auto}
.section-title{font-family:'Cormorant Garamond',Georgia,serif;font-size:2.2rem;font-weight:400;text-align:center;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{text-align:center;color:var(--muted);margin-bottom:3rem;font-size:.95rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.5rem}
.treatment{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:2rem;transition:transform .35s,box-shadow .35s}
.treatment:hover{transform:translateY(-4px);box-shadow:0 14px 32px rgba(66,58,54,.06)}
.treatment .duration{font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent-2);margin-bottom:.6rem}
.treatment h3{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.5rem;font-weight:500;margin-bottom:.5rem}
.treatment p{color:var(--muted);font-size:.9rem;margin-bottom:1rem}
.treatment .price{color:var(--accent);font-weight:600}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.9rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}.breath{width:320px;height:320px}}
"""
    nav = ('<header><a href="/" class="logo">Solstice <span>Wellness</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/treatments/">Treatments</a>'
           '<a href="/retreats/">Retreats</a>'
           '<a href="/practitioners/">Practitioners</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Solstice Wellness — Spa & Retreat", f"""
{nav}
<div class="hero">
  <div class="breath"></div>
  <div class="hero-inner">
    <span class="eyebrow">Wellness · Since 2018</span>
    <h1>Breathe in. <br>Stay a while.</h1>
    <p>A small day spa and retreat centre on the edge of the forest. No schedules, no music you didn't choose, no rush.</p>
    <a href="/treatments/" class="btn btn-primary">View treatments</a>
    <a href="/retreats/" class="btn btn-ghost">Upcoming retreats</a>
  </div>
</div>
<section>
  <h2 class="section-title">Treatments</h2>
  <p class="section-sub">Slow, considered, and tailored on the day.</p>
  <div class="grid">
    <div class="treatment"><div class="duration">90 min</div><h3>Forest massage</h3><p>Slow, grounding strokes with warm herbal oil.</p><div class="price">€ 130</div></div>
    <div class="treatment"><div class="duration">60 min</div><h3>Hydrating facial</h3><p>Plant-based, fragrance-free, suitable for sensitive skin.</p><div class="price">€ 95</div></div>
    <div class="treatment"><div class="duration">120 min</div><h3>Quiet ritual</h3><p>Sauna, cold plunge, rest, and a long massage.</p><div class="price">€ 210</div></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Solstice <span>Wellness</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">A quiet spa by the forest.</p></div>
    <div><h4>Spa</h4><a href="/treatments/">Treatments</a><a href="/practitioners/">Practitioners</a></div>
    <div><h4>Stays</h4><a href="/retreats/">Retreats</a><a href="/contact/">Bookings</a></div>
    <div><h4>Visit</h4><a href="/contact/">Directions</a><a href="/contact/">Hours</a></div>
  </div>
  <div class="foot-bottom">© 2026 Solstice Wellness</div>
</footer>"""),
        "treatments/index.html": _doc("Treatments — Solstice Wellness", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">All treatments</h2>
  <p class="section-sub">Booked by appointment, never overlapping.</p>
  <div class="grid">
    <div class="treatment"><div class="duration">90 min</div><h3>Forest massage</h3><p>Slow, grounding strokes with warm herbal oil.</p><div class="price">€ 130</div></div>
    <div class="treatment"><div class="duration">60 min</div><h3>Hydrating facial</h3><p>Plant-based, fragrance-free.</p><div class="price">€ 95</div></div>
    <div class="treatment"><div class="duration">120 min</div><h3>Quiet ritual</h3><p>Sauna, plunge, rest, massage.</p><div class="price">€ 210</div></div>
    <div class="treatment"><div class="duration">45 min</div><h3>Reflexology</h3><p>Pressure-point work on feet and lower legs.</p><div class="price">€ 75</div></div>
    <div class="treatment"><div class="duration">75 min</div><h3>Hot stone</h3><p>Basalt stones, slow heat, deep release.</p><div class="price">€ 115</div></div>
    <div class="treatment"><div class="duration">30 min</div><h3>Sound bath</h3><p>Bowls and gongs in the cedar room.</p><div class="price">€ 45</div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Solstice Wellness · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "retreats/index.html": _doc("Retreats — Solstice Wellness", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Upcoming retreats</h2>
  <p class="section-sub">Small groups · 6–10 guests.</p>
  <div class="grid">
    <div class="treatment"><div class="duration">3 days · April</div><h3>Stillness retreat</h3><p>Silence, walking, simple food.</p><div class="price">€ 540</div></div>
    <div class="treatment"><div class="duration">5 days · June</div><h3>Forest immersion</h3><p>Shinrin-yoku, journaling, breathwork.</p><div class="price">€ 890</div></div>
    <div class="treatment"><div class="duration">2 days · October</div><h3>Equinox reset</h3><p>Sauna, cold plunge, slow meals.</p><div class="price">€ 380</div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Solstice Wellness · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "practitioners/index.html": _doc("Practitioners — Solstice Wellness", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Practitioners</h2>
  <p class="section-sub">A small team, each with fifteen years or more of practice.</p>
  <div class="grid">
    <div class="treatment"><h3>Hana Lindqvist</h3><p style="color:var(--muted);font-size:.9rem">Massage therapist · 22 years</p></div>
    <div class="treatment"><h3>Owen Bright</h3><p style="color:var(--muted);font-size:.9rem">Acupuncturist · 18 years</p></div>
    <div class="treatment"><h3>Mira Aalto</h3><p style="color:var(--muted);font-size:.9rem">Facialist · 15 years</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Solstice Wellness · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Solstice Wellness", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Visit</h2>
  <p class="section-sub">By the forest, twenty minutes from the city.</p>
  <div class="grid" style="max-width:840px;margin:1rem auto">
    <div class="treatment"><h3>Address</h3><p style="color:var(--muted);font-size:.9rem">7 Forest Edge Lane</p></div>
    <div class="treatment"><h3>Hours</h3><p style="color:var(--muted);font-size:.9rem">Tue–Sun · 9:00–20:00</p></div>
    <div class="treatment"><h3>Bookings</h3><p style="color:var(--muted);font-size:.9rem">book@solstice.example</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Solstice Wellness · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 11: Atelier Meridian — Design studio • shape morph
# =============================================================================
def create_atelier(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#fbfaf6;--surface:#fff;--text:#1a1a1a;--muted:#7a7670;--accent:#a08850;--accent-2:#1a1a1a;--border:#e8e5dd}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.7}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(251,250,246,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.2rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.45rem;font-weight:500;letter-spacing:1.5px;text-transform:uppercase}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.75rem;flex-wrap:wrap}
nav a{font-size:.82rem;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;transition:color .25s;padding:.3rem 0}
nav a:hover{color:var(--text)}
nav a.active{color:var(--text);border-bottom:1px solid var(--accent)}
.btn{display:inline-block;padding:.85rem 2rem;border-radius:0;font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;font-weight:600;transition:all .3s}
.btn-primary{background:var(--text);color:var(--bg)}
.btn-primary:hover{background:var(--accent);transform:translateY(-2px)}
.btn-ghost{border:1px solid var(--text);color:var(--text);margin-left:.75rem}
.btn-ghost:hover{background:var(--text);color:var(--bg)}
.hero{position:relative;min-height:80vh;display:flex;align-items:center;overflow:hidden}
.morph{position:absolute;right:8%;top:50%;transform:translateY(-50%);width:380px;height:380px}
.morph .shape{position:absolute;inset:0;background:var(--accent);animation:morph 14s ease-in-out infinite}
.morph .shape:nth-child(2){background:var(--text);animation-delay:-3.5s;opacity:.6}
.morph .shape:nth-child(3){background:#c9b87a;animation-delay:-7s;opacity:.4}
@keyframes morph{0%,100%{border-radius:30% 70% 70% 30%/30% 30% 70% 70%;transform:rotate(0deg) scale(1)}33%{border-radius:60% 40% 30% 70%/60% 30% 70% 40%;transform:rotate(120deg) scale(.9)}66%{border-radius:30% 60% 70% 40%/50% 60% 30% 60%;transform:rotate(240deg) scale(1.05)}}
.hero-inner{position:relative;z-index:2;padding:5rem 5%;max-width:600px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.25em;text-transform:uppercase;color:var(--accent);margin-bottom:1.5rem;display:block}
.hero h1{font-family:'Cormorant Garamond',Georgia,serif;font-size:clamp(2.6rem,6vw,5rem);font-weight:400;line-height:1.05;margin-bottom:1.5rem;letter-spacing:-.5px}
.hero p{color:var(--muted);max-width:460px;margin-bottom:2.25rem;font-size:1.05rem}
section{padding:5rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-family:'Cormorant Garamond',Georgia,serif;font-size:2.4rem;font-weight:400;text-align:center;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{text-align:center;color:var(--muted);margin-bottom:3rem;font-size:.92rem;letter-spacing:.04em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:2rem}
.work{background:var(--surface);border:1px solid var(--border);transition:transform .4s;overflow:hidden}
.work:hover{transform:translateY(-6px)}
.work .img{height:240px;background:linear-gradient(135deg,#e8e5dd,#d4cfc0);position:relative;overflow:hidden}
.work .img::after{content:"";position:absolute;inset:0;background:linear-gradient(45deg,rgba(160,136,80,.1),rgba(26,26,26,.08))}
.work .body{padding:1.5rem}
.work .cat{font-size:.72rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);margin-bottom:.5rem}
.work h3{font-family:'Cormorant Garamond',Georgia,serif;font-size:1.5rem;font-weight:500;margin-bottom:.4rem}
.work p{color:var(--muted);font-size:.88rem}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.72rem;text-transform:uppercase;letter-spacing:.18em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.88rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.78rem;letter-spacing:.06em}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}.morph{display:none}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Atelier <span>Meridian</span></a>'
           '<nav>'
           '<a href="/" class="active">Index</a>'
           '<a href="/work/">Work</a>'
           '<a href="/studio/">Studio</a>'
           '<a href="/services/">Services</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Atelier Meridian — Design Studio", f"""
{nav}
<div class="hero">
  <div class="morph"><div class="shape"></div><div class="shape"></div><div class="shape"></div></div>
  <div class="hero-inner">
    <span class="eyebrow">Brand &amp; digital · Since 2014</span>
    <h1>Design that<br>says less.</h1>
    <p>Atelier Meridian is a six-person studio working on brand identity, editorial design, and quiet digital products for cultural institutions and small companies.</p>
    <a href="/work/" class="btn btn-primary">View work</a>
    <a href="/studio/" class="btn btn-ghost">The studio</a>
  </div>
</div>
<section>
  <h2 class="section-title">Selected work</h2>
  <p class="section-sub">A short list, by intention.</p>
  <div class="grid">
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Brand identity · 2025</div><h3>Maison Verre</h3><p>Identity for a small glass studio</p></div></div>
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Editorial · 2024</div><h3>Quietly Magazine</h3><p>Independent print quarterly</p></div></div>
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Digital product · 2024</div><h3>Folio Reader</h3><p>e-reader for long-form essays</p></div></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Atelier <span>Meridian</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.85rem;max-width:240px">Brand, editorial, digital.</p></div>
    <div><h4>Work</h4><a href="/work/">Projects</a><a href="/services/">Services</a></div>
    <div><h4>Studio</h4><a href="/studio/">About</a><a href="/contact/">Contact</a></div>
    <div><h4>Elsewhere</h4><a href="/contact/">Instagram</a><a href="/contact/">Are.na</a></div>
  </div>
  <div class="foot-bottom">© 2026 ATELIER MERIDIAN</div>
</footer>"""),
        "work/index.html": _doc("Work — Atelier Meridian", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Work</h2>
  <p class="section-sub">2020 — present.</p>
  <div class="grid">
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Brand · 2025</div><h3>Maison Verre</h3><p>Glass studio, Lyon</p></div></div>
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Editorial · 2024</div><h3>Quietly Magazine</h3><p>Print quarterly</p></div></div>
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Product · 2024</div><h3>Folio Reader</h3><p>Long-form e-reader</p></div></div>
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Brand · 2023</div><h3>Olive &amp; Co.</h3><p>Specialty grocer</p></div></div>
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Editorial · 2022</div><h3>Field Notes Journal</h3><p>Annual review</p></div></div>
    <div class="work"><div class="img"></div><div class="body"><div class="cat">Product · 2021</div><h3>Margin Notes</h3><p>Reading app</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 ATELIER MERIDIAN · <a href="/" style="color:var(--accent)">← index</a></div></footer>"""),
        "studio/index.html": _doc("Studio — Atelier Meridian", f"""
{nav}
<section style="padding-top:5rem;max-width:720px;margin:0 auto;text-align:center">
  <h2 class="section-title">Studio</h2>
  <p class="section-sub">Six people, one room, no open-plan.</p>
  <p style="color:var(--muted);line-height:1.9;margin:1.5rem 0">Atelier Meridian was founded in 2014 in a former bookbindery. We work on brand identity, editorial design, and digital products — usually for cultural institutions and small companies that share our preference for quiet work.</p>
  <p style="color:var(--muted);line-height:1.9">We take on six to eight projects a year. Every project is led by one of the partners. We do not pitch.</p>
</section>
<footer><div class="foot-bottom">© 2026 ATELIER MERIDIAN · <a href="/" style="color:var(--accent)">← index</a></div></footer>"""),
        "services/index.html": _doc("Services — Atelier Meridian", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Services</h2>
  <p class="section-sub">Three things, done well.</p>
  <div class="grid">
    <div class="work"><div class="body"><div class="cat">01</div><h3>Brand identity</h3><p>Strategy, naming, logo, type system, brand guidelines.</p></div></div>
    <div class="work"><div class="body"><div class="cat">02</div><h3>Editorial design</h3><p>Magazines, books, reports, annual reviews.</p></div></div>
    <div class="work"><div class="body"><div class="cat">03</div><h3>Digital product</h3><p>Design systems, websites, mobile apps.</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 ATELIER MERIDIAN · <a href="/" style="color:var(--accent)">← index</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Atelier Meridian", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Contact</h2>
  <p class="section-sub">We take on six to eight new projects each year.</p>
  <div class="grid" style="max-width:840px;margin:1rem auto">
    <div class="work"><div class="body"><h3>Email</h3><p style="color:var(--muted);font-size:.9rem">studio@meridian.example</p></div></div>
    <div class="work"><div class="body"><h3>Studio</h3><p style="color:var(--muted);font-size:.9rem">14 Rue des Bouquinistes, Lyon</p></div></div>
    <div class="work"><div class="body"><h3>Phone</h3><p style="color:var(--muted);font-size:.9rem">+33 4 72 00 11 22</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 ATELIER MERIDIAN · <a href="/" style="color:var(--accent)">← index</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 12: Harborline Logistics — Shipping & freight • wave motion
# =============================================================================
def create_harborline(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f5f7fa;--surface:#fff;--text:#1c2a3a;--muted:#6b7a8a;--accent:#2c4a6b;--accent-2:#5a8a9a;--border:#e0e6ee}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(245,247,250,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:1.25rem;font-weight:800;letter-spacing:-.3px}
.logo span{color:var(--accent)}
nav{display:flex;gap:.4rem;flex-wrap:wrap}
nav a{padding:.45rem .9rem;border-radius:6px;font-size:.88rem;color:var(--muted);transition:color .2s,background .2s}
nav a:hover{color:var(--text);background:var(--surface)}
nav a.active{color:var(--text);background:var(--surface);box-shadow:0 1px 3px rgba(28,42,58,.06)}
.btn{display:inline-block;padding:.75rem 1.6rem;border-radius:6px;font-size:.88rem;font-weight:600;transition:transform .2s,box-shadow .2s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(44,74,107,.25)}
.btn-ghost{border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.hero{position:relative;min-height:72vh;display:flex;align-items:center;overflow:hidden;background:linear-gradient(180deg,#f5f7fa 0%,#e8eef4 100%)}
.waves{position:absolute;bottom:0;left:0;right:0;height:200px;pointer-events:none}
.waves svg{width:100%;height:100%}
.waves .w1{animation:waveMove 12s linear infinite}
.waves .w2{animation:waveMove 18s linear infinite reverse;opacity:.5}
@keyframes waveMove{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.hero-inner{position:relative;z-index:2;padding:5rem 5%;max-width:680px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent-2);margin-bottom:1.25rem;display:block}
.hero h1{font-size:clamp(2rem,5vw,3.4rem);font-weight:800;letter-spacing:-1px;margin-bottom:1.25rem;line-height:1.1}
.hero p{color:var(--muted);max-width:520px;margin-bottom:2rem;font-size:1.05rem}
section{padding:5rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-size:1.8rem;font-weight:700;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{color:var(--muted);margin-bottom:3rem;font-size:.95rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:2rem;transition:transform .3s,box-shadow .3s}
.card:hover{transform:translateY(-4px);box-shadow:0 12px 28px rgba(28,42,58,.06)}
.card .icon{width:44px;height:44px;border-radius:10px;background:rgba(44,74,107,.08);display:flex;align-items:center;justify-content:center;font-size:1.3rem;color:var(--accent);margin-bottom:1rem}
.card h3{font-size:1.15rem;margin-bottom:.5rem}
.card p{color:var(--muted);font-size:.9rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:2rem;text-align:center;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:3rem 2rem;margin:2rem 0}
.stat .num{font-size:2.4rem;font-weight:800;color:var(--accent);letter-spacing:-1px}
.stat .label{color:var(--muted);font-size:.85rem;margin-top:.25rem}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.88rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    # SVG waves: two layered paths duplicated for seamless scroll.
    wave_path = "M0,80 C150,120 350,40 600,80 C850,120 1050,40 1200,80 L1200,200 L0,200 Z"
    waves_svg = (
        '<div class="waves"><svg viewBox="0 0 1200 200" preserveAspectRatio="none">'
        f'<path class="w2" fill="rgba(90,138,154,.18)" d="{wave_path}"/>'
        f'<path class="w1" fill="rgba(44,74,107,.22)" d="{wave_path}"/>'
        '</svg></div>'
    )

    nav = ('<header><a href="/" class="logo">Harbor<span>line</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/services/">Services</a>'
           '<a href="/fleet/">Fleet</a>'
           '<a href="/tracking/">Tracking</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Harborline Logistics — Shipping & Freight", f"""
{nav}
<div class="hero">
  {waves_svg}
  <div class="hero-inner">
    <span class="eyebrow">Freight forwarding · Since 2008</span>
    <h1>Quiet freight, on schedule</h1>
    <p>Harborline moves containers, breakbulk and project cargo across 38 ports. We answer the phone, we send the documents on time, we don't oversell.</p>
    <a href="/services/" class="btn btn-primary">Our services</a>
    <a href="/tracking/" class="btn btn-ghost">Track a shipment</a>
  </div>
</div>
<section>
  <h2 class="section-title">What we do</h2>
  <p class="section-sub">Three core services, run by the same team for fifteen years.</p>
  <div class="grid">
    <div class="card"><div class="icon">⚓</div><h3>Ocean freight</h3><p>FCL and LCL to 38 ports, weekly sailings on all major lanes.</p></div>
    <div class="card"><div class="icon">▣</div><h3>Project cargo</h3><p>Oversized and heavy-lift, with engineered stowage plans.</p></div>
    <div class="card"><div class="icon">⇄</div><h3>Customs</h3><p>In-house brokers in 12 countries, single point of contact.</p></div>
    <div class="card"><div class="icon">⌖</div><h3>Warehousing</h3><p>Bonded storage in 6 hubs, with cross-dock and distribution.</p></div>
  </div>
</section>
<section>
  <div class="stats">
    <div class="stat"><div class="num">38</div><div class="label">Ports served</div></div>
    <div class="stat"><div class="num">15</div><div class="label">Years in business</div></div>
    <div class="stat"><div class="num">99.4%</div><div class="label">On-time arrival</div></div>
    <div class="stat"><div class="num">24/7</div><div class="label">Operations desk</div></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Harbor<span>line</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">Quiet freight, on schedule.</p></div>
    <div><h4>Services</h4><a href="/services/">Ocean</a><a href="/services/">Project</a><a href="/services/">Customs</a></div>
    <div><h4>Tools</h4><a href="/tracking/">Tracking</a><a href="/fleet/">Fleet</a></div>
    <div><h4>Company</h4><a href="/contact/">Contact</a><a href="/contact/">Careers</a></div>
  </div>
  <div class="foot-bottom">© 2026 Harborline Logistics Ltd.</div>
</footer>"""),
        "services/index.html": _doc("Services — Harborline Logistics", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Services</h2>
  <p class="section-sub">Run by the same team for fifteen years.</p>
  <div class="grid">
    <div class="card"><div class="icon">⚓</div><h3>Ocean freight</h3><p>FCL and LCL to 38 ports, weekly sailings on all major lanes.</p></div>
    <div class="card"><div class="icon">▣</div><h3>Project cargo</h3><p>Oversized and heavy-lift, with engineered stowage plans.</p></div>
    <div class="card"><div class="icon">⇄</div><h3>Customs brokerage</h3><p>In-house brokers in 12 countries, single point of contact.</p></div>
    <div class="card"><div class="icon">⌖</div><h3>Warehousing</h3><p>Bonded storage in 6 hubs, with cross-dock and distribution.</p></div>
    <div class="card"><div class="icon">⎘</div><h3>Inland transport</h3><p>Trucking and rail from port to door, across Europe.</p></div>
    <div class="card"><div class="icon">⌬</div><h3>Insurance</h3><p>All-risk cargo cover, arranged in-house.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Harborline Logistics Ltd. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "fleet/index.html": _doc("Fleet — Harborline Logistics", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Fleet &amp; partners</h2>
  <p class="section-sub">Chartered and owned vessels, plus trusted carrier partners.</p>
  <div class="grid">
    <div class="card"><div class="icon">⚓</div><h3>MV Harbor Star</h3><p>1,800 TEU · owned · Northern Europe lane</p></div>
    <div class="card"><div class="icon">⚓</div><h3>MV Tiderunner</h3><p>2,400 TEU · owned · Mediterranean lane</p></div>
    <div class="card"><div class="icon">⚓</div><h3>MV Quietwater</h3><p>1,200 TEU · chartered · Transatlantic</p></div>
    <div class="card"><div class="icon">⎘</div><h3>Carrier partners</h3><p>Slot arrangements with 8 major lines.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Harborline Logistics Ltd. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "tracking/index.html": _doc("Tracking — Harborline Logistics", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Track a shipment</h2>
  <p class="section-sub">Enter your booking reference for live status.</p>
  <div class="card" style="max-width:560px;margin:1rem auto;text-align:center">
    <p style="color:var(--muted);font-size:.9rem;margin-bottom:1rem">Booking reference format: HBL-XXXXXX</p>
    <a href="/contact/" class="btn btn-primary">Contact ops desk</a>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Harborline Logistics Ltd. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Harborline Logistics", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Contact</h2>
  <p class="section-sub">24/7 operations desk — a person always answers.</p>
  <div class="grid" style="max-width:840px;margin:1rem auto">
    <div class="card"><div class="icon">⌖</div><h3>HQ</h3><p>17 Harbour Square, Rotterdam</p></div>
    <div class="card"><div class="icon">⌚</div><h3>Ops desk</h3><p>+31 10 234 5678 · 24/7</p></div>
    <div class="card"><div class="icon">✉</div><h3>Email</h3><p>ops@harborline.example</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Harborline Logistics Ltd. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 13: Quietude Library — Digital library • page flip
# =============================================================================
def create_quietude(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f3ecdd;--surface:#faf5e8;--text:#3a3026;--muted:#8a7c66;--accent:#5e6b4e;--accent-2:#8b6b3e;--border:#e0d5be}
body{font-family:'Crimson Text','Georgia',serif;background:var(--bg);color:var(--text);line-height:1.75;font-size:1.05rem}
body{font-family:'Inter',system-ui,sans-serif;font-size:1rem}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(243,236,221,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.2rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Crimson Text',Georgia,serif;font-size:1.55rem;font-weight:600;letter-spacing:.5px}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.5rem;flex-wrap:wrap}
nav a{font-size:.92rem;color:var(--muted);transition:color .25s;padding:.3rem 0}
nav a:hover{color:var(--accent)}
nav a.active{color:var(--accent)}
.btn{display:inline-block;padding:.8rem 1.9rem;border-radius:2px;font-size:.82rem;letter-spacing:.14em;text-transform:uppercase;font-weight:600;transition:all .3s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#4d5940;transform:translateY(-2px)}
.btn-ghost{border:1px solid var(--text);color:var(--text);margin-left:.5rem}
.btn-ghost:hover{background:var(--text);color:var(--bg)}
.hero{position:relative;min-height:74vh;display:flex;align-items:center;overflow:hidden}
.hero::before{content:"";position:absolute;inset:0;background:radial-gradient(ellipse at 80% 30%,rgba(139,107,62,.1),transparent 60%);pointer-events:none}
.book-stack{position:absolute;right:8%;top:50%;transform:translateY(-50%);width:240px;height:320px;perspective:1000px}
.book{position:absolute;inset:0;background:linear-gradient(135deg,var(--accent),#4d5940);border-radius:2px 6px 6px 2px;box-shadow:6px 6px 0 rgba(58,48,38,.15);transform-origin:left center;animation:flipBook 8s ease-in-out infinite}
.book:nth-child(2){background:linear-gradient(135deg,var(--accent-2),#6f522f);animation-delay:-1.5s;transform:translateX(-12px) rotateY(-8deg)}
.book:nth-child(3){background:linear-gradient(135deg,#7a5a4a,#5a3f30);animation-delay:-3s;transform:translateX(-24px) rotateY(-16deg)}
@keyframes flipBook{0%,100%{transform:rotateY(0deg)}50%{transform:rotateY(-18deg)}}
.hero-inner{position:relative;z-index:2;padding:5rem 5%;max-width:640px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.22em;text-transform:uppercase;color:var(--accent-2);margin-bottom:1.25rem;display:block}
.hero h1{font-family:'Crimson Text',Georgia,serif;font-size:clamp(2.4rem,6vw,4.4rem);font-weight:600;line-height:1.1;margin-bottom:1.5rem;letter-spacing:-.3px}
.hero p{color:var(--muted);max-width:480px;margin-bottom:2.25rem;font-size:1.05rem}
section{padding:5rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-family:'Crimson Text',Georgia,serif;font-size:2.2rem;font-weight:600;text-align:center;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{text-align:center;color:var(--muted);margin-bottom:3rem;font-size:.95rem;font-style:italic}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.5rem}
.book-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;overflow:hidden;transition:transform .4s,box-shadow .4s}
.book-card:hover{transform:translateY(-6px) rotate(-.5deg);box-shadow:0 16px 36px rgba(58,48,38,.1)}
.book-card .cover{height:200px;background:linear-gradient(135deg,#8b6b3e,#6f522f);position:relative;display:flex;align-items:center;justify-content:center;color:rgba(255,255,255,.7);font-family:'Crimson Text',Georgia,serif;font-size:1.1rem;font-style:italic;padding:1rem;text-align:center}
.book-card .cover.c2{background:linear-gradient(135deg,#5e6b4e,#4d5940)}
.book-card .cover.c3{background:linear-gradient(135deg,#7a5a4a,#5a3f30)}
.book-card .cover.c4{background:linear-gradient(135deg,#6b5b4e,#4e4035)}
.book-card .body{padding:1.25rem}
.book-card h3{font-family:'Crimson Text',Georgia,serif;font-size:1.2rem;font-weight:600;margin-bottom:.3rem}
.book-card .author{color:var(--muted);font-size:.85rem;font-style:italic}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.9rem;margin-bottom:.5rem;color:var(--text);transition:color .2s;font-family:'Crimson Text',Georgia,serif}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}.book-stack{display:none}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Quietude <span>Library</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/catalog/">Catalog</a>'
           '<a href="/reading/">Reading</a>'
           '<a href="/membership/">Membership</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Quietude Library — Digital Library", f"""
{nav}
<div class="hero">
  <div class="book-stack"><div class="book"></div><div class="book"></div><div class="book"></div></div>
  <div class="hero-inner">
    <span class="eyebrow">Public domain · Curated · Since 2019</span>
    <h1>Books that ask <br>to be read slowly.</h1>
    <p>Quietude is a small digital library of public-domain works, hand-picked and typeset for long-form reading. No ads, no log, no engagement metrics.</p>
    <a href="/catalog/" class="btn btn-primary">Browse the catalog</a>
    <a href="/reading/" class="btn btn-ghost">Reading room</a>
  </div>
</div>
<section>
  <h2 class="section-title">From the catalog</h2>
  <p class="section-sub">A few of this season's additions.</p>
  <div class="grid">
    <div class="book-card"><div class="cover">Letters from a Stoic</div><div class="body"><h3>Letters from a Stoic</h3><div class="author">Seneca · 65 CE</div></div></div>
    <div class="book-card"><div class="cover c2">Walden</div><div class="body"><h3>Walden</h3><div class="author">H. D. Thoreau · 1854</div></div></div>
    <div class="book-card"><div class="cover c3">The Story of My Life</div><div class="body"><h3>The Story of My Life</h3><div class="author">Helen Keller · 1903</div></div></div>
    <div class="book-card"><div class="cover c4">Afield and Afloat</div><div class="body"><h3>Afield and Afloat</h3><div class="author">John Burroughs · 1905</div></div></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Quietude <span>Library</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">A small library, curated by hand.</p></div>
    <div><h4>Read</h4><a href="/catalog/">Catalog</a><a href="/reading/">Reading room</a></div>
    <div><h4>Join</h4><a href="/membership/">Membership</a><a href="/contact/">Newsletter</a></div>
    <div><h4>About</h4><a href="/contact/">About</a><a href="/contact/">Sources</a></div>
  </div>
  <div class="foot-bottom">© 2026 Quietude Library Cooperative</div>
</footer>"""),
        "catalog/index.html": _doc("Catalog — Quietude Library", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Catalog</h2>
  <p class="section-sub">Public-domain works, hand-typeset.</p>
  <div class="grid">
    <div class="book-card"><div class="cover">Meditations</div><div class="body"><h3>Meditations</h3><div class="author">Marcus Aurelius · 180 CE</div></div></div>
    <div class="book-card"><div class="cover c2">Walden</div><div class="body"><h3>Walden</h3><div class="author">H. D. Thoreau · 1854</div></div></div>
    <div class="book-card"><div class="cover c3">Letters from a Stoic</div><div class="body"><h3>Letters from a Stoic</h3><div class="author">Seneca · 65 CE</div></div></div>
    <div class="book-card"><div class="cover c4">Afield and Afloat</div><div class="body"><h3>Afield and Afloat</h3><div class="author">John Burroughs · 1905</div></div></div>
    <div class="book-card"><div class="cover">The Story of My Life</div><div class="body"><h3>The Story of My Life</h3><div class="author">Helen Keller · 1903</div></div></div>
    <div class="book-card"><div class="cover c2">The Natural History</div><div class="body"><h3>Natural History</h3><div class="author">Pliny the Elder · 77 CE</div></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Quietude Library Cooperative · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "reading/index.html": _doc("Reading Room — Quietude Library", f"""
{nav}
<section style="padding-top:5rem;max-width:720px;margin:0 auto;text-align:center">
  <h2 class="section-title">Reading room</h2>
  <p class="section-sub">A quiet corner, no distractions.</p>
  <p style="color:var(--muted);line-height:1.9;margin:1.5rem 0">Every book in the library is typeset for long-form reading. Choose a serif or sans-serif body, adjust the line-height, pick a cream or paper-white background. Your settings stay with you across books.</p>
  <p style="color:var(--muted);line-height:1.9">There is no timer, no streak, no progress bar. The library will not email you about coming back.</p>
</section>
<footer><div class="foot-bottom">© 2026 Quietude Library Cooperative · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "membership/index.html": _doc("Membership — Quietude Library", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Membership</h2>
  <p class="section-sub">Free, and it stays free.</p>
  <div class="grid" style="max-width:840px;margin:1rem auto">
    <div class="book-card"><div class="body"><h3>Reader</h3><p style="color:var(--muted);font-size:.9rem">Free · full catalog · reading room</p></div></div>
    <div class="book-card"><div class="body"><h3>Patron</h3><p style="color:var(--muted);font-size:.9rem">€ 36/year · helps us typeset more books</p></div></div>
    <div class="book-card"><div class="body"><h3>Benefactor</h3><p style="color:var(--muted);font-size:.9rem">€ 240/year · sponsors one new edition</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Quietude Library Cooperative · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Quietude Library", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Contact</h2>
  <p class="section-sub">Book suggestions, errata, and quiet hellos.</p>
  <div class="grid" style="max-width:780px;margin:1rem auto">
    <div class="book-card"><div class="body"><h3>Email</h3><p style="color:var(--muted);font-size:.9rem">hello@quietude.example</p></div></div>
    <div class="book-card"><div class="body"><h3>Suggestions</h3><p style="color:var(--muted);font-size:.9rem">suggest@quietude.example</p></div></div>
    <div class="book-card"><div class="body"><h3>Errata</h3><p style="color:var(--muted);font-size:.9rem">errata@quietude.example</p></div></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Quietude Library Cooperative · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 14: Mensara Consulting — Strategy consulting • slide reveal
# =============================================================================
def create_mensara(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#fcfcfa;--surface:#fff;--text:#1c2330;--muted:#7a8090;--accent:#3a4f6b;--accent-2:#9a8a4a;--border:#e8e8e0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.7}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(252,252,250,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1.2rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Playfair Display',Georgia,serif;font-size:1.4rem;font-weight:600;letter-spacing:1px}
.logo span{color:var(--accent)}
nav{display:flex;gap:1.75rem;flex-wrap:wrap}
nav a{font-size:.85rem;color:var(--muted);transition:color .25s;padding:.3rem 0;letter-spacing:.04em}
nav a:hover{color:var(--accent)}
nav a.active{color:var(--accent)}
.btn{display:inline-block;padding:.85rem 2rem;border-radius:2px;font-size:.82rem;letter-spacing:.14em;text-transform:uppercase;font-weight:600;transition:all .3s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#2c3e57;transform:translateY(-2px);box-shadow:0 8px 22px rgba(58,79,107,.2)}
.btn-ghost{border:1px solid var(--text);color:var(--text);margin-left:.75rem}
.btn-ghost:hover{background:var(--text);color:var(--bg)}
.hero{position:relative;min-height:80vh;display:flex;align-items:center;overflow:hidden}
.slide-panel{position:absolute;right:0;top:0;bottom:0;width:42%;background:var(--accent);transform:translateX(40%);animation:slideIn 1.4s .4s cubic-bezier(.2,.7,.2,1) forwards;z-index:1}
.slide-panel::before{content:"";position:absolute;left:0;top:20%;bottom:20%;width:1px;background:rgba(255,255,255,.3)}
@keyframes slideIn{to{transform:translateX(0)}}
.slide-num{position:absolute;right:5%;top:50%;transform:translateY(-50%);color:rgba(255,255,255,.85);font-family:'Playfair Display',Georgia,serif;font-size:8rem;font-weight:300;line-height:1;letter-spacing:-4px;opacity:0;animation:fadeIn 1s 1.4s forwards;z-index:2}
@keyframes fadeIn{to{opacity:1}}
.hero-inner{position:relative;z-index:3;padding:5rem 5%;max-width:580px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.25em;text-transform:uppercase;color:var(--accent);margin-bottom:1.5rem;display:block}
.hero h1{font-family:'Playfair Display',Georgia,serif;font-size:clamp(2.4rem,5.5vw,4.2rem);font-weight:600;line-height:1.1;margin-bottom:1.5rem;letter-spacing:-.5px}
.hero p{color:var(--muted);max-width:460px;margin-bottom:2.25rem;font-size:1.05rem}
section{padding:5rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-family:'Playfair Display',Georgia,serif;font-size:2.2rem;font-weight:600;text-align:center;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{text-align:center;color:var(--muted);margin-bottom:3rem;font-size:.95rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);padding:2rem;transition:transform .3s,box-shadow .3s}
.card:hover{transform:translateY(-4px);box-shadow:0 12px 28px rgba(28,35,48,.06)}
.card .num{font-family:'Playfair Display',Georgia,serif;font-size:2rem;color:var(--accent-2);font-weight:600;line-height:1;margin-bottom:.85rem}
.card h3{font-size:1.15rem;margin-bottom:.5rem}
.card p{color:var(--muted);font-size:.9rem}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:2rem;text-align:center;border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:2.5rem 0;margin:2rem 0}
.stat .num{font-family:'Playfair Display',Georgia,serif;font-size:2.6rem;color:var(--accent);font-weight:600;letter-spacing:-1px}
.stat .label{color:var(--muted);font-size:.85rem;margin-top:.25rem}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.9rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}.slide-panel{display:none}.slide-num{display:none}nav{display:none}}
"""
    nav = ('<header><a href="/" class="logo">Mensara <span>Consulting</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/expertise/">Expertise</a>'
           '<a href="/cases/">Cases</a>'
           '<a href="/team/">Team</a>'
           '<a href="/contact/">Contact</a>'
           '</nav></header>')

    pages = {
        "index.html": _doc("Mensara Consulting — Strategy Consulting", f"""
{nav}
<div class="hero">
  <div class="slide-panel"></div>
  <div class="slide-num">14</div>
  <div class="hero-inner">
    <span class="eyebrow">Strategy consulting · Since 2011</span>
    <h1>Strategy, written <br>in plain language.</h1>
    <p>Mensara is a small strategy consultancy working with mid-sized companies on growth, pricing, and operational redesign. We write short reports, give clear recommendations, and stay until the work is done.</p>
    <a href="/expertise/" class="btn btn-primary">Our expertise</a>
    <a href="/cases/" class="btn btn-ghost">Case studies</a>
  </div>
</div>
<section>
  <h2 class="section-title">What we do</h2>
  <p class="section-sub">Three practices, one small team.</p>
  <div class="grid">
    <div class="card"><div class="num">01</div><h3>Growth strategy</h3><p>Where to play, how to win, what to stop doing.</p></div>
    <div class="card"><div class="num">02</div><h3>Pricing</h3><p>Price architecture, value modelling, sales force enablement.</p></div>
    <div class="card"><div class="num">03</div><h3>Operations</h3><p>Process redesign, organisation, cost-to-serve.</p></div>
  </div>
</section>
<section>
  <div class="stats-row">
    <div class="stat"><div class="num">14</div><div class="label">Years in practice</div></div>
    <div class="stat"><div class="num">82</div><div class="label">Engagements delivered</div></div>
    <div class="stat"><div class="num">9</div><div class="label">Consultants</div></div>
    <div class="stat"><div class="num">3</div><div class="label">Offices</div></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Mensara <span>Consulting</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">Strategy in plain language.</p></div>
    <div><h4>Practice</h4><a href="/expertise/">Expertise</a><a href="/cases/">Cases</a></div>
    <div><h4>Firm</h4><a href="/team/">Team</a><a href="/contact/">Contact</a></div>
    <div><h4>Offices</h4><a href="/contact/">Zurich</a><a href="/contact/">Singapore</a></div>
  </div>
  <div class="foot-bottom">© 2026 Mensara Consulting AG</div>
</footer>"""),
        "expertise/index.html": _doc("Expertise — Mensara Consulting", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Expertise</h2>
  <p class="section-sub">Three practices, working closely together.</p>
  <div class="grid">
    <div class="card"><div class="num">01</div><h3>Growth strategy</h3><p>Market assessment, segment choice, channel architecture, M&amp;A screening.</p></div>
    <div class="card"><div class="num">02</div><h3>Pricing</h3><p>Price architecture, value modelling, competitive intelligence, sales enablement.</p></div>
    <div class="card"><div class="num">03</div><h3>Operations</h3><p>Process redesign, organisation design, cost-to-serve, footprint.</p></div>
    <div class="card"><div class="num">04</div><h3>Due diligence</h3><p>Commercial DD for mid-market PE, both buy-side and sell-side.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Mensara Consulting AG · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "cases/index.html": _doc("Cases — Mensara Consulting", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Selected cases</h2>
  <p class="section-sub">Anonymised, with client permission.</p>
  <div class="grid">
    <div class="card"><div class="num">01</div><h3>Specialty materials</h3><p>Growth strategy for a € 280M specialty chemicals firm. Three new segments identified, two divested.</p></div>
    <div class="card"><div class="num">02</div><h3>Industrial services</h3><p>Pricing redesign for a services business with 14 regional units. EBIT margin +3.1 pp in 18 months.</p></div>
    <div class="card"><div class="num">03</div><h3>Consumer durables</h3><p>Operations turnaround for a kitchen-appliance maker. Lead times halved, on-time delivery from 78% to 96%.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Mensara Consulting AG · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "team/index.html": _doc("Team — Mensara Consulting", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Team</h2>
  <p class="section-sub">Nine consultants, three offices.</p>
  <div class="grid">
    <div class="card"><h3>Dr. Anika Weber</h3><p>Managing partner · Zurich</p></div>
    <div class="card"><h3>Henri Lavoisier</h3><p>Partner · Paris</p></div>
    <div class="card"><h3>Wei-Lin Tan</h3><p>Partner · Singapore</p></div>
    <div class="card"><h3>Sofia Marchetti</h3><p>Principal · Zurich</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Mensara Consulting AG · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Mensara Consulting", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Contact</h2>
  <p class="section-sub">We take on eight to ten engagements a year.</p>
  <div class="grid" style="max-width:840px;margin:1rem auto">
    <div class="card"><h3>Zurich</h3><p style="color:var(--muted);font-size:.9rem">Bahnhofstrasse 14 · +41 44 234 5678</p></div>
    <div class="card"><h3>Singapore</h3><p style="color:var(--muted);font-size:.9rem">1 Raffles Place · +65 6234 5678</p></div>
    <div class="card"><h3>Email</h3><p style="color:var(--muted);font-size:.9rem">partners@mensara.example</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Mensara Consulting AG · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 15: Cascade Analytics — Data analytics SaaS • data flow
# =============================================================================
def create_cascade(web_root: Path) -> None:
    css = """
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f6f8fa;--surface:#fff;--text:#1f2937;--muted:#6b7280;--accent:#4f46e5;--accent-2:#0d9488;--border:#e5e7eb}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;background:rgba(246,248,250,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--border);z-index:50;padding:1rem 5%;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:1.25rem;font-weight:800;letter-spacing:-.4px}
.logo span{color:var(--accent)}
nav{display:flex;gap:.4rem;flex-wrap:wrap}
nav a{padding:.45rem .9rem;border-radius:6px;font-size:.88rem;color:var(--muted);transition:color .2s,background .2s}
nav a:hover{color:var(--text);background:var(--surface)}
nav a.active{color:var(--text);background:var(--surface);box-shadow:0 1px 3px rgba(31,41,55,.06)}
.btn{display:inline-block;padding:.7rem 1.5rem;border-radius:8px;font-size:.88rem;font-weight:600;transition:transform .2s,box-shadow .2s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(79,70,229,.25)}
.btn-ghost{border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.hero{position:relative;min-height:74vh;display:flex;align-items:center;overflow:hidden}
.flow-bg{position:absolute;inset:0;pointer-events:none;overflow:hidden}
.flow-bg svg{width:100%;height:100%;position:absolute;inset:0}
.flow-line{fill:none;stroke-width:1.5;stroke-dasharray:8 12;animation:flow 4s linear infinite}
@keyframes flow{from{stroke-dashoffset:0}to{stroke-dashoffset:-40}}
.hero-inner{position:relative;z-index:2;padding:5rem 5%;max-width:680px}
.hero .eyebrow{font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);background:rgba(79,70,229,.08);padding:.4rem 1rem;border-radius:99px;margin-bottom:1.5rem;display:inline-block}
.hero h1{font-size:clamp(2rem,5vw,3.4rem);font-weight:800;letter-spacing:-1px;margin-bottom:1.25rem;line-height:1.1}
.hero h1 .grad{background:linear-gradient(120deg,var(--accent),var(--accent-2));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--muted);max-width:540px;margin-bottom:2rem;font-size:1.05rem}
section{padding:5rem 5%;max-width:1200px;margin:0 auto}
.section-title{font-size:1.8rem;font-weight:700;margin-bottom:.5rem;letter-spacing:-.3px}
.section-sub{color:var(--muted);margin-bottom:3rem;font-size:.95rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.75rem;transition:transform .3s,box-shadow .3s}
.card:hover{transform:translateY(-4px);box-shadow:0 12px 28px rgba(31,41,55,.06)}
.card .icon{width:42px;height:42px;border-radius:10px;background:rgba(79,70,229,.08);display:flex;align-items:center;justify-content:center;font-size:1.2rem;color:var(--accent);margin-bottom:1rem}
.card h3{font-size:1.1rem;margin-bottom:.5rem}
.card p{color:var(--muted);font-size:.9rem}
.chart{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:2rem;margin-top:1.5rem}
.bar-row{display:flex;align-items:flex-end;gap:.75rem;height:180px;padding-top:1rem}
.bar{flex:1;background:linear-gradient(180deg,var(--accent),var(--accent-2));border-radius:6px 6px 0 0;animation:grow 1.4s .2s cubic-bezier(.2,.7,.2,1) backwards;transform-origin:bottom}
@keyframes grow{from{transform:scaleY(0)}to{transform:scaleY(1)}}
.bar-labels{display:flex;gap:.75rem;margin-top:.5rem;font-size:.78rem;color:var(--muted)}
.bar-labels span{flex:1;text-align:center}
footer{background:var(--surface);border-top:1px solid var(--border);padding:3rem 5%;margin-top:4rem}
footer .grid{grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem;display:grid}
footer h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-bottom:1rem;font-weight:600}
footer a{display:block;font-size:.88rem;margin-bottom:.5rem;color:var(--text);transition:color .2s}
footer a:hover{color:var(--accent)}
.foot-bottom{border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;text-align:center;color:var(--muted);font-size:.82rem}
@media(max-width:720px){footer .grid{grid-template-columns:1fr 1fr}nav{display:none}}
"""
    # SVG flow lines — three diagonal "data pipes" with animated dashes.
    flow_svg = (
        '<div class="flow-bg"><svg viewBox="0 0 1200 600" preserveAspectRatio="xMidYMid slice">'
        '<path class="flow-line" stroke="rgba(79,70,229,.25)" d="M-50,120 C200,80 400,180 700,140 C900,110 1100,180 1250,160"/>'
        '<path class="flow-line" stroke="rgba(13,148,136,.22)" d="M-50,300 C200,260 400,360 700,320 C900,290 1100,360 1250,340" style="animation-duration:6s"/>'
        '<path class="flow-line" stroke="rgba(79,70,229,.18)" d="M-50,480 C200,440 400,540 700,500 C900,470 1100,540 1250,520" style="animation-duration:5s"/>'
        '<circle cx="120" cy="115" r="6" fill="rgba(79,70,229,.4)"/>'
        '<circle cx="430" cy="172" r="5" fill="rgba(13,148,136,.4)"/>'
        '<circle cx="780" cy="135" r="6" fill="rgba(79,70,229,.4)"/>'
        '<circle cx="1080" cy="178" r="4" fill="rgba(13,148,136,.4)"/>'
        '</svg></div>'
    )

    nav = ('<header><a href="/" class="logo">Cascade <span>Analytics</span></a>'
           '<nav>'
           '<a href="/" class="active">Home</a>'
           '<a href="/product/">Product</a>'
           '<a href="/solutions/">Solutions</a>'
           '<a href="/pricing/">Pricing</a>'
           '<a href="/contact/">Contact</a>'
           '</nav>'
           '<a href="/contact/" class="btn btn-primary">Start free</a></header>')

    pages = {
        "index.html": _doc("Cascade Analytics — Data Analytics SaaS", f"""
{nav}
<div class="hero">
  {flow_svg}
  <div class="hero-inner">
    <span class="eyebrow">v4 · Now with live pipelines</span>
    <h1>Quiet analytics for <span class="grad">busy teams</span></h1>
    <p>Cascade connects to your warehouse, models metrics once, and gives every team the same numbers. No dashboards-of-dashboards, no three definitions of "revenue".</p>
    <a href="/product/" class="btn btn-primary">See the product</a>
    <a href="/pricing/" class="btn btn-ghost">View pricing</a>
  </div>
</div>
<section>
  <h2 class="section-title">One model. Every report.</h2>
  <p class="section-sub">Define a metric once. Cascade keeps it consistent everywhere.</p>
  <div class="grid">
    <div class="card"><div class="icon">⇄</div><h3>Live pipelines</h3><p>Streaming ingestion from Postgres, Snowflake, BigQuery, and S3.</p></div>
    <div class="card"><div class="icon">▤</div><h3>Semantic layer</h3><p>Define metrics once in YAML. Every dashboard uses the same definition.</p></div>
    <div class="card"><div class="icon">|RF</div><h3>Alerts</h3><p>Threshold and anomaly alerts, sent quietly to Slack or email.</p></div>
    <div class="card"><div class="icon">⌖</div><h3>Embedded</h3><p>Drop a metric, chart, or full dashboard into your own product.</p></div>
  </div>
  <div class="chart">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem"><strong>Weekly active users</strong><span style="color:var(--accent-2);font-size:.85rem">+12.4% vs last week</span></div>
    <div class="bar-row">
      <div class="bar" style="height:42%;animation-delay:.05s"></div>
      <div class="bar" style="height:58%;animation-delay:.1s"></div>
      <div class="bar" style="height:50%;animation-delay:.15s"></div>
      <div class="bar" style="height:72%;animation-delay:.2s"></div>
      <div class="bar" style="height:64%;animation-delay:.25s"></div>
      <div class="bar" style="height:85%;animation-delay:.3s"></div>
      <div class="bar" style="height:96%;animation-delay:.35s"></div>
    </div>
    <div class="bar-labels"><span>Mon</span><span>Tue</span><span>Wed</span><span>Thu</span><span>Fri</span><span>Sat</span><span>Sun</span></div>
  </div>
</section>
<footer>
  <div class="grid">
    <div><div class="logo">Cascade <span>Analytics</span></div><p style="margin-top:1rem;color:var(--muted);font-size:.88rem;max-width:240px">Quiet analytics for busy teams.</p></div>
    <div><h4>Product</h4><a href="/product/">Features</a><a href="/pricing/">Pricing</a></div>
    <div><h4>Solutions</h4><a href="/solutions/">By team</a><a href="/solutions/">By stack</a></div>
    <div><h4>Company</h4><a href="/contact/">Contact</a><a href="/contact/">About</a></div>
  </div>
  <div class="foot-bottom">© 2026 Cascade Analytics Inc.</div>
</footer>"""),
        "product/index.html": _doc("Product — Cascade Analytics", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">The product</h2>
  <p class="section-sub">Pipelines, semantic layer, dashboards, alerts — in one calm tool.</p>
  <div class="grid">
    <div class="card"><div class="icon">⇄</div><h3>Pipelines</h3><p>Streaming and batch ingestion, with schema drift handled automatically.</p></div>
    <div class="card"><div class="icon">▤</div><h3>Semantic layer</h3><p>Metrics defined in YAML, version-controlled, reviewed in PRs.</p></div>
    <div class="card"><div class="icon">|RF</div><h3>Alerts</h3><p>Threshold and anomaly detection, with quiet hours.</p></div>
    <div class="card"><div class="icon">⌖</div><h3>Embedded</h3><p>Customer-facing analytics without building a BI tool.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Cascade Analytics Inc. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "solutions/index.html": _doc("Solutions — Cascade Analytics", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Solutions</h2>
  <p class="section-sub">By team, by stack.</p>
  <div class="grid">
    <div class="card"><div class="icon">▤</div><h3>Finance</h3><p>Close the books faster, with one source of truth.</p></div>
    <div class="card"><div class="icon">|RF</div><h3>Marketing</h3><p>Attribution that matches finance, finally.</p></div>
    <div class="card"><div class="icon">⇄</div><h3>Product</h3><p>Funnels, retention, feature adoption — same definitions.</p></div>
    <div class="card"><div class="icon">⌖</div><h3>Data team</h3><p>A semantic layer your stakeholders can trust.</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Cascade Analytics Inc. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "pricing/index.html": _doc("Pricing — Cascade Analytics", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Pricing</h2>
  <p class="section-sub">Per metric, not per seat.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr))">
    <div class="card" style="text-align:center"><h3>Starter</h3><div style="font-size:2.4rem;font-weight:800;color:var(--accent);margin:.5rem 0">$0</div><p style="color:var(--muted);font-size:.9rem">25 metrics · 1 source</p></div>
    <div class="card" style="text-align:center;border-color:var(--accent);box-shadow:0 12px 28px rgba(79,70,229,.12)"><h3>Team</h3><div style="font-size:2.4rem;font-weight:800;color:var(--accent);margin:.5rem 0">$99<small style="font-size:1rem;color:var(--muted);font-weight:500">/mo</small></div><p style="color:var(--muted);font-size:.9rem">250 metrics · 5 sources · alerts</p></div>
    <div class="card" style="text-align:center"><h3>Enterprise</h3><div style="font-size:2.4rem;font-weight:800;color:var(--accent);margin:.5rem 0">Custom</div><p style="color:var(--muted);font-size:.9rem">Unlimited · SSO · SLA · embedded</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Cascade Analytics Inc. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
        "contact/index.html": _doc("Contact — Cascade Analytics", f"""
{nav}
<section style="padding-top:5rem">
  <h2 class="section-title">Talk to us</h2>
  <p class="section-sub">Sales, support, or just a question — we reply within a day.</p>
  <div class="grid" style="max-width:840px;margin:1rem auto">
    <div class="card"><div class="icon">✉</div><h3>Email</h3><p>hello@cascade.example</p></div>
    <div class="card"><div class="icon">⌖</div><h3>Office</h3><p>410 Townsend Street, SF</p></div>
    <div class="card"><div class="icon">⌚</div><h3>Hours</h3><p>Mon–Fri, 9–18 PT</p></div>
  </div>
</section>
<footer><div class="foot-bottom">© 2026 Cascade Analytics Inc. · <a href="/" style="color:var(--accent)">Back home</a></div></footer>"""),
    }
    _emit_site(web_root, css, pages)


# =============================================================================
#  ШАБЛОН 16: Fake Login — страница «Доступ к серверу» с капчей
# =============================================================================
# Используется ТОЛЬКО в профиле «CDN masking» (скрытое меню). Не входит в
# стандартный выбор шаблонов 1..15 (create_website() в nginx_setup.py
# ограничивает индекс 1..15). Активируется через cdn_masking_mode=True
# в setup_nginx_final(), который явно вызывает create_fake_login().
#
# HTML перенесён 1:1 из base64-декодированного decoy #1 файла
# install-caddy-node.sh (DECOYS[0]). Оригинал — одностраничная fake-login
# форма с JS-капчей («Сколько будет X+Y?») и toast-уведомлением
# «Неверный логин или пароль». Любая опечатка при переносе = баг.
def create_fake_login(web_root: Path) -> None:
    """Создаёт одностраничную заглушку «Доступ к серверу» с капчей.

    Используется только в профиле CDN masking. В отличие от шаблонов 1..15,
    здесь ОДНА страница (index.html) без подстраниц и без style.css —
    стили инлайнены в <head>, т.к. заглушка должна быть самодостаточной
    (CDN может не отдавать /style.css при некоторых конфигурациях).
    """
    web_root.mkdir(parents=True, exist_ok=True)
    # Контент перенесён 1:1 из decoy #1 install-caddy-node.sh.
    # Не меняем ни одного байта — это рабочий HTML, откалиброванный
    # против DPI-сканеров.
    html = _FAKE_LOGIN_HTML
    (web_root / "index.html").write_text(html, encoding="utf-8")
    # robots.txt — на случай если краулеры CDN/поисковики зайдут.
    (web_root / "robots.txt").write_text("User-agent: *\nDisallow: /\n",
                                          encoding="utf-8")


_FAKE_LOGIN_HTML: str = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Доступ к серверу</title>
<style>

*{ box-sizing:border-box; }
html,body{ height:100%; }
body{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px;
  font-family:ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, "Noto Sans", "Liberation Sans", sans-serif; color:#f2f2ff; background:#07060d;  }
.stage{ position:relative; z-index:1; display:flex;  width:min(460px,94vw);  }
.aside{ display:none; }
.card{ position:relative; flex:1; min-width:0; background:#0d0b18; border:1px solid #ff2e8855; border-radius:16px; overflow:hidden; box-shadow:0 0 40px -8px rgba(255,46,136,.5), 0 30px 60px -25px #000;  }
.card-head{ display:flex; align-items:center; gap:10px; padding:14px 18px; border-bottom:1px solid #ff2e8833; background:rgba(255,255,255,.02); }
.dot{ width:11px; height:11px; border-radius:50%; flex:0 0 auto; display:inline-block; }
.dot.r{ background:#ff5f57; } .dot.y{ background:#febc2e; } .dot.g{ background:#28c840; }
.path{ margin-left:8px; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size:12px; color:#6b7099; letter-spacing:.3px; }
.status-pill{ margin-left:auto; display:inline-flex; align-items:center; gap:6px; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size:11px; color:#ff2e88; background:#ff2e881a; border:1px solid #ff2e8866; padding:3px 9px; border-radius:999px; }
.status-pill .led{ width:6px; height:6px; border-radius:50%; background:#ff2e88; box-shadow:0 0 10px #ff2e88; }
.card-body{ padding:26px 26px 22px; }
.eyebrow{ display:block; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size:11px; text-transform:uppercase; letter-spacing:2px; color:#ff2e88; margin:0 0 10px; }
h1{ margin:0 0 8px; font-size:26px; font-weight:650; font-family:ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, "Noto Sans", "Liberation Sans", sans-serif; color:#fff; letter-spacing:.2px; }
.subtitle{ margin:0 0 24px; color:#9aa0c0; line-height:1.45; font-size:14px; }
.field{ margin:16px 0; }
label{ display:block; font-size:12px; font-weight:600; color:#9aa0c0; margin:0 0 8px; }
.input{ display:flex; align-items:center; gap:11px; padding:12px 14px; background:#0a0814; border:1px solid #ff2e8840; border-radius:10px; transition:border-color .15s ease, box-shadow .15s ease, background .15s ease; }
.input:focus-within{ border-color:#ff2e88; box-shadow:0 0 0 3px #ff2e8833, 0 0 14px rgba(255,46,136,.5); }
.icon{ width:18px; height:18px; flex:0 0 auto; color:#6b7099; }
.input:focus-within .icon{ color:#ff2e88; }
input{ width:100%; border:0; background:transparent; color:#f2f2ff; font-size:14px; font-family:ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, "Noto Sans", "Liberation Sans", sans-serif; outline:none; }
input::placeholder{ color:#5a5f85; }
.btn{ margin-top:22px; width:100%; border:0; padding:13px 14px; border-radius:10px; color:#07060d; font-weight:700; font-size:14px; letter-spacing:.3px; cursor:pointer; font-family:ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, "Noto Sans", "Liberation Sans", sans-serif; background:#ff2e88; box-shadow:0 0 22px -2px rgba(255,46,136,.5); transition:transform .06s ease, filter .15s ease, box-shadow .15s ease; }
.btn:hover{ filter:brightness(1.05);  }
.btn:active{ transform:translateY(1px); }
.hint{ margin:16px 0 0; font-size:12px; color:#6b7099; text-align:center; }
.captcha-box{ padding:15px; border-radius:10px; background:#0a0814; border:1px dashed #ff2e8855; }
.captcha-top{ display:flex; align-items:center; justify-content:space-between; gap:12px; }
.captcha-label{ font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#9aa0c0; margin-bottom:6px; }
.captcha-q{ font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size:16px; font-weight:700; color:#f2f2ff; }
.btn-ghost{ border:1px solid #ff2e8855; background:transparent; color:#9aa0c0; padding:9px 12px; border-radius:10px; font-weight:600; font-size:13px; cursor:pointer; font-family:ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, "Noto Sans", "Liberation Sans", sans-serif; transition:.15s ease; }
.btn-ghost:hover{ border-color:#ff2e88; color:#ff2e88; }
.toast{ position:fixed; left:50%; bottom:24px; transform:translateX(-50%) translateY(8px); display:flex; align-items:center; gap:9px; background:#0d0b18; border:1px solid #ff2e8855; border-left:3px solid #ff5577; color:#f2f2ff; padding:11px 15px; border-radius:10px; box-shadow:0 18px 40px -12px rgba(0,0,0,.45); font-size:13px; opacity:0; pointer-events:none; transition:opacity .2s ease, transform .2s ease; }
.toast::before{ content:""; width:7px; height:7px; border-radius:50%; background:#ff5577; flex:0 0 auto; }
.toast.show{ opacity:1; transform:translateX(-50%) translateY(0); }
</style>
</head>
<body>
  <div class="stage">
    <div class="aside" aria-hidden="true"></div>
    <main class="card" role="main" aria-label="Форма доступа">
      <div class="card-head">
        <span class="dot r"></span>
        <span class="dot y"></span>
        <span class="dot g"></span>
        <span class="path">ssh://secure-gateway</span>
        <span class="status-pill"><span class="led"></span>online</span>
      </div>
      <div class="card-body">
        <span class="eyebrow">Secure Access</span>
        <h1>Доступ к серверу</h1>
        <p class="subtitle">Авторизация требуется для продолжения. Используйте корпоративные учётные данные.</p>
        <form id="loginForm" autocomplete="off" novalidate>
          <div class="field">
            <label for="user">Логин</label>
            <div class="input">
              <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
              <input id="user" name="user" type="text" placeholder="ivan.petrov" autocomplete="username" required/>
            </div>
          </div>
          <div class="field">
            <label for="pass">Пароль</label>
            <div class="input">
              <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              <input id="pass" name="pass" type="password" placeholder="••••••••" autocomplete="current-password" required/>
            </div>
          </div>
          <div class="field" id="captchaWrap" style="display:none">
            <label>Проверка</label>
            <div class="captcha-box">
              <div class="captcha-label">Подтвердите, что вы человек</div>
              <div class="captcha-top">
                <div class="captcha-q" id="captchaQuestion">—</div>
                <button type="button" class="btn-ghost" id="captchaRefresh" aria-label="Обновить">↻</button>
              </div>
              <div class="input" style="margin-top:12px">
                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
                <input id="captchaAnswer" type="text" inputmode="numeric" pattern="[0-9]*" placeholder="Ответ" autocomplete="off"/>
              </div>
            </div>
          </div>
          <button type="submit" class="btn">Войти</button>
          <p class="hint">Забыли пароль? Обратитесь к администратору системы.</p>
        </form>
      </div>
    </main>
  </div>
  <div class="toast" id="toast" role="status" aria-live="polite"></div>
  <script>
  const form = document.getElementById('loginForm');
  const captchaWrap = document.getElementById('captchaWrap');
  const captchaQuestion = document.getElementById('captchaQuestion');
  const captchaAnswer = document.getElementById('captchaAnswer');
  const captchaRefresh = document.getElementById('captchaRefresh');
  const toast = document.getElementById('toast');
  let captchaAnswerValue = 0;
  let attempts = 0;
  let toastTimer = null;
  function showToast(msg){ toast.textContent = msg; toast.classList.add('show'); if(toastTimer) clearTimeout(toastTimer); toastTimer = setTimeout(()=>{ toast.classList.remove('show'); }, 2600); }
  function newCaptcha(){ const a = Math.floor(Math.random()*9)+1; const b = Math.floor(Math.random()*9)+1; captchaAnswerValue = a + b; captchaQuestion.textContent = a + ' + ' + b + ' = ?'; captchaAnswer.value = ''; }
  function captchaIsRequired(){ return attempts >= 1; }
  function captchaIsSolved(){ if(!captchaIsRequired()) return true; const v = parseInt(captchaAnswer.value, 10); return v === captchaAnswer.result; }
  function showCaptchaIfNeeded(){ if(captchaIsRequired()){ captchaWrap.style.display='block'; if(!captchaQuestion.textContent || captchaQuestion.textContent==='—'){ newCaptcha(); } } }
  captchaRefresh.addEventListener('click', ()=>{ newCaptcha(); showToast('Капча обновлена.'); });
  form.addEventListener('submit', (e)=>{
    e.preventDefault();
    if(captchaIsRequired()){ showCaptchaIfNeeded(); if(!captchaIsSolved()){ showToast('Неверная капча. Попробуйте ещё раз.'); return; } }
    attempts += 1; showCaptchaIfNeeded(); showToast('Неверный логин или пароль.');
  });
</script>
</body>
</html>
"""


# =============================================================================
#  Диспетчер: возвращает функцию-генератор по индексу 1..16
# =============================================================================
# Шаблон 16 (Fake Login) добавлен для профиля CDN masking. В стандартный
# выбор через create_website() (nginx_setup.py) он НЕ входит — там
# индекс ограничен 1..15. Активируется только через cdn_masking_mode=True
# в setup_nginx_final(), который явно вызывает create_fake_login().
TEMPLATES = {
    1:  ("TechHub",            create_techhub),
    2:  ("NexCloud",           create_nexcloud),
    3:  ("Holm & Oak",         create_holm_oak),
    4:  ("Ember & Grain",      create_ember_grain),
    5:  ("NexHub",             create_nexhub),
    6:  ("ByteForge",          create_byteforge),
    7:  ("Lumen Architects",   create_lumen),
    8:  ("Verdant Botanical",  create_verdant),
    9:  ("Northwind Coffee",   create_northwind),
    10: ("Solstice Wellness",  create_solstice),
    11: ("Atelier Meridian",   create_atelier),
    12: ("Harborline Logistics", create_harborline),
    13: ("Quietude Library",   create_quietude),
    14: ("Mensara Consulting", create_mensara),
    15: ("Cascade Analytics",  create_cascade),
    16: ("Fake Login",         create_fake_login),  # CDN masking only
}


def get_template_names() -> list:
    """Возвращает список имён шаблонов, индексированный 1..16.

    Индекс 0 — пустой (для совместимости со старым кодом, ожидавшим 'random').
    Индекс 16 — «Fake Login», используется только в профиле CDN masking
    (через cdn_masking_mode=True в setup_nginx_final); в стандартном
    выборе шаблонов 1..15 не участвует.
    """
    return [""] + [name for name, _fn in TEMPLATES.values()]


def build_template(index: int, web_root: Path) -> None:
    """Вызывает функцию-генератор для шаблона с заданным индексом (1..16).

    Индексы 1..15 — стандартные шаблоны сайта (выбор через create_website()).
    Индекс 16 — Fake Login, используется только в профиле CDN masking.
    """
    if index not in TEMPLATES:
        # Fallback на NexCloud для неизвестных индексов (старое поведение).
        index = 2
    name, fn = TEMPLATES[index]
    fn(web_root)
