"""
chimera/modules/user_portal.py
───────────────────────────────────────────────────────────────────────────────
User Self-Service Portal — HTML/CSS/JS для конечных пользователей.

Анимированный интерфейс, серо-голубые тона, крупные шрифты.
Вызывается из rest_api.py при GET /portal/.
───────────────────────────────────────────────────────────────────────────────
"""
import html


def get_portal_html(user: dict) -> str:
    """Возвращает HTML User Portal для конкретного пользователя."""
    email = user.get("email", "user")
    name = user.get("name", email.split("@")[0] if email else "user")

    # Все пользовательские строки экранируются перед вставкой в HTML
    # (name, email могут содержать любые символы — защита от XSS).
    email_safe = html.escape(email)
    name_safe = html.escape(name)
    initial_safe = html.escape(name[0].upper()) if name else "U"

    return f'''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VLESS Portal — {name_safe}</title>
<style>
:root {{
  --bg: #0f172a;
  --bg-glass: rgba(30, 41, 59, 0.7);
  --bg-glass-hover: rgba(51, 65, 85, 0.75);
  --accent: #38bdf8;
  --accent-light: #7dd3fc;
  --accent-glow: rgba(56, 189, 248, 0.4);
  --text: #e2e8f0;
  --text-dim: #94a3b8;
  --green: #4ade80;
  --yellow: #fbbf24;
  --red: #f87171;
  --border: rgba(56, 189, 248, 0.15);
  --radius: 16px;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}}

/* Анимированный фон */
.bg-animation {{
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  z-index: -1;
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 30%, #0f172a 60%, #1e293b 100%);
  background-size: 400% 400%;
  animation: gradientShift 15s ease infinite;
}}
@keyframes gradientShift {{
  0% {{ background-position: 0% 50%; }}
  50% {{ background-position: 100% 50%; }}
  100% {{ background-position: 0% 50%; }}
}}

/* Плавающие частицы */
.particles {{
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  z-index: -1;
  overflow: hidden;
  pointer-events: none;
}}
.particle {{
  position: absolute;
  width: 4px; height: 4px;
  background: var(--accent);
  border-radius: 50%;
  opacity: 0;
  animation: floatUp 8s linear infinite;
}}
@keyframes floatUp {{
  0% {{ transform: translateY(100vh) scale(0); opacity: 0; }}
  10% {{ opacity: 0.6; }}
  90% {{ opacity: 0.3; }}
  100% {{ transform: translateY(-10vh) scale(1.5); opacity: 0; }}
}}

.container {{
  max-width: 700px;
  margin: 0 auto;
  padding: 20px;
  padding-top: 40px;
}}

/* Анимация появления */
.fade-in {{ animation: fadeIn 0.6s ease forwards; opacity: 0; }}
@keyframes fadeIn {{ to {{ opacity: 1; transform: translateY(0); }} }}

/* Header */
.header {{
  text-align: center;
  margin-bottom: 30px;
  animation: fadeIn 0.6s ease forwards;
}}

.header .avatar {{
  width: 72px; height: 72px;
  margin: 0 auto 16px;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--accent), var(--accent-light));
  display: flex; align-items: center; justify-content: center;
  font-size: 2rem; font-weight: 700; color: var(--bg);
  box-shadow: 0 0 30px var(--accent-glow);
  animation: pulse 3s ease infinite;
}}
@keyframes pulse {{
  0%, 100% {{ box-shadow: 0 0 30px var(--accent-glow); }}
  50% {{ box-shadow: 0 0 50px var(--accent-glow); }}
}}

.header h1 {{
  font-size: 1.6rem;
  font-weight: 600;
  background: linear-gradient(135deg, var(--accent), var(--accent-light));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}}

.header .subtitle {{
  font-size: 1rem;
  color: var(--text-dim);
  margin-top: 4px;
}}

/* Card */
.card {{
  background: var(--bg-glass);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  margin-bottom: 20px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.2);
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}}

.card:hover {{
  box-shadow: 0 8px 32px var(--accent-glow);
}}

.card-title {{
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--accent-light);
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}}

/* VLESS Link */
.link-box {{
  background: rgba(15,23,42,0.6);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
  font-family: 'Cascadia Code', 'Fira Code', monospace;
  font-size: 0.82rem;
  word-break: break-all;
  color: var(--accent-light);
  margin-bottom: 12px;
  max-height: 100px;
  overflow-y: auto;
}}

/* QR Code */
.qr-container {{
  text-align: center;
  margin: 16px 0;
}}
.qr-container img {{
  border-radius: 12px;
  border: 2px solid var(--border);
  max-width: 220px;
}}

/* Buttons */
.btn {{
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 12px;
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;
  text-decoration: none;
}}

.btn-primary {{
  background: linear-gradient(135deg, var(--accent), var(--accent-light));
  color: var(--bg);
}}
.btn-primary:hover {{
  box-shadow: 0 4px 20px var(--accent-glow);
  transform: translateY(-2px);
}}

.btn-ghost {{
  background: rgba(56,189,248,0.1);
  color: var(--accent);
  border: 1px solid var(--border);
}}
.btn-ghost:hover {{ background: rgba(56,189,248,0.2); }}

.btn-full {{ width: 100%; justify-content: center; }}

/* Traffic */
.traffic-bar {{
  height: 8px;
  background: rgba(148,163,184,0.15);
  border-radius: 4px;
  overflow: hidden;
  margin: 12px 0;
}}
.traffic-fill {{
  height: 100%;
  background: linear-gradient(90deg, var(--accent), var(--green));
  border-radius: 4px;
  transition: width 0.8s ease;
  animation: shimmer 2s linear infinite;
  background-size: 200% 100%;
}}
@keyframes shimmer {{
  0% {{ background-position: 200% 0; }}
  100% {{ background-position: -200% 0; }}
}}

.traffic-info {{
  display: flex;
  justify-content: space-between;
  font-size: 0.9rem;
  color: var(--text-dim);
}}

/* TTL countdown */
.ttl-badge {{
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  border-radius: 20px;
  font-size: 0.9rem;
  font-weight: 500;
}}
.ttl-badge.active {{ background: rgba(74,222,128,0.15); color: var(--green); }}
.ttl-badge.warning {{ background: rgba(251,191,36,0.15); color: var(--yellow); }}
.ttl-badge.expired {{ background: rgba(248,113,113,0.15); color: var(--red); }}

/* System info */
.sys-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}}
.sys-item {{
  background: rgba(15,23,42,0.5);
  border-radius: 10px;
  padding: 12px 16px;
}}
.sys-item .label {{ font-size: 0.78rem; color: var(--text-dim); }}
.sys-item .value {{ font-size: 1.1rem; font-weight: 600; margin-top: 2px; }}

/* Toast */
.toast {{
  position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%);
  padding: 14px 28px;
  background: var(--bg-glass);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 12px;
  z-index: 1000;
  opacity: 0;
  transition: opacity 0.3s, transform 0.3s;
}}
.toast.show {{ opacity: 1; transform: translateX(-50%) translateY(0); }}
.toast.success {{ border-color: var(--green); }}
.toast.error {{ border-color: var(--red); }}

/* Password change */
.input-field {{
  width: 100%;
  padding: 12px 16px;
  background: rgba(15,23,42,0.6);
  border: 1px solid var(--border);
  border-radius: 10px;
  color: var(--text);
  font-size: 1rem;
  margin-bottom: 12px;
}}
.input-field:focus {{ outline: none; border-color: var(--accent); }}

/* Loading */
.loading {{ text-align: center; padding: 20px; color: var(--text-dim); }}
.spinner {{
  display: inline-block; width: 28px; height: 28px;
  border: 3px solid rgba(56,189,248,0.2);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}

/* Responsive */
@media (max-width: 600px) {{
  .sys-grid {{ grid-template-columns: 1fr; }}
  .header h1 {{ font-size: 1.3rem; }}
}}
</style>
</head>
<body>

<div class="bg-animation"></div>
<div class="particles" id="particles"></div>

<div class="container">
  <!-- Header -->
  <div class="header fade-in">
    <div class="avatar">{initial_safe}</div>
    <h1>{name_safe}</h1>
    <div class="subtitle">{email_safe}</div>
  </div>

  <!-- VLESS Links + QR -->
  <div class="card fade-in" style="animation-delay: 0.1s">
    <div class="card-title">🔗 Подключение</div>
    <div id="links-container">
      <div class="loading"><span class="spinner"></span></div>
    </div>
  </div>

  <!-- My Subscription (единая подписка: все форматы + мульти-нод конфиги) -->
  <div class="card fade-in" id="sub-card" style="animation-delay: 0.12s; display:none">
    <div class="card-title">📚 Моя подписка</div>
    <div id="sub-container">
      <div class="loading"><span class="spinner"></span></div>
    </div>
  </div>

  <!-- My Subscription (единая подписка: все форматы + мульти-нод конфиги) -->
  <div class="card fade-in" id="sub-card" style="animation-delay: 0.12s; display:none">
    <div class="card-title">📚 Моя подписка</div>
    <div id="sub-container">
      <div class="loading"><span class="spinner"></span></div>
    </div>
  </div>

  <!-- My AmneziaWG (показывается только если у юзера есть привязанный пир) -->
  <div class="card fade-in" id="awg-card" style="animation-delay: 0.15s; display:none">
    <div class="card-title">🛡 Мой AmneziaWG</div>
    <div id="awg-container">
      <div class="loading"><span class="spinner"></span></div>
    </div>
  </div>

  <!-- Traffic -->
  <div class="card fade-in" style="animation-delay: 0.2s">
    <div class="card-title">📊 Трафик</div>
    <div id="traffic-container">
      <div class="loading"><span class="spinner"></span></div>
    </div>
  </div>

  <!-- TTL -->
  <div class="card fade-in" id="ttl-card" style="animation-delay: 0.3s; display:none">
    <div class="card-title">⏰ Срок действия</div>
    <div id="ttl-container"></div>
  </div>

  <!-- System Status -->
  <div class="card fade-in" style="animation-delay: 0.4s">
    <div class="card-title">🖥 Состояние сервера</div>
    <div class="sys-grid" id="sys-grid">
      <div class="loading"><span class="spinner"></span></div>
    </div>
  </div>

  <!-- Download configs -->
  <div class="card fade-in" style="animation-delay: 0.5s">
    <div class="card-title">📥 Скачать конфиги</div>
    <div style="display:flex; gap:12px; flex-wrap:wrap">
      <a class="btn btn-ghost" href="/api/portal/clash" download>Clash Meta</a>
      <a class="btn btn-ghost" href="/api/portal/singbox" download>Sing-box</a>
      <a class="btn btn-ghost" href="/api/portal/hiddify" download>Hiddify</a>
      <a class="btn btn-ghost" href="/api/portal/vless-link" download>VLESS-ссылка</a>
    </div>
    <div style="margin-top:16px; padding:12px; background:rgba(15,23,42,0.5); border-radius:10px; font-size:0.85rem; color:var(--text-dim); line-height:1.6">
      <strong style="color:var(--accent-light)">📱 Подсказка по клиентам:</strong><br>
      • <strong>Clash Meta</strong> / <strong>Mihomo</strong> — скачайте файл Clash Meta выше, импортируйте в приложение<br>
      • <strong>Sing-box</strong> — скачайте файл Sing-box выше, импортируйте в приложение<br>
      • <strong>Hiddify</strong> — скачайте файл Hiddify выше или отсканируйте QR-код<br>
      • <strong>v2rayN</strong> / <strong>v2rayNG</strong> / <strong>Karing</strong> / <strong>NekoBox</strong> / <strong>INCY</strong> / <strong>HAPP</strong> — отсканируйте QR-код или скопируйте VLESS-ссылку<br>
      • <strong>Streisand</strong> / <strong>Shadowrocket</strong> (iOS) — отсканируйте QR-код<br>
      • <strong>AmneziaWG</strong> — если у вас есть AWG-пир, конфиг доступен в блоке «Мой AmneziaWG» выше
    </div>
  </div>

  <!-- Change password -->
  <div class="card fade-in" style="animation-delay: 0.6s">
    <div class="card-title">🔒 Смена пароля портала</div>
    <input type="password" class="input-field" id="new-pass" placeholder="Новый пароль (мин. 8 символов)">
    <button class="btn btn-primary btn-full" onclick="changePassword()">Сменить пароль</button>
  </div>

  <!-- My IP addresses (per-user whitelist for ingress_geoip) -->
  <div class="card fade-in" style="animation-delay: 0.7s">
    <div class="card-title">🛂 Мои IP-адреса</div>
    <div id="ips-detected" style="margin-bottom:12px;padding:10px;border-radius:8px;background:rgba(15,23,42,0.5);font-size:0.88rem;color:var(--text-dim);line-height:1.5">
      <span class="spinner" style="display:inline-block;width:14px;height:14px;border:2px solid var(--accent) transparent;border-radius:50%;animation:spin 1s linear infinite;vertical-align:middle"></span>
      Определяем ваш текущий IP...
    </div>
    <div id="ips-list" style="margin-bottom:12px">
      <div class="loading"><span class="spinner"></span></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <input type="text" class="input-field" id="new-ip" placeholder="IP или CIDR (5.167.98.20 или 5.167.98.0/24)" style="flex:1;min-width:200px">
      <button class="btn btn-primary" onclick="addIP()">Добавить</button>
      <button class="btn btn-ghost" onclick="addAutoIP()" id="btn-auto-ip">Текущий IP</button>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
      <button class="btn btn-ghost" onclick="replaceAllIPs()" style="font-size:0.85rem">🔄 Заменить все на текущий</button>
    </div>
    <div style="margin-top:12px;padding:10px;background:rgba(15,23,42,0.5);border-radius:8px;font-size:0.82rem;color:var(--text-dim);line-height:1.5">
      <strong style="color:var(--accent-light)">ℹ️ Для чего это нужно:</strong><br>
      Если на сервере включена блокировка входящих из РФ — клиенты с российскими IP
      не смогут подключиться к VLESS на порту 443. Добавьте свой IP-адрес сюда,
      и вы получите доступ. IP берётся напрямую из вашего TCP-подключения —
      его нельзя подделать.<br><br>
      <strong style="color:var(--accent-light)">📌 Закрепление:</strong>
      Закреплённые IP (📌) не удаляются автоматически при очистке старых адресов.
      Закрепите свой домашний статический IP, если он есть.<br><br>
      <strong style="color:var(--accent-light)">🔄 Заменить все:</strong>
      Удаляет все ваши IP (кроме закреплённых) и добавляет текущий.
      Полезно при смене провайдера или если накопилось много старых адресов.
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
// ── Particles ───────────────────────────────────────────────────────────────
(function initParticles() {{
  const container = document.getElementById('particles');
  for (let i = 0; i < 20; i++) {{
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + '%';
    p.style.animationDelay = Math.random() * 8 + 's';
    p.style.animationDuration = (6 + Math.random() * 6) + 's';
    p.style.width = p.style.height = (2 + Math.random() * 4) + 'px';
    container.appendChild(p);
  }}
}})();

function showToast(msg, type = 'success') {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.className = 'toast', 3000);
}}

async function api(path) {{
  const res = await fetch(path, {{ credentials: 'same-origin' }});
  if (res.status === 401) {{ alert('Требуется авторизация'); location.reload(); return null; }}
  return res.json();
}}

// ── Load links ──────────────────────────────────────────────────────────────
async function loadLinks() {{
  const data = await api('/api/portal/links');
  if (!data || !data.links) return;

  const container = document.getElementById('links-container');
  // Flex-контейнер: QR-коды рядом, по центру, с переносом на новую строку.
  container.style.display = 'flex';
  container.style.flexWrap = 'wrap';
  container.style.justifyContent = 'center';
  container.style.gap = '20px';

  container.innerHTML = data.links.map((item, i) => {{
    const qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' + encodeURIComponent(item.link);
    return `
      <div style="flex:0 1 280px;min-width:260px;text-align:center">
        <div style="font-size:0.85rem;color:var(--text-dim);margin-bottom:6px">${{item.label}} (${{item.protocol}})</div>
        <div class="link-box" id="link-${{i}}">${{item.link}}</div>
        <div class="qr-container">
          <img src="${{qrUrl}}" alt="QR ${{item.label}}" loading="lazy">
        </div>
        <button class="btn btn-ghost btn-full" onclick="copyLink(${{i}})">📋 Копировать ссылку</button>
      </div>
    `;
  }}).join('');
}}

function copyLink(i) {{
  const el = document.getElementById('link-' + i);
  navigator.clipboard.writeText(el.textContent).then(() => {{
    showToast('Ссылка скопирована!');
  }}).catch(() => {{
    showToast('Ошибка копирования', 'error');
  }});
}}

// ── Load subscription (единая подписка) ──────────────────────────────
async function loadSubscription() {{
  let data;
  try {{
    data = await api('/api/portal/sub-info');
  }} catch (e) {{ return; }}
  if (!data || !data.service_enabled || !data.urls || !data.urls.base64) return;

  const card = document.getElementById('sub-card');
  const container = document.getElementById('sub-container');
  card.style.display = '';

  const qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' + encodeURIComponent(data.urls.base64);
  const nodes = (data.multinode && data.multinode.nodes) || [];
  let nodeRows = '';
  if (data.multinode && data.multinode.enabled && nodes.length) {{
    nodeRows = `<div style="margin-top:14px;padding:12px;background:rgba(15,23,42,0.5);border-radius:10px;font-size:0.85rem;color:var(--text-dim);line-height:1.7">` +
      `<strong style="color:var(--accent-light)">🌐 Нод в конфигах: ${{nodes.length}}</strong><br>` +
      nodes.map(n => `• ${{n.name}} <span style="opacity:0.6">(${{n.kind === 'exit' ? 'exit' : (n.kind === 'mirror' ? 'зеркало' : 'вход')}})</span>`).join('<br>') +
      `</div>`;
  }}

  container.innerHTML = `
    <div class="link-box" id="sub-url-box">${{data.urls.base64}}</div>
    <div class="qr-container">
      <img src="${{qrUrl}}" alt="QR подписки" loading="lazy">
    </div>
    <div style="display:flex; gap:10px; flex-wrap:wrap">
      <button class="btn btn-primary" style="flex:1;min-width:160px" onclick="copySubUrl()">📋 Копировать URL</button>
      <a class="btn btn-ghost" href="/api/portal/sub-clash" download>mihomo (полный)</a>
      <a class="btn btn-ghost" href="/api/portal/sub-singbox" download>sing-box (полный)</a>
    </div>
    <div style="margin-top:12px;padding:12px;background:rgba(15,23,42,0.5);border-radius:10px;font-size:0.82rem;color:var(--text-dim);line-height:1.7">
      <strong style="color:var(--accent-light)">💡 Как использовать:</strong><br>
      • <strong>FlClash / Mihomo / Clash</strong> — добавьте URL как подписку или скачайте полный конфиг кнопкой выше (группы выбора нод, RU-сплит, adblock)<br>
      • <strong>NekoBox / Happ / v2rayNG</strong> — добавьте URL как подписку: формат sing-box и exit-ноды подберутся автоматически<br>
      • <strong>Karing (iOS)</strong> — используйте ссылку с суффиксом <code>/ios</code><br>
      • Подписка обновляется автоматически (клиент перечитывает её раз в 6 часов)
    </div>
    ${{nodeRows}}
  `;
}}

function copySubUrl() {{
  const el = document.getElementById('sub-url-box');
  navigator.clipboard.writeText(el.textContent).then(() => {{
    showToast('URL подписки скопирован!');
  }}).catch(() => {{
    showToast('Ошибка копирования', 'error');
  }});
}}

async function loadTraffic() {{
  const data = await api('/api/portal/traffic');
  if (!data) return;

  // Traffic
  const container = document.getElementById('traffic-container');
  const gb = data.total_gb || 0;
  const bytes = data.total_bytes || 0;

  // Если есть лимит — показываем прогресс
  if (data.limit_gb && data.limit_gb > 0) {{
    const pct = Math.min(100, (gb / data.limit_gb) * 100);
    container.innerHTML = `
      <div class="traffic-info">
        <span>Использовано: <strong>${{gb}} ГБ</strong></span>
        <span>Лимит: ${{data.limit_gb}} ГБ</span>
      </div>
      <div class="traffic-bar"><div class="traffic-fill" style="width:${{pct}}%"></div></div>
      <div class="traffic-info">
        <span>${{pct.toFixed(1)}}%</span>
        <span>${{(data.limit_gb - gb).toFixed(2)}} ГБ осталось</span>
      </div>
    `;
  }} else {{
    container.innerHTML = `
      <div class="traffic-info">
        <span>Всего использовано:</span>
        <span style="font-size:1.4rem;font-weight:700;color:var(--accent-light)">${{gb}} ГБ</span>
      </div>
      <div style="font-size:0.82rem;color:var(--text-dim);margin-top:4px">${{bytes.toLocaleString()}} байт</div>
    `;
  }}

  // TTL
  if (data.has_ttl) {{
    document.getElementById('ttl-card').style.display = 'block';
    const ttlContainer = document.getElementById('ttl-container');
    if (data.expired) {{
      ttlContainer.innerHTML = `<div class="ttl-badge expired">⏰ Срок истёк</div>`;
    }} else {{
      const days = data.days || 0;
      const cls = days <= 1 ? 'expired' : days <= 7 ? 'warning' : 'active';
      ttlContainer.innerHTML = `
        <div class="ttl-badge ${{cls}}">⏰ ${{data.expires_str || 'активен'}}</div>
        <div style="font-size:0.85rem;color:var(--text-dim);margin-top:8px">Установлен на ${{days}} дн.</div>
      `;
    }}
  }}
}}

// ── Load system health ──────────────────────────────────────────────────────
async function loadHealth() {{
  const data = await api('/api/portal/health');
  if (!data) return;

  const grid = document.getElementById('sys-grid');
  const xrayColor = data.xray === 'active' ? 'var(--green)' : 'var(--red)';

  grid.innerHTML = `
    <div class="sys-item">
      <div class="label">Статус Xray</div>
      <div class="value" style="color:${{xrayColor}}">${{data.xray || '—'}}</div>
    </div>
    <div class="sys-item">
      <div class="label">Домен</div>
      <div class="value" style="font-size:0.9rem">${{data.domain || '—'}}</div>
    </div>
    <div class="sys-item">
      <div class="label">Протокол</div>
      <div class="value">${{data.protocol_mode || '—'}}</div>
    </div>
    <div class="sys-item">
      <div class="label">SSL дней</div>
      <div class="value" style="color:${{(data.ssl_days_left ?? 99) > 14 ? 'var(--green)' : 'var(--yellow)'}}">${{data.ssl_days_left ?? '—'}}</div>
    </div>
    <div class="sys-item">
      <div class="label">Uptime</div>
      <div class="value">${{data.uptime_hours || 0}}ч</div>
    </div>
    <div class="sys-item">
      <div class="label">Порт</div>
      <div class="value">${{data.server_port || 443}}</div>
    </div>
  `;
}}

// ── Change password ─────────────────────────────────────────────────────────
async function changePassword() {{
  const newPass = document.getElementById('new-pass').value.trim();
  if (newPass.length < 8) {{ showToast('Минимум 8 символов', 'error'); return; }}

  const res = await fetch('/api/portal/password', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    credentials: 'same-origin',
    body: JSON.stringify({{ new_password: newPass }})
  }});
  const data = await res.json();

  if (data.status === 'changed') {{
    showToast('Пароль изменён!');
    document.getElementById('new-pass').value = '';
  }} else {{
    showToast(data.error || 'Ошибка', 'error');
  }}
}}

// ── My IP addresses (per-user whitelist) ────────────────────────────────────
let _detectedIP = '';

async function loadMyIPs() {{
  let data;
  try {{
    data = await api('/api/portal/ips');
  }} catch (e) {{
    document.getElementById('ips-list').innerHTML = '<div style="color:var(--text-dim);font-size:0.85rem">IP whitelist недоступен</div>';
    return;
  }}
  if (!data) return;

  // Detected IP — показываем, если есть.
  _detectedIP = data.detected_ip || '';
  const detectedEl = document.getElementById('ips-detected');
  if (_detectedIP) {{
    detectedEl.innerHTML = `Ваш текущий IP: <strong style="color:var(--accent-light);font-family:monospace">${{_detectedIP}}</strong>`;
    document.getElementById('btn-auto-ip').disabled = false;
    document.getElementById('btn-auto-ip').style.opacity = '1';
  }} else {{
    detectedEl.innerHTML = '<span style="color:var(--text-dim)">Ваш IP не определён (возможно, вы за SSH-туннелем или localhost). Укажите IP вручную.</span>';
    document.getElementById('btn-auto-ip').disabled = true;
    document.getElementById('btn-auto-ip').style.opacity = '0.5';
  }}

  // Render IP list —  detailed format с pinned статусом.
  const container = document.getElementById('ips-list');
  const ips = data.ips || [];
  const max = data.max || 20;
  if (ips.length === 0) {{
    container.innerHTML = `<div style="color:var(--text-dim);font-size:0.85rem">IP-адресов нет. Если на сервере включена блокировка РФ — добавьте свой IP.</div>`;
  }} else {{
    container.innerHTML = `
      <div style="font-size:0.82rem;color:var(--text-dim);margin-bottom:6px">${{ips.length}}/${{max}} IP:</div>
      ${{ips.map((entry, i) => {{
        const ip = entry.ip;
        const pinned = entry.pinned;
        const pinIcon = pinned ? '📌' : '';
        const pinBtn = pinned
          ? `<button class="btn btn-ghost" style="padding:4px 8px;font-size:0.75rem" onclick="unpinIP('${{ip}}')">Открепить</button>`
          : `<button class="btn btn-ghost" style="padding:4px 8px;font-size:0.75rem" onclick="pinIP('${{ip}}')">Закрепить</button>`;
        return `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 10px;margin:4px 0;background:rgba(15,23,42,0.5);border-radius:8px;font-family:monospace;font-size:0.9rem">
          <span>${{pinIcon}} ${{ip}}</span>
          <div style="display:flex;gap:4px">
            ${{pinBtn}}
            <button class="btn btn-ghost" style="padding:4px 10px;font-size:0.8rem" onclick="deleteIP('${{ip}}')">Удалить</button>
          </div>
        </div>`;
      }}).join('')}}
    `;
  }}
}}

async function addIP() {{
  const ip = document.getElementById('new-ip').value.trim();
  if (!ip) {{ showToast('Введите IP или CIDR', 'error'); return; }}
  await _sendIP(ip);
}}

async function addAutoIP() {{
  if (!_detectedIP) {{ showToast('Текущий IP не определён', 'error'); return; }}
  await _sendIP(_detectedIP);
}}

async function _sendIP(ip) {{
  const res = await fetch('/api/portal/ips', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    credentials: 'same-origin',
    body: JSON.stringify({{ ip: ip }})
  }});
  const data = await res.json();
  if (data.status === 'added') {{
    showToast(data.message || 'IP добавлен');
    document.getElementById('new-ip').value = '';
    loadMyIPs();
  }} else {{
    showToast(data.error || 'Ошибка', 'error');
  }}
}}

async function deleteIP(ip) {{
  if (!confirm(`Удалить ${{ip}} из whitelist?`)) return;
  const url = '/api/portal/ips?ip=' + encodeURIComponent(ip);
  const res = await fetch(url, {{
    method: 'DELETE',
    credentials: 'same-origin'
  }});
  const data = await res.json();
  if (data.status === 'deleted') {{
    showToast(data.message || 'IP удалён');
    loadMyIPs();
  }} else {{
    showToast(data.error || 'Ошибка', 'error');
  }}
}}

//  pin / unpin / replace-all
async function pinIP(ip) {{
  const res = await fetch('/api/portal/ips/pin', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    credentials: 'same-origin',
    body: JSON.stringify({{ ip: ip }})
  }});
  const data = await res.json();
  if (data.status === 'pinned') {{
    showToast(data.message || 'IP закреплён');
    loadMyIPs();
  }} else {{
    showToast(data.error || 'Ошибка', 'error');
  }}
}}

async function unpinIP(ip) {{
  const res = await fetch('/api/portal/ips/unpin', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    credentials: 'same-origin',
    body: JSON.stringify({{ ip: ip }})
  }});
  const data = await res.json();
  if (data.status === 'unpinned') {{
    showToast(data.message || 'IP откреплён');
    loadMyIPs();
  }} else {{
    showToast(data.error || 'Ошибка', 'error');
  }}
}}

async function replaceAllIPs() {{
  if (!_detectedIP) {{ showToast('Текущий IP не определён', 'error'); return; }}
  if (!confirm(`Заменить ВСЕ ваши IP на ${{_detectedIP}}?\\nЗакреплённые IP (📌) будут сохранены.`)) return;
  const res = await fetch('/api/portal/ips/replace-all', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    credentials: 'same-origin',
    body: JSON.stringify({{ ip: 'auto', keep_pinned: true }})
  }});
  const data = await res.json();
  if (data.status === 'replaced') {{
    showToast(data.message || 'IP заменены');
    loadMyIPs();
  }} else {{
    showToast(data.error || 'Ошибка', 'error');
  }}
}}

// ── My AmneziaWG ────────────────────────────────────────────────────────────
function _fmtBytes(b) {{
  if (!b || b <= 0) return '0 B';
  const units = ['B','KiB','MiB','GiB','TiB'];
  let v = b;
  for (const u of units) {{
    if (v < 1024) return v.toFixed(1) + ' ' + u;
    v /= 1024;
  }}
  return v.toFixed(1) + ' PiB';
}}

function _fmtHandshake(ts) {{
  if (!ts || ts === '0') return 'никогда';
  const ago = Math.floor(Date.now()/1000) - parseInt(ts);
  if (ago < 60) return ago + ' сек назад';
  if (ago < 3600) return Math.floor(ago/60) + ' мин назад';
  if (ago < 86400) return Math.floor(ago/3600) + ' ч назад';
  return Math.floor(ago/86400) + ' дн назад';
}}

function _fmtExpires(iso) {{
  if (!iso) return '∞ (бессрочно)';
  try {{
    const d = new Date(iso);
    const days = Math.floor((d - Date.now()) / 86400000);
    if (days < 0) return 'истёк';
    if (days === 0) return 'сегодня';
    return days + ' дн';
  }} catch {{ return iso; }}
}}

async function loadMyAWG() {{
  let data;
  try {{
    data = await api('/api/awg/my-peer');
  }} catch (e) {{
    // AWG не установлен или endpoint недоступен — просто прячем блок
    document.getElementById('awg-card').style.display = 'none';
    return;
  }}
  if (!data || !data.peer) {{
    // Нет привязанного пира — блок не показываем (без заглушек "недоступно")
    document.getElementById('awg-card').style.display = 'none';
    return;
  }}
  const p = data.peer;
  const container = document.getElementById('awg-container');
  const statusColor = p.status === 'expired' ? 'var(--red)' : 'var(--green)';
  const statusText = p.status === 'expired' ? 'истёк' : 'активен';
  container.innerHTML = `
    <div class="sys-grid" style="margin-bottom:16px">
      <div class="sys-item">
        <div class="label">Имя пира</div>
        <div class="value" style="font-size:0.95rem">${{p.name || '—'}}</div>
      </div>
      <div class="sys-item">
        <div class="label">IP</div>
        <div class="value" style="font-size:0.9rem;font-family:monospace">${{p.client_ip || '—'}}</div>
      </div>
      <div class="sys-item">
        <div class="label">Статус</div>
        <div class="value" style="color:${{statusColor}}">${{statusText}}</div>
      </div>
      <div class="sys-item">
        <div class="label">Истекает</div>
        <div class="value" style="font-size:0.95rem">${{_fmtExpires(p.expires_at)}}</div>
      </div>
      <div class="sys-item">
        <div class="label">Принято (Rx)</div>
        <div class="value" style="font-size:0.95rem">${{_fmtBytes(p.rx_bytes || 0)}}</div>
      </div>
      <div class="sys-item">
        <div class="label">Отправлено (Tx)</div>
        <div class="value" style="font-size:0.95rem">${{_fmtBytes(p.tx_bytes || 0)}}</div>
      </div>
      <div class="sys-item">
        <div class="label">Handshake</div>
        <div class="value" style="font-size:0.85rem">${{_fmtHandshake(p.handshake_ago)}}</div>
      </div>
    </div>
    <div class="qr-container">
      <img src="/api/awg/my-peer/qr" alt="QR AmneziaWG" style="max-width:200px">
    </div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:12px">
      <a class="btn btn-ghost" href="/api/awg/my-peer/config" download>📥 Скачать .conf</a>
      <button class="btn btn-primary" onclick="regenMyAWG()">🔄 Перевыпустить ключи</button>
    </div>
  `;
  document.getElementById('awg-card').style.display = 'block';
}}

async function regenMyAWG() {{
  if (!confirm('Перевыпустить ключи AmneziaWG? Старый .conf перестанет работать.')) return;
  const res = await fetch('/api/awg/my-peer/regen', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    credentials: 'same-origin'
  }});
  const data = await res.json();
  if (data.status === 'regenerated') {{
    showToast('Ключи перевыпущены!');
    loadMyAWG();
  }} else {{
    showToast(data.error || 'Ошибка', 'error');
  }}
}}

// ── Init ────────────────────────────────────────────────────────────────────
loadLinks();
loadSubscription();
loadTraffic();
loadHealth();
loadMyAWG();
loadMyIPs();
setInterval(loadHealth, 30000);
setInterval(loadTraffic, 60000);
setInterval(loadMyAWG, 60000);
</script>
</body>
</html>'''
