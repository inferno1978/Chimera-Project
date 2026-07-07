"""
vless_installer/modules/user_portal.py
───────────────────────────────────────────────────────────────────────────────
User Self-Service Portal — HTML/CSS/JS для конечных пользователей.

Анимированный интерфейс, серо-голубые тона, крупные шрифты.
Вызывается из rest_api.py при GET /portal/.
───────────────────────────────────────────────────────────────────────────────
"""


def get_portal_html(user: dict) -> str:
    """Возвращает HTML User Portal для конкретного пользователя."""
    email = user.get("email", "user")
    name = user.get("name", email.split("@")[0] if email else "user")

    return f'''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VLESS Portal — {name}</title>
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
    <div class="avatar">{name[0].upper() if name else 'U'}</div>
    <h1>{name}</h1>
    <div class="subtitle">{email}</div>
  </div>

  <!-- VLESS Links + QR -->
  <div class="card fade-in" style="animation-delay: 0.1s">
    <div class="card-title">🔗 Подключение</div>
    <div id="links-container">
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
    </div>
  </div>

  <!-- Change password -->
  <div class="card fade-in" style="animation-delay: 0.6s">
    <div class="card-title">🔒 Смена пароля портала</div>
    <input type="password" class="input-field" id="new-pass" placeholder="Новый пароль (мин. 6 символов)">
    <button class="btn btn-primary btn-full" onclick="changePassword()">Сменить пароль</button>
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
  const res = await fetch(path);
  if (res.status === 401) {{ alert('Требуется авторизация'); location.reload(); return null; }}
  return res.json();
}}

// ── Load links ──────────────────────────────────────────────────────────────
async function loadLinks() {{
  const data = await api('/api/portal/links');
  if (!data || !data.links) return;

  const container = document.getElementById('links-container');
  container.innerHTML = data.links.map((item, i) => {{
    const qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' + encodeURIComponent(item.link);
    return `
      <div style="margin-bottom:16px">
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

// ── Load traffic + TTL ──────────────────────────────────────────────────────
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
  if (newPass.length < 6) {{ showToast('Минимум 6 символов', 'error'); return; }}

  const res = await fetch('/api/portal/password', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
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

// ── Init ────────────────────────────────────────────────────────────────────
loadLinks();
loadTraffic();
loadHealth();
setInterval(loadHealth, 30000);
setInterval(loadTraffic, 60000);
</script>
</body>
</html>'''
