"""
vless_installer/modules/admin_panel.py
───────────────────────────────────────────────────────────────────────────────
Admin Panel — HTML/CSS/JS для управления VLESS сервером.

Glassmorphism дизайн, серо-голубые тона, крупные шрифты.
Вызывается из rest_api.py при GET /admin/.
───────────────────────────────────────────────────────────────────────────────
"""


def get_admin_html() -> str:
    """Возвращает HTML Admin Panel."""
    return '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VLESS Admin Panel</title>
<style>
:root {
  --bg-dark: #0f172a;
  --bg-card: rgba(30, 41, 59, 0.75);
  --bg-card-hover: rgba(51, 65, 85, 0.8);
  --accent: #38bdf8;
  --accent-light: #7dd3fc;
  --accent-dark: #0284c7;
  --text: #e2e8f0;
  --text-dim: #94a3b8;
  --green: #4ade80;
  --yellow: #fbbf24;
  --red: #f87171;
  --border: rgba(56, 189, 248, 0.2);
  --radius: 16px;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
  color: var(--text);
  min-height: 100vh;
  padding: 20px;
}

.container { max-width: 1200px; margin: 0 auto; }

/* Header */
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding: 20px 30px;
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
}

.header h1 {
  font-size: 1.8rem;
  font-weight: 600;
  background: linear-gradient(135deg, var(--accent), var(--accent-light));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.header .status {
  display: flex;
  gap: 15px;
  font-size: 0.95rem;
}

.status-badge {
  padding: 6px 16px;
  border-radius: 20px;
  font-size: 0.85rem;
  font-weight: 500;
}

.status-badge.active { background: rgba(74,222,128,0.15); color: var(--green); border: 1px solid rgba(74,222,128,0.3); }
.status-badge.inactive { background: rgba(248,113,113,0.15); color: var(--red); border: 1px solid rgba(248,113,113,0.3); }

/* Grid */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.card {
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  box-shadow: 0 4px 20px rgba(0,0,0,0.2);
}

.card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 32px rgba(56,189,248,0.15);
}

.card h2 {
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 16px;
  color: var(--accent-light);
}

.card .value {
  font-size: 2.2rem;
  font-weight: 700;
  color: var(--text);
}

.card .label {
  font-size: 0.85rem;
  color: var(--text-dim);
  margin-top: 4px;
}

.card .progress {
  height: 6px;
  background: rgba(148,163,184,0.2);
  border-radius: 3px;
  margin-top: 12px;
  overflow: hidden;
}

.card .progress-bar {
  height: 100%;
  background: linear-gradient(90deg, var(--accent-dark), var(--accent));
  border-radius: 3px;
  transition: width 0.5s ease;
}

/* Table */
.table-card {
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  margin-bottom: 30px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.2);
}

.table-card h2 {
  font-size: 1.2rem;
  margin-bottom: 20px;
  color: var(--accent-light);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 12px 16px;
  text-align: left;
  border-bottom: 1px solid rgba(148,163,184,0.1);
  font-size: 0.95rem;
}

th { color: var(--text-dim); font-weight: 500; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
td { color: var(--text); }

tr:hover { background: rgba(56,189,248,0.05); }

/* Buttons */
.btn {
  padding: 10px 20px;
  border: none;
  border-radius: 10px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;
}

.btn-primary {
  background: linear-gradient(135deg, var(--accent-dark), var(--accent));
  color: white;
}
.btn-primary:hover { box-shadow: 0 4px 16px rgba(56,189,248,0.4); transform: translateY(-2px); }

.btn-danger {
  background: rgba(248,113,113,0.2);
  color: var(--red);
  border: 1px solid rgba(248,113,113,0.3);
}
.btn-danger:hover { background: rgba(248,113,113,0.3); }

.btn-sm { padding: 6px 14px; font-size: 0.82rem; }

/* Actions */
.actions {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

/* Loading */
.loading { text-align: center; padding: 40px; color: var(--text-dim); }
.spinner { display: inline-block; width: 32px; height: 32px; border: 3px solid rgba(56,189,248,0.2); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* Toast */
.toast {
  position: fixed; bottom: 30px; right: 30px;
  padding: 16px 24px;
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
  z-index: 1000;
  opacity: 0;
  transform: translateY(20px);
  transition: opacity 0.3s, transform 0.3s;
}
.toast.show { opacity: 1; transform: translateY(0); }
.toast.success { border-color: var(--green); }
.toast.error { border-color: var(--red); }

/* Modal */
.modal-overlay {
  position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.6);
  backdrop-filter: blur(4px);
  display: none;
  align-items: center; justify-content: center;
  z-index: 100;
}
.modal-overlay.show { display: flex; }
.modal {
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 30px;
  width: 90%; max-width: 480px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}
.modal h2 { font-size: 1.3rem; margin-bottom: 20px; color: var(--accent-light); }
.modal input {
  width: 100%; padding: 12px 16px;
  background: rgba(15,23,42,0.6); border: 1px solid var(--border);
  border-radius: 10px; color: var(--text); font-size: 1rem; margin-bottom: 16px;
}
.modal input:focus { outline: none; border-color: var(--accent); }
.modal-actions { display: flex; gap: 12px; justify-content: flex-end; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔒 VLESS Admin Panel</h1>
    <div class="status" id="header-status">
      <span class="loading"><span class="spinner"></span></span>
    </div>
  </div>

  <!-- Health cards -->
  <div class="grid" id="health-grid">
    <div class="card"><div class="loading"><span class="spinner"></span></div></div>
  </div>

  <!-- Actions -->
  <div class="actions">
    <button class="btn btn-primary" onclick="showAddUserModal()">➕ Добавить пользователя</button>
    <button class="btn btn-primary" onclick="rotateUUID()">🔄 Ротация UUID</button>
    <button class="btn btn-primary" onclick="rotateReality()">🔑 Ротация REALITY</button>
    <button class="btn btn-primary" onclick="createBackup()">💾 Создать бэкап</button>
  </div>

  <!-- Users table -->
  <div class="table-card">
    <h2>👥 Пользователи <button class="btn btn-sm btn-primary" onclick="loadUsers()">↻</button></h2>
    <table>
      <thead>
        <tr><th>Email</th><th>UUID</th><th>Создан</th><th>Трафик</th><th>TTL</th><th>Действия</th></tr>
      </thead>
      <tbody id="users-tbody">
        <tr><td colspan="6" class="loading"><span class="spinner"></span></td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- Add User Modal -->
<div class="modal-overlay" id="add-user-modal">
  <div class="modal">
    <h2>➕ Новый пользователь</h2>
    <input type="text" id="new-email" placeholder="Email (например: user@xray)">
    <input type="text" id="new-name" placeholder="Имя (необязательно)">
    <div class="modal-actions">
      <button class="btn btn-danger" onclick="closeModal('add-user-modal')">Отмена</button>
      <button class="btn btn-primary" onclick="addUser()">Создать</button>
    </div>
  </div>
</div>

<!-- Set Password Modal -->
<div class="modal-overlay" id="set-pass-modal">
  <div class="modal">
    <h2>🔑 Сменить пароль портала</h2>
    <input type="text" id="set-pass-email" readonly style="opacity:0.6">
    <input type="text" id="set-pass-value" placeholder="Новый пароль (мин. 8 символов)">
    <div class="modal-actions">
      <button class="btn btn-danger" onclick="closeModal('set-pass-modal')">Отмена</button>
      <button class="btn btn-primary" onclick="setUserPassword()">Сохранить</button>
    </div>
  </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
const API = '';

// Escape пользовательских данных перед вставкой в innerHTML (XSS защита).
// email/name приходят с сервера и могут содержать < > " ' & и т.п.
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

function authHeader() {
  // Используем кэшированные креды из URL (Basic Auth уже в заголовке)
  return {};
}

async function api(path, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
    // credentials: same-origin — чтобы браузер передавал Basic Auth креды
    // в JS-запросах (fetch по умолчанию не всегда передаёт их для same-origin).
    credentials: 'same-origin'
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(API + path, opts);
  if (res.status === 401) { alert('Требуется авторизация'); location.reload(); return null; }
  return res.json();
}

function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.className = 'toast', 3000);
}

function showModal(id) { document.getElementById(id).classList.add('show'); }
function closeModal(id) { document.getElementById(id).classList.remove('show'); }

// ── Health ──────────────────────────────────────────────────────────────────
async function loadHealth() {
  const data = await api('/api/health');
  if (!data) return;

  // Header status
  const xrayStatus = data.xray === 'active' ? 'active' : 'inactive';
  document.getElementById('header-status').innerHTML = `
    <span class="status-badge ${xrayStatus}">Xray: ${data.xray}</span>
    <span class="status-badge ${data.nginx === 'active' ? 'active' : 'inactive'}">Nginx: ${data.nginx}</span>
    <span class="status-badge ${data.ssl_days_left > 30 ? 'active' : 'inactive'}">SSL: ${data.ssl_days_left || '?'}д</span>
  `;

  // Cards
  const grid = document.getElementById('health-grid');
  const ramPct = data.ram_pct || 0;
  const diskPct = data.disk_pct || 0;
  const ramColor = ramPct < 70 ? '#4ade80' : ramPct < 90 ? '#fbbf24' : '#f87171';
  const diskColor = diskPct < 70 ? '#4ade80' : diskPct < 90 ? '#fbbf24' : '#f87171';

  grid.innerHTML = `
    <div class="card">
      <h2>🌐 Домен</h2>
      <div class="value" style="font-size:1.3rem">${data.domain || '—'}</div>
      <div class="label">Порт: ${data.server_port} · ${data.protocol_mode}</div>
    </div>
    <div class="card">
      <h2>💾 Диск</h2>
      <div class="value">${data.disk_pct || 0}%</div>
      <div class="label">${data.disk_used || '?'} / ${data.disk_total || '?'}</div>
      <div class="progress"><div class="progress-bar" style="width:${diskPct}%;background:${diskColor}"></div></div>
    </div>
    <div class="card">
      <h2>🖥 RAM</h2>
      <div class="value">${ramPct}%</div>
      <div class="label">${data.ram_used_mb || 0} / ${data.ram_total_mb || 0} МБ</div>
      <div class="progress"><div class="progress-bar" style="width:${ramPct}%;background:${ramColor}"></div></div>
    </div>
    <div class="card">
      <h2>⚡ Соединения</h2>
      <div class="value">${data.xray_connections || 0}</div>
      <div class="label">Активных Xray</div>
    </div>
    <div class="card">
      <h2>⏱ Uptime</h2>
      <div class="value">${data.uptime_hours || 0}ч</div>
      <div class="label">${data.cpu_cores || 1} ядер</div>
    </div>
    <div class="card">
      <h2>🔒 SSL</h2>
      <div class="value">${data.ssl_days_left ?? '—'}</div>
      <div class="label">дней до истечения</div>
    </div>
  `;
}

// ── Users ───────────────────────────────────────────────────────────────────
async function loadUsers() {
  const data = await api('/api/users');
  if (!data) return;

  const tbody = document.getElementById('users-tbody');
  if (!data.users || data.users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">Нет пользователей</td></tr>';
    return;
  }

  tbody.innerHTML = data.users.map(u => `
    <tr>
      <td>${esc(u.email) || '—'}</td>
      <td style="font-family:monospace;font-size:0.82rem">${esc((u.uuid || '').slice(0,8))}...</td>
      <td>${esc(u.created ? u.created.slice(0,10) : '—')}</td>
      <td id="traffic-${esc(u.email)}">—</td>
      <td id="ttl-${esc(u.email)}">—</td>
      <td>
        <button class="btn btn-sm btn-ghost" onclick="showSetPassModal('${esc(u.email)}')">🔑</button>
        <button class="btn btn-sm btn-danger" onclick="deleteUser('${esc(u.email)}')">🗑 Удалить</button>
      </td>
    </tr>
  `).join('');

  // Загружаем трафик для каждого
  data.users.forEach(async u => {
    const email = u.email;
    if (!email) return;
    const t = await api(`/api/users/${encodeURIComponent(email)}/traffic`);
    if (t) {
      const el = document.getElementById(`traffic-${email}`);
      if (el) el.textContent = t.total_gb >= 0 ? t.total_gb + ' ГБ' : '—';
      const ttlEl = document.getElementById(`ttl-${email}`);
      if (ttlEl) {
        if (t.has_ttl) {
          ttlEl.innerHTML = t.expired
            ? `<span style="color:var(--red)">истёк</span>`
            : `<span style="color:var(--yellow)">${t.expires_str || ''}</span>`;
        } else {
          ttlEl.textContent = '—';
        }
      }
    }
  });
}

function showAddUserModal() {
  document.getElementById('new-email').value = '';
  document.getElementById('new-name').value = '';
  showModal('add-user-modal');
  document.getElementById('new-email').focus();
}

async function addUser() {
  const email = document.getElementById('new-email').value.trim();
  const name = document.getElementById('new-name').value.trim();
  if (!email) { showToast('Email обязателен', 'error'); return; }

  const data = await api('/api/users', 'POST', { email, name });
  if (data && data.status === 'created') {
    // portal_password возвращается ОДИН раз — показываем админу для передачи пользователю.
    if (data.portal_password) {
      alert('Пользователь создан: ' + email +
            '\\n\\nportal_login: ' + (data.portal_login || email) +
            '\\nportal_password: ' + data.portal_password +
            '\\n\\n⚠️ Сохраните пароль — он больше не будет показан.');
    } else {
      showToast('Пользователь создан: ' + email);
    }
    closeModal('add-user-modal');
    loadUsers();
  } else {
    showToast('Ошибка создания', 'error');
  }
}

async function deleteUser(email) {
  if (!confirm(`Удалить ${email}?`)) return;
  const data = await api(`/api/users/${encodeURIComponent(email)}`, 'DELETE');
  if (data && data.status === 'deleted') {
    showToast('Удалён: ' + email);
    loadUsers();
  } else {
    showToast('Ошибка удаления', 'error');
  }
}

// ── Set user password (admin) ──────────────────────────────────────────────
function showSetPassModal(email) {
  document.getElementById('set-pass-email').value = email;
  document.getElementById('set-pass-value').value = '';
  showModal('set-pass-modal');
  setTimeout(() => document.getElementById('set-pass-value').focus(), 100);
}

async function setUserPassword() {
  const email = document.getElementById('set-pass-email').value;
  const newPass = document.getElementById('set-pass-value').value.trim();
  if (newPass.length < 8) { showToast('Минимум 8 символов', 'error'); return; }
  const data = await api(`/api/users/${encodeURIComponent(email)}/password`, 'POST', { new_password: newPass });
  if (data && data.status === 'changed') {
    showToast('Пароль изменён для ' + email);
    closeModal('set-pass-modal');
  } else {
    showToast(data && data.error ? data.error : 'Ошибка', 'error');
  }
}

// ── Rotation ────────────────────────────────────────────────────────────────
async function rotateUUID() {
  if (!confirm('Ротация UUID отключит всех клиентов! Продолжить?')) return;
  const data = await api('/api/rotate/uuid', 'POST');
  if (data && data.status === 'rotated') {
    showToast('UUID ротация: ' + data.new_uuid.slice(0, 8) + '...');
    loadUsers();
  } else {
    showToast('Ошибка ротации UUID', 'error');
  }
}

async function rotateReality() {
  if (!confirm('Ротация REALITY-ключей отключит всех клиентов! Продолжить?')) return;
  const data = await api('/api/rotate/reality', 'POST');
  if (data && data.status === 'rotated') {
    showToast('REALITY ключи сменены');
  } else {
    showToast('Ошибка ротации REALITY', 'error');
  }
}

// ── Backup ──────────────────────────────────────────────────────────────────
async function createBackup() {
  showToast('Создание бэкапа...');
  const data = await api('/api/backup', 'POST');
  if (data && data.status === 'backup_created') {
    showToast('Бэкап создан');
  } else {
    showToast('Ошибка бэкапа', 'error');
  }
}

// ── Init ────────────────────────────────────────────────────────────────────
loadHealth();
loadUsers();
setInterval(loadHealth, 30000); // обновление каждые 30с
</script>
</body>
</html>'''
