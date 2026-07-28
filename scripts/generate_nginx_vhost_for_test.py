#!/usr/bin/env python3
"""
scripts/generate_nginx_vhost_for_test.py
───────────────────────────────────────────────────────────────────────────────
Генерирует реальный nginx vhost-файл через setup_nginx_final() с
cdn_masking_mode=True и cdn_masking_mode=False — для последующей
ручной проверки nginx -t на живом сервере.

Это нужно потому, что среда разработки не имеет root-прав и не может
установить nginx. Скрипт генерирует файлы в /tmp/ и выводит команды
для ручной проверки.

Использование:
    python3 scripts/generate_nginx_vhost_for_test.py
    # Затем на сервере с nginx:
    # nginx -t -c /tmp/nginx-test-cdn.conf
    # nginx -t -c /tmp/nginx-test-simple.conf
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает _core.py через exec и регистрирует фейк в sys.modules."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def generate_vhost(cdn_masking_mode: bool, output_dir: Path) -> Path:
    """Генерирует vhost-файл с заданным cdn_masking_mode и возвращает путь."""
    core = _setup_core()

    # NGINX_CONF_DIR — отдельная поддиректория, не пересекается с /var/www
    nginx_conf_dir = output_dir / "nginx-conf"
    nginx_conf_dir.mkdir(parents=True, exist_ok=True)

    # Минимальные globals
    core.PROTOCOL_MODE = "xhttp"
    core.XHTTP_PATH = "/api/v2/static.ts"
    core.XHTTP_BACKEND_PORT = 7443 if cdn_masking_mode else 8443
    core.PARAM_DOMAIN = "test.example.com"
    core.PARAM_SOCKET_PATH = "/run/xray.sock"
    core.AWG_EXIT_ENABLED = False
    core.IS_IPV6_AVAILABLE = False
    core.SERVER_PORT = 443
    core.PARAM_SITE_TEMPLATE = "16" if cdn_masking_mode else "2"
    core.NGINX_CONF_DIR = nginx_conf_dir
    core.NGINX_ENABLED_DIR = output_dir / "enabled"
    core.NGINX_ENABLED_DIR.mkdir(parents=True, exist_ok=True)
    core.NGINX_RATE_LIMIT_CONF = output_dir / "rate.conf"
    core._run = MagicMock(return_value=MagicMock(returncode=0, stdout="",
                                                   stderr="nginx version"))
    core.find_nginx_bin = lambda: "/usr/sbin/nginx"
    core.info = lambda *a, **kw: None
    core.warn = lambda *a, **kw: None
    core.success = lambda *a, **kw: None
    core.log_to_file = lambda *a, **kw: None

    # Patch create_website / create_fake_login чтобы не писать в /var/www
    import chimera.modules.nginx_setup_templates as nst
    nst.create_fake_login = lambda web_root: None  # no-op
    import chimera.modules.nginx_setup as ns
    ns.create_website = lambda **kw: None  # no-op

    # Патчим Path.mkdir чтобы /var/www перенаправлялся в output_dir/www
    www_dir = output_dir / "www"
    www_dir.mkdir(parents=True, exist_ok=True)
    output_dir_str = str(output_dir)
    orig_mkdir = Path.mkdir
    def patched_mkdir(self, *args, **kwargs):
        s = str(self)
        if s.startswith("/var/www/"):
            self = Path(output_dir_str + s[len("/var/www"):])
        return orig_mkdir(self, *args, **kwargs)
    Path.mkdir = patched_mkdir

    # Патчим Path.write_text для /var/www путей
    orig_write_text = Path.write_text
    def patched_write_text(self, data, *args, **kwargs):
        s = str(self)
        if s.startswith("/var/www/"):
            new_path = Path(output_dir_str + s[len("/var/www"):])
            new_path.parent.mkdir(parents=True, exist_ok=True)
            return orig_write_text(new_path, data, *args, **kwargs)
        return orig_write_text(self, data, *args, **kwargs)
    Path.write_text = patched_write_text

    # Патчим Path.exists для /var/www путей
    orig_exists = Path.exists
    def patched_exists(self, *args, **kwargs):
        s = str(self)
        if s.startswith("/var/www/"):
            new_path = Path(output_dir_str + s[len("/var/www"):])
            return orig_exists(new_path, *args, **kwargs)
        return orig_exists(self, *args, **kwargs)
    Path.exists = patched_exists

    # Патчим Path.symlink_to — sites-enabled symlink
    orig_symlink = Path.symlink_to
    def patched_symlink(self, target, *args, **kwargs):
        return orig_symlink(self, target, *args, **kwargs)
    Path.symlink_to = patched_symlink

    try:
        ns.setup_nginx_final(cdn_masking_mode=cdn_masking_mode)
    finally:
        Path.mkdir = orig_mkdir
        Path.write_text = orig_write_text
        Path.exists = orig_exists
        Path.symlink_to = orig_symlink

    vhost_file = nginx_conf_dir / "test.example.com"
    return vhost_file


def wrap_in_nginx_conf(vhost_content: str, ssl_cert_path: str = "/etc/letsencrypt/live/test.example.com/fullchain.pem",
                       ssl_key_path: str = "/etc/letsencrypt/live/test.example.com/privkey.pem") -> str:
    """Оборачивает vhost в полный nginx.conf для теста nginx -t.

    Создаёт минимальный http {} блок с events {} и http {} обёрткой.
    Сертификаты — заглушки (nginx -t проверяет синтаксис, не реальное наличие).
    """
    return f"""# Auto-generated test config for nginx -t
events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Заглушка для ssl_certificate — nginx -t требует файл,
    # но мы не можем его создать. Проверяем только синтаксис.
    # Если nginx ругается на отсутствие сертификата — это НЕ синтаксическая ошибка.

    {vhost_content}
}}
"""


def main():
    output_dir = Path(tempfile.mkdtemp(prefix="nginx_test_"))
    print(f"=== Генерация vhost-файлов в {output_dir} ===")
    print()

    # Генерируем CDN masking vhost
    cdn_vhost = generate_vhost(cdn_masking_mode=True, output_dir=output_dir / "cdn")
    print(f"CDN masking vhost: {cdn_vhost}")
    cdn_content = cdn_vhost.read_text()

    # Генерируем simple XHTTP vhost
    simple_vhost = generate_vhost(cdn_masking_mode=False, output_dir=output_dir / "simple")
    print(f"Simple XHTTP vhost: {simple_vhost}")
    simple_content = simple_vhost.read_text()

    # Оборачиваем в полный nginx.conf
    cdn_full = wrap_in_nginx_conf(cdn_content)
    simple_full = wrap_in_nginx_conf(simple_content)

    cdn_full_file = output_dir / "nginx-test-cdn.conf"
    simple_full_file = output_dir / "nginx-test-simple.conf"
    cdn_full_file.write_text(cdn_full)
    simple_full_file.write_text(simple_full)

    print()
    print(f"=== Полные конфиги для nginx -t ===")
    print(f"  CDN masking:  {cdn_full_file}")
    print(f"  Simple XHTTP: {simple_full_file}")
    print()
    print("=== Команды для проверки на сервере с nginx ===")
    print(f"  nginx -t -c {cdn_full_file}")
    print(f"  nginx -t -c {simple_full_file}")
    print()
    print("=== Содержимое CDN masking vhost (server-блок с директивами) ===")
    for i, line in enumerate(cdn_content.split('\n'), 1):
        if any(k in line for k in ['large_client_header', 'underscores_in_headers',
                                     'proxy_send_timeout', 'proxy_read_timeout',
                                     'proxy_next_upstream', 'location ', 'server ',
                                     'server_name', 'add_header', 'root ']):
            print(f"  L{i}: {line}")
    print()
    print("=== Содержимое simple XHTTP vhost (для сравнения) ===")
    for i, line in enumerate(simple_content.split('\n'), 1):
        if any(k in line for k in ['large_client_header', 'underscores_in_headers',
                                     'proxy_send_timeout', 'proxy_read_timeout',
                                     'proxy_next_upstream', 'location ', 'server ',
                                     'server_name', 'add_header', 'root ']):
            print(f"  L{i}: {line}")

    # Подсчёт директив для проверки дублирования
    print()
    print("=== Подсчёт директив в location-блоке (CDN masking) ===")
    cdn_lines = cdn_content.split('\n')
    in_location = False
    loc_depth = 0
    loc_directives = []
    for line in cdn_lines:
        s = line.strip()
        if s.startswith('location ') and '{' in s:
            in_location = True
            loc_depth = s.count('{') - s.count('}')
            continue
        if in_location:
            if '{' in s: loc_depth += s.count('{')
            if '}' in s:
                loc_depth -= s.count('}')
                if loc_depth <= 0:
                    in_location = False
                    continue
            if s and not s.startswith('#'):
                loc_directives.append(s)
    for d in ['proxy_read_timeout', 'proxy_send_timeout', 'proxy_next_upstream',
              'proxy_next_upstream_tries', 'large_client_header_buffers',
              'underscores_in_headers']:
        count = sum(1 for x in loc_directives if x.startswith(d))
        print(f"  {d}: {count} вхождений в location")

    return 0


if __name__ == "__main__":
    sys.exit(main())
