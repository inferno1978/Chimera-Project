# xHTTP + REALITY Implementation Plan

## Branch: `xhttp-reality` (on GitLab, from chimera-v5)

## Goal
Add `xhttp_reality` as third `protocol_mode` option — combines xHTTP
transport (xmux, padding, HTTP/2 traffic patterns) with REALITY TLS
camouflage. No Let's Encrypt cert needed (REALITY handles TLS).

## Architecture

```
Client (xray-based) → Server inbound (xhttp+reality) → freedom
Client (mihomo)     → NOT supported (fallback to tcp+reality)

Cascade:
Client → Entry (tcp+reality) → Exit (xhttp+reality) → freedom
```

## Files to modify (6 files, ~500 lines new code)

### 1. install_prompts.py — prompt_protocol_mode() (line 676)
Add third option:
```
[1] VLESS + TCP + REALITY (все клиенты, с MLKEM768)
[2] VLESS + xHTTP + TLS (все клиенты, нужен LE-сертификат)
[3] VLESS + xHTTP + REALITY (только xray-клиенты: v2rayN, NekoBox,
    sing-box. mihomo НЕ поддерживается. REALITY маскировка + xmux
    + padding. Без MLKEM768 костыля.)
```
Set `PROTOCOL_MODE = "xhttp_reality"` when [3] selected.
Also update `proto_str` (line 571) and confirmation display.

### 2. xray_install.py — new function generate_xray_config_xhttp_reality()
Based on generate_xray_config() (reality) but with:
- `"network": "xhttp"` instead of `"network": "tcp"`
- Keep `"security": "reality"` + `realitySettings`
- Add `"xhttpSettings"` from `_build_xhttp_settings(XHTTP_MODE, XHTTP_PATH)`
- NO `tlsSettings` (REALITY handles TLS, no LE cert needed)
- NO `flow` (xhttp doesn't use xtls-rprx-vision)
- Clients: no flow (like xhttp branch)
- Everything else: same as generate_xray_config() (DNS, routing, users, etc.)

Key difference from generate_xray_config():
- streamSettings combines BOTH xhttpSettings AND realitySettings
- No xtls_flow (xhttp transport doesn't support flow)
- Uses _build_xhttp_settings() for transport layer
- Uses same realitySettings as generate_xray_config()

### 3. _core.py — dispatch + PROTOCOL_MODE handling
In _rebuild_and_restart_xray() (line ~2981):
```python
if INSTALL_MODE == "B":
    generate_xray_config_chain_entry_multi()
elif PROTOCOL_MODE == "xhttp":
    generate_xray_config_xhttp()
elif PROTOCOL_MODE == "xhttp_reality":
    generate_xray_config_xhttp_reality()  # NEW
else:
    generate_xray_config()
```

All other PROTOCOL_MODE checks (42 total): add `xhttp_reality` branch
where appropriate. Key patterns:
- `if PROTOCOL_MODE == "reality"` → often needs `or PROTOCOL_MODE == "xhttp_reality"`
  (e.g. reality keys, dest, nginx socket — all apply to xhttp_reality too)
- `if PROTOCOL_MODE == "xhttp"` → usually does NOT apply to xhttp_reality
  (e.g. LE cert, no flow, nginx setup — xhttp_reality uses REALITY, not TLS cert)

### 4. rest_api.py — client config generation
_generate_vless_links() (line 588): add xhttp_reality branch:
```
vless://uuid@domain:port?encryption=none&security=reality&sni=domain
&fp=chrome&pbk=...&sid=...&type=xhttp&path=/&mode=stream-up#name
```
Note: security=reality (not tls), type=xhttp (not tcp).

_generate_singbox_config() (line 851): add xhttp_reality branch:
```json
{
  "transport": {"type": "http", "path": xhttp_path},
  "tls": {
    "enabled": true,
    "server_name": sni,
    "utls": {"enabled": true, "fingerprint": fp},
    "reality": {"enabled": true, "public_key": pbk, "short_id": sid}
  }
}
```

_generate_clash_config() (line 774): mihomo fallback —
for xhttp_reality, generate tcp+reality config (with MLKEM768).
mihomo can't do network:http + reality-opts together.

### 5. chain_nodes.py — cascade config
_make_exit_node_config() (line 943): add third branch for proto="xhttp_reality":
- Inbound: network=xhttp + security=reality + xhttpSettings + realitySettings
- No LE cert (REALITY handles TLS)
- No flow (xhttp transport)

Entry outbound generation: for exit nodes with proto=xhttp_reality:
- Outbound: network=xhttp + security=reality + xhttpSettings + realitySettings
- Use _build_exit_xhttp_outbound_settings() for transport
- Use same realitySettings as tcp+reality outbound

Chain node add menu: add "xhttp_reality" as third proto option (line 1237).

### 6. subscription_multinode.py — mihomo config
_mihomo_proxy_block() (line 407): for proto="xhttp_reality":
- FALLBACK to tcp+reality (mihomo doesn't support http+reality)
- Use the same reality-opts + support-x25519mlkem768 + chrome FP
- Add a comment: "# xHTTP+REALITY node — mihomo fallback to tcp+reality"

## vless:// URL format for xhttp_reality
```
vless://uuid@host:443?encryption=none&security=reality&sni=host
&fp=chrome&pbk=PUBKEY&sid=SHORTID&type=xhttp&path=/&mode=stream-up#Name
```

## state.json fields
Same as reality mode (uses REALITY keys/dest/SNI) PLUS:
- xhttp_path (default "/")
- xhttp_mode (default "stream-up")

## Testing checklist
1. Fresh install Mode A with xhttp_reality → xray starts, config valid
2. vless:// link → import to v2rayN → connection works
3. sing-box config → import → connection works
4. mihomo config → uses tcp+reality fallback → connection works
5. Mode B cascade: exit node proto=xhttp_reality → entry→exit works
6. _rebuild_and_restart_xray → picks up xhttp_reality correctly
7. xray run -test → config validates
