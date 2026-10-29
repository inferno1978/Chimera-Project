# Chimera — индекс тестов по семействам

> Сгенерировано `scripts/tests_index.py` (миграция 2026-10-29). Плоский layout tests/ — намеренный: 299+ файлов считают `_PROJECT_ROOT = Path(__file__).resolve().parent.parent`, ci_gate.txt хранит module-пути `tests.test_*`, ci_suite.sh full строит список через `ls tests/test_*.py` — перенос в подкаталоги = правка ~300 файлов без функциональной выгоды. Навигация — этот индекс.

Всего тест-модулей: **314** (гейт-манифест: **314**; каждый test_*.py обязан быть в tests/ci_gate.txt — сверяется tests/test_tests_index.py).


## AmneziaWG (transport Mode B + standalone 2.0) (30)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_awg_apply.py`](../tests/test_awg_apply.py) | Unit-тесты для chimera/modules/awg_apply.py. | ✓ |
| [`test_awg_b4_split.py`](../tests/test_awg_b4_split.py) | Unit-тесты для B4-сплита AWG-каскада. | ✓ |
| [`test_awg_backup.py`](../tests/test_awg_backup.py) | Unit-тесты для chimera/modules/awg_backup.py. | ✓ |
| [`test_awg_cascade.py`](../tests/test_awg_cascade.py) | Unit-тесты для chimera/modules/awg_cascade.py. | ✓ |
| [`test_awg_cascade_31.py`](../tests/test_awg_cascade_31.py) | Unit-тесты AWG 3.1 в awg_cascade.py — каскад из 2 серверов. | ✓ |
| [`test_awg_cascade_lb.py`](../tests/test_awg_cascade_lb.py) | Unit-тесты балансировки мульти-exit каскада (chimera/modules/awg_cascade_lb.py | ✓ |
| [`test_awg_cascade_multiexit.py`](../tests/test_awg_cascade_multiexit.py) | Unit-тесты мульти-exit каскада в awg_cascade.py. | ✓ |
| [`test_awg_compat.py`](../tests/test_awg_compat.py) | Unit-тесты для chimera/modules/awg_compat.py. | ✓ |
| [`test_awg_compat_31.py`](../tests/test_awg_compat_31.py) | Unit-тесты детекции поддержки AWG 3.1 (awg_compat.py) и диагностики версии | ✓ |
| [`test_awg_constants.py`](../tests/test_awg_constants.py) | Unit-тесты для chimera/modules/awg_constants.py. | ✓ |
| [`test_awg_diagnose.py`](../tests/test_awg_diagnose.py) | Unit-тесты для chimera/modules/awg_diagnose.py. | ✓ |
| [`test_awg_expires.py`](../tests/test_awg_expires.py) | Unit-тесты для chimera/modules/awg_expires.py. | ✓ |
| [`test_awg_hw_tuning.py`](../tests/test_awg_hw_tuning.py) | Unit-тесты для chimera/modules/awg_hw_tuning.py. | ✓ |
| [`test_awg_i2i5_mimicry.py`](../tests/test_awg_i2i5_mimicry.py) | Unit-тесты автозаполнения I2-I5 (сверка с генератором ARCHITECT, Task 31): | ✓ |
| [`test_awg_install_fixes.py`](../tests/test_awg_install_fixes.py) | Юнит-тесты фиксов (E2E fi1 2026-10-03): | ✓ |
| [`test_awg_ipv6_dualstack.py`](../tests/test_awg_ipv6_dualstack.py) | Unit-тесты для IPv6-интеграции AWG. | ✓ |
| [`test_awg_net_common.py`](../tests/test_awg_net_common.py) | Unit-тесты для chimera/modules/awg_net_common.py. | ✓ |
| [`test_awg_peers.py`](../tests/test_awg_peers.py) | Unit-тесты для chimera/modules/awg_peers.py. | ✓ |
| [`test_awg_presets.py`](../tests/test_awg_presets.py) | Unit-тесты для chimera/modules/awg_presets.py. | ✓ |
| [`test_awg_presets_31.py`](../tests/test_awg_presets_31.py) | Unit-тесты генерации/валидации параметров AmneziaWG 3.1 в awg_presets.py. | ✓ |
| [`test_awg_protocol_31.py`](../tests/test_awg_protocol_31.py) | Unit-тесты для chimera/modules/awg_protocol.py — версионное ядро AWG 2.0/3.1. | ✓ |
| [`test_awg_qr.py`](../tests/test_awg_qr.py) | Unit-тесты для chimera/modules/awg_qr.py. | ✓ |
| [`test_awg_qr_31.py`](../tests/test_awg_qr_31.py) | Unit-тесты AWG 3.1 в awg_qr.py — клиентские конфиги и vpn:// URI. | ✓ |
| [`test_awg_rest_api.py`](../tests/test_awg_rest_api.py) | Unit-тесты для chimera/modules/awg_rest_api.py и интеграции с rest_api. | ✓ |
| [`test_awg_standalone.py`](../tests/test_awg_standalone.py) | Unit-тесты для chimera/modules/awg_standalone.py. | ✓ |
| [`test_awg_standalone_31.py`](../tests/test_awg_standalone_31.py) | Unit-тесты AWG 3.1 в awg_standalone.py / awg_state.py / awg_peers.py. | ✓ |
| [`test_awg_state.py`](../tests/test_awg_state.py) | Unit-тесты для chimera/modules/awg_state.py. | ✓ |
| [`test_awg_transport.py`](../tests/test_awg_transport.py) | Unit-тесты для chimera/modules/awg_transport.py. | ✓ |
| [`test_awg_transport_31.py`](../tests/test_awg_transport_31.py) | Unit-тесты AWG 3.1 в awg_transport.py — Mode B (транспорт exit-ноды). | ✓ |
| [`test_awg_ui_smoke.py`](../tests/test_awg_ui_smoke.py) | UI-smoke стилизации AWG-семейства (кейс стилизации AWG TUI, окт.2026). | ✓ |

## Альтернативные протоколы (21)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_csqtt_manual_binary.py`](../tests/test_csqtt_manual_binary.py) | Unit-тесты ГОТОВЫЙ бинарь csqtt-server, собранный на другой машине | ✓ |
| [`test_csqtt_packages.py`](../tests/test_csqtt_packages.py) | Unit-тесты для chimera/modules/csqtt_packages.py. | ✓ |
| [`test_csqtt_uninstall_state.py`](../tests/test_csqtt_uninstall_state.py) | Unit-тесты починки трёх живых кейсов CSQTT: | ✓ |
| [`test_fptn.py`](../tests/test_fptn.py) | Unit-тесты для chimera/modules/fptn.py. | ✓ |
| [`test_hybrid_addon.py`](../tests/test_hybrid_addon.py) | Unit-тесты для chimera/modules/hybrid_addon.py. | ✓ |
| [`test_naiveproxy.py`](../tests/test_naiveproxy.py) | Unit-тесты для chimera/modules/naiveproxy.py. | ✓ |
| [`test_naiveproxy_fptn_mirrors.py`](../tests/test_naiveproxy_fptn_mirrors.py) | Unit-тесты для mirror-реестров и specs Волны 4 (naiveproxy + fptn): | ✓ |
| [`test_naiveproxy_stats.py`](../tests/test_naiveproxy_stats.py) | Unit-тесты для chimera/modules/naiveproxy_stats.py. | ✓ |
| [`test_no_streamup_typo.py`](../tests/test_no_streamup_typo.py) | Регрессионный тест на опечатку "streamup" (без дефиса). | ✓ |
| [`test_olcrtc.py`](../tests/test_olcrtc.py) | Unit-тесты для chimera/modules/olcrtc.py — переработанная версия с manager panel. | ✓ |
| [`test_proto_common.py`](../tests/test_proto_common.py) | Unit-тесты для chimera/modules/proto_common.py — общие хелперы | ✓ |
| [`test_proto_port_username_v424.py`](../tests/test_proto_port_username_v424.py) | Тесты для v4.24 — выбор порта + имя первого пользователя в протоколах: | ✓ |
| [`test_slipgate.py`](../tests/test_slipgate.py) | Unit-тесты для chimera/modules/slipgate.py. | ✓ |
| [`test_trusttunnel.py`](../tests/test_trusttunnel.py) | Unit-тесты для chimera/modules/trusttunnel.py (main module). | ✓ |
| [`test_trusttunnel_user_lifecycle.py`](../tests/test_trusttunnel_user_lifecycle.py) | Unit-тесты для TrustTunnelAdapter + batched restart mechanism in user_lifecycle.py. | ✓ |
| [`test_turnable.py`](../tests/test_turnable.py) | Unit-тесты для chimera/modules/turnable.py. | ✓ |
| [`test_turntunnel.py`](../tests/test_turntunnel.py) | Unit-тесты для chimera/modules/turntunnel.py. | ✓ |
| [`test_turntunnel_links.py`](../tests/test_turntunnel_links.py) | Unit-тесты для chimera/modules/turntunnel_links.py. | ✓ |
| [`test_wdtt.py`](../tests/test_wdtt.py) | Unit-тесты для chimera/modules/wdtt.py. | ✓ |
| [`test_wdtt_webdav_mirrors.py`](../tests/test_wdtt_webdav_mirrors.py) | Unit-тесты для mirror-реестров и PackageSpecs Волны 2: | ✓ |
| [`test_webdav_tunnel.py`](../tests/test_webdav_tunnel.py) | Unit-тесты для chimera/modules/webdav_tunnel.py. | ✓ |

## Мониторинг и трафик (20)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_bandwidth_monitor.py`](../tests/test_bandwidth_monitor.py) | tests/test_bandwidth_monitor.py — unit-тесты для bandwidth_monitor. | ✓ |
| [`test_certmon_v2.py`](../tests/test_certmon_v2.py) | Тесты v2 генератора _certbot_install_monitor_cron (chimera/modules/ssl_certbot.py). | ✓ |
| [`test_connection_audit.py`](../tests/test_connection_audit.py) | Unit-тесты для chimera/modules/connection_audit.py. | ✓ |
| [`test_diagnostics.py`](../tests/test_diagnostics.py) | Unit-тесты для chimera/modules/diagnostics.py. | ✓ |
| [`test_diagnostics_errorlog.py`](../tests/test_diagnostics_errorlog.py) | Unit-тесты для chimera/modules/diagnostics.py: проверка фильтра _BENIGN_PATTERNS | ✓ |
| [`test_domain_external_check.py`](../tests/test_domain_external_check.py) | Регрессия живого кейса (окт. 2026, прод-юзер, скрин WARN): | ✓ |
| [`test_health.py`](../tests/test_health.py) | Unit-тесты для chimera/modules/health.py. | ✓ |
| [`test_health_report.py`](../tests/test_health_report.py) | Unit-тесты для chimera/modules/health_report.py. | ✓ |
| [`test_logrotate.py`](../tests/test_logrotate.py) | Unit-тесты для chimera/modules/logrotate.py. | ✓ |
| [`test_speed_test_cf_cap.py`](../tests/test_speed_test_cf_cap.py) | Регрессия живого кейса (окт. 2026, №15, прод-юзер): | ✓ |
| [`test_speed_test_cf_doh.py`](../tests/test_speed_test_cf_doh.py) | Unit-тесты для DoH-резолва speed.cloudflare.com в speed-test функциях. | ✓ |
| [`test_speed_test_chain_fail.py`](../tests/test_speed_test_chain_fail.py) | Регрессия живого кейса (окт. 2026, прод-юзер, скриншоты error1/error2): | ✓ |
| [`test_status_awg_v3.py`](../tests/test_status_awg_v3.py) | Тесты v3 статуса каскада в TG-боте (08.10.2026). | ✓ |
| [`test_status_panel.py`](../tests/test_status_panel.py) | Unit-тесты для chimera/modules/status_panel.py. | ✓ |
| [`test_steal_monitor.py`](../tests/test_steal_monitor.py) | Unit-тесты для chimera/modules/steal_monitor.py — CPU Steal монитор. | ✓ |
| [`test_traffic_accounting.py`](../tests/test_traffic_accounting.py) | Unit-тесты для chimera/modules/traffic_accounting.py. | ✓ |
| [`test_traffic_collectors.py`](../tests/test_traffic_collectors.py) | Реалистичные тесты для трёх protocol-specific коллекторов трафика: | ✓ |
| [`test_traffic_dispatcher.py`](../tests/test_traffic_dispatcher.py) | Unit-тесты на мультипротокольный диспетчер трафика: | ✓ |
| [`test_traffic_history.py`](../tests/test_traffic_history.py) | Unit-тесты для chimera/modules/traffic_history.py. | ✓ |
| [`test_traffic_tracking.py`](../tests/test_traffic_tracking.py) | Unit-тесты для chimera/modules/traffic_tracking.py. | ✓ |

## Ядро и TUI (16)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_box_renderer.py`](../tests/test_box_renderer.py) | Unit-тесты для chimera/modules/box_renderer.py. | ✓ |
| [`test_core_dns_redirect_integration.py`](../tests/test_core_dns_redirect_integration.py) | Регрессионный тест Bug 4: _do_dns_redirect_health_screen() в _core.py | ✓ |
| [`test_core_dynamic_version.py`](../tests/test_core_dynamic_version.py) | Тест динамической подстановки версии в chimera/_core.py. | ✓ |
| [`test_cron_subprocess_integration.py`](../tests/test_cron_subprocess_integration.py) | ИНТЕГРАЦИОННЫЕ тесты cron-команд, которые РЕАЛЬНО запускают сгенерированные | ✓ |
| [`test_download_manager.py`](../tests/test_download_manager.py) | Unit-тесты для chimera/modules/download_manager.py. | ✓ |
| [`test_env_isolation.py`](../tests/test_env_isolation.py) | Самопроверка env-изоляции (tests/_env_isolation.py) — гард группы 8 | ✓ |
| [`test_resources.py`](../tests/test_resources.py) | Unit-тесты для chimera/modules/resources.py. | ✓ |
| [`test_scheduler.py`](../tests/test_scheduler.py) | Unit-тесты для chimera/modules/scheduler.py. | ✓ |
| [`test_smoke_test.py`](../tests/test_smoke_test.py) | Unit-тесты для chimera/modules/smoke_test.py. | ✓ |
| [`test_test_runner.py`](../tests/test_test_runner.py) | Unit-тесты для chimera/modules/test_runner.py. | ✓ |
| [`test_text_width.py`](../tests/test_text_width.py) | Unit-тесты для chimera/modules/text_width.py. | ✓ |
| [`test_tty_json.py`](../tests/test_tty_json.py) | Unit-тесты для chimera/modules/_tty_json.py — обход 4-КБ лимита TTY-буфера | ✓ |
| [`test_tui.py`](../tests/test_tui.py) | Unit-тесты для chimera/modules/tui.py. | ✓ |
| [`test_ui_restyle_batch2_smoke.py`](../tests/test_ui_restyle_batch2_smoke.py) | UI-smoke стилизации второй партии модулей (окт.2026, продолжение кейса | ✓ |
| [`test_ui_restyle_batch3_smoke.py`](../tests/test_ui_restyle_batch3_smoke.py) | UI-smoke стилизации третьей партии модулей (окт.2026, продолжение кейса | ✓ |
| [`test_updater.py`](../tests/test_updater.py) | Unit-тесты модуля самообновления Chimera (chimera/modules/updater.py). | ✓ |

## Маршрутизация и GeoIP (15)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_as_direct.py`](../tests/test_as_direct.py) | Unit-тесты для chimera/modules/as_direct.py. | ✓ |
| [`test_asn_cache.py`](../tests/test_asn_cache.py) | Unit-тесты для chimera/modules/asn_cache.py. | ✓ |
| [`test_geo_asset_path.py`](../tests/test_geo_asset_path.py) | : регрессионные тесты гео-активов Xray. | ✓ |
| [`test_geo_cron_script.py`](../tests/test_geo_cron_script.py) | Smoke-тест для bash-скрипта автообновления geo-файлов (setup_geo_autoupdate). | ✓ |
| [`test_geo_emergency_fallback.py`](../tests/test_geo_emergency_fallback.py) | Regression-тесты для chimera/modules/geo_files.py::emergency_curl_fallback | ✓ |
| [`test_geo_files.py`](../tests/test_geo_files.py) | Unit-тесты для chimera/modules/geo_files.py. | ✓ |
| [`test_geo_mirrors.py`](../tests/test_geo_mirrors.py) | Unit-тесты для chimera/modules/geo_mirrors.py. | ✓ |
| [`test_geo_resistant_dns.py`](../tests/test_geo_resistant_dns.py) | : гео-резистентность DNS-стека Chimera — добивка. | ✓ |
| [`test_geoblock.py`](../tests/test_geoblock.py) | Тесты для chimera/modules/geoblock.py — гео-блокировка по странам. | ✓ |
| [`test_geoip_block.py`](../tests/test_geoip_block.py) | Unit-тесты для chimera/modules/geoip_block.py. | ✓ |
| [`test_geosite_category_check.py`](../tests/test_geosite_category_check.py) | Тесты для _geosite_has_category() и условного добавления geosite-правил | ✓ |
| [`test_ingress_geoip.py`](../tests/test_ingress_geoip.py) | Unit-тесты для chimera/modules/ingress_geoip.py. | ✓ |
| [`test_ingress_port_follow_agh_autostart.py`](../tests/test_ingress_port_follow_agh_autostart.py) | : два контракта. | ✓ |
| [`test_ripe_file_age.py`](../tests/test_ripe_file_age.py) | Unit-тесты для chimera/modules/ripe_file_age.py. | ✓ |
| [`test_ru_subnets.py`](../tests/test_ru_subnets.py) | Unit-тесты для chimera/modules/ru_subnets.py. | ✓ |

## Hysteria2 (14)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_hysteria2_backup.py`](../tests/test_hysteria2_backup.py) | Unit-тесты для chimera/modules/hysteria2_backup.py. | ✓ |
| [`test_hysteria2_balancer.py`](../tests/test_hysteria2_balancer.py) | tests/test_hysteria2_balancer.py — _live_nodes, _weighted_random, _least_rtt, | ✓ |
| [`test_hysteria2_cert_mgr.py`](../tests/test_hysteria2_cert_mgr.py) | Unit-тесты для chimera/modules/hysteria2_cert_mgr.py. | ✓ |
| [`test_hysteria2_cluster.py`](../tests/test_hysteria2_cluster.py) | Unit-тесты для chimera/modules/hysteria2_cluster.py. | ✓ |
| [`test_hysteria2_common.py`](../tests/test_hysteria2_common.py) | Unit-тесты для chimera/modules/hysteria2_common.py. | ✓ |
| [`test_hysteria2_dnscrypt_mirrors.py`](../tests/test_hysteria2_dnscrypt_mirrors.py) | Unit-тесты для mirror-реестров Волны 3: | ✓ |
| [`test_hysteria2_dpi.py`](../tests/test_hysteria2_dpi.py) | Unit-тесты для chimera/modules/hysteria2_dpi.py. | ✓ |
| [`test_hysteria2_exit_mgr.py`](../tests/test_hysteria2_exit_mgr.py) | tests/test_hysteria2_exit_mgr.py — _generate_h2_config | ✓ |
| [`test_hysteria2_quality.py`](../tests/test_hysteria2_quality.py) | Unit-тесты для chimera/modules/hysteria2_quality.py. | ✓ |
| [`test_hysteria2_salamander.py`](../tests/test_hysteria2_salamander.py) | Unit-тесты для chimera/modules/hysteria2_salamander.py. | ✓ |
| [`test_hysteria2_smoke_test.py`](../tests/test_hysteria2_smoke_test.py) | Unit-тесты для chimera/modules/hysteria2_smoke_test.py. | ✓ |
| [`test_hysteria2_traffic.py`](../tests/test_hysteria2_traffic.py) | Unit-тесты для chimera/modules/hysteria2_traffic.py. | ✓ |
| [`test_hysteria2_transport.py`](../tests/test_hysteria2_transport.py) | Unit-тесты для chimera/modules/hysteria2_transport.py. | ✓ |
| [`test_hysteria2_watchdog.py`](../tests/test_hysteria2_watchdog.py) | Unit-тесты для chimera/modules/hysteria2_watchdog.py. | ✓ |

## sing-box / мульти-протокольные ядра (14)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_singbox_client_links.py`](../tests/test_singbox_client_links.py) | Unit-тесты для генератора клиентских ссылок v4.23.12. | ✓ |
| [`test_singbox_client_rulesets.py`](../tests/test_singbox_client_rulesets.py) | Тесты для модуля chimera/modules/singbox_client_rulesets.py. | ✓ |
| [`test_singbox_config.py`](../tests/test_singbox_config.py) | Unit-тесты для chimera/modules/singbox_config.py и singbox_state.py. | ✓ |
| [`test_singbox_install.py`](../tests/test_singbox_install.py) | Unit-тесты для chimera/modules/singbox_install.py. | ✓ |
| [`test_singbox_multinode_config.py`](../tests/test_singbox_multinode_config.py) | регресс-тесты клиентского sing-box-конфига мульти-ноды (Режим B). | ✓ |
| [`test_singbox_nginx.py`](../tests/test_singbox_nginx.py) | Unit-тесты для chimera/modules/singbox_nginx.py. | ✓ |
| [`test_singbox_packages.py`](../tests/test_singbox_packages.py) | Unit-тесты для chimera/modules/singbox_packages.py и singbox_mirrors.py. | ✓ |
| [`test_singbox_sni_autoconfig.py`](../tests/test_singbox_sni_autoconfig.py) | Тесты для v4.23.5-v4.23.6: SNI-dispatch auto-config + common_name fix. | ✓ |
| [`test_singbox_state.py`](../tests/test_singbox_state.py) | Unit-тесты для chimera/modules/singbox_state.py. | ✓ |
| [`test_singbox_ufw.py`](../tests/test_singbox_ufw.py) | Unit-тесты для chimera/modules/singbox_ufw.py (v4.23.14). | ✓ |
| [`test_singbox_vless_ws_cdn.py`](../tests/test_singbox_vless_ws_cdn.py) | Unit-тесты для VLESS-WS-CDN (v4.23). | ✓ |
| [`test_singbox_vless_ws_cdn_fix.py`](../tests/test_singbox_vless_ws_cdn_fix.py) | Тесты для v4.23.1 — фиксы двух багов из v4.23: | ✓ |
| [`test_singbox_vless_ws_cdn_fix2.py`](../tests/test_singbox_vless_ws_cdn_fix2.py) | Тесты для v4.23.2 — 4 продакшн-фикса из v4.23.1: | ✓ |
| [`test_singbox_vless_ws_cdn_fix3.py`](../tests/test_singbox_vless_ws_cdn_fix3.py) | Тесты для v4.23.3 — 2 фикса порядка операций: | ✓ |

## Клиентские ссылки/конфиги (12)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_cdn_masking_guide.py`](../tests/test_cdn_masking_guide.py) | Unit-тесты для chimera/modules/cdn_masking_guide.py — печать инструкции | ✓ |
| [`test_cdn_masking_path_skip.py`](../tests/test_cdn_masking_path_skip.py) | Unit-тесты для проверки skip-логики вопроса о path в _prompt_xhttp_options() | ✓ |
| [`test_client_config_export.py`](../tests/test_client_config_export.py) | Unit-тесты для chimera/modules/client_config_export.py — TUI генерация | ✓ |
| [`test_ios_link_regression.py`](../tests/test_ios_link_regression.py) | Регрессионные тесты для iOS/Karing-ветки генерации VLESS-ссылок. | ✓ |
| [`test_ios_link_variant.py`](../tests/test_ios_link_variant.py) | Unit-тесты для chimera/modules/ios_link_variant.py — | ✓ |
| [`test_ios_patch4_open_surfaces.py`](../tests/test_ios_patch4_open_surfaces.py) | Регрессионные тесты для патча №4 — открытие двух закрытых TODO-веток | ✓ |
| [`test_ios_patch5_subscription_cleanup.py`](../tests/test_ios_patch5_subscription_cleanup.py) | Регрессионные тесты для патча №5 — открытие /sub/{token}/ios маршрута, | ✓ |
| [`test_ios_shadow_client.py`](../tests/test_ios_shadow_client.py) | Регрессионные тесты для ПАТЧА №2 (теневой iOS-клиент без XTLS Vision flow). | ✓ |
| [`test_ios_unified_menu.py`](../tests/test_ios_unified_menu.py) | Тесты для мини-патча №3: пункт K в do_unified_user_manager + функция | ✓ |
| [`test_linkqr_lib.py`](../tests/test_linkqr_lib.py) | Unit-тесты для chimera/modules/linkqr_lib.py. | ✓ |
| [`test_mtu_tuning.py`](../tests/test_mtu_tuning.py) | Unit-тесты для chimera/modules/mtu_tuning.py. | ✓ |
| [`test_pq_vless.py`](../tests/test_pq_vless.py) | Unit-тесты для chimera/modules/pq_vless.py. | ✓ |

## Фрагментация TLS (fragment-стек) (12)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_fragment_config.py`](../tests/test_fragment_config.py) | Unit-тесты для chimera/modules/fragment_config.py. | ✓ |
| [`test_fragment_fuzzer.py`](../tests/test_fragment_fuzzer.py) | Unit-тесты для chimera/modules/fragment_fuzzer.py. | ✓ |
| [`test_fragment_guide.py`](../tests/test_fragment_guide.py) | Unit-тесты для chimera/modules/fragment_guide.py. | ✓ |
| [`test_fragment_link.py`](../tests/test_fragment_link.py) | Unit-тесты для chimera/modules/fragment_link.py. | ✓ |
| [`test_fragment_log_viewer.py`](../tests/test_fragment_log_viewer.py) | Unit-тесты для chimera/modules/fragment_log_viewer.py. | ✓ |
| [`test_fragment_mux.py`](../tests/test_fragment_mux.py) | Unit-тесты для chimera/modules/fragment_mux.py. | ✓ |
| [`test_fragment_noise.py`](../tests/test_fragment_noise.py) | Unit-тесты для chimera/modules/fragment_noise.py. | ✓ |
| [`test_fragment_presets.py`](../tests/test_fragment_presets.py) | Unit-тесты для chimera/modules/fragment_presets.py. | ✓ |
| [`test_fragment_share.py`](../tests/test_fragment_share.py) | Unit-тесты для chimera/modules/fragment_share.py. | ✓ |
| [`test_fragment_stats.py`](../tests/test_fragment_stats.py) | Unit-тесты для chimera/modules/fragment_stats.py. | ✓ |
| [`test_fragment_watchdog.py`](../tests/test_fragment_watchdog.py) | Unit-тесты для chimera/modules/fragment_watchdog.py. | ✓ |
| [`test_server_fragment.py`](../tests/test_server_fragment.py) | Unit-тесты для chimera/modules/server_fragment.py (v4.28+, Task 24 / 24-5b). | ✓ |

## Mieru (12)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_mieru.py`](../tests/test_mieru.py) | Unit-тесты для chimera/modules/mieru.py. | ✓ |
| [`test_mieru_cascade_b4qlog.py`](../tests/test_mieru_cascade_b4qlog.py) | Unit-тесты querylog-harvest в chimera/modules/mieru_cascade.py — третьего | ✓ |
| [`test_mieru_cascade_health_timer.py`](../tests/test_mieru_cascade_health_timer.py) | Unit-тесты systemd-юнитов mieru_cascade: расписание health-таймера. | ✓ |
| [`test_mieru_cascade_lb_exits.py`](../tests/test_mieru_cascade_lb_exits.py) | Состав балансировки Exit-ов (lb_exits) в mieru-каскаде — порт выбора | ✓ |
| [`test_mieru_cascade_monitor.py`](../tests/test_mieru_cascade_monitor.py) | Unit-тесты TG-монитора mieru-каскада (chimera/modules/mieru_cascade_monitor.py). | ✓ |
| [`test_mieru_cascade_redsocks_guard.py`](../tests/test_mieru_cascade_redsocks_guard.py) | Unit-тесты redsocks-guard mieru_cascade (инцидент DNS 2026-10-03). | ✓ |
| [`test_mieru_cascade_weights_hysteresis.py`](../tests/test_mieru_cascade_weights_hysteresis.py) | Гистерезис дрейфа весов в health-тике mieru-каскада. | ✓ |
| [`test_mieru_download.py`](../tests/test_mieru_download.py) | Тесты для multi-mirror логики скачивания mita/mieru в chimera/modules/mieru.py. | ✓ |
| [`test_mieru_dpi.py`](../tests/test_mieru_dpi.py) | Unit-тесты для chimera/modules/mieru_dpi.py — модуля «Mieru + B4» | ✓ |
| [`test_mieru_mirrors.py`](../tests/test_mieru_mirrors.py) | Unit-тесты для chimera/modules/mieru_mirrors.py. | ✓ |
| [`test_mieru_stats.py`](../tests/test_mieru_stats.py) | Unit-тесты для chimera/modules/mieru_stats.py. | ✓ |
| [`test_mieru_traffic_presets.py`](../tests/test_mieru_traffic_presets.py) | Unit-тесты для chimera/modules/mieru_traffic_presets.py. | ✓ |

## Пользователи и доступ (11)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_access_control.py`](../tests/test_access_control.py) | Unit-тесты для chimera/modules/access_control.py — master + OTP парольная защита. | ✓ |
| [`test_credential_rotation.py`](../tests/test_credential_rotation.py) | Unit-тесты для chimera/modules/credential_rotation.py. | ✓ |
| [`test_fingerprint_manager.py`](../tests/test_fingerprint_manager.py) | Unit-тесты для chimera/modules/fingerprint_manager.py. | ✓ |
| [`test_identity_guard.py`](../tests/test_identity_guard.py) | Unit-тесты для (Anti-Empty Identity Guard): | ✓ |
| [`test_user_fp_manager.py`](../tests/test_user_fp_manager.py) | Unit-тесты для chimera/modules/user_fp_manager.py. | ✓ |
| [`test_user_ip_whitelist.py`](../tests/test_user_ip_whitelist.py) | Unit-тесты для chimera/modules/user_ip_whitelist.py — per-user IP whitelist. | ✓ |
| [`test_user_lifecycle.py`](../tests/test_user_lifecycle.py) | Unit-тесты для chimera/modules/user_lifecycle.py. | ✓ |
| [`test_user_portal.py`](../tests/test_user_portal.py) | Smoke-тест для chimera/modules/user_portal.py. | ✓ |
| [`test_user_sync_v425.py`](../tests/test_user_sync_v425.py) | Тесты для v4.25 — двусторонняя синхронизация пользователей между VLESS | ✓ |
| [`test_users_manager.py`](../tests/test_users_manager.py) | Unit-тесты для chimera/modules/users_manager.py — управление | ✓ |
| [`test_users_watchdog.py`](../tests/test_users_watchdog.py) | Unit-тесты для chimera/modules/users_watchdog.py. | ✓ |

## Гигиена репо и CI (11)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_all_specs_real_fetch_package.py`](../tests/test_all_specs_real_fetch_package.py) | ОБЯЗАТЕЛЬНЫЕ regression-тесты для КАЖДОГО PackageSpec в проекте. | ✓ |
| [`test_clean_install_no_warnings.py`](../tests/test_clean_install_no_warnings.py) | : чистая переустановка БЕЗ предупреждений (инцидент <ip>). | ✓ |
| [`test_const_default_scan.py`](../tests/test_const_default_scan.py) | Самопроверка const-default сканера (scripts/const_default_scan.py) + ГЕЙТ: | ✓ |
| [`test_fake_login_template.py`](../tests/test_fake_login_template.py) | Unit-тесты для chimera/modules/nginx_setup_templates.py — шаблон #16 | ✓ |
| [`test_leak_guard.py`](../tests/test_leak_guard.py) | Unit-тесты scripts/leak_guard.py — гард гигиены репозитория. | ✓ |
| [`test_py_compat.py`](../tests/test_py_compat.py) | Гард совместимости исходников с Python 3.10/3.11 — заявленным минимумом | ✓ |
| [`test_release_notes.py`](../tests/test_release_notes.py) | — | ✓ |
| [`test_tests_index.py`](../tests/test_tests_index.py) | — | ✓ |
| [`test_wave5_mirrors.py`](../tests/test_wave5_mirrors.py) | Unit-тесты для mirror-реестров и specs Волны 5: | ✓ |
| [`test_wave6_mirrors.py`](../tests/test_wave6_mirrors.py) | Unit-тесты для mirror-реестров и specs Волны 6 (awg_transport + olcrtc): | ✓ |
| [`test_wave6_smoke.py`](../tests/test_wave6_smoke.py) | Smoke-тесты для оставшихся модулей Волны 6: | ✓ |

## Установка/bootstrap (11)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_bootstrap_mirrors.py`](../tests/test_bootstrap_mirrors.py) | Unit-тесты мульти-источникового bootstrap.sh (CHIMERA_MIRROR / CHIMERA_BRANCH). | ✓ |
| [`test_emergency_repair_socket_wait.py`](../tests/test_emergency_repair_socket_wait.py) | Юнит-тест на логику ожидания Unix-сокета в аварийном восстановлении. | ✓ |
| [`test_install_prompts.py`](../tests/test_install_prompts.py) | Unit-тесты для chimera/modules/install_prompts.py — _prompt_h1_h4_unique(). | ✓ |
| [`test_nginx_cdn_masking_config.py`](../tests/test_nginx_cdn_masking_config.py) | Регрессионные тесты на баги в CDN masking профиле nginx-конфига: | ✓ |
| [`test_nginx_cleanup_stale_vhosts.py`](../tests/test_nginx_cleanup_stale_vhosts.py) | Тесты для chimera.modules.nginx_setup._cleanup_stale_chimera_vhosts. | ✓ |
| [`test_nginx_watchdog.py`](../tests/test_nginx_watchdog.py) | Unit-тесты для chimera/modules/nginx_watchdog.py. | ✓ |
| [`test_secure_bootstrap.py`](../tests/test_secure_bootstrap.py) | Тесты безопасной мульти-зеркальной установки (CHIMERA SECURE INSTALL). | ✓ |
| [`test_ssl_cert_guard.py`](../tests/test_ssl_cert_guard.py) | : защита LE-сертификата + устойчивая DNS-проверка (инцидент 203.0.113.102). | ✓ |
| [`test_ssl_certbot.py`](../tests/test_ssl_certbot.py) | Unit-тесты для chimera/modules/ssl_certbot.py. | ✓ |
| [`test_uninstall_dns_alive.py`](../tests/test_uninstall_dns_alive.py) | Regression-тесты инцидента (server-ru): ПОЛНОЕ удаление Chimera | ✓ |
| [`test_uninstall_nginx_safety.py`](../tests/test_uninstall_nginx_safety.py) | Regression-тесты для критического бага в uninstall.py. | ✓ |

## Telemt (телеметрия) (11)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_mtproto.py`](../tests/test_mtproto.py) | Unit-тесты для chimera/modules/mtproto.py — Telemt MTProto Proxy. | ✓ |
| [`test_mtproto_limits.py`](../tests/test_mtproto_limits.py) | Тесты для per-user лимитов Telemt (квота трафика + срок действия). | ✓ |
| [`test_mtproto_stats.py`](../tests/test_mtproto_stats.py) | Unit-тесты для chimera/modules/mtproto_stats.py. | ✓ |
| [`test_telemt_download.py`](../tests/test_telemt_download.py) | Тесты для multi-mirror логики скачивания telemt/telemt-panel. | ✓ |
| [`test_telemt_fallback.py`](../tests/test_telemt_fallback.py) | Unit-тесты для chimera/modules/telemt_fallback.py. | ✓ |
| [`test_telemt_ios_fix.py`](../tests/test_telemt_ios_fix.py) | Unit-тесты для chimera/modules/telemt_ios_fix.py. | ✓ |
| [`test_telemt_mirrors.py`](../tests/test_telemt_mirrors.py) | Unit-тесты для chimera/modules/telemt_mirrors.py. | ✓ |
| [`test_telemt_mss_selector.py`](../tests/test_telemt_mss_selector.py) | Unit-тесты для chimera/modules/telemt_mss_selector.py. | ✓ |
| [`test_telemt_nginx_fallback.py`](../tests/test_telemt_nginx_fallback.py) | Регресс-тесты для Telemt nginx-fallback (свой домен + свой сайт вместо | ✓ |
| [`test_telemt_panel.py`](../tests/test_telemt_panel.py) | Unit-тесты для chimera/modules/telemt_panel.py. | ✓ |
| [`test_telemt_syn_limiter.py`](../tests/test_telemt_syn_limiter.py) | Unit-тесты для chimera/modules/telemt_syn_limiter.py. | ✓ |

## WPP: веб-панели и REST API (10)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_admin_panel.py`](../tests/test_admin_panel.py) | Smoke-тест для chimera/modules/admin_panel.py. | ✓ |
| [`test_admin_whitelist_geo_dns.py`](../tests/test_admin_whitelist_geo_dns.py) | : регрессионные тесты двух инцидентов. | ✓ |
| [`test_panel_nginx_front_input.py`](../tests/test_panel_nginx_front_input.py) | Регрессионные тесты инцидента 29.08.2026 (прод, vds-old): | ✓ |
| [`test_rest_api.py`](../tests/test_rest_api.py) | Unit-тесты для chimera/modules/rest_api.py — функции генерации | ✓ |
| [`test_rest_api_auth.py`](../tests/test_rest_api_auth.py) | Unit-тесты для auth-функций из chimera/modules/rest_api.py | ✓ |
| [`test_rest_api_web_panel_firewall.py`](../tests/test_rest_api_web_panel_firewall.py) | Тесты для ufw-управления веб-панелью (admin + user portal) в rest_api.py. | ✓ |
| [`test_triple_panel.py`](../tests/test_triple_panel.py) | Unit-тесты для chimera/modules/triple_panel.py + triple_panel_web.py. | ✓ |
| [`test_wpp_awg_adapters.py`](../tests/test_wpp_awg_adapters.py) | tests/test_wpp_awg_adapters.py — адаптеры rest_api-стиля для WPP-хендлера. | ✓ |
| [`test_wpp_portal_mieru.py`](../tests/test_wpp_portal_mieru.py) | tests/test_wpp_portal_mieru.py — вкладка Mieru + «Подключение: все протоколы». | ✓ |
| [`test_wpp_upstream_sync.py`](../tests/test_wpp_upstream_sync.py) | Регрессия синхронизации WPP с апстримом POLESNIESOVETI12/web-panel-proxy | ✓ |

## Сеть и системный слой (10)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_cold_boot_restore.py`](../tests/test_cold_boot_restore.py) | Unit-тесты для chimera/modules/cold_boot_restore.py. | ✓ |
| [`test_enable_dns_ipv6_script.py`](../tests/test_enable_dns_ipv6_script.py) | проверки scripts/enable-dns-ipv6.sh — структурные и функциональные. | ✓ |
| [`test_fw_guard.py`](../tests/test_fw_guard.py) | Unit-тесты для chimera/modules/fw_guard.py. | ✓ |
| [`test_ipset_boot_sync.py`](../tests/test_ipset_boot_sync.py) | Unit-тесты для chimera/modules/ipset_boot_sync.py — бут-восстановление | ✓ |
| [`test_ipset_persist.py`](../tests/test_ipset_persist.py) | Unit-тесты для chimera/modules/ipset_persist.py. | ✓ |
| [`test_network_bench.py`](../tests/test_network_bench.py) | Unit-тесты для chimera/modules/network_bench.py. | ✓ |
| [`test_network_setup.py`](../tests/test_network_setup.py) | Unit-тесты для chimera/modules/network_setup.py — configure_firewall(). | ✓ |
| [`test_resolv_conf_fix.py`](../tests/test_resolv_conf_fix.py) | Unit-тесты для chimera/modules/resolv_conf_fix.py v6 — static resolv.conf + | ✓ |
| [`test_system_deps.py`](../tests/test_system_deps.py) | Unit-тесты для chimera/modules/system_deps.py. | ✓ |
| [`test_system_doctor.py`](../tests/test_system_doctor.py) | Unit-тесты для chimera/modules/system_doctor.py. | ✓ |

## Установка/конфиг Xray (10)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_domain_strategy.py`](../tests/test_domain_strategy.py) | Unit-тесты для chimera/modules/domain_strategy.py (смена domainStrategy | ✓ |
| [`test_min_client_ver.py`](../tests/test_min_client_ver.py) | Unit-тесты для гейта версий клиента REALITY (minClientVer) — опция меню 5b. | ✓ |
| [`test_sni_dispatch_xray_patch.py`](../tests/test_sni_dispatch_xray_patch.py) | Тесты для v4.23.8: автоматический патч config.json Xray для SNI-dispatch. | ✓ |
| [`test_sni_hygiene.py`](../tests/test_sni_hygiene.py) | tests/test_sni_hygiene.py — SNI/dest-гигиена. | ✓ |
| [`test_tfo_settings.py`](../tests/test_tfo_settings.py) | Unit-тесты для chimera/modules/tfo_settings.py (TCP Fast Open). | ✓ |
| [`test_xray_dns_via_agh.py`](../tests/test_xray_dns_via_agh.py) | : порядок установки AGH→Xray + гарантия «запросы Xray идут через AGH». | ✓ |
| [`test_xray_downgrade.py`](../tests/test_xray_downgrade.py) | Unit-тесты для даунгрейда ядра Xray-core — пункт меню 5c | ✓ |
| [`test_xray_install.py`](../tests/test_xray_install.py) | Unit-тесты для chimera/modules/xray_install.py — установка/обновление | ✓ |
| [`test_xray_safe_apply.py`](../tests/test_xray_safe_apply.py) | Unit-тесты для chimera/modules/xray_safe_apply.py. | ✓ |
| [`test_xray_safe_restart.py`](../tests/test_xray_safe_restart.py) | Unit-тесты для (start-limit-fix): | ✓ |

## Каскад и ноды (Mode B) (9)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_chain_lb_nodes.py`](../tests/test_chain_lb_nodes.py) | Unit-тесты LB-состава (выбор нод для балансировки) VLESS-каскада | ✓ |
| [`test_chain_nodes.py`](../tests/test_chain_nodes.py) | Unit-тесты для chimera/modules/chain_nodes.py — управление exit-нодами | ✓ |
| [`test_chain_relay.py`](../tests/test_chain_relay.py) | Unit-тесты для chimera/modules/chain_relay.py — релейные хопы (многохоповый | ✓ |
| [`test_chain_relay_speed_chunk.py`](../tests/test_chain_relay_speed_chunk.py) | Регрессия живого кейса (окт. 2026, №15): «Download (через цепочку): не измерен» | ✓ |
| [`test_cluster_ops.py`](../tests/test_cluster_ops.py) | Unit-тесты для chimera/modules/cluster_ops.py. | ✓ |
| [`test_exit_switch_watcher.py`](../tests/test_exit_switch_watcher.py) | Unit-тесты для chimera/modules/exit_switch_watcher.py. | ✓ |
| [`test_failover.py`](../tests/test_failover.py) | Unit-тесты для chimera/modules/failover.py. | ✓ |
| [`test_node_health_monitor.py`](../tests/test_node_health_monitor.py) | Unit-тесты для chimera/modules/node_health_monitor.py. | ✓ |
| [`test_smart_balancer.py`](../tests/test_smart_balancer.py) | Unit-тесты для chimera/modules/smart_balancer.py. | ✓ |

## Подписки (subscription) (8)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_satellite_bindings.py`](../tests/test_satellite_bindings.py) | tests/test_satellite_bindings.py — тесты per-user привязки сателлитов. | ✓ |
| [`test_subscription.py`](../tests/test_subscription.py) | Unit-тесты для chimera/modules/subscription.py. | ✓ |
| [`test_subscription_content_negotiation.py`](../tests/test_subscription_content_negotiation.py) | Тесты для content negotiation в единой подписке: | ✓ |
| [`test_subscription_e2e.py`](../tests/test_subscription_e2e.py) | Сквозные (end-to-end) тесты для HTTP-пути единой подписки. | ✓ |
| [`test_subscription_multinode.py`](../tests/test_subscription_multinode.py) | tests/test_subscription_multinode.py — тесты мульти-нодовых конфигов подписки. | ✓ |
| [`test_subscription_nginx_front.py`](../tests/test_subscription_nginx_front.py) | Тесты для nginx front (прямой доступ по домену/IP с TLS) в подписке. | ✓ |
| [`test_subscription_registry.py`](../tests/test_subscription_registry.py) | Тесты для реестра сателлитных протоколов в subscription.py: | ✓ |
| [`test_subscription_uninstall.py`](../tests/test_subscription_uninstall.py) | Тесты для надёжного uninstall/stop сервиса vless-subscription. | ✓ |

## DNS (DNSCrypt, правила, редирект) (7)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_dns_ipv6.py`](../tests/test_dns_ipv6.py) | IPv6 в DNS-стеке Chimera: | ✓ |
| [`test_dns_path_report.py`](../tests/test_dns_path_report.py) | : фактический DNS-путь Xray в health-отчёте меню и emergency repair. | ✓ |
| [`test_dns_redirect.py`](../tests/test_dns_redirect.py) | Unit-тесты для chimera/modules/dns_redirect.py. | ✓ |
| [`test_dns_rules.py`](../tests/test_dns_rules.py) | Unit-тесты для chimera/modules/dns_rules.py. | ✓ |
| [`test_dnscrypt_dynamic_pool.py`](../tests/test_dnscrypt_dynamic_pool.py) | Unit + integration тесты (динамический пул DNSCrypt): | ✓ |
| [`test_dnscrypt_selector.py`](../tests/test_dnscrypt_selector.py) | Unit-тесты для chimera/modules/dnscrypt_selector.py. | ✓ |
| [`test_dnscrypt_setup.py`](../tests/test_dnscrypt_setup.py) | Unit-тесты для chimera/modules/dnscrypt_setup.py. | ✓ |

## Зеркала и апстримы (7)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_entry_mirrors.py`](../tests/test_entry_mirrors.py) | Unit-тесты для chimera/modules/entry_mirrors.py. | ✓ |
| [`test_entry_mirrors_ui_smoke.py`](../tests/test_entry_mirrors_ui_smoke.py) | UI-smoke стилизации Entry Mirrors (продолжение кейса стилизации TUI, окт.2026). | ✓ |
| [`test_github_mirrors.py`](../tests/test_github_mirrors.py) | Unit-тесты для chimera/modules/github_mirrors.py. | ✓ |
| [`test_openflux.py`](../tests/test_openflux.py) | Unit-тесты для chimera/modules/openflux.py. | ✓ |
| [`test_stale_mirror_guard.py`](../tests/test_stale_mirror_guard.py) | (stale-mirror-guard): защита от устаревших кэшей зеркал при установке Xray. | ✓ |
| [`test_turn_mirrors.py`](../tests/test_turn_mirrors.py) | Unit-тесты для chimera/modules/turn_mirrors.py и turn_packages.py. | ✓ |
| [`test_upstream_updates.py`](../tests/test_upstream_updates.py) | Unit-тесты для chimera/modules/upstream_updates.py + layout-probe | ✓ |

## Cloudflare WARP (7)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_warp.py`](../tests/test_warp.py) | Unit-тесты для chimera/modules/warp.py. | ✓ |
| [`test_warp_curated_lists.py`](../tests/test_warp_curated_lists.py) | Unit-тесты для chimera/modules/warp_curated_lists.py. | ✓ |
| [`test_warp_install.py`](../tests/test_warp_install.py) | Unit-тесты установки/удаления WARP (warp.install_warp / uninstall_warp): | ✓ |
| [`test_warp_scan_pools.py`](../tests/test_warp_scan_pools.py) | Unit-тесты автообновления пулов сканирования WARP из warpscout | ✓ |
| [`test_warp_ssh_guard.py`](../tests/test_warp_ssh_guard.py) | Unit-тесты защиты SSH в chimera/modules/warp.py (живой кейс окт.2026 №12: | ✓ |
| [`test_warp_subnet_table.py`](../tests/test_warp_subnet_table.py) | Unit-тесты «таблицы подсетей» — warpscout-дашборда Chimera | ✓ |
| [`test_warp_telegram_probe.py`](../tests/test_warp_telegram_probe.py) | Unit-тесты интеграции идей warpscout / warpscout-tg в WARP-модуль Chimera. | ✓ |

## Безопасность и баны (6)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_autoban.py`](../tests/test_autoban.py) | Unit-тесты для chimera/modules/autoban.py. | ✓ |
| [`test_fail2ban_manager.py`](../tests/test_fail2ban_manager.py) | Unit-тесты для chimera/modules/fail2ban_manager.py. | ✓ |
| [`test_honeypot.py`](../tests/test_honeypot.py) | Unit-тесты для chimera/modules/honeypot.py. | ✓ |
| [`test_icmp_gate.py`](../tests/test_icmp_gate.py) | Unit-тесты для chimera/modules/icmp_gate.py. | ✓ |
| [`test_ip_mask.py`](../tests/test_ip_mask.py) | Unit-тесты wildcard-масок IP (фича ipmask-1): 176.9.*.* → 176.9.0.0/16. | ✓ |
| [`test_ipban.py`](../tests/test_ipban.py) | Unit-тесты для chimera/modules/ipban.py. | ✓ |

## DPI-детекторы и гейты (6)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_dpi_bypass.py`](../tests/test_dpi_bypass.py) | Unit-тесты для chimera/modules/dpi_bypass.py — централизованного DPI Bypass | ✓ |
| [`test_dpi_censor_check.py`](../tests/test_dpi_censor_check.py) | Unit-тесты для chimera/modules/dpi_censor_check.py. | ✓ |
| [`test_dpi_detector.py`](../tests/test_dpi_detector.py) | Unit-тесты для chimera/modules/dpi_detector.py. | ✓ |
| [`test_dpi_gate.py`](../tests/test_dpi_gate.py) | Unit-тесты для chimera/modules/dpi_gate.py. | ✓ |
| [`test_dpi_response.py`](../tests/test_dpi_response.py) | Unit-тесты для chimera/modules/dpi_response.py. | ✓ |
| [`test_mask_gate.py`](../tests/test_mask_gate.py) | Unit-тесты для chimera/modules/mask_gate.py. | ✓ |

## AdGuard Home (5)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_agh_aware_and_start_limit.py`](../tests/test_agh_aware_and_start_limit.py) | Unit-тесты для | ✓ |
| [`test_agh_le_cert_order.py`](../tests/test_agh_le_cert_order.py) | : «Fresh-сервер: AGH поставился, LE-сертификат НЕ выпустился | ✓ |
| [`test_agh_probe.py`](../tests/test_agh_probe.py) | Unit-тесты для chimera/modules/agh_probe.py — health-check локального | ✓ |
| [`test_agh_ratelimit_heal.py`](../tests/test_agh_ratelimit_heal.py) | : «Клиент сыпал EOFами — убрал AGH, всё заработало». | ✓ |
| [`test_aghome_setup.py`](../tests/test_aghome_setup.py) | Unit-тесты для AdGuard Home стека Chimera: | ✓ |

## YouTube/b4 (DPI bypass) (5)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_b4_mcp_nginx.py`](../tests/test_b4_mcp_nginx.py) | Тесты MCP-проксирования b4 через nginx front. | ✓ |
| [`test_b4_monitor.py`](../tests/test_b4_monitor.py) | Unit-тесты ops-слоя B4 (chimera/modules/b4_monitor.py). | ✓ |
| [`test_youtube_ip_pin.py`](../tests/test_youtube_ip_pin.py) | Тесты для chimera/modules/youtube_ip_pin.py — экспериментальная опция | ✓ |
| [`test_youtube_route.py`](../tests/test_youtube_route.py) | Тесты для chimera/modules/youtube_route.py — переключателя маршрутизации | ✓ |
| [`test_youtube_route_v5013.py`](../tests/test_youtube_route_v5013.py) | Регрессионные тесты для    — стабильность YouTube через RU+fragment. | ✓ |

## Telegram-боты и уведомления (5)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_tg_bot.py`](../tests/test_tg_bot.py) | Unit-тесты для chimera/modules/tg_bot.py. | ✓ |
| [`test_tg_client_bot.py`](../tests/test_tg_client_bot.py) | Unit-тесты для chimera/modules/tg_client_bot.py. | ✓ |
| [`test_tg_client_bot_inner_script.py`](../tests/test_tg_client_bot_inner_script.py) | End-to-end тесты для сгенерированного inner-скрипта клиентского бота | ✓ |
| [`test_tg_nets.py`](../tests/test_tg_nets.py) | Unit-тесты для chimera/modules/tg_nets.py. | ✓ |
| [`test_tgmon_v2.py`](../tests/test_tgmon_v2.py) | Тесты v2 генератора _install_monitor_cron (chimera/modules/tg_bot.py). | ✓ |

## Порты (port_registry, knocking, hopping) (4)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_port_follow.py`](../tests/test_port_follow.py) | Unit-тесты (port-follow): зависимые модули следуют за портом Xray при его | ✓ |
| [`test_port_hopping.py`](../tests/test_port_hopping.py) | Unit-тесты для chimera/modules/port_hopping.py. | ✓ |
| [`test_port_knocking.py`](../tests/test_port_knocking.py) | Unit-тесты для chimera/modules/port_knocking.py. | ✓ |
| [`test_port_registry.py`](../tests/test_port_registry.py) | Unit-тесты для chimera/modules/port_registry.py — централизованный реестр портов. | ✓ |

## Бэкап и восстановление (3)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_backup_registry.py`](../tests/test_backup_registry.py) | Unit-тесты для chimera/modules/backup_registry.py — единой автоматической | ✓ |
| [`test_config_backup.py`](../tests/test_config_backup.py) | Unit-тесты для chimera/modules/config_backup.py. | ✓ |
| [`test_migration.py`](../tests/test_migration.py) | Unit-тесты для chimera/modules/migration.py. | ✓ |

## xHTTP + REALITY (2)

| Тест | Что покрывает (первая строка докстринга) | ci_gate |
|---|---|---|
| [`test_xhttp_cdn_masking.py`](../tests/test_xhttp_cdn_masking.py) | Unit-тесты для chimera/modules/xhttp_cdn_masking.py — экспертный профиль XHTTP | ✓ |
| [`test_xhttp_path_gen.py`](../tests/test_xhttp_path_gen.py) | Unit-тесты для chimera/modules/xhttp_path_gen.py — генератор случайного | ✓ |
