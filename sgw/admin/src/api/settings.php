<?php
require_once __DIR__ . '/_auth.php';

$method = $_SERVER['REQUEST_METHOD'];

// GET — 读取当前设置
if ($method === 'GET') {
    try {
        $s = read_settings();
        $certInfo = get_cert_info();
        if (empty($s['upstream_url']) || empty($s['subscribe_path'])) {
            $parsed = parse_protect_conf();
            if ($parsed) {
                $s['upstream_url']   = $s['upstream_url']   ?? $parsed['upstream_url'];
                $s['upstream_host']  = $s['upstream_host']  ?? $parsed['upstream_host'];
                $s['subscribe_path'] = $s['subscribe_path'] ?? $parsed['subscribe_path'];
            }
        }
        // 网关端口：优先取 settings.json 中保存的值，否则取容器环境变量（即 .env 当前值）
        if (empty($s['gateway_port'])) {
            $s['gateway_port'] = GATEWAY_PORT;
        }
        $s = normalize_security_settings($s);
        json_out(['ok' => true, 'settings' => $s, 'cert' => $certInfo]);
    } catch (Throwable $e) {
        json_err('PHP错误: ' . $e->getMessage());
    }
}

// POST — 保存设置
if ($method === 'POST') {
    try {
    $body = json_decode(file_get_contents('php://input'), true) ?? [];

    // 仅同步部署信息
    if (!empty($body['_sync_deploy'])) {
        $s = read_settings();
        update_deploy_info($s);
        json_out(['ok' => true]);
    }

    $s = read_settings();

    // ── 界面标题 ───────────────────────────────────────────────
    if (isset($body['site_title'])) $s['site_title'] = trim($body['site_title']) ?: 'SubSieve';
    if (isset($body['page_title'])) $s['page_title'] = trim($body['page_title']) ?: 'SubSieve Admin';

    // ── 管理员凭证 ─────────────────────────────────────────────
    if (!empty($body['admin_user'])) {
        $s['admin_user'] = trim($body['admin_user']);
    }
    if (!empty($body['new_pass'])) {
        $newPass = $body['new_pass'];
        $confPass = $body['confirm_pass'] ?? '';
        if ($newPass !== $confPass) {
            json_err('两次输入的密码不一致');
        }
        if (strlen($newPass) < 6) {
            json_err('密码至少需要6位');
        }
        $s['admin_pass'] = $newPass;
    }

    // ── 网关端口 ───────────────────────────────────────────────
    $gatewayPortChanged = false;
    if (isset($body['gateway_port'])) {
        $gp = (int)$body['gateway_port'];
        if ($gp < 1 || $gp > 65535) {
            json_err('网关端口无效（1-65535）');
        }
        $s['gateway_port'] = $gp;
        $gatewayPortChanged = true;
    }

    // ── 上游（机场）配置 ────────────────────────────────────────
    $upstreamChanged = false;
    if (isset($body['upstream_url']) && $body['upstream_url'] !== '') {
        // 上游地址会直接拼入 proxy_pass，拒绝换行 / { } ; 等可篡改反代的字符
        $url = safe_conf_value($body['upstream_url']);
        // 自动加 https:// 前缀
        if (!preg_match('#^https?://#', $url)) $url = 'https://' . $url;
        $s['upstream_url'] = $url;
        // 自动提取 host（用于 proxy_set_header Host）
        $host = parse_url($url, PHP_URL_HOST);
        $s['upstream_host'] = safe_conf_value($host ?: $url);
        $upstreamChanged = true;
    }
    if (isset($body['subscribe_path']) && $body['subscribe_path'] !== '') {
        // 订阅路径会直接拼入 location ^~ ，同样拒绝结构字符
        $path = safe_conf_value($body['subscribe_path']);
        if (!str_starts_with($path, '/')) $path = '/' . $path;
        $s['subscribe_path'] = $path;
        $upstreamChanged = true;
    }

    // ── 安全设置 ───────────────────────────────────────────────
    $securityChanged = false;
    foreach (['security_rate_rpm','security_rate_burst','security_waf_enabled','security_waf_patterns','security_auto_ban_enabled','security_auto_ban_rpm','security_auto_ban_burst','security_relation_enabled','security_relation_window_minutes','security_relation_action','security_token_ip_limit_enabled','security_token_ip_window_minutes','security_token_max_ips','security_ip_token_limit_enabled','security_ip_token_window_minutes','security_ip_max_tokens'] as $k) {
        if (array_key_exists($k, $body)) { $securityChanged = true; break; }
    }
    if ($securityChanged) {
        $s['security_rate_rpm'] = require_int_range($body['security_rate_rpm'] ?? ($s['security_rate_rpm'] ?? DEFAULT_SECURITY_RATE_RPM), '订阅访问限频', 1, 6000);
        $s['security_rate_burst'] = require_int_range($body['security_rate_burst'] ?? ($s['security_rate_burst'] ?? DEFAULT_SECURITY_RATE_BURST), '订阅访问 burst', 0, 10000);
        $s['security_waf_enabled'] = settings_bool($body['security_waf_enabled'] ?? null, settings_bool($s['security_waf_enabled'] ?? null, DEFAULT_SECURITY_WAF_ENABLED));
        $s['security_waf_patterns'] = normalize_waf_patterns($body['security_waf_patterns'] ?? ($s['security_waf_patterns'] ?? DEFAULT_SECURITY_WAF_PATTERNS));
        $s['security_auto_ban_enabled'] = settings_bool($body['security_auto_ban_enabled'] ?? null, settings_bool($s['security_auto_ban_enabled'] ?? null, DEFAULT_SECURITY_AUTO_BAN_ENABLED));
        $s['security_auto_ban_rpm'] = require_int_range($body['security_auto_ban_rpm'] ?? ($s['security_auto_ban_rpm'] ?? DEFAULT_SECURITY_AUTO_BAN_RPM), '自动临时封禁/拦截阈值', 1, 6000);
        $s['security_auto_ban_burst'] = require_int_range($body['security_auto_ban_burst'] ?? ($s['security_auto_ban_burst'] ?? DEFAULT_SECURITY_AUTO_BAN_BURST), '自动临时封禁/拦截 burst', 0, 10000);

        // 旧字段仅用于兼容读取/保存，不再驱动主要处置逻辑。
        if (array_key_exists('security_relation_enabled', $body)) {
            $s['security_relation_enabled'] = settings_bool($body['security_relation_enabled'], DEFAULT_SECURITY_RELATION_ENABLED);
        }
        if (array_key_exists('security_relation_window_minutes', $body)) {
            $s['security_relation_window_minutes'] = require_int_range($body['security_relation_window_minutes'], '关系检测时间窗口', 1, 1440);
        }
        if (array_key_exists('security_relation_action', $body)) {
            $action = (string)$body['security_relation_action'];
            if (!in_array($action, ['blacklist_ip', 'block_token', 'both'], true)) {
                json_err('关系检测处置动作无效');
            }
            $s['security_relation_action'] = $action;
        }

        $legacyEnabledDefault = settings_bool($body['security_relation_enabled'] ?? ($s['security_relation_enabled'] ?? null), DEFAULT_SECURITY_RELATION_ENABLED);
        $legacyWindowDefault = isset($body['security_relation_window_minutes'])
            ? (int)$body['security_relation_window_minutes']
            : (int)($s['security_relation_window_minutes'] ?? DEFAULT_SECURITY_RELATION_WINDOW_MINUTES);

        $s['security_token_ip_limit_enabled'] = settings_bool($body['security_token_ip_limit_enabled'] ?? null, $legacyEnabledDefault);
        $s['security_token_ip_window_minutes'] = require_int_range($body['security_token_ip_window_minutes'] ?? $legacyWindowDefault, 'Token 多 IP 检测窗口', 1, 1440);
        $s['security_token_max_ips'] = require_int_range($body['security_token_max_ips'] ?? ($s['security_token_max_ips'] ?? DEFAULT_SECURITY_TOKEN_MAX_IPS), '单个 Token 最大 IP 数', 2, 10000);
        $s['security_ip_token_limit_enabled'] = settings_bool($body['security_ip_token_limit_enabled'] ?? null, $legacyEnabledDefault);
        $s['security_ip_token_window_minutes'] = require_int_range($body['security_ip_token_window_minutes'] ?? $legacyWindowDefault, 'IP 多 Token 检测窗口', 1, 1440);
        $s['security_ip_max_tokens'] = require_int_range($body['security_ip_max_tokens'] ?? ($s['security_ip_max_tokens'] ?? DEFAULT_SECURITY_IP_MAX_TOKENS), '单个 IP 最大 Token 数', 2, 10000);
    }

    $s = normalize_security_settings($s);

    // 保存 settings.json
    if (!write_settings($s)) {
        json_err('保存设置失败，请检查文件权限');
    }

    $nginxReloaded = false;
    $protectUpdated = false;

    // 若上游配置变更，重新生成 protect.conf
    if (($upstreamChanged || $securityChanged) && !empty($s['upstream_url']) && !empty($s['subscribe_path'])) {
        // 写入 nginx 配置前对三个结构性值统一兜底校验，
        // 覆盖可能来自旧 settings.json（本次未改动）的未校验值
        $safePath    = safe_conf_value($s['subscribe_path']);
        $safeBackend = safe_conf_value($s['upstream_url']);
        $safeHost    = safe_conf_value($s['upstream_host'] ?? (parse_url($s['upstream_url'], PHP_URL_HOST) ?: $s['upstream_url']));
        $protectUpdated = write_security_conf($s) && write_protect_conf($safePath, $safeBackend, $safeHost, $s);
        if ($protectUpdated) {
            $nginxReloaded = nginx_reload();
        }
    } elseif ($securityChanged) {
        $protectUpdated = write_security_conf($s);
        if ($protectUpdated) {
            $nginxReloaded = nginx_reload();
        }
    }

    // 更新 DEPLOY_INFO.txt
    update_deploy_info($s);

    $msg = '设置已保存' . ($nginxReloaded ? '，nginx 已重载' : '');
    if ($gatewayPortChanged) {
        $msg .= '。网关端口已记录，需在宿主机执行 bash update.sh 后生效';
    }
    json_out([
        'ok'                   => true,
        'nginx_reloaded'       => $nginxReloaded,
        'protect_updated'      => $protectUpdated,
        'gateway_port_changed' => $gatewayPortChanged,
        'msg'                  => $msg,
    ]);
    } catch (Throwable $e) {
        json_err('PHP错误: ' . $e->getMessage());
    }
}

json_err('不支持的请求方式', 405);

// ── 辅助函数 ──────────────────────────────────────────────────

function read_settings(): array {
    if (!file_exists(SETTINGS_JSON)) return [];
    $raw = @file_get_contents(SETTINGS_JSON);
    if ($raw === false) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function write_settings(array $s): bool {
    return file_put_contents(SETTINGS_JSON, json_encode($s, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX) !== false;
}

function require_int_range($value, string $label, int $min, int $max): int {
    if ($value === null || $value === '' || !is_numeric($value)) {
        json_err($label . '必须为整数');
    }
    $n = (int)$value;
    if ($n < $min || $n > $max) {
        json_err($label . "无效（$min-$max）");
    }
    return $n;
}

function write_security_conf(array $s): bool {
    $s = normalize_security_settings($s);
    $wafEnabled = $s['security_waf_enabled'] ? 1 : 0;
    $autoRate = $s['security_auto_ban_enabled'] ? $s['security_auto_ban_rpm'] : 6000;
    $lines = [
        '# Generated by admin settings. WAF blocks/temporarily throttles probes; it does not write permanent firewall deny rules.',
        'limit_req_zone $binary_remote_addr zone=subscribe_limit:10m rate=' . $s['security_rate_rpm'] . 'r/m;',
        'limit_req_zone $binary_remote_addr zone=waf_probe_limit:10m rate=' . $autoRate . 'r/m;',
        'map $request_uri $is_bad_request {',
        '    default 0;',
    ];
    foreach ($s['security_waf_patterns'] as $pattern) {
        $lines[] = '    ~*"' . nginx_literal_regex($pattern) . '" 1;';
    }
    $lines[] = '}';
    $lines[] = 'map "' . $wafEnabled . '" $waf_enabled { default ' . $wafEnabled . '; }';
    $lines[] = '';
    $r1 = file_put_contents(SECURITY_CONF, implode("\n", $lines), LOCK_EX) !== false;
    $r2 = write_token_block_conf(read_security_token_blocks(), $s['subscribe_path'] ?? null);
    return $r1 && $r2;
}

/**
 * 重新生成 protect.conf（覆盖上游配置）
 */
function write_protect_conf(string $subscribePath, string $backend, string $host, array $settings = []): bool {
    $settings = normalize_security_settings($settings);
    $rateBurst = $settings['security_rate_burst'];
    $autoBurst = $settings['security_auto_ban_burst'];
    $conf = <<<NGINX
location ^~ $subscribePath {

    set \$waf_block "";
    if (\$whitelist_ip = 1) { set \$block_reason ""; }

    if (\$is_cloud_ip = 1)       { set \$block_reason "cloud"; }
    if (\$bad_subscribe_ua = 1)  { set \$block_reason "ua"; }
    if (\$is_custom_bad_ua = 1)  { set \$block_reason "ua"; }
    if (\$is_ua_whitelisted = 1) { set \$block_reason ""; }

    if (\$whitelist_ip = 1) { set \$block_reason ""; }

    if (\$block_reason = "cloud") { return 403 "Forbidden: Cloud IP"; }
    if (\$block_reason = "ua")    { return 403 "Forbidden: Invalid Client"; }

    if (\$is_blocked_token = 1) { return 403 "Forbidden: Blocked Token"; }

    if (\$waf_enabled = 1) { set \$waf_block \$is_bad_request; }
    limit_req zone=subscribe_limit burst=$rateBurst nodelay;
    limit_req_status 429;

    error_page 418 = @subscribe_waf_block;
    if (\$waf_block = 1) { return 418; }

    set \$upstream_backend   $backend;
    proxy_pass              \$upstream_backend;
    proxy_set_header    Host              $host;
    proxy_set_header    X-Real-IP         \$remote_addr;
    proxy_set_header    X-Forwarded-For   \$proxy_add_x_forwarded_for;
    proxy_set_header    REMOTE-HOST       \$remote_addr;
    proxy_ssl_server_name on;
    proxy_ssl_name        $host;
    proxy_set_header    Upgrade           \$http_upgrade;
    proxy_set_header    Connection        \$connection_upgrade;
    proxy_http_version  1.1;
    proxy_connect_timeout 10s;
    proxy_send_timeout    15s;
    proxy_read_timeout    60s;

    add_header Cache-Control no-store;
    add_header X-Subscribe-Filter "active";
}

location @subscribe_waf_block {
    limit_req zone=waf_probe_limit burst=$autoBurst nodelay;
    limit_req_status 429;
    try_files /__subsieve_waf_forbidden__ =403;
}
NGINX;
    return file_put_contents(PROTECT_CONF, $conf, LOCK_EX) !== false;
}

/**
 * 解析 protect.conf 提取上游配置
 */
function parse_protect_conf(): ?array {
    if (!file_exists(PROTECT_CONF)) return null;
    $content = @file_get_contents(PROTECT_CONF);
    if ($content === false) return null;
    $result = [];
    if (preg_match('/^location\s+\^~\s+(\S+)/m', $content, $m)) {
        $result['subscribe_path'] = $m[1];
    }
    // 优先从 "set $upstream_backend URL;" 提取（模板生成的 protect.conf 格式）
    if (preg_match('/set\s+\$upstream_backend\s+(\S+);/m', $content, $m)) {
        $result['upstream_url'] = rtrim($m[1], ';');
    } elseif (preg_match('/proxy_pass\s+(\S+);/m', $content, $m)) {
        $val = rtrim($m[1], ';');
        // 跳过 nginx 变量引用（如 $upstream_backend），只取真实 URL
        if (!str_starts_with($val, '$')) {
            $result['upstream_url'] = $val;
        }
    }
    if (preg_match('/proxy_set_header\s+Host\s+(\S+);/m', $content, $m)) {
        $result['upstream_host'] = rtrim($m[1], ';');
    }
    return $result ?: null;
}

/**
 * 获取 SSL 证书信息
 */
function get_cert_info(): array {
    $certFile = '/etc/nginx/ssl/cert.pem';
    if (!file_exists($certFile)) {
        return ['exists' => false];
    }
    $info = ['exists' => true, 'path' => $certFile];
    $certContent = @file_get_contents($certFile);
    if ($certContent === false) {
        return $info; // 无读取权限，返回 exists:true 但无 subject
    }
    $certData = @openssl_x509_parse($certContent);
    if ($certData) {
        $info['subject']   = $certData['subject']['CN'] ?? '';
        $info['valid_to']  = date('Y-m-d', $certData['validTo_time_t']);
        $info['valid_from']= date('Y-m-d', $certData['validFrom_time_t']);
        $info['issuer']    = $certData['issuer']['O'] ?? $certData['issuer']['CN'] ?? '';
        $san = '';
        if (!empty($certData['extensions']['subjectAltName'])) {
            $san = $certData['extensions']['subjectAltName'];
        }
        $info['san'] = $san;
        $daysLeft = (int)(($certData['validTo_time_t'] - time()) / 86400);
        $info['days_left'] = $daysLeft;
    }
    return $info;
}

/**
 * 更新 DEPLOY_INFO.txt（在共享日志卷中）
 */
function update_deploy_info(array $s): void {
    $protectInfo = parse_protect_conf();
    $subscribePath = $protectInfo['subscribe_path'] ?? $s['subscribe_path'] ?? '—';
    $upstreamUrl   = $protectInfo['upstream_url']   ?? $s['upstream_url']   ?? '—';
    $adminUser     = $s['admin_user'] ?? ADMIN_USER;
    $siteTitle     = $s['site_title'] ?? SITE_TITLE;
    $now           = date('Y-m-d H:i:s');

    $content = <<<TXT
$siteTitle 部署信息
更新时间: $now

管理后台
  用户名: $adminUser
  （密码已隐藏，请从系统设置中修改）

订阅网关
  订阅路径: $subscribePath
  代理到:   $upstreamUrl
TXT;
    @file_put_contents(DEPLOY_INFO_FILE, $content, LOCK_EX);
}
