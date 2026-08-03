<?php
// =============================================================
// config.php — 从环境变量加载配置
// =============================================================

// 文件路径（共享 volume）— 先定义，以便读取 settings.json
define('LOG_FILE',          '/var/log/subscribe/access.log');
define('WHITELIST_IPS',     '/etc/nginx/subscribe/whitelist_ips.txt');
define('WHITELIST_CONF',    '/etc/nginx/subscribe/whitelist.conf');
define('BLACKLIST_JSON',    '/etc/nginx/subscribe/blacklist.json');
define('BLACKLIST_CONF',    '/etc/nginx/subscribe/blacklist.conf');
define('CLOUD_GEO_LOG',     '/var/log/subscribe/update_cloud_geo.log');
define('CLOUD_GEO_CONF',    '/etc/nginx/subscribe/cloud_geo.conf');
define('UA_BLACKLIST_JSON', '/etc/nginx/subscribe/ua_blacklist.json');
define('UA_CUSTOM_CONF',    '/etc/nginx/subscribe/ua_custom.conf');
define('UA_WHITELIST_JSON', '/etc/nginx/subscribe/ua_whitelist.json');
define('UA_WHITELIST_CONF',    '/etc/nginx/subscribe/ua_whitelist.conf');
define('TOKEN_BLACKLIST_JSON', '/etc/nginx/subscribe/token_blacklist.json');
define('SETTINGS_JSON',     '/etc/nginx/subscribe/admin_settings.json');
define('PROTECT_CONF',      '/etc/nginx/subscribe/protect.conf');
define('SECURITY_CONF',     '/etc/nginx/subscribe/security.conf');
define('DEPLOY_INFO_FILE',  '/var/log/subscribe/DEPLOY_INFO.txt');

define('DEFAULT_SECURITY_RATE_RPM', 10);
define('DEFAULT_SECURITY_RATE_BURST', 5);
define('DEFAULT_SECURITY_WAF_ENABLED', true);
define('DEFAULT_SECURITY_AUTO_BAN_ENABLED', true);
define('DEFAULT_SECURITY_AUTO_BAN_RPM', 3);
define('DEFAULT_SECURITY_AUTO_BAN_BURST', 2);
define('DEFAULT_SECURITY_WAF_PATTERNS', [
    '/cgi-bin/', '/etc/passwd', 'wget', 'curl', 'busybox', 'chmod', 'eval(', 'base64_decode',
]);

// 读取持久化设置（覆盖环境变量）
$_sg = [];
if (file_exists(SETTINGS_JSON)) {
    $_d = json_decode(file_get_contents(SETTINGS_JSON), true);
    if (is_array($_d)) $_sg = $_d;
}

define('ADMIN_USER',        $_sg['admin_user']      ?? (getenv('ADMIN_USER')        ?: 'admin'));
define('ADMIN_PASS',        $_sg['admin_pass']      ?? (getenv('ADMIN_PASS')        ?: ''));
define('NGINX_RELOAD_SIGNAL',     '/etc/nginx/subscribe/.reload');
define('WHITELIST_RELOAD_SIGNAL', '/etc/nginx/subscribe/.reload_whitelist');
define('GATEWAY_PORT',      (int)(getenv('GATEWAY_PORT') ?: 443));
define('SESSION_LIFETIME',  (int)(getenv('SESSION_LIFETIME') ?: 28800)); // 8小时
// 后台访问路径前缀，留空则不校验（例如 ef9d1566 → 必须访问 /ef9d1566 才能进入后台）
define('ADMIN_SECRET_PATH', trim(trim(getenv('ADMIN_SECRET_PATH') ?: ''), '/'));

// 界面显示设置
define('SITE_TITLE', $_sg['site_title'] ?? 'SubSieve');
define('PAGE_TITLE', $_sg['page_title'] ?? 'SubSieve Admin');

// ── 辅助函数 ──────────────────────────────────────────────────

function json_out(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function json_err(string $msg, int $code = 400): void {
    json_out(['ok' => false, 'error' => $msg], $code);
}

/**
 * 触发 gateway nginx reload
 * 向共享 volume 写入信号文件，gateway 的 watcher 检测后执行 nginx -s reload
 * 无需挂载 Docker socket，避免宿主机 root 权限暴露
 */
function nginx_reload(): bool {
    return file_put_contents(NGINX_RELOAD_SIGNAL, '1', LOCK_EX) !== false;
}

function whitelist_reload(): bool {
    return file_put_contents(WHITELIST_RELOAD_SIGNAL, '1', LOCK_EX) !== false;
}

// ── 写入 nginx 配置前的安全过滤 ────────────────────────────────
// 后台多处会把用户输入（路径、上游地址、UA、备注等）写入 nginx 配置文件，
// 若不过滤，换行 / 结构字符（{ } ; "）可篡改反代规则或注入指令。

/**
 * 校验将作为「结构性 token」直接拼入 nginx 配置的值（如订阅路径、上游地址、Host）。
 * 这些值未加引号写入配置，含换行或 nginx 结构字符（{ } ;）即可越权注入，故直接拒绝。
 * 校验不通过会输出 JSON 错误并终止请求。
 */
function safe_conf_value(string $s): string {
    $s = trim($s);
    if (preg_match('/[\r\n{};]/', $s)) {
        json_err('包含非法字符（不允许换行或 { } ; 等字符）');
    }
    return $s;
}

function normalize_subscribe_path(?string $path): string {
    $path = trim((string)$path);
    if ($path === '') return '/api/v1/client/subscribe';
    if (!str_starts_with($path, '/')) $path = '/' . $path;
    return rtrim($path, '/') ?: '/';
}

function settings_bool($value, bool $default): bool {
    if ($value === null) return $default;
    if (is_bool($value)) return $value;
    if (is_int($value)) return $value !== 0;
    if (is_string($value)) {
        $v = strtolower(trim($value));
        if (in_array($v, ['1', 'true', 'yes', 'on'], true)) return true;
        if (in_array($v, ['0', 'false', 'no', 'off'], true)) return false;
    }
    return $default;
}

function settings_int($value, int $default, int $min, int $max): int {
    if ($value === null || $value === '') return $default;
    if (!is_numeric($value)) return $default;
    $n = (int)$value;
    if ($n < $min) return $min;
    if ($n > $max) return $max;
    return $n;
}

function normalize_waf_patterns($value): array {
    if (is_string($value)) {
        $value = preg_split('/\r\n|\r|\n|\s*,\s*/', $value) ?: [];
    }
    if (!is_array($value)) $value = DEFAULT_SECURITY_WAF_PATTERNS;
    $out = [];
    foreach ($value as $p) {
        $p = trim((string)$p);
        // map 行会写入 nginx 配置；拒绝换行、结构字符与过长模式，避免注入/畸形配置。
        if ($p === '' || strlen($p) > 128 || preg_match('/[\r\n{};"`]/', $p)) continue;
        $out[$p] = true;
    }
    if (!$out) {
        foreach (DEFAULT_SECURITY_WAF_PATTERNS as $p) $out[$p] = true;
    }
    return array_keys($out);
}

function normalize_security_settings(array $s): array {
    $s['security_rate_rpm'] = settings_int($s['security_rate_rpm'] ?? null, DEFAULT_SECURITY_RATE_RPM, 1, 6000);
    $s['security_rate_burst'] = settings_int($s['security_rate_burst'] ?? null, DEFAULT_SECURITY_RATE_BURST, 0, 10000);
    $s['security_waf_enabled'] = settings_bool($s['security_waf_enabled'] ?? null, DEFAULT_SECURITY_WAF_ENABLED);
    $s['security_waf_patterns'] = normalize_waf_patterns($s['security_waf_patterns'] ?? DEFAULT_SECURITY_WAF_PATTERNS);
    $s['security_auto_ban_enabled'] = settings_bool($s['security_auto_ban_enabled'] ?? null, DEFAULT_SECURITY_AUTO_BAN_ENABLED);
    $s['security_auto_ban_rpm'] = settings_int($s['security_auto_ban_rpm'] ?? null, DEFAULT_SECURITY_AUTO_BAN_RPM, 1, 6000);
    $s['security_auto_ban_burst'] = settings_int($s['security_auto_ban_burst'] ?? null, DEFAULT_SECURITY_AUTO_BAN_BURST, 0, 10000);
    return $s;
}

function nginx_literal_regex(string $s): string {
    return str_replace(['\\', '"'], ['\\\\', '\\"'], preg_quote($s, '~'));
}

function extract_subscribe_token_from_request(string $request, ?string $subscribePath = null): string {
    // v2board 兼容：/api/v1/client/subscribe?token=xxx
    if (preg_match('/[?&]token=([^&\s"]+)/i', $request, $m)) {
        return rawurldecode($m[1]);
    }
    // xboard / 自定义路径：在配置 subscribe_path 下取第一个后续路径段作为 token，例如 /clouddy/455...
    $parts = preg_split('/\s+/', trim($request));
    $target = $parts[1] ?? '';
    if ($target === '') return '';
    $path = parse_url($target, PHP_URL_PATH) ?: '';
    $base = normalize_subscribe_path($subscribePath ?? ($GLOBALS['_sg']['subscribe_path'] ?? null));
    if ($base === '/' || $path === $base || !str_starts_with($path, $base . '/')) return '';
    $rest = substr($path, strlen($base) + 1);
    $seg = strtok($rest, '/');
    return $seg ? rawurldecode($seg) : '';
}

/**
 * 清洗将写入 nginx 配置 / 数据文件的「备注」文本，使其只能作为单行普通注释存在：
 * 移除换行（避免越行注入指令）及 # ; { } 等结构 / 注释字符，多个连续字符压缩为单空格。
 */
function safe_comment(string $s): string {
    return trim(preg_replace('/[\r\n#;{}]+/', ' ', $s));
}

/**
 * 将用户输入的 UA 关键词转为 nginx map 的「字面量」匹配模式（配合 ~* 前缀）。
 * 1) preg_quote 中和全部正则元字符，避免 . * 等生效或被构造成 ReDoS；
 * 2) 再转义 nginx 双引号字符串层的 \ 与 "，避免提前闭合字符串注入配置。
 * 调用方需保证传入的 UA 不含换行（写入前已剔除）。
 */
function nginx_ua_pattern(string $ua): string {
    $p = preg_quote($ua, '~');
    return str_replace(['\\', '"'], ['\\\\', '\\"'], $p);
}

// ── V2B 数据库接口（预留，后续填充）─────────────────────────
// TODO: 连接 V2B MySQL 查询 token 对应用户信息
// function v2b_get_user_by_token(string $token): ?array { return null; }
