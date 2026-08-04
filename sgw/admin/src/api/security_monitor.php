<?php
require_once __DIR__ . '/_auth.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET' || $method === 'POST') {
    $apply = $method === 'POST';
    $settings = normalize_security_settings(read_settings_monitor());
    $summary = scan_relation_limits($settings);
    $actions = ['blacklisted_ips' => [], 'blocked_tokens' => [], 'nginx_reloaded' => false];

    if ($apply) {
        $actions = apply_relation_limit_actions($summary, $settings);
    }

    $summary['token_ip_violation_count'] = count($summary['token_ip_violations'] ?? []);
    $summary['ip_token_violation_count'] = count($summary['ip_token_violations'] ?? []);
    $summary['token_block_added'] = count($actions['blocked_tokens'] ?? []);
    $summary['blacklist_added'] = count($actions['blacklisted_ips'] ?? []);
    // 旧前端字段兼容：designer 改 UI 前不让摘要展示断裂。
    $summary['violation_token_count'] = $summary['token_ip_violation_count'];
    $summary['violation_ip_count'] = $summary['ip_token_violation_count'];
    $summary['token_violations'] = $summary['token_ip_violations'];
    $summary['ip_violations'] = $summary['ip_token_violations'];
    $summary['relation_enabled'] = $settings['security_token_ip_limit_enabled'] || $settings['security_ip_token_limit_enabled'];
    $summary['action'] = 'split_rules';
    $summary['message'] = $apply
        ? '已执行检测：Token 多 IP 仅自动阻断 Token；IP 多 Token 仅自动拉黑 IP。'
        : '仅检测未应用；POST 后按两条独立规则应用动作。';

    json_out([
        'ok' => true,
        'enabled' => $summary['relation_enabled'],
        'settings' => [
            'security_token_ip_limit_enabled' => $settings['security_token_ip_limit_enabled'],
            'security_token_ip_window_minutes' => $settings['security_token_ip_window_minutes'],
            'security_token_max_ips' => $settings['security_token_max_ips'],
            'security_ip_token_limit_enabled' => $settings['security_ip_token_limit_enabled'],
            'security_ip_token_window_minutes' => $settings['security_ip_token_window_minutes'],
            'security_ip_max_tokens' => $settings['security_ip_max_tokens'],
            // 旧字段兼容返回。
            'security_relation_enabled' => $settings['security_relation_enabled'],
            'security_relation_window_minutes' => $settings['security_relation_window_minutes'],
            'security_relation_action' => $settings['security_relation_action'],
        ],
        'summary' => $summary,
        'actions' => $actions,
        'token_blocks' => read_security_token_blocks(),
    ]);
}

json_err('不支持的请求方式', 405);

function read_settings_monitor(): array {
    return read_json_array_file(SETTINGS_JSON);
}

function scan_relation_limits(array $settings): array {
    $subscribePath = $settings['subscribe_path'] ?? '/api/v1/client/subscribe';
    $now = time();
    $tokenCutoff = $now - $settings['security_token_ip_window_minutes'] * 60;
    $ipCutoff = $now - $settings['security_ip_token_window_minutes'] * 60;
    $minCutoff = min($tokenCutoff, $ipCutoff);

    $tokenIps = [];
    $ipTokens = [];
    $total = 0;
    $matchedTokenWindow = 0;
    $matchedIpWindow = 0;

    if (file_exists(LOG_FILE) && ($fh = fopen(LOG_FILE, 'r'))) {
        while (($line = fgets($fh)) !== false) {
            $total++;
            $line = rtrim($line);
            if ($line === '') continue;
            if (!preg_match('/^(\S+) \[([^\]]+)\] "([^"]*)" (\d+)/', $line, $m)) continue;
            [, $ip, $time, $request, $status] = $m;
            if ((int)$status !== 200) continue;
            $ts = parse_log_ts($time);
            if ($ts < $minCutoff) continue;
            $token = extract_subscribe_token_from_request($request, $subscribePath);
            if ($token === '') continue;

            if ($settings['security_token_ip_limit_enabled'] && $ts >= $tokenCutoff) {
                $matchedTokenWindow++;
                $tokenIps[$token][$ip] = true;
            }
            if ($settings['security_ip_token_limit_enabled'] && $ts >= $ipCutoff) {
                $matchedIpWindow++;
                $ipTokens[$ip][$token] = true;
            }
        }
        fclose($fh);
    }

    $tokenIpViolations = [];
    foreach ($tokenIps as $token => $ips) {
        $cnt = count($ips);
        if ($cnt > $settings['security_token_max_ips']) {
            $tokenIpViolations[] = ['token' => $token, 'ip_count' => $cnt, 'ips' => array_keys($ips)];
        }
    }
    usort($tokenIpViolations, fn($a, $b) => $b['ip_count'] <=> $a['ip_count']);

    $ipTokenViolations = [];
    foreach ($ipTokens as $ip => $tokens) {
        $cnt = count($tokens);
        if ($cnt > $settings['security_ip_max_tokens']) {
            $ipTokenViolations[] = ['ip' => $ip, 'token_count' => $cnt, 'tokens' => array_keys($tokens)];
        }
    }
    usort($ipTokenViolations, fn($a, $b) => $b['token_count'] <=> $a['token_count']);

    return [
        'token_ip_enabled' => $settings['security_token_ip_limit_enabled'],
        'token_ip_window_minutes' => $settings['security_token_ip_window_minutes'],
        'token_max_ips' => $settings['security_token_max_ips'],
        'ip_token_enabled' => $settings['security_ip_token_limit_enabled'],
        'ip_token_window_minutes' => $settings['security_ip_token_window_minutes'],
        'ip_max_tokens' => $settings['security_ip_max_tokens'],
        'window_minutes' => max($settings['security_token_ip_window_minutes'], $settings['security_ip_token_window_minutes']),
        'scanned_lines' => $total,
        'matched_token_ip_pulls' => $matchedTokenWindow,
        'matched_ip_token_pulls' => $matchedIpWindow,
        'matched_subscribe_pulls' => max($matchedTokenWindow, $matchedIpWindow),
        'token_ip_violations' => $tokenIpViolations,
        'ip_token_violations' => $ipTokenViolations,
        'checked_at' => date('Y-m-d H:i:s'),
    ];
}

function apply_relation_limit_actions(array $summary, array $settings): array {
    $reloadNeeded = false;
    $blacklisted = [];
    $blockedTokens = [];
    $now = date('Y-m-d H:i');

    // 规则 1：单 Token 多 IP，只阻断 Token。
    if ($settings['security_token_ip_limit_enabled']) {
        $entries = read_security_token_blocks();
        $existing = [];
        foreach ($entries as $e) $existing[$e['token']] = true;
        foreach ($summary['token_ip_violations'] as $v) {
            $token = safe_token_value($v['token']);
            if ($token === '' || isset($existing[$token])) continue;
            $entries[] = ['token' => $token, 'comment' => '自动检测：' . $v['ip_count'] . ' 个 IP 在 ' . $settings['security_token_ip_window_minutes'] . ' 分钟内拉取', 'added_at' => $now];
            $existing[$token] = true;
            $blockedTokens[] = $token;
        }
        if ($blockedTokens && write_security_token_blocks($entries, $settings['subscribe_path'] ?? null)) $reloadNeeded = true;
    }

    // 规则 2：单 IP 多 Token，只拉黑 IP。
    if ($settings['security_ip_token_limit_enabled']) {
        $entries = read_json_array_file(BLACKLIST_JSON);
        $existing = [];
        foreach ($entries as $e) if (!empty($e['ip'])) $existing[$e['ip']] = true;
        foreach ($summary['ip_token_violations'] as $v) {
            $ip = $v['ip'];
            if (!preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $ip) || isset($existing[$ip])) continue;
            $entries[] = ['ip' => $ip, 'comment' => '自动检测：' . $v['token_count'] . ' 个 Token 在 ' . $settings['security_ip_token_window_minutes'] . ' 分钟内被拉取', 'added_at' => $now];
            $existing[$ip] = true;
            $blacklisted[] = $ip;
        }
        if ($blacklisted && write_blacklist_entries($entries)) $reloadNeeded = true;
    }

    $reloaded = $reloadNeeded ? nginx_reload() : false;
    return ['blacklisted_ips' => $blacklisted, 'blocked_tokens' => $blockedTokens, 'nginx_reloaded' => $reloaded];
}

function parse_log_ts(string $time): int {
    $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $time);
    return $dt ? $dt->getTimestamp() : 0;
}
