<?php
require_once __DIR__ . '/_auth.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET' || $method === 'POST') {
    $apply = $method === 'POST';
    $settings = normalize_security_settings(read_settings_monitor());
    $summary = scan_relation_abuse($settings);
    $actions = ['blacklisted_ips' => [], 'blocked_tokens' => [], 'nginx_reloaded' => false];

    if ($apply && $settings['security_relation_enabled']) {
        $actions = apply_relation_actions($summary, $settings);
    }

    $summary['relation_enabled'] = $settings['security_relation_enabled'];
    $summary['action'] = $settings['security_relation_action'];
    $summary['violation_token_count'] = count($summary['token_violations'] ?? []);
    $summary['violation_ip_count'] = count($summary['ip_violations'] ?? []);
    $summary['blacklist_added'] = count($actions['blacklisted_ips'] ?? []);
    $summary['token_block_added'] = count($actions['blocked_tokens'] ?? []);
    $summary['message'] = $apply
        ? '已执行检测并按配置应用动作。'
        : '仅检测未应用；点击“立即检测 / 应用”后才会写入黑名单或 Token 阻断。';

    json_out([
        'ok' => true,
        'enabled' => $settings['security_relation_enabled'],
        'settings' => [
            'security_relation_enabled' => $settings['security_relation_enabled'],
            'security_relation_window_minutes' => $settings['security_relation_window_minutes'],
            'security_token_max_ips' => $settings['security_token_max_ips'],
            'security_ip_max_tokens' => $settings['security_ip_max_tokens'],
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

function scan_relation_abuse(array $settings): array {
    $window = $settings['security_relation_window_minutes'];
    $cutoff = time() - $window * 60;
    $subscribePath = $settings['subscribe_path'] ?? '/api/v1/client/subscribe';
    $tokenIps = [];
    $ipTokens = [];
    $total = 0;
    $matched = 0;

    if (file_exists(LOG_FILE) && ($fh = fopen(LOG_FILE, 'r'))) {
        while (($line = fgets($fh)) !== false) {
            $total++;
            $line = rtrim($line);
            if ($line === '') continue;
            if (!preg_match('/^(\S+) \[([^\]]+)\] "([^"]*)" (\d+)/', $line, $m)) continue;
            [, $ip, $time, $request, $status] = $m;
            if ((int)$status !== 200) continue;
            $ts = parse_log_ts($time);
            if ($ts < $cutoff) continue;
            $token = extract_subscribe_token_from_request($request, $subscribePath);
            if ($token === '') continue;
            $matched++;
            $tokenIps[$token][$ip] = true;
            $ipTokens[$ip][$token] = true;
        }
        fclose($fh);
    }

    $tokenViolations = [];
    foreach ($tokenIps as $token => $ips) {
        $cnt = count($ips);
        if ($cnt > $settings['security_token_max_ips']) {
            $tokenViolations[] = ['token' => $token, 'ip_count' => $cnt, 'ips' => array_keys($ips)];
        }
    }
    usort($tokenViolations, fn($a, $b) => $b['ip_count'] <=> $a['ip_count']);

    $ipViolations = [];
    foreach ($ipTokens as $ip => $tokens) {
        $cnt = count($tokens);
        if ($cnt > $settings['security_ip_max_tokens']) {
            $ipViolations[] = ['ip' => $ip, 'token_count' => $cnt, 'tokens' => array_keys($tokens)];
        }
    }
    usort($ipViolations, fn($a, $b) => $b['token_count'] <=> $a['token_count']);

    return [
        'window_minutes' => $window,
        'scanned_lines' => $total,
        'matched_subscribe_pulls' => $matched,
        'token_violations' => $tokenViolations,
        'ip_violations' => $ipViolations,
        'checked_at' => date('Y-m-d H:i:s'),
    ];
}

function apply_relation_actions(array $summary, array $settings): array {
    $action = $settings['security_relation_action'];
    $reloadNeeded = false;
    $blacklisted = [];
    $blockedTokens = [];
    $now = date('Y-m-d H:i');

    if ($action === 'blacklist_ip' || $action === 'both') {
        $entries = read_json_array_file(BLACKLIST_JSON);
        $existing = [];
        foreach ($entries as $e) if (!empty($e['ip'])) $existing[$e['ip']] = true;

        $candidates = [];
        foreach ($summary['ip_violations'] as $v) $candidates[$v['ip']] = '短时间拉取多个 token: ' . $v['token_count'];
        if ($action === 'both') {
            foreach ($summary['token_violations'] as $v) {
                foreach ($v['ips'] as $ip) $candidates[$ip] = '同一 token 被多 IP 拉取: ' . $v['token'];
            }
        }
        foreach ($candidates as $ip => $comment) {
            if (!preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $ip) || isset($existing[$ip])) continue;
            $entries[] = ['ip' => $ip, 'comment' => '自动关系检测：' . safe_comment($comment), 'added_at' => $now];
            $existing[$ip] = true;
            $blacklisted[] = $ip;
        }
        if ($blacklisted && write_blacklist_entries($entries)) $reloadNeeded = true;
    }

    if ($action === 'block_token' || $action === 'both') {
        $entries = read_security_token_blocks();
        $existing = [];
        foreach ($entries as $e) $existing[$e['token']] = true;
        foreach ($summary['token_violations'] as $v) {
            $token = safe_token_value($v['token']);
            if ($token === '' || isset($existing[$token])) continue;
            $entries[] = ['token' => $token, 'comment' => '自动关系检测：' . $v['ip_count'] . ' 个 IP 拉取', 'added_at' => $now];
            $existing[$token] = true;
            $blockedTokens[] = $token;
        }
        if ($blockedTokens && write_security_token_blocks($entries, $settings['subscribe_path'] ?? null)) $reloadNeeded = true;
    }

    $reloaded = $reloadNeeded ? nginx_reload() : false;
    return ['blacklisted_ips' => $blacklisted, 'blocked_tokens' => $blockedTokens, 'nginx_reloaded' => $reloaded];
}

function parse_log_ts(string $time): int {
    $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $time);
    return $dt ? $dt->getTimestamp() : 0;
}
